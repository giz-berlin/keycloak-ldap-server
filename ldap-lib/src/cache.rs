use std::{sync::Arc, time};

use ldap3_proto::{LdapResultCode, LdapSearchResultEntry, SearchRequest};

use crate::{entry, keycloak_service_account, proto};

/// Data class holding cache configuration values.
pub struct CacheConfiguration {
    pub keycloak_service_account_client_builder: keycloak_service_account::ServiceAccountClientBuilder,
    pub num_users_to_fetch: i32,
    pub include_group_info: bool,
    pub cache_update_interval: time::Duration,
    pub max_entry_inactive_time: time::Duration,
    pub ldap_entry_builder: entry::LdapEntryBuilder,
}

pub const REGISTRY_DEFAULT_HOUSEKEEPING_INTERVAL: time::Duration = time::Duration::from_secs(5);

/// A thread-safe registry keeping track of and allowing access to all active client caches.
/// Will periodically evict inactive caches.
pub struct CacheRegistry {
    configuration: Arc<CacheConfiguration>,
    per_client_ldap_trees: tokio::sync::RwLock<std::collections::HashMap<String, Arc<KeycloakClientLdapCache>>>,
}

impl CacheRegistry {
    /// Create a new registry and initialize housekeeping tasks.
    pub fn new(configuration: CacheConfiguration, housekeeping_interval: time::Duration) -> Arc<Self> {
        let registry = Arc::new(Self {
            configuration: Arc::new(configuration),
            per_client_ldap_trees: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        });
        registry.clone().trigger_housekeeping(housekeeping_interval);
        registry
    }

    fn trigger_housekeeping(self: Arc<Self>, housekeeping_interval: time::Duration) {
        tokio::spawn(self.perform_housekeeping(housekeeping_interval));
    }

    /// Periodically evict inactive caches.
    async fn perform_housekeeping(self: Arc<Self>, housekeeping_interval: time::Duration) {
        loop {
            tokio::time::sleep(housekeeping_interval).await;

            let mut locked_store = self.per_client_ldap_trees.write().await;
            let mut client_caches_to_evict = Vec::new();
            for (client, cache) in locked_store.iter() {
                if !cache.is_active().await {
                    client_caches_to_evict.push(client.to_owned());
                }
            }
            for client in client_caches_to_evict {
                log::info!("Evicting cache for client {} from registry", client);
                self._unregister_client_cache(&mut locked_store, client.as_str()).await;
            }
        }
    }

    /// Perform a bind for a client with the corresponding password.
    ///
    /// If this registry did not yet know of a client cache for this client, create one now. If authenticating using the provided
    /// credentials against Keycloak fails, an error is returned; otherwise, the operation succeeds and the entry is
    /// inserted into the registry.
    ///
    /// If the client is already present in the registry, only check whether the provided password matches the last known
    /// correct one (see note on the [KeycloakClientLdapCache::check_password] method).
    pub async fn perform_ldap_bind_for_client(self: &Arc<Self>, client: &str, password: &str) -> Result<(), proto::LdapError> {
        let new_cache_entry: Arc<KeycloakClientLdapCache>;

        {
            // Locking semantic of this method:
            // We need to acquire a lock as soon as possible in case two separate sessions try to perform a bind for the same new client:
            // We want to avoid a scenario where both threads then start creating a new cache.
            //
            // However, the lock should be dropped before we start initializing the new cache, because this is a relatively time-consuming
            // operation, and we cannot answer any queries (even for other clients) as long as we hold the exclusive lock.
            //
            // Doing it this way will allow the second thread to obtain the cache immediately, but issuing any search queries on it will
            // block until the initialization of the cache issued by the first thread has finished.
            let mut locked_store = self.per_client_ldap_trees.write().await;

            if let Some(cache_entry) = locked_store.get(client) {
                if cache_entry.is_active().await {
                    return cache_entry.check_password(password);
                } else {
                    // We need to create a new cache because the old one we had cannot be used anymore.
                    // But first, ensure the old one is being properly removed.
                    self._unregister_client_cache(&mut locked_store, client).await;
                }
            }

            log::info!("registry: Encountered new client '{client}', registering it");
            new_cache_entry = Arc::new(KeycloakClientLdapCache::create(self.configuration.clone(), client, password).await?);
            locked_store.insert(client.to_string(), new_cache_entry.clone());

            // We do not need to check the password here anymore:
            // If creation of the cache_entry has succeeded, we know that the credentials must have been valid.
        }

        new_cache_entry.initialize().await?;

        Ok(())
    }

    /// Return the cache for the given client ID.
    pub async fn obtain_client_cache(&self, client: &str) -> Result<Arc<KeycloakClientLdapCache>, proto::LdapError> {
        if let Some(cache_entry) = self.per_client_ldap_trees.read().await.get(client) {
            if cache_entry.is_active().await {
                return Ok(cache_entry.clone());
            }
        }

        Err(proto::LdapError(
            LdapResultCode::InvalidCredentials,
            "Unknown client! Maybe the client credentials have changed during an active bind session?".to_string(),
        ))
    }

    /// Unregister a client cache. Will make use of an already existing lock to perform the action.
    async fn _unregister_client_cache(
        &self,
        locked_store: &mut tokio::sync::RwLockWriteGuard<'_, std::collections::HashMap<String, Arc<KeycloakClientLdapCache>>>,
        client: &str,
    ) {
        if let Some(cache_entry) = locked_store.get_mut(client) {
            cache_entry.destroy().await;
            locked_store.remove(client);
        }
    }
}

/// A keycloak client LDAP registry keeps track of a set of user and (potentially) group information as visible to a certain keycloak client.
/// The information is provided in form of an LDAP tree.
/// Will periodically sync the LDAP information from keycloak.
pub struct KeycloakClientLdapCache {
    configuration: Arc<CacheConfiguration>,

    update_task_handle: tokio::sync::RwLock<Option<tokio::task::JoinHandle<()>>>,

    client: String,
    password: String,
    service_account_client: keycloak_service_account::ServiceAccountClient,
    last_used: tokio::sync::RwLock<time::Instant>,
    root: tokio::sync::RwLock<entry::LdapEntry>,
}

impl KeycloakClientLdapCache {
    /// Construct a new client cache.
    ///
    /// Will only succeed iff the entered credentials are valid.
    pub async fn create(configuration: Arc<CacheConfiguration>, client: &str, password: &str) -> Result<Self, proto::LdapError> {
        let service_account_client = configuration
            .keycloak_service_account_client_builder
            .new_service_account(client, password)
            .await?;
        Ok(Self {
            configuration,
            update_task_handle: tokio::sync::RwLock::new(None),
            client: client.to_owned(),
            password: password.to_owned(),
            service_account_client,
            last_used: tokio::sync::RwLock::new(time::Instant::now()),
            root: tokio::sync::RwLock::new(entry::LdapEntry::new("".to_string(), vec![])),
        })
    }

    /// Perform an initial data fetching to populate the cache.
    /// Will also initialize the cache lifecycle by triggering scheduled updates.
    pub async fn initialize(self: Arc<Self>) -> Result<(), proto::LdapError> {
        let mut lock = self.update_task_handle.write().await;
        self.fetch().await?;
        _ = lock.insert(self.clone().trigger_scheduled_update());
        Ok(())
    }

    async fn await_initialization(&self) {
        // During initialization, we obtain an exclusive lock on the handle.
        // As soon as we are able to obtain a read handle here as well, we are ready to proceed.
        let _ = self.update_task_handle.read().await;
    }

    /// Check whether this cache is still active and performing periodic updates.
    pub async fn is_active(&self) -> bool {
        let container = self.update_task_handle.read().await;
        assert!(container.is_some(), "Update task should be created during entry creation");
        !container.as_ref().unwrap().is_finished()
    }

    /// Check whether this cache has been destroyed.
    async fn is_destroyed(&self) -> bool {
        self.update_task_handle.read().await.is_none()
    }

    /// Destroy the cache.
    /// Will make sure to stop the thread responsible for performing perodic updates.
    pub async fn destroy(&self) {
        assert!(!self.is_destroyed().await, "Attempted to destroy a cache that is already destroyed!");

        let mut container = self.update_task_handle.write().await;
        // We will consume the handle now.
        let handle = container.take().unwrap();
        if !handle.is_finished() {
            log::warn!("registry entry '{}': Destroying cache that is still active!", self.client);
            handle.abort();
        }
        if let Err(e) = handle.await {
            log::warn!("registry entry '{}': Encountered error running update handler: {e}", self.client)
        }
    }

    /// Load user and group information from keycloak and convert them into an LDAP tree.
    /// Will only load groups if the registry tells us to do so.
    async fn fetch(&self) -> Result<(), proto::LdapError> {
        let mut root = self.configuration.ldap_entry_builder.rootdse();
        root.add_subordinate(self.configuration.ldap_entry_builder.subschema());

        let mut organization = self.configuration.ldap_entry_builder.organization();
        let mut users: std::collections::HashMap<String, entry::LdapEntry> = self
            .service_account_client
            .query_users(self.configuration.num_users_to_fetch)
            .await?
            .into_iter()
            .filter_map(|user| Some((user.id.clone()?, self.configuration.ldap_entry_builder.build_from_keycloak_user(user)?)))
            .collect();

        if self.configuration.include_group_info {
            let groups: Vec<keycloak::types::GroupRepresentation> = self.service_account_client.query_named_groups().await?;
            for group in groups.into_iter() {
                let group_associated_users = self
                    .service_account_client
                    .query_users_in_group(
                        // We can unwrap here because we made sure to filter out groups without a id
                        group.id.as_ref().unwrap(),
                    )
                    .await?;
                let ldap_group =
                    self.configuration
                        .ldap_entry_builder
                        .build_from_keycloak_group_with_associated_users(group, &mut users, &group_associated_users);
                organization.add_subordinate(ldap_group);
            }
        }
        users.into_values().for_each(|user| {
            organization.add_subordinate(user);
        });

        root.add_subordinate(organization);
        // Crucial: We only acquire a lock now in order to not block querying requests while we update the data
        *self.root.write().await = root;
        Ok(())
    }

    /// Launch a new task responsible for periodically syncing the cache data from keycloak.
    pub fn trigger_scheduled_update(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(self.perform_scheduled_update())
    }

    /// Periodically sync the cache data from keycloak as long as the cache should not be pruned.
    async fn perform_scheduled_update(self: Arc<Self>) {
        loop {
            tokio::time::sleep(self.configuration.cache_update_interval).await;

            if self.should_be_pruned().await {
                // TODO: proper logging
                log::info!("registry entry '{}': Terminating scheduled update due to pruning condition.", self.client);
                return;
            }

            if self.fetch().await.is_ok() {
                log::debug!("registry entry '{}': Updated registry entry.", self.client);
            } else {
                log::info!("registry entry '{}': Terminating scheduled update due to update failure.", self.client);
                return;
            }
        }
    }

    /// Whether this cache should be evicted from the registry because it was not used for too long.
    async fn should_be_pruned(&self) -> bool {
        self.last_used.read().await.elapsed() >= self.configuration.max_entry_inactive_time
    }

    /// Check whether the provided password matches the one we have cached.
    /// Supposed to enable client bind authentication without having to involve the Keycloak.
    ///
    /// IMPORTANT: If the password of the client has been changed in the Keycloak during the last couple
    /// of seconds, this implementation might still accept the - now invalid - old client authentication and
    /// reject the new authentication instead. However, this will last only a couple of seconds
    /// until the next registry entry sync, when we notice that the old password has become invalid.
    pub fn check_password(&self, password: &str) -> Result<(), proto::LdapError> {
        if crypto::util::fixed_time_eq(password.as_ref(), self.password.as_ref()) {
            Ok(())
        } else {
            Err(proto::LdapError(
                LdapResultCode::InvalidCredentials,
                "Incorrect password for client supplied".to_string(),
            ))
        }
    }

    /// Answer an LDAP search query using our cached LDAP tree.
    /// Also registers the current timestamp as the time this cache was last used.
    pub async fn search(&self, search_request: &SearchRequest) -> Result<Vec<LdapSearchResultEntry>, proto::LdapError> {
        self.await_initialization().await;

        let mut instant = self.last_used.write().await;
        *instant = time::Instant::now();

        self.root.read().await.find(search_request)
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use rstest::{fixture, rstest};

    use super::*;
    use crate::{
        keycloak_service_account, proto,
        test_util::{test_constants, util},
    };

    const REGISTRY_HOUSEKEEPING_INTERVAL: Duration = Duration::from_millis(40);
    const CACHE_UPDATE_INTERVAL: Duration = Duration::from_millis(20);
    const MAX_ENTRY_INACTIVE_TIME: Duration = Duration::from_secs(60);

    #[fixture]
    fn registry(#[default(false)] include_group_info: bool) -> Arc<CacheRegistry> {
        CacheRegistry::new(
            CacheConfiguration {
                keycloak_service_account_client_builder: keycloak_service_account::ServiceAccountClientBuilder::new("".to_string(), "".to_string()),
                num_users_to_fetch: test_constants::DEFAULT_NUM_USERS_TO_FETCH,
                include_group_info,
                cache_update_interval: CACHE_UPDATE_INTERVAL,
                max_entry_inactive_time: MAX_ENTRY_INACTIVE_TIME,
                ldap_entry_builder: proto::tests::ldap_entry_builder(),
            },
            REGISTRY_HOUSEKEEPING_INTERVAL,
        )
    }

    mod cache_registry {
        use super::*;

        mod when_performing_housekeeping {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_prune_inactive_cache(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();

                {
                    let mut locked_store = registry.per_client_ldap_trees.write().await;
                    let cache = keycloak_client_ldap_cache::create_inactive_cache(
                        registry.configuration.clone(),
                        test_constants::DEFAULT_CLIENT_ID,
                        test_constants::DEFAULT_CLIENT_PASSWORD,
                    )
                    .await;
                    locked_store.insert(test_constants::DEFAULT_CLIENT_ID.to_string(), Arc::new(cache));
                }

                // when
                util::await_concurrent_task_progress(REGISTRY_HOUSEKEEPING_INTERVAL).await;
                assert!(!registry.per_client_ldap_trees.read().await.contains_key(test_constants::DEFAULT_CLIENT_ID));
            }

            #[rstest]
            #[tokio::test]
            async fn then_do_not_prune_active_cache(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();

                {
                    let mut locked_store = registry.per_client_ldap_trees.write().await;
                    let cache = Arc::new(
                        KeycloakClientLdapCache::create(
                            registry.configuration.clone(),
                            test_constants::DEFAULT_CLIENT_ID,
                            test_constants::DEFAULT_CLIENT_PASSWORD,
                        )
                        .await
                        .expect("Construction"),
                    );
                    cache.clone().initialize().await.unwrap();
                    locked_store.insert(test_constants::DEFAULT_CLIENT_ID.to_string(), cache);
                }

                // when
                util::await_concurrent_task_progress(REGISTRY_HOUSEKEEPING_INTERVAL).await;
                assert!(registry.per_client_ldap_trees.read().await.contains_key(test_constants::DEFAULT_CLIENT_ID));
            }
        }

        mod when_performing_ldap_bind_for_client {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_create_entry_for_new_client(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();

                // when
                registry
                    .perform_ldap_bind_for_client(test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .unwrap();

                // then
                assert!(registry.per_client_ldap_trees.read().await.contains_key(test_constants::DEFAULT_CLIENT_ID));
            }

            #[rstest]
            #[tokio::test]
            async fn and_client_is_inactive__then_create_new_one_and_destroy_old_one(registry: Arc<CacheRegistry>) {
                // given
                let old_cache: Arc<KeycloakClientLdapCache>;
                {
                    let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                    old_cache = Arc::new(
                        keycloak_client_ldap_cache::create_inactive_cache(
                            registry.configuration.clone(),
                            test_constants::DEFAULT_CLIENT_ID,
                            test_constants::DEFAULT_CLIENT_PASSWORD,
                        )
                        .await,
                    );
                    let mut locked_store = registry.per_client_ldap_trees.write().await;
                    locked_store.insert(test_constants::DEFAULT_CLIENT_ID.to_string(), old_cache.clone());
                }
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();

                // when
                registry
                    .perform_ldap_bind_for_client(test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .unwrap();

                // then
                assert!(!Arc::ptr_eq(
                    registry.per_client_ldap_trees.read().await.get(test_constants::DEFAULT_CLIENT_ID).unwrap(),
                    &old_cache
                ));
                assert!(old_cache.is_destroyed().await);
            }

            #[rstest]
            #[tokio::test]
            async fn then_check_password(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                registry
                    .perform_ldap_bind_for_client(test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .expect("registering should succeed");

                // when & then
                assert!(registry
                    .perform_ldap_bind_for_client(test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .is_ok());
                assert!(registry
                    .perform_ldap_bind_for_client(test_constants::DEFAULT_CLIENT_ID, "wrong-password")
                    .await
                    .is_err());
            }
        }

        mod when_obtaining_client_cache {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_return_it(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                registry
                    .perform_ldap_bind_for_client(test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .unwrap();

                // when & then
                assert!(registry.obtain_client_cache(test_constants::DEFAULT_CLIENT_ID).await.is_ok());
            }

            #[rstest]
            #[tokio::test]
            async fn for_unknown_client__then_return_error(registry: Arc<CacheRegistry>) {
                // when & then
                assert!(registry.obtain_client_cache(test_constants::DEFAULT_CLIENT_ID).await.is_err());
            }

            #[rstest]
            #[tokio::test]
            async fn for_inactive_client__then_return_error(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                {
                    let mut locked_store = registry.per_client_ldap_trees.write().await;
                    let cache = keycloak_client_ldap_cache::create_inactive_cache(
                        registry.configuration.clone(),
                        test_constants::DEFAULT_CLIENT_ID,
                        test_constants::DEFAULT_CLIENT_PASSWORD,
                    )
                    .await;
                    locked_store.insert(test_constants::DEFAULT_CLIENT_ID.to_string(), Arc::new(cache));
                }

                // when & then
                assert!(registry.obtain_client_cache(test_constants::DEFAULT_CLIENT_ID).await.is_err());
            }
        }
    }
    mod keycloak_client_ldap_cache {
        use super::*;

        pub async fn create_inactive_cache(configuration: Arc<CacheConfiguration>, client_id: &str, password: &str) -> KeycloakClientLdapCache {
            let client = KeycloakClientLdapCache::create(configuration, client_id, password).await.unwrap();
            {
                let mut handle_lock = client.update_task_handle.write().await;
                _ = handle_lock.insert(tokio::spawn(util::async_noop())); // This will make the task terminate immediately.
                                                                          // However, we still have to wait slightly due to scheduling overhead
                util::await_concurrent_task_progress(Duration::from_millis(10)).await;
            }
            client
        }
        mod when_create {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_fail_on_invalid_client_auth(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_err(LdapResultCode::InvalidCredentials);

                // when & then
                assert!(KeycloakClientLdapCache::create(
                    registry.configuration.clone(),
                    test_constants::DEFAULT_CLIENT_ID,
                    test_constants::DEFAULT_CLIENT_PASSWORD
                )
                .await
                .is_err());
            }
        }
        mod when_initialize {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_fetch_information(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let cache = Arc::new(
                    KeycloakClientLdapCache::create(
                        registry.configuration.clone(),
                        test_constants::DEFAULT_CLIENT_ID,
                        test_constants::DEFAULT_CLIENT_PASSWORD,
                    )
                    .await
                    .unwrap(),
                );

                // when
                cache.clone().initialize().await.unwrap();

                // then
                assert!(cache.root.read().await.has_subordinates());
            }

            #[rstest]
            #[tokio::test]
            async fn then_trigger_scheduled_update(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let client_cache = Arc::new(
                    KeycloakClientLdapCache::create(
                        registry.configuration.clone(),
                        test_constants::DEFAULT_CLIENT_ID,
                        test_constants::DEFAULT_CLIENT_PASSWORD,
                    )
                    .await
                    .unwrap(),
                );

                // when
                let initial_query_count = client_cache.service_account_client.call_count();
                client_cache.clone().initialize().await.unwrap();
                util::await_concurrent_task_progress(CACHE_UPDATE_INTERVAL).await;

                // then
                let current_query_count = client_cache.service_account_client.call_count();
                assert!(current_query_count > initial_query_count);
            }
        }

        mod when_checking_if_active {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn and_update_task_still_running__then_return_true(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let cache = Arc::new(
                    KeycloakClientLdapCache::create(
                        registry.configuration.clone(),
                        test_constants::DEFAULT_CLIENT_ID,
                        test_constants::DEFAULT_CLIENT_PASSWORD,
                    )
                    .await
                    .unwrap(),
                );

                // when
                cache.clone().initialize().await.unwrap();

                // then
                assert!(cache.is_active().await);
            }

            #[rstest]
            #[tokio::test]
            async fn and_update_task_no_longer_running__then_return_false(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let cache = KeycloakClientLdapCache::create(
                    registry.configuration.clone(),
                    test_constants::DEFAULT_CLIENT_ID,
                    test_constants::DEFAULT_CLIENT_PASSWORD,
                )
                .await
                .unwrap();

                // when
                _ = cache.update_task_handle.write().await.insert(tokio::spawn(util::async_noop()));
                util::await_concurrent_task_progress(Duration::from_millis(10)).await;

                // then
                assert!(!cache.is_active().await);
            }
        }

        mod when_destroying {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_it_is_marked_destroyed(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let cache = Arc::new(
                    KeycloakClientLdapCache::create(
                        registry.configuration.clone(),
                        test_constants::DEFAULT_CLIENT_ID,
                        test_constants::DEFAULT_CLIENT_PASSWORD,
                    )
                    .await
                    .unwrap(),
                );
                cache.clone().initialize().await.unwrap();

                // when
                cache.destroy().await;

                // then
                assert!(cache.is_destroyed().await);
            }

            #[rstest]
            #[tokio::test]
            async fn then_update_task_is_removed(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let cache = Arc::new(
                    KeycloakClientLdapCache::create(
                        registry.configuration.clone(),
                        test_constants::DEFAULT_CLIENT_ID,
                        test_constants::DEFAULT_CLIENT_PASSWORD,
                    )
                    .await
                    .unwrap(),
                );
                cache.clone().initialize().await.unwrap();

                // when
                cache.destroy().await;

                // then
                assert!(cache.update_task_handle.read().await.is_none());
            }
        }

        /// Note: The update will be scheduled automatically when creating the client.
        /// Only retrieving the initial query count on the service_account_client after creation is
        /// therefore not ideal, but it should be fine since it will take some time before the first
        /// update actually runs.
        /// If these tests become brittle, consider increasing the CACHE_UPDATE_INTERVAL for the tests.
        mod when_performing_scheduled_update {
            use std::ops::Sub;

            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_periodically_update_data(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let cache = Arc::new(
                    KeycloakClientLdapCache::create(
                        registry.configuration.clone(),
                        test_constants::DEFAULT_CLIENT_ID,
                        test_constants::DEFAULT_CLIENT_PASSWORD,
                    )
                    .await
                    .unwrap(),
                );

                // when
                let mut initial_query_count = cache.service_account_client.call_count();
                cache.clone().initialize().await.unwrap();

                // then
                for _ in 0..3 {
                    util::await_concurrent_task_progress(CACHE_UPDATE_INTERVAL).await;
                    let current_query_count = cache.service_account_client.call_count();
                    assert!(current_query_count > initial_query_count);
                    initial_query_count = current_query_count;
                }
            }

            #[rstest]
            #[tokio::test]
            async fn then_stop_when_inactive(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let cache = Arc::new(
                    KeycloakClientLdapCache::create(
                        registry.configuration.clone(),
                        test_constants::DEFAULT_CLIENT_ID,
                        test_constants::DEFAULT_CLIENT_PASSWORD,
                    )
                    .await
                    .unwrap(),
                );
                cache.clone().initialize().await.unwrap();

                // when
                *cache.last_used.write().await = time::Instant::now().sub(MAX_ENTRY_INACTIVE_TIME);
                util::await_concurrent_task_progress(CACHE_UPDATE_INTERVAL).await;

                // then
                assert!(cache.update_task_handle.read().await.as_ref().unwrap().is_finished());
            }

            #[rstest]
            #[tokio::test]
            async fn then_stop_on_update_error(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let cache = Arc::new(
                    KeycloakClientLdapCache::create(
                        registry.configuration.clone(),
                        test_constants::DEFAULT_CLIENT_ID,
                        test_constants::DEFAULT_CLIENT_PASSWORD,
                    )
                    .await
                    .unwrap(),
                );

                // when
                cache.clone().initialize().await.unwrap();
                cache.service_account_client.change_err(LdapResultCode::InvalidCredentials);
                util::await_concurrent_task_progress(CACHE_UPDATE_INTERVAL).await;

                // then
                assert!(cache.update_task_handle.read().await.as_ref().unwrap().is_finished());
            }
        }

        mod when_checking_password {
            use std::clone::Clone;

            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_accept_valid_password(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let entry = KeycloakClientLdapCache::create(
                    registry.configuration.clone(),
                    test_constants::DEFAULT_CLIENT_ID,
                    test_constants::DEFAULT_CLIENT_PASSWORD,
                )
                .await
                .unwrap();

                // when & then
                assert!(entry.check_password(test_constants::DEFAULT_CLIENT_PASSWORD).is_ok());
            }

            #[rstest]
            #[tokio::test]
            async fn then_reject_invalid_password(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let entry = KeycloakClientLdapCache::create(
                    registry.configuration.clone(),
                    test_constants::DEFAULT_CLIENT_ID,
                    test_constants::DEFAULT_CLIENT_PASSWORD,
                )
                .await
                .unwrap();

                // when & then
                assert!(entry.check_password("invalid-password").is_err());
            }
        }
    }
}
