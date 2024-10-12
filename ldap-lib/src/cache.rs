use std::{sync::Arc, time};

use ldap3_proto::{LdapResultCode, LdapSearchResultEntry, SearchRequest};

use crate::{entry, keycloak_service_account, proto};

/// A thread-safe registry registry keeping track of and allowing access to all active client caches.
/// Will also provide configuration info applicable to all client caches.
pub struct CacheRegistry {
    pub keycloak_service_account_client_builder: keycloak_service_account::ServiceAccountClientBuilder,
    pub num_users_to_fetch: i32,
    pub include_group_info: bool,
    pub cache_update_interval: time::Duration,
    pub max_entry_inactive_time: time::Duration,
    pub ldap_entry_builder: entry::LdapEntryBuilder,
    per_client_ldap_trees: tokio::sync::RwLock<std::collections::HashMap<String, Arc<KeycloakClientLdapCache>>>,
}

impl CacheRegistry {
    pub fn new(
        service_account_builder: keycloak_service_account::ServiceAccountClientBuilder,
        num_users_to_fetch: i32,
        include_group_info: bool,
        cache_update_interval: time::Duration,
        max_entry_inactive_time: time::Duration,
        entry_builder: entry::LdapEntryBuilder,
    ) -> Self {
        Self {
            keycloak_service_account_client_builder: service_account_builder,
            num_users_to_fetch,
            include_group_info,
            cache_update_interval,
            max_entry_inactive_time,
            ldap_entry_builder: entry_builder,
            per_client_ldap_trees: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Register a client registry.
    async fn register_client_cache(&self, client: &str, cache_entry: Arc<KeycloakClientLdapCache>) {
        self.per_client_ldap_trees.write().await.insert(client.to_string(), cache_entry);
    }

    /// Unregister a client registry
    pub async fn unregister_client_cache(&self, client: &str) {
        self.per_client_ldap_trees.write().await.remove(client);
    }

    /// Perform a bind for a client with the corresponding password.
    ///
    /// If this registry did not yet know of a client registry for this client, create one now. If authenticating using the provided
    /// credentials against Keycloak fails, an error is returned; otherwise, the operation succeeds and the entry is
    /// inserted into the registry.
    ///
    /// If the client is already present in the registry, only check whether the provided password matches the last known
    /// correct one (see note on the [KeycloakClientLdapCache::check_password] method).
    pub async fn perform_ldap_bind_for_client(self: &Arc<Self>, client: &str, password: &str) -> Result<(), proto::LdapError> {
        if let Some(cache_entry) = self.per_client_ldap_trees.read().await.get(client) {
            return cache_entry.check_password(password);
        }

        log::debug!("registry: Encountered unknown client '{client}', registering it");
        let cache_entry = KeycloakClientLdapCache::create_and_initialize(self.clone(), client, password).await?;
        self.register_client_cache(client, cache_entry).await;
        // If creation of the cache_entry has succeeded, we know that the credentials must have been valid.
        Ok(())
    }

    /// Return the registry for the given client ID.
    pub async fn obtain_client_cache(&self, client: &str) -> Result<Arc<KeycloakClientLdapCache>, proto::LdapError> {
        if let Some(cache_entry) = self.per_client_ldap_trees.read().await.get(client) {
            Ok(cache_entry.clone())
        } else {
            Err(proto::LdapError(
                LdapResultCode::InvalidCredentials,
                "Unknown client! Maybe the client credentials have changed during an active bind session?".to_string(),
            ))
        }
    }
}

/// A keycloak client LDAP registry keeps track of a set of user and (potentially) group information as visible to a certain keycloak client.
/// The information is provided in form of an LDAP tree.
/// Will periodically sync the LDAP information from keycloak.
/// Will also automatically unregister itself from the CacheRegistry when it has become obsolete (for example, because the stored client credentials
/// have become invalid).
pub struct KeycloakClientLdapCache {
    cache_registry: Arc<CacheRegistry>,

    client: String,
    password: String,
    service_account_client: keycloak_service_account::ServiceAccountClient,
    last_used: tokio::sync::RwLock<time::Instant>,
    root: tokio::sync::RwLock<entry::LdapEntry>,
}

impl KeycloakClientLdapCache {
    /// Construct a new client cache.
    /// Will make sure to perform an initial data fetching to populate the cache.
    /// Will also initialize the cache lifecycle by triggering scheduled updates.
    ///
    /// Will only succeed iff the entered credentials are valid.
    pub async fn create_and_initialize(registry: Arc<CacheRegistry>, client: &str, password: &str) -> Result<Arc<Self>, proto::LdapError> {
        let service_account_client = registry.keycloak_service_account_client_builder.new_service_account(client, password).await?;
        let cache_entry = Arc::new(Self {
            cache_registry: registry,
            client: client.to_owned(),
            password: password.to_owned(),
            service_account_client,
            last_used: tokio::sync::RwLock::new(time::Instant::now()),
            root: tokio::sync::RwLock::new(entry::LdapEntry::new("".to_string(), vec![])),
        });
        cache_entry.fetch().await?;
        cache_entry.clone().trigger_scheduled_update();
        Ok(cache_entry)
    }

    /// Load user and group information from keycloak and convert them into an LDAP tree.
    /// Will only load groups if the registry tells us to do so.
    async fn fetch(&self) -> Result<(), proto::LdapError> {
        let mut root = self.cache_registry.ldap_entry_builder.rootdse();
        root.add_subordinate(self.cache_registry.ldap_entry_builder.subschema());

        let mut organization = self.cache_registry.ldap_entry_builder.organization();
        let mut users: std::collections::HashMap<String, entry::LdapEntry> = self
            .service_account_client
            .query_users(self.cache_registry.num_users_to_fetch)
            .await?
            .into_iter()
            .filter_map(|user| Some((user.id.clone()?, self.cache_registry.ldap_entry_builder.build_from_keycloak_user(user)?)))
            .collect();

        if self.cache_registry.include_group_info {
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
                    self.cache_registry
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
    pub fn trigger_scheduled_update(self: Arc<Self>) {
        tokio::spawn(self.perform_scheduled_update());
    }

    /// Periodically sync the cache data from keycloak.
    /// The cache will REMOVE ITSELF from the registry if it should be pruned or updating has failed.
    async fn perform_scheduled_update(self: Arc<Self>) {
        loop {
            tokio::time::sleep(self.cache_registry.cache_update_interval).await;

            if self.should_be_pruned().await {
                log::info!("registry entry '{}': Pruning registry entry.", self.client);
                self.cache_registry.unregister_client_cache(&self.client).await;
                return;
            }

            if self.fetch().await.is_ok() {
                log::debug!("registry entry '{}': Updated registry entry.", self.client);
            } else {
                log::info!("registry entry '{}': Pruning registry entry because update failed.", self.client);
                self.cache_registry.unregister_client_cache(&self.client).await;
                return;
            }
        }
    }

    /// Whether this cache should be evicted from the registry because it was not used for too long.
    async fn should_be_pruned(&self) -> bool {
        self.last_used.read().await.elapsed() >= self.cache_registry.max_entry_inactive_time
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

    async fn initialized(&self) -> bool {
        self.root.read().await.has_subordinates()
    }

    /// Answer an LDAP search query using our cached LDAP tree.
    /// Also registers the current timestamp as the time this cache was last used.
    pub async fn search(&self, search_request: &SearchRequest) -> Result<Vec<LdapSearchResultEntry>, proto::LdapError> {
        assert!(
            self.initialized().await,
            "A registry entry must be initialized before being able to serve search requests!"
        );

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
    use crate::{keycloak_service_account, proto};

    const CACHE_UPDATE_INTERVAL: Duration = Duration::from_millis(20);
    const CACHE_UPDATE_CHECK_INTERVAL: Duration = Duration::from_millis(25);
    const MAX_ENTRY_INACTIVE_TIME: Duration = Duration::from_secs(60);

    #[fixture]
    fn registry(#[default(false)] include_group_info: bool) -> Arc<CacheRegistry> {
        Arc::new(CacheRegistry::new(
            keycloak_service_account::ServiceAccountClientBuilder::new("".to_string(), "".to_string()),
            proto::tests::DEFAULT_USERS_TO_FETCH,
            include_group_info,
            CACHE_UPDATE_INTERVAL,
            MAX_ENTRY_INACTIVE_TIME,
            proto::tests::entry_builder(),
        ))
    }

    mod cache_registry {
        use super::*;

        mod when_perform_ldap_bind_for_client {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_create_entry_for_new_client(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();

                // when
                registry
                    .perform_ldap_bind_for_client(proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .expect("registering should succeed");

                // then
                assert!(registry.per_client_ldap_trees.read().await.contains_key(proto::tests::DEFAULT_CLIENT_ID));
            }

            #[rstest]
            #[tokio::test]
            async fn then_check_password(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                registry
                    .perform_ldap_bind_for_client(proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .expect("registering should succeed");

                // when & then
                assert!(registry
                    .perform_ldap_bind_for_client(proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .is_ok());
                assert!(registry
                    .perform_ldap_bind_for_client(proto::tests::DEFAULT_CLIENT_ID, "wrong-password")
                    .await
                    .is_err());
            }
        }

        mod when_unregistering_entry {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_it_is_gone(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                registry
                    .perform_ldap_bind_for_client(proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .expect("registering should succeed");

                // when
                registry.unregister_client_cache(proto::tests::DEFAULT_CLIENT_ID).await;

                // then
                assert!(!registry.per_client_ldap_trees.read().await.contains_key(proto::tests::DEFAULT_CLIENT_ID));
            }
        }

        mod when_obtaining_client_cache {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn for_unknown_client__then_return_error(registry: Arc<CacheRegistry>) {
                // when & then
                assert!(registry.obtain_client_cache(proto::tests::DEFAULT_CLIENT_ID).await.is_err());
            }
        }
    }

    mod keycloak_client_ldap_cache {
        use super::*;

        mod when_create {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_fetch_information(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();

                // when
                let entry = KeycloakClientLdapCache::create_and_initialize(registry, proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .expect("creation should succeed");

                // then
                assert!(entry.root.read().await.has_subordinates());
            }

            #[rstest]
            #[tokio::test]
            async fn then_fail_on_invalid_client_auth(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_err(LdapResultCode::InvalidCredentials);

                // when & then
                assert!(
                    KeycloakClientLdapCache::create_and_initialize(registry, proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                        .await
                        .is_err()
                );
            }

            #[rstest]
            #[tokio::test]
            async fn then_trigger_scheduled_update(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let client_cache =
                    KeycloakClientLdapCache::create_and_initialize(registry, proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                        .await
                        .unwrap();

                // when
                let initial_query_count = client_cache.service_account_client.call_count();
                tokio::time::sleep(CACHE_UPDATE_CHECK_INTERVAL).await;

                // then
                let current_query_count = client_cache.service_account_client.call_count();
                assert!(current_query_count > initial_query_count);
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
                let entry =
                    KeycloakClientLdapCache::create_and_initialize(registry.clone(), proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                        .await
                        .unwrap();

                // when
                let mut initial_query_count = entry.service_account_client.call_count();

                // then
                for _ in 0..3 {
                    tokio::time::sleep(CACHE_UPDATE_CHECK_INTERVAL).await;
                    let current_query_count = entry.service_account_client.call_count();
                    assert!(current_query_count > initial_query_count);
                    initial_query_count = current_query_count;
                }
            }

            #[rstest]
            #[tokio::test]
            async fn then_prune_old_entry(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let entry =
                    KeycloakClientLdapCache::create_and_initialize(registry.clone(), proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                        .await
                        .unwrap();
                registry.register_client_cache(proto::tests::DEFAULT_CLIENT_ID, entry.clone()).await;

                // when
                *entry.last_used.write().await = time::Instant::now().sub(MAX_ENTRY_INACTIVE_TIME);
                tokio::time::sleep(CACHE_UPDATE_CHECK_INTERVAL).await;

                // then
                assert!(!registry.per_client_ldap_trees.read().await.contains_key(proto::tests::DEFAULT_CLIENT_ID));
            }

            #[rstest]
            #[tokio::test]
            async fn then_prune_entry_on_update_error(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let entry =
                    KeycloakClientLdapCache::create_and_initialize(registry.clone(), proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                        .await
                        .unwrap();
                registry.register_client_cache(proto::tests::DEFAULT_CLIENT_ID, entry.clone()).await;

                // when
                entry.service_account_client.change_err(LdapResultCode::InvalidCredentials);
                tokio::time::sleep(CACHE_UPDATE_CHECK_INTERVAL).await;

                // then
                assert!(!registry.per_client_ldap_trees.read().await.contains_key(proto::tests::DEFAULT_CLIENT_ID));
            }
        }

        mod when_checking_password {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_accept_valid_password(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let entry = KeycloakClientLdapCache::create_and_initialize(registry, proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .unwrap();

                // when & then
                assert!(entry.check_password(proto::tests::DEFAULT_CLIENT_PASSWORD).is_ok());
            }

            #[rstest]
            #[tokio::test]
            async fn then_reject_invalid_password(registry: Arc<CacheRegistry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let entry = KeycloakClientLdapCache::create_and_initialize(registry, proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .unwrap();

                // when & then
                assert!(entry.check_password("invalid-password").is_err());
            }
        }
    }
}
