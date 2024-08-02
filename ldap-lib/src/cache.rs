use std::{sync::Arc, time};

use ldap3_proto::{LdapResultCode, LdapSearchResultEntry, SearchRequest};

use crate::{entry, keycloak_service_account, proto};

/// A thread-safe cache storing LDAP user and (optionally) group information visible to different
/// Keycloak clients.
pub struct LdapTreeCache {
    pub keycloak_service_account_client_builder: keycloak_service_account::ServiceAccountClientBuilder,
    pub num_users_to_fetch: i32,
    pub include_group_info: bool,
    pub cache_update_interval: time::Duration,
    pub max_entry_inactive_time: time::Duration,
    pub ldap_entry_builder: entry::LdapEntryBuilder,
    per_client_ldap_trees: tokio::sync::RwLock<std::collections::HashMap<String, Arc<CacheEntry>>>,
}

impl LdapTreeCache {
    pub fn new(
        service_account_builder: keycloak_service_account::ServiceAccountClientBuilder,
        num_users_to_fetch: i32,
        include_group_info: bool,
        cache_update_interval: time::Duration,
        max_entry_inactive_time: time::Duration,
        entry_builder: entry::LdapEntryBuilder,
    ) -> Arc<Self> {
        Arc::new(Self {
            keycloak_service_account_client_builder: service_account_builder,
            num_users_to_fetch,
            include_group_info,
            cache_update_interval,
            max_entry_inactive_time,
            ldap_entry_builder: entry_builder,
            per_client_ldap_trees: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        })
    }

    /// Register a new client and check the corresponding password.
    ///
    /// If the client did not have a corresponding cache entry, create a new one. If authenticating using the provided
    /// credentials against Keycloak fails, an error is returned; otherwise, the operation succeeds and the entry is
    /// inserted into the cache.
    ///
    /// If the client is already present in the cache, only check whether the provided password matches the last known
    /// correct one (see note on the CacheEntry::check_password method).
    pub async fn register_client(self: &Arc<Self>, client: &str, password: &str) -> Result<(), proto::LdapError> {
        if let Some(cache_entry) = self.per_client_ldap_trees.read().await.get(client) {
            return cache_entry.check_password(password);
        }

        log::debug!("Cache: Encountered unknown client '{client}', adding it");
        let cache_entry = CacheEntry::new(self.clone(), client, password).await?;
        cache_entry.clone().trigger_scheduled_update();
        self.insert_entry(client, cache_entry).await;
        // If creation of the cache_entry has succeeded, we know that the credentials must have been valid.
        Ok(())
    }

    /// Insert an entry into the cache.
    async fn insert_entry(&self, client: &str, cache_entry: Arc<CacheEntry>) {
        self.per_client_ldap_trees.write().await.insert(client.to_string(), cache_entry);
    }

    /// Remove an entry from the cache.
    pub async fn remove_entry(&self, client: &str) {
        self.per_client_ldap_trees.write().await.remove(client);
    }

    /// Answer an LDAP search directly from the cache.
    ///
    /// Trying to request information for a client without a corresponding entry in the cache is considered illegal because that
    /// would mean that the client was either not properly bound beforehand or that the credentials the client originally bound
    /// with have been revoked during the active session.
    pub async fn search(&self, client: &str, search_request: &SearchRequest) -> Result<Vec<LdapSearchResultEntry>, proto::LdapError> {
        if let Some(cache_entry) = self.per_client_ldap_trees.read().await.get(client) {
            cache_entry.search(search_request).await
        } else {
            Err(proto::LdapError(
                LdapResultCode::InvalidCredentials,
                "Can only perform LDAP search for known bind client! Maybe the client credentials have changed during an active bind session?".to_string(),
            ))
        }
    }
}

/// A cache entry keeping track of a set of keycloak client credentials and user (and potentially group) information in form of an LDAP tree.
/// Will periodically sync the LDAP information from keycloak. Will also decide about its own eviction from the cache.
struct CacheEntry {
    client: String,
    password: String,
    containing_cache: Arc<LdapTreeCache>,
    service_account_client: keycloak_service_account::ServiceAccountClient,
    last_used: tokio::sync::RwLock<time::Instant>,
    root: tokio::sync::RwLock<entry::LdapEntry>,
}

impl CacheEntry {
    pub async fn new(containing_cache: Arc<LdapTreeCache>, client: &str, password: &str) -> Result<Arc<Self>, proto::LdapError> {
        let service_account_client = containing_cache
            .keycloak_service_account_client_builder
            .new_service_account(client, password)
            .await?;
        let cache_entry = Arc::new(Self {
            client: client.to_owned(),
            password: password.to_owned(),
            containing_cache,
            service_account_client,
            last_used: tokio::sync::RwLock::new(time::Instant::now()),
            root: tokio::sync::RwLock::new(entry::LdapEntry::new("".to_string(), vec![])),
        });
        cache_entry.fetch().await?;
        Ok(cache_entry)
    }

    /// Load user and group information from keycloak and converts them into an LDAP tree.
    /// Will only load groups if the containing cache was configured to do so.
    pub async fn fetch(&self) -> Result<(), proto::LdapError> {
        let mut root = self.containing_cache.ldap_entry_builder.rootdse();
        root.add_subordinate(self.containing_cache.ldap_entry_builder.subschema());

        let mut organization = self.containing_cache.ldap_entry_builder.organization();
        let mut users: std::collections::HashMap<String, entry::LdapEntry> = self
            .service_account_client
            .query_users(self.containing_cache.num_users_to_fetch)
            .await?
            .into_iter()
            .filter_map(|user| Some((user.id.clone()?, self.containing_cache.ldap_entry_builder.build_from_keycloak_user(user)?)))
            .collect();

        if self.containing_cache.include_group_info {
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
                    self.containing_cache
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

    /// Launch a new task responsible for periodically syncing the cache entry from keycloak.
    pub fn trigger_scheduled_update(self: Arc<Self>) {
        tokio::spawn(self.perform_scheduled_update());
    }

    /// Periodically sync the cache entry from keycloak.
    /// The cache entry will REMOVE ITSELF from the cache if it should be pruned or updating has failed.
    async fn perform_scheduled_update(self: Arc<Self>) {
        loop {
            tokio::time::sleep(self.containing_cache.cache_update_interval).await;

            if self.should_be_pruned().await {
                log::info!("Cache entry '{}': Pruning cache entry.", self.client);
                self.containing_cache.remove_entry(&self.client).await;
                return;
            }

            if self.fetch().await.is_ok() {
                log::debug!("Cache entry '{}': Updated cache entry.", self.client);
            } else {
                log::info!("Cache entry '{}': Pruning cache entry because update failed.", self.client);
                self.containing_cache.remove_entry(&self.client).await;
                return;
            }
        }
    }

    /// Whether this entry should be evicted from the cache because it was not used for too long.
    async fn should_be_pruned(&self) -> bool {
        self.last_used.read().await.elapsed() >= self.containing_cache.max_entry_inactive_time
    }

    /// Check whether the provided password matches the one we have cached.
    /// Supposed to enable client bind authentication without having to involve the Keycloak.
    ///
    /// IMPORTANT: If the password of the client has been changed in the Keycloak during the last couple
    /// of seconds, this implementation might still accept the - now invalid - old client authentication and
    /// reject the new authentication instead. However, this will last only a couple of seconds
    /// until the next cache entry sync, when we notice that the old password has become invalid.
    pub fn check_password(&self, password: &str) -> Result<(), proto::LdapError> {
        if password == self.password {
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
    /// Also registers the current timestamp as the time this cache entry was last used.
    pub async fn search(&self, search_request: &SearchRequest) -> Result<Vec<LdapSearchResultEntry>, proto::LdapError> {
        assert!(
            self.initialized().await,
            "A cache entry must be initialized before being able to serve search requests!"
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
    fn cache(#[default(false)] include_group_info: bool) -> Arc<LdapTreeCache> {
        LdapTreeCache::new(
            keycloak_service_account::ServiceAccountClientBuilder::new("".to_string(), "".to_string()),
            proto::tests::DEFAULT_USERS_TO_FETCH,
            include_group_info,
            CACHE_UPDATE_INTERVAL,
            MAX_ENTRY_INACTIVE_TIME,
            proto::tests::entry_builder(),
        )
    }

    mod tree_cache {
        use super::*;

        mod when_registering_client {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_create_entry_for_new_client(cache: Arc<LdapTreeCache>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();

                // when
                cache
                    .register_client(proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .expect("registering should succeed");

                // then
                assert!(cache.per_client_ldap_trees.read().await.contains_key(proto::tests::DEFAULT_CLIENT_ID));
            }

            #[rstest]
            #[tokio::test]
            async fn then_check_password(cache: Arc<LdapTreeCache>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                cache
                    .register_client(proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .expect("registering should succeed");

                // when & then
                assert!(cache
                    .register_client(proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .is_ok());
                assert!(cache.register_client(proto::tests::DEFAULT_CLIENT_ID, "wrong-password").await.is_err());
            }

            #[rstest]
            #[tokio::test]
            async fn then_trigger_scheduled_update(cache: Arc<LdapTreeCache>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                cache
                    .register_client(proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .expect("registering should succeed");
                let read_lock = cache.per_client_ldap_trees.read().await;
                let service_account_client = &read_lock.get(proto::tests::DEFAULT_CLIENT_ID).unwrap().service_account_client;

                // when
                let initial_query_count = service_account_client.call_count();
                tokio::time::sleep(CACHE_UPDATE_CHECK_INTERVAL).await;

                // then
                let current_query_count = service_account_client.call_count();
                assert!(current_query_count > initial_query_count);
            }
        }

        mod when_removing_entry {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_it_is_gone(cache: Arc<LdapTreeCache>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                cache
                    .register_client(proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .expect("registering should succeed");

                // when
                cache.remove_entry(proto::tests::DEFAULT_CLIENT_ID).await;

                // then
                assert!(!cache.per_client_ldap_trees.read().await.contains_key(proto::tests::DEFAULT_CLIENT_ID));
            }
        }

        mod when_searching {
            use ldap3_proto::{LdapFilter, LdapSearchScope};

            use super::*;

            #[fixture]
            fn search_request() -> SearchRequest {
                SearchRequest {
                    msgid: 0,
                    base: "".to_string(),
                    scope: LdapSearchScope::Base,
                    filter: LdapFilter::Present("".to_string()),
                    attrs: vec![],
                }
            }

            #[rstest]
            #[tokio::test]
            async fn for_unknown_client__then_return_error(cache: Arc<LdapTreeCache>, search_request: SearchRequest) {
                // when & then
                assert!(cache.search(proto::tests::DEFAULT_CLIENT_ID, &search_request).await.is_err());
            }
        }
    }

    mod cache_entry {
        use super::*;

        mod when_create {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_fetch_information(cache: Arc<LdapTreeCache>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();

                // when
                let entry = CacheEntry::new(cache, proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .expect("creation should succeed");

                // then
                assert!(entry.root.read().await.has_subordinates());
            }

            #[rstest]
            #[tokio::test]
            async fn then_fail_on_invalid_client_auth(cache: Arc<LdapTreeCache>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_err(LdapResultCode::InvalidCredentials);

                // when & then
                assert!(CacheEntry::new(cache, proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .is_err());
            }
        }

        mod when_performing_scheduled_update {
            use std::ops::Sub;

            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_periodically_update_data(cache: Arc<LdapTreeCache>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let entry = CacheEntry::new(cache.clone(), proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .unwrap();

                // when
                let mut initial_query_count = entry.service_account_client.call_count();
                entry.clone().trigger_scheduled_update();

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
            async fn then_prune_old_entry(cache: Arc<LdapTreeCache>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let entry = CacheEntry::new(cache.clone(), proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .unwrap();
                cache.insert_entry(proto::tests::DEFAULT_CLIENT_ID, entry.clone()).await;

                // when
                *entry.last_used.write().await = time::Instant::now().sub(MAX_ENTRY_INACTIVE_TIME);
                entry.trigger_scheduled_update();
                tokio::time::sleep(CACHE_UPDATE_CHECK_INTERVAL).await;

                // then
                assert!(!cache.per_client_ldap_trees.read().await.contains_key(proto::tests::DEFAULT_CLIENT_ID));
            }

            #[rstest]
            #[tokio::test]
            async fn then_prune_entry_on_update_error(cache: Arc<LdapTreeCache>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let entry = CacheEntry::new(cache.clone(), proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .unwrap();
                cache.insert_entry(proto::tests::DEFAULT_CLIENT_ID, entry.clone()).await;

                // when
                entry.service_account_client.change_err(LdapResultCode::InvalidCredentials);
                entry.trigger_scheduled_update();
                tokio::time::sleep(CACHE_UPDATE_CHECK_INTERVAL).await;

                // then
                assert!(!cache.per_client_ldap_trees.read().await.contains_key(proto::tests::DEFAULT_CLIENT_ID));
            }
        }

        mod when_checking_password {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_accept_valid_password(cache: Arc<LdapTreeCache>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let entry = CacheEntry::new(cache, proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .unwrap();

                // when & then
                assert!(entry.check_password(proto::tests::DEFAULT_CLIENT_PASSWORD).is_ok());
            }

            #[rstest]
            #[tokio::test]
            async fn then_reject_invalid_password(cache: Arc<LdapTreeCache>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                let entry = CacheEntry::new(cache, proto::tests::DEFAULT_CLIENT_ID, proto::tests::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .unwrap();

                // when & then
                assert!(entry.check_password("invalid-password").is_err());
            }
        }
    }
}
