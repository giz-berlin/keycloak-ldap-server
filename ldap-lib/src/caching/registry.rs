use std::{sync::Arc, time};

use ldap3_proto::LdapResultCode;

use crate::{
    caching::{cache, configuration},
    proto,
};

pub const REGISTRY_DEFAULT_HOUSEKEEPING_INTERVAL: time::Duration = time::Duration::from_secs(5);

/// A thread-safe registry keeping track of and allowing access to all active client caches.
/// Will periodically evict inactive caches.
pub struct Registry<T: crate::interface::Target> {
    config: Arc<configuration::Configuration<T>>,
    per_client_ldap_trees: tokio::sync::RwLock<std::collections::HashMap<String, Arc<cache::KeycloakClientLdapCache<T>>>>,
}

impl<T: crate::interface::Target> Registry<T> {
    /// Create a new registry and initialize housekeeping tasks.
    pub fn new(config: configuration::Configuration<T>, housekeeping_interval: time::Duration) -> Arc<Self> {
        let registry = Arc::new(Self {
            config: Arc::new(config),
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
                tracing::info!(client, "Evicting cache for client from registry");
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
        let new_cache_entry: Arc<cache::KeycloakClientLdapCache<T>>;

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

            tracing::info!(new_client = client, "Encountered new client, registering it");
            new_cache_entry = Arc::new(cache::KeycloakClientLdapCache::create(self.config.clone(), client, password).await?);
            locked_store.insert(client.to_string(), new_cache_entry.clone());

            // We do not need to check the password here anymore:
            // If creation of the cache_entry has succeeded, we know that the credentials must have been valid.
        }

        new_cache_entry.initialize().await?;

        Ok(())
    }

    /// Return the cache for the given client ID.
    pub async fn obtain_client_cache(&self, client: &str) -> Result<Arc<cache::KeycloakClientLdapCache<T>>, proto::LdapError> {
        if let Some(cache_entry) = self.per_client_ldap_trees.read().await.get(client)
            && cache_entry.is_active().await
        {
            return Ok(cache_entry.clone());
        }

        Err(proto::LdapError(
            LdapResultCode::InvalidCredentials,
            "Unknown client! Maybe the client credentials have changed during an active bind session?".to_string(),
        ))
    }

    /// Unregister a client cache. Will make use of an already existing lock to perform the action.
    async fn _unregister_client_cache(
        &self,
        locked_store: &mut tokio::sync::RwLockWriteGuard<'_, std::collections::HashMap<String, Arc<cache::KeycloakClientLdapCache<T>>>>,
        client: &str,
    ) {
        if let Some(cache_entry) = locked_store.get_mut(client) {
            cache_entry.destroy().await;
            locked_store.remove(client);
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use rstest::{fixture, rstest};

    use super::*;
    use crate::{
        keycloak_service_account,
        test_util::{test_constants, util},
    };

    const REGISTRY_HOUSEKEEPING_INTERVAL: Duration = Duration::from_millis(40);

    #[fixture]
    fn registry(#[default(false)] include_group_info: bool) -> Arc<Registry<crate::interface::tests::DummyTarget>> {
        Registry::new(cache::test::config(include_group_info), REGISTRY_HOUSEKEEPING_INTERVAL)
    }

    mod cache_registry {
        use super::*;

        mod when_performing_housekeeping {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_prune_inactive_cache(registry: Arc<Registry<crate::interface::tests::DummyTarget>>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();

                {
                    let mut locked_store = registry.per_client_ldap_trees.write().await;
                    let cache = cache::test::create_inactive_cache(
                        registry.config.clone(),
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
            async fn then_do_not_prune_active_cache(registry: Arc<Registry<crate::interface::tests::DummyTarget>>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();

                {
                    let mut locked_store = registry.per_client_ldap_trees.write().await;
                    let cache = Arc::new(
                        cache::KeycloakClientLdapCache::create(
                            registry.config.clone(),
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
            async fn then_create_entry_for_new_client(registry: Arc<Registry<crate::interface::tests::DummyTarget>>) {
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
            async fn and_client_is_inactive__then_create_new_one_and_destroy_old_one(registry: Arc<Registry<crate::interface::tests::DummyTarget>>) {
                // given
                let old_cache: Arc<cache::KeycloakClientLdapCache<crate::interface::tests::DummyTarget>>;
                {
                    let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                    old_cache = Arc::new(
                        cache::test::create_inactive_cache(
                            registry.config.clone(),
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
            async fn then_check_password(registry: Arc<Registry<crate::interface::tests::DummyTarget>>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                registry
                    .perform_ldap_bind_for_client(test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .expect("registering should succeed");

                // when & then
                assert!(
                    registry
                        .perform_ldap_bind_for_client(test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
                        .await
                        .is_ok()
                );
                assert!(
                    registry
                        .perform_ldap_bind_for_client(test_constants::DEFAULT_CLIENT_ID, "wrong-password")
                        .await
                        .is_err()
                );
            }
        }

        mod when_obtaining_client_cache {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_return_it(registry: Arc<Registry<crate::interface::tests::DummyTarget>>) {
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
            async fn for_unknown_client__then_return_error(registry: Arc<Registry<crate::interface::tests::DummyTarget>>) {
                // when & then
                assert!(registry.obtain_client_cache(test_constants::DEFAULT_CLIENT_ID).await.is_err());
            }

            #[rstest]
            #[tokio::test]
            async fn for_inactive_client__then_return_error(registry: Arc<Registry<crate::interface::tests::DummyTarget>>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
                {
                    let mut locked_store = registry.per_client_ldap_trees.write().await;
                    let cache = cache::test::create_inactive_cache(
                        registry.config.clone(),
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
}
