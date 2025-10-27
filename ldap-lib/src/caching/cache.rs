use std::{sync::Arc, time};

use ldap3_proto::{LdapResultCode, LdapSearchResultEntry, SearchRequest};

use crate::{caching::configuration, dto, keycloak_service_account, proto};

/// A keycloak client LDAP registry keeps track of a set of user and (potentially) group information as visible to a certain keycloak client.
/// The information is provided in form of an LDAP tree.
/// Will periodically sync the LDAP information from keycloak.
pub struct KeycloakClientLdapCache {
    configuration: Arc<configuration::Configuration>,

    update_task_handle: tokio::sync::RwLock<Option<tokio::task::JoinHandle<()>>>,

    client: String,
    password: String,
    service_account_client: keycloak_service_account::ServiceAccountClient,
    last_used: tokio::sync::RwLock<time::Instant>,
    root: tokio::sync::RwLock<dto::LdapEntry>,
}

impl KeycloakClientLdapCache {
    /// Construct a new client cache.
    ///
    /// Will only succeed iff the entered credentials are valid.
    pub async fn create(configuration: Arc<configuration::Configuration>, client: &str, password: &str) -> Result<Self, proto::LdapError> {
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
            root: tokio::sync::RwLock::new(dto::LdapEntry::new("".to_string(), vec![])),
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
    pub(crate) async fn is_destroyed(&self) -> bool {
        self.update_task_handle.read().await.is_none()
    }

    /// Destroy the cache.
    /// Will make sure to stop the thread responsible for performing periodic updates.
    pub async fn destroy(&self) {
        assert!(!self.is_destroyed().await, "Attempted to destroy a cache that is already destroyed!");

        let mut container = self.update_task_handle.write().await;
        // We will consume the handle now.
        let handle = container.take().unwrap();
        if !handle.is_finished() {
            tracing::warn!(client = self.client, "Destroying cache even though it was still active!");
            handle.abort();
        }
        if let Err(e) = handle.await {
            tracing::warn!(client = self.client, error = ?e, "Cache has encountered an error running update handler")
        }
    }

    /// Load user and group information from keycloak and convert them into an LDAP tree.
    /// Will only load groups if the registry tells us to do so.
    async fn fetch(&self) -> Result<(), proto::LdapError> {
        let mut root = self.configuration.ldap_entry_builder.rootdse();
        root.add_subordinate(self.configuration.ldap_entry_builder.subschema());

        let mut organization = self.configuration.ldap_entry_builder.organization();
        let mut users: std::collections::HashMap<String, dto::LdapEntry> = self
            .service_account_client
            .query_users(self.configuration.num_users_to_fetch.unwrap_or(-1))
            .await?
            .into_iter()
            .filter_map(|user| Some((user.id.clone()?, self.configuration.ldap_entry_builder.build_from_keycloak_user(user)?)))
            .collect();

        if self.configuration.include_group_info {
            let groups: Vec<keycloak::types::GroupRepresentation> = self.service_account_client.query_named_groups().await?;
            for group in groups.into_iter() {
                let group_entry = self.fetch_group(group, None, &mut users).await?;
                organization.add_subordinate(group_entry);
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

    #[async_recursion::async_recursion]
    async fn fetch_group(
        &self,
        group: keycloak::types::GroupRepresentation,
        parent_group: Option<&dto::LdapEntry>,
        users: &mut std::collections::HashMap<String, dto::LdapEntry>,
    ) -> Result<dto::LdapEntry, proto::LdapError> {
        // We can unwrap here because we made sure to filter out groups without a id
        let group_id = group.id.as_ref().unwrap();
        let group_associated_users = self.service_account_client.query_users_in_group(group_id).await?;

        let subgroup_count = group.sub_group_count.unwrap_or(0);
        let sub_groups = if subgroup_count > 0 {
            self.service_account_client.query_sub_groups(group_id).await?
        } else {
            Vec::new()
        };

        let mut ldap_group =
            self.configuration
                .ldap_entry_builder
                .build_from_keycloak_group_with_associated_users(group, parent_group, users, &group_associated_users);

        for sub_group in sub_groups.into_iter() {
            let ldap_sub_group = self.fetch_group(sub_group, Some(&ldap_group), users).await?;
            ldap_group.add_subordinate(ldap_sub_group);
        }

        Ok(ldap_group)
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
                tracing::info!(client = self.client, "Terminating scheduled update due to pruning condition.");
                return;
            }

            if self.fetch().await.is_ok() {
                tracing::debug!(client = self.client, "Updated client cache.");
            } else {
                tracing::info!(client = self.client, "Terminating scheduled update due to update failure.");
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
pub(crate) mod test {
    use std::time::Duration;

    use rstest::{fixture, rstest};

    use super::*;
    use crate::test_util::{test_constants, util};

    pub const CACHE_UPDATE_INTERVAL: Duration = Duration::from_millis(20);
    pub const MAX_ENTRY_INACTIVE_TIME: Duration = Duration::from_secs(60);

    #[fixture]
    pub fn config(#[default(false)] include_group_info: bool) -> configuration::Configuration {
        configuration::Configuration {
            keycloak_service_account_client_builder: keycloak_service_account::ServiceAccountClientBuilder::new("".to_string(), "".to_string(), false),
            num_users_to_fetch: Some(test_constants::DEFAULT_NUM_USERS_TO_FETCH),
            include_group_info,
            cache_update_interval: CACHE_UPDATE_INTERVAL,
            max_entry_inactive_time: MAX_ENTRY_INACTIVE_TIME,
            ldap_entry_builder: proto::tests::ldap_entry_builder(),
        }
    }

    pub async fn create_inactive_cache(configuration: Arc<configuration::Configuration>, client_id: &str, password: &str) -> KeycloakClientLdapCache {
        let client = KeycloakClientLdapCache::create(configuration, client_id, password).await.unwrap();
        {
            let mut handle_lock = client.update_task_handle.write().await;
            _ = handle_lock.insert(tokio::spawn(util::async_noop())); // This will make the task terminate immediately.
            // However, we still have to wait slightly due to scheduling overhead
            util::await_concurrent_task_progress(time::Duration::from_millis(10)).await;
        }
        client
    }

    mod when_create {
        use super::*;

        #[rstest]
        #[tokio::test]
        async fn then_fail_on_invalid_client_auth(config: configuration::Configuration) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_err(LdapResultCode::InvalidCredentials);

            // when & then
            assert!(
                KeycloakClientLdapCache::create(Arc::new(config), test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
                    .await
                    .is_err()
            );
        }
    }
    mod when_initialize {
        use super::*;

        #[rstest]
        #[tokio::test]
        async fn then_fetch_information(config: configuration::Configuration) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
            let cache = Arc::new(
                KeycloakClientLdapCache::create(Arc::new(config), test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
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
        async fn then_trigger_scheduled_update(config: configuration::Configuration) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
            let client_cache = Arc::new(
                KeycloakClientLdapCache::create(Arc::new(config), test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
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
        async fn and_update_task_still_running__then_return_true(config: configuration::Configuration) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
            let cache = Arc::new(
                KeycloakClientLdapCache::create(Arc::new(config), test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
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
        async fn and_update_task_no_longer_running__then_return_false(config: configuration::Configuration) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
            let cache = KeycloakClientLdapCache::create(Arc::new(config), test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
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
        async fn then_it_is_marked_destroyed(config: configuration::Configuration) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
            let cache = Arc::new(
                KeycloakClientLdapCache::create(Arc::new(config), test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
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
        async fn then_update_task_is_removed(config: configuration::Configuration) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
            let cache = Arc::new(
                KeycloakClientLdapCache::create(Arc::new(config), test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
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
        async fn then_periodically_update_data(config: configuration::Configuration) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
            let cache = Arc::new(
                KeycloakClientLdapCache::create(Arc::new(config), test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
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
        async fn then_stop_when_inactive(config: configuration::Configuration) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
            let cache = Arc::new(
                KeycloakClientLdapCache::create(Arc::new(config), test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
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
        async fn then_stop_on_update_error(config: configuration::Configuration) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
            let cache = Arc::new(
                KeycloakClientLdapCache::create(Arc::new(config), test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
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
        use super::*;

        #[rstest]
        #[tokio::test]
        async fn then_accept_valid_password(config: configuration::Configuration) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
            let entry = KeycloakClientLdapCache::create(Arc::new(config), test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
                .await
                .unwrap();

            // when & then
            assert!(entry.check_password(test_constants::DEFAULT_CLIENT_PASSWORD).is_ok());
        }

        #[rstest]
        #[tokio::test]
        async fn then_reject_invalid_password(config: configuration::Configuration) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
            let entry = KeycloakClientLdapCache::create(Arc::new(config), test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
                .await
                .unwrap();

            // when & then
            assert!(entry.check_password("invalid-password").is_err());
        }
    }
}
