/// This will use the real or the mock implementation, depending on whether we are compiling for tests or not.
#[mockall_double::double]
pub use client::ServiceAccountClient;

use crate::proto;

/// A builder to construct keycloak service account clients for a pre-configured Keycloak server and realm.
pub struct ServiceAccountClientBuilder {
    keycloak_address: String,
    realm: String,
    insecure_disable_tls_verification: bool,
}

impl ServiceAccountClientBuilder {
    pub fn new(keycloak_address: String, realm: String, insecure_disable_tls_verification: bool) -> Self {
        Self {
            keycloak_address,
            realm,
            insecure_disable_tls_verification,
        }
    }

    /// Construct a new client using provided service account credentials.
    /// Will verify that the credentials authenticate successfully.
    pub async fn new_service_account(&self, client_id: &str, client_secret: &str) -> Result<ServiceAccountClient, proto::LdapError> {
        let mut reqwest_builder = reqwest::Client::builder();
        reqwest_builder = reqwest_builder.danger_accept_invalid_certs(self.insecure_disable_tls_verification);

        // Note that the token we receive is not validated, but that might be fine in our case.
        // Also, since the acquire method is not public, we need to do some API request to validate we actually have a working client...
        let keycloak_client = keycloak::KeycloakServiceAccountAdminTokenRetriever::create_with_custom_realm(
            client_id,
            client_secret,
            &self.realm,
            reqwest_builder.build().unwrap(),
        );

        let service_account = ServiceAccountClient::new(
            keycloak::KeycloakAdmin::new(&self.keycloak_address, keycloak_client, reqwest::Client::new()),
            self.realm.clone(),
        );

        // Verify credentials are actually working
        service_account.query_users(1).await?;

        Ok(service_account)
    }
}

#[cfg(not(test))]
mod client {
    use std::fmt::Formatter;

    use ldap3_proto::LdapResultCode;

    use super::*;

    /// A keycloak service account client that has been verified to authenticate successfully.
    /// Used to retrieve user-information for a single realm.
    pub struct ServiceAccountClient {
        client: keycloak::KeycloakAdmin<keycloak::KeycloakServiceAccountAdminTokenRetriever>,
        target_realm: String,
    }

    impl ServiceAccountClient {
        pub fn new(client: keycloak::KeycloakAdmin<keycloak::KeycloakServiceAccountAdminTokenRetriever>, target_realm: String) -> Self {
            Self { client, target_realm }
        }

        /// Convert a keycloakError into an appropriate LdapError.
        /// Also use the provided filter function to remove unwanted results from the resource data.
        fn error_convert_and_filter<Resource, Filter>(
            resource_name: &str,
            data: Result<Vec<Resource>, keycloak::KeycloakError>,
            filter: Filter,
        ) -> Result<Vec<Resource>, proto::LdapError>
        where
            Filter: Fn(&Resource) -> bool,
        {
            match data {
                Ok(resource) => Ok(resource.into_iter().filter(filter).collect()),
                Err(keycloak::KeycloakError::ReqwestFailure(_)) => {
                    Err(proto::LdapError(LdapResultCode::Unavailable, "Could not connect to keycloak.".to_string()))
                }
                Err(e) => {
                    tracing::error!(error = ?e, "Could not fetch {} from keycloak", resource_name);
                    Err(proto::LdapError(
                        LdapResultCode::Other,
                        format!("Could not fetch {} from keycloak", resource_name),
                    ))
                }
            }
        }

        /// Unconditionally retain the resource entry.
        fn retain_everything<Resource>(_: &Resource) -> bool {
            true
        }

        /// Query users of realm we configured for this client. Will not perform any pagination,
        /// so make sure the size_limit you pass is high enough to allow for all users to be returned.
        pub async fn query_users(&self, size_limit: i32) -> Result<Vec<keycloak::types::UserRepresentation>, proto::LdapError> {
            ServiceAccountClient::error_convert_and_filter(
                "users",
                self.client
                    .realm_users_get(
                        &self.target_realm,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        Some(size_limit),
                        None,
                        None,
                        None,
                    )
                    .await,
                ServiceAccountClient::retain_everything,
            )
        }

        /// Query all groups in realm we configured for this client, disregarding groups that do not have an id or a name.
        pub async fn query_named_groups(&self) -> Result<Vec<keycloak::types::GroupRepresentation>, proto::LdapError> {
            ServiceAccountClient::error_convert_and_filter(
                "groups",
                self.client
                    .realm_groups_get(&self.target_realm, Some(false), None, None, None, Some(true), None, None)
                    .await,
                |group| group.id.is_some() && group.name.is_some(),
            )
        }

        /// Query subgroups for a group.
        pub async fn query_sub_groups(&self, group_id: &str) -> Result<Vec<keycloak::types::GroupRepresentation>, proto::LdapError> {
            ServiceAccountClient::error_convert_and_filter(
                "sub_groups",
                self.client
                    .realm_groups_with_group_id_children_get(&self.target_realm, group_id, Some(true), None, None, Some(-1), None)
                    .await,
                ServiceAccountClient::retain_everything,
            )
        }

        /// Query users belonging to a group.
        pub async fn query_users_in_group(&self, group_id: &str) -> Result<Vec<keycloak::types::UserRepresentation>, proto::LdapError> {
            ServiceAccountClient::error_convert_and_filter(
                "users_in_group",
                self.client
                    .realm_groups_with_group_id_members_get(&self.target_realm, group_id, Some(true), None, None)
                    .await,
                ServiceAccountClient::retain_everything,
            )
        }
    }

    impl std::fmt::Debug for ServiceAccountClient {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "Service account for realm '{}'", self.target_realm)
        }
    }
}

#[cfg(test)]
pub mod client {
    use std::sync::{Mutex, MutexGuard};

    use ldap3_proto::LdapResultCode;

    use super::*;

    #[derive(Debug, Default)]
    pub struct TestGroup {
        pub id: &'static str,
        pub users: Vec<usize>,
        pub sub_groups: Vec<Self>,
    }

    impl TestGroup {
        pub fn new(id: &'static str, users: Vec<usize>) -> Self {
            Self {
                id,
                users,
                sub_groups: Vec::new(),
            }
        }

        pub fn with_subgroups(id: &'static str, sub_groups: Vec<Self>) -> Self {
            Self {
                id,
                users: Vec::new(),
                sub_groups,
            }
        }

        pub fn group_name(group_id: &'static str) -> String {
            group_id.to_string() + "_NAME"
        }

        pub fn to_keycloak_representation(&self) -> keycloak::types::GroupRepresentation {
            keycloak::types::GroupRepresentation {
                id: Some(self.id.to_string()),
                // In order for our tests to be able to check that ID and name are properly handled
                // separately, they should have different values. However, we don't want to bother
                // manually having to assign both each time, so we just make them follow this
                // hard-coded pattern.
                // This way, the values are not exactly independant, but not identical, which should
                // be good enough.
                name: Some(Self::group_name(self.id)),
                sub_group_count: Some(self.sub_groups.len() as i64),
                ..Default::default()
            }
        }

        fn search_group(&self, group_id: &str) -> Result<&Self, proto::LdapError> {
            if group_id == self.id {
                return Ok(self);
            }
            for group in self.sub_groups.iter() {
                if let Ok(res) = group.search_group(group_id) {
                    return Ok(res);
                }
            }
            Err(proto::LdapError(LdapResultCode::NoSuchObject, "Could not find group with ID".to_string()))
        }
    }

    /// A mock for our service account client. Used to test that our library deals with the information provided by keycloak directly
    /// without having to have an actual keycloak instance running.
    #[derive(Debug)]
    pub struct MockServiceAccountClient {
        pub user_ids: Vec<&'static str>,
        pub root_group: TestGroup,
        pub err_code: Mutex<Option<LdapResultCode>>,
        pub call_count: Mutex<u64>,
    }

    static MOCK_TEST_PIN_MUTEX: Mutex<()> = Mutex::new(());
    // Normally, we cannot reassign static values. Using a mutex allows us to do so by swapping out the internal
    // mutex value.
    static MOCK_SERVICE_ACCOUNT_CLIENT_SINGLETON: Mutex<Option<MockServiceAccountClient>> = Mutex::new(None);

    // If another test fails with a panic, it might fail to unlock the mutex, which
    // then becomes poisoned.
    // However, we don't care, as at that point, the mutex is effectively unlocked.
    macro_rules! lock_ignoring_poison {
        ($mutex:expr) => {
            match $mutex.lock() {
                Ok(guard) => guard,
                Err(poison) => poison.into_inner(),
            }
        };
    }

    impl MockServiceAccountClient {
        /// Sets a mock instance to be returned during a test when a ServiceAccountClient is constructed.
        fn set_singleton_instance(instance: Self) -> MutexGuard<'static, ()> {
            // This lock is needed because the tests run in parallel.
            // We lock the mock pin mutex to ensure that only one test may set the instance at a time
            // and each test always gets to see the client instance it has configured,
            // Note that we need a second mutex for that, because returning the MutexGuard of the singleton
            // mutex instead would prevent us from actually providing the instance to the client builder.
            let guard = lock_ignoring_poison!(MOCK_TEST_PIN_MUTEX);
            _ = lock_ignoring_poison!(MOCK_SERVICE_ACCOUNT_CLIENT_SINGLETON).insert(instance);
            guard
        }

        pub fn set_empty() -> MutexGuard<'static, ()> {
            Self::set_singleton_instance(MockServiceAccountClient {
                user_ids: vec![],
                root_group: TestGroup::default(),
                err_code: Mutex::new(None),
                call_count: Mutex::new(0),
            })
        }

        pub fn set_users(user_ids: Vec<&'static str>) -> MutexGuard<'static, ()> {
            Self::set_singleton_instance(MockServiceAccountClient {
                user_ids,
                root_group: TestGroup::default(),
                err_code: Mutex::new(None),
                call_count: Mutex::new(0),
            })
        }

        pub fn set_users_groups(user_ids: Vec<&'static str>, groups: Vec<TestGroup>) -> MutexGuard<'static, ()> {
            Self::set_singleton_instance(MockServiceAccountClient {
                user_ids,
                root_group: TestGroup::with_subgroups("", groups),
                err_code: Mutex::new(None),
                call_count: Mutex::new(0),
            })
        }

        pub fn set_err(err_code: LdapResultCode) -> MutexGuard<'static, ()> {
            Self::set_singleton_instance(MockServiceAccountClient {
                user_ids: vec![],
                root_group: TestGroup::default(),
                err_code: Mutex::new(Some(err_code)),
                call_count: Mutex::new(0),
            })
        }
    }

    /// This impl MUST always follow the same method signature as the real implementation.
    impl MockServiceAccountClient {
        pub fn new(_: keycloak::KeycloakAdmin<keycloak::KeycloakServiceAccountAdminTokenRetriever>, _: String) -> Self {
            // Take out the instance we configured earlier. Will take ownership of this instance, which means
            // this method may only be called once before we have to configure a new instance.
            // Luckily, one instance is all we need for the tests.
            lock_ignoring_poison!(MOCK_SERVICE_ACCOUNT_CLIENT_SINGLETON).take().unwrap()
        }

        pub fn call_count(&self) -> u64 {
            *lock_ignoring_poison!(self.call_count)
        }

        pub fn change_err(&self, code: LdapResultCode) {
            _ = lock_ignoring_poison!(self.err_code).insert(code);
        }

        pub async fn query_users(&self, _size_limit: i32) -> Result<Vec<keycloak::types::UserRepresentation>, proto::LdapError> {
            if let Some(err_code) = lock_ignoring_poison!(self.err_code).as_ref() {
                return Err(proto::LdapError(err_code.clone(), "".to_string()));
            }

            *lock_ignoring_poison!(self.call_count) += 1;
            Ok(self
                .user_ids
                .iter()
                .map(|user_id| keycloak::types::UserRepresentation {
                    id: Some(user_id.to_string()),
                    ..Default::default()
                })
                .collect())
        }

        pub async fn query_named_groups(&self) -> Result<Vec<keycloak::types::GroupRepresentation>, proto::LdapError> {
            if let Some(err_code) = lock_ignoring_poison!(self.err_code).as_ref() {
                return Err(proto::LdapError(err_code.clone(), "".to_string()));
            }

            *lock_ignoring_poison!(self.call_count) += 1;
            Ok(self.root_group.sub_groups.iter().map(TestGroup::to_keycloak_representation).collect())
        }

        pub async fn query_sub_groups(&self, group_id: &str) -> Result<Vec<keycloak::types::GroupRepresentation>, proto::LdapError> {
            if let Some(err_code) = lock_ignoring_poison!(self.err_code).as_ref() {
                return Err(proto::LdapError(err_code.clone(), "".to_string()));
            }
            *lock_ignoring_poison!(self.call_count) += 1;

            Ok(self
                .root_group
                .search_group(group_id)?
                .sub_groups
                .iter()
                .map(TestGroup::to_keycloak_representation)
                .collect())
        }

        pub async fn query_users_in_group(&self, group_id: &str) -> Result<Vec<keycloak::types::UserRepresentation>, proto::LdapError> {
            if let Some(err_code) = lock_ignoring_poison!(self.err_code).as_ref() {
                return Err(proto::LdapError(err_code.clone(), "".to_string()));
            }

            *lock_ignoring_poison!(self.call_count) += 1;
            Ok(self
                .root_group
                .search_group(group_id)?
                .users
                .iter()
                .map(|&user_index| keycloak::types::UserRepresentation {
                    id: Some(self.user_ids.get(user_index).unwrap().to_string()),
                    ..Default::default()
                })
                .collect())
        }
    }
}
