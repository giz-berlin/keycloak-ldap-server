/// This will use the real or the mock implementation, depending on whether we are compiling for tests or not.
#[mockall_double::double]
pub use client::ServiceAccountClient;

use crate::proto;

/// A builder to construct keycloak service account clients for a pre-configured Keycloak server and realm.
pub struct ServiceAccountClientBuilder {
    keycloak_address: String,
    realm: String,
}

impl ServiceAccountClientBuilder {
    pub fn new(keycloak_address: String, realm: String) -> Self {
        Self { keycloak_address, realm }
    }

    /// Construct a new client using provided service account credentials.
    /// Will verify that the credentials authenticate successfully.
    pub async fn new_service_account(&self, client_id: &str, client_secret: &str) -> Result<ServiceAccountClient, proto::LdapError> {
        // Note that the token we receive is not validated, but that might be fine in our case.
        // Also, since the acquire method is not public, we need to do some API request to validate we actually have a working client...
        let keycloak_client =
            keycloak::KeycloakServiceAccountAdminTokenRetriever::create_with_custom_realm(client_id, client_secret, &self.realm, reqwest::Client::new());

        let service_account = ServiceAccountClient::new(
            keycloak::KeycloakAdmin::new(&self.keycloak_address, keycloak_client, reqwest::Client::new()),
            self.realm.clone(),
        );

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

    macro_rules! error_convert_and_filter {
        ($resource_name:literal, $keycloak_api_call:expr) => {
            error_convert_and_filter!($resource_name, $keycloak_api_call, |_| true)
        };
        ($resource_name:literal, $keycloak_api_call:expr, $filter:expr) => {
            match $keycloak_api_call {
                Ok(resource) => Ok(resource.into_iter().filter($filter).collect()),
                Err(keycloak::KeycloakError::ReqwestFailure(_)) => {
                    return Err(proto::LdapError(
                        LdapResultCode::Unavailable,
                        "Could not connect to keycloak.".to_string(),
                    ))
                }
                Err(e) => {
                    log::error!("Could not fetch {} from keycloak: {:?}", $resource_name, e);
                    return Err(proto::LdapError(
                        LdapResultCode::Other,
                        format!("Could not load {} information from keycloak", $resource_name),
                    ));
                }
            }
        };
    }

    #[cfg_attr(test, mockall::automock)]
    impl ServiceAccountClient {
        pub fn new(client: keycloak::KeycloakAdmin<keycloak::KeycloakServiceAccountAdminTokenRetriever>, target_realm: String) -> Self {
            Self { client, target_realm }
        }

        /// Query users of realm we configured for this client. Will not perform any pagination,
        /// so make sure the size_limit you pass is high enough to allow for all users to be returned.
        pub async fn query_users(&self, size_limit: i32) -> Result<Vec<keycloak::types::UserRepresentation>, proto::LdapError> {
            error_convert_and_filter!(
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
                    .await
            )
        }

        /// Query all realm roles of realm we configured for this client, disregarding roles that do not have a name.
        pub async fn query_named_realm_roles(&self) -> Result<Vec<keycloak::types::RoleRepresentation>, proto::LdapError> {
            error_convert_and_filter!(
                "roles",
                self.client.realm_roles_get(&self.target_realm, None, None, Some(-1), None).await,
                |role| role.name.is_some()
            )
        }

        /// Query users associated to a realm role.
        pub async fn query_users_with_role(&self, role_name: &str) -> Result<Vec<keycloak::types::UserRepresentation>, proto::LdapError> {
            let url_safe_role_name = url::form_urlencoded::byte_serialize(role_name.as_bytes()).collect::<String>();

            error_convert_and_filter!(
                "role_users",
                self.client
                    .realm_roles_with_role_name_users_get(&self.target_realm, &url_safe_role_name, None, None)
                    .await
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
mod client {
    use std::{
        collections::HashMap,
        sync::{Mutex, MutexGuard},
    };

    use ldap3_proto::LdapResultCode;

    use super::*;

    /// A mock for our service account client. Used to test that our library deals with the information provided by keycloak directly
    /// without having to have an actual keycloak instance running.
    #[derive(Debug, Clone)]
    pub struct MockServiceAccountClient {
        pub user_ids: Vec<&'static str>,
        pub groups: HashMap<&'static str, Vec<usize>>,
        pub err_code: Option<LdapResultCode>,
    }

    static MOCK_TEST_PIN_MUTEX: Mutex<()> = Mutex::new(());
    // Normally, we cannot reassign static values. Using a mutex allows us to do so by swapping out the internal
    // mutex value.
    static MOCK_SERVICE_ACCOUNT_CLIENT_SINGLETON: Mutex<Option<MockServiceAccountClient>> = Mutex::new(None);

    impl MockServiceAccountClient {
        /// Sets a mock instance to be returned during a test when a ServiceAccountClient is constructed.
        fn set_singleton_instance(instance: Self) -> MutexGuard<'static, ()> {
            // This lock is needed because the tests run in parallel.
            // We lock the mock pin mutex to ensure that only one test may set the instance at a time
            // and each test always gets to see the client instance it has configured,
            // Note that we need a second mutex for that, because returning the MutexGuard of the singleton
            // mutex instead would prevent us from actually providing the instance to the client builder.
            let guard = match MOCK_TEST_PIN_MUTEX.lock() {
                Ok(guard) => guard,
                // If another test fails with a panic, it might fail to unlock the mutex, which
                // then becomes poisoned.
                // However, we don't care, as at that point, the mutex is effectively unlocked.
                Err(poison) => poison.into_inner(),
            };
            _ = MOCK_SERVICE_ACCOUNT_CLIENT_SINGLETON.lock().unwrap().insert(instance);
            guard
        }

        pub fn set_empty() -> MutexGuard<'static, ()> {
            Self::set_singleton_instance(MockServiceAccountClient {
                user_ids: vec![],
                groups: HashMap::new(),
                err_code: None,
            })
        }

        pub fn set_users(user_ids: Vec<&'static str>) -> MutexGuard<'static, ()> {
            Self::set_singleton_instance(MockServiceAccountClient {
                user_ids,
                groups: HashMap::new(),
                err_code: None,
            })
        }

        pub fn set_users_groups(user_ids: Vec<&'static str>, groups: Vec<(&'static str, Vec<usize>)>) -> MutexGuard<'static, ()> {
            Self::set_singleton_instance(MockServiceAccountClient {
                user_ids,
                groups: groups.into_iter().collect(),
                err_code: None,
            })
        }

        pub fn set_err(err_code: LdapResultCode) -> MutexGuard<'static, ()> {
            Self::set_singleton_instance(MockServiceAccountClient {
                user_ids: vec![],
                groups: HashMap::new(),
                err_code: Some(err_code),
            })
        }
    }

    /// This impl MUST always follow the same method signature as the real implementation.
    impl MockServiceAccountClient {
        pub fn new(_: keycloak::KeycloakAdmin<keycloak::KeycloakServiceAccountAdminTokenRetriever>, _: String) -> Self {
            // Take out the instance we configured earlier. Will take ownership of this instance, which means
            // this method may only be called once before we have to configure a new instance.
            // Luckily, once instance is all we need for the tests.
            MOCK_SERVICE_ACCOUNT_CLIENT_SINGLETON.lock().unwrap().take().unwrap()
        }

        pub async fn query_users(&self, _size_limit: i32) -> Result<Vec<keycloak::types::UserRepresentation>, proto::LdapError> {
            if let Some(err_code) = self.err_code.as_ref() {
                return Err(proto::LdapError(err_code.clone(), "".to_string()));
            }

            Ok(self
                .user_ids
                .iter()
                .map(|user_id| keycloak::types::UserRepresentation {
                    id: Some(user_id.to_string()),
                    ..Default::default()
                })
                .collect())
        }

        pub async fn query_named_realm_roles(&self) -> Result<Vec<keycloak::types::RoleRepresentation>, proto::LdapError> {
            if let Some(err_code) = self.err_code.as_ref() {
                return Err(proto::LdapError(err_code.clone(), "".to_string()));
            }

            Ok(self
                .groups
                .iter()
                .map(|(group_name, _)| keycloak::types::RoleRepresentation {
                    name: Some(group_name.to_string()),
                    ..Default::default()
                })
                .collect())
        }

        pub async fn query_users_with_role(&self, role_name: &str) -> Result<Vec<keycloak::types::UserRepresentation>, proto::LdapError> {
            if let Some(err_code) = self.err_code.as_ref() {
                return Err(proto::LdapError(err_code.clone(), "".to_string()));
            }

            Ok(self
                .groups
                .get(role_name)
                .unwrap()
                .iter()
                .map(|&user_index| keycloak::types::UserRepresentation {
                    id: Some(self.user_ids.get(user_index).unwrap().to_string()),
                    ..Default::default()
                })
                .collect())
        }
    }
}
