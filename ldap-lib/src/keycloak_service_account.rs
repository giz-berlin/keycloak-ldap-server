use crate::proto;

#[mockall_double::double]
pub use client::ServiceAccountClient;

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

mod client {
    use std::fmt::{Formatter};

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
                    return Err(proto::LdapError(LdapResultCode::Unavailable, "Could not connect to keycloak.".to_string()))
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
