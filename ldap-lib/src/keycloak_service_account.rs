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
    pub async fn new_service_account(&self, client_id: &str, client_secret: &str) -> anyhow::Result<ServiceAccountClient> {
        // TODO: this does not appear to do proper token refresh, but appears to fetch a new token for each API request
        // They appear to be aware of this issue: https://github.com/kilork/keycloak/issues/32
        // Also, the token we receive is not validated, apparently, but that might be fine in our case.
        // Also, since the acquire method is not public, we need to do some API request to validate we actually have a working client...
        let keycloak_client =
            keycloak::KeycloakServiceAccountAdminTokenRetriever::create_with_custom_realm(client_id, client_secret, &self.realm, reqwest::Client::new());

        let service_account = ServiceAccountClient::new(
            keycloak::KeycloakAdmin::new(&self.keycloak_address, keycloak_client, reqwest::Client::new()),
            self.realm.clone(),
        );

        match service_account.query_users(1).await {
            Ok(_) => Ok(service_account),
            Err(e) => anyhow::bail!("Service account appears to have no access to keycloak: {:?}", e),
        }
    }
}

#[mockall_double::double]
pub use client::ServiceAccountClient;
mod client {
    use keycloak::types::TypeVec;
    use keycloak::KeycloakError;
    use std::fmt::Formatter;

    /// A keycloak service account client that has been verified to authenticate successfully.
    /// Used to retrieve user-information for a single realm.
    pub struct ServiceAccountClient {
        client: keycloak::KeycloakAdmin<keycloak::KeycloakServiceAccountAdminTokenRetriever>,
        target_realm: String,
    }

    #[cfg_attr(test, mockall::automock)]
    impl ServiceAccountClient {
        pub fn new(client: keycloak::KeycloakAdmin<keycloak::KeycloakServiceAccountAdminTokenRetriever>, target_realm: String) -> Self {
            Self { client, target_realm }
        }

        /// Query users of realm we configured for this client. Will not perform any pagination,
        /// so make sure the size_limit you pass is high enough to allow for all users to be returned.
        pub async fn query_users(&self, size_limit: i32) -> Result<TypeVec<keycloak::types::UserRepresentation>, KeycloakError> {
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
        }
    }

    impl std::fmt::Debug for ServiceAccountClient {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "Service account for realm '{}'", self.target_realm)
        }
    }
}
