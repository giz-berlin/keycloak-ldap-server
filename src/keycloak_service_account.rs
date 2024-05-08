use std::fmt::Formatter;

use keycloak::types::{TypeVec, UserRepresentation};
use keycloak::KeycloakError;

pub struct ServiceAccountBuilder {
    keycloak_address: String,
    realm: String,
}

impl ServiceAccountBuilder {
    pub fn new(keycloak_address: String, realm: String) -> Self {
        Self { keycloak_address, realm }
    }

    pub async fn new_service_account(&self, client_id: &str, client_secret: &str) -> anyhow::Result<ServiceAccount> {
        // TODO: this does not appear to do proper token refresh, but appears to fetch a new token for each API request
        // They appear to be aware of this issue: https://github.com/kilork/keycloak/issues/32
        // Also, the token we receive is not validated, apparently, but that might be fine in our case.
        // Also, since the acquire method is not public, we need to do some API request to validate we actually have a working client...
        let keycloak_client =
            keycloak::KeycloakServiceAccountAdminTokenRetriever::create_with_custom_realm(client_id, client_secret, &self.realm, reqwest::Client::new());

        let service_account = ServiceAccount {
            service_account: keycloak::KeycloakAdmin::new(&self.keycloak_address, keycloak_client, reqwest::Client::new()),
            target_realm: self.realm.clone(),
        };

        match service_account.query_users(1).await {
            Ok(_) => Ok(service_account),
            Err(e) => anyhow::bail!("Service account appears to have no access to keycloak: {:?}", e),
        }
    }
}

pub struct ServiceAccount {
    service_account: keycloak::KeycloakAdmin<keycloak::KeycloakServiceAccountAdminTokenRetriever>,
    target_realm: String,
}

impl ServiceAccount {
    pub async fn query_users(&self, size_limit: i32) -> Result<TypeVec<UserRepresentation>, KeycloakError> {
        self.service_account
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

impl std::fmt::Debug for ServiceAccount {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Service account for realm '{}'", self.target_realm)
    }
}
