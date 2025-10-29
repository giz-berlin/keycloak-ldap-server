pub trait Target: Sized + 'static {
    /// The configuration struct to use for a specific [Target].
    /// Must derive from [serde::de::DeserializeOwned] because it will be deserialized from a
    /// TOML configuration file.
    type Config: serde::de::DeserializeOwned + std::fmt::Debug;

    type KeycloakAttributeExtractor: crate::dto::KeycloakAttributeExtractor;
}

#[cfg(test)]
pub(crate) mod tests {
    #[allow(dead_code)]
    pub(crate) struct DummyTarget;

    impl super::Target for DummyTarget {
        type Config = crate::config::EmptyConfig;

        type KeycloakAttributeExtractor = DummyKeycloakAttributeExtractor;
    }

    pub(crate) struct DummyKeycloakAttributeExtractor;

    impl crate::dto::KeycloakAttributeExtractor for DummyKeycloakAttributeExtractor {
        fn extract_user(&self, _user: keycloak::types::UserRepresentation, _ldap_entry: &mut crate::dto::LdapEntry) -> anyhow::Result<()> {
            // Just do nothing and return
            Ok(())
        }
    }
}
