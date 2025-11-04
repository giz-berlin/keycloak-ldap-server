pub trait Target: Send + Sync + Sized + 'static {
    /// The configuration struct to use for a specific [Target].
    /// Must derive from [serde::de::DeserializeOwned] because it will be deserialized from a
    /// TOML configuration file.
    type TargetConfig: serde::de::DeserializeOwned + std::fmt::Debug;

    /// Returns a new Interface object.
    /// May fail if some config is invalid.
    fn new(config: std::sync::Arc<crate::config::Config<Self::TargetConfig>>) -> anyhow::Result<Self>;

    /// Add the desired user attributes to the Keycloak entry.
    fn extract_user(&self, user: keycloak::types::UserRepresentation, ldap_entry: &mut crate::dto::LdapEntry) -> anyhow::Result<()>;

    /// Add the desired group attributes to the Keycloak entry.
    fn extract_group(&self, _group: keycloak::types::GroupRepresentation, _ldap_entry: &mut crate::dto::LdapEntry) -> anyhow::Result<()> {
        // Provide a default implementation here as not all clients want to deal with groups.
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #[allow(dead_code)]
    pub(crate) struct DummyTarget;

    impl super::Target for DummyTarget {
        type TargetConfig = crate::config::EmptyConfig;

        fn new(_config: std::sync::Arc<crate::config::Config<Self::TargetConfig>>) -> anyhow::Result<Self> {
            Ok(Self {})
        }

        fn extract_user(&self, _user: keycloak::types::UserRepresentation, _ldap_entry: &mut crate::dto::LdapEntry) -> anyhow::Result<()> {
            Ok(())
        }
    }
}
