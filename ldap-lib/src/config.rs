use anyhow::Context;

#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config<T> {
    /// Configuration for Sentry error tracing. Sentry integration becomes active once set.
    pub sentry: Option<SentryConfig>,

    /// Configuration of data source (only Keycloak in this case).
    #[serde(default)]
    pub source: SourceConfig,

    /// Configuration of data sink (different LDAP server variants).
    #[allow(dead_code)]
    pub target: T,

    /// Common configuration of LDAP server.
    #[serde(default)]
    pub ldap_server: LdapServerConfig,
}

#[derive(serde::Deserialize, Debug, Default)]
#[serde(default)]
pub struct SourceConfig {
    pub keycloak_api: KeycloakApiConfig,
    /// Number of users to fetch from Keycloak per request.
    pub fetch_users_num: Option<i32>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(default)]
pub struct KeycloakApiConfig {
    /// Address of the external Keycloak to fetch data from.
    pub url: String,
    /// Keycloak realm to fetch the data from.
    pub realm: String,
    /// Whether to validate the server certificate of the external API.
    /// Only disable for local development purposes!
    pub insecure_disable_tls_verification: bool,
}

impl Default for KeycloakApiConfig {
    fn default() -> Self {
        Self {
            url: "https://keycloak.example.org".to_string(),
            realm: "company".to_string(),
            insecure_disable_tls_verification: false,
        }
    }
}

#[derive(serde::Deserialize, Debug)]
#[serde(default)]
pub struct LdapServerConfig {
    /// The base point of our LDAP tree
    pub(crate) base_distinguished_name: String,
    /// The name of the organization as shown by the LDAP base entry
    pub(crate) organization_name: String,
    /// Bind address with port, e.g. [::]:3000
    pub(crate) bind_address: String,
    /// Whether to disable the secure LDAP access and enable unencrypted access
    pub(crate) disable_ldaps: bool,
    /// The TLS certificate used by the LDAP server if LDAPS is enabled
    pub(crate) certificate: String,
    /// The TLS certificate private key used by the LDAP server if LDAPS is enabled
    pub(crate) certificate_key: String,

    /// Time to wait before sending first response in a session in milliseconds because some client implementations will miss the first response if it comes in too fast.
    pub(crate) session_first_answer_delay_millis: u64,

    /// How often to update entries in the LDAP cache in seconds. WARNING: If client credentials are changed in the keycloak, the old secret/password will still stay valid for this long!
    pub(crate) cache_update_interval_secs: u64,

    /// How long to wait in seconds before pruning LDAP cache entries that are not being accessed.
    pub(crate) cache_entry_max_inactive_secs: u64,
}

impl Default for LdapServerConfig {
    fn default() -> Self {
        Self {
            base_distinguished_name: "dc=giz,dc=berlin".to_string(),
            organization_name: "giz.berlin".to_string(),
            bind_address: "[::]:3000".to_string(),
            disable_ldaps: false,
            certificate: "certificates/ldap.pem".to_string(),
            certificate_key: "certificates/ldap.key".to_string(),
            session_first_answer_delay_millis: 0,
            cache_update_interval_secs: 60,
            cache_entry_max_inactive_secs: 3600,
        }
    }
}

#[derive(serde::Deserialize, Debug)]
pub struct EmptyConfig {}

#[derive(serde::Deserialize, Debug, Default)]
pub struct SentryConfig {
    /// Sentry Data Source Name (DSN). Tells Sentry where to send events to so they're associated with the correct project.
    pub dsn: String,
    /// Tag specifying which context the service is running in (for example, development, production, ...).
    pub environment: String,
}

impl<T: serde::de::DeserializeOwned> Config<T> {
    pub fn try_from_str(content: &str) -> anyhow::Result<Self> {
        toml::from_str(content).context("Failed to parse config content")
    }
}

impl<T: serde::de::DeserializeOwned> TryFrom<&std::path::Path> for Config<T> {
    type Error = anyhow::Error;

    fn try_from(path: &std::path::Path) -> Result<Self, Self::Error> {
        let content = std::fs::read_to_string(path).with_context(|| format!("Failed to read config file: {}", path.display()))?;

        Self::try_from_str(&content).with_context(|| format!("Failed to parse config file: {}", path.display()))
    }
}

impl<T: serde::de::DeserializeOwned> TryFrom<std::path::PathBuf> for Config<T> {
    type Error = anyhow::Error;

    fn try_from(path: std::path::PathBuf) -> Result<Self, Self::Error> {
        Self::try_from(path.as_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_from_str_valid() {
        let toml_str = r#"
            [sentry]
            dsn = "https://example@sentry.io/123"
            environment = "production"

            [source]

            [target]
        "#;
        let config = Config::<EmptyConfig>::try_from_str(toml_str).unwrap();
        let sentry = config.sentry;
        assert!(sentry.is_some());
        assert_eq!(sentry.as_ref().unwrap().dsn, "https://example@sentry.io/123");
        assert_eq!(sentry.as_ref().unwrap().environment, "production");
    }

    #[test]
    fn test_try_from_str_sentry_inactive() {
        let toml_str = r#"
            [source]

            [target]
        "#;
        let config = Config::<EmptyConfig>::try_from_str(toml_str).unwrap();
        assert!(config.sentry.is_none());
    }

    #[test]
    fn test_try_from_str_missing_section() {
        let toml_str = r#"
            [sentry]
        "#;
        let result = Config::<EmptyConfig>::try_from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_from_str_invalid_toml() {
        let toml_str = r#"
            [sentry
            dsn = "https://example@sentry.io/123"
        "#;
        let result = Config::<EmptyConfig>::try_from_str(toml_str);
        assert!(result.is_err());
    }
}
