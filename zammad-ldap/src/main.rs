#![deny(warnings)]
#![deny(clippy::all)]

use anyhow::Context;
use giz_ldap_lib::{dto, server};
use keycloak::types::UserRepresentation;

pub struct Target;

impl giz_ldap_lib::interface::Target for Target {
    type TargetConfig = giz_ldap_lib::config::EmptyConfig;

    fn new(_config: std::sync::Arc<giz_ldap_lib::config::Config<Self::TargetConfig>>) -> anyhow::Result<Self> {
        Ok(Self {})
    }

    fn extract_user(&self, user: UserRepresentation, ldap_entry: &mut dto::LdapEntry) -> anyhow::Result<()> {
        // skip all disabled users. Zammad will then disable them.
        if !user.enabled.context("enabled missing")? {
            anyhow::bail!("User disabled!")
        }

        ldap_entry.set_attribute("givenName", vec![user.first_name.unwrap_or("".to_string())]);
        ldap_entry.set_attribute("surname", vec![user.last_name.context("last name missing")?]);
        ldap_entry.set_attribute("mail", vec![user.email.context("email missing")?]);

        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    server::start_ldap_server::<Target>(giz_ldap_lib::constants::GroupStrategy::SubgroupMembers).await
}
