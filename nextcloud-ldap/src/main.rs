#![deny(warnings)]
#![deny(clippy::all)]

use anyhow::Context;
use giz_ldap_lib::{dto, server};
use keycloak::types::{GroupRepresentation, UserRepresentation};

pub struct Target;

impl giz_ldap_lib::interface::Target for Target {
    type TargetConfig = giz_ldap_lib::config::EmptyConfig;

    fn new(_config: std::sync::Arc<giz_ldap_lib::config::Config<Self::TargetConfig>>) -> anyhow::Result<Self> {
        Ok(Self {})
    }

    fn extract_user(&self, user: UserRepresentation, ldap_entry: &mut dto::LdapEntry) -> anyhow::Result<()> {
        ldap_entry.set_attribute("entryuuid", vec![user.id.context("user id missing")?]);
        ldap_entry.set_attribute("username", vec![user.username.context("username missing")?]);
        ldap_entry.set_attribute(
            "displayname",
            vec![format!(
                "{} {}",
                user.first_name.clone().context("first_name missing")?,
                user.last_name.clone().context("last_name missing")?
            )],
        );
        ldap_entry.set_attribute("givenName", vec![user.first_name.unwrap_or("".to_string())]);
        ldap_entry.set_attribute("surname", vec![user.last_name.context("last name missing")?]);
        ldap_entry.set_attribute("mail", vec![user.email.context("email missing")?]);
        ldap_entry.set_attribute("enabled", vec![user.enabled.context("enabled missing")?.to_string()]);

        Ok(())
    }

    fn extract_group(&self, _group: GroupRepresentation, ldap_entry: &mut dto::LdapEntry) -> anyhow::Result<()> {
        ldap_entry.set_attribute(
            "entryUuid",
            // If this unwrap fails, our implementation is broken because we always set the ou as the
            // identifier of the group.
            ldap_entry.get_attribute("ou").unwrap().clone(),
        );
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    server::start_ldap_server::<Target>(true).await
}
