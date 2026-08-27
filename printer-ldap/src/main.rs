#![deny(warnings)]
#![deny(clippy::all)]

use anyhow::Context;
use giz_ldap_lib::deps::keycloak::types::UserRepresentation;

pub struct Target;

impl giz_ldap_lib::interface::Target for Target {
    type TargetConfig = giz_ldap_lib::config::EmptyConfig;

    fn new(_config: std::sync::Arc<giz_ldap_lib::config::Config<Self::TargetConfig>>) -> anyhow::Result<Self> {
        Ok(Self {})
    }

    fn extract_user(&self, user: UserRepresentation, ldap_entry: &mut giz_ldap_lib::dto::LdapEntry) -> anyhow::Result<()> {
        ldap_entry.set_attribute("displayName", vec![user.username.context("username missing")?]);
        ldap_entry.set_attribute("givenName", vec![user.first_name.unwrap_or("".to_string())]);
        ldap_entry.set_attribute(
            "surname",
            vec![
                // We would really like to have a name for the user so that the client can know who they
                // are dealing with.
                user.last_name.context("last name missing")?,
            ],
        );
        ldap_entry.set_attribute(
            "mail",
            vec![
                // A user without a mail is not very useful in our case.
                user.email.context("email missing")?,
            ],
        );

        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    giz_ldap_lib::server_run!(Target, giz_ldap_lib::constants::GroupStrategy::NoGroupInfo)
}
