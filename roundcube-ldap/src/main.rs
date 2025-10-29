#![deny(warnings)]
#![deny(clippy::all)]

use anyhow::Context;

pub struct Target;

impl giz_ldap_lib::interface::Target for Target {
    type Config = giz_ldap_lib::config::EmptyConfig;
    type KeycloakAttributeExtractor = PrinterUserAttributeExtractor;
}

pub struct PrinterUserAttributeExtractor;

impl giz_ldap_lib::dto::KeycloakAttributeExtractor for PrinterUserAttributeExtractor {
    fn extract_user(&self, user: keycloak::types::UserRepresentation, ldap_entry: &mut giz_ldap_lib::dto::LdapEntry) -> anyhow::Result<()> {
        // skip all disabled users as those are not reachable via mail anyways
        if !user.enabled.context("enabled missing")? {
            anyhow::bail!("User disabled!")
        }

        let given_name = user.first_name.unwrap_or("".to_string());
        // We would really like to have a name for the user so that the client can know who they
        // are dealing with.
        let surname = user.last_name.context("last name missing")?;
        ldap_entry.set_attribute("displayName", vec![format!("{given_name} {surname}")]);
        ldap_entry.set_attribute("givenName", vec![given_name]);
        ldap_entry.set_attribute("surname", vec![surname]);
        ldap_entry.set_attribute(
            "mail",
            vec![
                // A user without a mail is not very useful in our case.
                user.email.context("email missing")?,
            ],
        );
        ldap_entry.set_attribute("cn", vec![user.username.context("username missing")?]);
        ldap_entry.set_attribute("uid", vec![user.id.context("id missing")?]);

        Ok(())
    }

    fn extract_group(&self, group: keycloak::types::GroupRepresentation, ldap_entry: &mut giz_ldap_lib::dto::LdapEntry) -> anyhow::Result<()> {
        ldap_entry.set_attribute(
            "entryUuid",
            // If this unwrap fails, our implementation is broken because we always set the ou as the
            // identifier of the group.
            ldap_entry.get_attribute("ou").unwrap().clone(),
        );
        ldap_entry.set_attribute(
            "mail",
            // If this unwrap fails, our implementation is broken because we always set the ou as the
            // identifier of the group.
            vec![format!("{}@test.giz.berlin", group.id.unwrap())],
        );
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    giz_ldap_lib::server::start_ldap_server::<Target>(PrinterUserAttributeExtractor {}, true).await
}
