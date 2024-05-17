#![deny(warnings)]
#![deny(clippy::all)]

use anyhow::Context;
use giz_ldap_lib::{entry, server};
use keycloak::types::UserRepresentation;

pub struct PrinterUserAttributeExtractor;

impl entry::KeycloakUserAttributeExtractor for PrinterUserAttributeExtractor {
    fn extract(&self, user: UserRepresentation, ldap_entry: &mut entry::LdapEntry) -> anyhow::Result<()> {
        ldap_entry.attributes.insert("cn", vec![user.id.context("user id missing")?]);
        ldap_entry.attributes.insert("displayName", vec![user.username.context("username missing")?]);
        ldap_entry.attributes.insert("givenName", vec![user.first_name.unwrap_or("".to_string())]);
        ldap_entry.attributes.insert(
            "surname",
            vec![
                // We would really like to have a name for the user so that the client can know who they
                // are dealing with.
                user.last_name.context("last name missing")?,
            ],
        );
        ldap_entry.attributes.insert(
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
    server::start_ldap_server(Box::new(PrinterUserAttributeExtractor {})).await
}
