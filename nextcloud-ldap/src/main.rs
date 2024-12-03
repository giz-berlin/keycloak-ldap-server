#![deny(warnings)]
#![deny(clippy::all)]

use giz_ldap_lib::{entry, server};
use keycloak::types::{GroupRepresentation, UserRepresentation};

pub struct NextcloudAttributeExtractor;

impl entry::KeycloakAttributeExtractor for NextcloudAttributeExtractor {
    fn extract_user(&self, _user: UserRepresentation, _ldap_entry: &mut entry::LdapEntry) -> anyhow::Result<()> {
        // TODO

        Ok(())
    }

    fn extract_group(&self, _group: GroupRepresentation, ldap_entry: &mut entry::LdapEntry) -> anyhow::Result<()> {
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
    server::start_ldap_server(Box::new(NextcloudAttributeExtractor {}), true).await
}
