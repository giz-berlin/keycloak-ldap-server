#![deny(warnings)]
#![deny(clippy::all)]

use anyhow::Context;
use giz_ldap_lib::deps::keycloak::types::{GroupRepresentation, UserRepresentation};

#[derive(Debug, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NextcloudConfig {
    /// Attribute names in source for special fields
    pub keycloak_phone_attr: String,
    pub keycloak_org_role_attr: String,
}

impl Default for NextcloudConfig {
    fn default() -> Self {
        Self {
            keycloak_phone_attr: "phone".to_string(),
            keycloak_org_role_attr: "orgRole".to_string(),
        }
    }
}

pub struct Target {
    config: std::sync::Arc<giz_ldap_lib::config::Config<NextcloudConfig>>,
}

impl giz_ldap_lib::interface::Target for Target {
    type TargetConfig = NextcloudConfig;

    fn new(config: std::sync::Arc<giz_ldap_lib::config::Config<Self::TargetConfig>>) -> anyhow::Result<Self> {
        Ok(Self { config })
    }

    fn extract_user(&self, user: UserRepresentation, ldap_entry: &mut giz_ldap_lib::dto::LdapEntry) -> anyhow::Result<()> {
        ldap_entry.set_attribute("entryUuid", vec![user.id.context("user id missing")?]);
        ldap_entry.set_attribute("username", vec![user.username.clone().context("username missing")?]);
        ldap_entry.set_attribute(
            "active",
            vec![if user.enabled.context("Enabled attribute missing")? {
                "TRUE".to_owned()
            } else {
                "FALSE".to_owned()
            }],
        );

        match (&user.first_name, &user.last_name) {
            (Some(first_name), Some(last_name)) => {
                ldap_entry.set_attribute("displayName", vec![format!("{first_name} {last_name}")]);
                ldap_entry.set_attribute("givenName", vec![first_name.clone()]);
                ldap_entry.set_attribute("surname", vec![last_name.clone()]);
            }
            (Some(first_name), None) => {
                ldap_entry.set_attribute("displayName", vec![first_name.clone()]);
                ldap_entry.set_attribute("givenName", vec![first_name.clone()]);
            }
            (None, Some(last_name)) => {
                ldap_entry.set_attribute("displayName", vec![last_name.clone()]);
                ldap_entry.set_attribute("surname", vec![last_name.clone()]);
            }
            (None, None) => {
                // Use the preferred username if no name component is present
                let username = user.username.clone().expect("User has no names and no username");
                ldap_entry.set_attribute("displayName", vec![username.clone()]);
                ldap_entry.set_attribute("givenName", vec![username]);
            }
        }

        ldap_entry.set_attribute("mail", vec![user.email.context("email missing")?]);
        ldap_entry.set_attribute("enabled", vec![user.enabled.context("enabled missing")?.to_string()]);

        if let Some(attributes) = user.attributes {
            if let Some(phone_attrs) = attributes.get(&self.config.target.keycloak_phone_attr) {
                ldap_entry.set_attribute("phone", phone_attrs.to_vec());
            }
            if let Some(org_role_attrs) = attributes.get(&self.config.target.keycloak_org_role_attr) {
                ldap_entry.set_attribute("orgRole", org_role_attrs.to_vec());
            }
        }

        Ok(())
    }

    fn extract_group(&self, group: GroupRepresentation, ldap_entry: &mut giz_ldap_lib::dto::LdapEntry) -> anyhow::Result<()> {
        ldap_entry.set_attribute(
            "entryUuid",
            // If this unwrap fails, our implementation is broken because we always set the ou as the
            // identifier of the group.
            ldap_entry.get_attribute("ou").unwrap().clone(),
        );

        let full_path = group.path.context("Group path is None")?;
        let trimmed_path = full_path
            .strip_prefix('/')
            .with_context(|| format!("Group path does not start with /, stopping as we must prevent duplications, {full_path}"))?;

        ldap_entry.set_attribute("cn", vec![trimmed_path.into()]);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    giz_ldap_lib::server_run!(Target, giz_ldap_lib::constants::GroupStrategy::SubgroupMembers)
}
