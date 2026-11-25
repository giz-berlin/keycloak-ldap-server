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
        ldap_entry.set_attribute("username", vec![user.username.context("username missing")?]);
        ldap_entry.set_attribute(
            "active",
            vec![if user.enabled.context("Enabled attribute missing")? {
                "TRUE".to_owned()
            } else {
                "FALSE".to_owned()
            }],
        );
        ldap_entry.set_attribute(
            "displayName",
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

        if let Some(phone_attrs) = user
            .attributes
            .as_ref()
            .context("No user attributes sent")?
            .get(&self.config.target.keycloak_phone_attr)
        {
            ldap_entry.set_attribute("phone", phone_attrs.to_vec());
        }
        if let Some(org_role_attrs) = user
            .attributes
            .context("No user attributes sent")?
            .get(&self.config.target.keycloak_org_role_attr)
        {
            ldap_entry.set_attribute("orgRole", org_role_attrs.to_vec());
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
