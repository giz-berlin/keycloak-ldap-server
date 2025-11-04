#![deny(warnings)]
#![deny(clippy::all)]

use anyhow::Context;

#[derive(Debug, serde::Deserialize)]
#[serde(default)]
pub struct RoundcubeConfig {
    /// Attribute names in source groups and users corresponding to teams, groups and users in James.
    /// Only source groups that have the James team or group attribute will be synced to James.
    pub james_list_attr: String,
    pub james_team_attr: String,
    pub james_alias_attr: String,
}

impl Default for RoundcubeConfig {
    fn default() -> Self {
        Self {
            james_list_attr: "james-list".to_string(),
            james_team_attr: "james-team".to_string(),
            james_alias_attr: "james-alias".to_string(),
        }
    }
}

pub struct Target {
    config: std::sync::Arc<giz_ldap_lib::config::Config<RoundcubeConfig>>,
}

impl giz_ldap_lib::interface::Target for Target {
    type TargetConfig = RoundcubeConfig;

    fn new(config: std::sync::Arc<giz_ldap_lib::config::Config<Self::TargetConfig>>) -> anyhow::Result<Self> {
        Ok(Self { config })
    }

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

        let mut mail_addresses = vec![];

        // Add all mail addresses (aliases) of a user
        let user_attributes = user.attributes.unwrap_or_default();
        let aliases_opt = user_attributes.get(&self.config.target.james_alias_attr);

        if let Some(aliases) = aliases_opt {
            mail_addresses.append(&mut aliases.clone());
        }

        if let Some(main_email) = user.email {
            mail_addresses.push(main_email);
        } else {
            tracing::warn!("User {:?} has no main mail address set", user.id);
        }

        if !mail_addresses.is_empty(){
            ldap_entry.set_attribute("mail", mail_addresses);
        }

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

        // Map team mailboxes and lists to Roundcube
        let group_attributes = group.attributes.unwrap_or_default();
        let teams_opt = group_attributes.get(&self.config.target.james_team_attr);

        let mut mail_addresses = vec![];

        if let Some(teams) = teams_opt {
            mail_addresses.append(&mut teams.clone());
        }

        let lists_opt = group_attributes.get(&self.config.target.james_list_attr);
        if let Some(lists) = lists_opt {
            mail_addresses.append(&mut lists.clone());
        }

        if !mail_addresses.is_empty() {
            ldap_entry.set_attribute(
                "mail",
                // If this unwrap fails, our implementation is broken because we always set the ou as the
                // identifier of the group.
                mail_addresses,
            );
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    giz_ldap_lib::server::start_ldap_server::<Target>(true).await
}
