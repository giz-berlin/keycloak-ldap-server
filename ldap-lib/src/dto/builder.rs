use std::{collections::HashMap, string::ToString};

use crate::dto::entry;

pub const PRIMARY_USER_OBJECT_CLASS: &str = "inetOrgPerson";
pub const PRIMARY_GROUP_OBJECT_CLASS: &str = "groupOfUniqueNames";

pub(crate) struct LdapEntryBuilder<T: crate::interface::Target> {
    base_distinguished_name: String,
    organization_name: String,
    target: T,
}

impl<T: crate::interface::Target> LdapEntryBuilder<T> {
    pub fn new(base_distinguished_name: String, organization_name: String, target: T) -> Self {
        Self {
            base_distinguished_name,
            organization_name,
            target,
        }
    }

    /// The root-DSE: Provides meta-information on what functionality our server offers.
    pub fn rootdse(&self) -> entry::LdapEntry {
        let mut entry = entry::LdapEntry::new("".to_string(), vec!["OpenLDAProotDSE".to_string()]);
        entry.set_attribute("namingContexts", vec![self.base_distinguished_name.clone()]);
        entry.set_attribute("supportedLDAPVersion", vec!["3".to_string()]);
        // This is really just a dummy schema entry, see Self::subschema.
        // However, we still provide it, as some client implementations may error (or at least omit
        // a warning) if it is not present at all.
        entry.set_attribute("subschemaSubentry", vec!["cn=subschema".to_string()]);
        entry.set_attribute("vendorName", vec!["giz.berlin".to_string()]);
        entry.set_attribute("vendorVersion", vec!["LDAP Keycloak Bridge ".to_string() + env!("CARGO_PKG_VERSION")]);
        // WhoAmI: https://datatracker.ietf.org/doc/html/rfc4532.html#section-2
        entry.set_attribute("supportedExtension", vec!["1.3.6.1.4.1.4203.1.11.3".to_string()]);
        entry
    }

    /// The (dummy) schema specification that our server adheres to.
    /// [RFC 4512, section 4.2](https://datatracker.ietf.org/doc/html/rfc4512.html#section-4.2)
    /// says that this SHALL be specified by servers that permit modifications and is only
    /// RECOMMENDED for servers that do not.
    /// If we wanted to be fully standard-conform, we would need to list all object classes and
    /// attributes we support here, following the required syntax.
    /// As that's really tedious and probably unnecessary for this rather minimal service,
    /// we don't do that.
    /// Instead, we just return an empty schema and rely on the clients to hopefully
    /// use the default schema instead.
    pub fn subschema(&self) -> entry::LdapEntry {
        // This type of objectclass appears to be one of the few ones that is not actually
        // a subclass of top as constructed by Self::new. It still has an objectclass attribute, though,
        // so that should be fine as well.
        entry::LdapEntry::new("cn=subschema".to_string(), vec!["subschema".to_string()])
    }

    /// The root of our Directory Information Tree. Every entry is contained in the naming context
    /// of our organization, meaning it will be a subordinate of this entry.
    pub fn organization(&self) -> entry::LdapEntry {
        let mut entry = entry::LdapEntry::new(self.base_distinguished_name.clone(), vec!["organization".to_string()]);
        entry.set_attribute("organizationName", vec![self.organization_name.clone()]);
        entry
    }

    /// The DN of a user in our LDAP tree.
    pub fn user_dn(&self, user_id: &str) -> String {
        "cn=".to_owned() + user_id + "," + &self.base_distinguished_name
    }

    /// Convert a keycloak user to its corresponding LDAP representation.
    pub fn build_from_keycloak_user(&self, user: keycloak::types::UserRepresentation) -> Option<entry::LdapEntry> {
        tracing::trace!("Build from Keycloak user {user:?}");

        let mut entry = entry::LdapEntry::new(
            self.user_dn(user.id.as_ref()?),
            vec![
                PRIMARY_USER_OBJECT_CLASS.to_string(),
                "organizationalPerson".to_string(),
                "person".to_string(),
            ],
        );
        // No matter the target, the LDAP specification says that we need to have an
        // attribute matching the identifier used in the dsn
        entry.set_attribute("cn", vec![user.id.clone()?]);
        let tracing_user_uid = user.id.clone();
        if let Err(err) = self.target.extract_user(user, &mut entry) {
            tracing::warn!("Extracting user id {tracing_user_uid:?} failed due to {err:?}");
        }

        Some(entry)
    }

    /// The DN of a group in our LDAP tree.
    pub fn group_dn(&self, group_id: &str, parent_group_dn: Option<&str>) -> String {
        if let Some(parent_dn) = parent_group_dn {
            "ou=".to_owned() + group_id + "," + parent_dn
        } else {
            "ou=".to_owned() + group_id + "," + &self.base_distinguished_name
        }
    }

    /// The full name of a group, escaped by replacing all '/' with '_'.
    /// If a parent group name has been given, the name of
    /// the group will be appended to the name of the parent group.
    pub fn full_group_name(&self, group_name: &str, parent_group_name: Option<&str>) -> String {
        let escaped_name = group_name.replace("/", "_");
        if let Some(parent_name) = parent_group_name {
            parent_name.to_owned() + "/" + &escaped_name
        } else {
            escaped_name
        }
    }

    /// Convert a keycloak group and the associated users into a corresponding LDAP group.
    /// Will assign the users to the group and the group to the users.
    /// Note that there might be users associated to the group that we "don't know" in the sense
    /// that they exist in the keycloak, but we cannot see them when querying for all users.
    /// We will ignore these because adding users to the group that we cannot query for later does not make much sense.
    /// This method should ONLY be called on groups that are guaranteed to have id and name set.
    pub fn build_from_keycloak_group_with_associated_users(
        &self,
        group: keycloak::types::GroupRepresentation,
        parent_group: Option<&entry::LdapEntry>,
        known_users: &mut HashMap<String, entry::LdapEntry>,
        all_group_associated_users: &[keycloak::types::UserRepresentation],
    ) -> entry::LdapEntry {
        let mut parent_group_dn = None;
        let mut parent_group_full_name = None;
        if let Some(group) = parent_group {
            parent_group_full_name = group.get_attribute("fullName").unwrap().first().map(String::as_str);
            parent_group_dn = Some(group.dn.as_str());
        }

        let mut entry = entry::LdapEntry::new(
            self.group_dn(group.id.as_ref().unwrap(), parent_group_dn),
            vec![PRIMARY_GROUP_OBJECT_CLASS.to_string()],
        );
        entry.set_attribute("ou", vec![group.id.clone().unwrap()]);
        let raw_group_name = group.name.as_ref().unwrap().as_str();
        entry.set_attribute("cn", vec![self.full_group_name(raw_group_name, None)]);
        entry.set_attribute("fullName", vec![self.full_group_name(raw_group_name, parent_group_full_name)]);

        // See which of the users associated to the group are actually known to us.
        let mut group_members = vec![];
        for associated_user in all_group_associated_users.iter() {
            if let Some(id) = associated_user.id.as_ref() {
                if let Some(user) = known_users.get_mut(id) {
                    user.append_to_attribute("memberOf", entry.dn.clone());
                    group_members.push(self.user_dn(id));
                } else {
                    tracing::warn!(group = entry.dn, user = id, "Group contains user, but that user does not exist!");
                }
            }
        }
        entry.set_attribute("uniqueMember", group_members);

        // Add custom fields
        if let Err(e) = self.target.extract_group(group, &mut entry) {
            tracing::warn!(group = entry.dn, error = %e, "Adding custom attributes to group failed");
        }

        entry
    }
}
