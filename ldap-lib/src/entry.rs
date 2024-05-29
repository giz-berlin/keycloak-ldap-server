use keycloak::types::UserRepresentation;
use ldap3_proto::{LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry};
use std::collections::HashMap;
use std::string::ToString;

use crate::proto;
use ldap3_proto::proto::LdapSubstringFilter;
use regex::Regex;

const FILTER_MAX_DEPTH: usize = 5;
const FILTER_MAX_ELEMENTS: usize = 10;

/// An interface fur customizing which attributes of a Keycloak user should be added to the
/// corresponding LDAP entry.
// Trait bound in order to pass impls to async functions
pub trait KeycloakUserAttributeExtractor: Send + Sync {
    /// Add the desired user attributes to the keycloak entry.
    fn extract(&self, user: UserRepresentation, ldap_entry: &mut LdapEntry) -> anyhow::Result<()>;
}

pub(crate) struct LdapEntryBuilder {
    base_distinguished_name: String,
    extractor: Box<dyn KeycloakUserAttributeExtractor>,
}

impl LdapEntryBuilder {
    pub fn new(base_distinguished_name: String, extractor: Box<dyn KeycloakUserAttributeExtractor>) -> Self {
        Self {
            base_distinguished_name,
            extractor,
        }
    }

    /// The root-DSE: Provides meta-information on what functionality our server offers.
    pub fn rootdse(&self) -> LdapEntry {
        let mut entry = LdapEntry::new("".to_string(), vec!["OpenLDAProotDSE".to_string()], true);
        entry.set_attribute("namingContexts", vec![self.base_distinguished_name.clone()]);
        entry.set_attribute("supportedLDAPVersion", vec!["3".to_string()]);
        // This is really just a dummy schema entry, see Self::subschema.
        // However, we still provide it, as some client implementations may error (or at least omit
        // a warning) if it is not present at all.
        entry.set_attribute("subschemaSubentry", vec!["cn=subschema".to_string()]);
        entry.set_attribute("vendorName", vec!["giz.berlin".to_string()]);
        entry.set_attribute("vendorVersion", vec!["LDAP Keycloak Bridge 1.0".to_string()]);
        entry.set_attribute("supportedExtension", vec!["1.3.6.1.4.1.4203.1.11.3".to_string()]); // WhoAmI
        entry
    }

    /// The (dummy) schema specification that our server adheres to.
    /// RFC 4512 says that this SHALL be specified by servers that permit modifications and is only
    /// RECOMMENDED for servers that do not.
    /// If we wanted to be fully standard-conform, we would need to list all object classes and
    /// attributes we support here, following the required syntax.
    /// As that's really tedious and probably unnecessary for this rather minimal service,
    /// we don't do that.
    /// Instead, we just return an empty schema and rely on the clients to hopefully
    /// use the default schema instead.
    pub fn subschema(&self) -> LdapEntry {
        // This type of objectclass appears to be one of the few ones that is not actually
        // a subclass of top as constructed by Self::new. It still has an objectclass attribute, though,
        // so that should be fine as well.
        LdapEntry::new("cn=subschema".to_string(), vec!["subschema".to_string()], false)
    }

    /// The root of our Directory Information Tree. Every entry is containing in the naming context
    /// of our organization, meaning it will be a subordinate of this entry.
    pub fn organization(&self) -> LdapEntry {
        let mut entry = LdapEntry::new(self.base_distinguished_name.clone(), vec!["organization".to_string()], true);
        entry.set_attribute("organizationName", vec!["giz.berlin".to_string()]);
        entry
    }

    /// Convert a keycloak user to its corresponding LDAP representation.
    pub fn build_from_keycloak_user(&self, user: UserRepresentation) -> Option<LdapEntry> {
        let user_id = user.id.clone()?;
        let dn = "cn=".to_owned() + &user_id + "," + &self.base_distinguished_name;
        let mut entry = LdapEntry::new(
            dn,
            vec![
                "inetOrgPerson".to_string(),
                "organizationalPerson".to_string(),
                "person".to_string(),
            ],
            false,
        );
        // No matter the extractor, the LDAP specification says that we need to have an
        // attribute matching the identifier used in the dsn
        entry.set_attribute("cn", vec![user.id.clone()?]);
        self.extractor.extract(user, &mut entry).ok()?;

        Some(entry)
    }
}

/// A data class representing an entry in our directory.
pub struct LdapEntry {
    pub dn: String,
    attributes: HashMap<String, Vec<String>>,
    has_subordinates: bool,
}

impl LdapEntry {
    pub fn new(dn: String, mut class: Vec<String>, has_subordinates: bool) -> Self {
        let mut entry = LdapEntry {
            dn,
            attributes: HashMap::new(),
            has_subordinates,
        };
        class.push("top".to_string()); // Every entry belongs to this class
        entry.set_attribute("objectClass", class);
        entry
    }

    /// Sets an attribute for this entry. As LDAP is case-insensitive regarding attribute names,
    /// we will convert all attribute names to lower case.
    pub fn set_attribute(&mut self, name: &str, value: Vec<String>) {
        self.attributes.insert(name.to_lowercase(), value);
    }

    /// Gets the value of an attribute. As LDAP is case-insensitive, query for the lowercased version
    /// of the requested attribute.
    pub fn get_attribute(&self, name: &str) -> Option<&Vec<String>> {
        self.attributes.get(name.to_lowercase().as_str())
    }

    fn get_key_value(&self, attribute_name: &str) -> Option<(&String, &Vec<String>)> {
        self.attributes.get_key_value(attribute_name.to_lowercase().as_str())
    }

    /// The client appears to have searched for this entry. Convert this entry into the data
    /// format that will be sent over the wire, only including the attributes that the client requested.
    /// Note that this method will NOT check whether this entry matches the filter specified by the client.
    pub fn new_search_result(&self, requested_attributes: &[String]) -> LdapSearchResultEntry {
        let all_requested = requested_attributes.is_empty() ||
            // We don't have any operational attributes, so this is equivalent
            requested_attributes.iter().any(|attr| attr == "*" || attr == "+");
        let target_attributes: Vec<(&String, &Vec<String>)> = if all_requested {
            self.attributes.iter().collect()
        } else {
            requested_attributes
                .iter()
                .filter(|&attr| !attr.is_empty())
                .filter_map(|attr| self.get_key_value(attr))
                .collect()
        };

        let mut result = LdapSearchResultEntry {
            dn: self.dn.clone(),
            attributes: target_attributes
                .into_iter()
                .map(|(key, value)| LdapPartialAttribute {
                    atype: key.to_string(),
                    vals: value.iter().map(|entry| entry.as_bytes().to_vec()).collect(),
                })
                .collect(),
        };

        // We have this separately because this is not really an attribute of the entry,
        // but rather metainformation the client may explicitly query.
        if requested_attributes.iter().any(|attr| attr.to_lowercase() == "hassubordinates") {
            result.attributes.push(LdapPartialAttribute {
                atype: "hasSubordinates".to_string(),
                vals: vec![self.has_subordinates.to_string().into_bytes()],
            });
        }

        result
    }

    /// Check whether this entry matches the filter the client specified in its search.
    /// Enforces some limits on how complex that filter is allowed to be.
    pub fn matches_filter(&self, f: &LdapFilter) -> Result<bool, proto::LdapError> {
        let mut max_elements = FILTER_MAX_ELEMENTS;
        self._matches_filter(f, FILTER_MAX_DEPTH, &mut max_elements)
    }

    fn _matches_filter(&self, f: &LdapFilter, depth: usize, elems: &mut usize) -> Result<bool, proto::LdapError> {
        let mut new_depth = depth;
        self.consume_resource(&mut new_depth, 1)?;
        match f {
            LdapFilter::And(l) => {
                self.consume_resource(elems, l.len())?;

                for sub_filter in l.iter() {
                    let res = self._matches_filter(sub_filter, new_depth, elems)?;
                    if !res {
                        return Ok(false);
                    }
                }

                Ok(true)
            }
            LdapFilter::Or(l) => {
                self.consume_resource(elems, l.len())?;

                for sub_filter in l.iter() {
                    let res = self._matches_filter(sub_filter, new_depth, elems)?;
                    if res {
                        return Ok(true);
                    }
                }

                Ok(false)
            }
            LdapFilter::Not(sub_filter) => {
                self.consume_resource(elems, 1)?;
                Ok(!self._matches_filter(sub_filter, depth, elems)?)
            }
            LdapFilter::Equality(a, v) => {
                if let Some(values) = self.get_attribute(a) {
                    Ok(values.iter().any(|val| val == v))
                } else {
                    // If the attribute does not even exist, we have no match.
                    Ok(false)
                }
            }
            LdapFilter::Present(a) => Ok(self.get_attribute(a).is_some()),
            LdapFilter::Substring(a, LdapSubstringFilter { initial, any, final_ }) => {
                if let Some(values) = self.get_attribute(a) {
                    // This might not be the most efficient way to do this, but it would have
                    // been much more tedious to implement it manually with substring searches.
                    let mut regex = "".to_string();
                    if let Some(search) = initial {
                        regex += "^";
                        regex += &regex::escape(search);
                        regex += ".*"
                    }
                    for search in any {
                        regex += &regex::escape(search);
                        regex += ".*"
                    }
                    if let Some(search) = final_ {
                        regex += &regex::escape(search);
                        regex += "$"
                    }
                    // This should not fail, as the search values are fully escaped and the remaining RegEx is valid
                    let substr_filter = Regex::new(regex.as_str()).unwrap();
                    Ok(values.iter().any(|value| substr_filter.is_match(value)))
                } else {
                    // If the attribute does not even exist, we have no match.
                    Ok(false)
                }
            }
            _ => {
                log::error!("Unsupported filter operation");
                Err(proto::LdapError(LdapResultCode::UnwillingToPerform, "Operation not implemented".to_string()))
            }
        }
    }

    fn consume_resource(&self, resource: &mut usize, consumption_amount: usize) -> Result<(), proto::LdapError> {
        *resource = resource
            .checked_sub(consumption_amount)
            .ok_or(proto::LdapError(LdapResultCode::UnwillingToPerform, "Filter too expensive".to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use keycloak::types::UserRepresentation;
    use crate::entry::{KeycloakUserAttributeExtractor, LdapEntry};

    pub struct DummyExtractor;

    impl KeycloakUserAttributeExtractor for DummyExtractor {
        fn extract(&self, _user: UserRepresentation, _ldap_entry: &mut LdapEntry) -> anyhow::Result<()> {
            Ok(())
        }
    }
}
