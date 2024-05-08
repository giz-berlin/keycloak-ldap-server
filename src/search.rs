use keycloak::types::UserRepresentation;
use ldap3_proto::{LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry};
use std::collections::HashMap;
use std::string::ToString;

use crate::ldap;
use ldap3_proto::proto::LdapSubstringFilter;
use regex::Regex;

const FILTER_MAX_DEPTH: usize = 5;
const FILTER_MAX_ELEMENTS: usize = 10;

pub struct LdapEntry {
    pub dn: String,
    attributes: HashMap<&'static str, Vec<String>>,
    has_subordinates: bool,
}

impl LdapEntry {
    fn new(dn: String, mut class: Vec<String>, has_subordinates: bool) -> Self {
        let mut entry = LdapEntry {
            dn,
            attributes: HashMap::new(),
            has_subordinates,
        };
        class.push("top".to_string()); // Every entry belongs to this class
        entry.attributes.insert("objectClass", class);
        entry
    }

    pub fn rootdse(base_distinguished_name: String) -> Self {
        let mut entry = Self::new("".to_string(), vec!["OpenLDAProotDSE".to_string()], true);
        entry.attributes.insert("namingContexts", vec![base_distinguished_name]);
        entry.attributes.insert("supportedLDAPVersion", vec!["3".to_string()]);
        // This is really just a dummy schema entry, see Self::subschema.
        // However, we still provide it, as some client implementations may error (or at least omit
        // a warning) if it is not present at all.
        entry.attributes.insert("subschemaSubentry", vec!["cn=subschema".to_string()]);
        entry.attributes.insert("vendorName", vec!["giz.berlin".to_string()]);
        entry.attributes.insert("vendorVersion", vec!["LDAP Keycloak Bridge 1.0".to_string()]);
        entry.attributes.insert("supportedExtension", vec!["1.3.6.1.4.1.4203.1.11.3".to_string()]); // WhoAmI
        entry
    }

    pub fn subschema() -> Self {
        // RFC 4512 says that this SHALL be specified by servers that permit modifications and is only
        // RECOMMENDED for servers that do not.
        // If we wanted to be fully standard-conform, we would need to list all object classes and
        // attributes we support here, following the required syntax.
        // As that's really tedious and probably unnecessary for this rather minimal service,
        // we don't do that.
        // Instead, we just return an empty schema and rely on the clients to hopefully
        // use the default schema instead.
        // Also, this type of objectclass appears to be one of the few ones that is not actually
        // a subclass of top as constructed by Self::new. It still has an objectclass attribute, though,
        // so that should be fine as well.
        Self::new("cn=subschema".to_string(), vec!["subschema".to_string()], false)
    }

    pub fn organization(base_distinguished_name: String) -> Self {
        let mut entry = Self::new(base_distinguished_name.clone(), vec!["organization".to_string()], true);
        entry.attributes.insert("organizationName", vec!["giz.berlin".to_string()]);
        entry
    }

    pub fn from_keycloak_user(user: UserRepresentation, base_distinguished_name: &String) -> Option<Self> {
        let user_id = user.id?;
        let dn = "cn=".to_owned() + &user_id + "," + base_distinguished_name;
        let mut entry = Self::new(
            dn,
            vec![
                "inetOrgPerson".to_string(),
                "organizationalPerson".to_string(),
                "person".to_string(),
            ],
            false,
        );
        entry.attributes.insert("cn", vec![user_id]);
        entry.attributes.insert("displayName", vec![user.username?]);
        entry.attributes.insert("givenName", vec![user.first_name.unwrap_or("".to_string())]);
        entry.attributes.insert(
            "surname",
            vec![
                // We would really like to have a name for the user so that the client can know who they
                // are dealing with.
                user.last_name?,
            ],
        );
        entry.attributes.insert(
            "mail",
            vec![
                // A user without a mail is not very useful in our case.
                user.email?,
            ],
        );
        Some(entry)
    }

    pub fn new_search_result(&self, requested_attributes: &[String]) -> LdapSearchResultEntry {
        let all_requested = requested_attributes.is_empty() ||
            // We don't have any operational attributes, so this is equivalent
            requested_attributes.iter().any(|attr| attr == "*" || attr == "+");
        let target_attributes: Vec<(&&str, &Vec<String>)> = if all_requested {
            self.attributes.iter().collect()
        } else {
            requested_attributes
                .iter()
                .filter(|&attr| !attr.is_empty())
                .filter_map(|attr| self.attributes.get_key_value(attr.as_str()))
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
        if requested_attributes.iter().any(|attr| attr == "hasSubordinates") {
            result.attributes.push(LdapPartialAttribute {
                atype: "hasSubordinates".to_string(),
                vals: vec![self.has_subordinates.to_string().into_bytes()],
            });
        }

        result
    }

    pub fn matches_filter(&self, f: &LdapFilter) -> Result<bool, ldap::LdapError> {
        let mut max_elements = FILTER_MAX_ELEMENTS;
        self._matches_filter(f, FILTER_MAX_DEPTH, &mut max_elements)
    }

    fn _matches_filter(&self, f: &LdapFilter, depth: usize, elems: &mut usize) -> Result<bool, ldap::LdapError> {
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
                if let Some(values) = self.attributes.get(a.as_str()) {
                    Ok(values.iter().any(|val| val == v))
                } else {
                    // If the attribute does not even exist, we have no match.
                    Ok(false)
                }
            }
            LdapFilter::Present(a) => Ok(self.attributes.contains_key(a.as_str())),
            LdapFilter::Substring(a, LdapSubstringFilter { initial, any, final_ }) => {
                if let Some(values) = self.attributes.get(a.as_str()) {
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
                Err(ldap::LdapError(LdapResultCode::UnwillingToPerform, "Operation not implemented".to_string()))
            }
        }
    }

    pub fn consume_resource(&self, resource: &mut usize, consumption_amount: usize) -> Result<(), ldap::LdapError> {
        *resource = resource
            .checked_sub(consumption_amount)
            .ok_or(ldap::LdapError(LdapResultCode::UnwillingToPerform, "Filter too expensive".to_string()))?;
        Ok(())
    }
}
