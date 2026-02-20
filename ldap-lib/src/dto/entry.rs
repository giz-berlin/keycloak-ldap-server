use std::{collections::HashMap, string::ToString};

use itertools::Itertools;
use ldap3_proto::{LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry, LdapSearchScope, SearchRequest, proto::LdapSubstringFilter};
use regex::Regex;

use crate::proto;

const FILTER_MAX_DEPTH: usize = 5;
const FILTER_MAX_ELEMENTS: usize = 10;

/// A data class representing an entry in our directory.
pub struct LdapEntry {
    pub dn: String,
    attributes: HashMap<String, Vec<String>>,
    subordinates: Vec<LdapEntry>,
}

impl LdapEntry {
    pub fn new(dn: String, mut class: Vec<String>) -> Self {
        let mut entry = LdapEntry {
            dn,
            attributes: HashMap::new(),
            subordinates: Vec::new(),
        };
        class.push("top".to_string()); // Every entry belongs to this class
        entry.set_attribute("objectClass", class);
        entry
    }

    fn is_root(&self) -> bool {
        self.dn.is_empty()
    }

    /// Sets an attribute for this entry. As LDAP is case-insensitive regarding attribute names,
    /// we will convert all attribute names to lower case.
    pub fn set_attribute(&mut self, name: &str, value: Vec<String>) {
        self.attributes.insert(name.to_lowercase(), value);
    }

    /// Appends a value to the list associated with a attribute. Will create the attribute if
    /// it does not yet exist.
    pub fn append_to_attribute(&mut self, name: &str, value: String) {
        if let Some(entry) = self.attributes.get_mut(name.to_lowercase().as_str()) {
            entry.push(value);
        } else {
            self.set_attribute(name, vec![value]);
        }
    }

    /// Gets the value of an attribute. As LDAP is case-insensitive, query for the lowercased version
    /// of the requested attribute.
    pub fn get_attribute(&self, name: &str) -> Option<&Vec<String>> {
        self.attributes.get(name.to_lowercase().as_str())
    }

    /// Get a key-value pair for an attribute. Ensures to return the key casing specified by the client.
    fn get_key_value<'a>(&'a self, attribute_name: &'a String) -> Option<(&'a String, &'a Vec<String>)> {
        Some((attribute_name, self.get_attribute(attribute_name)?))
    }

    /// Add another ldap entry as a subordinate of this entry.
    /// Will make sure that this connection is actually valid, e.g., the DN of this entry
    /// must be part of the DN of the subordinate.
    /// If this check fails, this method will panic instead of returning an error, because
    /// failing to satisfy this constraint is considered a programming mistake.
    pub fn add_subordinate(&mut self, subordinate: LdapEntry) {
        assert!(subordinate.dn.ends_with(&self.dn));
        self.subordinates.push(subordinate);
    }

    /// Find all entries satisfying the given search request in the subtree of this entry.
    pub fn find(&self, search_request: &SearchRequest) -> Result<Vec<LdapSearchResultEntry>, proto::LdapError> {
        let mut results = Vec::new();
        if search_request.base == self.dn {
            // Should we add ourselves?
            match search_request.scope {
                LdapSearchScope::Base => {
                    if self.matches_filter(&search_request.filter)? {
                        results.push(self.new_search_result(&search_request.attrs))
                    }
                }
                LdapSearchScope::Subtree => {
                    // The rootDSE should not be included itself in subtree searches.
                    if !self.is_root() && self.matches_filter(&search_request.filter)? {
                        results.push(self.new_search_result(&search_request.attrs));
                    }
                }
                _ => (),
            }

            // What about our subordinates?
            if search_request.scope != LdapSearchScope::Base {
                let subsearch_scope = match search_request.scope {
                    LdapSearchScope::Subtree | LdapSearchScope::Children => {
                        // Recursively add the whole subtree while still honoring the other search
                        // parameters.
                        LdapSearchScope::Subtree
                    }
                    LdapSearchScope::OneLevel => {
                        // Tell all subordinates to only add themselves while still honoring the other
                        // search parameters.
                        LdapSearchScope::Base
                    }
                    _ => panic!("This code path should not be reachable."),
                };

                for subordinate in self.subordinates.iter() {
                    results.append(&mut subordinate.find(&SearchRequest {
                        base: subordinate.dn.clone(),
                        scope: subsearch_scope.clone(),
                        ..search_request.clone()
                    })?);
                }
            }

            return Ok(results);
        }

        // This search request does not apply to us as base, but it might apply to some of our
        // subordinates.
        for subordinate in self.subordinates.iter() {
            if search_request.base.ends_with(&subordinate.dn) {
                results.append(&mut subordinate.find(search_request)?)
            }
        }

        if results.is_empty() {
            return Err(proto::LdapError(
                LdapResultCode::NoSuchObject,
                "LDAP Search failure - invalid basedn or too deep nesting".to_string(),
            ));
        }
        Ok(results)
    }

    /// The client appears to have searched for this entry. Convert this entry into the data
    /// format that will be sent over the wire, only including the attributes that the client requested.
    /// Note that this method will NOT check whether this entry matches the filter specified by the client.
    fn new_search_result(&self, requested_attributes: &[String]) -> LdapSearchResultEntry {
        let all_requested = requested_attributes.is_empty() ||
            // We don't have any operational attributes, so this is equivalent
            requested_attributes.iter().any(|attr| attr == "*" || attr == "+");
        let target_attributes: Vec<(&String, &Vec<String>)> = if all_requested {
            self.attributes.iter().collect()
        } else {
            requested_attributes.iter().unique().filter_map(|attr| self.get_key_value(attr)).collect()
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
        if let Some(attr) = requested_attributes.iter().find(|attr| attr.to_lowercase() == "hassubordinates") {
            result.attributes.push(LdapPartialAttribute {
                atype: attr.to_string(), // We ensure to retain the casing specified by the client.
                vals: vec![self.has_subordinates().to_string().into_bytes()],
            });
        }

        result
    }

    /// Checks whether this entry has at least one subordinate.
    pub fn has_subordinates(&self) -> bool {
        !self.subordinates.is_empty()
    }

    /// Check whether this entry matches the filter the client specified in its search.
    /// Enforces some limits on how complex that filter is allowed to be.
    fn matches_filter(&self, f: &LdapFilter) -> Result<bool, proto::LdapError> {
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
            LdapFilter::Not(sub_filter) => Ok(!self._matches_filter(sub_filter, new_depth, elems)?),
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
                tracing::error!("Unsupported filter operation");
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
    use rstest::*;

    use super::*;

    mod when_finding {
        use super::*;

        const ENTRY_AT: &str = "dc=a,dc=t";
        const ENTRY_BT: &str = "dc=b,dc=t";
        const ENTRY_CAT: &str = "dc=c,dc=a,dc=t";
        const ENTRY_DAT: &str = "dc=d,dc=a,dc=t";

        #[fixture]
        fn test_ldap_tree() -> LdapEntry {
            let mut root = LdapEntry::new("".to_string(), vec![]);
            let mut at = LdapEntry::new(ENTRY_AT.to_string(), vec!["a".to_string()]);
            let bt = LdapEntry::new(ENTRY_BT.to_string(), vec!["b".to_string()]);
            let cat = LdapEntry::new(ENTRY_CAT.to_string(), vec!["c".to_string()]);
            let dat = LdapEntry::new(ENTRY_DAT.to_string(), vec!["d".to_string()]);

            at.add_subordinate(cat);
            at.add_subordinate(dat);
            root.add_subordinate(at);
            root.add_subordinate(bt);
            root
        }

        fn search_request(base: &str, scope: LdapSearchScope, filter: Option<LdapFilter>, attrs: Option<Vec<String>>) -> SearchRequest {
            SearchRequest {
                msgid: 0,
                base: base.to_string(),
                scope,
                filter: filter.unwrap_or(LdapFilter::Present("objectclass".to_string())),
                attrs: attrs.unwrap_or(vec!["objectclass".to_string()]),
            }
        }

        #[rstest]
        #[case::scope_base_root("", LdapSearchScope::Base, vec![""])]
        #[case::scope_base(ENTRY_AT, LdapSearchScope::Base, vec![ENTRY_AT])]
        #[case::scope_subtree(ENTRY_AT, LdapSearchScope::Subtree, vec![ENTRY_AT, ENTRY_CAT, ENTRY_DAT])]
        // Exclude root itself.
        #[case::root__scope_subtree("", LdapSearchScope::Subtree, vec![ENTRY_AT, ENTRY_CAT, ENTRY_DAT, ENTRY_BT])]
        #[case::scope_children(ENTRY_AT, LdapSearchScope::Children, vec![ENTRY_CAT, ENTRY_DAT])]
        #[case::scope_one_level("", LdapSearchScope::OneLevel, vec![ENTRY_AT, ENTRY_BT])]
        fn then_find_correct_entries(
            test_ldap_tree: LdapEntry,
            #[case] search_base: &str,
            #[case] search_scope: LdapSearchScope,
            #[case] expected_results: Vec<&str>,
        ) {
            // when
            let results = test_ldap_tree.find(&search_request(search_base, search_scope, None, None)).unwrap();

            // then
            assert_eq!(expected_results.len(), results.len());
            assert!(expected_results.into_iter().all(|exp| results.iter().any(|e| e.dn == exp)));
        }

        #[rstest]
        fn then_honour_filter(test_ldap_tree: LdapEntry) {
            // when
            let results = test_ldap_tree
                .find(&search_request(
                    "",
                    LdapSearchScope::Children,
                    Some(LdapFilter::Equality("objectClass".to_string(), "a".to_string())),
                    None,
                ))
                .unwrap();

            // then
            assert_eq!(1, results.len());
            assert!(results.iter().any(|e| e.dn == ENTRY_AT));
        }

        #[rstest]
        fn then_honour_attrs(test_ldap_tree: LdapEntry) {
            // when
            let results = test_ldap_tree
                .find(&search_request(ENTRY_AT, LdapSearchScope::Base, None, Some(vec!["objectClass".to_string()])))
                .unwrap();

            // then
            assert_eq!(1, results.len());
            let attrs = &results.get(0).unwrap().attributes;
            assert_eq!(1, attrs.len());
            assert_eq!("objectClass", attrs.get(0).unwrap().atype)
        }
    }

    mod when_creating_search_result {
        use super::*;

        const DUMMY_DN: &str = "dummy_dn";
        const DUMMY_CLASS: &str = "dummy_class";

        #[fixture]
        fn entry_with_some_attributes() -> LdapEntry {
            let mut entry = LdapEntry::new(DUMMY_DN.to_string(), vec![DUMMY_CLASS.to_string()]);
            entry.set_attribute("abc", vec!["abc".to_string()]);
            entry.set_attribute("def", vec!["def".to_string()]);
            entry.set_attribute("ghi", vec!["ghi".to_string()]);
            entry
        }

        #[rstest]
        fn then_return_dn(entry_with_some_attributes: LdapEntry) {
            // when & then
            assert_eq!(DUMMY_DN, entry_with_some_attributes.new_search_result(&[]).dn)
        }

        #[rstest]
        fn then_return_correct_object_class(entry_with_some_attributes: LdapEntry) {
            // when
            let result = entry_with_some_attributes.new_search_result(&["objectClass".to_string()]);

            // then
            let classes: Vec<&str> = result.attributes.get(0).unwrap().vals.iter().map(|c| std::str::from_utf8(c).unwrap()).collect();
            assert_eq!(2, classes.len());
            assert_eq!(&DUMMY_CLASS, classes.get(0).unwrap());
            assert_eq!(&"top", classes.get(1).unwrap());
        }

        #[rstest]
        fn then_return_all_attributes_when_no_filter(entry_with_some_attributes: LdapEntry) {
            // when & then
            assert_eq!(1 + 3, entry_with_some_attributes.new_search_result(&[]).attributes.len())
        }

        #[rstest]
        fn then_return_all_attributes_on_special_selectors(entry_with_some_attributes: LdapEntry) {
            // when & then
            assert_eq!(1 + 3, entry_with_some_attributes.new_search_result(&["*".to_string()]).attributes.len());
            assert_eq!(1 + 3, entry_with_some_attributes.new_search_result(&["+".to_string()]).attributes.len());
        }

        #[rstest]
        fn then_return_only_requested_attributes(entry_with_some_attributes: LdapEntry) {
            // when
            let result = entry_with_some_attributes.new_search_result(&["abc".to_string(), "ghi".to_string()]);

            // then
            assert_eq!(2, result.attributes.len());
            assert_eq!("abc", result.attributes.get(0).unwrap().atype);
            assert_eq!("ghi", result.attributes.get(1).unwrap().atype);
        }

        #[rstest]
        fn then_do_not_return_attribute_twice(entry_with_some_attributes: LdapEntry) {
            // when
            let result = entry_with_some_attributes.new_search_result(&["abc".to_string(), "abc".to_string()]);

            // when & then
            assert_eq!(1, result.attributes.len());
        }

        #[rstest]
        fn then_ignore_requested_empty_attribute(entry_with_some_attributes: LdapEntry) {
            // when
            let result = entry_with_some_attributes.new_search_result(&["".to_string()]);

            // when & then
            assert_eq!(0, result.attributes.len());
        }

        #[rstest]
        fn then_ignore_non_existent_attribute(entry_with_some_attributes: LdapEntry) {
            // when
            let result = entry_with_some_attributes.new_search_result(&["non-existent-attribute".to_string()]);

            // when & then
            assert_eq!(0, result.attributes.len());
        }

        #[rstest]
        fn then_return_attribute_cased_as_requested(entry_with_some_attributes: LdapEntry) {
            // when
            let result = entry_with_some_attributes.new_search_result(&["aBc".to_string(), "DEf".to_string(), "GhI".to_string()]);

            // when & then
            assert_eq!(3, result.attributes.len());
            assert_eq!("aBc", result.attributes.get(0).unwrap().atype);
            assert_eq!("DEf", result.attributes.get(1).unwrap().atype);
            assert_eq!("GhI", result.attributes.get(2).unwrap().atype);
        }

        #[rstest]
        fn then_entry_with_subordinates_has_subordinates(mut entry_with_some_attributes: LdapEntry) {
            // given
            entry_with_some_attributes.add_subordinate(LdapEntry::new("x,".to_string() + DUMMY_DN, vec![]));

            // when
            let result = entry_with_some_attributes.new_search_result(&["hasSubordinates".to_string()]);

            // then
            assert_eq!("hasSubordinates", result.attributes.get(0).unwrap().atype);
            let has_subordinates_str = std::str::from_utf8(result.attributes.get(0).unwrap().vals.get(0).unwrap()).unwrap();
            assert_eq!("true", has_subordinates_str);
        }

        #[rstest]
        fn then_entry_without_subordinates_has_no_subordinates(entry_with_some_attributes: LdapEntry) {
            // when
            let result = entry_with_some_attributes.new_search_result(&["hasSubordinates".to_string()]);

            // then
            assert_eq!("hasSubordinates", result.attributes.get(0).unwrap().atype);
            let has_subordinates_str = std::str::from_utf8(result.attributes.get(0).unwrap().vals.get(0).unwrap()).unwrap();
            assert_eq!("false", has_subordinates_str);
        }
    }

    mod when_filtering {
        use ldap3_proto::{LdapFilter, proto::LdapMatchingRuleAssertion};

        use super::*;

        #[fixture]
        fn dummy_entry() -> LdapEntry {
            LdapEntry::new("".to_string(), Vec::new())
        }

        fn matching_filter() -> LdapFilter {
            LdapFilter::Present("objectclass".to_string())
        }

        fn non_matching_filter() -> LdapFilter {
            LdapFilter::Not(Box::new(matching_filter()))
        }

        #[rstest]
        fn then_and_filter_works_correctly(dummy_entry: LdapEntry) {
            // when & then
            assert!(
                dummy_entry
                    .matches_filter(&LdapFilter::And(vec![matching_filter(), matching_filter(), matching_filter()]))
                    .unwrap()
            );
            assert!(
                !dummy_entry
                    .matches_filter(&LdapFilter::And(vec![matching_filter(), non_matching_filter(), matching_filter()]))
                    .unwrap()
            );
        }

        #[rstest]
        fn then_or_filter_works_correctly(dummy_entry: LdapEntry) {
            // when & then
            assert!(
                !dummy_entry
                    .matches_filter(&LdapFilter::Or(vec![non_matching_filter(), non_matching_filter(), non_matching_filter()]))
                    .unwrap()
            );
            assert!(
                dummy_entry
                    .matches_filter(&LdapFilter::Or(vec![non_matching_filter(), non_matching_filter(), matching_filter()]))
                    .unwrap()
            );
        }

        #[rstest]
        fn then_not_filter_works_correctly(dummy_entry: LdapEntry) {
            // when & then
            assert!(dummy_entry.matches_filter(&LdapFilter::Not(Box::new(non_matching_filter()))).unwrap());
            assert!(!dummy_entry.matches_filter(&LdapFilter::Not(Box::new(matching_filter()))).unwrap());
        }

        #[rstest]
        #[case("*", true)]
        #[case("very*", true)]
        #[case("*long*", true)]
        #[case("long*", false)]
        #[case("*long", false)]
        #[case("v*long*l*e", true)]
        fn then_substring_filter_works_correctly(mut dummy_entry: LdapEntry, #[case] filter_string: String, #[case] should_match: bool) {
            // given
            dummy_entry.set_attribute("attr", vec!["very_long_value".to_string()]);

            // when & then
            assert_eq!(
                should_match,
                dummy_entry
                    .matches_filter(&LdapFilter::Substring("attr".to_string(), LdapSubstringFilter::from(filter_string)))
                    .unwrap()
            )
        }

        #[rstest]
        fn then_present_filter_works_correctly(mut dummy_entry: LdapEntry) {
            // given
            dummy_entry.set_attribute("attr", vec!["value".to_string()]);

            // when & then
            assert!(dummy_entry.matches_filter(&LdapFilter::Present("attr".to_string())).unwrap());
            assert!(!dummy_entry.matches_filter(&LdapFilter::Present("other_attr".to_string())).unwrap());
        }

        #[rstest]
        fn then_equality_filter_works_correctly(mut dummy_entry: LdapEntry) {
            // given
            dummy_entry.set_attribute("attr", vec!["value".to_string()]);

            // when & then
            assert!(
                dummy_entry
                    .matches_filter(&LdapFilter::Equality("attr".to_string(), "value".to_string()))
                    .unwrap()
            );
            assert!(
                !dummy_entry
                    .matches_filter(&LdapFilter::Equality("attr".to_string(), "other_value".to_string()))
                    .unwrap()
            );
            assert!(
                !dummy_entry
                    .matches_filter(&LdapFilter::Equality("other_attr".to_string(), "value".to_string()))
                    .unwrap()
            );
        }

        #[rstest]
        fn then_match_case_insensitive(mut dummy_entry: LdapEntry) {
            // given
            dummy_entry.set_attribute("attribute", vec!["value".to_string()]);

            let filter = LdapFilter::Present("AttRIbUTe".to_string());

            // when & then
            assert!(dummy_entry.matches_filter(&filter).unwrap())
        }

        #[rstest]
        #[case::le(LdapFilter::LessOrEqual("".to_string(), "".to_string()))]
        #[case::ge(LdapFilter::GreaterOrEqual("".to_string(), "".to_string()))]
        #[case::approx(LdapFilter::Approx("".to_string(), "".to_string()))]
        #[case::extensible(LdapFilter::Extensible(LdapMatchingRuleAssertion{..Default::default()}))]
        fn then_reject_unsupported_filter(dummy_entry: LdapEntry, #[case] filter: LdapFilter) {
            // when & then
            assert!(dummy_entry.matches_filter(&filter).is_err())
        }

        #[rstest]
        fn then_forbid_too_many_filter_elements(dummy_entry: LdapEntry) {
            // given
            let mut sub_filters = Vec::new();
            for _ in 0..FILTER_MAX_ELEMENTS + 1 {
                sub_filters.push(matching_filter());
            }

            // when & then
            assert!(dummy_entry.matches_filter(&LdapFilter::And(sub_filters.clone())).is_err());
            assert!(dummy_entry.matches_filter(&LdapFilter::Or(sub_filters)).is_err());
        }

        #[rstest]
        #[case::not(|f| LdapFilter::Not(Box::new(f)))]
        #[case::and(|f| LdapFilter::And(vec![f]))]
        #[case::or(|f| LdapFilter::Or(vec![f]))]
        fn then_forbid_too_deep_nesting<F>(dummy_entry: LdapEntry, #[case] mk_filter: F)
        where
            F: Fn(LdapFilter) -> LdapFilter,
        {
            // given
            let mut filter = matching_filter();
            for _ in 0..FILTER_MAX_DEPTH + 1 {
                filter = mk_filter(filter);
            }

            // when & then
            assert!(dummy_entry.matches_filter(&filter).is_err())
        }
    }
}
