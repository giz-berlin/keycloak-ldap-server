use ldap3_proto::{LdapMsg, LdapResultCode, SearchRequest, ServerOps};
use regex::Regex;
use uuid::Uuid;

use crate::{entry, keycloak_service_account, server};

#[derive(Debug)]
pub struct LdapError(pub LdapResultCode, pub String);

#[derive(Debug)]
pub struct LdapBindInfo {
    pub client: String,
    // The keycloak service account associated with the credentials passed by the client.
    // Allows us to query the keycloak for user-data.
    // The client will only be able to see data that the service account has access to.
    pub keycloak_service_account: keycloak_service_account::ServiceAccountClient,
}

pub enum LdapResponseState {
    Bind(LdapBindInfo, LdapMsg),
    Unbind,
    Respond(LdapMsg),
    MultiPartRespond(Vec<LdapMsg>),
    Disconnect(LdapMsg),
}

/// A handler capable of adhering to the LDAP protocol and properly perform LDAP operations.
/// It knows how our DIT (directory information tree) looks like and how to bind clients by
/// handing off the authentication decision to a Keycloak server.
pub struct LdapHandler {
    keycloak_service_account_builder: keycloak_service_account::ServiceAccountClientBuilder,
    num_users_to_fetch: i32,
    include_group_info: bool,
    distinguished_name_regex: Regex,
    ldap_entry_builder: entry::LdapEntryBuilder,
}

impl LdapHandler {
    pub fn new(
        base_distinguished_name: String,
        num_users_to_fetch: i32,
        include_group_info: bool,
        keycloak_service_account_builder: keycloak_service_account::ServiceAccountClientBuilder,
        ldap_entry_builder: entry::LdapEntryBuilder,
    ) -> Self {
        let distinguished_name_regex = Regex::new(format!("^(([^=]+)=([^=]+),)?{base_distinguished_name}$").as_str())
            // We are responsible for passing a valid name as configuration parameter
            .unwrap();

        LdapHandler {
            keycloak_service_account_builder,
            num_users_to_fetch,
            include_group_info,
            distinguished_name_regex,
            ldap_entry_builder,
        }
    }

    /// Perform an LDAP operation, producing proper LDAP responses.
    /// Errors occurring during the execution will be converted to LDAP error states.
    pub async fn perform_ldap_operation(&self, operation: ServerOps, session: &server::LdapClientSession) -> LdapResponseState {
        match operation {
            ServerOps::SimpleBind(sbr) => self
                .do_bind(&session.id, &sbr.dn, &sbr.pw)
                .await
                .map(|token| LdapResponseState::Bind(token, sbr.gen_success()))
                .unwrap_or_else(|e| {
                    log::error!("Session {}, msg {} || Error performing bind request: {:?}", session.id, sbr.msgid, e);
                    LdapResponseState::Respond(sbr.gen_error(e.0, e.1.to_string()))
                }),
            ServerOps::Search(sr) => match &session.bind_info {
                Some(bound_user) => self
                    .do_search(&session.id, &sr, bound_user)
                    .await
                    .map(LdapResponseState::MultiPartRespond)
                    .unwrap_or_else(|e| {
                        log::error!("Session {}, msg {} || Error performing search request: {:?}", session.id, sr.msgid, e);
                        LdapResponseState::MultiPartRespond(vec![sr.gen_error(e.0, e.1.to_string())])
                    }),
                None => LdapResponseState::MultiPartRespond(vec![sr.gen_error(LdapResultCode::OperationsError, "Must authenticate first!".to_string())]),
            },
            ServerOps::Unbind(_) => LdapResponseState::Unbind,
            ServerOps::Compare(cr) => LdapResponseState::Respond(cr.gen_error(LdapResultCode::Other, "Operation not supported".to_string())),
            ServerOps::Whoami(wr) => match &session.bind_info {
                Some(u) => LdapResponseState::Respond(wr.gen_success(format!("u: {}", u.client).as_str())),
                None => LdapResponseState::Respond(wr.gen_operror(format!("Unbound Connection {}", session.id).as_str())),
            },
        }
    }

    /// Perform an LDAP bind. We treat the credentials we receive as keycloak client credentials;
    /// whether the bind succeeds will depend on whether these credentials can be actually used to
    /// authenticate against keycloak.
    /// Note that we disallow anonymous authentication, even though that might not be entirely
    /// standard-conform.
    async fn do_bind(&self, session_id: &Uuid, dn: &str, pw: &str) -> Result<LdapBindInfo, LdapError> {
        if dn.is_empty() || pw.is_empty() {
            return Err(LdapError(
                LdapResultCode::UnwillingToPerform,
                "Anonymous bind requested, which we do not allow!".to_string(),
            ));
        }

        let user_keycloak_service_account = self.keycloak_service_account_builder.new_service_account(dn, pw).await;

        match user_keycloak_service_account {
            Ok(service_account) => {
                log::info!("Session {} || LDAP Bind success for client {}", session_id, dn);
                Ok(LdapBindInfo {
                    client: dn.to_string(),
                    keycloak_service_account: service_account,
                })
            }
            Err(LdapError(LdapResultCode::Unavailable, _)) => {
                log::error!("Session {} || LDAP Bind failure, could not connect to keycloak", session_id);
                Err(LdapError(LdapResultCode::Unavailable, "Could not connect to keycloak".to_string()))
            }
            Err(e) => {
                log::error!("Session {} || LDAP Bind failure, could not authenticate against keycloak, {:?}", session_id, e);
                Err(LdapError(
                    LdapResultCode::InvalidCredentials,
                    "Could not authenticate against Keycloak".to_string(),
                ))
            }
        }
    }

    /// Perform an LDAP search. The actual logic determining which LDAP entries match the search
    /// request is implemented directly on the tree formed by the entries.
    async fn do_search(&self, session_id: &Uuid, sr: &SearchRequest, bound_user: &LdapBindInfo) -> Result<Vec<LdapMsg>, LdapError> {
        let mut root = self.ldap_entry_builder.rootdse();
        root.add_subordinate(self.ldap_entry_builder.subschema());

        let mut organization = self.ldap_entry_builder.organization();
        if self.distinguished_name_regex.captures(sr.base.as_str()).is_some() {
            self.query_keycloak(&mut organization, bound_user).await?;
        }
        root.add_subordinate(organization);

        let search_results = root.find(sr)?;
        log::debug!("Session {} || Search: Found {} ldap entries", session_id, search_results.len());
        let mut result_messages: Vec<LdapMsg> = search_results.into_iter().map(|r| sr.gen_result_entry(r)).collect();
        result_messages.push(sr.gen_success());
        Ok(result_messages)
    }

    /// Load user and group information from keycloak and insert them as subordinates of the organization entry.
    /// Will only load groups if the handler was configured to do so.
    async fn query_keycloak(&self, organization: &mut entry::LdapEntry, bound_user: &LdapBindInfo) -> Result<(), LdapError> {
        let mut users: std::collections::HashMap<String, entry::LdapEntry> = bound_user
            .keycloak_service_account
            .query_users(self.num_users_to_fetch)
            .await?
            .into_iter()
            .filter_map(|user| Some((user.id.clone()?, self.ldap_entry_builder.build_from_keycloak_user(user)?)))
            .collect();

        if self.include_group_info {
            let groups: Vec<keycloak::types::GroupRepresentation> = bound_user.keycloak_service_account.query_named_groups().await?;
            for group in groups.into_iter() {
                let group_associated_users = bound_user
                    .keycloak_service_account
                    .query_users_in_group(
                        // We can unwrap here because we made sure to filter out groups without a id
                        group.id.as_ref().unwrap(),
                    )
                    .await?;
                let ldap_group = self
                    .ldap_entry_builder
                    .build_from_keycloak_group_with_associated_users(group, &mut users, &group_associated_users);
                organization.add_subordinate(ldap_group);
            }
        }

        users.into_values().for_each(|user| {
            organization.add_subordinate(user);
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ldap3_proto::proto::LdapOp;
    use rstest::*;

    use super::*;
    use crate::{entry, keycloak_service_account};

    const DEFAULT_BASE_DISTINGUISHED_NAME: &str = "dc=base_dsn";
    const DEFAULT_ORGANIZATION_NAME: &str = "organization";
    const DEFAULT_USERS_TO_FETCH: i32 = 5;

    #[fixture]
    fn entry_builder() -> entry::LdapEntryBuilder {
        entry::LdapEntryBuilder::new(
            DEFAULT_BASE_DISTINGUISHED_NAME.to_string(),
            DEFAULT_ORGANIZATION_NAME.to_string(),
            Box::new(entry::tests::DummyExtractor {}),
        )
    }

    #[fixture]
    fn ldap_handler(entry_builder: entry::LdapEntryBuilder) -> LdapHandler {
        LdapHandler::new(
            DEFAULT_BASE_DISTINGUISHED_NAME.to_string(),
            DEFAULT_USERS_TO_FETCH,
            false,
            keycloak_service_account::ServiceAccountClientBuilder::new("".to_string(), "".to_string()),
            entry_builder,
        )
    }

    mod when_bind {
        use ldap3_proto::{proto::LdapBindResponse, SimpleBindRequest};

        use super::*;

        fn bind_request(dn: &str, pw: &str) -> ServerOps {
            ServerOps::SimpleBind(SimpleBindRequest {
                msgid: 1,
                dn: dn.to_string(),
                pw: pw.to_string(),
            })
        }

        #[rstest]
        #[tokio::test]
        async fn with_correct_credentials__then_succeed(ldap_handler: LdapHandler) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();

            // when
            let bind_request = bind_request("test_client", "client_secret");
            let client_session = server::LdapClientSession::new();

            let bind_response = ldap_handler.perform_ldap_operation(bind_request, &client_session).await;

            // then
            assert!(matches!(bind_response, LdapResponseState::Bind(_, _)))
        }

        macro_rules! assert_response_has_failure_code {
            ($response:expr, $result_code:expr) => {
                if let LdapResponseState::Respond(msg) = $response {
                    if let LdapOp::BindResponse(LdapBindResponse { res, saslcreds: _ }) = msg.op {
                        assert_eq!(res.code, $result_code);
                    }
                } else {
                    panic!("Unexpected operation result")
                }
            };
        }

        #[rstest]
        #[tokio::test]
        async fn with_invalid_credentials__then_fail(ldap_handler: LdapHandler) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_err(LdapResultCode::Other);

            // when
            let bind_request = bind_request("test_client", "client_secret");
            let client_session = server::LdapClientSession::new();

            let bind_response = ldap_handler.perform_ldap_operation(bind_request, &client_session).await;

            // then
            assert_response_has_failure_code!(bind_response, LdapResultCode::InvalidCredentials);
        }

        #[rstest]
        #[tokio::test]
        async fn without_keycloak_connection__then_fail(ldap_handler: LdapHandler) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_err(LdapResultCode::Unavailable);

            // when
            let bind_request = bind_request("test_client", "client_secret");
            let client_session = server::LdapClientSession::new();

            let bind_response = ldap_handler.perform_ldap_operation(bind_request, &client_session).await;

            // then
            assert_response_has_failure_code!(bind_response, LdapResultCode::Unavailable);
        }

        #[rstest]
        #[tokio::test]
        async fn anonymously__then_reject_request(ldap_handler: LdapHandler) {
            // when
            let bind_request = bind_request("", "");
            let client_session = server::LdapClientSession::new();

            let bind_response = ldap_handler.perform_ldap_operation(bind_request, &client_session).await;

            // then
            assert_response_has_failure_code!(bind_response, LdapResultCode::UnwillingToPerform);
        }
    }

    mod when_search {
        use ldap3_proto::{proto::LdapResult, LdapFilter, LdapSearchScope};

        use super::*;

        const DEFAULT_USER_ID: &str = "s0m3-us3r";

        fn search_request(base: &str, scope: LdapSearchScope, filter: Option<LdapFilter>) -> ServerOps {
            ServerOps::Search(SearchRequest {
                msgid: 0,
                base: base.to_string(),
                scope,
                filter: filter.unwrap_or(LdapFilter::Present("objectclass".to_string())),
                attrs: vec![
                    "objectclass".to_string(),
                    "cn".to_string(),
                    "uniqueMember".to_string(),
                    "memberOf".to_string(),
                ],
            })
        }

        async fn client_session(bound: bool, ldap_handler: &LdapHandler) -> server::LdapClientSession {
            let mut client_session = server::LdapClientSession::new();
            if bound {
                client_session.bind_info = Some(LdapBindInfo {
                    client: "default_client".to_string(),
                    keycloak_service_account: ldap_handler.keycloak_service_account_builder.new_service_account("", "").await.unwrap(),
                })
            }
            client_session
        }

        macro_rules! assert_search_result_contains_exactly_entries_satisfying {
            ($search_result:expr, $result_code:expr $(, $cn_value:expr)+) => {
                assert_search_result_contains_exactly_entries_satisfying!($search_result, $result_code $(, "cn" => $cn_value)+)
            };
            ($search_result:expr, $result_code:expr $(, $attr:expr => $value:expr)*) => {
                #[allow(unused_mut)] let mut previous_results = 0;
                if let LdapResponseState::MultiPartRespond(msgs) = $search_result {
                    $(
                        assert!(&msgs.iter().any(|msg| {
                            if let LdapOp::SearchResultEntry(entry) = &msg.op {
                                let target_attr = entry.attributes.iter().find(|attr| attr.atype == $attr);
                                if target_attr.is_none() {
                                    return false
                                }
                                let attr_vals: Vec<&str> = target_attr.unwrap().vals.iter().map(|val| std::str::from_utf8(val).unwrap()).collect();
                                attr_vals.iter().any(|val| val == &$value)
                            } else {
                                false
                            }
                        }), "Messages did not contain an entry with '{}' = '{}'", $attr, $value);
                        previous_results += 1;
                    )*
                    assert_eq!(msgs.len(), previous_results + 1);
                    if let LdapOp::SearchResultDone(LdapResult{ code, matcheddn: _, message: _, referral: _}) = &msgs.get(previous_results).unwrap().op {
                        assert_eq!(code, &$result_code)
                    } else {
                        panic!("Expected search result done message")
                    }
                } else {
                    panic!("Unexpected operation result")
                }
            };
        }

        #[rstest]
        #[tokio::test]
        async fn unbound__then_reject_request(ldap_handler: LdapHandler) {
            // when
            let search_request = search_request("", LdapSearchScope::Base, None);
            let client_session = client_session(false, &ldap_handler).await;

            let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

            // then
            assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::OperationsError);
        }

        #[rstest]
        #[tokio::test]
        async fn root_dse__then_return_result(ldap_handler: LdapHandler) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();

            // when
            let search_request = search_request("", LdapSearchScope::Base, None);
            let client_session = client_session(true, &ldap_handler).await;

            let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

            // then
            assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::Success, "objectclass" => "OpenLDAProotDSE");
        }

        #[rstest]
        #[tokio::test]
        async fn subschema__then_return_result(ldap_handler: LdapHandler) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();

            // when
            let search_request = search_request("cn=subschema", LdapSearchScope::Base, None);
            let client_session = client_session(true, &ldap_handler).await;

            let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

            // then
            assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::Success, "objectclass" => "subschema");
        }

        #[rstest]
        #[tokio::test]
        async fn organization_subtree__then_return_result(ldap_handler: LdapHandler) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_users(vec![DEFAULT_USER_ID]);

            // when
            let search_request = search_request(DEFAULT_BASE_DISTINGUISHED_NAME, LdapSearchScope::Subtree, None);
            let client_session = client_session(true, &ldap_handler).await;

            let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

            // then
            assert_search_result_contains_exactly_entries_satisfying!(
                search_result, LdapResultCode::Success,
                "objectclass" => "organization",
                "cn" => DEFAULT_USER_ID
            );
        }

        #[rstest]
        #[tokio::test]
        async fn organization_subtree_with_filter__then_only_return_matching_results(ldap_handler: LdapHandler) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_users(vec![DEFAULT_USER_ID, "other-user-id"]);

            // when
            let search_request = search_request(
                DEFAULT_BASE_DISTINGUISHED_NAME,
                LdapSearchScope::Subtree,
                Some(LdapFilter::Equality("cn".to_string(), DEFAULT_USER_ID.to_string())),
            );
            let client_session = client_session(true, &ldap_handler).await;

            let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

            // then
            assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::Success, DEFAULT_USER_ID);
        }

        #[rstest]
        #[tokio::test]
        async fn specifically_for_entry__then_return_result(ldap_handler: LdapHandler, entry_builder: entry::LdapEntryBuilder) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_users(vec![DEFAULT_USER_ID]);

            // when
            let search_request = search_request(entry_builder.user_dn(DEFAULT_USER_ID).as_str(), LdapSearchScope::Base, None);
            let client_session = client_session(true, &ldap_handler).await;

            let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

            // then
            assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::Success, DEFAULT_USER_ID);
        }

        #[rstest]
        #[tokio::test]
        async fn non_existing_entry__then_return_search_failure(ldap_handler: LdapHandler) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();

            // when
            let search_request = search_request("bad-dn", LdapSearchScope::Base, None);
            let client_session = client_session(true, &ldap_handler).await;

            let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

            // then
            assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::NoSuchObject);
        }

        mod without_groups {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_do_not_return_groups(ldap_handler: LdapHandler) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_users_groups(vec![DEFAULT_USER_ID], vec![("group-id", vec![0])]);

                // when
                let search_request = search_request(DEFAULT_BASE_DISTINGUISHED_NAME, LdapSearchScope::Children, None);
                let client_session = client_session(true, &ldap_handler).await;

                let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

                // then
                assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::Success, DEFAULT_USER_ID);
            }
        }

        mod with_groups {
            use super::*;

            #[fixture]
            fn ldap_handler(entry_builder: entry::LdapEntryBuilder) -> LdapHandler {
                let mut handler = super::ldap_handler(entry_builder);
                handler.include_group_info = true;
                handler
            }

            const DEFAULT_GROUP_ID: &'static str = "group_id";

            #[rstest]
            #[tokio::test]
            async fn then_do_return_groups(ldap_handler: LdapHandler) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_users_groups(vec![DEFAULT_USER_ID], vec![(DEFAULT_GROUP_ID, vec![0])]);

                // when
                let search_request = search_request(
                    DEFAULT_BASE_DISTINGUISHED_NAME,
                    LdapSearchScope::Children,
                    Some(LdapFilter::Present("uniqueMember".to_string())),
                );
                let client_session = client_session(true, &ldap_handler).await;

                let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

                // then
                assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::Success, DEFAULT_GROUP_ID);
            }

            #[rstest]
            #[tokio::test]
            async fn then_assign_users_to_groups(ldap_handler: LdapHandler, entry_builder: entry::LdapEntryBuilder) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_users_groups(
                    vec![DEFAULT_USER_ID, "another_user"],
                    vec![(DEFAULT_GROUP_ID, vec![0]), ("another_group", vec![1])],
                );

                // when
                let search_request = search_request(
                    DEFAULT_BASE_DISTINGUISHED_NAME,
                    LdapSearchScope::Children,
                    Some(LdapFilter::Present("uniqueMember".to_string())),
                );
                let client_session = client_session(true, &ldap_handler).await;

                let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

                // then
                assert_search_result_contains_exactly_entries_satisfying!(
                    search_result, LdapResultCode::Success,
                    "uniqueMember" => entry_builder.user_dn(DEFAULT_USER_ID),
                    "uniqueMember" => entry_builder.user_dn("another_user")
                );
            }

            #[rstest]
            #[tokio::test]
            async fn then_assign_groups_to_users(ldap_handler: LdapHandler, entry_builder: entry::LdapEntryBuilder) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_users_groups(
                    vec![DEFAULT_USER_ID, "another_user"],
                    vec![(DEFAULT_GROUP_ID, vec![0]), ("another_group", vec![1])],
                );

                // when
                let search_request = search_request(
                    DEFAULT_BASE_DISTINGUISHED_NAME,
                    LdapSearchScope::Children,
                    Some(LdapFilter::Present("memberOf".to_string())),
                );
                let client_session = client_session(true, &ldap_handler).await;

                let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

                // then
                assert_search_result_contains_exactly_entries_satisfying!(
                    search_result, LdapResultCode::Success,
                    "memberOf" => entry_builder.group_dn(DEFAULT_GROUP_ID),
                    "memberOf" => entry_builder.group_dn("another_group")
                );
            }
        }
    }
}
