use std::sync::Arc;

use ldap3_proto::{LdapMsg, LdapResultCode, SearchRequest, ServerOps};
use uuid::Uuid;

use crate::{caching, server};

#[derive(Debug)]
pub struct LdapError(pub LdapResultCode, pub String);

#[derive(Debug)]
pub struct LdapBindInfo {
    pub client: String,
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
    ldap_tree_cache: Arc<caching::registry::Registry>,
}

impl LdapHandler {
    pub fn new(ldap_tree_cache: Arc<caching::registry::Registry>) -> Self {
        LdapHandler { ldap_tree_cache }
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
                    tracing::error!(%session, msg = sbr.msgid, error = ?e, "Error performing bind request");
                    LdapResponseState::Respond(sbr.gen_error(e.0, e.1.to_string()))
                }),
            ServerOps::Search(sr) => match &session.bind_info {
                Some(bound_user) => self
                    .do_search(&session.id, &sr, bound_user)
                    .await
                    .map(LdapResponseState::MultiPartRespond)
                    .unwrap_or_else(|e| {
                        tracing::error!(%session, msg = sr.msgid, error = ?e, "Error performing search request");
                        if let LdapResultCode::InvalidCredentials = e.0 {
                            LdapResponseState::Disconnect(ldap3_proto::DisconnectionNotice::r#gen(e.0, e.1.as_str()))
                        } else {
                            LdapResponseState::MultiPartRespond(vec![sr.gen_error(e.0, e.1.to_string())])
                        }
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

        match self.ldap_tree_cache.perform_ldap_bind_for_client(dn, pw).await {
            Ok(()) => {
                tracing::info!(session = %session_id, client = dn, "LDAP Bind success");
                Ok(LdapBindInfo { client: dn.to_string() })
            }
            Err(LdapError(LdapResultCode::Unavailable, _)) => {
                tracing::error!(session = %session_id, "LDAP Bind failure, could not connect to keycloak");
                Err(LdapError(LdapResultCode::Unavailable, "Could not connect to keycloak".to_string()))
            }
            Err(e) => {
                tracing::error!(session = %session_id, error = ?e, "LDAP Bind failure, could not authenticate against keycloak");
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
        let client_cache = self.ldap_tree_cache.obtain_client_cache(bound_user.client.as_str()).await?;
        let search_results = client_cache.search(sr).await?;
        tracing::debug!(session = %session_id, "Search: Found {} ldap entries", search_results.len());
        let mut result_messages: Vec<LdapMsg> = search_results.into_iter().map(|r| sr.gen_result_entry(r)).collect();
        result_messages.push(sr.gen_success());
        Ok(result_messages)
    }
}

#[cfg(test)]
pub mod tests {
    use std::time::Duration;

    use ldap3_proto::proto::LdapOp;
    use rstest::*;

    use super::*;
    use crate::{dto, keycloak_service_account, test_util::test_constants};

    #[fixture]
    pub fn ldap_entry_builder() -> dto::LdapEntryBuilder {
        dto::LdapEntryBuilder::new(
            test_constants::DEFAULT_BASE_DISTINGUISHED_NAME.to_string(),
            test_constants::DEFAULT_ORGANIZATION_NAME.to_string(),
            Box::new(dto::test_util::DummyExtractor {}),
        )
    }

    #[fixture]
    async fn cache_registry(
        #[default(true)] register_default_client: bool,
        #[default(false)] include_group_info: bool,
        ldap_entry_builder: dto::LdapEntryBuilder,
    ) -> Arc<caching::registry::Registry> {
        let cache = caching::registry::Registry::new(
            caching::configuration::Configuration {
                keycloak_service_account_client_builder: keycloak_service_account::ServiceAccountClientBuilder::new("".to_string(), "".to_string()),
                num_users_to_fetch: test_constants::DEFAULT_NUM_USERS_TO_FETCH,
                include_group_info,
                cache_update_interval: Duration::from_secs(30),
                max_entry_inactive_time: Duration::from_secs(60 * 60),
                ldap_entry_builder,
            },
            caching::registry::REGISTRY_DEFAULT_HOUSEKEEPING_INTERVAL,
        );
        if register_default_client {
            cache
                .perform_ldap_bind_for_client(test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD)
                .await
                .expect("registering client should work");
        }
        cache
    }

    mod when_bind {
        use ldap3_proto::{SimpleBindRequest, proto::LdapBindResponse};

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
        async fn with_correct_credentials__then_succeed(
            #[future]
            #[with(false)]
            cache_registry: Arc<caching::registry::Registry>,
        ) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
            let client_session = server::LdapClientSession::new();
            let ldap_handler = LdapHandler::new(cache_registry.await);

            let bind_request = bind_request(test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD);

            // when
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
        async fn with_invalid_credentials__then_fail(
            #[future]
            #[with(false)]
            cache_registry: Arc<caching::registry::Registry>,
        ) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_err(LdapResultCode::Other);
            let client_session = server::LdapClientSession::new();
            let ldap_handler = LdapHandler::new(cache_registry.await);

            let bind_request = bind_request(test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD);

            // when
            let bind_response = ldap_handler.perform_ldap_operation(bind_request, &client_session).await;

            // then
            assert_response_has_failure_code!(bind_response, LdapResultCode::InvalidCredentials);
        }

        #[rstest]
        #[tokio::test]
        async fn without_keycloak_connection__then_fail(
            #[future]
            #[with(false)]
            cache_registry: Arc<caching::registry::Registry>,
        ) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_err(LdapResultCode::Unavailable);
            let client_session = server::LdapClientSession::new();
            let ldap_handler = LdapHandler::new(cache_registry.await);

            let bind_request = bind_request(test_constants::DEFAULT_CLIENT_ID, test_constants::DEFAULT_CLIENT_PASSWORD);

            // when
            let bind_response = ldap_handler.perform_ldap_operation(bind_request, &client_session).await;

            // then
            assert_response_has_failure_code!(bind_response, LdapResultCode::Unavailable);
        }

        #[rstest]
        #[tokio::test]
        async fn anonymously__then_reject_request(
            #[future]
            #[with(false)]
            cache_registry: Arc<caching::registry::Registry>,
        ) {
            // given
            let client_session = server::LdapClientSession::new();
            let ldap_handler = LdapHandler::new(cache_registry.await);

            let bind_request = bind_request("", "");

            // when
            let bind_response = ldap_handler.perform_ldap_operation(bind_request, &client_session).await;

            // then
            assert_response_has_failure_code!(bind_response, LdapResultCode::UnwillingToPerform);
        }
    }

    mod when_search {
        use keycloak_service_account::client::TestGroup;
        use ldap3_proto::{LdapFilter, LdapSearchScope, proto::LdapResult};

        use super::*;

        fn search_request(base: &str, scope: LdapSearchScope, filter: Option<LdapFilter>) -> ServerOps {
            ServerOps::Search(SearchRequest {
                msgid: 0,
                base: base.to_string(),
                scope,
                filter: filter.unwrap_or(LdapFilter::Present("objectclass".to_string())),
                attrs: vec![
                    "objectclass".to_string(),
                    "cn".to_string(),
                    "ou".to_string(),
                    "fullName".to_string(),
                    "uniqueMember".to_string(),
                    "memberOf".to_string(),
                ],
            })
        }

        fn client_session(bound: bool) -> server::LdapClientSession {
            let mut client_session = server::LdapClientSession::new();
            if bound {
                client_session.bind_info = Some(LdapBindInfo {
                    client: test_constants::DEFAULT_CLIENT_ID.to_string(),
                });
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
        async fn unbound__then_reject_request(
            #[future]
            #[with(false)]
            cache_registry: Arc<caching::registry::Registry>,
        ) {
            // given
            let client_session = client_session(false);
            let ldap_handler = LdapHandler::new(cache_registry.await);

            let search_request = search_request("", LdapSearchScope::Base, None);

            // when
            let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

            // then
            assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::OperationsError);
        }

        #[rstest]
        #[tokio::test]
        async fn but_sudden_authentication_error__then_disconnect(
            #[future]
            #[with(false)] // Not registering the client in the cache is equivalent to it being evicted for authentication reasons later.
            cache_registry: Arc<caching::registry::Registry>,
        ) {
            // given
            let client_session = client_session(true);
            let ldap_handler = LdapHandler::new(cache_registry.await);

            let search_request = search_request("", LdapSearchScope::Base, None);

            // when
            let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

            // then
            assert!(matches!(search_result, LdapResponseState::Disconnect(_)));
        }

        #[rstest]
        #[tokio::test]
        async fn root_dse__then_return_result(#[future] cache_registry: Arc<caching::registry::Registry>) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
            let client_session = client_session(true);
            let ldap_handler = LdapHandler::new(cache_registry.await);

            let search_request = search_request("", LdapSearchScope::Base, None);

            // when
            let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

            // then
            assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::Success, "objectclass" => "OpenLDAProotDSE");
        }

        #[rstest]
        #[tokio::test]
        async fn subschema__then_return_result(#[future] cache_registry: Arc<caching::registry::Registry>) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
            let client_session = client_session(true);
            let ldap_handler = LdapHandler::new(cache_registry.await);

            let search_request = search_request("cn=subschema", LdapSearchScope::Base, None);

            // when
            let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

            // then
            assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::Success, "objectclass" => "subschema");
        }

        #[rstest]
        #[tokio::test]
        async fn organization_subtree__then_return_result(#[future] cache_registry: Arc<caching::registry::Registry>) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_users(vec![test_constants::DEFAULT_USER_ID]);
            let client_session = client_session(true);
            let ldap_handler = LdapHandler::new(cache_registry.await);

            let search_request = search_request(test_constants::DEFAULT_BASE_DISTINGUISHED_NAME, LdapSearchScope::Subtree, None);

            // when
            let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

            // then
            assert_search_result_contains_exactly_entries_satisfying!(
                search_result, LdapResultCode::Success,
                "objectclass" => "organization",
                "cn" => test_constants::DEFAULT_USER_ID
            );
        }

        #[rstest]
        #[tokio::test]
        async fn organization_subtree_with_filter__then_only_return_matching_results(#[future] cache_registry: Arc<caching::registry::Registry>) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_users(vec![test_constants::DEFAULT_USER_ID, test_constants::ANOTHER_USER_ID]);
            let client_session = client_session(true);
            let ldap_handler = LdapHandler::new(cache_registry.await);

            let search_request = search_request(
                test_constants::DEFAULT_BASE_DISTINGUISHED_NAME,
                LdapSearchScope::Subtree,
                Some(LdapFilter::Equality("cn".to_string(), test_constants::DEFAULT_USER_ID.to_string())),
            );

            // when
            let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

            // then
            assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::Success, test_constants::DEFAULT_USER_ID);
        }

        #[rstest]
        #[tokio::test]
        async fn specifically_for_entry__then_return_result(
            #[future] cache_registry: Arc<caching::registry::Registry>,
            ldap_entry_builder: dto::LdapEntryBuilder,
        ) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_users(vec![test_constants::DEFAULT_USER_ID]);
            let client_session = client_session(true);
            let ldap_handler = LdapHandler::new(cache_registry.await);

            let search_request = search_request(
                ldap_entry_builder.user_dn(test_constants::DEFAULT_USER_ID).as_str(),
                LdapSearchScope::Base,
                None,
            );

            // when
            let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

            // then
            assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::Success, test_constants::DEFAULT_USER_ID);
        }

        #[rstest]
        #[tokio::test]
        async fn non_existing_entry__then_return_search_failure(#[future] cache_registry: Arc<caching::registry::Registry>) {
            // given
            let _lock = keycloak_service_account::ServiceAccountClient::set_empty();
            let client_session = client_session(true);
            let ldap_handler = LdapHandler::new(cache_registry.await);

            let search_request = search_request("bad-dn", LdapSearchScope::Base, None);

            // when
            let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

            // then
            assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::NoSuchObject);
        }

        mod without_groups {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_do_not_return_groups(#[future] cache_registry: Arc<caching::registry::Registry>) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_users_groups(
                    vec![test_constants::DEFAULT_USER_ID],
                    vec![TestGroup::new(test_constants::DEFAULT_GROUP_ID, vec![0])],
                );
                let client_session = client_session(true);
                let ldap_handler = LdapHandler::new(cache_registry.await);

                let search_request = search_request(test_constants::DEFAULT_BASE_DISTINGUISHED_NAME, LdapSearchScope::Children, None);

                // when
                let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

                // then
                assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::Success, test_constants::DEFAULT_USER_ID);
            }
        }

        mod with_groups {
            use super::*;

            #[rstest]
            #[tokio::test]
            async fn then_do_return_groups(
                #[future]
                #[with(true, true)]
                cache_registry: Arc<caching::registry::Registry>,
            ) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_users_groups(
                    vec![test_constants::DEFAULT_USER_ID],
                    vec![TestGroup::new(test_constants::DEFAULT_GROUP_ID, vec![0])],
                );
                let client_session = client_session(true);
                let ldap_handler = LdapHandler::new(cache_registry.await);

                let search_request = search_request(
                    test_constants::DEFAULT_BASE_DISTINGUISHED_NAME,
                    LdapSearchScope::Children,
                    Some(LdapFilter::Present("uniqueMember".to_string())),
                );

                // when
                let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

                // then
                assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::Success, "ou" => test_constants::DEFAULT_GROUP_ID);
            }

            #[rstest]
            #[tokio::test]
            async fn by_group_objectclass__then_only_return_groups(
                #[future]
                #[with(true, true)]
                cache_registry: Arc<caching::registry::Registry>,
            ) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_users_groups(
                    vec![test_constants::DEFAULT_USER_ID],
                    vec![TestGroup::new(test_constants::DEFAULT_GROUP_ID, vec![0])],
                );
                let client_session = client_session(true);
                let ldap_handler = LdapHandler::new(cache_registry.await);

                // when
                let search_request = search_request(
                    test_constants::DEFAULT_BASE_DISTINGUISHED_NAME,
                    LdapSearchScope::Children,
                    Some(LdapFilter::Equality("objectClass".to_string(), dto::PRIMARY_GROUP_OBJECT_CLASS.to_string())),
                );

                let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

                // then
                assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::Success, "ou" => test_constants::DEFAULT_GROUP_ID);
            }

            /// Note that testing for this only really makes sense here with group support enabled, because otherwise, all LDAP nodes are of type user.
            #[rstest]
            #[tokio::test]
            async fn by_user_objectclass__then_only_return_users(
                #[future]
                #[with(true, true)]
                cache_registry: Arc<caching::registry::Registry>,
            ) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_users_groups(
                    vec![test_constants::DEFAULT_USER_ID],
                    vec![TestGroup::new(test_constants::DEFAULT_GROUP_ID, vec![0])],
                );
                let client_session = client_session(true);
                let ldap_handler = LdapHandler::new(cache_registry.await);

                // when
                let search_request = search_request(
                    test_constants::DEFAULT_BASE_DISTINGUISHED_NAME,
                    LdapSearchScope::Children,
                    Some(LdapFilter::Equality("objectClass".to_string(), dto::PRIMARY_USER_OBJECT_CLASS.to_string())),
                );

                let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

                // then
                assert_search_result_contains_exactly_entries_satisfying!(search_result, LdapResultCode::Success, test_constants::DEFAULT_USER_ID);
            }

            #[rstest]
            #[tokio::test]
            async fn then_assign_users_to_groups(
                #[future]
                #[with(true, true)]
                cache_registry: Arc<caching::registry::Registry>,
                ldap_entry_builder: dto::LdapEntryBuilder,
            ) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_users_groups(
                    vec![test_constants::DEFAULT_USER_ID, test_constants::ANOTHER_USER_ID],
                    vec![
                        TestGroup::new(test_constants::DEFAULT_GROUP_ID, vec![0]),
                        TestGroup::new(test_constants::ANOTHER_GROUP_ID, vec![1]),
                    ],
                );
                let client_session = client_session(true);
                let ldap_handler = LdapHandler::new(cache_registry.await);

                let search_request = search_request(
                    test_constants::DEFAULT_BASE_DISTINGUISHED_NAME,
                    LdapSearchScope::Children,
                    Some(LdapFilter::Present("uniqueMember".to_string())),
                );

                // when
                let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

                // then
                assert_search_result_contains_exactly_entries_satisfying!(
                    search_result, LdapResultCode::Success,
                    "uniqueMember" => ldap_entry_builder.user_dn(test_constants::DEFAULT_USER_ID),
                    "uniqueMember" => ldap_entry_builder.user_dn(test_constants::ANOTHER_USER_ID)
                );
            }

            #[rstest]
            #[tokio::test]
            async fn then_assign_groups_to_users(
                #[future]
                #[with(true, true)]
                cache_registry: Arc<caching::registry::Registry>,
                ldap_entry_builder: dto::LdapEntryBuilder,
            ) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_users_groups(
                    vec![test_constants::DEFAULT_USER_ID, test_constants::ANOTHER_USER_ID],
                    vec![
                        TestGroup::new(test_constants::DEFAULT_GROUP_ID, vec![0]),
                        TestGroup::new(test_constants::ANOTHER_GROUP_ID, vec![1]),
                    ],
                );
                let client_session = client_session(true);
                let ldap_handler = LdapHandler::new(cache_registry.await);

                let search_request = search_request(
                    test_constants::DEFAULT_BASE_DISTINGUISHED_NAME,
                    LdapSearchScope::Children,
                    Some(LdapFilter::Present("memberOf".to_string())),
                );

                // when
                let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

                // then
                assert_search_result_contains_exactly_entries_satisfying!(
                    search_result, LdapResultCode::Success,
                    "memberOf" => ldap_entry_builder.group_dn(test_constants::DEFAULT_GROUP_ID, None),
                    "memberOf" => ldap_entry_builder.group_dn(test_constants::ANOTHER_GROUP_ID, None)
                );
            }

            #[rstest]
            #[tokio::test]
            async fn then_return_subgroups(
                #[future]
                #[with(true, true)]
                cache_registry: Arc<caching::registry::Registry>,
                ldap_entry_builder: dto::LdapEntryBuilder,
            ) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_users_groups(
                    vec![],
                    vec![TestGroup::with_subgroups(
                        test_constants::DEFAULT_GROUP_ID,
                        vec![TestGroup::new(test_constants::ANOTHER_GROUP_ID, vec![])],
                    )],
                );
                let client_session = client_session(true);
                let ldap_handler = LdapHandler::new(cache_registry.await);

                let search_request = search_request(test_constants::DEFAULT_BASE_DISTINGUISHED_NAME, LdapSearchScope::Children, None);

                // when
                let search_result = ldap_handler.perform_ldap_operation(search_request.clone(), &client_session).await;

                // then
                assert_search_result_contains_exactly_entries_satisfying!(
                    search_result, LdapResultCode::Success,
                    "cn" => ldap_entry_builder.full_group_name(&TestGroup::group_name(test_constants::DEFAULT_GROUP_ID), None),
                    // Note the compound group name!
                    "fullName" => ldap_entry_builder.full_group_name(&TestGroup::group_name(test_constants::ANOTHER_GROUP_ID), Some(&TestGroup::group_name(test_constants::DEFAULT_GROUP_ID)))
                );
            }

            #[rstest]
            #[tokio::test]
            async fn then_build_full_subgroup_hierarchy(
                #[future]
                #[with(true, true)]
                cache_registry: Arc<caching::registry::Registry>,
                ldap_entry_builder: dto::LdapEntryBuilder,
            ) {
                // given
                let _lock = keycloak_service_account::ServiceAccountClient::set_users_groups(
                    vec![],
                    vec![TestGroup::with_subgroups(
                        test_constants::DEFAULT_GROUP_ID,
                        vec![TestGroup::with_subgroups(
                            test_constants::ANOTHER_GROUP_ID,
                            vec![TestGroup::new("third-group", vec![])],
                        )],
                    )],
                );
                let client_session = client_session(true);
                let ldap_handler = LdapHandler::new(cache_registry.await);

                let search_request = search_request(
                    ldap_entry_builder.group_dn(test_constants::DEFAULT_GROUP_ID, None).as_str(),
                    LdapSearchScope::OneLevel,
                    None,
                );

                // when
                let search_result = ldap_handler.perform_ldap_operation(search_request, &client_session).await;

                // then
                // should only contain ANOTHER_GROUP as we are only searching for ONE_LEVEL below DEFAULT_GROUP
                assert_search_result_contains_exactly_entries_satisfying!(
                    search_result, LdapResultCode::Success,
                    "cn" => ldap_entry_builder.full_group_name(&TestGroup::group_name(test_constants::ANOTHER_GROUP_ID), None)
                );
            }
        }
    }
}
