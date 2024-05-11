use uuid::Uuid;

use crate::{keycloak_service_account, proto, search};
use ldap3_proto::{LdapFilter, LdapMsg, LdapResultCode, LdapSearchScope, SearchRequest, ServerOps};
use regex::Regex;

#[derive(Debug)]
pub struct LdapError(pub LdapResultCode, pub String);

#[derive(Debug)]
pub struct LdapBindInfo {
    // Used to help ID the user doing the action, makes logging nicer.
    pub client: String,
    // The keycloak service account associated with the credentials passed by the client.
    // Allows us to query the keycloak for user-data.
    // The client will only be able to see data that the service account has access to.
    pub keycloak_service_account: keycloak_service_account::ServiceAccount,
}

pub enum LdapResponseState {
    Bind(LdapBindInfo, LdapMsg),
    Unbind,
    Respond(LdapMsg),
    MultiPartRespond(Vec<LdapMsg>),
    Disconnect(LdapMsg),
}

pub struct LdapHandler {
    keycloak_service_account_builder: keycloak_service_account::ServiceAccountBuilder,
    base_distinguished_name: String,
    rootdse: search::LdapEntry,
    organization_base_entry: search::LdapEntry,
    num_users_to_fetch: i32,
    distinguished_name_regex: Regex,
}

impl LdapHandler {
    pub fn new(
        base_distinguished_name: String,
        num_users_to_fetch: i32,
        keycloak_service_account_builder: keycloak_service_account::ServiceAccountBuilder,
    ) -> Self {
        let distinguished_name_regex = Regex::new(format!("^((?P<attr>[^=]+)=(?P<val>[^=]+),)?{base_distinguished_name}$").as_str())
            // We are responsible for passing a valid name as configuration parameter
            .unwrap();
        let rootdse = search::LdapEntry::rootdse(base_distinguished_name.clone());
        let organization_base_entry = search::LdapEntry::organization(base_distinguished_name.clone());

        LdapHandler {
            keycloak_service_account_builder,
            base_distinguished_name,
            rootdse,
            organization_base_entry,
            num_users_to_fetch,
            distinguished_name_regex,
        }
    }

    pub async fn handle_request(&self, operation: ServerOps, session: &proto::LdapClientSession) -> LdapResponseState {
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
                        LdapResponseState::Respond(sr.gen_error(e.0, e.1.to_string()))
                    }),
                None => LdapResponseState::Respond(sr.gen_error(LdapResultCode::OperationsError, "Must authenticate first!".to_string())),
            },
            ServerOps::Unbind(_) => LdapResponseState::Unbind,
            ServerOps::Compare(cr) => LdapResponseState::Respond(cr.gen_error(LdapResultCode::Other, "Operation not supported".to_string())),
            ServerOps::Whoami(wr) => match &session.bind_info {
                Some(u) => LdapResponseState::Respond(wr.gen_success(format!("u: {}", u.client).as_str())),
                None => LdapResponseState::Respond(wr.gen_operror(format!("Unbound Connection {}", session.id).as_str())),
            },
        }
    }

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
            Err(e) => {
                log::info!("Session {} || LDAP Bind failure, could not authenticate against keycloak, {:?}", session_id, e);
                Err(LdapError(
                    LdapResultCode::InvalidCredentials,
                    "Could not authenticate against Keycloak".to_string(),
                ))
            }
        }
    }

    async fn do_search(&self, session_id: &Uuid, sr: &SearchRequest, bound_user: &LdapBindInfo) -> Result<Vec<LdapMsg>, LdapError> {
        if sr.base.is_empty() && sr.scope == LdapSearchScope::Base {
            log::debug!("Session {} || Search: Found RootDSE", session_id);
            Ok(vec![sr.gen_result_entry(self.rootdse.new_search_result(&sr.attrs)), sr.gen_success()])
        } else if sr.base.eq("cn=subschema") {
            log::debug!("Session {} || Search: Found subschema definition", session_id);
            Ok(vec![
                sr.gen_result_entry(search::LdapEntry::subschema().new_search_result(&sr.attrs)),
                sr.gen_success(),
            ])
        } else {
            let opt_value = match self.distinguished_name_regex.captures(sr.base.as_str()) {
                Some(caps) => caps.name("val").map(|v| v.as_str().to_string()),
                None => {
                    // TODO: return nearest ancestor?
                    log::debug!("Session {} || Search: Non-existing search base DN '{}'", session_id, sr.base);
                    return Err(LdapError(
                        LdapResultCode::NoSuchObject,
                        "LDAP Search failure - invalid basedn or too deep nesting".to_string(),
                    ));
                }
            };

            let mut results = Vec::new();
            let mut add_search_result_on_filter_match = |filter: &LdapFilter, ldap_entry: &search::LdapEntry| -> Result<(), LdapError> {
                if ldap_entry.matches_filter(filter)? {
                    results.push(sr.gen_result_entry(ldap_entry.new_search_result(&sr.attrs)))
                }

                Ok(())
            };

            let users: Vec<search::LdapEntry> = match bound_user.keycloak_service_account.query_users(self.num_users_to_fetch).await {
                Ok(users) => users,
                Err(e) => {
                    log::error!("Could not fetch users from keycloak: {:?}", e);
                    return Err(LdapError(LdapResultCode::Other, "Could not load user information from keycloak".to_string()));
                }
            }
            .into_iter()
            .filter_map(|user| search::LdapEntry::from_keycloak_user(user, &self.base_distinguished_name))
            .collect();

            match opt_value {
                None => {
                    if sr.scope == LdapSearchScope::Base || sr.scope == LdapSearchScope::Subtree {
                        add_search_result_on_filter_match(&sr.filter, &self.organization_base_entry)?
                    }
                    if sr.scope != LdapSearchScope::Base {
                        for user in users {
                            add_search_result_on_filter_match(&sr.filter, &user)?;
                        }
                    }
                }
                Some(value) => {
                    if sr.scope == LdapSearchScope::Base || sr.scope == LdapSearchScope::Subtree {
                        let filter = LdapFilter::And(vec![sr.filter.clone(), LdapFilter::Equality("cn".to_string(), value)]);
                        for user in users {
                            add_search_result_on_filter_match(&filter, &user)?;
                        }
                    }
                }
            }
            log::debug!("Session {} || Search: Found {} ldap entries", session_id, results.len());
            results.push(sr.gen_success());
            Ok(results)
        }
    }
}
