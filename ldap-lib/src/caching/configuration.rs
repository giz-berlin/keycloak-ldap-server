use std::time;

use crate::{dto, keycloak_service_account};

/// Data class holding cache configuration values.
pub struct Configuration<T: crate::interface::Target> {
    pub keycloak_service_account_client_builder: keycloak_service_account::ServiceAccountClientBuilder,
    pub num_users_to_fetch: Option<i32>,
    pub include_group_info: bool,
    pub cache_update_interval: time::Duration,
    pub max_entry_inactive_time: time::Duration,
    pub ldap_entry_builder: dto::LdapEntryBuilder<T>,
}
