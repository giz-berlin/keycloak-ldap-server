#![cfg_attr(test, allow(dead_code, non_snake_case))]
#[deny(warnings)]
#[deny(clippy::all)]
pub mod entry;
mod keycloak_service_account;
mod proto;
pub mod server;
mod tls;
