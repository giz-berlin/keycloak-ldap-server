#![deny(warnings)]
#![deny(clippy::all)]
#![cfg_attr(test, allow(dead_code, non_snake_case))]
pub mod entry;
mod keycloak_service_account;
mod proto;
pub mod server;
mod tls;
