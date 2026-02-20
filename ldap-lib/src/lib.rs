#![deny(warnings)]
#![deny(clippy::all)]
#![cfg_attr(test, allow(dead_code, non_snake_case))]
mod caching;
pub mod config;
pub mod dto;
pub mod interface;
mod keycloak_service_account;
mod proto;
pub mod server;
#[cfg(test)]
mod test_util;
mod tls;
