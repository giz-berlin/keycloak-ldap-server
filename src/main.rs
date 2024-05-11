#![deny(warnings)]
#![deny(clippy::all)]

mod keycloak_service_account;
mod ldap;
mod proto;
mod search;
mod tls;

use std::net;

use crate::ldap::LdapHandler;
use anyhow::Context;
use clap::Parser;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(author, version)]
/// Exposes a web API, used to do ?
pub struct CliArguments {
    #[clap(long, short, default_value = "0.0.0.0:3000", help = "Bind address with port")]
    bind_addr: String,

    #[clap(long, default_value = "dc=giz,dc=berlin", help = "The base point of our LDAP tree")]
    base_distinguished_name: String,

    #[clap(long, default_value = "ldap_keycloak_bridge.crt.pem", help = "The TLS certificate used by the LDAP server")]
    certificate: String,

    #[clap(
        long,
        default_value = "ldap_keycloak_bridge.key.pem",
        help = "The TLS certificate private key of the LDAP server"
    )]
    certificate_key: String,

    #[clap(long, default_value = "http://localhost:8080", help = "The address of the Keycloak server to fetch users from")]
    keycloak_address: String,

    #[clap(long, default_value = "giz_oidc", help = "The keycloak realm to fetch users from")]
    keycloak_realm: String,

    #[clap(short, long, default_value = "1000", help = "Number of users to fetch from keycloak")]
    num_users: i32,

    #[clap(flatten)]
    log_level: clap_verbosity_flag::Verbosity<clap_verbosity_flag::InfoLevel>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArguments::parse();

    simple_logger::SimpleLogger::new()
        .with_level(args.log_level.log_level().unwrap().to_level_filter())
        .with_utc_timestamps()
        .init()?;

    let ssl_acceptor = tls::setup_tls(std::path::PathBuf::from(args.certificate), std::path::PathBuf::from(args.certificate_key))?;

    log::info!("Starting LDAPS interface ldaps://{} ...", args.bind_addr);
    let addr = net::SocketAddr::from_str(args.bind_addr.as_str()).context("Could not parse LDAP server address")?;
    let listener = TcpListener::bind(&addr).await.context("Could not bind to LDAP server address")?;
    let handler = Arc::from(LdapHandler::new(
        args.base_distinguished_name,
        args.num_users,
        keycloak_service_account::ServiceAccountClientBuilder::new(args.keycloak_address, args.keycloak_realm),
    ));

    loop {
        match listener.accept().await {
            Ok((tcpstream, client_socket_addr)) => {
                tokio::spawn(proto::client_session(handler.clone(), tcpstream, ssl_acceptor.clone(), client_socket_addr));
            }
            Err(e) => {
                log::error!("TCP listener accept error, continuing -> {:?}", e);
            }
        }
    }
}
