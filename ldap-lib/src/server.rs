use std::{
    fmt::{Debug, Display, Formatter},
    net,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use ldap3_proto::{LdapCodec, LdapResultCode};
use openssl::ssl::{Ssl, SslAcceptor};
use uuid::Uuid;

use crate::{entry, keycloak_service_account, proto, server, tls};

#[derive(Parser, Debug)]
#[command(author, version)]
/// A simple LDAP server modeling a user directory by answering LDAP queries with user information fetched from a Keycloak server.
/// The LDAP clients will authenticate with the credentials of a keycloak client and are thus shown the users this
/// keycloak client has access to.
struct CliArguments {
    #[clap(long, short, default_value = "0.0.0.0:3000", help = "Bind address with port")]
    bind_addr: String,

    #[clap(long, default_value = "dc=giz,dc=berlin", help = "The base point of our LDAP tree")]
    base_distinguished_name: String,

    #[clap(long, default_value = "giz.berlin", help = "The name of the organization as shown by the LDAP base entry")]
    organization_name: String,

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

    #[clap(short, long, default_value = "-1", help = "Number of users to fetch from keycloak")]
    num_users: i32,

    #[clap(flatten)]
    log_level: clap_verbosity_flag::Verbosity<clap_verbosity_flag::InfoLevel>,
}

#[derive(Debug)]
pub(crate) struct LdapClientSession {
    pub id: Uuid,
    pub bind_info: Option<proto::LdapBindInfo>,
}

impl LdapClientSession {
    pub fn new() -> Self {
        LdapClientSession {
            id: Uuid::new_v4(),
            bind_info: None,
        }
    }
}

impl Display for LdapClientSession {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let bind_info = if let Some(bind_info) = &self.bind_info {
            format!("bound to '{}'", bind_info.client)
        } else {
            "unbound".to_string()
        };
        write!(f, "{} ({})", self.id, bind_info)
    }
}

/// Run the LDAP server. This method is meant to be the ONLY method called from the main function
/// of a derived binary. It will handle argument parsing and setup logging, which the derived binary
/// is expected to NOT do itself.
pub async fn start_ldap_server(user_attribute_extractor: Box<dyn entry::KeycloakUserAttributeExtractor>) -> anyhow::Result<()> {
    let args = server::CliArguments::parse();

    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Warn)
        .with_module_level("giz_ldap_lib", args.log_level.log_level().unwrap().to_level_filter())
        .env()
        .with_utc_timestamps()
        .init()?;

    let ssl_acceptor = tls::setup_tls(std::path::PathBuf::from(args.certificate), std::path::PathBuf::from(args.certificate_key))?;

    log::info!("Starting LDAPS interface ldaps://{} ...", args.bind_addr);
    let addr = net::SocketAddr::from_str(args.bind_addr.as_str()).context("Could not parse LDAP server address")?;
    let listener = tokio::net::TcpListener::bind(&addr).await.context("Could not bind to LDAP server address")?;
    let handler = Arc::from(proto::LdapHandler::new(
        args.base_distinguished_name.clone(),
        args.num_users,
        keycloak_service_account::ServiceAccountClientBuilder::new(args.keycloak_address, args.keycloak_realm),
        entry::LdapEntryBuilder::new(args.base_distinguished_name, args.organization_name, user_attribute_extractor),
    ));

    loop {
        match listener.accept().await {
            Ok((tcpstream, client_socket_addr)) => {
                tokio::spawn(client_session(handler.clone(), tcpstream, ssl_acceptor.clone(), client_socket_addr));
            }
            Err(e) => {
                log::error!("TCP listener accept error, continuing -> {:?}", e);
            }
        }
    }
}

/// Initiate an LDAP session. Will capture any errors that occur while handling the session and
/// convert them into log messages.
async fn client_session(ldap: Arc<proto::LdapHandler>, tcpstream: tokio::net::TcpStream, tls_acceptor: SslAcceptor, client_address: net::SocketAddr) {
    let mut session = LdapClientSession::new();
    log::info!("Starting new client session {}", session);
    if let Err(e) = _client_session(&mut session, ldap, tcpstream, tls_acceptor, client_address).await {
        log::error!("An error occurred while handling client session {}: {:?}", session.id, e);
    }
    log::info!("Closing client session {}", session);
}

/// Handle receiving and sending of LDAP messages for a client session.
async fn _client_session(
    session: &mut LdapClientSession,
    ldap: Arc<proto::LdapHandler>,
    tcpstream: tokio::net::TcpStream,
    tls_acceptor: SslAcceptor,
    client_address: net::SocketAddr,
) -> anyhow::Result<()> {
    let mut tlsstream = Ssl::new(tls_acceptor.context())
        .and_then(|tls_obj| tokio_openssl::SslStream::new(tls_obj, tcpstream))
        .context("Cannot setup SSL stream")?;
    tokio_openssl::SslStream::accept(Pin::new(&mut tlsstream))
        .await
        .context("Cannot accept SSL stream")?;

    let (r, w) = tokio::io::split(tlsstream);
    let mut ldap_reader = tokio_util::codec::FramedRead::new(r, LdapCodec::default());
    let mut ldap_writer = tokio_util::codec::FramedWrite::new(w, LdapCodec::default());

    // For some reason, some client implementations (namely Apache Directory Studio) appear to just
    // miss our first response if we are too fast :( It will then time out telling us we did not answer.
    // Therefore, we just wait a little before we start processing the first message.
    // This is the lowest delay value for which it appears to work reliably.
    // After the first message exchange, the response listener of the client appears to be properly
    // set up and no further delay is necessary.
    tokio::time::sleep(Duration::from_millis(25)).await;

    while let Some(Ok(protomsg)) = ldap_reader.next().await {
        log::trace!(
            "Session {:?} || Got message from {} {}: {:?}",
            session,
            client_address.ip(),
            client_address.port(),
            protomsg
        );
        let msg_id = protomsg.msgid;
        let operation_result = match ldap3_proto::ServerOps::try_from(protomsg) {
            Ok(server_op) => {
                log::debug!("Session {}, msg {} || Performing operation {:?}", session, msg_id, server_op);
                ldap.perform_ldap_operation(server_op, session).await
            }
            Err(_) => proto::LdapResponseState::Disconnect(ldap3_proto::DisconnectionNotice::gen(
                LdapResultCode::ProtocolError,
                format!("Invalid Request in session {}: msg {}", session.id, msg_id).as_str(),
            )),
        };

        match operation_result {
            proto::LdapResponseState::Bind(new_bind, return_message) => {
                session.bind_info = Some(new_bind);
                log::trace!("Session {:?} || Sending answer {:?}", session, return_message);
                ldap_writer.send(return_message).await?;
            }
            proto::LdapResponseState::Unbind => break,
            proto::LdapResponseState::Respond(return_message) => {
                log::trace!("Session {:?} || Sending answer {:?}", session, return_message);
                ldap_writer.send(return_message).await?;
            }
            proto::LdapResponseState::MultiPartRespond(messages) => {
                for return_message in messages.into_iter() {
                    log::trace!("Session {:?} || Sending answer {:?}", session, return_message);
                    ldap_writer.send(return_message).await?;
                }
            }
            proto::LdapResponseState::Disconnect(return_message) => {
                ldap_writer.send(return_message).await?;
                break;
            }
        };
    }

    Ok(())
}
