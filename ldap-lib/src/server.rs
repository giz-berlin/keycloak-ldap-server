use std::{
    fmt::{Debug, Display, Formatter},
    net,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    time,
};

use anyhow::Context;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use ldap3_proto::{LdapCodec, LdapResultCode};
use openssl::ssl::{Ssl, SslAcceptor};
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

use crate::{caching, dto, keycloak_service_account, proto, server, tls};

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

    #[clap(
        long,
        default_value = "false",
        default_missing_value = "true",
        help = "Whether this server is running via LDAPS or LDAP"
    )]
    disable_ldaps: bool,

    #[clap(
        long,
        default_value = "certificates/ldap_keycloak_bridge.crt.pem",
        help = "The TLS certificate used by the LDAP server if LDAPS is enabled"
    )]
    certificate: String,

    #[clap(
        long,
        default_value = "certificates/ldap_keycloak_bridge.key.pem",
        help = "The TLS certificate private key used by the LDAP server if LDAPS is enabled"
    )]
    certificate_key: String,

    #[clap(long, default_value = "http://localhost:8080", help = "The address of the Keycloak server to fetch users from")]
    keycloak_address: String,

    #[clap(long, default_value = "giz_oidc", help = "The keycloak realm to fetch users from")]
    keycloak_realm: String,

    #[clap(short, long, default_value = "-1", help = "Number of users to fetch from keycloak")]
    num_users: i32,

    #[clap(
        long,
        default_value = "55",
        help = "Time to wait before sending first response in a session, because some client implementations will miss the first response if it comes in too fast."
    )]
    session_first_answer_delay_millis: u64,

    #[clap(
        long,
        default_value = "30",
        help = "How often to update entries in the LDAP cache. WARNING: If client credentials are changed in the keycloak, the old secret/password will still stay valid for this long!"
    )]
    cache_update_interval_secs: u64,

    #[clap(
        long,
        default_value = "3600",
        help = "How long to wait before pruning LDAP cache entries that are not being accessed."
    )]
    cache_entry_max_inactive_secs: u64,

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

/// Run the LDAP server.
///
/// This method is meant to be the ONLY method called from the main function
/// of a derived binary. It will handle argument parsing and setup logging, which the derived binary
/// is expected to NOT do itself.
///
/// As the concrete user and group information needed depends on the specific use case,
/// this method accepts a [dto::KeycloakAttributeExtractor] implementation used to populate
/// the LDAP entries.
///
/// This method also allows configuring whether group information should be provided as well.
pub async fn start_ldap_server(attribute_extractor: Box<dyn dto::KeycloakAttributeExtractor>, include_group_info: bool) -> anyhow::Result<()> {
    let args = server::CliArguments::parse();

    tracing_subscriber::fmt()
        // Use configured log level for our library, and WARN for everything else.
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::Directive::from_str(
                    ("giz_ldap_lib=".to_owned() + args.log_level.log_level().unwrap().as_str()).as_str(),
                )?)
                .from_env()?
                .add_directive(tracing::Level::WARN.into()),
        )
        .with_file(true)
        .with_line_number(true)
        .init();

    let ssl_acceptor = if !args.disable_ldaps {
        tracing::info!("Starting LDAPS interface ldaps://{} ...", args.bind_addr);
        Some(tls::setup_tls(
            std::path::PathBuf::from(args.certificate),
            std::path::PathBuf::from(args.certificate_key),
        )?)
    } else {
        tracing::info!("Starting LDAP interface ldap://{} ...", args.bind_addr);
        None
    };

    let addr = net::SocketAddr::from_str(args.bind_addr.as_str()).context("Could not parse LDAP server address")?;
    let listener = tokio::net::TcpListener::bind(&addr).await.context("Could not bind to LDAP server address")?;
    let cache_configuration = caching::configuration::Configuration {
        keycloak_service_account_client_builder: keycloak_service_account::ServiceAccountClientBuilder::new(args.keycloak_address, args.keycloak_realm),
        num_users_to_fetch: args.num_users,
        include_group_info,
        cache_update_interval: time::Duration::from_secs(args.cache_update_interval_secs),
        max_entry_inactive_time: time::Duration::from_secs(args.cache_entry_max_inactive_secs),
        ldap_entry_builder: dto::LdapEntryBuilder::new(args.base_distinguished_name, args.organization_name, attribute_extractor),
    };
    let cache_registry = caching::registry::Registry::new(cache_configuration, caching::registry::REGISTRY_DEFAULT_HOUSEKEEPING_INTERVAL);
    let handler = Arc::from(proto::LdapHandler::new(cache_registry));

    loop {
        match listener.accept().await {
            Ok((tcpstream, client_socket_addr)) => {
                tokio::spawn(client_session(
                    handler.clone(),
                    tcpstream,
                    ssl_acceptor.clone(),
                    client_socket_addr,
                    time::Duration::from_millis(args.session_first_answer_delay_millis),
                ));
            }
            Err(e) => {
                tracing::error!(error = ?e, "TCP listener accept error, continuing");
            }
        }
    }
}

/// Initiate an LDAP session. Will capture any errors that occur while handling the session and
/// convert them into log messages.
/// If a TLS acceptor has been passed in, interpret the TcpStream as a SslStream.
/// Else, just use it as an unencrypted stream.
async fn client_session(
    ldap: Arc<proto::LdapHandler>,
    tcp_stream: tokio::net::TcpStream,
    ssl_acceptor: Option<SslAcceptor>,
    client_address: net::SocketAddr,
    delay_before_first_answer: time::Duration,
) -> anyhow::Result<()> {
    let mut session = LdapClientSession::new();
    tracing::info!(%session, "Starting new client session");
    let err = if let Some(acceptor) = ssl_acceptor {
        let mut ssl_stream = Ssl::new(acceptor.context())
            .and_then(|tls_obj| tokio_openssl::SslStream::new(tls_obj, tcp_stream))
            .context("Cannot setup SSL stream")?;
        tokio_openssl::SslStream::accept(Pin::new(&mut ssl_stream))
            .await
            .context("Cannot accept SSL stream")?;
        _client_session(&mut session, ldap, ssl_stream, client_address, delay_before_first_answer).await
    } else {
        _client_session(&mut session, ldap, tcp_stream, client_address, delay_before_first_answer).await
    };
    if let Err(e) = err {
        tracing::error!(%session, error = ?e, "An error occurred while handling client session");
    }
    tracing::info!(%session, "Closing client session");
    // If an error occurred above, this session died, but the server as a whole does not need to care.
    Ok(())
}

/// Handle receiving and sending of LDAP messages for a client session.
async fn _client_session<T>(
    session: &mut LdapClientSession,
    ldap: Arc<proto::LdapHandler>,
    stream: T,
    client_address: net::SocketAddr,
    delay_before_first_answer: time::Duration,
) -> anyhow::Result<()>
where
    T: AsyncRead + AsyncWrite,
{
    let (r, w) = tokio::io::split(stream);
    let mut ldap_reader = tokio_util::codec::FramedRead::new(r, LdapCodec::default());
    let mut ldap_writer = tokio_util::codec::FramedWrite::new(w, LdapCodec::default());

    // For some reason, some client implementations (namely Apache Directory Studio) appear to just
    // miss our first response if we are too fast :( It will then time out telling us we did not answer.
    // Therefore, we wait the configured amount of time before we start processing the first message.
    // After the first message exchange, the response listener of the client appears to be properly
    // set up and no further delay is necessary.
    if !delay_before_first_answer.is_zero() {
        tokio::time::sleep(delay_before_first_answer).await;
    }

    while let Some(Ok(protomsg)) = ldap_reader.next().await {
        tracing::trace!(
            %session,
            client_ip = %client_address.ip(),
            client_port = client_address.port(),
            msg = ?protomsg,
            "Received protocol message"
        );
        let msg_id = protomsg.msgid;
        let operation_result = match ldap3_proto::ServerOps::try_from(protomsg) {
            Ok(server_op) => {
                tracing::debug!(msg_id, %session, operation = ?server_op, "Performing LDAP operation");
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
                tracing::trace!(%session, ?return_message, "Sending protocol answer");
                ldap_writer.send(return_message).await?;
            }
            proto::LdapResponseState::Unbind => break,
            proto::LdapResponseState::Respond(return_message) => {
                tracing::trace!(%session, ?return_message, "Sending protocol answer");
                ldap_writer.send(return_message).await?;
            }
            proto::LdapResponseState::MultiPartRespond(messages) => {
                for return_message in messages.into_iter() {
                    tracing::trace!(%session, ?return_message, "Sending protocol answer");
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
