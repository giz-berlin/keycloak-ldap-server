use std::{
    fmt::{Debug, Display, Formatter},
    net,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    time,
};

use anyhow::Context;
use clap::{ArgMatches, Command};
use futures_util::{SinkExt, StreamExt};
use ldap3_proto::{LdapCodec, LdapResultCode};
use openssl::ssl::{Ssl, SslAcceptor};
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

use crate::{caching, keycloak_service_account, proto, tls};

/// KIDS - Keycloak LDAP Server
#[derive(Debug)]
pub struct CliArguments {
    pub config: std::path::PathBuf,
    pub log_level: clap_verbosity_flag::Verbosity<clap_verbosity_flag::InfoLevel>,
}

impl CliArguments {
    /// Parse [`CliArguments`] from clap [`ArgMatches`].
    pub fn from_arg_matches(matches: &ArgMatches) -> anyhow::Result<Self> {
        let config = matches
            .get_one::<String>("config")
            .map(std::path::PathBuf::from)
            .context("failed to parse config path argument")?;

        // Parse the log level from clap-verbosity-flag's verbosity arguments.
        // clap_verbosity_flag registers -v/--verbose (counts up) and -q/--quiet (counts down).
        let verbose = matches.get_count("verbose");
        let quiet = matches.get_count("quiet");
        let log_level = clap_verbosity_flag::Verbosity::<clap_verbosity_flag::InfoLevel>::new(verbose, quiet);

        Ok(CliArguments { config, log_level })
    }
}

/// Build a default clap [`Command`].
/// Pass all string arguments as `env!("CARGO_PKG_*")` from your binary crate.
pub fn parse_command(
    name: &'static str,
    version: &'static str,
    author: &'static str,
    about: &'static str,
    long_about: &'static str,
    homepage: &'static str,
) -> Command {
    Command::new(name)
        .version(version)
        .author(author)
        .about(about)
        .long_about(long_about)
        .after_help(homepage)
        .arg(
            clap::Arg::new("config")
                .long("config")
                .short('c')
                .default_value("config.toml")
                .value_name("FILE")
                .help("Path to the config file"),
        )
        .arg(
            clap::Arg::new("verbose")
                .short('v')
                .action(clap::ArgAction::Count)
                .help("Increase logging verbosity (can be repeated: -v, -vv, -vvv)"),
        )
        .arg(
            clap::Arg::new("quiet")
                .short('q')
                .action(clap::ArgAction::Count)
                .help("Decrease logging verbosity (can be repeated: -q, -qq, -qqq)"),
        )
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

/// Convenience macro that parses CLI arguments using the *calling crate's*
/// `CARGO_PKG_NAME`, `CARGO_PKG_VERSION`, `CARGO_PKG_AUTHORS`,
/// `CARGO_PKG_DESCRIPTION` and `CARGO_PKG_HOMEPAGE` environment variables,
/// then runs the LDAP server with the given target type.
///
/// Most binary crates should use this macro in their `main()` body instead of
/// writing argument parsing manually. The version and name shown in `--help`
/// come from each crate's own Cargo.toml via `CARGO_PKG_*` env vars.
///
/// # Example
/// ```ignore
/// fn main() -> anyhow::Result<()> {
///     giz_ldap_lib::cli_run!(Target, giz_ldap_lib::constants::GroupStrategy::SubgroupMembers)
/// }
/// ```
#[macro_export]
macro_rules! server_run {
    ($target:path, $strategy:expr) => {{
        let command = $crate::server::parse_command(
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_AUTHORS"),
            concat!("KIDS - Keycloak LDAP Server: ", env!("CARGO_PKG_NAME")),
            env!("CARGO_PKG_DESCRIPTION"),
            concat!("See also the project website at ", env!("CARGO_PKG_HOMEPAGE")),
        );
        let matches = command.get_matches();
        let args = $crate::server::CliArguments::from_arg_matches(&matches)?;
        $crate::server::start_ldap_server_with_args::<$target>($strategy, args).await
    }};
}

/// Run the LDAP server with pre-parsed CLI arguments.
///
/// Most binary crates should use the [`server_run!`] macro instead, which handles
/// argument parsing using that crate's own `CARGO_PKG_*` environment variables.
pub async fn start_ldap_server_with_args<T: crate::interface::Target>(
    group_strategy: crate::constants::GroupStrategy,
    args: CliArguments,
) -> anyhow::Result<()> {
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

    let config = std::sync::Arc::new(crate::config::Config::<T::TargetConfig>::try_from(args.config)?);

    tracing::debug!("Starting with {config:?}");

    let _guard = if let Some(sentry_config) = config.sentry.as_ref() {
        let dsn = sentry::types::Dsn::from_str(&sentry_config.dsn).map_err(|err| {
            tracing::error!("Invalid Sentry DSN {}: {}", &sentry_config.dsn, err);
            err
        })?;

        let guard = sentry::init(sentry::ClientOptions {
            dsn: Some(dsn),
            release: sentry::release_name!(),
            environment: Some(sentry_config.environment.clone().into()),
            attach_stacktrace: true,
            // TODO: We may not want to have all transactions and thus set this to a lower value.
            // See https://docs.sentry.io/platforms/rust/tracing/
            traces_sample_rate: 1.0,
            in_app_include: vec!["kids"],
            ..Default::default()
        });

        Some(guard)
    } else {
        None
    };

    let ssl_acceptor = if !config.ldap_server.disable_ldaps {
        tracing::info!("Starting LDAPS interface ldaps://{} ...", config.ldap_server.bind_address);
        Some(tls::setup_tls(
            std::path::PathBuf::from(&config.ldap_server.certificate),
            std::path::PathBuf::from(&config.ldap_server.certificate_key),
        )?)
    } else {
        tracing::info!("Starting LDAP interface ldap://{} ...", config.ldap_server.bind_address);
        None
    };

    let target = T::new(config.clone())?;

    let addr = net::SocketAddr::from_str(config.ldap_server.bind_address.as_str()).context("Could not parse LDAP server address")?;
    let listener = tokio::net::TcpListener::bind(&addr).await.context("Could not bind to LDAP server address")?;
    let cache_configuration = caching::configuration::Configuration::<T> {
        keycloak_service_account_client_builder: keycloak_service_account::ServiceAccountClientBuilder::new(
            config.source.keycloak_api.url.clone(),
            config.source.keycloak_api.realm.clone(),
            config.source.keycloak_api.insecure_disable_tls_verification,
        ),
        group_strategy,
        cache_update_interval: time::Duration::from_secs(config.ldap_server.cache_update_interval_secs),
        max_entry_inactive_time: time::Duration::from_secs(config.ldap_server.cache_entry_max_inactive_secs),
        ldap_entry_builder: crate::dto::LdapEntryBuilder::new(
            config.ldap_server.base_distinguished_name.clone(),
            config.ldap_server.organization_name.clone(),
            target,
        ),
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
                    time::Duration::from_millis(config.ldap_server.session_first_answer_delay_millis),
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
async fn client_session<T: crate::interface::Target>(
    ldap: Arc<proto::LdapHandler<T>>,
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
async fn _client_session<T, S>(
    session: &mut LdapClientSession,
    ldap: Arc<proto::LdapHandler<T>>,
    stream: S,
    client_address: net::SocketAddr,
    delay_before_first_answer: time::Duration,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite,
    T: crate::interface::Target,
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
            Err(_) => proto::LdapResponseState::Disconnect(ldap3_proto::DisconnectionNotice::r#gen(
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
