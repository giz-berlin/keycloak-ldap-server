use anyhow::Context;
use std::fmt::{Debug, Display, Formatter};
use std::net;
use std::pin::Pin;
use std::sync;

use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use ldap3_proto::{DisconnectionNotice, LdapCodec, LdapResultCode, ServerOps};
use openssl::ssl::{Ssl, SslAcceptor};

use tokio::net::TcpStream;
use tokio_openssl::SslStream;
use tokio_util::codec::{FramedRead, FramedWrite};

use uuid::Uuid;

use crate::ldap;
use crate::ldap::LdapBindInfo;

#[derive(Debug)]
pub struct LdapClientSession {
    pub id: Uuid,
    pub bind_info: Option<LdapBindInfo>,
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

pub async fn client_session(ldap: sync::Arc<ldap::LdapHandler>, tcpstream: TcpStream, tls_acceptor: SslAcceptor, client_address: net::SocketAddr) {
    let mut session = LdapClientSession::new();
    log::info!("Starting new client session {}", session);
    if let Err(e) = _client_session(&mut session, ldap, tcpstream, tls_acceptor, client_address).await {
        log::error!("An error occurred while handling client session {}: {:?}", session.id, e);
    }
    log::info!("Closing client session {}", session);
}

pub async fn _client_session(
    session: &mut LdapClientSession,
    ldap: sync::Arc<ldap::LdapHandler>,
    tcpstream: TcpStream,
    tls_acceptor: SslAcceptor,
    client_address: net::SocketAddr,
) -> anyhow::Result<()> {
    // Start the event
    // From the parameters we need to create an SslContext.
    let mut tlsstream = Ssl::new(tls_acceptor.context())
        .and_then(|tls_obj| SslStream::new(tls_obj, tcpstream))
        .context("Cannot setup SSL stream")?;
    SslStream::accept(Pin::new(&mut tlsstream)).await.context("Cannot accept SSL stream")?;

    let (r, w) = tokio::io::split(tlsstream);
    let mut ldap_reader = FramedRead::new(r, LdapCodec::default());
    let mut ldap_writer = FramedWrite::new(w, LdapCodec::default());

    // Now that we have the session we begin an event loop to process input OR we return.
    while let Some(Ok(protomsg)) = ldap_reader.next().await {
        log::trace!(
            "Session {:?} || Got message from {} {}: {:?}",
            session,
            client_address.ip(),
            client_address.port(),
            protomsg
        );
        let msg_id = protomsg.msgid;
        let operation_result = match ServerOps::try_from(protomsg) {
            Ok(server_op) => {
                log::debug!("Session {}, msg {} || Performing operation {:?}", session, msg_id, server_op);
                ldap.handle_request(server_op, session).await
            }
            Err(_) => ldap::LdapResponseState::Disconnect(DisconnectionNotice::gen(
                LdapResultCode::ProtocolError,
                format!("Invalid Request in session {}: msg {}", session.id, msg_id).as_str(),
            )),
        };

        match operation_result {
            ldap::LdapResponseState::Bind(new_bind, return_message) => {
                session.bind_info = Some(new_bind);
                log::trace!("Session {:?} || Sending answer {:?}", session, return_message);
                ldap_writer.send(return_message).await?;
            }
            ldap::LdapResponseState::Unbind => break,
            ldap::LdapResponseState::Respond(return_message) => {
                log::trace!("Session {:?} || Sending answer {:?}", session, return_message);
                ldap_writer.send(return_message).await?;
            }
            ldap::LdapResponseState::MultiPartRespond(messages) => {
                for return_message in messages.into_iter() {
                    log::trace!("Session {:?} || Sending answer {:?}", session, return_message);
                    ldap_writer.send(return_message).await?;
                }
            }
            ldap::LdapResponseState::Disconnect(return_message) => {
                ldap_writer.send(return_message).await?;
                break;
            }
        };
    }

    Ok(())
}
