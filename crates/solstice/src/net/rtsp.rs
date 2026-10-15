//! The RTSP listener.
//!
//! Plaintext and GCM-wrapped messages arrive on the same socket; the MSB of the
//! first word says which. Once a session is encrypted, a plaintext message is
//! refused rather than tolerated (`rtsp.cpp:166`).

use std::net::SocketAddr;
use std::sync::Arc;

use solstice_gamestream::crypto::gcm::SessionCrypto;
use solstice_gamestream::rtsp::sdp::{Limits, StreamConfig};
use solstice_gamestream::rtsp::{encrypted, message, RtspOutcome, RtspServer, StreamPorts};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// What a completed negotiation hands to the supervisor.
#[derive(Debug)]
pub struct Negotiated {
    /// The client's requested configuration, already clamped.
    pub config: Box<StreamConfig>,
    /// Which launch session it belongs to.
    pub session_id: String,
}

/// Everything the listener needs to answer for one launch session.
#[derive(Clone)]
pub struct RtspContext {
    /// The session id, echoed as the RTSP `Session:` attribute.
    pub session_id: String,
    /// The `rikey`, when the client negotiated encrypted RTSP.
    pub key: Option<[u8; 16]>,
    /// UDP ports to advertise.
    pub ports: StreamPorts,
    /// Ceilings applied to the ANNOUNCE.
    pub limits: Limits,
    /// Encryption the host supports.
    pub supported_encryption: u32,
    /// Encryption the host insists on.
    pub required_encryption: u32,
}

/// Build the context for whichever launch session is current.
///
/// RTSP carries no identity of its own: the connection is bound to a session by
/// the fact that a session exists and the client was handed its URL over mutual
/// TLS moments earlier. With `max_sessions = 1` that is unambiguous.
pub fn context_for(
    host: &solstice_gamestream::nvhttp::Host,
    ports: StreamPorts,
    limits: Limits,
    supported_encryption: u32,
    required_encryption: u32,
) -> Option<RtspContext> {
    let sessions = host.sessions.lock().expect("session lock");
    let session = sessions.first()?;
    Some(RtspContext {
        session_id: session.id.clone(),
        key: session.encrypted_rtsp.then(|| *session.rikey),
        ports,
        limits,
        supported_encryption,
        required_encryption,
    })
}

/// Serve RTSP until the process ends.
pub async fn serve(
    addr: SocketAddr,
    host: Arc<solstice_gamestream::nvhttp::Host>,
    ports: StreamPorts,
    limits: Limits,
    supported_encryption: u32,
    required_encryption: u32,
    negotiated: mpsc::Sender<Negotiated>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "rtsp listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let host = host.clone();
        let negotiated = negotiated.clone();
        tokio::spawn(async move {
            let Some(context) = context_for(
                &host,
                ports,
                limits,
                supported_encryption,
                required_encryption,
            ) else {
                tracing::warn!(%peer, "RTSP connection with no launch session; dropping");
                return;
            };
            if let Err(e) = serve_one(stream, peer, context, negotiated).await {
                tracing::debug!(%peer, error = %e, "rtsp connection ended");
            }
        });
    }
}

async fn serve_one(
    mut stream: TcpStream,
    peer: SocketAddr,
    context: RtspContext,
    negotiated: mpsc::Sender<Negotiated>,
) -> std::io::Result<()> {
    let crypto = context.key.map(|k| SessionCrypto::new(&k));
    let mut server = RtspServer::new(
        context.ports,
        context.limits,
        context.supported_encryption,
        context.required_encryption,
        context.session_id.clone(),
    );

    let mut buf = Vec::with_capacity(4096);
    let mut tx_sequence = 0u32;
    loop {
        // Try to take one message out of the buffer.
        let taken = if let (Some(crypto), true) = (&crypto, encrypted::is_encrypted(&buf)) {
            match encrypted::open(crypto, &buf) {
                Ok(Some((plaintext, used))) => Some((plaintext, used, true)),
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!(%peer, error = %e, "rejecting RTSP message");
                    return Ok(());
                }
            }
        } else if crypto.is_some() && !buf.is_empty() {
            tracing::warn!(%peer, "plaintext RTSP message on an encrypted session");
            return Ok(());
        } else {
            match message::parse_request(&buf) {
                Ok(Some((_, used))) => Some((buf[..used].to_vec(), used, false)),
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!(%peer, error = %e, "malformed RTSP message");
                    return Ok(());
                }
            }
        };

        let Some((plaintext, used, was_encrypted)) = taken else {
            let mut chunk = [0u8; 4096];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..read]);
            if buf.len() > message::MAX_MESSAGE_LEN {
                tracing::warn!(%peer, "RTSP message exceeded the cap");
                return Ok(());
            }
            continue;
        };
        buf.drain(..used);

        let Ok(Some((request, _))) = message::parse_request(&plaintext) else {
            tracing::warn!(%peer, "RTSP payload did not parse");
            return Ok(());
        };
        tracing::debug!(%peer, method = %request.method, uri = %request.uri, "rtsp");

        let outcome = server.handle(&request);
        let (response, close, play) = match outcome {
            RtspOutcome::Reply(r) => (r, false, None),
            RtspOutcome::Close(r) => (r, true, None),
            RtspOutcome::Play(r, config) => (r, false, Some(config)),
        };

        let bytes = response.to_bytes();
        let framed = if was_encrypted {
            let sealed = encrypted::seal(crypto.as_ref().expect("checked"), tx_sequence, &bytes)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            tx_sequence = tx_sequence.wrapping_add(1);
            sealed
        } else {
            bytes
        };
        stream.write_all(&framed).await?;
        stream.flush().await?;

        if let Some(config) = play {
            tracing::info!(
                %peer,
                width = config.width,
                height = config.height,
                fps = config.fps,
                "rtsp PLAY -- starting the stream"
            );
            let _ = negotiated
                .send(Negotiated {
                    config,
                    session_id: context.session_id.clone(),
                })
                .await;
        }
        if close {
            return Ok(());
        }
    }
}
