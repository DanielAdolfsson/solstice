//! The RTSP listener.
//!
//! Plaintext and GCM-wrapped messages arrive on the same socket; the MSB of the
//! first word says which. Once a session is encrypted, a plaintext message is
//! refused rather than tolerated (`rtsp.cpp:166`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use solstice_gamestream::crypto::gcm::SessionCrypto;
use solstice_gamestream::rtsp::sdp::{Limits, StreamConfig};
use solstice_gamestream::rtsp::{
    encrypted, message, RtspOutcome, RtspServer, SessionParams, StreamPorts,
};
use solstice_gamestream::wire::control::Origin;
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
    /// The values the client is handed back during the negotiation.
    pub session: SessionParams,
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
        session: SessionParams {
            session_id: session.id.clone(),
            control_connect_data: session.control_connect_data,
            ping_payload: session.av_ping_payload,
        },
        key: session.encrypted_rtsp.then(|| *session.rikey),
        ports,
        limits,
        supported_encryption,
        required_encryption,
    })
}

/// How long a connection may go without completing a request before it is
/// dropped. One message arrives per connection, so a connection that has not
/// produced one is holding the negotiation open for nothing.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// The negotiation state, which outlives any one connection.
///
/// `moonlight-common-c` opens a **fresh TCP connection for every RTSP
/// message** and reads the reply until the host closes the socket
/// (`RtspConnection.c:386-517`: `connectTcpSocket` at the top,
/// `closeSocket` at the bottom, and `recv() == 0` as the only end-of-response
/// signal). So the stage machine cannot live in the connection handler --
/// SETUP would arrive at a server that had never seen a DESCRIBE -- and
/// neither can the encryption sequence number, which must never repeat under
/// one key.
struct SessionRtsp {
    /// Which launch session this state belongs to. A different one means a
    /// new launch, and the negotiation starts over.
    session_id: String,
    server: RtspServer,
    /// Host-originated message counter, continuing across connections.
    tx_sequence: u32,
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
    // One client, one message in flight, so the lock is also what keeps two
    // connections from interleaving halfway through a negotiation.
    let state: Arc<tokio::sync::Mutex<Option<SessionRtsp>>> = Arc::default();
    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let host = host.clone();
        let negotiated = negotiated.clone();
        let state = state.clone();
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
            let mut guard = state.lock().await;
            if guard.as_ref().map(|s| s.session_id.as_str())
                != Some(context.session.session_id.as_str())
            {
                *guard = Some(SessionRtsp {
                    session_id: context.session.session_id.clone(),
                    server: RtspServer::new(
                        context.ports,
                        context.limits,
                        context.supported_encryption,
                        context.required_encryption,
                        context.session.clone(),
                    ),
                    tx_sequence: 0,
                });
            }
            let ended = {
                let state = guard.as_mut().expect("just populated");
                match tokio::time::timeout(
                    REQUEST_TIMEOUT,
                    serve_one(stream, peer, &context, state, negotiated),
                )
                .await
                {
                    Ok(Ok(ended)) => ended,
                    Ok(Err(e)) => {
                        tracing::debug!(%peer, error = %e, "rtsp connection ended");
                        false
                    }
                    Err(_) => {
                        // A connection that never produced a request says
                        // nothing about the negotiation, so leave it standing.
                        tracing::warn!(%peer, "rtsp connection produced no request in time");
                        false
                    }
                }
            };
            if ended {
                *guard = None;
            }
        });
    }
}

/// Handle exactly one request on one connection, then close it.
///
/// Closing is not tidiness: it is the end-of-message framing the client reads
/// by. See [`SessionRtsp`].
///
/// Returns whether the negotiation itself is over -- a refusal, a TEARDOWN or
/// anything malformed -- in which case the caller discards the session state
/// rather than letting the next connection continue from it.
async fn serve_one(
    mut stream: TcpStream,
    peer: SocketAddr,
    context: &RtspContext,
    state: &mut SessionRtsp,
    negotiated: mpsc::Sender<Negotiated>,
) -> std::io::Result<bool> {
    let crypto = context.key.map(|k| SessionCrypto::new(&k));
    let server = &mut state.server;

    let mut buf = Vec::with_capacity(4096);
    loop {
        // Try to take one message out of the buffer.
        let taken = if let (Some(crypto), true) = (&crypto, encrypted::is_encrypted(&buf)) {
            match encrypted::open(crypto, Origin::Client, &buf) {
                Ok(Some((plaintext, used))) => Some((plaintext, used, true)),
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!(%peer, error = %e, "rejecting RTSP message");
                    return Ok(true);
                }
            }
        } else if crypto.is_some() && !buf.is_empty() {
            tracing::warn!(%peer, "plaintext RTSP message on an encrypted session");
            return Ok(true);
        } else {
            match message::parse_request(&buf) {
                Ok(Some((_, used))) => Some((buf[..used].to_vec(), used, false)),
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!(%peer, error = %e, "malformed RTSP message");
                    return Ok(true);
                }
            }
        };

        let Some((plaintext, used, was_encrypted)) = taken else {
            let mut chunk = [0u8; 4096];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                // The client hung up before finishing a message. That is its
                // business; the negotiation so far still stands.
                return Ok(false);
            }
            buf.extend_from_slice(&chunk[..read]);
            if buf.len() > message::MAX_MESSAGE_LEN {
                tracing::warn!(%peer, "RTSP message exceeded the cap");
                return Ok(true);
            }
            continue;
        };
        buf.drain(..used);

        let Ok(Some((request, _))) = message::parse_request(&plaintext) else {
            tracing::warn!(%peer, "RTSP payload did not parse");
            return Ok(true);
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
            let sealed = encrypted::seal(
                crypto.as_ref().expect("checked"),
                state.tx_sequence,
                Origin::Host,
                &bytes,
            )
            .map_err(|e| std::io::Error::other(e.to_string()))?;
            state.tx_sequence = state.tx_sequence.wrapping_add(1);
            sealed
        } else {
            bytes
        };
        stream.write_all(&framed).await?;
        stream.flush().await?;
        // The FIN is the message terminator: the client reads until the host
        // closes. `close` only decides whether the *negotiation* survives.
        let _ = stream.shutdown().await;

        if let Some(config) = play {
            tracing::info!(
                %peer,
                width = config.width,
                height = config.height,
                fps = config.fps,
                bitrate_kbps = config.bitrate_kbps,
                audio_channels = config.audio_channels,
                audio_packet_ms = config.audio_packet_duration,
                "rtsp PLAY -- starting the stream"
            );
            let _ = negotiated
                .send(Negotiated {
                    config,
                    session_id: context.session.session_id.clone(),
                })
                .await;
        }
        return Ok(close);
    }
}
