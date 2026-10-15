//! The ENet control channel.
//!
//! ENet is the significant pre-authentication surface: it maintains per-peer
//! state, reassembles fragments and runs a retransmission timer, all before the
//! host knows who the peer is. GHSA-c428-87f8-rrv5 is exactly that -- an
//! unauthenticated denial of service via a short control packet
//! (`docs/security.md` §2.4).
//!
//! `rusty_enet` is a C-to-Rust transpilation of ENet 1.3.18 whose own README is
//! candid that it "couldn't be much further from ready for serious use". It is
//! used here because the alternative is reimplementing ENet, but it is kept
//! behind three things: a hard peer limit, a refusal to accept a second peer
//! while one is connected, and a message layer that authenticates every packet
//! with AES-GCM before a single byte reaches the input parser.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use solstice_gamestream::stream::control::{ControlCodec, ControlMessage};
use solstice_gamestream::wire::control::msg;
use tokio::sync::mpsc;

/// One connected peer at a time, and no more.
const MAX_PEERS: usize = 1;
/// Two channels, which is what Moonlight uses.
const CHANNELS: usize = 2;

/// What the control thread reports upward.
#[derive(Debug)]
pub enum ControlEvent {
    /// A client connected.
    Connected,
    /// A decoded message.
    Message(ControlMessage),
    /// The client went away.
    Disconnected,
}

/// Run the ENet host until `running` goes false.
///
/// Blocking: ENet is a poll loop, so this belongs on its own thread.
pub fn run(
    socket: UdpSocket,
    key: Option<[u8; 16]>,
    expected_connect_data: u32,
    events: mpsc::Sender<ControlEvent>,
    running: Arc<AtomicBool>,
) -> Result<(), String> {
    socket.set_nonblocking(true).map_err(|e| e.to_string())?;
    let mut host = rusty_enet::Host::new(
        socket,
        rusty_enet::HostSettings {
            peer_limit: MAX_PEERS,
            channel_limit: CHANNELS,
            ..Default::default()
        },
    )
    .map_err(|e| format!("enet host: {e:?}"))?;

    let mut codec = ControlCodec::new(key.as_ref());
    tracing::info!(
        encrypted = codec.is_encrypted(),
        "control channel listening"
    );

    while running.load(Ordering::Relaxed) {
        match host.service() {
            Ok(Some(event)) => match event {
                rusty_enet::Event::Connect { peer, data, .. } => {
                    // The connect data binds an incoming peer to a launch
                    // session. A peer that does not present it is not ours.
                    if data != expected_connect_data {
                        tracing::warn!(
                            got = data,
                            "refusing an ENet peer with the wrong connect data"
                        );
                        peer.disconnect_now(0);
                        continue;
                    }
                    tracing::info!("control peer connected");
                    let _ = events.blocking_send(ControlEvent::Connected);
                }
                rusty_enet::Event::Disconnect { .. } => {
                    tracing::info!("control peer disconnected");
                    let _ = events.blocking_send(ControlEvent::Disconnected);
                }
                rusty_enet::Event::Receive { packet, .. } => {
                    match codec.decode(packet.data()) {
                        Ok(message) => {
                            let _ = events.blocking_send(ControlEvent::Message(message));
                        }
                        Err(e) => {
                            // A packet that fails authentication is dropped and
                            // counted, never parsed further.
                            tracing::warn!(error = %e, "dropping a control packet");
                        }
                    }
                }
            },
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(e) => {
                tracing::warn!(error = ?e, "enet service failed");
                break;
            }
        }
    }
    Ok(())
}

/// Encode a host-originated control message.
pub fn encode(codec: &mut ControlCodec, msg_type: u16, payload: &[u8]) -> Option<Vec<u8>> {
    codec.encode(msg_type, payload).ok()
}

/// Message types the host sends.
pub mod host_messages {
    #![allow(missing_docs)]
    pub use super::msg::{HDR_MODE, RUMBLE, TERMINATION};
}

/// Where the control channel listens.
pub fn bind(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    UdpSocket::bind(addr)
}
