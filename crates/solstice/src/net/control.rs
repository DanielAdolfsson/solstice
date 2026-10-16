//! The ENet control channel.
//!
//! ENet is the significant pre-authentication surface: it keeps per-peer
//! state, sequences and acknowledges, and runs retransmission timers, all
//! before the host knows who the peer is. GHSA-c428-87f8-rrv5 is exactly that
//! -- an unauthenticated denial of service via a short control packet
//! (`docs/security.md` §2.4).
//!
//! The protocol is `solstice_gamestream::stream::enet`, a sans-I/O host that
//! implements only the subset Moonlight uses and refuses the rest -- one peer,
//! bound to its address, admitted only with the launch's connect data, and no
//! fragment reassembly at all. This module is the socket and the thread around
//! it. Behind it, the message layer authenticates every packet with AES-GCM
//! before a single byte reaches the input parser.

use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use solstice_gamestream::stream::control::{ControlCodec, ControlMessage};
use solstice_gamestream::stream::enet::{Event, Host, HostConfig};
use solstice_gamestream::wire::control::msg;
use solstice_gamestream::wire::enet::MAXIMUM_MTU;
use tokio::sync::mpsc;

/// The longest the thread blocks on the socket, so it notices `running`
/// going false promptly.
const MAX_WAIT: Duration = Duration::from_millis(50);

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
/// Blocking, so it belongs on its own thread.
pub fn run(
    socket: UdpSocket,
    key: Option<[u8; 16]>,
    expected_connect_data: u32,
    events: mpsc::Sender<ControlEvent>,
    running: Arc<AtomicBool>,
) -> Result<(), String> {
    let mut host = Host::new(HostConfig::new(expected_connect_data), Instant::now());
    let mut codec = ControlCodec::new(key.as_ref());
    tracing::info!(
        encrypted = codec.is_encrypted(),
        "control channel listening"
    );

    // One byte more than any conforming datagram, so an oversized one arrives
    // whole enough to be refused as oversized rather than silently truncated.
    let mut buf = vec![0u8; MAXIMUM_MTU as usize + 1];
    let mut reported = host.stats();
    let result = loop {
        if !running.load(Ordering::Relaxed) {
            break Ok(());
        }
        let now = Instant::now();
        let wait = host
            .poll_timeout()
            .map_or(MAX_WAIT, |t| t.saturating_duration_since(now))
            .clamp(Duration::from_millis(1), MAX_WAIT);
        if let Err(e) = socket.set_read_timeout(Some(wait)) {
            break Err(e.to_string());
        }
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => host.handle_datagram(Instant::now(), from, &buf[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            // An ICMP error for an earlier send, on platforms that report one
            // here. Not this socket's failure.
            Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
            Err(e) => break Err(e.to_string()),
        }
        let now = Instant::now();
        if host.poll_timeout().is_some_and(|t| t <= now) {
            host.handle_timeout(now);
        }
        transmit(&socket, &mut host);

        while let Some(event) = host.poll_event() {
            let event = match event {
                Event::Connected { address } => {
                    tracing::info!(%address, "control peer connected");
                    ControlEvent::Connected
                }
                Event::Disconnected { reason } => {
                    tracing::info!(?reason, "control peer disconnected");
                    ControlEvent::Disconnected
                }
                Event::Receive { data, .. } => match codec.decode(&data) {
                    Ok(message) => ControlEvent::Message(message),
                    Err(e) => {
                        // A packet that fails authentication is dropped,
                        // never parsed further.
                        tracing::warn!(error = %e, "dropping a control packet");
                        continue;
                    }
                },
            };
            let _ = events.blocking_send(event);
        }

        // Every refusal is silent on the wire; this is where they show.
        let stats = host.stats();
        if stats != reported {
            if stats.wrong_connect_data > reported.wrong_connect_data || stats.busy > reported.busy
            {
                tracing::warn!(?stats, "refused an ENet connection attempt");
            } else {
                tracing::debug!(?stats, "ENet refusals");
            }
            reported = stats;
        }
    };

    // Tell a client still connected that the session is over, rather than
    // leaving it to time out.
    host.disconnect(0);
    transmit(&socket, &mut host);
    result
}

fn transmit(socket: &UdpSocket, host: &mut Host) {
    while let Some(t) = host.poll_transmit() {
        if let Err(e) = socket.send_to(&t.payload, t.destination) {
            tracing::debug!(error = %e, "control send failed");
        }
    }
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
