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
use std::sync::{mpsc as std_mpsc, Arc};
use std::time::{Duration, Instant};

use solstice_gamestream::stream::control::{ControlCodec, ControlMessage};
use solstice_gamestream::stream::enet::{Event, Host, HostConfig};
use solstice_gamestream::wire::control::msg;
use solstice_gamestream::wire::enet::MAXIMUM_MTU;
use tokio::sync::mpsc;

/// The longest the thread blocks on the socket, so it notices `running`
/// going false promptly.
const MAX_WAIT: Duration = Duration::from_millis(50);

/// How long a stopping thread waits for the client to acknowledge what the
/// host last sent before it disconnects anyway.
///
/// Moonlight drops the peer the moment it reads a `TERMINATION`, without
/// waiting for anything (`ControlStream.c`, the `IDX_TERMINATION` branch), so
/// the host's disconnect must not overtake it. A round trip on a LAN is a few
/// milliseconds; this only bounds a client that has already gone.
const LINGER: Duration = Duration::from_secs(1);

/// `NVST_DISCONN_SERVER_TERMINATED_CLOSED`: the host ended the session on
/// purpose. Moonlight reports it as a graceful termination once a frame has
/// arrived, and as an early one before.
pub const TERMINATED_CLOSED: u32 = 0x8003_0023;

/// What the stream task asks the control thread to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outgoing {
    /// `TERMINATION` with this HRESULT. Sent big-endian in the extended form,
    /// the only one an encrypted stream reads (`packetTypesGen7Enc`).
    Terminate(u32),
}

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
/// Blocking, so it belongs on its own thread. Whatever `outgoing` carries is
/// sent before `running` is next looked at, so a message queued just before
/// stopping still goes out, and the thread lingers (up to [`LINGER`]) until
/// the client has acknowledged it.
pub fn run(
    socket: UdpSocket,
    key: Option<[u8; 16]>,
    expected_connect_data: u32,
    events: mpsc::Sender<ControlEvent>,
    outgoing: std_mpsc::Receiver<Outgoing>,
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
    let mut stopping_since: Option<Instant> = None;
    let result = loop {
        while let Ok(message) = outgoing.try_recv() {
            send(&mut host, &mut codec, message);
        }
        transmit(&socket, &mut host);
        if !running.load(Ordering::Relaxed) {
            let since = *stopping_since.get_or_insert_with(Instant::now);
            if !host.is_connected() || host.unacknowledged() == 0 || since.elapsed() >= LINGER {
                break Ok(());
            }
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

fn send(host: &mut Host, codec: &mut ControlCodec, message: Outgoing) {
    let (msg_type, payload) = match message {
        Outgoing::Terminate(code) => (msg::TERMINATION, code.to_be_bytes()),
    };
    let sent = codec
        .encode(msg_type, &payload)
        .map_err(|e| e.to_string())
        .and_then(|packet| {
            host.send(Instant::now(), 0, &packet)
                .map_err(|e| e.to_string())
        });
    match sent {
        Ok(()) => tracing::info!(?message, "sent to the control peer"),
        Err(e) => tracing::warn!(?message, error = %e, "could not send to the control peer"),
    }
}

fn transmit(socket: &UdpSocket, host: &mut Host) {
    while let Some(t) = host.poll_transmit() {
        if let Err(e) = socket.send_to(&t.payload, t.destination) {
            tracing::debug!(error = %e, "control send failed");
        }
    }
}

/// Where the control channel listens.
pub fn bind(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    UdpSocket::bind(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solstice_gamestream::crypto::gcm::SessionCrypto;
    use solstice_gamestream::wire::control::{control_iv, EncryptedPacket, Origin, V2Header};

    const KEY: [u8; 16] = [7; 16];
    const CONNECT_DATA: u32 = 0x1234_5678;

    type Client = rusty_enet::Host<UdpSocket>;

    struct Running {
        address: SocketAddr,
        outgoing: std_mpsc::Sender<Outgoing>,
        running: Arc<AtomicBool>,
        thread: std::thread::JoinHandle<Result<(), String>>,
        events: mpsc::Receiver<ControlEvent>,
    }

    fn start() -> Running {
        let socket = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = socket.local_addr().unwrap();
        let (events_tx, events) = mpsc::channel(64);
        let (outgoing, outgoing_rx) = std_mpsc::channel();
        let running = Arc::new(AtomicBool::new(true));
        let thread = std::thread::spawn({
            let running = running.clone();
            move || {
                run(
                    socket,
                    Some(KEY),
                    CONNECT_DATA,
                    events_tx,
                    outgoing_rx,
                    running,
                )
            }
        });
        Running {
            address,
            outgoing,
            running,
            thread,
            events,
        }
    }

    /// Connected on both sides: the client's event fires on the verify, the
    /// host's only once the client has acknowledged it.
    fn connected_client(host: &mut Running) -> Client {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut client = rusty_enet::Host::new(
            socket,
            rusty_enet::HostSettings {
                peer_limit: 1,
                channel_limit: 0x30,
                ..Default::default()
            },
        )
        .unwrap();
        client.connect(host.address, 0x30, CONNECT_DATA).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(Instant::now() < deadline, "never connected");
            client.service().unwrap();
            if let Ok(ControlEvent::Connected) = host.events.try_recv() {
                return client;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// What the client would read out of a host-originated packet.
    fn open(packet: &[u8]) -> (u16, Vec<u8>) {
        let parsed = EncryptedPacket::parse(packet).unwrap();
        let plain = SessionCrypto::new(&KEY)
            .decrypt(
                &control_iv(parsed.header.sequence, Origin::Host),
                parsed.ciphertext,
                parsed.tag,
            )
            .unwrap();
        let (header, payload) = V2Header::parse(&plain).unwrap();
        (header.msg_type, payload.to_vec())
    }

    fn join_within(thread: std::thread::JoinHandle<Result<(), String>>, limit: Duration) {
        let started = Instant::now();
        while !thread.is_finished() {
            assert!(started.elapsed() < limit, "the control thread did not stop");
            std::thread::sleep(Duration::from_millis(5));
        }
        thread.join().unwrap().unwrap();
    }

    /// The stream task queues a `TERMINATION` and stops the thread in the same
    /// breath. It must still arrive, ahead of the disconnect, and the thread
    /// must stop as soon as the client has it -- Moonlight hangs up the moment
    /// it reads one, as this client does.
    #[test]
    fn a_termination_queued_as_the_thread_stops_still_reaches_the_client() {
        let mut host = start();
        let mut client = connected_client(&mut host);

        host.outgoing
            .send(Outgoing::Terminate(TERMINATED_CLOSED))
            .unwrap();
        host.running.store(false, Ordering::Relaxed);

        let deadline = Instant::now() + Duration::from_secs(5);
        let received = loop {
            assert!(Instant::now() < deadline, "no TERMINATION arrived");
            match client.service().unwrap().map(|e| e.no_ref()) {
                Some(rusty_enet::EventNoRef::Receive { packet, peer, .. }) => {
                    let message = open(packet.data());
                    client.peer_mut(peer).disconnect_now(0);
                    break message;
                }
                Some(rusty_enet::EventNoRef::Disconnect { .. }) => {
                    panic!("disconnected before the TERMINATION arrived")
                }
                _ => std::thread::sleep(Duration::from_millis(1)),
            }
        };
        assert_eq!(received.0, msg::TERMINATION);
        assert_eq!(received.1, 0x8003_0023u32.to_be_bytes());
        join_within(host.thread, LINGER / 2);
    }

    /// A client that has already gone cannot acknowledge anything, and must
    /// not hold the thread -- or the control port -- for long.
    #[test]
    fn the_linger_is_bounded_when_nobody_acknowledges() {
        let mut host = start();
        let client = connected_client(&mut host);
        drop(client);

        host.outgoing
            .send(Outgoing::Terminate(TERMINATED_CLOSED))
            .unwrap();
        host.running.store(false, Ordering::Relaxed);
        let started = Instant::now();
        join_within(host.thread, LINGER + Duration::from_millis(500));
        assert!(
            started.elapsed() >= LINGER - Duration::from_millis(100),
            "stopped after {:?}, without waiting for the acknowledgement",
            started.elapsed()
        );
    }

    /// With nothing sent, stopping is as prompt as it always was.
    #[test]
    fn stopping_with_nothing_unacknowledged_does_not_linger() {
        let mut host = start();
        let _client = connected_client(&mut host);
        host.running.store(false, Ordering::Relaxed);
        join_within(host.thread, Duration::from_millis(300));
    }
}
