//! The host end of ENet, reduced to what a Moonlight control stream uses.
//!
//! ENet is the one stateful protocol Solstice speaks before it knows who the
//! peer is (`docs/security.md` §2.4), and GHSA-c428-87f8-rrv5 is an
//! unauthenticated denial of service in exactly this position. This used to be
//! `rusty_enet`, a C-to-Rust transpilation of all of ENet whose own README says
//! it "couldn't be much further from ready for serious use". This is the
//! subset instead, read off `moonlight-common-c`'s `ControlStream.c` and its
//! ENet fork, and off a captured real session (`docs/roadmap.md` §7):
//!
//! - **One peer.** A `CONNECT` is the only command read from an unknown
//!   address, and it is answered only if its connect data is the launch's.
//!   Anything else -- a wrong connect data, a second client, a `CONNECT` while
//!   one is in progress -- gets no reply at all and leaves no state. The one
//!   reply, `VERIFY_CONNECT`, is smaller than the `CONNECT` that earns it, so
//!   the port is not an amplifier.
//! - **Bound to its address.** Upstream ENet re-learns a peer's address from
//!   every datagram that carries its ID and session (the check is commented
//!   out in `protocol.c`). Here a datagram from anywhere else is dropped.
//! - **No fragments.** Moonlight builds every control message in a 256-byte
//!   buffer (`sendMessageEnet`), far below the 900-byte MTU its fork defaults
//!   to, so it never fragments. Reassembly is the largest piece of ENet's
//!   pre-authentication state and is simply not here: a fragment ends the
//!   datagram it arrived in and is never acknowledged.
//! - **No compression, no checksum, no throttle, no bandwidth limits.**
//!   Moonlight configures none of the first two, and the last two shape what a
//!   sender sends; the host sends almost nothing.
//! - **Bounded.** The reorder buffer, the commands read per datagram and the
//!   unacknowledged reliable sends are all capped, so no sequence of
//!   datagrams makes the host hold more than a few tens of kilobytes.
//!
//! What remains is ENet's reliability core, kept wire-compatible: reliable
//! in-order delivery per channel, unreliable and unsequenced delivery,
//! acknowledgements, retransmission of the host's own reliable commands, and
//! liveness. The module is sans-I/O -- datagrams and instants in, datagrams and
//! events out -- so the tests and the fuzzer drive it without a socket.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::wire::enet::{
    command, commands, Body, Command, CommandHeader, Connect, Header, CONTROL_CHANNEL,
    FLAG_ACKNOWLEDGE, FLAG_UNSEQUENCED, MAXIMUM_CHANNEL_COUNT, MAXIMUM_MTU,
    MAXIMUM_PACKET_COMMANDS, MAXIMUM_WINDOW_SIZE, MINIMUM_MTU, MINIMUM_WINDOW_SIZE,
    UNASSIGNED_PEER_ID,
};

/// The only peer ID this host hands out.
const PEER_ID: u16 = 0;
/// How far ahead of the next expected reliable command one may arrive and be
/// held rather than dropped. ENet's own reach is seven windows of 4096; a
/// sender limited to [`HostConfig::window_size`] bytes in flight cannot get
/// anywhere near either.
const REORDER_REACH: u16 = 1024;
/// Held out-of-order reliable commands, per peer.
const MAX_EARLY_COMMANDS: usize = 256;
/// `ENET_PEER_DEFAULT_ROUND_TRIP_TIME`, before any acknowledgement says
/// otherwise.
const INITIAL_RTT_MS: u32 = 500;
/// The retransmission timeout grows linearly with attempts up to this
/// multiple (`ENetPeer::timeoutLimit`; Moonlight sets 2 on its side).
const BACKOFF_LIMIT: u32 = 4;
/// `ENET_PEER_UNSEQUENCED_WINDOW_SIZE`.
const UNSEQUENCED_WINDOW: u32 = 1024;
/// `ENET_PEER_FREE_UNSEQUENCED_WINDOWS`.
const FREE_UNSEQUENCED_WINDOWS: u32 = 32;
/// Room for the header with its sent time.
const HEADER_LEN: usize = 4;

/// How the host behaves.
#[derive(Clone, Debug)]
pub struct HostConfig {
    /// The connect data the launch handed out. A `CONNECT` carrying anything
    /// else is not this session's client.
    pub connect_data: u32,
    /// Channels granted, at most. Moonlight asks for `CTRL_CHANNEL_COUNT`
    /// (0x30) and folds anything above what it is granted onto channel 0.
    pub channel_limit: u8,
    /// The largest datagram the host sends; the client's own proposal can only
    /// lower it.
    pub mtu: u32,
    /// The reliable window offered, in bytes: how much a sender may have in
    /// flight unacknowledged. Kept no larger than `max_buffered_bytes`, so a
    /// conforming sender never overruns the reorder buffer.
    pub window_size: u32,
    /// Bytes of out-of-order reliable data held, at most.
    pub max_buffered_bytes: usize,
    /// How long a peer may go silent, or leave a reliable command of the
    /// host's unacknowledged, before it is considered gone. Moonlight uses ten
    /// seconds for its own side (`enet_peer_timeout(peer, 2, 10000, 10000)`).
    pub peer_timeout: Duration,
    /// Reliable commands of the host's own that may await acknowledgement.
    pub max_in_flight: usize,
}

impl HostConfig {
    /// The defaults, for a launch that handed out `connect_data`.
    pub fn new(connect_data: u32) -> Self {
        Self {
            connect_data,
            channel_limit: 2,
            mtu: 1392,
            window_size: MAXIMUM_WINDOW_SIZE,
            max_buffered_bytes: 64 * 1024,
            peer_timeout: Duration::from_secs(10),
            max_in_flight: 64,
        }
    }
}

/// Something the application should know about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The handshake completed: the client acknowledged `VERIFY_CONNECT`.
    Connected {
        /// Where it is.
        address: SocketAddr,
    },
    /// A packet, delivered with ENet's guarantees for the way it was sent.
    Receive {
        /// The channel it arrived on.
        channel: u8,
        /// Its bytes.
        data: Vec<u8>,
    },
    /// The connection is over.
    Disconnected {
        /// Why.
        reason: DisconnectReason,
    },
}

/// Why a connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectReason {
    /// The client sent `DISCONNECT`, with this data.
    Remote(u32),
    /// The client went silent, or stopped acknowledging.
    TimedOut,
}

/// A datagram to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit {
    /// Where.
    pub destination: SocketAddr,
    /// What.
    pub payload: Vec<u8>,
}

/// Why [`Host::send`] refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// Nobody is connected.
    #[error("no connected peer")]
    NotConnected,
    /// The channel was not granted.
    #[error("channel {0} was not granted")]
    NoSuchChannel(u8),
    /// The packet does not fit one datagram, and this host does not fragment.
    #[error("packet of {0} bytes exceeds the MTU")]
    TooLarge(usize),
    /// Too many reliable commands already await acknowledgement.
    #[error("too many unacknowledged packets")]
    Busy,
}

/// What the host has refused, by reason. Every refusal is silent on the wire,
/// so this is the only place one shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Datagrams or commands that did not parse, and datagrams over the MTU.
    pub malformed: u64,
    /// Compressed datagrams. Moonlight never compresses.
    pub compressed: u64,
    /// `CONNECT`s carrying the wrong connect data.
    pub wrong_connect_data: u64,
    /// `CONNECT`s while another peer holds the slot.
    pub busy: u64,
    /// Datagrams for a peer that does not exist, from the wrong address or
    /// with the wrong session.
    pub foreign: u64,
    /// Well-formed commands that are not valid in the peer's state.
    pub unexpected: u64,
    /// Fragments, which this host never reassembles.
    pub fragments: u64,
    /// Reliable commands dropped unacknowledged because they arrived too far
    /// ahead or the reorder buffer was full. The sender will retransmit them.
    pub overflow: u64,
}

/// The ENet host.
pub struct Host {
    config: HostConfig,
    epoch: Instant,
    peer: Option<Peer>,
    events: VecDeque<Event>,
    transmits: VecDeque<Transmit>,
    stats: Stats,
}

impl std::fmt::Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Host")
            .field(
                "peer",
                &self.peer.as_ref().map(|p| (p.address, p.connected)),
            )
            .field("stats", &self.stats)
            .finish()
    }
}

struct Peer {
    address: SocketAddr,
    connected: bool,
    connect_id: u32,
    /// The client's own index for this peer; goes in every header we send.
    remote_peer_id: u16,
    incoming_session: u8,
    outgoing_session: u8,
    mtu: usize,
    channels: Vec<Channel>,
    /// Outgoing reliable sequence on [`CONTROL_CHANNEL`].
    control_sequence: u16,
    unsequenced_base: u16,
    unsequenced_seen: [u32; (UNSEQUENCED_WINDOW / 32) as usize],
    in_flight: VecDeque<InFlight>,
    /// Acknowledgements owed: the command acknowledged and the sent time of the
    /// datagram that carried it.
    acks: Vec<(CommandHeader, u16)>,
    buffered_bytes: usize,
    early_commands: usize,
    last_receive: Instant,
    rtt: Option<(u32, u32)>,
}

#[derive(Default)]
struct Channel {
    incoming_reliable: u16,
    incoming_unreliable: u16,
    outgoing_reliable: u16,
    /// Reliable commands that arrived ahead of the next expected one, by
    /// sequence number.
    early: BTreeMap<u16, Vec<u8>>,
}

struct InFlight {
    channel: u8,
    sequence: u16,
    /// The serialised command.
    bytes: Vec<u8>,
    /// When it first went out; `None` until it has.
    first_sent: Option<Instant>,
    sent_at: Instant,
    attempts: u32,
    timeout: Duration,
}

/// What handling a command did to the walk over its datagram.
enum Flow {
    Continue,
    /// Stop reading this datagram; what was handled stands.
    Stop,
    /// The peer is gone.
    Gone(DisconnectReason),
}

impl Host {
    /// A host whose clock starts at `now`.
    pub fn new(config: HostConfig, now: Instant) -> Self {
        Self {
            config,
            epoch: now,
            peer: None,
            events: VecDeque::new(),
            transmits: VecDeque::new(),
            stats: Stats::default(),
        }
    }

    /// What has been refused so far.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Whether a client has completed the handshake and not gone away.
    pub fn is_connected(&self) -> bool {
        self.peer.as_ref().is_some_and(|p| p.connected)
    }

    /// The host's own reliable sends still awaiting acknowledgement. Zero
    /// means everything sent has arrived, so a caller about to disconnect
    /// knows a last message was not lost to the disconnect overtaking it.
    pub fn unacknowledged(&self) -> usize {
        self.peer.as_ref().map_or(0, |p| p.in_flight.len())
    }

    /// The next event, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// The next datagram to send, if any.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    /// When [`Host::handle_timeout`] next has something to do.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let peer = self.peer.as_ref()?;
        let mut at = peer.last_receive + self.config.peer_timeout;
        for f in &peer.in_flight {
            at = at.min(f.sent_at + f.timeout);
        }
        Some(at)
    }

    /// Advance the clock: retransmit what is due, and give up on a peer that
    /// has gone quiet.
    pub fn handle_timeout(&mut self, now: Instant) {
        let Some(peer) = &self.peer else { return };
        let silent = now.saturating_duration_since(peer.last_receive) >= self.config.peer_timeout;
        let unacknowledged = peer.in_flight.iter().any(|f| {
            f.first_sent
                .is_some_and(|t| now.saturating_duration_since(t) >= self.config.peer_timeout)
        });
        if silent || unacknowledged {
            self.drop_peer(DisconnectReason::TimedOut);
            return;
        }
        self.flush(now);
    }

    /// Handle one datagram from `from`.
    pub fn handle_datagram(&mut self, now: Instant, from: SocketAddr, datagram: &[u8]) {
        if datagram.len() > MAXIMUM_MTU as usize {
            self.stats.malformed += 1;
            return;
        }
        let Ok((header, body)) = Header::parse(datagram) else {
            self.stats.malformed += 1;
            return;
        };
        if header.compressed {
            self.stats.compressed += 1;
            return;
        }
        if header.peer_id == UNASSIGNED_PEER_ID {
            self.handle_connect(now, from, body);
            return;
        }

        let Some(peer) = &mut self.peer else {
            self.stats.foreign += 1;
            return;
        };
        if from != peer.address
            || header.peer_id != PEER_ID
            || header.session != peer.incoming_session
        {
            self.stats.foreign += 1;
            return;
        }
        peer.last_receive = now;

        let now_ms = clock_ms(self.epoch, now);
        let mut gone = None;
        for (i, parsed) in commands(body).enumerate() {
            if i == MAXIMUM_PACKET_COMMANDS {
                self.stats.malformed += 1;
                break;
            }
            let Ok(cmd) = parsed else {
                self.stats.malformed += 1;
                break;
            };
            match peer.handle(
                now_ms,
                &self.config,
                header.sent_time,
                cmd,
                &mut self.events,
                &mut self.stats,
            ) {
                Flow::Continue => {}
                Flow::Stop => break,
                Flow::Gone(reason) => {
                    gone = Some(reason);
                    break;
                }
            }
        }
        // Owed acknowledgements go out even when the peer is leaving: its
        // `DISCONNECT` is one of them.
        self.flush(now);
        if let Some(reason) = gone {
            self.drop_peer(reason);
        }
    }

    /// Queue `data` for reliable, in-order delivery on `channel`.
    pub fn send(&mut self, now: Instant, channel: u8, data: &[u8]) -> Result<(), SendError> {
        let peer = match &mut self.peer {
            Some(p) if p.connected => p,
            _ => return Err(SendError::NotConnected),
        };
        let max_in_flight = self.config.max_in_flight;
        let Some(ch) = peer.channels.get_mut(channel as usize) else {
            return Err(SendError::NoSuchChannel(channel));
        };
        let cmd_len = 6 + data.len();
        if HEADER_LEN + cmd_len > peer.mtu {
            return Err(SendError::TooLarge(data.len()));
        }
        if peer.in_flight.len() >= max_in_flight {
            return Err(SendError::Busy);
        }
        ch.outgoing_reliable = ch.outgoing_reliable.wrapping_add(1);
        let sequence = ch.outgoing_reliable;
        peer.queue_reliable(
            now,
            Command {
                header: CommandHeader {
                    command: command::SEND_RELIABLE | FLAG_ACKNOWLEDGE,
                    channel,
                    reliable_sequence: sequence,
                },
                body: Body::SendReliable { data },
            },
        );
        self.flush(now);
        Ok(())
    }

    /// End the connection now, as `enet_peer_disconnect_now` does: one
    /// unacknowledged `DISCONNECT`, and the peer is forgotten. No event.
    pub fn disconnect(&mut self, data: u32) {
        let Some(mut peer) = self.peer.take() else {
            return;
        };
        peer.control_sequence = peer.control_sequence.wrapping_add(1);
        let mut payload = Vec::with_capacity(2 + 8);
        peer.header(None).write(&mut payload);
        Command {
            header: CommandHeader {
                command: command::DISCONNECT | FLAG_UNSEQUENCED,
                channel: CONTROL_CHANNEL,
                reliable_sequence: peer.control_sequence,
            },
            body: Body::Disconnect { data },
        }
        .write(&mut payload);
        self.transmits.push_back(Transmit {
            destination: peer.address,
            payload,
        });
    }

    fn handle_connect(&mut self, now: Instant, from: SocketAddr, body: &[u8]) {
        // An unassigned peer ID may carry exactly one thing, a `CONNECT`; ENet
        // stops at anything else, and so does this. Nothing after the
        // `CONNECT` is read either: the peer it creates cannot accept data
        // until the handshake completes.
        let connect = match commands(body).next() {
            Some(Ok(Command {
                body: Body::Connect(c),
                ..
            })) => c,
            Some(Ok(_)) | None => {
                self.stats.foreign += 1;
                return;
            }
            Some(Err(_)) => {
                self.stats.malformed += 1;
                return;
            }
        };
        if !(1..=MAXIMUM_CHANNEL_COUNT).contains(&connect.channel_count) {
            self.stats.malformed += 1;
            return;
        }
        if connect.data != self.config.connect_data {
            self.stats.wrong_connect_data += 1;
            return;
        }
        if let Some(peer) = &self.peer {
            // The client retransmits its `CONNECT` until it sees our verify,
            // which this host retransmits on its own schedule.
            if !(peer.address == from && peer.connect_id == connect.connect_id) {
                self.stats.busy += 1;
            }
            return;
        }

        let mut peer = Peer::accept(now, from, &connect, &self.config);
        let verify = Connect {
            outgoing_peer_id: PEER_ID,
            // Ours, crossed over: what we send with is what it receives with.
            incoming_session: peer.outgoing_session,
            outgoing_session: peer.incoming_session,
            mtu: peer.mtu as u32,
            window_size: connect
                .window_size
                .min(self.config.window_size)
                .clamp(MINIMUM_WINDOW_SIZE, MAXIMUM_WINDOW_SIZE),
            channel_count: peer.channels.len() as u32,
            incoming_bandwidth: 0,
            outgoing_bandwidth: 0,
            // A client refuses a verify that does not echo these three.
            packet_throttle_interval: connect.packet_throttle_interval,
            packet_throttle_acceleration: connect.packet_throttle_acceleration,
            packet_throttle_deceleration: connect.packet_throttle_deceleration,
            connect_id: connect.connect_id,
            data: 0,
        };
        peer.control_sequence = 1;
        peer.queue_reliable(
            now,
            Command {
                header: CommandHeader {
                    command: command::VERIFY_CONNECT | FLAG_ACKNOWLEDGE,
                    channel: CONTROL_CHANNEL,
                    reliable_sequence: 1,
                },
                body: Body::VerifyConnect(verify),
            },
        );
        self.peer = Some(peer);
        self.flush(now);
    }

    fn drop_peer(&mut self, reason: DisconnectReason) {
        if let Some(peer) = self.peer.take() {
            if peer.connected {
                self.events.push_back(Event::Disconnected { reason });
            }
        }
    }

    /// Send what is owed: acknowledgements, then reliable commands that have
    /// not gone out or are due again, packed into as few datagrams as the MTU
    /// and the per-datagram command limit allow.
    fn flush(&mut self, now: Instant) {
        let Some(peer) = &mut self.peer else { return };
        let sent_time = clock_ms(self.epoch, now);

        let mut acks = std::mem::take(&mut peer.acks).into_iter().peekable();
        let mut due: VecDeque<usize> = peer
            .in_flight
            .iter()
            .enumerate()
            .filter(|(_, f)| f.first_sent.is_none() || now >= f.sent_at + f.timeout)
            .map(|(i, _)| i)
            .collect();

        while acks.peek().is_some() || !due.is_empty() {
            let mut body = Vec::new();
            let mut count = 0;
            let mut reliable = false;
            while count < MAXIMUM_PACKET_COMMANDS && HEADER_LEN + body.len() + 8 <= peer.mtu {
                let Some((acked, time)) = acks.next() else {
                    break;
                };
                Command {
                    header: CommandHeader {
                        command: command::ACKNOWLEDGE,
                        channel: acked.channel,
                        reliable_sequence: acked.reliable_sequence,
                    },
                    body: Body::Acknowledge {
                        received_reliable_sequence: acked.reliable_sequence,
                        received_sent_time: time,
                    },
                }
                .write(&mut body);
                count += 1;
            }
            while count < MAXIMUM_PACKET_COMMANDS {
                let Some(&i) = due.front() else { break };
                let base = peer.retransmit_timeout(self.config.peer_timeout);
                let f = &mut peer.in_flight[i];
                if HEADER_LEN + body.len() + f.bytes.len() > peer.mtu {
                    break;
                }
                due.pop_front();
                body.extend_from_slice(&f.bytes);
                if f.first_sent.is_none() {
                    f.first_sent = Some(now);
                }
                f.attempts += 1;
                f.timeout = base * f.attempts.min(BACKOFF_LIMIT);
                f.sent_at = now;
                count += 1;
                reliable = true;
            }
            if count == 0 {
                // Unreachable while every queued command fits the MTU, which
                // `send` guarantees; refuse to spin if that ever changes.
                break;
            }
            let mut payload = Vec::with_capacity(HEADER_LEN + body.len());
            peer.header(reliable.then_some(sent_time))
                .write(&mut payload);
            payload.extend_from_slice(&body);
            self.transmits.push_back(Transmit {
                destination: peer.address,
                payload,
            });
        }
    }
}

/// ENet's clock as the wire carries it: milliseconds, low 16 bits.
fn clock_ms(epoch: Instant, now: Instant) -> u16 {
    (now.saturating_duration_since(epoch).as_millis() & 0xFFFF) as u16
}

impl Peer {
    fn accept(now: Instant, address: SocketAddr, connect: &Connect, config: &HostConfig) -> Self {
        // Session IDs as `enet_protocol_handle_connect` picks them for a fresh
        // peer slot, whose own are both 0xFF: the client's proposal plus one,
        // in two bits.
        let next = |proposed: u8| proposed.wrapping_add(1) & 3;
        let channels = connect
            .channel_count
            .min(config.channel_limit.max(1) as u32) as usize;
        Self {
            address,
            connected: false,
            connect_id: connect.connect_id,
            remote_peer_id: connect.outgoing_peer_id,
            outgoing_session: next(connect.incoming_session),
            incoming_session: next(connect.outgoing_session),
            mtu: connect
                .mtu
                .clamp(MINIMUM_MTU, MAXIMUM_MTU)
                .min(config.mtu.max(MINIMUM_MTU)) as usize,
            channels: (0..channels).map(|_| Channel::default()).collect(),
            control_sequence: 0,
            unsequenced_base: 0,
            unsequenced_seen: [0; (UNSEQUENCED_WINDOW / 32) as usize],
            in_flight: VecDeque::new(),
            acks: Vec::new(),
            buffered_bytes: 0,
            early_commands: 0,
            last_receive: now,
            rtt: None,
        }
    }

    fn header(&self, sent_time: Option<u16>) -> Header {
        Header {
            peer_id: self.remote_peer_id,
            // ENet only stamps a session on a peer that has a real ID.
            session: if self.remote_peer_id < UNASSIGNED_PEER_ID {
                self.outgoing_session
            } else {
                0
            },
            compressed: false,
            sent_time,
        }
    }

    fn queue_reliable(&mut self, now: Instant, cmd: Command<'_>) {
        let mut bytes = Vec::with_capacity(cmd.wire_len());
        cmd.write(&mut bytes);
        self.in_flight.push_back(InFlight {
            channel: cmd.header.channel,
            sequence: cmd.header.reliable_sequence,
            bytes,
            first_sent: None,
            sent_at: now,
            attempts: 0,
            timeout: Duration::ZERO,
        });
    }

    /// ENet's: the smoothed round trip plus up to four deviations, capped at a
    /// fifth of the peer timeout.
    fn retransmit_timeout(&self, peer_timeout: Duration) -> Duration {
        let (rtt, var) = self.rtt.unwrap_or((INITIAL_RTT_MS, 0));
        let ms = rtt + rtt.min(4 * var.max(1));
        Duration::from_millis(ms as u64).min(peer_timeout / 5)
    }

    fn handle(
        &mut self,
        now_ms: u16,
        config: &HostConfig,
        sent_time: Option<u16>,
        cmd: Command<'_>,
        events: &mut VecDeque<Event>,
        stats: &mut Stats,
    ) -> Flow {
        let channel = cmd.header.channel;
        // Whether to acknowledge, if the command asked.
        let mut ack = true;
        match cmd.body {
            Body::Acknowledge {
                received_reliable_sequence,
                received_sent_time,
            } => {
                let verified = self.acknowledged(
                    now_ms,
                    channel,
                    received_reliable_sequence,
                    received_sent_time,
                    events,
                );
                if !self.connected && !verified {
                    stats.unexpected += 1;
                    return Flow::Stop;
                }
            }
            Body::Disconnect { data } => {
                if cmd.header.wants_ack() && self.connected {
                    if let Some(t) = sent_time {
                        self.acks.push((cmd.header, t));
                    }
                }
                return Flow::Gone(DisconnectReason::Remote(data));
            }
            Body::Connect(_) | Body::VerifyConnect(_) => {
                stats.unexpected += 1;
                return Flow::Stop;
            }
            Body::SendFragment(_) | Body::SendUnreliableFragment(_) => {
                stats.fragments += 1;
                return Flow::Stop;
            }
            _ if !self.connected => {
                stats.unexpected += 1;
                return Flow::Stop;
            }
            Body::Ping | Body::BandwidthLimit { .. } | Body::ThrottleConfigure { .. } => {}
            Body::SendReliable { data } => {
                if channel as usize >= self.channels.len() {
                    stats.unexpected += 1;
                    return Flow::Stop;
                }
                ack = self.receive_reliable(
                    channel,
                    cmd.header.reliable_sequence,
                    data,
                    config,
                    events,
                    stats,
                );
            }
            Body::SendUnreliable {
                unreliable_sequence,
                data,
            } => {
                let Some(ch) = self.channels.get_mut(channel as usize) else {
                    stats.unexpected += 1;
                    return Flow::Stop;
                };
                // Sequenced after the reliable command it followed. One that
                // overtook that command is dropped rather than held: it is
                // unreliable, and holding it is state.
                if cmd.header.reliable_sequence == ch.incoming_reliable
                    && unreliable_sequence > ch.incoming_unreliable
                {
                    ch.incoming_unreliable = unreliable_sequence;
                    events.push_back(Event::Receive {
                        channel,
                        data: data.to_vec(),
                    });
                }
            }
            Body::SendUnsequenced {
                unsequenced_group,
                data,
            } => {
                if channel as usize >= self.channels.len() {
                    stats.unexpected += 1;
                    return Flow::Stop;
                }
                if self.fresh_unsequenced(unsequenced_group) {
                    events.push_back(Event::Receive {
                        channel,
                        data: data.to_vec(),
                    });
                }
            }
        }

        if cmd.header.wants_ack() {
            // ENet stops reading a datagram whose acknowledgeable command it
            // cannot acknowledge for want of a sent time.
            let Some(t) = sent_time else {
                return Flow::Stop;
            };
            if ack && self.connected {
                self.acks.push((cmd.header, t));
            }
        }
        Flow::Continue
    }

    /// Retire the reliable command an acknowledgement names. Returns whether
    /// it was the `VERIFY_CONNECT`, which completes the handshake.
    fn acknowledged(
        &mut self,
        now_ms: u16,
        channel: u8,
        sequence: u16,
        echoed_ms: u16,
        events: &mut VecDeque<Event>,
    ) -> bool {
        // The echo is the low 16 bits of our clock when the acknowledged
        // datagram left, so the round trip is how far the clock has moved past
        // it. ENet ignores an acknowledgement from the future; so does this.
        let rtt = now_ms.wrapping_sub(echoed_ms);
        if rtt > u16::MAX / 2 {
            return false;
        }
        let Some(i) = self
            .in_flight
            .iter()
            .position(|f| f.first_sent.is_some() && f.channel == channel && f.sequence == sequence)
        else {
            return false;
        };
        self.update_rtt((rtt as u32).max(1));
        self.in_flight.remove(i);

        if !self.connected && channel == CONTROL_CHANNEL && sequence == 1 {
            self.connected = true;
            events.push_back(Event::Connected {
                address: self.address,
            });
            return true;
        }
        false
    }

    /// `enet_protocol_handle_acknowledge`'s smoothing.
    fn update_rtt(&mut self, sample: u32) {
        self.rtt = Some(match self.rtt {
            None => (sample, sample.div_ceil(2)),
            Some((mut rtt, mut var)) => {
                var -= var.div_ceil(4);
                if sample >= rtt {
                    let diff = sample - rtt;
                    var += diff.div_ceil(4);
                    rtt += diff.div_ceil(8);
                } else {
                    let diff = rtt - sample;
                    var += diff.div_ceil(4);
                    rtt -= diff.div_ceil(8);
                }
                (rtt, var)
            }
        });
    }

    /// Deliver a reliable command in order, or hold it until it can be.
    /// Returns whether to acknowledge it: a command that is neither delivered
    /// nor held must not be, or the sender would never resend it.
    fn receive_reliable(
        &mut self,
        channel: u8,
        sequence: u16,
        data: &[u8],
        config: &HostConfig,
        events: &mut VecDeque<Event>,
        stats: &mut Stats,
    ) -> bool {
        let ch = &mut self.channels[channel as usize];
        let ahead = sequence.wrapping_sub(ch.incoming_reliable);
        if ahead == 0 || ahead > u16::MAX / 2 {
            // Already delivered: the sender missed our acknowledgement.
            return true;
        }
        if ahead > REORDER_REACH {
            stats.overflow += 1;
            return false;
        }
        if ahead > 1 {
            if ch.early.contains_key(&sequence) {
                return true;
            }
            if self.early_commands >= MAX_EARLY_COMMANDS
                || self.buffered_bytes + data.len() > config.max_buffered_bytes
            {
                stats.overflow += 1;
                return false;
            }
            self.early_commands += 1;
            self.buffered_bytes += data.len();
            ch.early.insert(sequence, data.to_vec());
            return true;
        }

        ch.incoming_reliable = sequence;
        ch.incoming_unreliable = 0;
        events.push_back(Event::Receive {
            channel,
            data: data.to_vec(),
        });
        while let Some(next) = ch.early.remove(&ch.incoming_reliable.wrapping_add(1)) {
            self.early_commands -= 1;
            self.buffered_bytes -= next.len();
            ch.incoming_reliable = ch.incoming_reliable.wrapping_add(1);
            events.push_back(Event::Receive {
                channel,
                data: next,
            });
        }
        true
    }

    /// ENet's unsequenced duplicate window
    /// (`enet_protocol_handle_send_unsequenced`).
    fn fresh_unsequenced(&mut self, group: u16) -> bool {
        let index = group as u32 % UNSEQUENCED_WINDOW;
        let mut g = group as u32;
        let base = self.unsequenced_base as u32;
        if g < base {
            g += 0x10000;
        }
        if g >= base + FREE_UNSEQUENCED_WINDOWS * UNSEQUENCED_WINDOW {
            return false;
        }
        let g = g & 0xFFFF;
        let window_base = (g - index) as u16;
        if window_base != self.unsequenced_base {
            self.unsequenced_base = window_base;
            self.unsequenced_seen = [0; (UNSEQUENCED_WINDOW / 32) as usize];
        } else if self.unsequenced_seen[(index / 32) as usize] & (1 << (index % 32)) != 0 {
            return false;
        }
        self.unsequenced_seen[(index / 32) as usize] |= 1 << (index % 32);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: u32 = 0xb49654be;
    const CONNECT_ID: u32 = 0xc095f5a9;

    fn client() -> SocketAddr {
        "127.0.0.1:50000".parse().unwrap()
    }

    fn stranger() -> SocketAddr {
        "127.0.0.1:50001".parse().unwrap()
    }

    fn connect_body(data: u32) -> Connect {
        Connect {
            outgoing_peer_id: 0,
            incoming_session: 0xFF,
            outgoing_session: 0xFF,
            mtu: 900,
            window_size: MAXIMUM_WINDOW_SIZE,
            channel_count: 0x30,
            incoming_bandwidth: 0,
            outgoing_bandwidth: 0,
            packet_throttle_interval: 5000,
            packet_throttle_acceleration: 2,
            packet_throttle_deceleration: 2,
            connect_id: CONNECT_ID,
            data,
        }
    }

    /// A client-side datagram builder.
    struct Client {
        peer_id: u16,
        session: u8,
        time: u16,
    }

    impl Client {
        fn new() -> Self {
            Self {
                peer_id: UNASSIGNED_PEER_ID,
                session: 0,
                time: 0x1000,
            }
        }

        fn datagram(&mut self, cmds: &[Command<'_>]) -> Vec<u8> {
            self.time = self.time.wrapping_add(1);
            let mut out = Vec::new();
            Header {
                peer_id: self.peer_id,
                session: self.session,
                compressed: false,
                sent_time: Some(self.time),
            }
            .write(&mut out);
            for c in cmds {
                c.write(&mut out);
            }
            out
        }
    }

    fn cmd(number: u8, channel: u8, seq: u16, body: Body<'_>) -> Command<'_> {
        Command {
            header: CommandHeader {
                command: number,
                channel,
                reliable_sequence: seq,
            },
            body,
        }
    }

    fn connect_cmd(data: u32) -> Command<'static> {
        cmd(
            command::CONNECT | FLAG_ACKNOWLEDGE,
            CONTROL_CHANNEL,
            1,
            Body::Connect(connect_body(data)),
        )
    }

    fn reliable(channel: u8, seq: u16, data: &[u8]) -> Command<'_> {
        cmd(
            command::SEND_RELIABLE | FLAG_ACKNOWLEDGE,
            channel,
            seq,
            Body::SendReliable { data },
        )
    }

    fn ack_of(channel: u8, seq: u16, time: u16) -> Command<'static> {
        cmd(
            command::ACKNOWLEDGE,
            channel,
            seq,
            Body::Acknowledge {
                received_reliable_sequence: seq,
                received_sent_time: time,
            },
        )
    }

    /// Every command in every queued datagram, with the header it came in.
    fn drain(host: &mut Host) -> Vec<(Header, Vec<Command<'static>>)> {
        let mut out = Vec::new();
        while let Some(t) = host.poll_transmit() {
            assert_eq!(t.destination, client());
            assert!(t.payload.len() <= 900, "over the negotiated MTU");
            let bytes: &'static [u8] = Box::leak(t.payload.into_boxed_slice());
            let (h, body) = Header::parse(bytes).unwrap();
            out.push((
                h,
                commands(body).collect::<crate::wire::Result<_>>().unwrap(),
            ));
        }
        out
    }

    fn events(host: &mut Host) -> Vec<Event> {
        std::iter::from_fn(|| host.poll_event()).collect()
    }

    fn received(host: &mut Host) -> Vec<Vec<u8>> {
        events(host)
            .into_iter()
            .map(|e| match e {
                Event::Receive { data, .. } => data,
                other => panic!("expected data, got {other:?}"),
            })
            .collect()
    }

    fn acked(out: &[(Header, Vec<Command<'_>>)]) -> Vec<(u8, u16)> {
        out.iter()
            .flat_map(|(_, cmds)| cmds)
            .filter_map(|c| match c.body {
                Body::Acknowledge {
                    received_reliable_sequence,
                    ..
                } => Some((c.header.channel, received_reliable_sequence)),
                _ => None,
            })
            .collect()
    }

    /// A host with a client through the handshake.
    fn connected() -> (Host, Client, Instant) {
        let t0 = Instant::now();
        let mut host = Host::new(HostConfig::new(DATA), t0);
        let mut c = Client::new();
        host.handle_datagram(t0, client(), &c.datagram(&[connect_cmd(DATA)]));
        let out = drain(&mut host);
        let (h, cmds) = &out[0];
        let Body::VerifyConnect(v) = cmds[0].body else {
            panic!()
        };
        c.peer_id = v.outgoing_peer_id;
        c.session = v.outgoing_session;
        let t1 = t0 + Duration::from_millis(20);
        host.handle_datagram(
            t1,
            client(),
            &c.datagram(&[ack_of(CONTROL_CHANNEL, 1, h.sent_time.unwrap())]),
        );
        assert_eq!(events(&mut host), [Event::Connected { address: client() }]);
        (host, c, t1)
    }

    #[test]
    fn a_connect_is_answered_with_a_smaller_verify_that_echoes_what_a_client_checks() {
        let t0 = Instant::now();
        let mut host = Host::new(HostConfig::new(DATA), t0);
        let connect = Client::new().datagram(&[connect_cmd(DATA)]);
        host.handle_datagram(t0, client(), &connect);

        let t = host.poll_transmit().unwrap();
        assert!(host.poll_transmit().is_none());
        assert!(
            t.payload.len() < connect.len(),
            "{} >= {}: the port would amplify",
            t.payload.len(),
            connect.len()
        );
        let (h, body) = Header::parse(&t.payload).unwrap();
        assert_eq!(h.peer_id, 0, "addressed to the client's own peer index");
        assert!(
            h.sent_time.is_some(),
            "a reliable command needs a sent time"
        );
        let cmds: Vec<_> = commands(body).collect::<crate::wire::Result<_>>().unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(
            cmds[0].header.command,
            command::VERIFY_CONNECT | FLAG_ACKNOWLEDGE
        );
        assert_eq!(cmds[0].header.reliable_sequence, 1);
        let Body::VerifyConnect(v) = cmds[0].body else {
            panic!()
        };
        // `enet_protocol_handle_verify_connect` refuses a verify unless these
        // four match what it sent.
        assert_eq!(v.connect_id, CONNECT_ID);
        assert_eq!(v.packet_throttle_interval, 5000);
        assert_eq!(v.packet_throttle_acceleration, 2);
        assert_eq!(v.packet_throttle_deceleration, 2);
        assert_eq!(v.channel_count, 2);
        assert_eq!(v.mtu, 900);
        assert_eq!((v.incoming_session, v.outgoing_session), (0, 0));
        // Not connected until the verify is acknowledged.
        assert!(events(&mut host).is_empty());
        assert!(!host.is_connected());
    }

    #[test]
    fn the_wrong_connect_data_gets_no_reply_and_no_state() {
        let t0 = Instant::now();
        let mut host = Host::new(HostConfig::new(DATA), t0);
        host.handle_datagram(
            t0,
            client(),
            &Client::new().datagram(&[connect_cmd(DATA ^ 1)]),
        );
        assert!(host.poll_transmit().is_none());
        assert!(host.poll_timeout().is_none(), "no peer was created");
        assert_eq!(host.stats().wrong_connect_data, 1);
        // And the slot is still free for the real client.
        host.handle_datagram(t0, client(), &Client::new().datagram(&[connect_cmd(DATA)]));
        assert!(host.poll_transmit().is_some());
    }

    #[test]
    fn nothing_but_a_connect_is_read_from_an_unknown_peer() {
        let t0 = Instant::now();
        let mut host = Host::new(HostConfig::new(DATA), t0);
        let mut c = Client::new();
        for body in [
            reliable(0, 1, b"hi"),
            cmd(
                command::PING | FLAG_ACKNOWLEDGE,
                CONTROL_CHANNEL,
                1,
                Body::Ping,
            ),
            ack_of(CONTROL_CHANNEL, 1, 0),
        ] {
            host.handle_datagram(t0, client(), &c.datagram(&[body]));
        }
        // Nor anything after a connect in the same datagram.
        host.handle_datagram(
            t0,
            client(),
            &c.datagram(&[connect_cmd(DATA), reliable(0, 1, b"early")]),
        );
        let out = drain(&mut host);
        assert_eq!(out.len(), 1, "only the verify");
        assert!(events(&mut host).is_empty());
        assert_eq!(host.stats().foreign, 3);
    }

    #[test]
    fn a_second_client_is_refused_silently_while_the_first_holds_the_slot() {
        let (mut host, _, t) = connected();
        let mut other = connect_cmd(DATA);
        if let Body::Connect(c) = &mut other.body {
            c.connect_id ^= 0xFFFF;
        }
        host.handle_datagram(t, stranger(), &Client::new().datagram(&[other]));
        assert!(host.poll_transmit().is_none());
        assert_eq!(host.stats().busy, 1);
        assert!(host.is_connected());
    }

    #[test]
    fn a_retransmitted_connect_does_not_restart_the_handshake() {
        let t0 = Instant::now();
        let mut host = Host::new(HostConfig::new(DATA), t0);
        let mut c = Client::new();
        host.handle_datagram(t0, client(), &c.datagram(&[connect_cmd(DATA)]));
        assert_eq!(drain(&mut host).len(), 1);
        host.handle_datagram(
            t0 + Duration::from_millis(5),
            client(),
            &c.datagram(&[connect_cmd(DATA)]),
        );
        assert!(host.poll_transmit().is_none());
        assert_eq!(host.stats().busy, 0, "the same client, not a second one");
    }

    #[test]
    fn the_verify_is_retransmitted_until_acknowledged() {
        let t0 = Instant::now();
        let mut host = Host::new(HostConfig::new(DATA), t0);
        host.handle_datagram(t0, client(), &Client::new().datagram(&[connect_cmd(DATA)]));
        drain(&mut host);
        let mut sends = 0;
        let mut now = t0;
        while now < t0 + Duration::from_secs(3) {
            now = host
                .poll_timeout()
                .unwrap()
                .max(now + Duration::from_millis(1));
            host.handle_timeout(now);
            sends += drain(&mut host).len();
        }
        // 500 ms, then 1 s, 1.5 s... in the first three seconds.
        assert!((2..=5).contains(&sends), "{sends} retransmissions");
    }

    #[test]
    fn a_handshake_that_never_completes_is_abandoned_without_an_event() {
        let t0 = Instant::now();
        let mut host = Host::new(HostConfig::new(DATA), t0);
        host.handle_datagram(t0, client(), &Client::new().datagram(&[connect_cmd(DATA)]));
        host.handle_timeout(t0 + Duration::from_secs(11));
        assert!(host.poll_timeout().is_none());
        assert!(events(&mut host).is_empty());
    }

    #[test]
    fn reliable_data_is_delivered_in_order_whatever_order_it_arrives_in() {
        let (mut host, mut c, t) = connected();
        for seq in [3u16, 1, 4, 2] {
            let payload = [seq as u8];
            host.handle_datagram(t, client(), &c.datagram(&[reliable(0, seq, &payload)]));
        }
        assert_eq!(received(&mut host), [[1], [2], [3], [4]]);
        let mut acks = acked(&drain(&mut host));
        acks.sort();
        assert_eq!(acks, [(0, 1), (0, 2), (0, 3), (0, 4)]);
    }

    #[test]
    fn a_duplicate_is_acknowledged_again_but_delivered_once() {
        let (mut host, mut c, t) = connected();
        host.handle_datagram(t, client(), &c.datagram(&[reliable(0, 1, b"a")]));
        host.handle_datagram(t, client(), &c.datagram(&[reliable(0, 1, b"a")]));
        // And a held one, duplicated before the gap fills.
        host.handle_datagram(t, client(), &c.datagram(&[reliable(0, 3, b"c")]));
        host.handle_datagram(t, client(), &c.datagram(&[reliable(0, 3, b"c")]));
        host.handle_datagram(t, client(), &c.datagram(&[reliable(0, 2, b"b")]));
        assert_eq!(received(&mut host), [b"a", b"b", b"c"]);
        assert_eq!(acked(&drain(&mut host)).len(), 5);
    }

    #[test]
    fn channels_are_ordered_independently() {
        let (mut host, mut c, t) = connected();
        host.handle_datagram(
            t,
            client(),
            &c.datagram(&[reliable(0, 2, b"0b"), reliable(1, 1, b"1a")]),
        );
        let got = events(&mut host);
        assert_eq!(
            got,
            [Event::Receive {
                channel: 1,
                data: b"1a".to_vec()
            }]
        );
        // A channel that was not granted ends the datagram.
        host.handle_datagram(
            t,
            client(),
            &c.datagram(&[reliable(2, 1, b"x"), reliable(0, 1, b"0a")]),
        );
        assert!(events(&mut host).is_empty());
        assert_eq!(host.stats().unexpected, 1);
    }

    #[test]
    fn a_reliable_command_too_far_ahead_is_neither_held_nor_acknowledged() {
        let (mut host, mut c, t) = connected();
        host.handle_datagram(
            t,
            client(),
            &c.datagram(&[reliable(0, REORDER_REACH + 1, b"far")]),
        );
        assert!(acked(&drain(&mut host)).is_empty());
        assert_eq!(host.stats().overflow, 1);
    }

    #[test]
    fn the_reorder_buffer_is_bounded_and_refuses_rather_than_grows() {
        let t0 = Instant::now();
        let mut config = HostConfig::new(DATA);
        config.max_buffered_bytes = 1000;
        let mut host = Host::new(config, t0);
        let mut c = Client::new();
        host.handle_datagram(t0, client(), &c.datagram(&[connect_cmd(DATA)]));
        let (h, cmds) = drain(&mut host).remove(0);
        let Body::VerifyConnect(v) = cmds[0].body else {
            panic!()
        };
        c.peer_id = v.outgoing_peer_id;
        host.handle_datagram(
            t0,
            client(),
            &c.datagram(&[ack_of(CONTROL_CHANNEL, 1, h.sent_time.unwrap())]),
        );
        events(&mut host);

        let blob = [0u8; 400];
        for seq in 2..=4u16 {
            host.handle_datagram(t0, client(), &c.datagram(&[reliable(0, seq, &blob)]));
        }
        assert_eq!(acked(&drain(&mut host)), [(0, 2), (0, 3)]);
        assert_eq!(host.stats().overflow, 1);
        // The gap fills and the held two drain; the refused one comes again.
        host.handle_datagram(t0, client(), &c.datagram(&[reliable(0, 1, b"x")]));
        host.handle_datagram(t0, client(), &c.datagram(&[reliable(0, 4, &blob)]));
        assert_eq!(received(&mut host).len(), 4);
    }

    #[test]
    fn fragments_are_refused_unacknowledged_and_end_the_datagram() {
        let (mut host, mut c, t) = connected();
        let frag = cmd(
            command::SEND_FRAGMENT | FLAG_ACKNOWLEDGE,
            0,
            1,
            Body::SendFragment(crate::wire::enet::Fragment {
                start_sequence: 1,
                fragment_count: 1_000_000,
                fragment_number: 0,
                total_length: u32::MAX,
                fragment_offset: 0,
                data: b"x",
            }),
        );
        host.handle_datagram(t, client(), &c.datagram(&[frag, reliable(0, 1, b"after")]));
        assert!(acked(&drain(&mut host)).is_empty());
        assert!(events(&mut host).is_empty());
        assert_eq!(host.stats().fragments, 1);
    }

    #[test]
    fn a_datagram_from_anywhere_but_the_peer_is_dropped() {
        let (mut host, mut c, t) = connected();
        let d = c.datagram(&[reliable(0, 1, b"spoof")]);
        host.handle_datagram(t, stranger(), &d);
        // The right address with the wrong session is a stale connection.
        c.session ^= 1;
        host.handle_datagram(t, client(), &c.datagram(&[reliable(0, 1, b"stale")]));
        assert!(events(&mut host).is_empty());
        assert!(host.poll_transmit().is_none());
        assert_eq!(host.stats().foreign, 2);
    }

    #[test]
    fn no_more_than_thirty_two_commands_are_read_from_one_datagram() {
        let (mut host, mut c, t) = connected();
        let pings: Vec<_> = (0..40)
            .map(|i| {
                cmd(
                    command::PING | FLAG_ACKNOWLEDGE,
                    CONTROL_CHANNEL,
                    i + 2,
                    Body::Ping,
                )
            })
            .collect();
        host.handle_datagram(t, client(), &c.datagram(&pings));
        let out = drain(&mut host);
        assert_eq!(acked(&out).len(), MAXIMUM_PACKET_COMMANDS);
        assert_eq!(out.len(), 1, "32 acknowledgements fit one datagram");
    }

    #[test]
    fn an_acknowledgeable_command_without_a_sent_time_ends_the_datagram() {
        let (mut host, c, t) = connected();
        let mut d = Vec::new();
        Header {
            peer_id: c.peer_id,
            session: c.session,
            compressed: false,
            sent_time: None,
        }
        .write(&mut d);
        reliable(0, 1, b"a").write(&mut d);
        reliable(0, 2, b"b").write(&mut d);
        host.handle_datagram(t, client(), &d);
        // ENet delivers the first and stops; so does this.
        assert_eq!(received(&mut host), [b"a"]);
        assert!(acked(&drain(&mut host)).is_empty());
    }

    #[test]
    fn unsequenced_data_is_delivered_once_in_any_order() {
        let (mut host, mut c, t) = connected();
        for group in [5u16, 3, 5, 4, 3] {
            let payload = [group as u8];
            host.handle_datagram(
                t,
                client(),
                &c.datagram(&[cmd(
                    command::SEND_UNSEQUENCED | FLAG_UNSEQUENCED,
                    0,
                    0,
                    Body::SendUnsequenced {
                        unsequenced_group: group,
                        data: &payload,
                    },
                )]),
            );
        }
        assert_eq!(received(&mut host), [[5], [3], [4]]);
    }

    #[test]
    fn unreliable_data_never_goes_backwards() {
        let (mut host, mut c, t) = connected();
        for useq in [2u16, 1, 3, 3] {
            let payload = [useq as u8];
            host.handle_datagram(
                t,
                client(),
                &c.datagram(&[cmd(
                    command::SEND_UNRELIABLE,
                    0,
                    0,
                    Body::SendUnreliable {
                        unreliable_sequence: useq,
                        data: &payload,
                    },
                )]),
            );
        }
        assert_eq!(received(&mut host), [[2], [3]]);
    }

    #[test]
    fn a_disconnect_is_acknowledged_and_ends_the_connection() {
        let (mut host, mut c, t) = connected();
        host.handle_datagram(
            t,
            client(),
            &c.datagram(&[cmd(
                command::DISCONNECT | FLAG_ACKNOWLEDGE,
                CONTROL_CHANNEL,
                3,
                Body::Disconnect { data: 7 },
            )]),
        );
        assert_eq!(acked(&drain(&mut host)), [(CONTROL_CHANNEL, 3)]);
        assert_eq!(
            events(&mut host),
            [Event::Disconnected {
                reason: DisconnectReason::Remote(7)
            }]
        );
        assert!(!host.is_connected());
        // The slot is free again.
        host.handle_datagram(t, client(), &Client::new().datagram(&[connect_cmd(DATA)]));
        assert!(host.poll_transmit().is_some());
    }

    #[test]
    fn a_silent_peer_times_out() {
        let (mut host, _, t) = connected();
        host.handle_timeout(t + Duration::from_secs(9));
        assert!(host.is_connected());
        host.handle_timeout(t + Duration::from_secs(10));
        assert_eq!(
            events(&mut host),
            [Event::Disconnected {
                reason: DisconnectReason::TimedOut
            }]
        );
    }

    #[test]
    fn the_hosts_own_sends_are_retransmitted_until_acknowledged() {
        let (mut host, mut c, t) = connected();
        assert_eq!(host.unacknowledged(), 0);
        host.send(t, 0, b"rumble").unwrap();
        assert_eq!(host.unacknowledged(), 1);
        let (h, cmds) = drain(&mut host).remove(0);
        assert_eq!(cmds[0].body, Body::SendReliable { data: b"rumble" });
        assert_eq!(cmds[0].header.reliable_sequence, 1);

        // Lost: it comes again once the timeout passes.
        let later = host.poll_timeout().unwrap();
        host.handle_timeout(later);
        let (h2, again) = drain(&mut host).remove(0);
        assert_eq!(again[0].body, cmds[0].body);

        // Acknowledging either transmission retires it.
        let _ = h;
        host.handle_datagram(
            later,
            client(),
            &c.datagram(&[ack_of(0, 1, h2.sent_time.unwrap())]),
        );
        assert_eq!(host.unacknowledged(), 0);
        host.handle_timeout(later + Duration::from_secs(5));
        assert!(drain(&mut host).is_empty());
        assert!(host.is_connected());
    }

    #[test]
    fn a_peer_that_stops_acknowledging_is_given_up_on_even_if_it_still_talks() {
        let (mut host, mut c, t) = connected();
        host.send(t, 0, b"x").unwrap();
        let mut now = t;
        let mut seq = 1;
        while host.is_connected() {
            now += Duration::from_millis(250);
            seq += 1;
            host.handle_datagram(
                now,
                client(),
                &c.datagram(&[cmd(
                    command::PING | FLAG_ACKNOWLEDGE,
                    CONTROL_CHANNEL,
                    seq,
                    Body::Ping,
                )]),
            );
            host.handle_timeout(now);
            assert!(now < t + Duration::from_secs(11));
        }
        assert!(now >= t + Duration::from_secs(10));
    }

    #[test]
    fn sends_are_refused_rather_than_queued_without_bound() {
        let (mut host, _, t) = connected();
        assert_eq!(host.send(t, 5, b"x"), Err(SendError::NoSuchChannel(5)));
        assert_eq!(host.send(t, 0, &[0; 2000]), Err(SendError::TooLarge(2000)));
        for _ in 0..64 {
            host.send(t, 0, b"x").unwrap();
        }
        assert_eq!(host.send(t, 0, b"x"), Err(SendError::Busy));
        // Everything queued went out, within the MTU and command limits.
        let out = drain(&mut host);
        assert_eq!(out.iter().map(|(_, c)| c.len()).sum::<usize>(), 64);
        assert!(out.iter().all(|(_, c)| c.len() <= MAXIMUM_PACKET_COMMANDS));
    }

    #[test]
    fn disconnect_sends_one_unacknowledged_disconnect_and_forgets_the_peer() {
        let (mut host, _, _) = connected();
        host.disconnect(0);
        let out = drain(&mut host);
        assert_eq!(out.len(), 1);
        let (h, cmds) = &out[0];
        assert_eq!(h.sent_time, None);
        assert_eq!(
            cmds[0].header.command,
            command::DISCONNECT | FLAG_UNSEQUENCED
        );
        assert!(!host.is_connected());
        assert!(events(&mut host).is_empty());
    }

    /// The host is driven with mangled versions of real datagrams. Nothing may
    /// panic, and the held state stays inside its bounds whatever arrives.
    /// The cargo-fuzz target `enet_host` does this properly; this keeps a
    /// stable-toolchain `cargo test` honest in the meantime.
    #[test]
    fn mangled_datagrams_never_panic_and_never_grow_the_state() {
        let mut rng = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for round in 0..200 {
            let (mut host, mut c, mut now) = connected();
            let mut seeds = vec![
                c.datagram(&[reliable(0, 1, b"input batch")]),
                c.datagram(&[ack_of(CONTROL_CHANNEL, 1, 0), reliable(1, 1, b"idr")]),
                c.datagram(&[cmd(
                    command::SEND_UNSEQUENCED,
                    0,
                    0,
                    Body::SendUnsequenced {
                        unsequenced_group: 1,
                        data: b"fec",
                    },
                )]),
                Client::new().datagram(&[connect_cmd(DATA)]),
            ];
            for _ in 0..300 {
                let mut d = seeds[(next() % seeds.len() as u64) as usize].clone();
                for _ in 0..(next() % 4) {
                    let at = (next() % d.len().max(1) as u64) as usize;
                    match next() % 4 {
                        0 if !d.is_empty() => d[at] ^= 1 << (next() % 8),
                        1 if !d.is_empty() => d[at] = next() as u8,
                        2 => d.truncate(at),
                        _ => d.extend((0..next() % 16).map(|_| next() as u8)),
                    }
                }
                let from = if next() % 8 == 0 {
                    stranger()
                } else {
                    client()
                };
                now += Duration::from_millis(next() % 50);
                host.handle_datagram(now, from, &d);
                if next() % 16 == 0 {
                    host.handle_timeout(now);
                }
                while host.poll_transmit().is_some() {}
                while host.poll_event().is_some() {}
                if let Some(p) = &host.peer {
                    assert!(p.buffered_bytes <= 64 * 1024, "round {round}");
                    assert!(p.early_commands <= MAX_EARLY_COMMANDS);
                    assert!(p.in_flight.len() <= 64 + 1);
                    assert!(p.acks.is_empty(), "acks are flushed per datagram");
                }
                if next() % 32 == 0 {
                    seeds.push(d);
                }
            }
        }
    }
}
