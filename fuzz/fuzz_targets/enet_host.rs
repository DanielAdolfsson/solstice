//! The ENet host: the one stateful protocol reachable before authentication
//! (`docs/security.md` §2.4), and where GHSA-c428-87f8-rrv5 lives.
//!
//! The input is a run of datagrams, each `[flags][len: u16 le][bytes]`. Every
//! one goes to two hosts: a fresh one, which is the pre-authentication surface
//! -- anything may arrive, and only a `CONNECT` with the right connect data
//! may change its state -- and one a scripted client has already connected,
//! which is everything after. `flags` picks the sender (bit 0: a stranger),
//! whether timers run afterwards (bit 1), and how far the clock moves first
//! (bits 2-7, in 50 ms steps).
#![no_main]
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use solstice_gamestream::stream::enet::{Event, Host, HostConfig};
use solstice_gamestream::wire::enet::{
    command, Body, Command, CommandHeader, Connect, Header, CONTROL_CHANNEL, FLAG_ACKNOWLEDGE,
    UNASSIGNED_PEER_ID,
};

const CONNECT_DATA: u32 = 0xb49654be;

fn datagram(peer_id: u16, sent_time: u16, cmd: Command<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    Header {
        peer_id,
        session: 0,
        compressed: false,
        sent_time: Some(sent_time),
    }
    .write(&mut out);
    cmd.write(&mut out);
    out
}

/// A host with a client already through the handshake.
fn connected(t0: Instant, client: SocketAddr) -> Host {
    let mut host = Host::new(HostConfig::new(CONNECT_DATA), t0);
    let connect = Command {
        header: CommandHeader {
            command: command::CONNECT | FLAG_ACKNOWLEDGE,
            channel: CONTROL_CHANNEL,
            reliable_sequence: 1,
        },
        body: Body::Connect(Connect {
            outgoing_peer_id: 0,
            incoming_session: 0xFF,
            outgoing_session: 0xFF,
            mtu: 900,
            window_size: 65536,
            channel_count: 0x30,
            incoming_bandwidth: 0,
            outgoing_bandwidth: 0,
            packet_throttle_interval: 5000,
            packet_throttle_acceleration: 2,
            packet_throttle_deceleration: 2,
            connect_id: 1,
            data: CONNECT_DATA,
        }),
    };
    host.handle_datagram(t0, client, &datagram(UNASSIGNED_PEER_ID, 1, connect));
    let verify = host.poll_transmit().expect("a verify");
    let (h, _) = Header::parse(&verify.payload).unwrap();
    let ack = Command {
        header: CommandHeader {
            command: command::ACKNOWLEDGE,
            channel: CONTROL_CHANNEL,
            reliable_sequence: 1,
        },
        body: Body::Acknowledge {
            received_reliable_sequence: 1,
            received_sent_time: h.sent_time.unwrap(),
        },
    };
    host.handle_datagram(t0, client, &datagram(0, 2, ack));
    assert!(host.is_connected());
    host
}

fuzz_target!(|data: &[u8]| {
    let client: SocketAddr = "127.0.0.1:50000".parse().unwrap();
    let stranger: SocketAddr = "127.0.0.1:50001".parse().unwrap();
    let mut now = Instant::now();
    let mut fresh = Host::new(HostConfig::new(CONNECT_DATA), now);
    let mut host = connected(now, client);

    let mut rest = data;
    while rest.len() >= 3 {
        let flags = rest[0];
        let len = (u16::from_le_bytes([rest[1], rest[2]]) as usize).min(rest.len() - 3);
        let d = &rest[3..3 + len];
        rest = &rest[3 + len..];

        now += Duration::from_millis(50 * (flags >> 2) as u64);
        let from = if flags & 1 != 0 { stranger } else { client };
        for h in [&mut fresh, &mut host] {
            h.handle_datagram(now, from, d);
            if flags & 2 != 0 {
                h.handle_timeout(now);
            }
            while let Some(t) = h.poll_transmit() {
                // Never larger than the largest MTU a client can negotiate.
                assert!(t.payload.len() <= 1392);
            }
            while let Some(e) = h.poll_event() {
                if let Event::Receive { data, .. } = e {
                    assert!(data.len() <= 4096);
                }
            }
        }
    }
});
