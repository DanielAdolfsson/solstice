//! ENet's wire format: the datagram header and the twelve commands
//! (`enet/include/enet/protocol.h` in Moonlight's fork, which is ENet 1.3.17
//! plus QoS and IPv6 changes that leave the wire alone).
//!
//! Everything is big-endian. A datagram is a 2-byte header, optionally followed
//! by a 2-byte sent time, and then a run of commands packed back to back, each
//! of a fixed size given by its number, with the payload of the four `SEND_*`
//! commands trailing it. Moonlight runs ENet without a checksum and without
//! compression, so neither is modelled beyond being recognised and refused.
//!
//! This module only frames. What a command *means* -- sequencing,
//! acknowledgement, the connection state machine -- is `stream::enet`.

use super::{Reader, Result, WireError};

/// The peer ID a client uses before the host has assigned it one.
pub const UNASSIGNED_PEER_ID: u16 = 0x0FFF;
/// The channel ENet's own housekeeping (connect, ping, disconnect) rides on.
pub const CONTROL_CHANNEL: u8 = 0xFF;
/// `ENET_PROTOCOL_MINIMUM_MTU`.
pub const MINIMUM_MTU: u32 = 576;
/// `ENET_PROTOCOL_MAXIMUM_MTU`, and so the largest datagram a conforming peer
/// sends.
pub const MAXIMUM_MTU: u32 = 4096;
/// `ENET_PROTOCOL_MINIMUM_WINDOW_SIZE`.
pub const MINIMUM_WINDOW_SIZE: u32 = 4096;
/// `ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE`.
pub const MAXIMUM_WINDOW_SIZE: u32 = 65536;
/// `ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT`.
pub const MAXIMUM_CHANNEL_COUNT: u32 = 255;
/// `ENET_PROTOCOL_MAXIMUM_PACKET_COMMANDS`: a sender assembles a datagram in a
/// fixed array of this many commands, so no conforming datagram holds more.
pub const MAXIMUM_PACKET_COMMANDS: usize = 32;

const HEADER_FLAG_COMPRESSED: u16 = 1 << 14;
const HEADER_FLAG_SENT_TIME: u16 = 1 << 15;
const HEADER_SESSION_SHIFT: u16 = 12;
const HEADER_SESSION_MASK: u16 = 3 << HEADER_SESSION_SHIFT;

/// `ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE`: the receiver must acknowledge.
pub const FLAG_ACKNOWLEDGE: u8 = 1 << 7;
/// `ENET_PROTOCOL_COMMAND_FLAG_UNSEQUENCED`.
pub const FLAG_UNSEQUENCED: u8 = 1 << 6;
const COMMAND_MASK: u8 = 0x0F;

/// Command numbers (`ENetProtocolCommand`).
pub mod command {
    #![allow(missing_docs)]
    pub const ACKNOWLEDGE: u8 = 1;
    pub const CONNECT: u8 = 2;
    pub const VERIFY_CONNECT: u8 = 3;
    pub const DISCONNECT: u8 = 4;
    pub const PING: u8 = 5;
    pub const SEND_RELIABLE: u8 = 6;
    pub const SEND_UNRELIABLE: u8 = 7;
    pub const SEND_FRAGMENT: u8 = 8;
    pub const SEND_UNSEQUENCED: u8 = 9;
    pub const BANDWIDTH_LIMIT: u8 = 10;
    pub const THROTTLE_CONFIGURE: u8 = 11;
    pub const SEND_UNRELIABLE_FRAGMENT: u8 = 12;
}

/// The fixed size of each command, payload excluded (`commandSizes` in
/// `protocol.c`). Zero marks a number that is not a command.
const COMMAND_SIZES: [usize; 13] = [0, 8, 48, 44, 8, 4, 6, 8, 24, 8, 12, 16, 24];

/// Size of the common command header.
pub const COMMAND_HEADER_LEN: usize = 4;

/// The datagram header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The receiver's peer ID, or [`UNASSIGNED_PEER_ID`].
    pub peer_id: u16,
    /// Two bits that tell one connection on a peer slot from the last.
    pub session: u8,
    /// The body is compressed. Moonlight never sets this.
    pub compressed: bool,
    /// The sender's clock, low 16 bits, in milliseconds. Present whenever the
    /// datagram carries a command that must be acknowledged, since the
    /// acknowledgement echoes it.
    pub sent_time: Option<u16>,
}

impl Header {
    /// Parse a header, returning it and the commands that follow.
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8])> {
        let mut r = Reader::new(buf);
        let word = r.u16be()?;
        let sent_time = if word & HEADER_FLAG_SENT_TIME != 0 {
            Some(r.u16be()?)
        } else {
            None
        };
        Ok((
            Self {
                peer_id: word
                    & !(HEADER_FLAG_COMPRESSED | HEADER_FLAG_SENT_TIME | HEADER_SESSION_MASK),
                session: ((word & HEADER_SESSION_MASK) >> HEADER_SESSION_SHIFT) as u8,
                compressed: word & HEADER_FLAG_COMPRESSED != 0,
                sent_time,
            },
            r.peek_rest(),
        ))
    }

    /// Serialise.
    pub fn write(&self, out: &mut Vec<u8>) {
        let mut word = (self.peer_id & UNASSIGNED_PEER_ID)
            | ((self.session as u16) << HEADER_SESSION_SHIFT) & HEADER_SESSION_MASK;
        if self.compressed {
            word |= HEADER_FLAG_COMPRESSED;
        }
        if self.sent_time.is_some() {
            word |= HEADER_FLAG_SENT_TIME;
        }
        out.extend_from_slice(&word.to_be_bytes());
        if let Some(t) = self.sent_time {
            out.extend_from_slice(&t.to_be_bytes());
        }
    }
}

/// The header every command starts with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandHeader {
    /// The command number with its two flags.
    pub command: u8,
    /// Which channel, or [`CONTROL_CHANNEL`].
    pub channel: u8,
    /// The sender's reliable sequence number on that channel.
    pub reliable_sequence: u16,
}

impl CommandHeader {
    /// The command number, flags masked off.
    pub fn number(&self) -> u8 {
        self.command & COMMAND_MASK
    }

    /// Whether the receiver must acknowledge this command.
    pub fn wants_ack(&self) -> bool {
        self.command & FLAG_ACKNOWLEDGE != 0
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.command);
        out.push(self.channel);
        out.extend_from_slice(&self.reliable_sequence.to_be_bytes());
    }
}

/// `ENetProtocolConnect` and `ENetProtocolVerifyConnect` share every field but
/// the last; `data` is the connect's alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connect {
    /// The sender's own index for this peer.
    pub outgoing_peer_id: u16,
    /// Session the sender expects to receive with, or `0xFF` for "pick one".
    pub incoming_session: u8,
    /// Session the sender will send with, or `0xFF` for "pick one".
    pub outgoing_session: u8,
    /// Proposed MTU.
    pub mtu: u32,
    /// Proposed reliable window, in bytes.
    pub window_size: u32,
    /// Channels requested.
    pub channel_count: u32,
    /// Bandwidth limits, bytes per second, zero for none.
    pub incoming_bandwidth: u32,
    /// See `incoming_bandwidth`.
    pub outgoing_bandwidth: u32,
    /// Throttle parameters. A client checks that the verify echoes all three.
    pub packet_throttle_interval: u32,
    /// See `packet_throttle_interval`.
    pub packet_throttle_acceleration: u32,
    /// See `packet_throttle_interval`.
    pub packet_throttle_deceleration: u32,
    /// Random per attempt; echoed in the verify. Not byte-swapped by ENet, so
    /// it is carried here exactly as the wire has it.
    pub connect_id: u32,
    /// The application's connect data. For GameStream it binds the peer to a
    /// launch (`docs/moonlight-sunshine-protocol.md`). Absent from a verify.
    pub data: u32,
}

/// One command, with its payload borrowed from the datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body<'a> {
    /// Acknowledges one reliable command.
    Acknowledge {
        /// The acknowledged command's sequence number.
        received_reliable_sequence: u16,
        /// The `sent_time` of the datagram that carried it.
        received_sent_time: u16,
    },
    /// Opens a connection.
    Connect(Connect),
    /// Accepts one. `data` is always zero.
    VerifyConnect(Connect),
    /// Closes one.
    Disconnect {
        /// Application data.
        data: u32,
    },
    /// Keeps one alive.
    Ping,
    /// Reliable, ordered data.
    SendReliable {
        /// The payload.
        data: &'a [u8],
    },
    /// Unreliable, sequenced data.
    SendUnreliable {
        /// Sequence among the unreliables since the last reliable.
        unreliable_sequence: u16,
        /// The payload.
        data: &'a [u8],
    },
    /// One fragment of a packet larger than the MTU.
    SendFragment(Fragment<'a>),
    /// Unreliable, unordered data.
    SendUnsequenced {
        /// The group, for duplicate suppression.
        unsequenced_group: u16,
        /// The payload.
        data: &'a [u8],
    },
    /// New bandwidth limits.
    BandwidthLimit {
        /// Bytes per second, zero for none.
        incoming: u32,
        /// Bytes per second, zero for none.
        outgoing: u32,
    },
    /// New throttle parameters.
    ThrottleConfigure {
        /// Milliseconds.
        interval: u32,
        /// Throttle step up.
        acceleration: u32,
        /// Throttle step down.
        deceleration: u32,
    },
    /// One fragment of an unreliable packet larger than the MTU.
    SendUnreliableFragment(Fragment<'a>),
}

/// `ENetProtocolSendFragment`. Parsed so that the commands after it can be
/// found; never reassembled (`stream::enet` says why).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment<'a> {
    /// The sequence number of the first fragment.
    pub start_sequence: u16,
    /// How many fragments make up the packet.
    pub fragment_count: u32,
    /// Which one this is.
    pub fragment_number: u32,
    /// Length of the reassembled packet.
    pub total_length: u32,
    /// Where this fragment goes in it.
    pub fragment_offset: u32,
    /// The fragment's bytes.
    pub data: &'a [u8],
}

/// A command: its header and body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Command<'a> {
    /// The common header.
    pub header: CommandHeader,
    /// What follows it.
    pub body: Body<'a>,
}

impl<'a> Command<'a> {
    /// Parse one command from the front of `r`.
    ///
    /// Every size is checked before it is used: a fixed part that overruns the
    /// datagram, and a payload length that does, are both errors rather than
    /// short reads. This is where GHSA-c428-87f8-rrv5, a short ENet control
    /// packet, would land.
    pub fn parse(r: &mut Reader<'a>) -> Result<Self> {
        let start = r.peek_rest();
        let header = {
            let mut h = Reader::new(start);
            CommandHeader {
                command: h.u8()?,
                channel: h.u8()?,
                reliable_sequence: h.u16be()?,
            }
        };
        let number = header.number();
        let size = COMMAND_SIZES.get(number as usize).copied().unwrap_or(0);
        if size == 0 {
            return Err(WireError::InvalidField {
                field: "ENet command",
                value: number as u64,
            });
        }
        let mut c = Reader::new(r.take(size)?);
        c.skip(COMMAND_HEADER_LEN)?;

        let mut payload = |len: u16| -> Result<&'a [u8]> {
            let len = len as usize;
            if r.remaining() < len {
                return Err(WireError::LengthOverrun {
                    claimed: len,
                    available: r.remaining(),
                });
            }
            r.take(len)
        };

        let body = match number {
            command::ACKNOWLEDGE => Body::Acknowledge {
                received_reliable_sequence: c.u16be()?,
                received_sent_time: c.u16be()?,
            },
            command::CONNECT => Body::Connect(parse_connect(&mut c, true)?),
            command::VERIFY_CONNECT => Body::VerifyConnect(parse_connect(&mut c, false)?),
            command::DISCONNECT => Body::Disconnect { data: c.u32be()? },
            command::PING => Body::Ping,
            command::SEND_RELIABLE => {
                let len = c.u16be()?;
                Body::SendReliable {
                    data: payload(len)?,
                }
            }
            command::SEND_UNRELIABLE => {
                let unreliable_sequence = c.u16be()?;
                let len = c.u16be()?;
                Body::SendUnreliable {
                    unreliable_sequence,
                    data: payload(len)?,
                }
            }
            command::SEND_UNSEQUENCED => {
                let unsequenced_group = c.u16be()?;
                let len = c.u16be()?;
                Body::SendUnsequenced {
                    unsequenced_group,
                    data: payload(len)?,
                }
            }
            command::SEND_FRAGMENT | command::SEND_UNRELIABLE_FRAGMENT => {
                let start_sequence = c.u16be()?;
                let len = c.u16be()?;
                let fragment = Fragment {
                    start_sequence,
                    fragment_count: c.u32be()?,
                    fragment_number: c.u32be()?,
                    total_length: c.u32be()?,
                    fragment_offset: c.u32be()?,
                    data: payload(len)?,
                };
                if number == command::SEND_FRAGMENT {
                    Body::SendFragment(fragment)
                } else {
                    Body::SendUnreliableFragment(fragment)
                }
            }
            command::BANDWIDTH_LIMIT => Body::BandwidthLimit {
                incoming: c.u32be()?,
                outgoing: c.u32be()?,
            },
            command::THROTTLE_CONFIGURE => Body::ThrottleConfigure {
                interval: c.u32be()?,
                acceleration: c.u32be()?,
                deceleration: c.u32be()?,
            },
            _ => unreachable!("COMMAND_SIZES has a zero for every other number"),
        };
        Ok(Self { header, body })
    }

    /// Serialise.
    pub fn write(&self, out: &mut Vec<u8>) {
        self.header.write(out);
        match &self.body {
            Body::Acknowledge {
                received_reliable_sequence,
                received_sent_time,
            } => {
                out.extend_from_slice(&received_reliable_sequence.to_be_bytes());
                out.extend_from_slice(&received_sent_time.to_be_bytes());
            }
            Body::Connect(c) => write_connect(c, true, out),
            Body::VerifyConnect(c) => write_connect(c, false, out),
            Body::Disconnect { data } => out.extend_from_slice(&data.to_be_bytes()),
            Body::Ping => {}
            Body::SendReliable { data } => {
                out.extend_from_slice(&(data.len() as u16).to_be_bytes());
                out.extend_from_slice(data);
            }
            Body::SendUnreliable {
                unreliable_sequence,
                data,
            } => {
                out.extend_from_slice(&unreliable_sequence.to_be_bytes());
                out.extend_from_slice(&(data.len() as u16).to_be_bytes());
                out.extend_from_slice(data);
            }
            Body::SendUnsequenced {
                unsequenced_group,
                data,
            } => {
                out.extend_from_slice(&unsequenced_group.to_be_bytes());
                out.extend_from_slice(&(data.len() as u16).to_be_bytes());
                out.extend_from_slice(data);
            }
            Body::SendFragment(f) | Body::SendUnreliableFragment(f) => {
                out.extend_from_slice(&f.start_sequence.to_be_bytes());
                out.extend_from_slice(&(f.data.len() as u16).to_be_bytes());
                out.extend_from_slice(&f.fragment_count.to_be_bytes());
                out.extend_from_slice(&f.fragment_number.to_be_bytes());
                out.extend_from_slice(&f.total_length.to_be_bytes());
                out.extend_from_slice(&f.fragment_offset.to_be_bytes());
                out.extend_from_slice(f.data);
            }
            Body::BandwidthLimit { incoming, outgoing } => {
                out.extend_from_slice(&incoming.to_be_bytes());
                out.extend_from_slice(&outgoing.to_be_bytes());
            }
            Body::ThrottleConfigure {
                interval,
                acceleration,
                deceleration,
            } => {
                out.extend_from_slice(&interval.to_be_bytes());
                out.extend_from_slice(&acceleration.to_be_bytes());
                out.extend_from_slice(&deceleration.to_be_bytes());
            }
        }
    }

    /// The serialised size.
    pub fn wire_len(&self) -> usize {
        let payload = match &self.body {
            Body::SendReliable { data }
            | Body::SendUnreliable { data, .. }
            | Body::SendUnsequenced { data, .. } => data.len(),
            Body::SendFragment(f) | Body::SendUnreliableFragment(f) => f.data.len(),
            _ => 0,
        };
        COMMAND_SIZES[self.header.number() as usize] + payload
    }
}

fn parse_connect(c: &mut Reader<'_>, with_data: bool) -> Result<Connect> {
    Ok(Connect {
        outgoing_peer_id: c.u16be()?,
        incoming_session: c.u8()?,
        outgoing_session: c.u8()?,
        mtu: c.u32be()?,
        window_size: c.u32be()?,
        channel_count: c.u32be()?,
        incoming_bandwidth: c.u32be()?,
        outgoing_bandwidth: c.u32be()?,
        packet_throttle_interval: c.u32be()?,
        packet_throttle_acceleration: c.u32be()?,
        packet_throttle_deceleration: c.u32be()?,
        connect_id: u32::from_ne_bytes(c.take_array()?),
        data: if with_data { c.u32be()? } else { 0 },
    })
}

fn write_connect(c: &Connect, with_data: bool, out: &mut Vec<u8>) {
    out.extend_from_slice(&c.outgoing_peer_id.to_be_bytes());
    out.push(c.incoming_session);
    out.push(c.outgoing_session);
    for v in [
        c.mtu,
        c.window_size,
        c.channel_count,
        c.incoming_bandwidth,
        c.outgoing_bandwidth,
        c.packet_throttle_interval,
        c.packet_throttle_acceleration,
        c.packet_throttle_deceleration,
    ] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(&c.connect_id.to_ne_bytes());
    if with_data {
        out.extend_from_slice(&c.data.to_be_bytes());
    }
}

/// Iterate the commands of a datagram body.
///
/// Stops at the end of the datagram, and yields an error and then stops at the
/// first command that does not parse -- which is what ENet does (`protocol.c`,
/// `enet_protocol_handle_incoming_commands`): the commands before a bad one
/// stand, and nothing after it is read.
pub fn commands(body: &[u8]) -> Commands<'_> {
    Commands {
        reader: Reader::new(body),
        failed: false,
    }
}

/// See [`commands`].
#[derive(Debug, Clone)]
pub struct Commands<'a> {
    reader: Reader<'a>,
    failed: bool,
}

impl<'a> Iterator for Commands<'a> {
    type Item = Result<Command<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.reader.is_empty() {
            return None;
        }
        let parsed = Command::parse(&mut self.reader);
        self.failed = parsed.is_err();
        Some(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first datagram of the captured session (`tests/vectors/capture/`):
    /// the reference client's CONNECT.
    const CAPTURED_CONNECT: &str = "8fff69a182ff00010000ffff0000038400010000000000300000000000000000000013880000000200000002a9f595c0b49654be";

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn the_captured_connect_parses_field_by_field() {
        let datagram = unhex(CAPTURED_CONNECT);
        let (header, body) = Header::parse(&datagram).unwrap();
        assert_eq!(
            header,
            Header {
                peer_id: UNASSIGNED_PEER_ID,
                session: 0,
                compressed: false,
                sent_time: Some(0x69a1),
            }
        );
        let all: Vec<_> = commands(body).collect::<Result<_>>().unwrap();
        assert_eq!(all.len(), 1);
        let cmd = all[0];
        assert_eq!(cmd.header.number(), command::CONNECT);
        assert!(cmd.header.wants_ack());
        assert_eq!(cmd.header.channel, CONTROL_CHANNEL);
        assert_eq!(cmd.header.reliable_sequence, 1);
        let Body::Connect(c) = cmd.body else {
            panic!("not a connect: {cmd:?}")
        };
        assert_eq!(c.outgoing_peer_id, 0);
        assert_eq!((c.incoming_session, c.outgoing_session), (0xFF, 0xFF));
        // Moonlight's fork defaults the MTU to 900, not upstream's 1392.
        assert_eq!(c.mtu, 900);
        assert_eq!(c.window_size, MAXIMUM_WINDOW_SIZE);
        // `CTRL_CHANNEL_COUNT`.
        assert_eq!(c.channel_count, 0x30);
        assert_eq!(c.packet_throttle_interval, 5000);
        assert_eq!(c.data, 0xb49654be);
    }

    #[test]
    fn a_datagram_round_trips_byte_for_byte() {
        let datagram = unhex(CAPTURED_CONNECT);
        let (header, body) = Header::parse(&datagram).unwrap();
        let mut out = Vec::new();
        header.write(&mut out);
        for cmd in commands(body) {
            let cmd = cmd.unwrap();
            let before = out.len();
            cmd.write(&mut out);
            assert_eq!(out.len() - before, cmd.wire_len());
        }
        assert_eq!(out, datagram);
    }

    #[test]
    fn every_command_round_trips() {
        let frag = Fragment {
            start_sequence: 3,
            fragment_count: 2,
            fragment_number: 1,
            total_length: 9,
            fragment_offset: 4,
            data: b"tail!",
        };
        let bodies = [
            Body::Acknowledge {
                received_reliable_sequence: 7,
                received_sent_time: 0xbeef,
            },
            Body::Disconnect { data: 9 },
            Body::Ping,
            Body::SendReliable { data: b"hello" },
            Body::SendUnreliable {
                unreliable_sequence: 4,
                data: b"",
            },
            Body::SendUnsequenced {
                unsequenced_group: 0xffff,
                data: b"x",
            },
            Body::SendFragment(frag),
            Body::SendUnreliableFragment(frag),
            Body::BandwidthLimit {
                incoming: 1,
                outgoing: 2,
            },
            Body::ThrottleConfigure {
                interval: 1,
                acceleration: 2,
                deceleration: 3,
            },
        ];
        let numbers = [1, 4, 5, 6, 7, 9, 8, 12, 10, 11];
        let mut datagram = Vec::new();
        let mut expected = Vec::new();
        for (body, number) in bodies.into_iter().zip(numbers) {
            let cmd = Command {
                header: CommandHeader {
                    command: number,
                    channel: 1,
                    reliable_sequence: 42,
                },
                body,
            };
            cmd.write(&mut datagram);
            expected.push(cmd);
        }
        let parsed: Vec<_> = commands(&datagram).collect::<Result<_>>().unwrap();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn a_header_alone_is_not_a_datagram_but_parses() {
        let (h, body) = Header::parse(&[0x00, 0x00]).unwrap();
        assert_eq!(h.sent_time, None);
        assert!(body.is_empty());
        assert!(Header::parse(&[0x80]).is_err());
        // A sent-time flag promises two more bytes.
        assert!(Header::parse(&[0x80, 0x00, 0x01]).is_err());
    }

    #[test]
    fn every_truncation_of_every_command_is_an_error_not_a_panic() {
        let mut datagram = Vec::new();
        Command {
            header: CommandHeader {
                command: command::SEND_RELIABLE | FLAG_ACKNOWLEDGE,
                channel: 0,
                reliable_sequence: 1,
            },
            body: Body::SendReliable { data: b"payload" },
        }
        .write(&mut datagram);
        datagram.extend_from_slice(&unhex(CAPTURED_CONNECT)[4..]);
        for cut in 0..datagram.len() {
            let results: Vec<_> = commands(&datagram[..cut]).collect();
            if cut == 0 {
                assert!(results.is_empty());
            } else {
                // Whatever parsed, the last item of a cut datagram is an error
                // -- unless the cut fell exactly between the two commands.
                let complete = cut == 13;
                assert_eq!(results.last().unwrap().is_err(), !complete, "cut {cut}");
            }
        }
    }

    #[test]
    fn a_payload_length_that_overruns_is_refused() {
        let datagram = [command::SEND_RELIABLE, 0, 0, 1, 0x00, 0x10, b'a'];
        let err = commands(&datagram).next().unwrap().unwrap_err();
        assert_eq!(
            err,
            WireError::LengthOverrun {
                claimed: 16,
                available: 1
            }
        );
    }

    #[test]
    fn unknown_command_numbers_stop_the_walk() {
        for number in [0u8, 13, 14, 15] {
            let datagram = [number, 0, 0, 0, 0, 0, 0, 0];
            let mut it = commands(&datagram);
            assert!(it.next().unwrap().is_err(), "{number}");
            assert!(it.next().is_none());
        }
    }
}
