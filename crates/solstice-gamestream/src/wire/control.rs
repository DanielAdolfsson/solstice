//! The ENet control channel's framing (`ControlStream.c:25-32`,
//! `stream.cpp:245-305`).
//!
//! Two layers. The inner one is `NVCTL_ENET_PACKET_HEADER_V2`: a type and a
//! length. The outer one, used whenever the client negotiated
//! `useReliableUdp == 13`, wraps that in AES-128-GCM.

use super::{Reader, Result, WireError};

/// Size of the inner `NVCTL_ENET_PACKET_HEADER_V2`.
pub const V2_HEADER_LEN: usize = 4;
/// Size of `NVCTL_ENCRYPTED_PACKET_HEADER` before the tag.
pub const ENCRYPTED_HEADER_LEN: usize = 8;
/// The only value `encryptedHeaderType` ever takes.
pub const ENCRYPTED_HEADER_TYPE: u16 = 0x0001;
/// GCM tag length.
pub const TAG_LEN: usize = 16;

/// Control message types for protocol generation 7 (`ControlStream.c:203-217`).
pub mod msg {
    #![allow(missing_docs)]
    pub const REQUEST_IDR_FRAME: u16 = 0x0302;
    pub const START_B: u16 = 0x0307;
    pub const INVALIDATE_REF_FRAMES: u16 = 0x0301;
    pub const LOSS_STATS: u16 = 0x0201;
    pub const FRAME_STATS: u16 = 0x0204;
    pub const INPUT_DATA: u16 = 0x0206;
    pub const RUMBLE: u16 = 0x010b;
    pub const TERMINATION: u16 = 0x0109;
    pub const HDR_MODE: u16 = 0x010e;
    pub const RUMBLE_TRIGGERS: u16 = 0x5500;
    pub const SET_MOTION_EVENT: u16 = 0x5501;
    pub const SET_RGB_LED: u16 = 0x5502;
    pub const SET_ADAPTIVE_TRIGGERS: u16 = 0x5503;
    pub const LTR_FRAME_ACK: u16 = 0x0350;
}

/// Who sent a control message. The byte lands in `iv[10]` and is what keeps the
/// two directions' deterministic IVs from colliding under one key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Client-originated: `iv[10] = b'C'`.
    Client,
    /// Host-originated: `iv[10] = b'H'`.
    Host,
}

impl Origin {
    const fn tag_byte(self) -> u8 {
        match self {
            Origin::Client => b'C',
            Origin::Host => b'H',
        }
    }
}

/// Build the 12-byte control IV (`ControlStream.c:548-580`).
pub fn control_iv(sequence: u32, origin: Origin) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[..4].copy_from_slice(&sequence.to_le_bytes());
    iv[10] = origin.tag_byte();
    iv[11] = b'C';
    iv
}

/// The inner, plaintext control header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V2Header {
    /// One of [`msg`].
    pub msg_type: u16,
    /// Length of the payload that follows.
    pub payload_length: u16,
}

impl V2Header {
    /// Serialise.
    pub fn to_bytes(&self) -> [u8; V2_HEADER_LEN] {
        let mut out = [0u8; V2_HEADER_LEN];
        out[0..2].copy_from_slice(&self.msg_type.to_le_bytes());
        out[2..4].copy_from_slice(&self.payload_length.to_le_bytes());
        out
    }

    /// Parse a header and the payload it claims, rejecting a length that
    /// overruns the buffer.
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8])> {
        let mut r = Reader::new(buf);
        let header = Self {
            msg_type: r.u16le()?,
            payload_length: r.u16le()?,
        };
        let claimed = header.payload_length as usize;
        if r.remaining() < claimed {
            return Err(WireError::LengthOverrun {
                claimed,
                available: r.remaining(),
            });
        }
        Ok((header, r.take(claimed)?))
    }
}

/// The outer, encrypted control envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptedHeader {
    /// Always [`ENCRYPTED_HEADER_TYPE`].
    pub header_type: u16,
    /// `sizeof(seq) + TAG_LEN + ciphertext`.
    pub length: u16,
    /// Feeds the IV.
    pub sequence: u32,
}

/// A parsed encrypted control packet: its header, GCM tag and ciphertext.
#[derive(Clone, Copy, Debug)]
pub struct EncryptedPacket<'a> {
    /// The envelope header.
    pub header: EncryptedHeader,
    /// The authentication tag.
    pub tag: &'a [u8; TAG_LEN],
    /// The ciphertext of `{V2 header || payload}`.
    pub ciphertext: &'a [u8],
}

impl EncryptedHeader {
    /// Serialise the header alone.
    pub fn to_bytes(&self) -> [u8; ENCRYPTED_HEADER_LEN] {
        let mut out = [0u8; ENCRYPTED_HEADER_LEN];
        out[0..2].copy_from_slice(&self.header_type.to_le_bytes());
        out[2..4].copy_from_slice(&self.length.to_le_bytes());
        out[4..8].copy_from_slice(&self.sequence.to_le_bytes());
        out
    }
}

impl<'a> EncryptedPacket<'a> {
    /// Parse an encrypted control packet.
    ///
    /// This is the shape of GHSA-c428-87f8-rrv5 -- an unauthenticated
    /// short-packet DoS -- so every field is checked against what is actually
    /// present before it is used.
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        let header_type = r.u16le()?;
        if header_type != ENCRYPTED_HEADER_TYPE {
            return Err(WireError::InvalidField {
                field: "encryptedHeaderType",
                value: header_type as u64,
            });
        }
        let length = r.u16le()?;
        let sequence = r.u32le()?;
        // `length` counts the sequence number and the tag as well as the body.
        let body_len =
            (length as usize)
                .checked_sub(4 + TAG_LEN)
                .ok_or(WireError::InvalidField {
                    field: "length",
                    value: length as u64,
                })?;
        let tag: &[u8; TAG_LEN] = r
            .take(TAG_LEN)?
            .try_into()
            .expect("take returned the requested length");
        if r.remaining() < body_len {
            return Err(WireError::LengthOverrun {
                claimed: body_len,
                available: r.remaining(),
            });
        }
        Ok(Self {
            header: EncryptedHeader {
                header_type,
                length,
                sequence,
            },
            tag,
            ciphertext: r.take(body_len)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_iv_separates_the_two_directions() {
        let c = control_iv(1, Origin::Client);
        let h = control_iv(1, Origin::Host);
        assert_ne!(c, h);
        assert_eq!(c[10], b'C');
        assert_eq!(h[10], b'H');
        assert_eq!(c[11], b'C');
        assert_eq!(&c[..4], &1u32.to_le_bytes());
    }

    #[test]
    fn v2_header_round_trips() {
        let h = V2Header {
            msg_type: msg::INPUT_DATA,
            payload_length: 3,
        };
        let mut buf = h.to_bytes().to_vec();
        buf.extend_from_slice(&[1, 2, 3]);
        let (parsed, payload) = V2Header::parse(&buf).unwrap();
        assert_eq!(parsed, h);
        assert_eq!(payload, &[1, 2, 3]);
    }

    #[test]
    fn v2_header_rejects_a_length_that_overruns() {
        let mut buf = V2Header {
            msg_type: msg::INPUT_DATA,
            payload_length: 64,
        }
        .to_bytes()
        .to_vec();
        buf.extend_from_slice(&[1, 2, 3]);
        assert_eq!(
            V2Header::parse(&buf).unwrap_err(),
            WireError::LengthOverrun {
                claimed: 64,
                available: 3
            }
        );
    }

    #[test]
    fn encrypted_packet_round_trips() {
        let body = [0xABu8; 7];
        let header = EncryptedHeader {
            header_type: ENCRYPTED_HEADER_TYPE,
            length: (4 + TAG_LEN + body.len()) as u16,
            sequence: 9,
        };
        let mut buf = header.to_bytes().to_vec();
        buf.extend_from_slice(&[0x5A; TAG_LEN]);
        buf.extend_from_slice(&body);
        let p = EncryptedPacket::parse(&buf).unwrap();
        assert_eq!(p.header, header);
        assert_eq!(p.tag, &[0x5A; TAG_LEN]);
        assert_eq!(p.ciphertext, &body);
    }

    /// GHSA-c428-87f8-rrv5: a short ENet control packet must be an error, not
    /// an out-of-bounds read.
    #[test]
    fn short_encrypted_packets_are_rejected_at_every_prefix() {
        let body = [0xABu8; 7];
        let header = EncryptedHeader {
            header_type: ENCRYPTED_HEADER_TYPE,
            length: (4 + TAG_LEN + body.len()) as u16,
            sequence: 9,
        };
        let mut full = header.to_bytes().to_vec();
        full.extend_from_slice(&[0x5A; TAG_LEN]);
        full.extend_from_slice(&body);
        for n in 0..full.len() {
            assert!(
                EncryptedPacket::parse(&full[..n]).is_err(),
                "prefix of {n} bytes accepted"
            );
        }
        assert!(EncryptedPacket::parse(&full).is_ok());
    }

    #[test]
    fn encrypted_packet_rejects_an_undersized_length_field() {
        let mut buf = EncryptedHeader {
            header_type: ENCRYPTED_HEADER_TYPE,
            length: 3,
            sequence: 0,
        }
        .to_bytes()
        .to_vec();
        buf.extend_from_slice(&[0u8; 64]);
        // length < sizeof(seq) + tag would underflow a naive subtraction.
        assert!(EncryptedPacket::parse(&buf).is_err());
    }

    #[test]
    fn encrypted_packet_rejects_a_foreign_header_type() {
        let mut buf = EncryptedHeader {
            header_type: 2,
            length: 20,
            sequence: 0,
        }
        .to_bytes()
        .to_vec();
        buf.extend_from_slice(&[0u8; 64]);
        assert!(EncryptedPacket::parse(&buf).is_err());
    }
}
