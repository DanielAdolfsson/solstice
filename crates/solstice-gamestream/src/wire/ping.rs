//! `SS_PING` -- how the host learns the client's UDP source address.
//!
//! The payload is the 16 ASCII hex characters minted at `/launch`
//! (`nvhttp.cpp:534`). The legacy form, a literal `"PING"` matched by source
//! address alone, is **not implemented**: `docs/security.md` §2.3 calls it out
//! as trivially spoofable and says so explicitly.

use super::{Reader, Result, WireError};

/// Length of the hex-encoded ping payload.
pub const PING_PAYLOAD_LEN: usize = 16;
/// Size of a well-formed `SS_PING` on the wire.
pub const PING_LEN: usize = PING_PAYLOAD_LEN + 4;

/// A parsed ping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ping {
    /// The 16 hex characters the client was given at launch.
    pub payload: [u8; PING_PAYLOAD_LEN],
    /// Monotonic sequence number, big-endian on the wire.
    pub sequence_number: u32,
}

impl Ping {
    /// Parse a ping datagram.
    ///
    /// Rejects the 4-byte legacy `"PING"` form outright.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf == b"PING" {
            return Err(WireError::InvalidField {
                field: "legacy PING",
                value: 0,
            });
        }
        let mut r = Reader::new(buf);
        Ok(Self {
            payload: r.take_array()?,
            sequence_number: r.u32be()?,
        })
    }

    /// Serialise, for the test client.
    pub fn to_bytes(&self) -> [u8; PING_LEN] {
        let mut out = [0u8; PING_LEN];
        out[..PING_PAYLOAD_LEN].copy_from_slice(&self.payload);
        out[PING_PAYLOAD_LEN..].copy_from_slice(&self.sequence_number.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let p = Ping {
            payload: *b"0123456789abcdef",
            sequence_number: 7,
        };
        assert_eq!(Ping::parse(&p.to_bytes()).unwrap(), p);
    }

    #[test]
    fn legacy_ping_is_refused() {
        assert!(Ping::parse(b"PING").is_err());
    }

    #[test]
    fn short_ping_is_refused() {
        assert!(Ping::parse(b"0123456789abcde").is_err());
    }
}
