//! The audio datagram layout (`stream.cpp:1872-1920`, `RtpAudioQueue.h`).
//!
//! Opus in RTP with payload type 97, and a fixed RS(4,2) parity pair every four
//! packets carried as payload type 127 behind an [`AudioFecHeader`].

use super::{Reader, Result};

/// Data shards per audio FEC block.
pub const AUDIO_DATA_SHARDS: usize = 4;
/// Parity shards per audio FEC block.
pub const AUDIO_PARITY_SHARDS: usize = 2;
/// Size of `AUDIO_FEC_HEADER`.
pub const AUDIO_FEC_HEADER_LEN: usize = 12;

/// Header on an audio parity packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AudioFecHeader {
    /// 0 or 1 -- which parity shard this is.
    pub fec_shard_index: u8,
    /// The payload type of the data shards being protected (97).
    pub payload_type: u8,
    /// Sequence number of the first data shard in the block.
    pub base_sequence_number: u16,
    /// Timestamp of the first data shard in the block.
    pub base_timestamp: u32,
    /// Always zero.
    pub ssrc: u32,
}

impl AudioFecHeader {
    /// Serialise into exactly [`AUDIO_FEC_HEADER_LEN`] bytes.
    pub fn write(&self, out: &mut [u8]) {
        assert!(out.len() >= AUDIO_FEC_HEADER_LEN);
        out[0] = self.fec_shard_index;
        out[1] = self.payload_type;
        out[2..4].copy_from_slice(&self.base_sequence_number.to_be_bytes());
        out[4..8].copy_from_slice(&self.base_timestamp.to_be_bytes());
        out[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
    }

    /// Parse.
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            fec_shard_index: r.u8()?,
            payload_type: r.u8()?,
            base_sequence_number: r.u16be()?,
            base_timestamp: r.u32be()?,
            ssrc: r.u32be()?,
        })
    }
}

/// Build the AES-128-CBC IV for an audio packet.
///
/// Sixteen zero bytes with `BE32(rikeyid + sequence_number)` written over bytes
/// 0..4 (`stream.cpp:1899`). `rikeyid` is signed and the addition is allowed to
/// wrap, so this uses wrapping arithmetic deliberately.
pub fn audio_iv(rikey_id: i32, sequence_number: u32) -> [u8; 16] {
    let mut iv = [0u8; 16];
    let value = (rikey_id as i64 + sequence_number as i64) as i32;
    iv[..4].copy_from_slice(&value.to_be_bytes());
    iv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fec_header_round_trips() {
        let h = AudioFecHeader {
            fec_shard_index: 1,
            payload_type: 97,
            base_sequence_number: 0x0102,
            base_timestamp: 0x0A0B0C0D,
            ssrc: 0,
        };
        let mut buf = [0u8; AUDIO_FEC_HEADER_LEN];
        h.write(&mut buf);
        assert_eq!(&buf[2..4], &[0x01, 0x02]);
        assert_eq!(AudioFecHeader::parse(&mut Reader::new(&buf)).unwrap(), h);
    }

    #[test]
    fn audio_iv_counts_from_rikeyid() {
        assert_eq!(audio_iv(0, 0), [0u8; 16]);
        let iv = audio_iv(0x1000, 5);
        assert_eq!(&iv[..4], &0x1005u32.to_be_bytes());
        assert_eq!(&iv[4..], &[0u8; 12]);
        // Successive packets must never share an IV under one key.
        assert_ne!(audio_iv(7, 1), audio_iv(7, 2));
    }

    #[test]
    fn audio_iv_tolerates_a_negative_rikeyid() {
        // rikeyid arrives as a signed int in the launch query string and may
        // legitimately be negative; the sum is allowed to wrap.
        let iv = audio_iv(-1, 1);
        assert_eq!(&iv[..4], &0u32.to_be_bytes());
    }
}
