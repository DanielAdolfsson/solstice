//! The video datagram layout (`stream.cpp:1560-1860`, `Video.h`).
//!
//! ```text
//! [ video_packet_enc_prefix (32 B) ]   only when SS_ENC_VIDEO
//!   RTP_PACKET                (12 B)
//!   reserved                  ( 4 B)
//!   NV_VIDEO_PACKET           (16 B)
//!   payload
//! ```

use super::rtp::{RtpHeader, RTP_HEADER_LEN};
use super::{Reader, Result, WireError};

/// `RTP_PACKET` plus the 4 reserved bytes plus `NV_VIDEO_PACKET`.
pub const VIDEO_HEADER_LEN: usize = 32;
/// Size of `NV_VIDEO_PACKET` on its own.
pub const NV_VIDEO_PACKET_LEN: usize = 16;
/// Size of `video_short_frame_header_t`.
pub const FRAME_HEADER_LEN: usize = 8;
/// Size of `video_packet_enc_prefix_t`.
pub const ENC_PREFIX_LEN: usize = 32;

/// `NV_VIDEO_PACKET.flags`.
pub mod flags {
    #![allow(missing_docs)]
    pub const CONTAINS_PIC_DATA: u8 = 0x1;
    pub const EOF: u8 = 0x2;
    pub const SOF: u8 = 0x4;
}

/// Constant Sunshine always writes into `multiFecFlags`.
pub const MULTI_FEC_FLAGS: u8 = 0x10;

/// The per-shard NVIDIA header. All fields little-endian.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NvVideoPacket {
    /// `(lowseq + i) << 8`. 24 usable bits, which is why it is not just the
    /// RTP sequence number.
    pub stream_packet_index: u32,
    /// Monotonic frame counter.
    pub frame_index: u32,
    /// [`flags`].
    pub flags: u8,
    /// Bit 0 marks a long-term reference frame.
    pub extra_flags: u8,
    /// Always [`MULTI_FEC_FLAGS`].
    pub multi_fec_flags: u8,
    /// `(block_index << 4) | ((block_count - 1) << 6)`.
    pub multi_fec_blocks: u8,
    /// `(shard_index << 12) | (data_shards << 22) | (fec_percentage << 4)`.
    pub fec_info: u32,
}

impl NvVideoPacket {
    /// Pack `multiFecBlocks` from its two fields.
    pub const fn pack_multi_fec_blocks(block_index: u8, block_count: u8) -> u8 {
        (block_index << 4) | ((block_count - 1) << 6)
    }

    /// Unpack `multiFecBlocks` into `(block_index, block_count)`.
    pub const fn unpack_multi_fec_blocks(v: u8) -> (u8, u8) {
        (((v >> 4) & 0x3), ((v >> 6) & 0x3) + 1)
    }

    /// Pack `fecInfo` from its three fields.
    pub const fn pack_fec_info(shard_index: u32, data_shards: u32, fec_percentage: u32) -> u32 {
        (shard_index << 12) | (data_shards << 22) | (fec_percentage << 4)
    }

    /// Unpack `fecInfo` into `(shard_index, data_shards, fec_percentage)`.
    pub const fn unpack_fec_info(v: u32) -> (u32, u32, u32) {
        ((v >> 12) & 0x3FF, (v >> 22) & 0x3FF, (v >> 4) & 0xFF)
    }

    /// Serialise into exactly [`NV_VIDEO_PACKET_LEN`] bytes.
    pub fn write(&self, out: &mut [u8]) {
        assert!(out.len() >= NV_VIDEO_PACKET_LEN);
        out[0..4].copy_from_slice(&self.stream_packet_index.to_le_bytes());
        out[4..8].copy_from_slice(&self.frame_index.to_le_bytes());
        out[8] = self.flags;
        out[9] = self.extra_flags;
        out[10] = self.multi_fec_flags;
        out[11] = self.multi_fec_blocks;
        out[12..16].copy_from_slice(&self.fec_info.to_le_bytes());
    }

    /// Overwrite only the fields Sunshine patches *after* Reed-Solomon
    /// (`stream.cpp:1745-1759`).
    ///
    /// The split matters: anything written here is destroyed in the parity
    /// shards and therefore cannot be recovered, so the set has to match what
    /// the client re-derives for itself. `streamPacketIndex`, `flags`,
    /// `extraFlags` and `multiFecFlags` are deliberately absent -- the client
    /// asserts those come back out of the parity intact
    /// (`RtpVideoQueue.c:385-389`).
    pub fn patch_after_fec(out: &mut [u8], frame_index: u32, multi_fec_blocks: u8, fec_info: u32) {
        assert!(out.len() >= NV_VIDEO_PACKET_LEN);
        out[4..8].copy_from_slice(&frame_index.to_le_bytes());
        out[11] = multi_fec_blocks;
        out[12..16].copy_from_slice(&fec_info.to_le_bytes());
    }

    /// Parse.
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            stream_packet_index: r.u32le()?,
            frame_index: r.u32le()?,
            flags: r.u8()?,
            extra_flags: r.u8()?,
            multi_fec_flags: r.u8()?,
            multi_fec_blocks: r.u8()?,
            fec_info: r.u32le()?,
        })
    }
}

/// A whole video datagram, minus any encryption prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VideoPacketHeader {
    /// RTP header.
    pub rtp: RtpHeader,
    /// NVIDIA header.
    pub nv: NvVideoPacket,
}

impl VideoPacketHeader {
    /// Write the 32-byte header -- RTP, the four reserved bytes, then the NV
    /// header -- into `out`.
    pub fn write(&self, out: &mut [u8]) {
        assert!(out.len() >= VIDEO_HEADER_LEN);
        self.rtp.write(&mut out[..RTP_HEADER_LEN]);
        out[RTP_HEADER_LEN..RTP_HEADER_LEN + 4].fill(0);
        self.nv
            .write(&mut out[RTP_HEADER_LEN + 4..VIDEO_HEADER_LEN]);
    }

    /// Parse a datagram header, returning it with the payload that follows.
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8])> {
        let mut r = Reader::new(buf);
        let rtp = RtpHeader::parse(&mut r)?;
        r.skip(4)?;
        let nv = NvVideoPacket::parse(&mut r)?;
        Ok((Self { rtp, nv }, r.peek_rest()))
    }
}

/// `frameType` in [`FrameHeader`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Predicted frame.
    P = 1,
    /// Instantaneous decoder refresh.
    Idr = 2,
    /// Intra-refresh frame.
    IntraRefresh = 4,
    /// The frame after an intra-refresh cycle completes.
    PostRfi = 5,
}

/// `video_short_frame_header_t` -- 8 bytes in front of the first shard of each
/// frame (`stream.cpp:101-135`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// Processing latency in 1/10 ms; 0 when unknown.
    pub frame_processing_latency: u16,
    /// What kind of frame follows.
    pub frame_type: FrameType,
    /// Real length of the final shard's payload, since shards are zero-padded.
    pub last_payload_len: u16,
}

impl FrameHeader {
    /// Serialise into exactly [`FRAME_HEADER_LEN`] bytes.
    pub fn write(&self, out: &mut [u8]) {
        assert!(out.len() >= FRAME_HEADER_LEN);
        out[0] = 0x01; // headerType
        out[1..3].copy_from_slice(&self.frame_processing_latency.to_le_bytes());
        out[3] = self.frame_type as u8;
        out[4..6].copy_from_slice(&self.last_payload_len.to_le_bytes());
        out[6..8].fill(0);
    }

    /// Serialise to a fresh array.
    pub fn to_bytes(&self) -> [u8; FRAME_HEADER_LEN] {
        let mut out = [0u8; FRAME_HEADER_LEN];
        self.write(&mut out);
        out
    }

    /// Parse.
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let header_type = r.u8()?;
        if header_type != 0x01 {
            return Err(WireError::InvalidField {
                field: "frame headerType",
                value: header_type as u64,
            });
        }
        let frame_processing_latency = r.u16le()?;
        let ft = r.u8()?;
        let frame_type = match ft {
            1 => FrameType::P,
            2 => FrameType::Idr,
            4 => FrameType::IntraRefresh,
            5 => FrameType::PostRfi,
            other => {
                return Err(WireError::InvalidField {
                    field: "frameType",
                    value: other as u64,
                })
            }
        };
        let last_payload_len = r.u16le()?;
        r.skip(2)?;
        Ok(Self {
            frame_processing_latency,
            frame_type,
            last_payload_len,
        })
    }
}

/// `video_packet_enc_prefix_t` (`stream.cpp:1762-1781`).
///
/// The IV is a deterministic NIST SP 800-38D §8.2.1 construction: a 64-bit
/// little-endian counter in bytes 0..8 with `iv[11] = b'V'` as the fixed field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncPrefix {
    /// GCM nonce.
    pub iv: [u8; 12],
    /// The frame this shard belongs to.
    pub frame_number: u32,
    /// GCM authentication tag.
    pub tag: [u8; 16],
}

impl EncPrefix {
    /// Build the deterministic IV for `counter`.
    pub fn iv_for(counter: u64) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv[..8].copy_from_slice(&counter.to_le_bytes());
        iv[11] = b'V';
        iv
    }

    /// Serialise into exactly [`ENC_PREFIX_LEN`] bytes.
    pub fn write(&self, out: &mut [u8]) {
        assert!(out.len() >= ENC_PREFIX_LEN);
        out[..12].copy_from_slice(&self.iv);
        out[12..16].copy_from_slice(&self.frame_number.to_le_bytes());
        out[16..32].copy_from_slice(&self.tag);
    }

    /// Parse, returning the prefix and the ciphertext that follows.
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8])> {
        let mut r = Reader::new(buf);
        let iv = r.take_array()?;
        let frame_number = r.u32le()?;
        let tag = r.take_array()?;
        Ok((
            Self {
                iv,
                frame_number,
                tag,
            },
            r.peek_rest(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fec_info_round_trips_at_the_field_limits() {
        for (shard, data, pct) in [(0, 1, 0), (254, 212, 20), (1023, 1023, 255)] {
            let packed = NvVideoPacket::pack_fec_info(shard, data, pct);
            assert_eq!(NvVideoPacket::unpack_fec_info(packed), (shard, data, pct));
        }
    }

    #[test]
    fn multi_fec_blocks_round_trips() {
        for block_count in 1..=4u8 {
            for block_index in 0..block_count {
                let packed = NvVideoPacket::pack_multi_fec_blocks(block_index, block_count);
                assert_eq!(
                    NvVideoPacket::unpack_multi_fec_blocks(packed),
                    (block_index, block_count)
                );
            }
        }
    }

    #[test]
    fn header_round_trips_through_bytes() {
        let h = VideoPacketHeader {
            rtp: RtpHeader::video(0x1234, 90_000),
            nv: NvVideoPacket {
                stream_packet_index: 0x1234 << 8,
                frame_index: 42,
                flags: flags::CONTAINS_PIC_DATA | flags::SOF,
                extra_flags: 0,
                multi_fec_flags: MULTI_FEC_FLAGS,
                multi_fec_blocks: NvVideoPacket::pack_multi_fec_blocks(0, 1),
                fec_info: NvVideoPacket::pack_fec_info(0, 10, 20),
            },
        };
        let mut buf = vec![0u8; VIDEO_HEADER_LEN + 3];
        h.write(&mut buf);
        buf[VIDEO_HEADER_LEN..].copy_from_slice(&[9, 9, 9]);
        let (parsed, payload) = VideoPacketHeader::parse(&buf).unwrap();
        assert_eq!(parsed, h);
        assert_eq!(payload, &[9, 9, 9]);
        // The four bytes between the RTP and NV headers are reserved and zero.
        assert_eq!(&buf[12..16], &[0, 0, 0, 0]);
    }

    #[test]
    fn frame_header_round_trips() {
        let fh = FrameHeader {
            frame_processing_latency: 123,
            frame_type: FrameType::Idr,
            last_payload_len: 900,
        };
        let bytes = fh.to_bytes();
        assert_eq!(bytes[0], 0x01);
        assert_eq!(FrameHeader::parse(&mut Reader::new(&bytes)).unwrap(), fh);
    }

    #[test]
    fn frame_header_rejects_foreign_header_type() {
        let mut bytes = FrameHeader {
            frame_processing_latency: 0,
            frame_type: FrameType::P,
            last_payload_len: 1,
        }
        .to_bytes();
        bytes[0] = 0x02;
        assert!(FrameHeader::parse(&mut Reader::new(&bytes)).is_err());
    }

    #[test]
    fn video_iv_is_the_documented_deterministic_construction() {
        let iv = EncPrefix::iv_for(0x0102_0304_0506_0708);
        assert_eq!(&iv[..8], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&iv[8..], &[0, 0, 0, b'V']);
        // Distinct counters must give distinct nonces: the whole safety of the
        // deterministic construction rests on it.
        assert_ne!(EncPrefix::iv_for(1), EncPrefix::iv_for(2));
    }

    #[test]
    fn enc_prefix_round_trips() {
        let p = EncPrefix {
            iv: EncPrefix::iv_for(9),
            frame_number: 5,
            tag: [0xAB; 16],
        };
        let mut buf = vec![0u8; ENC_PREFIX_LEN + 2];
        p.write(&mut buf);
        buf[ENC_PREFIX_LEN..].copy_from_slice(&[1, 2]);
        let (parsed, rest) = EncPrefix::parse(&buf).unwrap();
        assert_eq!(parsed, p);
        assert_eq!(rest, &[1, 2]);
    }
}
