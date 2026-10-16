//! `RTP_PACKET` -- the 12-byte header in front of every video and audio
//! datagram (`Video.h`).

use super::{Reader, Result};

/// Size on the wire.
pub const RTP_HEADER_LEN: usize = 12;

/// `0x80 | FLAG_EXTENSION` -- what the video stream sets.
pub const VIDEO_HEADER: u8 = 0x90;
/// Plain RTP version 2, no extension -- what the audio stream sets.
pub const AUDIO_HEADER: u8 = 0x80;
/// Payload type for Opus audio.
pub const AUDIO_PAYLOAD_TYPE: u8 = 97;
/// Payload type for an audio FEC shard.
pub const AUDIO_FEC_PAYLOAD_TYPE: u8 = 127;

/// The RTP header as Moonlight uses it: fixed SSRC, a 90 kHz timestamp on
/// video, and a sequence number that is only the low 16 bits of a wider
/// counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RtpHeader {
    /// Version/flags byte.
    pub header: u8,
    /// Payload type, 0 on video.
    pub packet_type: u8,
    /// Low 16 bits of the stream's packet counter.
    pub sequence_number: u16,
    /// 90 kHz on video; `packetDuration` units on audio.
    pub timestamp: u32,
    /// Always zero in this protocol.
    pub ssrc: u32,
}

impl RtpHeader {
    /// A video header with the flags Sunshine sets.
    pub const fn video(sequence_number: u16, timestamp: u32) -> Self {
        Self {
            header: VIDEO_HEADER,
            packet_type: 0,
            sequence_number,
            timestamp,
            ssrc: 0,
        }
    }

    /// An audio header.
    pub const fn audio(payload_type: u8, sequence_number: u16, timestamp: u32) -> Self {
        Self {
            header: AUDIO_HEADER,
            packet_type: payload_type,
            sequence_number,
            timestamp,
            ssrc: 0,
        }
    }

    /// Serialise into exactly [`RTP_HEADER_LEN`] bytes.
    pub fn write(&self, out: &mut [u8]) {
        assert!(out.len() >= RTP_HEADER_LEN);
        out[0] = self.header;
        out[1] = self.packet_type;
        out[2..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        out[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        out[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
    }

    /// Overwrite only the three fields Sunshine patches into a video shard
    /// after Reed-Solomon (`stream.cpp:1752-1754`).
    ///
    /// `packetType`, `ssrc` and the four reserved bytes that follow are left
    /// alone on purpose: in a parity shard they hold parity, and rewriting
    /// them would take that parity out of the recovery.
    pub fn patch_video_after_fec(out: &mut [u8], sequence_number: u16, timestamp: u32) {
        assert!(out.len() >= RTP_HEADER_LEN);
        out[0] = VIDEO_HEADER;
        out[2..4].copy_from_slice(&sequence_number.to_be_bytes());
        out[4..8].copy_from_slice(&timestamp.to_be_bytes());
    }

    /// Serialise to a fresh array.
    pub fn to_bytes(&self) -> [u8; RTP_HEADER_LEN] {
        let mut out = [0u8; RTP_HEADER_LEN];
        self.write(&mut out);
        out
    }

    /// Parse.
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            header: r.u8()?,
            packet_type: r.u8()?,
            sequence_number: r.u16be()?,
            timestamp: r.u32be()?,
            ssrc: r.u32be()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let h = RtpHeader::video(0xBEEF, 90_000);
        let bytes = h.to_bytes();
        assert_eq!(bytes[0], 0x90);
        assert_eq!(&bytes[2..4], &[0xBE, 0xEF]);
        assert_eq!(RtpHeader::parse(&mut Reader::new(&bytes)).unwrap(), h);
    }

    #[test]
    fn truncated_header_is_an_error_not_a_panic() {
        assert!(RtpHeader::parse(&mut Reader::new(&[0x90, 0, 0])).is_err());
    }
}
