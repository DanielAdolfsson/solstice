//! Opus packets to UDP 48000 (`stream.cpp:1872-1920`).
//!
//! ```text
//! Opus packet -> RTP(pt 97) -> [AES-128-CBC] -> UDP
//!                           -> RS(4,2) parity pair every four packets (pt 127)
//! ```
//!
//! The RFB backend has no audio at all, so in practice this sends Opus silence
//! at the negotiated packet duration -- cheap, and it keeps the client out of
//! its "no audio stream" edge cases (`docs/bridging-design.md` §3).

use crate::crypto::gcm::cbc_encrypt;
use crate::wire::audio::{audio_iv, AudioFecHeader, AUDIO_DATA_SHARDS, AUDIO_FEC_HEADER_LEN};
use crate::wire::rtp::{RtpHeader, AUDIO_FEC_PAYLOAD_TYPE, AUDIO_PAYLOAD_TYPE, RTP_HEADER_LEN};

use super::fec::Rs;

/// Configuration for one session's audio channel.
#[derive(Clone, Copy, Debug)]
pub struct AudioConfig {
    /// `x-nv-aqos.packetDuration`, milliseconds per Opus packet.
    pub packet_duration_ms: u32,
    /// Whether `SS_ENC_AUDIO` was negotiated.
    pub encrypt: bool,
    /// The signed `rikeyid` from `/launch`, which seeds the CBC IV.
    pub rikey_id: i32,
}

impl Default for AudioConfig {
    fn default() -> Self {
        Self {
            packet_duration_ms: 5,
            encrypt: true,
            rikey_id: 0,
        }
    }
}

/// Turns Opus packets into datagrams, with parity every four.
#[derive(Debug)]
pub struct AudioPacketizer {
    config: AudioConfig,
    key: Option<[u8; 16]>,
    sequence: u16,
    timestamp: u32,
    /// The payloads of the block currently being filled: what follows each
    /// data packet's RTP header, as sent. Padded to a common length when the
    /// parity is computed, because RS needs equal shards.
    block: Vec<Vec<u8>>,
    block_base_sequence: u16,
    block_base_timestamp: u32,
}

impl AudioPacketizer {
    /// Build one. `key` is the `rikey`, required when `config.encrypt` is set.
    pub fn new(config: AudioConfig, key: Option<&[u8; 16]>) -> Self {
        Self {
            config,
            key: key.copied().filter(|_| config.encrypt),
            sequence: 0,
            timestamp: 0,
            block: Vec::with_capacity(AUDIO_DATA_SHARDS),
            block_base_sequence: 0,
            block_base_timestamp: 0,
        }
    }

    /// Packets emitted so far, parity included.
    pub fn sequence(&self) -> u16 {
        self.sequence
    }

    /// Packetise one Opus packet, returning the datagrams to send.
    ///
    /// Every fourth call also emits the block's two parity packets.
    pub fn packetize(&mut self, opus: &[u8]) -> Vec<Vec<u8>> {
        if self.block.is_empty() {
            self.block_base_sequence = self.sequence;
            self.block_base_timestamp = self.timestamp;
        }

        let rtp = RtpHeader::audio(AUDIO_PAYLOAD_TYPE, self.sequence, self.timestamp);
        let mut datagram = Vec::with_capacity(RTP_HEADER_LEN + opus.len() + 16);
        datagram.extend_from_slice(&rtp.to_bytes());
        match &self.key {
            Some(key) => {
                let iv = audio_iv(self.config.rikey_id, self.sequence as u32);
                datagram.extend_from_slice(&cbc_encrypt(key, &iv, opus));
            }
            None => datagram.extend_from_slice(opus),
        }

        // Parity protects the payload as sent, not the RTP header. The client
        // takes a data shard to be everything after the header
        // (`RtpAudioQueue.c`, `completeFecBlock`: `dataPackets[i] + 1`),
        // rebuilds a recovered packet's header from the FEC header, and
        // requires a parity shard to be exactly a data payload long. Parity
        // over the whole datagram was 12 bytes too long, so the first time a
        // client needed it, it switched audio FEC off for the session instead.
        self.block.push(datagram[RTP_HEADER_LEN..].to_vec());
        self.sequence = self.sequence.wrapping_add(1);
        self.timestamp = self.timestamp.wrapping_add(self.config.packet_duration_ms);

        let mut out = vec![datagram];
        if self.block.len() == AUDIO_DATA_SHARDS {
            out.extend(self.flush_parity());
        }
        out
    }

    fn flush_parity(&mut self) -> Vec<Vec<u8>> {
        let shard_len = self.block.iter().map(|s| s.len()).max().unwrap_or(0);
        let padded: Vec<Vec<u8>> = self
            .block
            .iter()
            .map(|s| {
                let mut v = s.clone();
                v.resize(shard_len, 0);
                v
            })
            .collect();
        let refs: Vec<&[u8]> = padded.iter().map(|s| s.as_slice()).collect();
        let parity = Rs::audio()
            .encode(&refs)
            .expect("RS(4,2) over four equal shards");
        self.block.clear();

        // The parity shards borrow the next two sequence numbers but do not
        // consume them: Sunshine increments the audio sequence once per *data*
        // packet and nothing else (`stream.cpp:1913`), so the data numbering
        // stays contiguous and every FEC block begins on a multiple of four.
        // The client requires exactly that and switches FEC off for the whole
        // session when it does not hold (`RtpAudioQueue.c:269-280`). A parity
        // packet is told apart by its payload type, not its sequence number.

        parity
            .into_iter()
            .enumerate()
            .map(|(j, shard)| {
                let rtp = RtpHeader::audio(
                    AUDIO_FEC_PAYLOAD_TYPE,
                    self.block_base_sequence
                        .wrapping_add(AUDIO_DATA_SHARDS as u16 + j as u16),
                    self.block_base_timestamp,
                );
                let fec = AudioFecHeader {
                    fec_shard_index: j as u8,
                    payload_type: AUDIO_PAYLOAD_TYPE,
                    base_sequence_number: self.block_base_sequence,
                    base_timestamp: self.block_base_timestamp,
                    ssrc: 0,
                };
                let mut out =
                    Vec::with_capacity(RTP_HEADER_LEN + AUDIO_FEC_HEADER_LEN + shard.len());
                out.extend_from_slice(&rtp.to_bytes());
                out.resize(RTP_HEADER_LEN + AUDIO_FEC_HEADER_LEN, 0);
                fec.write(&mut out[RTP_HEADER_LEN..]);
                out.extend_from_slice(&shard);
                out
            })
            .collect()
    }
}

/// A valid Opus frame encoding digital silence.
///
/// This is the standard "no audio" packet: TOC byte selecting SILK/CELT
/// depending on the configuration, with an empty frame body. The RFB backend
/// has nothing else to send, and sending nothing at all drives some clients
/// into their missing-stream paths.
pub fn opus_silence_packet(channels: u8) -> Vec<u8> {
    // TOC: config 29 (CELT, 20 ms, fullband), stereo bit, code 0 (one frame).
    let stereo = if channels >= 2 { 0x04 } else { 0x00 };
    vec![0xF8 | stereo, 0xFF, 0xFE]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::gcm::cbc_decrypt;
    use crate::wire::Reader;

    fn parse_rtp(packet: &[u8]) -> RtpHeader {
        RtpHeader::parse(&mut Reader::new(packet)).unwrap()
    }

    #[test]
    fn packets_carry_payload_type_97_and_advance_the_clock() {
        let mut p = AudioPacketizer::new(
            AudioConfig {
                encrypt: false,
                packet_duration_ms: 5,
                rikey_id: 0,
            },
            None,
        );
        for i in 0..3u16 {
            let out = p.packetize(b"opus");
            assert_eq!(out.len(), 1);
            let rtp = parse_rtp(&out[0]);
            assert_eq!(rtp.header, 0x80);
            assert_eq!(rtp.packet_type, AUDIO_PAYLOAD_TYPE);
            assert_eq!(rtp.sequence_number, i);
            assert_eq!(rtp.timestamp, i as u32 * 5);
            assert_eq!(&out[0][RTP_HEADER_LEN..], b"opus");
        }
    }

    #[test]
    fn every_fourth_packet_emits_two_parity_shards() {
        let mut p = AudioPacketizer::new(
            AudioConfig {
                encrypt: false,
                ..Default::default()
            },
            None,
        );
        let mut emitted = 0;
        for i in 0..8 {
            let out = p.packetize(b"opus-packet");
            emitted += out.len();
            if i % 4 == 3 {
                assert_eq!(out.len(), 3, "packet {i} should carry the parity pair");
                for (j, parity) in out[1..].iter().enumerate() {
                    let rtp = parse_rtp(parity);
                    assert_eq!(rtp.packet_type, AUDIO_FEC_PAYLOAD_TYPE);
                    let fec =
                        AudioFecHeader::parse(&mut Reader::new(&parity[RTP_HEADER_LEN..])).unwrap();
                    assert_eq!(fec.fec_shard_index, j as u8);
                    assert_eq!(fec.payload_type, AUDIO_PAYLOAD_TYPE);
                    assert_eq!(fec.base_sequence_number, (i as u16 / 4) * 4);
                }
            } else {
                assert_eq!(out.len(), 1);
            }
        }
        assert_eq!(emitted, 8 + 4);
    }

    /// `RtpAudioQueue.c:269-280` refuses a block whose base sequence number
    /// is not a multiple of four, and disables audio FEC for the rest of the
    /// session when it sees one. Skipping sequence numbers for the parity
    /// shards -- which is the intuitive reading of the layout -- produces
    /// bases of 0, 6, 12, and only the first one passes.
    #[test]
    fn every_fec_block_starts_on_a_four_boundary() {
        let mut p = AudioPacketizer::new(AudioConfig::default(), None);
        let mut bases = Vec::new();
        let mut data_sequences = Vec::new();
        for _ in 0..16 {
            for packet in p.packetize(b"opus-packet") {
                let rtp = parse_rtp(&packet);
                if rtp.packet_type == AUDIO_FEC_PAYLOAD_TYPE {
                    let fec =
                        AudioFecHeader::parse(&mut Reader::new(&packet[RTP_HEADER_LEN..])).unwrap();
                    bases.push(fec.base_sequence_number);
                } else {
                    data_sequences.push(rtp.sequence_number);
                }
            }
        }
        assert_eq!(bases, vec![0, 0, 4, 4, 8, 8, 12, 12]);
        assert!(bases.iter().all(|b| b % 4 == 0));
        // And the data numbering is contiguous, with no gap left for parity.
        assert_eq!(data_sequences, (0..16u16).collect::<Vec<_>>());
    }

    /// The client's own check: every packet of a block must imply the same
    /// block size, a data packet's being its length less the RTP header and
    /// a parity packet's its length less the RTP and FEC headers
    /// (`RtpAudioQueue.c`, "Audio block size mismatch"). A mismatch turns
    /// audio FEC off for the session, or asserts in a debug client.
    #[test]
    fn parity_shards_are_exactly_a_data_payload_long() {
        let key = [3u8; 16];
        let mut p = AudioPacketizer::new(AudioConfig::default(), Some(&key));
        let silence = opus_silence_packet(2);
        let mut sizes = std::collections::BTreeSet::new();
        for _ in 0..8 {
            for packet in p.packetize(&silence) {
                let rtp = parse_rtp(&packet);
                let block_size = if rtp.packet_type == AUDIO_FEC_PAYLOAD_TYPE {
                    packet.len() - RTP_HEADER_LEN - AUDIO_FEC_HEADER_LEN
                } else {
                    packet.len() - RTP_HEADER_LEN
                };
                sizes.insert(block_size);
            }
        }
        assert_eq!(sizes.len(), 1, "block sizes {sizes:?}");
    }

    /// The whole point of the parity: lose a data packet and get it back,
    /// laid out as the client lays it out -- payloads as the data shards,
    /// and the header rebuilt from the FEC header.
    #[test]
    fn a_lost_audio_packet_recovers_from_parity() {
        let mut p = AudioPacketizer::new(
            AudioConfig {
                encrypt: false,
                ..Default::default()
            },
            None,
        );
        let mut data = Vec::new();
        let mut parity = Vec::new();
        for i in 0..4u8 {
            let out = p.packetize(&[i; 40]);
            data.push(out[0].clone());
            if out.len() > 1 {
                parity.extend(
                    out[1..]
                        .iter()
                        .map(|x| x[RTP_HEADER_LEN + AUDIO_FEC_HEADER_LEN..].to_vec()),
                );
            }
        }
        assert_eq!(parity.len(), crate::wire::audio::AUDIO_PARITY_SHARDS);

        let mut slots: Vec<Option<Vec<u8>>> = data
            .iter()
            .map(|d| Some(d[RTP_HEADER_LEN..].to_vec()))
            .chain(parity.into_iter().map(Some))
            .collect();
        let original = slots[2].clone().unwrap();
        slots[2] = None;
        Rs::audio().reconstruct(&mut slots).unwrap();
        assert_eq!(slots[2].as_ref().unwrap(), &original);
        assert_eq!(&data[2][RTP_HEADER_LEN..], &original[..]);
    }

    #[test]
    fn encrypted_packets_decrypt_back() {
        let key = [0x17; 16];
        let mut p = AudioPacketizer::new(
            AudioConfig {
                encrypt: true,
                rikey_id: 0x1234,
                packet_duration_ms: 5,
            },
            Some(&key),
        );
        for i in 0..4u32 {
            let out = p.packetize(b"an opus packet");
            let body = &out[0][RTP_HEADER_LEN..];
            let iv = audio_iv(0x1234, i);
            assert_eq!(cbc_decrypt(&key, &iv, body).unwrap(), b"an opus packet");
        }
    }

    #[test]
    fn opus_silence_is_a_short_well_formed_packet() {
        let mono = opus_silence_packet(1);
        let stereo = opus_silence_packet(2);
        assert_eq!(mono.len(), 3);
        assert_ne!(mono[0] & 0x04, stereo[0] & 0x04); // the stereo bit differs
        assert_eq!(mono[0] & 0x03, 0); // code 0: exactly one frame
    }

    #[test]
    fn sequence_numbers_wrap_without_gaps() {
        let mut p = AudioPacketizer::new(
            AudioConfig {
                encrypt: false,
                ..Default::default()
            },
            None,
        );
        p.sequence = u16::MAX - 1;
        let a = parse_rtp(&p.packetize(b"x")[0]).sequence_number;
        let b = parse_rtp(&p.packetize(b"x")[0]).sequence_number;
        let c = parse_rtp(&p.packetize(b"x")[0]).sequence_number;
        assert_eq!((a, b, c), (u16::MAX - 1, u16::MAX, 0));
    }
}
