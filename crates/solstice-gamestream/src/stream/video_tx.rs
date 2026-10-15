//! Access unit in, UDP datagrams out (`stream.cpp:1560-1860`).
//!
//! ```text
//! Annex-B AU -> frame header -> shard split -> [FEC] -> [AES-GCM] -> UDP
//! ```
//!
//! Three details decide whether this interoperates at all.
//!
//! **The buffer layout is shaped around FEC.** Each shard is
//! `packet_size + MAX_RTP_HEADER_SIZE` bytes, of which the first
//! [`VIDEO_HEADER_LEN`] are the RTP and NV headers. Parity is computed over the
//! *whole* shard with those header bytes still zero, and every header -- data
//! and parity alike -- is written afterwards. Sunshine reserves exactly this
//! space at each block boundary so shards can be built in place
//! (`concat_and_insert`), and the client zeroes the same region before
//! recovering. Build the no-FEC path first and this layout is the thing you
//! have to tear out (`docs/bridging-design.md` §2.5).
//!
//! **The parity count is never transmitted.** Both ends derive it from the data
//! shard count and the percentage, so the percentage written into `fecInfo`
//! must re-derive to the count actually used.
//!
//! **The sequence counter is wider than 16 bits.** Only its low 16 bits go in
//! `rtp.sequenceNumber`, while `streamPacketIndex` carries 24 usable bits
//! shifted left by 8. Conflating them freezes the picture after 65536 packets.

use crate::crypto::gcm::SessionCrypto;
use crate::wire::rtp::RtpHeader;
use crate::wire::video::{
    flags, EncPrefix, FrameHeader, FrameType, NvVideoPacket, VideoPacketHeader, ENC_PREFIX_LEN,
    FRAME_HEADER_LEN, MULTI_FEC_FLAGS, VIDEO_HEADER_LEN,
};

use super::fec::{self, parity_count, Rs};

/// `MAX_RTP_HEADER_SIZE` from `Limelight-internal.h`.
pub const MAX_RTP_HEADER_SIZE: usize = 16;
/// Most FEC blocks a frame may use: `multiFecBlocks` carries two bits for the
/// count.
pub const MAX_FEC_BLOCKS: usize = 4;
/// Most shards one block may hold.
pub const MAX_SHARDS_PER_BLOCK: usize = 255;

/// How a frame is being paced onto the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// The datagrams, in send order.
    pub packets: Vec<Vec<u8>>,
    /// Frame index written into every shard.
    pub frame_index: u32,
    /// Whether this frame was an IDR.
    pub is_idr: bool,
    /// FEC percentage actually used; 0 means parity was disabled for this
    /// frame.
    pub fec_percentage: u32,
    /// Number of FEC blocks the frame was split into.
    pub blocks: usize,
}

/// Configuration for one streaming session's video channel.
#[derive(Clone, Copy, Debug)]
pub struct VideoConfig {
    /// `x-nv-video[0].packetSize`.
    pub packet_size: usize,
    /// Requested FEC percentage. `0` is legal and a useful bisection tool, but
    /// is not the shipping configuration.
    pub fec_percentage: u32,
    /// `x-nv-vqos[0].fec.minRequiredFecPackets`.
    pub min_required_fec_packets: u32,
    /// Whether `SS_ENC_VIDEO` was negotiated.
    pub encrypt: bool,
}

impl Default for VideoConfig {
    fn default() -> Self {
        Self {
            packet_size: 1392,
            fec_percentage: 20,
            min_required_fec_packets: 2,
            encrypt: true,
        }
    }
}

/// Turns encoded access units into datagrams.
pub struct VideoPacketizer {
    config: VideoConfig,
    crypto: Option<SessionCrypto>,
    /// Wider than 16 bits on purpose; the RTP field takes the low half.
    sequence: u32,
    frame_index: u32,
    /// The deterministic GCM counter. Monotonic for the life of the session;
    /// `rikey` is fresh per `/launch`, so it never repeats under a key.
    iv_counter: u64,
}

impl std::fmt::Debug for VideoPacketizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VideoPacketizer")
            .field("sequence", &self.sequence)
            .field("frame_index", &self.frame_index)
            .finish_non_exhaustive()
    }
}

impl VideoPacketizer {
    /// Build one. `key` is the `rikey` from `/launch`, required when
    /// `config.encrypt` is set.
    pub fn new(config: VideoConfig, key: Option<&[u8; 16]>) -> Self {
        Self {
            config,
            crypto: key.map(SessionCrypto::new).filter(|_| config.encrypt),
            sequence: 0,
            frame_index: 0,
            iv_counter: 0,
        }
    }

    /// Full datagram size: `packet_size + MAX_RTP_HEADER_SIZE`.
    pub fn blocksize(&self) -> usize {
        self.config.packet_size + MAX_RTP_HEADER_SIZE
    }

    /// Payload bytes per shard, after the 32-byte header.
    pub fn payload_blocksize(&self) -> usize {
        self.blocksize() - VIDEO_HEADER_LEN
    }

    /// Frames emitted so far.
    pub fn frame_index(&self) -> u32 {
        self.frame_index
    }

    /// Packetise one Annex-B access unit.
    ///
    /// `timestamp` is the 90 kHz RTP clock, which belongs to the session rather
    /// than to the packetiser. It has to be supplied here rather than patched
    /// in afterwards: on an encrypted stream the RTP header is inside the
    /// ciphertext, and rewriting those bytes would invalidate the GCM tag.
    ///
    /// `latency_tenths_ms` goes in `frame_processing_latency`; pass 0 when it
    /// is not known.
    pub fn packetize(
        &mut self,
        access_unit: &[u8],
        frame_type: FrameType,
        timestamp: u32,
        latency_tenths_ms: u16,
    ) -> Result<Frame, fec::FecError> {
        let payload_blocksize = self.payload_blocksize();
        let frame_index = self.frame_index;
        self.frame_index = self.frame_index.wrapping_add(1);

        // 1. The frame header goes in front of the access unit, and the whole
        //    thing is what gets split.
        let total_len = FRAME_HEADER_LEN + access_unit.len();
        let data_shards = total_len.div_ceil(payload_blocksize).max(1);
        let last_payload_len = {
            let rem = total_len % payload_blocksize;
            if rem == 0 {
                payload_blocksize
            } else {
                rem
            }
        };

        let header = FrameHeader {
            frame_processing_latency: latency_tenths_ms,
            frame_type,
            last_payload_len: last_payload_len as u16,
        };
        let mut payload = Vec::with_capacity(data_shards * payload_blocksize);
        payload.extend_from_slice(&header.to_bytes());
        payload.extend_from_slice(access_unit);
        payload.resize(data_shards * payload_blocksize, 0);

        // 2. Decide the FEC geometry. More than MAX_FEC_BLOCKS blocks and
        //    Sunshine disables FEC for the frame outright
        //    (`stream.cpp:1637-1643`), because `multiFecBlocks` cannot express
        //    a fifth block.
        let (fec_percentage, blocks) = self.fec_geometry(data_shards);

        // 3. Build every block.
        let mut packets = Vec::new();
        let per_block = data_shards.div_ceil(blocks);
        for block_index in 0..blocks {
            let first = block_index * per_block;
            let count = per_block.min(data_shards - first);
            let block_parity = if fec_percentage == 0 {
                0
            } else {
                self.block_parity_count(count, fec_percentage)
            };
            let block_payload =
                &payload[first * payload_blocksize..(first + count) * payload_blocksize];
            packets.extend(self.build_block(
                block_payload,
                count,
                block_parity,
                fec_percentage,
                block_index as u8,
                blocks as u8,
                frame_index,
                timestamp,
            )?);
        }

        Ok(Frame {
            packets,
            frame_index,
            is_idr: frame_type == FrameType::Idr,
            fec_percentage,
            blocks,
        })
    }

    /// Parity shards for one block, honouring `minRequiredFecPackets`.
    ///
    /// Moonlight sends `2`. Sunshine's path bumps the count and *recomputes*
    /// the percentage so that both ends still derive the same number; that
    /// round-trip only holds because the bump fires for small blocks.
    fn block_parity_count(&self, data_shards: usize, fec_percentage: u32) -> usize {
        let base = parity_count(data_shards, fec_percentage as usize);
        base.max(self.config.min_required_fec_packets as usize)
            .max(1)
    }

    fn fec_geometry(&self, data_shards: usize) -> (u32, usize) {
        let pct = self.config.fec_percentage;
        if pct == 0 {
            return (
                0,
                1.max(data_shards.div_ceil(MAX_SHARDS_PER_BLOCK))
                    .min(MAX_FEC_BLOCKS),
            );
        }
        let max_data = fec::max_data_shards(pct as usize).max(1);
        let blocks = data_shards.div_ceil(max_data).max(1);
        if blocks > MAX_FEC_BLOCKS {
            // Too big to describe; ship it without parity rather than lie about
            // the geometry.
            (
                0,
                data_shards
                    .div_ceil(MAX_SHARDS_PER_BLOCK)
                    .clamp(1, MAX_FEC_BLOCKS),
            )
        } else {
            (pct, blocks)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_block(
        &mut self,
        block_payload: &[u8],
        data_shards: usize,
        parity_shards: usize,
        fec_percentage: u32,
        block_index: u8,
        block_count: u8,
        frame_index: u32,
        timestamp: u32,
    ) -> Result<Vec<Vec<u8>>, fec::FecError> {
        let blocksize = self.blocksize();
        let payload_blocksize = self.payload_blocksize();

        // Shards are built in place: 32 zero bytes, then the payload chunk.
        // The zeroes are what the parity is computed over, and the client
        // zeroes the same region before recovering.
        let mut shards: Vec<Vec<u8>> = (0..data_shards)
            .map(|i| {
                let mut shard = vec![0u8; blocksize];
                shard[VIDEO_HEADER_LEN..].copy_from_slice(
                    &block_payload[i * payload_blocksize..(i + 1) * payload_blocksize],
                );
                shard
            })
            .collect();

        if parity_shards > 0 {
            let rs = Rs::video(data_shards, parity_shards)?;
            let refs: Vec<&[u8]> = shards.iter().map(|s| s.as_slice()).collect();
            let parity = rs.encode(&refs)?;
            shards.extend(parity);
        }

        // Headers last, over every shard, exactly as Sunshine does.
        let total = shards.len();
        let mut out = Vec::with_capacity(total);
        for (i, mut shard) in shards.into_iter().enumerate() {
            let sequence = self.sequence;
            self.sequence = self.sequence.wrapping_add(1);

            let mut nv_flags = 0u8;
            if i < data_shards {
                nv_flags |= flags::CONTAINS_PIC_DATA;
                if i == 0 && block_index == 0 {
                    nv_flags |= flags::SOF;
                }
                if i == data_shards - 1 && block_index + 1 == block_count {
                    nv_flags |= flags::EOF;
                }
            }

            let header = VideoPacketHeader {
                rtp: RtpHeader::video(sequence as u16, timestamp),
                nv: NvVideoPacket {
                    stream_packet_index: sequence << 8,
                    frame_index,
                    flags: nv_flags,
                    extra_flags: 0,
                    multi_fec_flags: MULTI_FEC_FLAGS,
                    multi_fec_blocks: NvVideoPacket::pack_multi_fec_blocks(
                        block_index,
                        block_count,
                    ),
                    fec_info: NvVideoPacket::pack_fec_info(
                        i as u32,
                        data_shards as u32,
                        fec_percentage,
                    ),
                },
            };
            header.write(&mut shard);
            out.push(self.maybe_encrypt(shard, frame_index));
        }
        Ok(out)
    }

    fn maybe_encrypt(&mut self, shard: Vec<u8>, frame_index: u32) -> Vec<u8> {
        let Some(crypto) = &self.crypto else {
            return shard;
        };
        let counter = self.iv_counter;
        self.iv_counter += 1;
        let iv = EncPrefix::iv_for(counter);
        let mut body = shard;
        let tag = crypto
            .encrypt_detached(&iv, &mut body)
            .expect("GCM encryption of a fixed-size buffer cannot fail");
        let mut out = Vec::with_capacity(ENC_PREFIX_LEN + body.len());
        let prefix = EncPrefix {
            iv,
            frame_number: frame_index,
            tag,
        };
        out.resize(ENC_PREFIX_LEN, 0);
        prefix.write(&mut out);
        out.extend_from_slice(&body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::video::VideoPacketHeader;

    fn access_unit(len: usize) -> Vec<u8> {
        // Annex-B start code plus deterministic filler.
        let mut au = vec![0x00, 0x00, 0x00, 0x01, 0x65];
        au.extend((0..len.saturating_sub(5)).map(|i| (i % 251) as u8));
        au
    }

    fn plain_config() -> VideoConfig {
        VideoConfig {
            packet_size: 1392,
            fec_percentage: 20,
            min_required_fec_packets: 2,
            encrypt: false,
        }
    }

    /// A port of `moonlight-common-c`'s depacketiser, enough to prove the
    /// stream is reassemblable. Returns the access unit.
    fn reassemble(packets: &[Vec<u8>], payload_blocksize: usize) -> Vec<u8> {
        let mut data: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut last_payload_len = payload_blocksize;
        for p in packets {
            let (h, payload) = VideoPacketHeader::parse(p).unwrap();
            if h.nv.flags & flags::CONTAINS_PIC_DATA == 0 {
                continue; // parity
            }
            let (shard_index, _, _) = NvVideoPacket::unpack_fec_info(h.nv.fec_info);
            let (block_index, _) = NvVideoPacket::unpack_multi_fec_blocks(h.nv.multi_fec_blocks);
            if h.nv.flags & flags::SOF != 0 {
                let fh = FrameHeader::parse(&mut crate::wire::Reader::new(payload)).unwrap();
                last_payload_len = fh.last_payload_len as usize;
            }
            // Order by (block, shard): the sender emits blocks in order.
            data.push(((block_index as u32) << 16 | shard_index, payload.to_vec()));
        }
        data.sort_by_key(|(k, _)| *k);
        let n = data.len();
        let mut out = Vec::new();
        for (i, (_, payload)) in data.into_iter().enumerate() {
            if i + 1 == n {
                out.extend_from_slice(&payload[..last_payload_len]);
            } else {
                out.extend_from_slice(&payload);
            }
        }
        // Strip the 8-byte frame header.
        out[FRAME_HEADER_LEN..].to_vec()
    }

    #[test]
    fn a_small_frame_fits_in_one_shard_and_reassembles() {
        let mut p = VideoPacketizer::new(plain_config(), None);
        let au = access_unit(100);
        let frame = p.packetize(&au, FrameType::Idr, 0, 0).unwrap();
        // 1 data shard, and minRequiredFecPackets bumps parity to 2.
        assert_eq!(frame.blocks, 1);
        assert_eq!(frame.packets.len(), 3);
        assert_eq!(reassemble(&frame.packets, p.payload_blocksize()), au);
    }

    #[test]
    fn a_large_frame_splits_and_reassembles_byte_exactly() {
        let mut p = VideoPacketizer::new(plain_config(), None);
        let au = access_unit(40_000);
        let frame = p.packetize(&au, FrameType::Idr, 90_000, 12).unwrap();
        let data_shards = frame
            .packets
            .iter()
            .filter(|pkt| {
                VideoPacketHeader::parse(pkt).unwrap().0.nv.flags & flags::CONTAINS_PIC_DATA != 0
            })
            .count();
        assert_eq!(
            data_shards,
            (FRAME_HEADER_LEN + au.len()).div_ceil(p.payload_blocksize())
        );
        assert_eq!(reassemble(&frame.packets, p.payload_blocksize()), au);
    }

    #[test]
    fn every_shard_is_exactly_one_blocksize() {
        let mut p = VideoPacketizer::new(plain_config(), None);
        let frame = p
            .packetize(&access_unit(10_000), FrameType::P, 0, 0)
            .unwrap();
        for packet in &frame.packets {
            assert_eq!(packet.len(), p.blocksize());
        }
    }

    #[test]
    fn sof_and_eof_mark_the_first_and_last_data_shards() {
        let mut p = VideoPacketizer::new(plain_config(), None);
        let frame = p
            .packetize(&access_unit(5000), FrameType::Idr, 0, 0)
            .unwrap();
        let headers: Vec<_> = frame
            .packets
            .iter()
            .map(|x| VideoPacketHeader::parse(x).unwrap().0)
            .collect();
        let data: Vec<_> = headers
            .iter()
            .filter(|h| h.nv.flags & flags::CONTAINS_PIC_DATA != 0)
            .collect();
        assert!(data.first().unwrap().nv.flags & flags::SOF != 0);
        assert!(data.last().unwrap().nv.flags & flags::EOF != 0);
        assert_eq!(
            data.iter().filter(|h| h.nv.flags & flags::SOF != 0).count(),
            1
        );
        assert_eq!(
            data.iter().filter(|h| h.nv.flags & flags::EOF != 0).count(),
            1
        );
    }

    /// The width mismatch that has bitten forks: the counter is wider than the
    /// RTP field, and `streamPacketIndex` is the counter shifted left by 8.
    #[test]
    fn stream_packet_index_and_rtp_sequence_stay_consistent_past_65536() {
        let mut p = VideoPacketizer::new(
            VideoConfig {
                fec_percentage: 0,
                min_required_fec_packets: 0,
                ..plain_config()
            },
            None,
        );
        p.sequence = 65_530;
        let mut seen = Vec::new();
        for _ in 0..4 {
            let frame = p.packetize(&access_unit(3000), FrameType::P, 0, 0).unwrap();
            for packet in &frame.packets {
                let (h, _) = VideoPacketHeader::parse(packet).unwrap();
                seen.push((h.rtp.sequence_number, h.nv.stream_packet_index));
            }
        }
        for (i, (rtp_seq, spi)) in seen.iter().enumerate() {
            let wide = 65_530u32 + i as u32;
            assert_eq!(*rtp_seq, wide as u16, "packet {i}");
            assert_eq!(*spi, wide << 8, "packet {i}");
        }
        // The RTP field wrapped; the wide counter did not.
        assert!(seen.iter().any(|(s, _)| *s < 10));
        assert!(seen.iter().all(|(_, spi)| *spi >= 65_530 << 8));
    }

    /// `fecInfo` must re-derive to the parity count actually sent, because the
    /// count itself is never on the wire.
    #[test]
    fn the_percentage_re_derives_to_the_parity_actually_sent() {
        for payload_len in [100usize, 1400, 5000, 40_000] {
            let mut p = VideoPacketizer::new(plain_config(), None);
            let frame = p
                .packetize(&access_unit(payload_len), FrameType::Idr, 0, 0)
                .unwrap();
            let headers: Vec<_> = frame
                .packets
                .iter()
                .map(|x| VideoPacketHeader::parse(x).unwrap().0)
                .collect();
            for block in 0..frame.blocks as u8 {
                let in_block: Vec<_> = headers
                    .iter()
                    .filter(|h| {
                        NvVideoPacket::unpack_multi_fec_blocks(h.nv.multi_fec_blocks).0 == block
                    })
                    .collect();
                let data = in_block
                    .iter()
                    .filter(|h| h.nv.flags & flags::CONTAINS_PIC_DATA != 0)
                    .count();
                let parity = in_block.len() - data;
                let (_, declared_data, declared_pct) =
                    NvVideoPacket::unpack_fec_info(in_block[0].nv.fec_info);
                assert_eq!(declared_data as usize, data, "len {payload_len}");
                let derived = fec::parity_count(data, declared_pct as usize)
                    .max(p.config.min_required_fec_packets as usize)
                    .max(1);
                assert_eq!(derived, parity, "len {payload_len}, block {block}");
            }
        }
    }

    /// The `FEC_VALIDATION_MODE` invariant: drop a data shard per block and
    /// recover it from parity, byte-exactly, with the header region zeroed the
    /// way the client zeroes it.
    #[test]
    fn a_lost_shard_recovers_from_parity() {
        let mut p = VideoPacketizer::new(plain_config(), None);
        let au = access_unit(20_000);
        let frame = p.packetize(&au, FrameType::Idr, 0, 0).unwrap();

        let mut by_block: std::collections::BTreeMap<u8, Vec<(u32, Vec<u8>)>> = Default::default();
        for packet in &frame.packets {
            let (h, _) = VideoPacketHeader::parse(packet).unwrap();
            let (block, _) = NvVideoPacket::unpack_multi_fec_blocks(h.nv.multi_fec_blocks);
            let (shard_index, _, _) = NvVideoPacket::unpack_fec_info(h.nv.fec_info);
            by_block
                .entry(block)
                .or_default()
                .push((shard_index, packet.clone()));
        }

        let mut recovered_packets = Vec::new();
        for (_, mut shards) in by_block {
            shards.sort_by_key(|(i, _)| *i);
            let (_, _, pct) = NvVideoPacket::unpack_fec_info(
                VideoPacketHeader::parse(&shards[0].1)
                    .unwrap()
                    .0
                    .nv
                    .fec_info,
            );
            let data_count = shards
                .iter()
                .filter(|(_, pkt)| {
                    VideoPacketHeader::parse(pkt).unwrap().0.nv.flags & flags::CONTAINS_PIC_DATA
                        != 0
                })
                .count();
            let parity_count_ = shards.len() - data_count;
            assert!(parity_count_ > 0, "pct {pct}");

            // The client zeroes the header region before running recovery.
            let mut slots: Vec<Option<Vec<u8>>> = shards
                .iter()
                .map(|(_, pkt)| {
                    let mut s = pkt.clone();
                    s[..VIDEO_HEADER_LEN].fill(0);
                    Some(s)
                })
                .collect();
            let original = slots[0].clone().unwrap();
            slots[0] = None;

            let rs = Rs::video(data_count, parity_count_).unwrap();
            rs.reconstruct(&mut slots).unwrap();
            assert_eq!(
                slots[0].as_ref().unwrap(),
                &original,
                "recovered bytes differ"
            );

            // Put the headers back and check the frame still reassembles.
            for (i, (_, pkt)) in shards.iter().enumerate() {
                let mut s = slots[i].clone().unwrap();
                s[..VIDEO_HEADER_LEN].copy_from_slice(&pkt[..VIDEO_HEADER_LEN]);
                recovered_packets.push(s);
            }
        }
        assert_eq!(reassemble(&recovered_packets, p.payload_blocksize()), au);
    }

    #[test]
    fn fec_percentage_zero_emits_no_parity() {
        let mut p = VideoPacketizer::new(
            VideoConfig {
                fec_percentage: 0,
                min_required_fec_packets: 0,
                ..plain_config()
            },
            None,
        );
        let au = access_unit(5000);
        let frame = p.packetize(&au, FrameType::P, 0, 0).unwrap();
        assert_eq!(frame.fec_percentage, 0);
        for packet in &frame.packets {
            let (h, _) = VideoPacketHeader::parse(packet).unwrap();
            assert!(h.nv.flags & flags::CONTAINS_PIC_DATA != 0);
        }
        assert_eq!(reassemble(&frame.packets, p.payload_blocksize()), au);
    }

    #[test]
    fn an_enormous_frame_disables_fec_rather_than_lying_about_the_geometry() {
        let mut p = VideoPacketizer::new(
            VideoConfig {
                packet_size: 300,
                ..plain_config()
            },
            None,
        );
        // 300-byte packets means ~284 payload bytes per shard; 400 kB needs far
        // more than 4 blocks at 20%.
        let frame = p
            .packetize(&access_unit(400_000), FrameType::Idr, 0, 0)
            .unwrap();
        assert_eq!(frame.fec_percentage, 0);
        assert!(frame.blocks <= MAX_FEC_BLOCKS);
    }

    #[test]
    fn encrypted_shards_carry_a_prefix_and_decrypt_back() {
        let key = [0x5A; 16];
        let mut p = VideoPacketizer::new(
            VideoConfig {
                encrypt: true,
                ..plain_config()
            },
            Some(&key),
        );
        let au = access_unit(3000);
        let frame = p.packetize(&au, FrameType::Idr, 0, 0).unwrap();

        let crypto = SessionCrypto::new(&key);
        let mut decrypted = Vec::new();
        let mut seen_ivs = std::collections::BTreeSet::new();
        for packet in &frame.packets {
            assert_eq!(packet.len(), ENC_PREFIX_LEN + p.blocksize());
            let (prefix, ciphertext) = EncPrefix::parse(packet).unwrap();
            assert_eq!(prefix.iv[11], b'V');
            assert_eq!(prefix.frame_number, frame.frame_index);
            assert!(seen_ivs.insert(prefix.iv), "an IV repeated under one key");
            decrypted.push(crypto.decrypt(&prefix.iv, ciphertext, &prefix.tag).unwrap());
        }
        assert_eq!(reassemble(&decrypted, p.payload_blocksize()), au);
    }

    /// The 90 kHz timestamp must reach every shard, encrypted or not.
    #[test]
    fn the_rtp_timestamp_is_carried_on_every_shard() {
        for encrypt in [false, true] {
            let key = [0x11u8; 16];
            let mut p = VideoPacketizer::new(
                VideoConfig {
                    encrypt,
                    ..plain_config()
                },
                encrypt.then_some(&key),
            );
            let frame = p
                .packetize(&access_unit(5000), FrameType::Idr, 123_456, 0)
                .unwrap();
            let crypto = SessionCrypto::new(&key);
            for packet in &frame.packets {
                let plaintext = if encrypt {
                    let (prefix, ciphertext) = EncPrefix::parse(packet).unwrap();
                    crypto.decrypt(&prefix.iv, ciphertext, &prefix.tag).unwrap()
                } else {
                    packet.clone()
                };
                let (header, _) = VideoPacketHeader::parse(&plaintext).unwrap();
                assert_eq!(header.rtp.timestamp, 123_456);
            }
        }
    }

    #[test]
    fn frame_indices_advance_and_idr_is_marked() {
        let mut p = VideoPacketizer::new(plain_config(), None);
        let a = p
            .packetize(&access_unit(500), FrameType::Idr, 0, 0)
            .unwrap();
        let b = p.packetize(&access_unit(500), FrameType::P, 0, 0).unwrap();
        assert_eq!(a.frame_index + 1, b.frame_index);
        assert!(a.is_idr);
        assert!(!b.is_idr);
        for packet in &b.packets {
            assert_eq!(
                VideoPacketHeader::parse(packet).unwrap().0.nv.frame_index,
                b.frame_index
            );
        }
    }

    #[test]
    fn an_empty_access_unit_still_produces_a_valid_frame() {
        let mut p = VideoPacketizer::new(plain_config(), None);
        let frame = p.packetize(&[], FrameType::P, 0, 0).unwrap();
        assert!(!frame.packets.is_empty());
        assert_eq!(
            reassemble(&frame.packets, p.payload_blocksize()),
            Vec::<u8>::new()
        );
    }
}
