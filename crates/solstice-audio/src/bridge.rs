//! From backend frames to one packet per tick.
//!
//! # The buffer
//!
//! Packets ready to send wait in a queue. [`AudioBridge::tick`] runs on the
//! client's clock, once per packet duration, and takes one:
//!
//! - **Buffering.** Until the queue holds [`PREBUFFER_MS`] of audio, every
//!   tick sends silence. A SPICE server sends 10 ms at a time, with whatever
//!   jitter the guest's scheduler adds, so starting to play on the first
//!   packet would mean an underrun on the second.
//! - **Playing.** Each tick sends the oldest packet. An empty queue is an
//!   underrun: silence for this tick, and back to buffering.
//! - **Too far behind.** More than [`MAX_QUEUE_MS`] queued means the source is
//!   running faster than the client's clock, or the sender stalled. The oldest
//!   packets are dropped back down to the prebuffer, because latency that
//!   accumulates in audio never drains on its own.
//!
//! The SPICE server and the daemon read the same host clock, so in practice
//! the last case is a stall rather than drift.

use std::collections::VecDeque;

use solstice_backend::{AudioFormat, AudioFrame};

use crate::codec::{Decoder, Encoder, Layout, Result};
use crate::{mix, toc, AudioError, SAMPLES_PER_MS, SAMPLE_RATE};

/// Audio held before playing starts, and again after every underrun.
pub const PREBUFFER_MS: u32 = 20;

/// The most audio held before the oldest is dropped.
pub const MAX_QUEUE_MS: u32 = 100;

/// After this long sending nothing but silence, a partial frame left over
/// from the last sound is stale: it belongs to a sound that has ended, and
/// prepending it to the next one would be a click.
const STALE_MS: u32 = 200;

/// What the client negotiated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputConfig {
    /// The multistream layout the client decodes with.
    pub layout: Layout,
    /// Total bitrate, bits per second.
    pub bitrate: u32,
    /// `x-nv-aqos.packetDuration`: milliseconds per packet.
    pub packet_ms: u32,
}

/// What the bridge has done, for the log at the end of a session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BridgeStats {
    /// Backend packets sent on untouched.
    pub passed_through: u64,
    /// Packets encoded from backend audio.
    pub encoded: u64,
    /// Ticks that sent silence.
    pub silent_ticks: u64,
    /// Times the queue ran dry while playing.
    pub underruns: u64,
    /// Packets dropped because the queue was too long.
    pub dropped: u64,
    /// Backend frames that could not be used: undecodable, or in a format
    /// this bridge does not take.
    pub rejected: u64,
}

/// Backend audio in, the client's packets out.
#[derive(Debug)]
pub struct AudioBridge {
    config: OutputConfig,
    /// Samples per channel in one output packet.
    frame_samples: usize,
    encoder: Encoder,
    /// Built on the first Opus frame that needs decoding, for its channel
    /// count, and rebuilt if that changes.
    decoder: Option<Decoder>,
    /// Remixed PCM waiting to make up a whole output frame.
    pcm: Vec<i16>,
    /// Decoded PCM before remixing, kept to save an allocation per frame.
    decoded: Vec<i16>,
    queue: VecDeque<Vec<u8>>,
    playing: bool,
    silent_run: u32,
    prebuffer: usize,
    max_queue: usize,
    stale_ticks: u32,
    stats: BridgeStats,
    warned: bool,
}

impl AudioBridge {
    /// Build one for what the client negotiated.
    ///
    /// The packet duration must be one Opus can encode in whole
    /// milliseconds: 5, 10, 20, 40 or 60. Moonlight asks for 5 or 10.
    pub fn new(config: OutputConfig) -> Result<Self> {
        if ![5, 10, 20, 40, 60].contains(&config.packet_ms) {
            return Err(AudioError::Unsupported(format!(
                "a packet duration of {} ms",
                config.packet_ms
            )));
        }
        let encoder = Encoder::new(&config.layout, config.bitrate)?;
        let packets = |ms: u32| ms.div_ceil(config.packet_ms).max(1) as usize;
        Ok(AudioBridge {
            config,
            frame_samples: config.packet_ms as usize * SAMPLES_PER_MS,
            encoder,
            decoder: None,
            pcm: Vec::new(),
            decoded: Vec::new(),
            queue: VecDeque::new(),
            playing: false,
            silent_run: 0,
            prebuffer: packets(PREBUFFER_MS),
            max_queue: packets(MAX_QUEUE_MS),
            stale_ticks: STALE_MS / config.packet_ms,
            stats: BridgeStats::default(),
            warned: false,
        })
    }

    /// What has happened so far.
    pub fn stats(&self) -> BridgeStats {
        self.stats
    }

    /// Packets waiting to be sent.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Take one frame from the backend.
    pub fn push(&mut self, frame: &AudioFrame) {
        if let Err(e) = self.try_push(frame) {
            self.stats.rejected += 1;
            // Once per session: a backend sending something unusable sends
            // it a hundred times a second.
            if !self.warned {
                self.warned = true;
                tracing::warn!(error = %e, format = ?frame.format, "backend audio dropped");
            }
        }
    }

    fn try_push(&mut self, frame: &AudioFrame) -> Result<()> {
        let (rate, channels) = match frame.format {
            AudioFormat::Opus {
                sample_rate,
                channels,
            }
            | AudioFormat::Pcm16 {
                sample_rate,
                channels,
            } => (sample_rate, channels),
            other => return Err(AudioError::Unsupported(format!("{other:?}"))),
        };
        if rate != SAMPLE_RATE {
            // spice-server streams at 48 kHz in both modes, so a resampler
            // would be code with no source to test it against.
            return Err(AudioError::Unsupported(format!(
                "a sample rate of {rate} Hz"
            )));
        }
        if channels == 0 {
            return Err(AudioError::Unsupported("zero channels".into()));
        }

        match frame.format {
            AudioFormat::Opus { .. } if self.can_pass_through(channels, &frame.data) => {
                self.stats.passed_through += 1;
                self.enqueue(frame.data.to_vec());
            }
            AudioFormat::Opus { .. } => {
                if self.decoder.as_ref().map(Decoder::channels) != Some(channels as usize) {
                    self.decoder = Some(Decoder::new(channels)?);
                }
                let decoder = self.decoder.as_mut().expect("just built");
                self.decoded.clear();
                decoder.decode_into(&frame.data, &mut self.decoded)?;
                let decoded = std::mem::take(&mut self.decoded);
                self.accumulate(&decoded, channels as usize)?;
                self.decoded = decoded;
            }
            _ => {
                if frame.data.len() % (2 * channels as usize) != 0 {
                    return Err(AudioError::Unsupported("a partial PCM sample frame".into()));
                }
                let pcm: Vec<i16> = frame
                    .data
                    .chunks_exact(2)
                    .map(|b| i16::from_ne_bytes([b[0], b[1]]))
                    .collect();
                self.accumulate(&pcm, channels as usize)?;
            }
        }
        Ok(())
    }

    /// A backend packet can go to the client as it is when the client would
    /// decode it identically: plain stereo Opus is exactly a one-stream,
    /// one-coupled multistream packet, and the duration must be the one the
    /// client sized its buffer for. And only when nothing transcoded is
    /// half-made, or the two would go out of order.
    fn can_pass_through(&self, channels: u8, packet: &[u8]) -> bool {
        let layout = &self.config.layout;
        channels == 2
            && (layout.channels, layout.streams, layout.coupled_streams) == (2, 1, 1)
            && layout.mapping[..2] == [0, 1]
            && self.pcm.is_empty()
            && toc::samples_48k(packet) == Some(self.frame_samples)
    }

    fn accumulate(&mut self, pcm: &[i16], channels: usize) -> Result<()> {
        let out_channels = self.encoder.channels();
        mix::remix(pcm, channels, out_channels, &mut self.pcm);
        let frame_len = self.frame_samples * out_channels;
        let mut start = 0;
        while self.pcm.len() - start >= frame_len {
            let packet = self.encoder.encode(&self.pcm[start..start + frame_len])?;
            self.stats.encoded += 1;
            self.enqueue(packet);
            start += frame_len;
        }
        self.pcm.drain(..start);
        Ok(())
    }

    fn enqueue(&mut self, packet: Vec<u8>) {
        self.queue.push_back(packet);
        if self.queue.len() > self.max_queue {
            let excess = self.queue.len() - self.prebuffer;
            self.queue.drain(..excess);
            self.stats.dropped += excess as u64;
        }
    }

    /// The packet for this tick: call once per packet duration.
    pub fn tick(&mut self) -> Vec<u8> {
        if !self.playing && self.queue.len() >= self.prebuffer {
            self.playing = true;
        }
        if self.playing {
            if let Some(packet) = self.queue.pop_front() {
                self.silent_run = 0;
                return packet;
            }
            self.playing = false;
            self.stats.underruns += 1;
        }
        self.silent_run = self.silent_run.saturating_add(1);
        if self.silent_run >= self.stale_ticks {
            self.pcm.clear();
        }
        self.stats.silent_ticks += 1;
        self.silence()
    }

    fn silence(&mut self) -> Vec<u8> {
        let zeros = vec![0i16; self.frame_samples * self.encoder.channels()];
        self.encoder.encode(&zeros).unwrap_or_else(|e| {
            // Not reachable with a layout the constructor accepted; an empty
            // payload is still better than ending the audio stream over it.
            tracing::warn!(error = %e, "encoding silence failed");
            Vec::new()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Decoder, MultistreamDecoder};
    use crate::tone::{self, Sine};
    use bytes::Bytes;

    fn stereo(packet_ms: u32) -> OutputConfig {
        OutputConfig {
            layout: Layout::STEREO,
            bitrate: 96_000,
            packet_ms,
        }
    }

    fn surround_51() -> OutputConfig {
        OutputConfig {
            layout: Layout {
                channels: 6,
                streams: 4,
                coupled_streams: 2,
                mapping: [0, 1, 2, 3, 4, 5, 0, 0],
            },
            bitrate: 256_000,
            packet_ms: 5,
        }
    }

    /// What spice-server sends: 10 ms of stereo Opus.
    fn spice_packets(n: usize) -> Vec<AudioFrame> {
        let mut encoder = Encoder::new(&Layout::STEREO, 64_000).unwrap();
        let mut sine = Sine::new(440.0, 2);
        (0..n)
            .map(|_| AudioFrame {
                format: AudioFormat::Opus {
                    sample_rate: 48_000,
                    channels: 2,
                },
                data: Bytes::from(encoder.encode(&sine.take(480)).unwrap()),
            })
            .collect()
    }

    fn pcm_frame(pcm: &[i16], channels: u8) -> AudioFrame {
        AudioFrame {
            format: AudioFormat::Pcm16 {
                sample_rate: 48_000,
                channels,
            },
            data: Bytes::from(pcm.iter().flat_map(|s| s.to_ne_bytes()).collect::<Vec<_>>()),
        }
    }

    /// The layout as the daemon builds it from the negotiated one, whose
    /// unused mapping entries are not zero. Comparing the whole array missed
    /// every pass-through against a real SPICE server.
    #[test]
    fn pass_through_ignores_the_unused_tail_of_the_mapping() {
        let mut config = stereo(10);
        config.layout.mapping = [0, 1, 2, 3, 4, 5, 6, 7];
        let mut bridge = AudioBridge::new(config).unwrap();
        bridge.push(&spice_packets(1)[0]);
        assert_eq!(bridge.stats().passed_through, 1);
    }

    #[test]
    fn ten_millisecond_stereo_goes_through_untouched() {
        let mut bridge = AudioBridge::new(stereo(10)).unwrap();
        let frames = spice_packets(4);
        for frame in &frames {
            bridge.push(frame);
        }
        let sent: Vec<Vec<u8>> = (0..4).map(|_| bridge.tick()).collect();
        assert_eq!(
            sent,
            frames.iter().map(|f| f.data.to_vec()).collect::<Vec<_>>()
        );
        assert_eq!(bridge.stats().passed_through, 4);
        assert_eq!(bridge.stats().encoded, 0);
    }

    /// The default Moonlight request, and the reason this crate exists.
    #[test]
    fn five_millisecond_clients_get_two_packets_per_spice_packet_and_the_tone() {
        let mut bridge = AudioBridge::new(stereo(5)).unwrap();
        for frame in spice_packets(50) {
            bridge.push(&frame);
        }
        assert_eq!(bridge.stats().encoded, 100);
        assert_eq!(bridge.stats().passed_through, 0);

        let mut client = Decoder::new(2).unwrap();
        let mut decoded = Vec::new();
        for _ in 0..bridge.queued() {
            let packet = bridge.tick();
            assert_eq!(toc::samples_48k(&packet), Some(240));
            client.decode_into(&packet, &mut decoded).unwrap();
        }
        let left = tone::channel(&decoded[decoded.len() / 2..], 2, 0);
        assert!(
            tone::purity(&left, 440.0) > 0.9,
            "{}",
            tone::purity(&left, 440.0)
        );
    }

    #[test]
    fn stereo_reaches_the_front_pair_of_a_surround_client_and_nothing_else() {
        let mut bridge = AudioBridge::new(surround_51()).unwrap();
        let mut sine = Sine::new(440.0, 2);
        for _ in 0..40 {
            bridge.push(&pcm_frame(&sine.take(480), 2));
        }
        let mut client = MultistreamDecoder::new(&surround_51().layout).unwrap();
        let mut decoded = Vec::new();
        while bridge.queued() > 0 {
            decoded.extend(client.decode(&bridge.tick()).unwrap());
        }
        let settled = &decoded[decoded.len() / 2..];
        for ch in 0..2 {
            let c = tone::channel(settled, 6, ch);
            assert!(tone::purity(&c, 440.0) > 0.9, "channel {ch}");
        }
        for ch in 2..6 {
            let c = tone::channel(settled, 6, ch);
            assert!(
                tone::rms(&c) < 50.0,
                "channel {ch} carries {}",
                tone::rms(&c)
            );
        }
    }

    /// The bug the canned packet had: a surround client must be able to
    /// decode the silence too.
    #[test]
    fn silence_is_valid_for_the_negotiated_layout() {
        let mut bridge = AudioBridge::new(surround_51()).unwrap();
        let mut client = MultistreamDecoder::new(&surround_51().layout).unwrap();
        for _ in 0..10 {
            let pcm = client.decode(&bridge.tick()).unwrap();
            assert_eq!(pcm.len(), 240 * 6);
            assert!(pcm.iter().all(|&s| s.abs() < 4));
        }
        assert_eq!(bridge.stats().silent_ticks, 10);
    }

    #[test]
    fn nothing_plays_until_the_prebuffer_fills_and_an_underrun_rebuffers() {
        let mut bridge = AudioBridge::new(stereo(10)).unwrap();
        let frames = spice_packets(4);
        // One 10 ms packet is under the 20 ms prebuffer.
        bridge.push(&frames[0]);
        let first = bridge.tick();
        assert_ne!(first, frames[0].data.to_vec());
        assert_eq!(bridge.stats().silent_ticks, 1);

        bridge.push(&frames[1]);
        assert_eq!(bridge.tick(), frames[0].data.to_vec());
        assert_eq!(bridge.tick(), frames[1].data.to_vec());
        // Dry: an underrun, then silence until two are queued again.
        bridge.tick();
        assert_eq!(bridge.stats().underruns, 1);
        bridge.push(&frames[2]);
        bridge.tick();
        assert_eq!(bridge.stats().silent_ticks, 3);
        bridge.push(&frames[3]);
        assert_eq!(bridge.tick(), frames[2].data.to_vec());
    }

    #[test]
    fn a_runaway_source_is_trimmed_back_to_the_prebuffer() {
        let mut bridge = AudioBridge::new(stereo(10)).unwrap();
        let frames = spice_packets(11);
        for frame in &frames {
            bridge.push(frame);
        }
        // 110 ms queued is over the 100 ms ceiling; what is left is the
        // newest 20 ms.
        assert_eq!(bridge.queued(), 2);
        assert_eq!(bridge.stats().dropped, 9);
        assert_eq!(bridge.tick(), frames[9].data.to_vec());
    }

    #[test]
    fn mono_pcm_is_spread_across_the_front_pair() {
        let mut bridge = AudioBridge::new(stereo(5)).unwrap();
        let mut sine = Sine::new(440.0, 1);
        for _ in 0..40 {
            bridge.push(&pcm_frame(&sine.take(240), 1));
        }
        let mut client = Decoder::new(2).unwrap();
        let mut decoded = Vec::new();
        while bridge.queued() > 0 {
            client.decode_into(&bridge.tick(), &mut decoded).unwrap();
        }
        let settled = &decoded[decoded.len() / 2..];
        assert!(tone::purity(&tone::channel(settled, 2, 0), 440.0) > 0.9);
        assert!(tone::purity(&tone::channel(settled, 2, 1), 440.0) > 0.9);
    }

    #[test]
    fn odd_sized_pcm_accumulates_across_frames() {
        let mut bridge = AudioBridge::new(stereo(5)).unwrap();
        let mut sine = Sine::new(440.0, 2);
        // 7 ms, then 3 ms: one packet, then a second once the rest arrives.
        bridge.push(&pcm_frame(&sine.take(336), 2));
        assert_eq!(bridge.stats().encoded, 1);
        bridge.push(&pcm_frame(&sine.take(144), 2));
        assert_eq!(bridge.stats().encoded, 2);
    }

    #[test]
    fn unusable_frames_are_counted_and_skipped() {
        let mut bridge = AudioBridge::new(stereo(5)).unwrap();
        bridge.push(&AudioFrame {
            format: AudioFormat::Pcm16 {
                sample_rate: 44_100,
                channels: 2,
            },
            data: Bytes::from(vec![0u8; 1764]),
        });
        bridge.push(&AudioFrame {
            format: AudioFormat::Opus {
                sample_rate: 48_000,
                channels: 2,
            },
            data: Bytes::from_static(&[0xFB, 0x00]),
        });
        bridge.push(&pcm_frame(&[1, 2, 3], 2));
        assert_eq!(bridge.stats().rejected, 3);
        assert_eq!(bridge.queued(), 0);
    }

    #[test]
    fn durations_opus_cannot_frame_are_refused_up_front() {
        for ms in [0, 1, 3, 7, 15, 120] {
            assert!(AudioBridge::new(stereo(ms)).is_err(), "{ms} ms");
        }
        for ms in [5, 10, 20, 40, 60] {
            assert!(AudioBridge::new(stereo(ms)).is_ok(), "{ms} ms");
        }
    }

    /// A transcoded half-frame must not be overtaken by a packet passed
    /// through after it.
    #[test]
    fn pass_through_waits_for_a_half_made_frame() {
        let mut bridge = AudioBridge::new(stereo(10)).unwrap();
        let mut sine = Sine::new(440.0, 2);
        bridge.push(&pcm_frame(&sine.take(240), 2));
        bridge.push(&spice_packets(1)[0]);
        assert_eq!(bridge.stats().passed_through, 0);
        assert_eq!(bridge.stats().encoded, 1);
    }

    #[test]
    fn a_stale_partial_frame_is_not_prepended_to_the_next_sound() {
        let mut bridge = AudioBridge::new(stereo(5)).unwrap();
        bridge.push(&pcm_frame(&Sine::new(440.0, 2).take(100), 2));
        for _ in 0..(STALE_MS / 5) {
            bridge.tick();
        }
        // The leftover 100 samples are gone, so 240 more make exactly one.
        bridge.push(&pcm_frame(&[0; 480], 2));
        assert_eq!(bridge.stats().encoded, 1);
        bridge.push(&pcm_frame(&[0; 280], 2));
        assert_eq!(bridge.stats().encoded, 1);
    }
}
