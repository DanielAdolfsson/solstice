//! Thin wrappers over libopus.
//!
//! `opusic-c` takes its multistream channel count as a const generic, which
//! fits a codec whose layout is known at compile time and not one negotiated
//! per session. These pick the instantiation at run time, and hold PCM as
//! `i16` rather than the bindings' `u16`.

use opusic_c::multistream;
use opusic_c::{Application, Bitrate, Channels, ErrorCode, SampleRate};

use crate::SAMPLES_PER_MS;

/// Anything that can go wrong in the audio path.
#[derive(Debug, thiserror::Error)]
pub enum AudioError {
    /// libopus refused.
    #[error("opus: {0}")]
    Opus(&'static str),
    /// A layout or frame shape this crate does not handle.
    #[error("unsupported audio: {0}")]
    Unsupported(String),
}

impl From<ErrorCode> for AudioError {
    fn from(code: ErrorCode) -> Self {
        AudioError::Opus(code.message())
    }
}

/// Shorthand.
pub type Result<T> = std::result::Result<T, AudioError>;

/// The largest packet the encoder may produce.
///
/// Sunshine's figure (`audio.cpp`, `encodeThread`). The largest layout,
/// high-quality 7.1 at 2 Mbit/s, is 1,280 bytes in 5 ms; CBR caps a packet at
/// this size rather than overrunning it, so a longer duration at that bitrate
/// costs quality rather than an encode failure.
pub const MAX_PACKET: usize = 1400;

/// The largest Opus packet duration, 120 ms, in samples per channel.
const MAX_FRAME_SAMPLES: usize = 120 * SAMPLES_PER_MS;

/// A multistream layout: channel count, streams, and the mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Channels in and out.
    pub channels: u8,
    /// Elementary streams per packet.
    pub streams: u8,
    /// How many of them are coupled. They come first.
    pub coupled_streams: u8,
    /// `mapping[j]` is the decoded channel for I/O channel `j`. Only the
    /// first `channels` entries are read.
    pub mapping: [u8; 8],
}

impl Layout {
    /// One coupled stream: plain stereo Opus, byte for byte.
    pub const STEREO: Layout = Layout {
        channels: 2,
        streams: 1,
        coupled_streams: 1,
        mapping: [0, 1, 0, 0, 0, 0, 0, 0],
    };

    fn config<const CH: usize>(&self) -> Result<multistream::Config<CH>> {
        let mut mapping = [0u8; CH];
        mapping.copy_from_slice(&self.mapping[..CH]);
        multistream::Config::try_new(self.streams, self.coupled_streams, mapping)
            .ok_or_else(|| AudioError::Unsupported(format!("multistream layout {self:?}")))
    }
}

/// The multistream encoder, at 48 kHz, CBR, for one layout.
pub struct Encoder {
    inner: multistream::Encoder,
    channels: usize,
    scratch: Vec<u16>,
}

impl std::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encoder")
            .field("channels", &self.channels)
            .finish_non_exhaustive()
    }
}

impl Encoder {
    /// Build one.
    ///
    /// `RESTRICTED_LOWDELAY` and CBR, as Sunshine configures it: the client
    /// sizes nothing from the bitrate, but a CBR stream keeps the audio
    /// packets one size, which is what the client's FEC block check expects
    /// of every packet in a block anyway (`RtpAudioQueue.c`).
    pub fn new(layout: &Layout, bitrate: u32) -> Result<Self> {
        let rate = SampleRate::Hz48000;
        let app = Application::LowDelay;
        let mut inner = match layout.channels {
            1 => multistream::Encoder::new(layout.config::<1>()?, rate, app)?,
            2 => multistream::Encoder::new(layout.config::<2>()?, rate, app)?,
            6 => multistream::Encoder::new(layout.config::<6>()?, rate, app)?,
            8 => multistream::Encoder::new(layout.config::<8>()?, rate, app)?,
            n => {
                return Err(AudioError::Unsupported(format!(
                    "an encoder for {n} channels"
                )))
            }
        };
        inner.set_bitrate(Bitrate::Value(bitrate))?;
        inner.set_vbr(false)?;
        Ok(Encoder {
            inner,
            channels: layout.channels as usize,
            scratch: Vec::new(),
        })
    }

    /// Channels per sample frame.
    pub fn channels(&self) -> usize {
        self.channels
    }

    /// Encode one frame of interleaved PCM. Its length must be a whole Opus
    /// frame duration (2.5, 5, 10, 20, 40 or 60 ms) times the channel count.
    pub fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>> {
        // The bindings take `u16` where libopus takes `opus_int16`.
        self.scratch.clear();
        self.scratch.extend(pcm.iter().map(|&s| s as u16));
        let mut out = vec![0u8; MAX_PACKET];
        let n = self.inner.encode_to_slice(&self.scratch, &mut out)?;
        out.truncate(n);
        Ok(out)
    }
}

/// A plain (single-stream) decoder for a backend's mono or stereo Opus.
pub struct Decoder {
    inner: opusic_c::Decoder,
    channels: usize,
    scratch: Vec<u16>,
}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoder")
            .field("channels", &self.channels)
            .finish_non_exhaustive()
    }
}

impl Decoder {
    /// Build one for `channels`, which must be 1 or 2: a backend sending
    /// more than that in Opus would be sending multistream, with a mapping
    /// nobody has told us.
    pub fn new(channels: u8) -> Result<Self> {
        let layout = match channels {
            1 => Channels::Mono,
            2 => Channels::Stereo,
            n => {
                return Err(AudioError::Unsupported(format!(
                    "decoding {n}-channel Opus from a backend"
                )))
            }
        };
        Ok(Decoder {
            inner: opusic_c::Decoder::new(layout, SampleRate::Hz48000)?,
            channels: channels as usize,
            scratch: vec![0; MAX_FRAME_SAMPLES * channels as usize],
        })
    }

    /// Channels per sample frame.
    pub fn channels(&self) -> usize {
        self.channels
    }

    /// Decode one packet, appending interleaved PCM to `out`. Never call it
    /// with an empty packet: libopus reads that as a loss to conceal.
    pub fn decode_into(&mut self, packet: &[u8], out: &mut Vec<i16>) -> Result<usize> {
        if packet.is_empty() {
            return Err(AudioError::Opus("an empty packet"));
        }
        let samples = self
            .inner
            .decode_to_slice(packet, &mut self.scratch, false)?;
        let total = samples * self.channels;
        out.extend(self.scratch[..total].iter().map(|&s| s as i16));
        Ok(samples)
    }
}

/// A multistream decoder: what a Moonlight client builds from DESCRIBE.
///
/// Not used on the host's own path. It is here so tests can decode the stream
/// exactly as the client would, in any crate, without a dependency on libopus
/// of their own.
pub struct MultistreamDecoder {
    inner: multistream::Decoder,
    channels: usize,
    scratch: Vec<u16>,
}

impl std::fmt::Debug for MultistreamDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultistreamDecoder")
            .field("channels", &self.channels)
            .finish_non_exhaustive()
    }
}

impl MultistreamDecoder {
    /// Build one for `layout`, at 48 kHz.
    pub fn new(layout: &Layout) -> Result<Self> {
        let rate = SampleRate::Hz48000;
        let inner = match layout.channels {
            1 => multistream::Decoder::new(layout.config::<1>()?, rate)?,
            2 => multistream::Decoder::new(layout.config::<2>()?, rate)?,
            6 => multistream::Decoder::new(layout.config::<6>()?, rate)?,
            8 => multistream::Decoder::new(layout.config::<8>()?, rate)?,
            n => {
                return Err(AudioError::Unsupported(format!(
                    "a decoder for {n} channels"
                )))
            }
        };
        Ok(MultistreamDecoder {
            inner,
            channels: layout.channels as usize,
            scratch: vec![0; MAX_FRAME_SAMPLES * layout.channels as usize],
        })
    }

    /// Decode one packet into interleaved PCM.
    pub fn decode(&mut self, packet: &[u8]) -> Result<Vec<i16>> {
        if packet.is_empty() {
            return Err(AudioError::Opus("an empty packet"));
        }
        let samples = self
            .inner
            .decode_to_slice(packet, &mut self.scratch, false)?;
        Ok(self.scratch[..samples * self.channels]
            .iter()
            .map(|&s| s as i16)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tone;

    #[test]
    fn stereo_round_trips_through_the_codec() {
        let mut encoder = Encoder::new(&Layout::STEREO, 96_000).unwrap();
        let mut decoder = Decoder::new(2).unwrap();
        let mut sine = tone::Sine::new(440.0, 2);
        let mut decoded = Vec::new();
        for _ in 0..100 {
            let packet = encoder.encode(&sine.take(5 * SAMPLES_PER_MS)).unwrap();
            assert!(packet.len() <= MAX_PACKET);
            decoder.decode_into(&packet, &mut decoded).unwrap();
        }
        assert_eq!(decoded.len(), 100 * 5 * SAMPLES_PER_MS * 2);
        // Past the codec's start-up, the tone is what came out.
        let left = tone::channel(&decoded[decoded.len() / 2..], 2, 0);
        assert!(tone::purity(&left, 440.0) > 0.9);
    }

    #[test]
    fn every_supported_channel_count_builds_and_odd_ones_do_not() {
        for channels in [1u8, 2, 6, 8] {
            let layout = Layout {
                channels,
                streams: channels,
                coupled_streams: 0,
                mapping: [0, 1, 2, 3, 4, 5, 6, 7],
            };
            Encoder::new(&layout, 64_000 * channels as u32).unwrap();
            MultistreamDecoder::new(&layout).unwrap();
        }
        let three = Layout {
            channels: 3,
            streams: 3,
            coupled_streams: 0,
            mapping: [0, 1, 2, 0, 0, 0, 0, 0],
        };
        assert!(Encoder::new(&three, 96_000).is_err());
        assert!(Decoder::new(6).is_err());
    }

    #[test]
    fn a_corrupt_packet_is_an_error_not_a_crash() {
        let mut decoder = Decoder::new(2).unwrap();
        let mut out = Vec::new();
        assert!(decoder.decode_into(&[], &mut out).is_err());
        // Code 3 with a frame count of zero: invalid by RFC 6716 §3.2.5.
        assert!(decoder.decode_into(&[0xFB, 0x00], &mut out).is_err());
        assert!(out.is_empty());
    }
}
