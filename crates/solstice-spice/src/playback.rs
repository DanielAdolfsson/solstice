//! The playback channel: guest audio out.
//!
//! The one place SPICE is *cheaper* than RFB rather than merely richer.
//! GameStream's audio stream is Opus and so is SPICE's -- `SPICE_PLAYBACK_CAP_OPUS`
//! (`protocol.h:116-121`) -- so a packet can in principle be
//! **repacketised rather than transcoded** (`docs/spice-protocol.md` §7).
//!
//! Whether it actually can depends on the frame duration and channel layout
//! lining up with what the Moonlight client asked for in
//! `x-nv-aqos.packetDuration`, which is a question for the pipeline rather
//! than this module: the format travels with the frame
//! ([`solstice_backend::AudioFormat`]) so the decision can be made where the
//! client's request is known.
//!
//! # The mode is sticky
//!
//! `PLAYBACK_MODE` sets how the `PLAYBACK_DATA` that follows is encoded, and
//! carries a payload of its own. `PLAYBACK_START` gives the sample rate and
//! channel count. Neither is repeated per frame, so both are state this
//! module keeps -- and a `DATA` arriving before either is a server that
//! started mid-stream, which is survivable by dropping the frame rather than
//! guessing a rate.

use bytes::Bytes;
use solstice_backend::{AudioFormat, AudioFrame};

use crate::error::{Result, SpiceError};
use crate::protocol::{audio_fmt, audio_mode, playback_msg};
use crate::wire::Reader;

/// The largest audio packet this client will accept.
///
/// An Opus frame is at most a few hundred bytes and a raw S16 frame at
/// 48 kHz stereo is under 200 kB even at a second per packet. Anything past
/// this is a server misbehaving.
pub const MAX_PACKET: usize = 1024 * 1024;

/// The playback channel's state.
#[derive(Clone, Debug)]
pub struct Playback {
    mode: u16,
    channels: u8,
    sample_rate: u32,
    started: bool,
}

impl Default for Playback {
    fn default() -> Self {
        Playback::new()
    }
}

impl Playback {
    /// A channel that has not been told anything yet.
    pub fn new() -> Self {
        Playback {
            mode: audio_mode::INVALID,
            channels: 2,
            sample_rate: 48_000,
            started: false,
        }
    }

    /// Whether `PLAYBACK_START` has been seen.
    pub fn is_started(&self) -> bool {
        self.started
    }

    /// The format frames are currently in, if one is known.
    pub fn format(&self) -> Option<AudioFormat> {
        match self.mode {
            audio_mode::OPUS => Some(AudioFormat::Opus {
                sample_rate: self.sample_rate,
                channels: self.channels,
            }),
            audio_mode::RAW => Some(AudioFormat::Pcm16 {
                sample_rate: self.sample_rate,
                channels: self.channels,
            }),
            _ => None,
        }
    }

    /// Handle one playback message, returning a frame if it carried one.
    pub fn handle(&mut self, kind: u16, body: &[u8]) -> Result<Option<AudioFrame>> {
        let mut r = Reader::new(body);
        match kind {
            playback_msg::START => {
                let channels = r.u32()?;
                let format = r.u16()?;
                let frequency = r.u32()?;
                let _time = r.u32()?;
                if format != audio_fmt::S16 {
                    return Err(SpiceError::protocol(format!(
                        "playback in audio format {format}, which is not S16"
                    )));
                }
                if channels == 0 || channels > 8 {
                    return Err(SpiceError::protocol(format!(
                        "playback with {channels} channels"
                    )));
                }
                if frequency == 0 || frequency > 384_000 {
                    return Err(SpiceError::protocol(format!("playback at {frequency} Hz")));
                }
                self.channels = channels as u8;
                self.sample_rate = frequency;
                self.started = true;
                tracing::info!(channels, frequency, "spice playback started");
                Ok(None)
            }

            playback_msg::MODE => {
                let _time = r.u32()?;
                let mode = r.u16()?;
                self.mode = mode;
                tracing::debug!(mode, "spice playback mode");
                // A mode message carries the first packet in that mode.
                let data = r.rest();
                self.frame(data)
            }

            playback_msg::DATA => {
                let _time = r.u32()?;
                let data = r.rest();
                self.frame(data)
            }

            playback_msg::STOP => {
                self.started = false;
                Ok(None)
            }

            // Volume and mute belong to the guest's mixer; Moonlight has its
            // own and the stream is not attenuated on the way through.
            playback_msg::VOLUME | playback_msg::MUTE | playback_msg::LATENCY => Ok(None),

            other => {
                tracing::debug!(kind = other, "ignoring playback message");
                Ok(None)
            }
        }
    }

    fn frame(&self, data: &[u8]) -> Result<Option<AudioFrame>> {
        if data.is_empty() {
            return Ok(None);
        }
        if data.len() > MAX_PACKET {
            return Err(SpiceError::limit(format!(
                "audio packet of {} bytes exceeds the {MAX_PACKET} byte ceiling",
                data.len()
            )));
        }
        if !self.started {
            // `PLAYBACK_START` carries the sample rate, and there is no
            // sensible default to guess: a frame decoded at the wrong rate
            // is worse than a frame dropped.
            tracing::debug!("dropping an audio frame that arrived before PLAYBACK_START");
            return Ok(None);
        }
        let Some(format) = self.format() else {
            tracing::debug!(
                mode = self.mode,
                "dropping an audio frame in an unknown mode"
            );
            return Ok(None);
        };
        if matches!(format, AudioFormat::Pcm16 { .. }) && data.len() % 2 != 0 {
            return Err(SpiceError::protocol(
                "raw audio packet with a half sample in it",
            ));
        }
        Ok(Some(AudioFrame {
            format,
            data: Bytes::copy_from_slice(data),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Writer;

    fn start(channels: u32, frequency: u32) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(channels).u16(audio_fmt::S16).u32(frequency).u32(0);
        w.finish()
    }

    fn mode(mode: u16, data: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(0).u16(mode).bytes(data);
        w.finish()
    }

    fn data(payload: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(0).bytes(payload);
        w.finish()
    }

    #[test]
    fn opus_frames_pass_through_with_the_rate_start_announced() {
        let mut playback = Playback::new();
        playback
            .handle(playback_msg::START, &start(2, 48_000))
            .unwrap();
        playback
            .handle(playback_msg::MODE, &mode(audio_mode::OPUS, &[]))
            .unwrap();
        let frame = playback
            .handle(playback_msg::DATA, &data(&[1, 2, 3]))
            .unwrap()
            .unwrap();
        assert_eq!(
            frame.format,
            AudioFormat::Opus {
                sample_rate: 48_000,
                channels: 2
            }
        );
        assert_eq!(&frame.data[..], &[1, 2, 3]);
    }

    #[test]
    fn a_mode_message_carries_the_first_packet_in_that_mode() {
        let mut playback = Playback::new();
        playback
            .handle(playback_msg::START, &start(2, 48_000))
            .unwrap();
        let frame = playback
            .handle(playback_msg::MODE, &mode(audio_mode::OPUS, &[9, 9]))
            .unwrap()
            .unwrap();
        assert_eq!(&frame.data[..], &[9, 9]);
    }

    #[test]
    fn raw_mode_is_reported_as_pcm_rather_than_opus() {
        let mut playback = Playback::new();
        playback
            .handle(playback_msg::START, &start(1, 44_100))
            .unwrap();
        playback
            .handle(playback_msg::MODE, &mode(audio_mode::RAW, &[]))
            .unwrap();
        let frame = playback
            .handle(playback_msg::DATA, &data(&[0, 1, 2, 3]))
            .unwrap()
            .unwrap();
        assert_eq!(
            frame.format,
            AudioFormat::Pcm16 {
                sample_rate: 44_100,
                channels: 1
            }
        );
    }

    #[test]
    fn a_frame_before_start_is_dropped_rather_than_decoded_at_a_guessed_rate() {
        let mut playback = Playback::new();
        playback
            .handle(playback_msg::MODE, &mode(audio_mode::OPUS, &[]))
            .unwrap();
        assert!(playback
            .handle(playback_msg::DATA, &data(&[1, 2, 3]))
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_frame_in_an_unknown_mode_is_dropped() {
        let mut playback = Playback::new();
        playback
            .handle(playback_msg::START, &start(2, 48_000))
            .unwrap();
        assert!(playback
            .handle(playback_msg::DATA, &data(&[1, 2, 3]))
            .unwrap()
            .is_none());
    }

    #[test]
    fn celt_is_not_decoded_because_the_client_never_advertises_it() {
        let mut playback = Playback::new();
        playback
            .handle(playback_msg::START, &start(2, 48_000))
            .unwrap();
        playback
            .handle(playback_msg::MODE, &mode(audio_mode::CELT_0_5_1, &[]))
            .unwrap();
        assert!(playback
            .handle(playback_msg::DATA, &data(&[1, 2, 3]))
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_start_in_a_format_that_is_not_s16_is_refused() {
        let mut playback = Playback::new();
        let mut w = Writer::new();
        w.u32(2).u16(99).u32(48_000).u32(0);
        assert!(playback.handle(playback_msg::START, &w.finish()).is_err());
    }

    #[test]
    fn absurd_channel_counts_and_rates_are_refused() {
        let mut playback = Playback::new();
        assert!(playback
            .handle(playback_msg::START, &start(0, 48_000))
            .is_err());
        assert!(playback
            .handle(playback_msg::START, &start(64, 48_000))
            .is_err());
        assert!(playback.handle(playback_msg::START, &start(2, 0)).is_err());
        assert!(playback
            .handle(playback_msg::START, &start(2, 10_000_000))
            .is_err());
    }

    #[test]
    fn stop_means_the_next_frame_is_dropped_until_start_comes_again() {
        let mut playback = Playback::new();
        playback
            .handle(playback_msg::START, &start(2, 48_000))
            .unwrap();
        playback
            .handle(playback_msg::MODE, &mode(audio_mode::OPUS, &[]))
            .unwrap();
        playback.handle(playback_msg::STOP, &[]).unwrap();
        assert!(!playback.is_started());
        assert!(playback
            .handle(playback_msg::DATA, &data(&[1]))
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_truncated_message_is_an_error_rather_than_a_panic() {
        let mut playback = Playback::new();
        assert!(playback.handle(playback_msg::START, &[1, 2]).is_err());
        assert!(playback.handle(playback_msg::DATA, &[1]).is_err());
    }

    #[test]
    fn an_empty_data_message_is_not_a_frame() {
        let mut playback = Playback::new();
        playback
            .handle(playback_msg::START, &start(2, 48_000))
            .unwrap();
        playback
            .handle(playback_msg::MODE, &mode(audio_mode::OPUS, &[]))
            .unwrap();
        assert!(playback
            .handle(playback_msg::DATA, &data(&[]))
            .unwrap()
            .is_none());
    }
}
