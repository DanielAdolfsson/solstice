//! Audio from a backend, where one exists.

use bytes::Bytes;

/// How the samples in an [`AudioFrame`] are encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AudioFormat {
    /// An Opus packet, ready to repacketise if the duration and channel layout
    /// line up with what the client negotiated.
    Opus {
        /// Sample rate in Hz.
        sample_rate: u32,
        /// Channel count.
        channels: u8,
    },
    /// Interleaved signed 16-bit PCM, host-endian.
    Pcm16 {
        /// Sample rate in Hz.
        sample_rate: u32,
        /// Channel count.
        channels: u8,
    },
}

/// One frame of backend audio.
#[derive(Clone, Debug)]
pub struct AudioFrame {
    /// Encoding of `data`.
    pub format: AudioFormat,
    /// The samples.
    pub data: Bytes,
}
