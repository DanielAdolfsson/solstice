//! The audio path: backend frames in, the client's Opus packets out.
//!
//! ```text
//! SPICE Opus, 10 ms ──┬── duration and layout match ───────────────┐
//!                     └── decode ──┐                               ├─▶ jitter ─▶ one packet
//! raw S16 PCM ─────────────────────┴─▶ remix ─▶ encode, client's   │   buffer    per tick
//!                                               layout & duration ─┘
//! ```
//!
//! Three things here are not obvious from the protocol docs.
//!
//! **Pass-through is the exception.** `spice-server` sends 10 ms stereo
//! Opus. Moonlight asks for 5 ms unless its decoder is slow or the stream is
//! under 5 Mbit/s (`SdpGenerator.c`), and it sizes its decode buffer from what
//! it asked for. So a packet goes through untouched only when the client asked
//! for 10 ms stereo, and everything else is decoded and re-encoded to the
//! layout the client will decode with
//! (`solstice_gamestream::stream::opus_layout`).
//!
//! **Silence is encoded, not canned.** The hand-made silence packet the daemon
//! used to send is single-stream Opus. A surround client decodes multistream,
//! and a single-stream packet is not a valid multistream packet for any
//! layout but stereo. Silence here comes out of the same encoder as the sound,
//! so it is valid for whatever the client negotiated.
//!
//! **The backend does not set the pace.** A SPICE server sends audio only
//! while the guest plays it, in bursts, and stops outright when the guest goes
//! quiet. The client expects one packet per packet duration whatever happens.
//! [`AudioBridge::tick`] is called on the client's clock and always has a
//! packet: the next one buffered, or silence when there is none.

#![forbid(unsafe_code)]

pub mod bridge;
pub mod codec;
pub mod mix;
pub mod toc;
pub mod tone;

pub use bridge::{AudioBridge, BridgeStats, OutputConfig};
pub use codec::{AudioError, MultistreamDecoder};

/// The only rate Opus streams in GameStream, and the only rate this crate
/// accepts from a backend: `spice-server` produces nothing else.
pub const SAMPLE_RATE: u32 = 48_000;

/// Samples per channel in one millisecond at [`SAMPLE_RATE`].
pub const SAMPLES_PER_MS: usize = (SAMPLE_RATE / 1000) as usize;
