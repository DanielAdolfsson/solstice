//! The encode path: framebuffer in, Annex-B access units out.
//!
//! ```text
//! BGRA framebuffer -> colour convert (I420) -> H.264 encoder -> Annex-B AU
//!                                                   ^
//!                                      force IDR ---'  (control stream 0x0302)
//! ```
//!
//! Two things here are not obvious from the protocol docs.
//!
//! **There is no capture clock.** RFB produces dirty rectangles and SPICE
//! produces draw commands; neither has a frame rate. [`clock`] synthesises one
//! at the rate the client asked for, and emits a frame whether or not anything
//! changed, because Moonlight's watchdog fires `ML_ERROR_NO_VIDEO_TRAFFIC` if
//! the stream goes quiet.
//!
//! **The conversion is per-rectangle.** Converting a whole 1080p screen every
//! frame costs more than encoding it. [`convert`] converts only the damaged
//! region into a persistent I420 frame.

#![forbid(unsafe_code)]

pub mod clock;
pub mod convert;
pub mod encoder;
pub mod frame;
pub mod null;
pub mod testsrc;

#[cfg(feature = "openh264")]
pub mod openh264;

pub use clock::{FrameClock, Tick};
pub use encoder::{EncodedFrame, EncoderConfig, VideoEncoder, VideoError};
pub use frame::I420Frame;
