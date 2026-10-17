//! The SPICE backend.
//!
//! Solstice is a **client** here, as it is for RFB: it dials QEMU's console
//! protocol, composites what arrives into a framebuffer, and injects input.
//! SPICE is the optional backend and the harder one, and three structural
//! facts explain both why it is worth having and why it took this much code
//! (`docs/spice-protocol.md` §8):
//!
//! 1. **A session is many connections.** Each channel -- main, display,
//!    inputs, cursor, playback -- is its own socket, repeating the whole link
//!    handshake with a `connection_id` the main channel was given. The
//!    backend seam did not have to change for this: [`solstice_backend::Session`]
//!    is a handle, not a socket.
//! 2. **The display channel is a drawing command stream, not a video
//!    stream.** There is nothing to forward. Surfaces, raster operations,
//!    brushes, stencil masks, clip regions, glyphs and six image codecs all
//!    have to be executed before there is a picture to encode, and video
//!    streams are layered on top of the result as a server-side optimisation.
//! 3. **The agent is what makes it good.** With `spice-vdagent` in the guest
//!    the resolution can be set to exactly what Moonlight asked for and the
//!    pointer is absolute; without it both degrade, and that is a supported
//!    state rather than a failure.
//!
//! # Map
//!
//! | Module | What it is |
//! |---|---|
//! | [`wire`] | bounds-checked little-endian reading, and the 32-bit offsets SPICE uses instead of inline structures |
//! | [`link`] | the per-channel handshake and the RSA-OAEP ticket |
//! | [`channel`] | message framing, and the base messages every channel shares -- including the ack window, which is not optional |
//! | [`main_channel`] | session setup, mouse mode, and the agent tunnel |
//! | [`agent`] | `spice-vdagent`: resize, capabilities, the clipboard exchange |
//! | [`display`] | surfaces, draw commands, image decoding, video streams, and the framebuffer |
//! | [`cursor`] | cursor shapes, composited by the display task |
//! | [`inputs`] | scancodes and pointer messages, with motion flow control |
//! | [`playback`] | guest audio, handed on in the format the server sent |
//! | [`backend`] | dialling, wiring the channels together, and the [`solstice_backend::Backend`] implementation |
//! | [`mock`] | a deliberately minimal server, for the negative cases a real one never produces |
//!
//! The three image codecs with no Rust implementation -- QUIC, LZ and GLZ --
//! are their own crate, `solstice-spice-codec`, because they are a leaf with
//! no workspace dependencies and can therefore be fuzzed and tested without a
//! SPICE backend existing at all.
//!
//! # Hostile input
//!
//! Everything here sits on attacker-influenced input: the backend may be a VM
//! the operator does not control (`docs/security.md` §5.4). The crate
//! forbids `unsafe`, so the whole failure surface is panics and unbounded
//! allocation, and both are treated as bugs:
//!
//! * every length, offset and count is checked before it is used, which is
//!   what [`wire::Reader`] exists for;
//! * every allocation decided by a header has a ceiling -- surfaces
//!   ([`display::surface::MAX_SURFACE_PIXELS`]), images
//!   ([`display::DisplayLimits`]), cursors
//!   ([`cursor::MAX_CURSOR_DIMENSION`]), agent messages
//!   ([`agent::MAX_MESSAGE_SIZE`]), audio packets
//!   ([`playback::MAX_PACKET`]) and whole messages
//!   ([`channel::DEFAULT_MAX_MESSAGE`]);
//! * a bad *image* costs one draw command rather than the session, because
//!   dropping a frame is a better failure than dropping a desktop. A bad
//!   *header* is fatal, because the next byte would be read in the wrong
//!   place.
//!
//! # Provenance
//!
//! Written against the canonical sources rather than from memory, read
//! 2026-10-15:
//!
//! * `spice-protocol` @ master -- `spice/protocol.h`, `spice/enums.h`,
//!   `spice/vd_agent.h`;
//! * `spice-common` @ master -- `spice.proto`, which is the authoritative
//!   description of every message layout, plus `common/canvas_base.c` and
//!   `common/rop3.c` for the raster operations;
//! * `spice-gtk` @ master -- `src/spice-channel.c`, `src/channel-main.c`,
//!   `src/channel-inputs.c`, `src/channel-cursor.c`,
//!   `src/channel-display.c`, for client behaviour the wire format does not
//!   determine.
//!
//! Line references in the module documentation are to those trees.

#![forbid(unsafe_code)]

pub mod agent;
pub mod backend;
pub mod channel;
pub mod cursor;
pub mod display;
pub mod error;
pub mod inputs;
pub mod link;
pub mod main_channel;
pub mod mock;
pub mod playback;
pub mod protocol;
pub mod wire;

pub use agent::ClipboardType;
pub use backend::{
    connect, ClipboardEvent, SpiceBackend, SpiceConfig, SpiceSecurity, SpiceSession,
};
pub use error::{Result, SpiceError};
