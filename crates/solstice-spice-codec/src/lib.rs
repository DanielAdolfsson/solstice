//! SPICE's image codecs, in Rust: **QUIC**, **LZ** and **GLZ**.
//!
//! SPICE's display channel carries 2D draw commands whose bitmaps are
//! compressed with one of a handful of schemes (`docs/spice-protocol.md`
//! §5.1). JPEG, ZLIB and LZ4 all have Rust crates. Three do not, and two of
//! those three are on QEMU's default path -- `image-compression=auto_glz`
//! picks between GLZ and QUIC per image, so neither can be skipped by a client
//! that wants to render a real guest. This crate is those three:
//!
//! | Codec | What it is |
//! |---|---|
//! | [`quic`] | SPICE's own lossless codec, a derivative of Starosolski's SFALIC: per-channel prediction, an adaptive Golomb-Rice model, and a melcode run mode |
//! | [`lz`] | a FastLZ derivative specialised for pixels, with the dictionary confined to the image |
//! | [`glz`] | the same byte format, but matches may reach back into *previously decoded images* through a session-long window |
//!
//! `docs/roadmap.md` §2.2 framed the choice as FFI to `spice-common` versus a
//! port, and recommended FFI. This crate takes the other option. The reason is
//! `docs/security.md` §5.5: these decoders sit directly on attacker-influenced
//! input, and the C ones reach that input through pointer arithmetic with
//! bounds checks compiled out in release builds (`spice_extra_assert`). A port
//! keeps the whole data path inside `#![forbid(unsafe_code)]`, and the
//! correctness risk a port carries is answered by differential vectors against
//! the C encoders rather than by inspection -- see `tests/`.
//!
//! # Output format
//!
//! Every decoder produces **BGRA**, four bytes per pixel in memory order
//! `b, g, r, a` -- the layout `solstice-backend`'s framebuffer wants, and the
//! same layout SPICE itself calls `rgb32`. The exception is QUIC's `GRAY`
//! type, which stays 8 bits per pixel because that is what SPICE uses it for
//! (A8 alpha masks), and converting it to grey BGRA would be a guess about
//! intent.
//!
//! The alpha byte is **zero** for formats that carry no alpha, which is what
//! the C decoders write and therefore what the differential vectors assert.
//! Treat a [`PixelFormat::Bgra8`] buffer as opaque unless the source type was
//! one that carries alpha ([`Image::has_alpha`]).
//!
//! # Robustness
//!
//! The intent is that every entry point is total -- that it returns [`Error`]
//! rather than panicking, for any input at all. In a crate that forbids
//! `unsafe`, a panic is the entire failure surface, so that is the property
//! worth stating and the one `cargo fuzz run spice_quic` and `spice_lz` exist
//! to attack. They have each found real violations of it (a 23-byte header
//! asking for a 151 MiB image; a width whose stride overflowed a `u32`), both
//! of which now have named regression tests. Treat the claim as "fuzzed, not
//! proven".
//!
//! The two codec families reach it differently, and the difference is worth
//! knowing:
//!
//! - **QUIC** writes to positions fixed by the header's width and height. The
//!   bitstream chooses pixel *values* and run *lengths*, never destinations,
//!   so the bit reader is allowed to run off the end of the input and yield
//!   zeroes; the overrun is latched and turned into [`Error::Truncated`] once
//!   decoding finishes. Run lengths are bounds-checked where the C does it.
//! - **LZ/GLZ** are dictionary codecs, so the input *does* choose
//!   destinations. Every offset and length is checked before it is used, which
//!   the C only does under `spice_assert` -- compiled out in release builds.
//!
//! Both are bounded by [`Limits`], because the cost of a decode is set by the
//! header and paid before anything in it has been validated. **A caller that
//! knows how big the image should be -- a display channel does -- should say
//! so** rather than take the defaults.
//!
//! # Provenance
//!
//! Ported from the reference C, read at `spice-common` @ master and
//! `spice-gtk` @ master, 2026-10-15:
//!
//! - `common/quic.c`, `common/quic_tmpl.c`, `common/quic_family_tmpl.c`
//! - `common/lz.c`, `common/lz_decompress_tmpl.c`, `common/lz_common.h`
//! - `src/decode-glz.c`, `src/decode-glz-tmpl.c` (spice-gtk)
//!
//! Those files are LGPL-2.1-or-later; this crate is GPL-3.0-or-later with the
//! rest of Solstice, which that licence permits. The constant tables
//! (`TABRAND_CHAOS`, `J`, `BEST_TRIG_TAB`) are the reference values and are
//! reproduced verbatim -- they are the format, not an implementation choice.

#![forbid(unsafe_code)]

pub mod glz;
pub mod lz;
pub mod quic;

mod bits;

pub use glz::{GlzDecoder, GlzWindow};
pub use lz::LzImageType;
pub use quic::{QuicDecoder, QuicImageType};

/// Why a decode failed.
///
/// Every variant is reachable from a hostile server, and none of them should
/// be fatal to the session: the caller's remedy is to drop the image and carry
/// on. The one exception is [`Error::GlzWindowMiss`], which means the GLZ
/// history is no longer consistent and the channel has to be reset
/// (`docs/spice-protocol.md` §5.1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The stream did not start with the codec's magic number.
    #[error("bad {codec} magic: expected {expected:#010x}, got {got:#010x}")]
    BadMagic {
        /// Which codec was being decoded.
        codec: &'static str,
        /// The magic the format requires.
        expected: u32,
        /// What was actually there.
        got: u32,
    },
    /// The version field is one this decoder does not implement.
    #[error("unsupported {codec} version {got:#010x}, expected {expected:#010x}")]
    BadVersion {
        /// Which codec was being decoded.
        codec: &'static str,
        /// The version the format requires.
        expected: u32,
        /// What was actually there.
        got: u32,
    },
    /// The image type field held a value the format does not define.
    #[error("invalid {codec} image type {got}")]
    BadImageType {
        /// Which codec was being decoded.
        codec: &'static str,
        /// The undefined discriminant.
        got: u32,
    },
    /// Width or height is zero, negative, or large enough to overflow.
    #[error("invalid image size {width}x{height}")]
    BadSize {
        /// The width claimed by the header.
        width: i64,
        /// The height claimed by the header.
        height: i64,
    },
    /// The header asked for more pixels than [`Limits::max_pixels`] allows.
    ///
    /// Two 32-bit header fields can ask for an image far larger than anything
    /// a desktop produces, and the work of decoding it is paid before
    /// anything is known to be wrong. A 23-byte QUIC stream claiming
    /// 96 x 393433 is a real input a fuzzer found in minutes.
    #[error("image of {pixels} pixels exceeds the {limit} pixel limit")]
    TooLarge {
        /// `width * height` as the header asked for it.
        pixels: u64,
        /// The ceiling in force.
        limit: u64,
    },
    /// The header's stride does not agree with its width and image type.
    #[error("stride {stride} does not match {width} px of type {image_type:?}")]
    BadStride {
        /// The stride claimed by the header.
        stride: u32,
        /// The width claimed by the header.
        width: u32,
        /// The image type claimed by the header.
        image_type: LzImageType,
    },
    /// The compressed data ended before the image did.
    #[error("compressed data ended early")]
    Truncated,
    /// A dictionary match pointed outside the data decoded so far.
    ///
    /// LZ and GLZ encode back-references as a distance; a distance larger than
    /// the output written so far would read uninitialised memory in C.
    #[error(
        "back-reference of {distance} px at output offset {offset} px reaches before the start"
    )]
    BadBackReference {
        /// How far back the match pointed.
        distance: u64,
        /// Where in the output it pointed back from.
        offset: u64,
    },
    /// A match or literal run would have written past the end of the image.
    #[error("copy of {length} px at output offset {offset} px overruns the {capacity} px image")]
    OutputOverrun {
        /// How many pixels the instruction wanted to write.
        length: u64,
        /// Where the write would have started.
        offset: u64,
        /// How many pixels the image holds in total.
        capacity: u64,
    },
    /// A QUIC run-length ran past the end of the row it started on.
    #[error("run of {length} px overruns the {remaining} px left in the row")]
    BadRunLength {
        /// The decoded run length.
        length: i64,
        /// How much of the row was left.
        remaining: i64,
    },
    /// A palette image arrived without the palette it indexes into.
    #[error("palette image needs a palette")]
    MissingPalette,
    /// A palette index pointed past the end of the palette.
    #[error("palette index {index} is past the end of a {entries}-entry palette")]
    BadPaletteIndex {
        /// The index the stream asked for.
        index: u32,
        /// How many entries the palette has.
        entries: u32,
    },
    /// A GLZ match referred to an image no longer in the window.
    ///
    /// Either the server and client disagree about the window, or images
    /// arrived out of order and the one being referred to has not been decoded
    /// yet. Unlike the other variants this is not recoverable per-image: the
    /// window is stateful, so the display channel must be reset.
    #[error("GLZ match in image {id} refers to image {wanted}, which is not in the window")]
    GlzWindowMiss {
        /// The image being decoded.
        id: u64,
        /// The image it referred back to.
        wanted: u64,
    },
    /// A GLZ match reached past the end of the image it referred to.
    #[error("GLZ match wants {length} px at offset {offset} of a {size} px image")]
    GlzBadOffset {
        /// How many pixels the match wanted.
        length: u64,
        /// Where in the referenced image it started.
        offset: u64,
        /// How many pixels that image holds.
        size: u64,
    },
    /// The output format asked for is not one this source type decodes to.
    #[error("cannot decode {from} to {to}")]
    UnsupportedConversion {
        /// The type the stream says it is.
        from: &'static str,
        /// The type the caller asked for.
        to: &'static str,
    },
}

/// The format's own ceiling, `SPICE_MAX_IMAGE_SIZE` in `common/quic.c`.
///
/// This is what the C enforces and it is far too generous to be a decoder's
/// only defence: at four bytes a pixel it permits a two-gigabyte allocation
/// from a header a server can write in twenty bytes. [`Limits::max_pixels`]
/// is the one that matters; no setting of it can exceed this.
pub const MAX_IMAGE_PIXELS: u64 = 512 * 1024 * 1024 - 1;

/// What a decoder will do before giving up on a hostile server.
///
/// Both ceilings exist because the cost of a decode is set by the header,
/// which arrives before anything has been validated. Neither is part of the
/// format: a server behaving normally stays far inside both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The largest image a decoder will allocate for, in pixels.
    ///
    /// The default, [`Limits::DEFAULT_MAX_PIXELS`], is 33.5 million -- just
    /// past 7680 x 4320, so it accepts anything a real display produces and
    /// nothing much beyond. **A SPICE backend should lower this to the
    /// surface it is decoding into**, which it knows and this crate does not:
    /// a draw command's bitmap can never be larger than the surface it draws
    /// onto, so anything bigger is already a protocol violation.
    pub max_pixels: u64,
    /// The decoded bytes a [`GlzWindow`] will hold before dropping its oldest
    /// images.
    ///
    /// The window's size is the *server's* choice, so without a cap a server
    /// can make the client hold an unbounded amount. Dropping the oldest
    /// image turns that into an [`Error::GlzWindowMiss`] on the next
    /// long-range match, which resets a channel; growing to match it does
    /// not end so tidily.
    pub glz_window_bytes: usize,
}

impl Limits {
    /// 2^25 pixels: 33.5 million, or 128 MiB of BGRA.
    pub const DEFAULT_MAX_PIXELS: u64 = 1 << 25;
    /// 64 MiB, the same order as `spice-server`'s own GLZ dictionary.
    pub const DEFAULT_GLZ_WINDOW_BYTES: usize = 64 * 1024 * 1024;

    /// The effective pixel ceiling: never above the format's own.
    pub(crate) fn pixel_ceiling(&self) -> u64 {
        self.max_pixels.min(MAX_IMAGE_PIXELS)
    }

    /// Reject an image whose header asks for more than the ceiling allows.
    pub(crate) fn check_pixels(&self, pixels: u64) -> Result<(), Error> {
        let limit = self.pixel_ceiling();
        if pixels > limit {
            Err(Error::TooLarge { pixels, limit })
        } else {
            Ok(())
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_pixels: Limits::DEFAULT_MAX_PIXELS,
            glz_window_bytes: Limits::DEFAULT_GLZ_WINDOW_BYTES,
        }
    }
}

/// The memory layout of a decoded buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// Four bytes per pixel, in memory order `b`, `g`, `r`, `a`.
    Bgra8,
    /// One byte per pixel.
    Gray8,
}

impl PixelFormat {
    /// Bytes one pixel occupies.
    pub const fn bytes_per_pixel(self) -> usize {
        match self {
            PixelFormat::Bgra8 => 4,
            PixelFormat::Gray8 => 1,
        }
    }
}

/// A decoded image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// How to read [`Image::data`].
    pub format: PixelFormat,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Whether the source type carried a meaningful alpha channel.
    ///
    /// When this is false the alpha bytes of a [`PixelFormat::Bgra8`] buffer
    /// are zero -- not 255 -- because that is what the C decoders write.
    pub has_alpha: bool,
    /// Whether the first row in [`Image::data`] is the top row of the image.
    ///
    /// QUIC has no orientation field and is always top-down. LZ and GLZ carry
    /// one, and a bottom-up image arrives last row first; this crate leaves it
    /// that way rather than flipping, because the caller blitting into a
    /// framebuffer can walk it backwards for free.
    pub top_down: bool,
    /// Tightly packed rows: `width * format.bytes_per_pixel()` bytes each.
    pub data: Vec<u8>,
}

impl Image {
    /// Bytes per row.
    pub fn stride(&self) -> usize {
        self.width as usize * self.format.bytes_per_pixel()
    }
}

/// A palette, as the display channel delivers it alongside an indexed image.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Palette {
    /// Entries, each `0x00rrggbb` packed into a `u32` as SPICE sends them.
    pub entries: Vec<u32>,
}

impl Palette {
    /// Look an entry up, failing rather than wrapping on an out-of-range index.
    ///
    /// The C decoders take `% num_ents` for 4- and 1-bit images and index
    /// unchecked for 8-bit ones, which reads out of bounds when the palette is
    /// shorter than the stream expects.
    fn get(&self, index: u32) -> Result<u32, Error> {
        self.entries
            .get(index as usize)
            .copied()
            .ok_or(Error::BadPaletteIndex {
                index,
                entries: self.entries.len() as u32,
            })
    }
}
