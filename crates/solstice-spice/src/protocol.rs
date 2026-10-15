//! Wire constants, transcribed from the canonical headers.
//!
//! Sources, read at the trees in `docs/spice-protocol.md`'s preamble:
//!
//! * `spice-protocol/spice/protocol.h` -- link structures, capability bits,
//!   the two header forms, `SPICE_INPUT_MOTION_ACK_BUNCH`;
//! * `spice-protocol/spice/enums.h` -- channel types, message numbers and
//!   every field enumeration;
//! * `spice-common/spice.proto` -- the authoritative description of what is
//!   *in* each message, which the headers do not carry.
//!
//! Message type numbers are per-channel namespaces: 1..=99 are the common
//! base set and channel-specific types start at 101, so `MAIN_INIT` (103) and
//! `DISPLAY_RESET` (103) are different messages with the same number
//! (`docs/spice-protocol.md` §3).

#![allow(missing_docs)]

/// `"REDQ"` as a little-endian `u32` (`protocol.h:40`).
pub const MAGIC: u32 = u32::from_le_bytes(*b"REDQ");
/// `protocol.h:41-42`.
pub const VERSION_MAJOR: u32 = 2;
/// `protocol.h:41-42`.
pub const VERSION_MINOR: u32 = 2;
/// `protocol.h:45`. The password is encrypted with its NUL terminator, so 60
/// characters is the ceiling on the string itself.
pub const MAX_PASSWORD_LENGTH: usize = 60;
/// `protocol.h:45`: the per-connection RSA key's size.
pub const TICKET_KEY_BITS: usize = 1024;
/// `protocol.h:46`: 1024 / 8 + 34 = 162 bytes of DER `SubjectPublicKeyInfo`.
pub const TICKET_PUBKEY_BYTES: usize = 162;
/// `protocol.h:47`: the RSA block the client returns.
pub const TICKET_BYTES: usize = 128;
/// `protocol.h:113`. At most four unacknowledged motion bunches.
pub const INPUT_MOTION_ACK_BUNCH: u32 = 4;
/// `protocol.h:52`: stream ids live in `[0, 64)`.
pub const MAX_NUM_STREAMS: u32 = 64;

/// Byte lengths of the three link structures, which are packed and so are
/// exactly the sum of their fields.
pub mod link_size {
    /// `magic`, `major_version`, `minor_version`, `size`.
    pub const HEADER: usize = 16;
    /// `connection_id`, `channel_type`, `channel_id`, `num_common_caps`,
    /// `num_channel_caps`, `caps_offset`.
    pub const MESS: usize = 4 + 1 + 1 + 4 + 4 + 4;
    /// `error`, `pub_key[162]`, `num_common_caps`, `num_channel_caps`,
    /// `caps_offset`.
    pub const REPLY: usize = 4 + super::TICKET_PUBKEY_BYTES + 4 + 4 + 4;
}

/// Channel types (`enums.h:407-421`).
pub mod channel {
    pub const MAIN: u8 = 1;
    pub const DISPLAY: u8 = 2;
    pub const INPUTS: u8 = 3;
    pub const CURSOR: u8 = 4;
    pub const PLAYBACK: u8 = 5;
    pub const RECORD: u8 = 6;
    pub const TUNNEL: u8 = 7;
    pub const SMARTCARD: u8 = 8;
    pub const USBREDIR: u8 = 9;
    pub const PORT: u8 = 10;
    pub const WEBDAV: u8 = 11;

    /// A name for logs.
    pub fn name(kind: u8) -> &'static str {
        match kind {
            MAIN => "main",
            DISPLAY => "display",
            INPUTS => "inputs",
            CURSOR => "cursor",
            PLAYBACK => "playback",
            RECORD => "record",
            TUNNEL => "tunnel",
            SMARTCARD => "smartcard",
            USBREDIR => "usbredir",
            PORT => "port",
            WEBDAV => "webdav",
            _ => "unknown",
        }
    }
}

/// Common capability bits (`protocol.h:61-67`).
pub mod common_cap {
    pub const PROTOCOL_AUTH_SELECTION: u32 = 0;
    pub const AUTH_SPICE: u32 = 1;
    pub const AUTH_SASL: u32 = 2;
    pub const MINI_HEADER: u32 = 3;
}

/// Main-channel capability bits (`protocol.h:129-134`).
pub mod main_cap {
    pub const SEMI_SEAMLESS_MIGRATE: u32 = 0;
    pub const NAME_AND_UUID: u32 = 1;
    pub const AGENT_CONNECTED_TOKENS: u32 = 2;
    pub const SEAMLESS_MIGRATE: u32 = 3;
}

/// Display-channel capability bits (`protocol.h:136-153`).
pub mod display_cap {
    pub const SIZED_STREAM: u32 = 0;
    pub const MONITORS_CONFIG: u32 = 1;
    pub const COMPOSITE: u32 = 2;
    pub const A8_SURFACE: u32 = 3;
    pub const STREAM_REPORT: u32 = 4;
    pub const LZ4_COMPRESSION: u32 = 5;
    pub const PREF_COMPRESSION: u32 = 6;
    pub const GL_SCANOUT: u32 = 7;
    pub const MULTI_CODEC: u32 = 8;
    pub const CODEC_MJPEG: u32 = 9;
    pub const CODEC_VP8: u32 = 10;
    pub const CODEC_H264: u32 = 11;
    pub const PREF_VIDEO_CODEC_TYPE: u32 = 12;
    pub const CODEC_VP9: u32 = 13;
    pub const CODEC_H265: u32 = 14;
    pub const GL_SCANOUT2: u32 = 15;
}

/// Inputs-channel capability bits (`protocol.h:155-157`).
pub mod inputs_cap {
    pub const KEY_SCANCODE: u32 = 0;
}

/// Playback-channel capability bits (`protocol.h:116-121`).
pub mod playback_cap {
    pub const CELT_0_5_1: u32 = 0;
    pub const VOLUME: u32 = 1;
    pub const LATENCY: u32 = 2;
    pub const OPUS: u32 = 3;
}

/// Base messages, server to client (`enums.h:423-433`).
pub mod msg {
    pub const MIGRATE: u16 = 1;
    pub const MIGRATE_DATA: u16 = 2;
    pub const SET_ACK: u16 = 3;
    pub const PING: u16 = 4;
    pub const WAIT_FOR_CHANNELS: u16 = 5;
    pub const DISCONNECTING: u16 = 6;
    pub const NOTIFY: u16 = 7;
    pub const LIST: u16 = 8;
    pub const BASE_LAST: u16 = 100;
}

/// Base messages, client to server (`enums.h:435-443`).
pub mod msgc {
    pub const ACK_SYNC: u16 = 1;
    pub const ACK: u16 = 2;
    pub const PONG: u16 = 3;
    pub const MIGRATE_FLUSH_MARK: u16 = 4;
    pub const MIGRATE_DATA: u16 = 5;
    pub const DISCONNECTING: u16 = 6;
}

/// Main channel, server to client (`enums.h:445-465`).
pub mod main_msg {
    pub const MIGRATE_BEGIN: u16 = 101;
    pub const MIGRATE_CANCEL: u16 = 102;
    pub const INIT: u16 = 103;
    pub const CHANNELS_LIST: u16 = 104;
    pub const MOUSE_MODE: u16 = 105;
    pub const MULTI_MEDIA_TIME: u16 = 106;
    pub const AGENT_CONNECTED: u16 = 107;
    pub const AGENT_DISCONNECTED: u16 = 108;
    pub const AGENT_DATA: u16 = 109;
    pub const AGENT_TOKEN: u16 = 110;
    pub const MIGRATE_SWITCH_HOST: u16 = 111;
    pub const MIGRATE_END: u16 = 112;
    pub const NAME: u16 = 113;
    pub const UUID: u16 = 114;
    pub const AGENT_CONNECTED_TOKENS: u16 = 115;
    pub const MIGRATE_BEGIN_SEAMLESS: u16 = 116;
}

/// Main channel, client to server (`enums.h:467-483`).
pub mod main_msgc {
    pub const CLIENT_INFO: u16 = 101;
    pub const MIGRATE_CONNECTED: u16 = 102;
    pub const MIGRATE_CONNECT_ERROR: u16 = 103;
    pub const ATTACH_CHANNELS: u16 = 104;
    pub const MOUSE_MODE_REQUEST: u16 = 105;
    pub const AGENT_START: u16 = 106;
    pub const AGENT_DATA: u16 = 107;
    pub const AGENT_TOKEN: u16 = 108;
}

/// Display channel, server to client (`enums.h:485-519`).
pub mod display_msg {
    pub const MODE: u16 = 101;
    pub const MARK: u16 = 102;
    pub const RESET: u16 = 103;
    pub const COPY_BITS: u16 = 104;
    pub const INVAL_LIST: u16 = 105;
    pub const INVAL_ALL_PIXMAPS: u16 = 106;
    pub const INVAL_PALETTE: u16 = 107;
    pub const INVAL_ALL_PALETTES: u16 = 108;
    pub const STREAM_CREATE: u16 = 122;
    pub const STREAM_DATA: u16 = 123;
    pub const STREAM_CLIP: u16 = 124;
    pub const STREAM_DESTROY: u16 = 125;
    pub const STREAM_DESTROY_ALL: u16 = 126;
    pub const DRAW_FILL: u16 = 302;
    pub const DRAW_OPAQUE: u16 = 303;
    pub const DRAW_COPY: u16 = 304;
    pub const DRAW_BLEND: u16 = 305;
    pub const DRAW_BLACKNESS: u16 = 306;
    pub const DRAW_WHITENESS: u16 = 307;
    pub const DRAW_INVERS: u16 = 308;
    pub const DRAW_ROP3: u16 = 309;
    pub const DRAW_STROKE: u16 = 310;
    pub const DRAW_TEXT: u16 = 311;
    pub const DRAW_TRANSPARENT: u16 = 312;
    pub const DRAW_ALPHA_BLEND: u16 = 313;
    pub const SURFACE_CREATE: u16 = 314;
    pub const SURFACE_DESTROY: u16 = 315;
    pub const STREAM_DATA_SIZED: u16 = 316;
    pub const MONITORS_CONFIG: u16 = 317;
    pub const DRAW_COMPOSITE: u16 = 318;
    pub const STREAM_ACTIVATE_REPORT: u16 = 319;
    pub const GL_SCANOUT_UNIX: u16 = 320;
    pub const GL_DRAW: u16 = 321;
    pub const QUALITY_INDICATOR: u16 = 322;
    pub const GL_SCANOUT2_UNIX: u16 = 323;
}

/// Display channel, client to server (`enums.h:521-529`).
pub mod display_msgc {
    pub const INIT: u16 = 101;
    pub const STREAM_REPORT: u16 = 102;
    pub const PREFERRED_COMPRESSION: u16 = 103;
    pub const GL_DRAW_DONE: u16 = 104;
    pub const PREFERRED_VIDEO_CODEC_TYPE: u16 = 105;
}

/// Inputs channel (`enums.h:534-553`).
pub mod inputs_msg {
    pub const INIT: u16 = 101;
    pub const KEY_MODIFIERS: u16 = 102;
    pub const MOUSE_MOTION_ACK: u16 = 111;
}

/// Inputs channel, client to server (`enums.h:543-553`).
pub mod inputs_msgc {
    pub const KEY_DOWN: u16 = 101;
    pub const KEY_UP: u16 = 102;
    pub const KEY_MODIFIERS: u16 = 103;
    pub const KEY_SCANCODE: u16 = 104;
    pub const MOUSE_MOTION: u16 = 111;
    pub const MOUSE_POSITION: u16 = 112;
    pub const MOUSE_PRESS: u16 = 113;
    pub const MOUSE_RELEASE: u16 = 114;
}

/// Cursor channel (`enums.h:555-566`).
pub mod cursor_msg {
    pub const INIT: u16 = 101;
    pub const RESET: u16 = 102;
    pub const SET: u16 = 103;
    pub const MOVE: u16 = 104;
    pub const HIDE: u16 = 105;
    pub const TRAIL: u16 = 106;
    pub const INVAL_ONE: u16 = 107;
    pub const INVAL_ALL: u16 = 108;
}

/// Playback channel (`enums.h:568-578`).
pub mod playback_msg {
    pub const DATA: u16 = 101;
    pub const MODE: u16 = 102;
    pub const START: u16 = 103;
    pub const STOP: u16 = 104;
    pub const VOLUME: u16 = 105;
    pub const MUTE: u16 = 106;
    pub const LATENCY: u16 = 107;
}

/// `SpiceMouseMode` (`enums.h:118-121`). A *flags* enum, not an enumeration:
/// `supported_modes` carries both bits at once.
pub mod mouse_mode {
    pub const SERVER: u32 = 1 << 0;
    pub const CLIENT: u32 = 1 << 1;
}

/// `SpiceMouseButton` (`enums.h:333-344`).
pub mod mouse_button {
    pub const LEFT: u8 = 1;
    pub const MIDDLE: u8 = 2;
    pub const RIGHT: u8 = 3;
    pub const UP: u8 = 4;
    pub const DOWN: u8 = 5;
    pub const SIDE: u8 = 6;
    pub const EXTRA: u8 = 7;
}

/// `SpiceMouseButtonMask` (`enums.h:346-356`).
pub mod button_mask {
    pub const LEFT: u16 = 1 << 0;
    pub const MIDDLE: u16 = 1 << 1;
    pub const RIGHT: u16 = 1 << 2;
    pub const UP: u16 = 1 << 3;
    pub const DOWN: u16 = 1 << 4;
    pub const SIDE: u16 = 1 << 5;
    pub const EXTRA: u16 = 1 << 6;
}

/// `SpiceImageType` (`enums.h:175-190`).
pub mod image_type {
    pub const BITMAP: u8 = 0;
    pub const QUIC: u8 = 1;
    pub const RESERVED: u8 = 2;
    pub const LZ_PLT: u8 = 100;
    pub const LZ_RGB: u8 = 101;
    pub const GLZ_RGB: u8 = 102;
    pub const FROM_CACHE: u8 = 103;
    pub const SURFACE: u8 = 104;
    pub const JPEG: u8 = 105;
    pub const FROM_CACHE_LOSSLESS: u8 = 106;
    pub const ZLIB_GLZ_RGB: u8 = 107;
    pub const JPEG_ALPHA: u8 = 108;
    pub const LZ4: u8 = 109;
}

/// `SpiceImageFlags` (`enums.h:208-214`).
pub mod image_flags {
    pub const CACHE_ME: u8 = 1 << 0;
    pub const HIGH_BITS_SET: u8 = 1 << 1;
    pub const CACHE_REPLACE_ME: u8 = 1 << 2;
}

/// `SpiceImageCompression` (`enums.h:192-206`), for `PREFERRED_COMPRESSION`.
pub mod image_compression {
    pub const INVALID: u8 = 0;
    pub const OFF: u8 = 1;
    pub const AUTO_GLZ: u8 = 2;
    pub const AUTO_LZ: u8 = 3;
    pub const QUIC: u8 = 4;
    pub const GLZ: u8 = 5;
    pub const LZ: u8 = 6;
    pub const LZ4: u8 = 7;
}

/// `SpiceBitmapFmt` (`enums.h:216-230`).
pub mod bitmap_fmt {
    pub const INVALID: u8 = 0;
    pub const BIT1_LE: u8 = 1;
    pub const BIT1_BE: u8 = 2;
    pub const BIT4_LE: u8 = 3;
    pub const BIT4_BE: u8 = 4;
    pub const BIT8: u8 = 5;
    pub const BIT16: u8 = 6;
    pub const BIT24: u8 = 7;
    pub const BIT32: u8 = 8;
    pub const RGBA: u8 = 9;
    pub const BIT8_A: u8 = 10;
}

/// `SpiceBitmapFlags` (`enums.h:232-238`).
pub mod bitmap_flags {
    pub const PAL_CACHE_ME: u8 = 1 << 0;
    pub const PAL_FROM_CACHE: u8 = 1 << 1;
    pub const TOP_DOWN: u8 = 1 << 2;
}

/// `SpiceSurfaceFmt` (`enums.h:292-301`).
pub mod surface_fmt {
    pub const INVALID: u32 = 0;
    pub const A1: u32 = 1;
    pub const A8: u32 = 8;
    pub const RGB16_555: u32 = 16;
    pub const RGB32_XRGB: u32 = 32;
    pub const RGB16_565: u32 = 80;
    pub const RGB32_ARGB: u32 = 96;
}

/// `SpiceSurfaceFlags` (`enums.h:285-290`).
pub mod surface_flags {
    pub const PRIMARY: u32 = 1 << 0;
    pub const STREAMING_MODE: u32 = 1 << 1;
}

/// `SpiceClipType` (`enums.h:131-136`).
pub mod clip_type {
    pub const NONE: u8 = 0;
    pub const RECTS: u8 = 1;
}

/// `SpiceBrushType` (`enums.h:163-168`).
pub mod brush_type {
    pub const NONE: u8 = 0;
    pub const SOLID: u8 = 1;
    pub const PATTERN: u8 = 2;
}

/// `SpiceMaskFlags` (`enums.h:170-174`).
pub mod mask_flags {
    pub const INVERS: u8 = 1 << 0;
}

/// `SpiceRopd` (`enums.h:253-267`).
pub mod ropd {
    pub const INVERS_SRC: u16 = 1 << 0;
    pub const INVERS_BRUSH: u16 = 1 << 1;
    pub const INVERS_DEST: u16 = 1 << 2;
    pub const OP_PUT: u16 = 1 << 3;
    pub const OP_OR: u16 = 1 << 4;
    pub const OP_AND: u16 = 1 << 5;
    pub const OP_XOR: u16 = 1 << 6;
    pub const OP_BLACKNESS: u16 = 1 << 7;
    pub const OP_WHITENESS: u16 = 1 << 8;
    pub const OP_INVERS: u16 = 1 << 9;
    pub const INVERS_RES: u16 = 1 << 10;
}

/// `SpiceStringFlags` (`enums.h:277-284`).
pub mod string_flags {
    pub const RASTER_A1: u8 = 1 << 0;
    pub const RASTER_A4: u8 = 1 << 1;
    pub const RASTER_A8: u8 = 1 << 2;
    pub const RASTER_TOP_DOWN: u8 = 1 << 3;
}

/// `SpicePathFlags` (`enums.h:138-145`).
pub mod path_flags {
    pub const BEGIN: u8 = 1 << 0;
    pub const END: u8 = 1 << 1;
    pub const CLOSE: u8 = 1 << 3;
    pub const BEZIER: u8 = 1 << 4;
}

/// `SpiceAlphaFlags` (`enums.h:303-308`).
pub mod alpha_flags {
    pub const DEST_HAS_ALPHA: u8 = 1 << 0;
    pub const SRC_SURFACE_HAS_ALPHA: u8 = 1 << 1;
}

/// `SpiceCursorType` (`enums.h:358-368`).
pub mod cursor_type {
    pub const ALPHA: u8 = 0;
    pub const MONO: u8 = 1;
    pub const COLOR4: u8 = 2;
    pub const COLOR8: u8 = 3;
    pub const COLOR16: u8 = 4;
    pub const COLOR24: u8 = 5;
    pub const COLOR32: u8 = 6;
}

/// `SpiceCursorFlags` (`enums.h:370-377`).
pub mod cursor_flags {
    pub const NONE: u16 = 1 << 0;
    pub const CACHE_ME: u16 = 1 << 1;
    pub const FROM_CACHE: u16 = 1 << 2;
}

/// `SpiceVideoCodecType` (`enums.h:147-155`).
pub mod video_codec {
    pub const MJPEG: u8 = 1;
    pub const VP8: u8 = 2;
    pub const H264: u8 = 3;
    pub const VP9: u8 = 4;
    pub const H265: u8 = 5;
}

/// `SpiceStreamFlags` (`enums.h:157-161`).
pub mod stream_flags {
    pub const TOP_DOWN: u8 = 1 << 0;
}

/// `SpiceAudioDataMode` (`enums.h:379-387`).
pub mod audio_mode {
    pub const INVALID: u16 = 0;
    pub const RAW: u16 = 1;
    pub const CELT_0_5_1: u16 = 2;
    pub const OPUS: u16 = 3;
}

/// `SpiceAudioFmt` (`enums.h:389-394`).
pub mod audio_fmt {
    pub const INVALID: u16 = 0;
    pub const S16: u16 = 1;
}

/// `SpiceLinkErr` (`enums.h:37-50`), named for the error message.
pub fn link_err_name(code: u32) -> &'static str {
    match code {
        0 => "ok",
        1 => "error",
        2 => "invalid magic",
        3 => "invalid data",
        4 => "version mismatch",
        5 => "need secured",
        6 => "need unsecured",
        7 => "permission denied",
        8 => "bad connection id",
        9 => "channel not available",
        _ => "unknown",
    }
}

/// A capability bitmask, as the link messages carry it: a run of `u32` words,
/// bit `n` of word `n / 32`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Caps {
    words: Vec<u32>,
}

impl Caps {
    /// An empty set.
    pub fn new() -> Self {
        Caps::default()
    }

    /// A set holding exactly `bits`.
    pub fn from_bits(bits: &[u32]) -> Self {
        let mut caps = Caps::new();
        for &bit in bits {
            caps.set(bit);
        }
        caps
    }

    /// Wrap words read off the wire.
    pub fn from_words(words: Vec<u32>) -> Self {
        Caps { words }
    }

    /// The words, for writing.
    pub fn words(&self) -> &[u32] {
        &self.words
    }

    /// Add a capability.
    pub fn set(&mut self, bit: u32) {
        let word = (bit / 32) as usize;
        if self.words.len() <= word {
            self.words.resize(word + 1, 0);
        }
        self.words[word] |= 1 << (bit % 32);
    }

    /// Whether a capability is present.
    pub fn has(&self, bit: u32) -> bool {
        let word = (bit / 32) as usize;
        self.words
            .get(word)
            .is_some_and(|w| w & (1 << (bit % 32)) != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_magic_is_the_four_bytes_r_e_d_q_in_wire_order() {
        assert_eq!(MAGIC.to_le_bytes(), *b"REDQ");
    }

    #[test]
    fn capability_words_index_by_bit_over_32() {
        let caps = Caps::from_bits(&[common_cap::MINI_HEADER, 33, 64]);
        assert!(caps.has(common_cap::MINI_HEADER));
        assert!(caps.has(33));
        assert!(caps.has(64));
        assert!(!caps.has(32));
        assert_eq!(caps.words().len(), 3);
        assert_eq!(caps.words()[0], 1 << 3);
        assert_eq!(caps.words()[1], 1 << 1);
    }

    #[test]
    fn an_absent_word_reads_as_absent_rather_than_panicking() {
        let caps = Caps::from_words(vec![0]);
        assert!(!caps.has(1000));
    }

    #[test]
    fn the_link_structures_are_the_sizes_the_header_packs_them_to() {
        assert_eq!(link_size::HEADER, 16);
        assert_eq!(link_size::MESS, 18);
        assert_eq!(link_size::REPLY, 178);
    }
}
