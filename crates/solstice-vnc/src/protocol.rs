//! RFB message constants and framing (`rfbproto.rst`, RFC 6143).
//!
//! All integers are big-endian.

/// Something went wrong talking RFB.
#[derive(Debug, thiserror::Error)]
pub enum RfbError {
    /// Transport failure.
    #[error("rfb I/O: {0}")]
    Io(#[from] std::io::Error),
    /// The server sent something the protocol does not allow.
    #[error("rfb protocol: {0}")]
    Protocol(String),
    /// The server's version string was not one we can speak.
    #[error("unsupported RFB version: {0}")]
    UnsupportedVersion(String),
    /// Authentication failed, or policy refused the offered methods.
    #[error("rfb authentication: {0}")]
    Auth(String),
    /// A rectangle used an encoding this build does not implement.
    #[error("unsupported encoding {0}")]
    UnsupportedEncoding(i32),
    /// Decompressed or declared data exceeded a safety limit.
    #[error("rfb limit exceeded: {0}")]
    Limit(String),
    /// TLS failed.
    #[error("rfb TLS: {0}")]
    Tls(String),
}

/// Shorthand.
pub type Result<T> = std::result::Result<T, RfbError>;

/// Client-to-server message numbers.
pub mod client_msg {
    #![allow(missing_docs)]
    pub const SET_PIXEL_FORMAT: u8 = 0;
    pub const SET_ENCODINGS: u8 = 2;
    pub const FRAMEBUFFER_UPDATE_REQUEST: u8 = 3;
    pub const KEY_EVENT: u8 = 4;
    pub const POINTER_EVENT: u8 = 5;
    pub const CLIENT_CUT_TEXT: u8 = 6;
    pub const ENABLE_CONTINUOUS_UPDATES: u8 = 150;
    pub const CLIENT_FENCE: u8 = 248;
    pub const QEMU: u8 = 255;
    pub const QEMU_SUB_EXTENDED_KEY: u8 = 0;
}

/// Server-to-client message numbers.
pub mod server_msg {
    #![allow(missing_docs)]
    pub const FRAMEBUFFER_UPDATE: u8 = 0;
    pub const SET_COLOUR_MAP_ENTRIES: u8 = 1;
    pub const BELL: u8 = 2;
    pub const SERVER_CUT_TEXT: u8 = 3;
    pub const END_OF_CONTINUOUS_UPDATES: u8 = 150;
    pub const SERVER_FENCE: u8 = 248;
}

/// Encoding numbers (`rfbproto.rst:3047-3098`).
pub mod encoding {
    #![allow(missing_docs)]
    pub const RAW: i32 = 0;
    pub const COPY_RECT: i32 = 1;
    pub const RRE: i32 = 2;
    pub const HEXTILE: i32 = 5;
    pub const ZLIB: i32 = 6;
    pub const ZRLE: i32 = 16;

    pub const PSEUDO_DESKTOP_SIZE: i32 = -223;
    pub const PSEUDO_LAST_RECT: i32 = -224;
    pub const PSEUDO_QEMU_EXTENDED_KEY: i32 = -258;
    pub const PSEUDO_EXTENDED_DESKTOP_SIZE: i32 = -308;
    pub const PSEUDO_FENCE: i32 = -312;
    pub const PSEUDO_CONTINUOUS_UPDATES: i32 = -313;
}

/// Security type numbers (`rfbproto.rst:367-407`).
pub mod security {
    #![allow(missing_docs)]
    pub const INVALID: u8 = 0;
    pub const NONE: u8 = 1;
    pub const VNC_AUTH: u8 = 2;
    pub const TIGHT: u8 = 16;
    pub const VENCRYPT: u8 = 19;
}

/// VeNCrypt sub-types.
pub mod vencrypt {
    #![allow(missing_docs)]
    pub const PLAIN: u32 = 256;
    pub const TLS_NONE: u32 = 257;
    pub const TLS_VNC: u32 = 258;
    pub const TLS_PLAIN: u32 = 259;
    pub const X509_NONE: u32 = 260;
    pub const X509_VNC: u32 = 261;
    pub const X509_PLAIN: u32 = 262;
}

/// A rectangle header from a `FramebufferUpdate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RectHeader {
    /// Left edge.
    pub x: u16,
    /// Top edge.
    pub y: u16,
    /// Width.
    pub width: u16,
    /// Height.
    pub height: u16,
    /// Encoding number; negative values are pseudo-encodings.
    pub encoding: i32,
}

impl RectHeader {
    /// Parse the 12-byte header.
    pub fn parse(buf: &[u8; 12]) -> Self {
        Self {
            x: u16::from_be_bytes([buf[0], buf[1]]),
            y: u16::from_be_bytes([buf[2], buf[3]]),
            width: u16::from_be_bytes([buf[4], buf[5]]),
            height: u16::from_be_bytes([buf[6], buf[7]]),
            encoding: i32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        }
    }

    /// Serialise, for the mock server.
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..2].copy_from_slice(&self.x.to_be_bytes());
        out[2..4].copy_from_slice(&self.y.to_be_bytes());
        out[4..6].copy_from_slice(&self.width.to_be_bytes());
        out[6..8].copy_from_slice(&self.height.to_be_bytes());
        out[8..12].copy_from_slice(&self.encoding.to_be_bytes());
        out
    }

    /// As a backend rectangle.
    pub fn rect(&self) -> solstice_backend::Rect {
        solstice_backend::Rect {
            x: self.x as u32,
            y: self.y as u32,
            width: self.width as u32,
            height: self.height as u32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rect_headers_round_trip_including_negative_encodings() {
        let h = RectHeader {
            x: 1,
            y: 2,
            width: 3,
            height: 4,
            encoding: encoding::PSEUDO_LAST_RECT,
        };
        assert_eq!(RectHeader::parse(&h.to_bytes()), h);
        assert!(h.encoding < 0);
    }

    #[test]
    fn rect_header_converts_to_a_backend_rect() {
        let h = RectHeader {
            x: 10,
            y: 20,
            width: 30,
            height: 40,
            encoding: 0,
        };
        let r = h.rect();
        assert_eq!((r.x, r.y, r.width, r.height), (10, 20, 30, 40));
    }
}
