//! `PIXEL_FORMAT` to BGRA.
//!
//! The server announces its preferred format in `ServerInit` and the client may
//! ask for another with `SetPixelFormat`. Solstice asks for 32-bit true colour
//! with the shifts it wants, which every server supports, but it must still
//! handle being told something else -- the request is advisory and a server is
//! within its rights to keep its own format.

use crate::protocol::{Result, RfbError};

/// The 16-byte `PIXEL_FORMAT` structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PixelFormat {
    /// 8, 16 or 32.
    pub bits_per_pixel: u8,
    /// Significant bits per pixel.
    pub depth: u8,
    /// Whether multi-byte pixels are big-endian.
    pub big_endian: bool,
    /// Whether the pixel values are direct colour rather than palette indices.
    pub true_colour: bool,
    /// Maximum red value.
    pub red_max: u16,
    /// Maximum green value.
    pub green_max: u16,
    /// Maximum blue value.
    pub blue_max: u16,
    /// Red shift.
    pub red_shift: u8,
    /// Green shift.
    pub green_shift: u8,
    /// Blue shift.
    pub blue_shift: u8,
}

impl PixelFormat {
    /// The format Solstice asks for: little-endian BGRX, which is a memcpy
    /// away from the framebuffer.
    pub const BGRA: Self = Self {
        bits_per_pixel: 32,
        depth: 24,
        big_endian: false,
        true_colour: true,
        red_max: 255,
        green_max: 255,
        blue_max: 255,
        red_shift: 16,
        green_shift: 8,
        blue_shift: 0,
    };

    /// Parse from the wire.
    pub fn parse(buf: &[u8; 16]) -> Result<Self> {
        let format = Self {
            bits_per_pixel: buf[0],
            depth: buf[1],
            big_endian: buf[2] != 0,
            true_colour: buf[3] != 0,
            red_max: u16::from_be_bytes([buf[4], buf[5]]),
            green_max: u16::from_be_bytes([buf[6], buf[7]]),
            blue_max: u16::from_be_bytes([buf[8], buf[9]]),
            red_shift: buf[10],
            green_shift: buf[11],
            blue_shift: buf[12],
        };
        format.validate()?;
        Ok(format)
    }

    /// Reject formats this decoder cannot handle, before any pixel is read
    /// through them.
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.bits_per_pixel, 8 | 16 | 32) {
            return Err(RfbError::Protocol(format!(
                "bits-per-pixel {} is not 8, 16 or 32",
                self.bits_per_pixel
            )));
        }
        if !self.true_colour {
            return Err(RfbError::Protocol(
                "palette formats are not supported".into(),
            ));
        }
        if self.depth == 0 || self.depth > self.bits_per_pixel {
            return Err(RfbError::Protocol(format!(
                "depth {} is not valid for {} bits per pixel",
                self.depth, self.bits_per_pixel
            )));
        }
        for (name, max, shift) in [
            ("red", self.red_max, self.red_shift),
            ("green", self.green_max, self.green_shift),
            ("blue", self.blue_max, self.blue_shift),
        ] {
            if max == 0 {
                return Err(RfbError::Protocol(format!("{name}-max is zero")));
            }
            // A shift that shoves the mask off the end of the pixel would make
            // every pixel read garbage.
            if shift as u32 + max.leading_zeros().min(16) >= 64 {
                return Err(RfbError::Protocol(format!(
                    "{name}-shift {shift} is out of range"
                )));
            }
            if shift >= self.bits_per_pixel {
                return Err(RfbError::Protocol(format!(
                    "{name}-shift {shift} exceeds {} bits per pixel",
                    self.bits_per_pixel
                )));
            }
        }
        Ok(())
    }

    /// Serialise, for `SetPixelFormat` and the mock server.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0] = self.bits_per_pixel;
        out[1] = self.depth;
        out[2] = u8::from(self.big_endian);
        out[3] = u8::from(self.true_colour);
        out[4..6].copy_from_slice(&self.red_max.to_be_bytes());
        out[6..8].copy_from_slice(&self.green_max.to_be_bytes());
        out[8..10].copy_from_slice(&self.blue_max.to_be_bytes());
        out[10] = self.red_shift;
        out[11] = self.green_shift;
        out[12] = self.blue_shift;
        out
    }

    /// Bytes per pixel on the wire.
    pub const fn bytes_per_pixel(&self) -> usize {
        self.bits_per_pixel as usize / 8
    }

    /// Whether this is exactly the layout the framebuffer uses, so a row can be
    /// copied rather than converted.
    pub fn is_native_bgra(&self) -> bool {
        *self == Self::BGRA
    }

    /// Read one pixel as a native-endian value.
    fn read_pixel(&self, bytes: &[u8]) -> u32 {
        match self.bytes_per_pixel() {
            1 => bytes[0] as u32,
            2 => {
                let v = [bytes[0], bytes[1]];
                if self.big_endian {
                    u16::from_be_bytes(v) as u32
                } else {
                    u16::from_le_bytes(v) as u32
                }
            }
            _ => {
                let v = [bytes[0], bytes[1], bytes[2], bytes[3]];
                if self.big_endian {
                    u32::from_be_bytes(v)
                } else {
                    u32::from_le_bytes(v)
                }
            }
        }
    }

    /// Convert one pixel to BGRA.
    pub fn to_bgra(&self, bytes: &[u8]) -> [u8; 4] {
        self.bgra_from_components(self.components(bytes))
    }

    /// The red, green and blue intensities of one pixel, unscaled: each is in
    /// `0..=max` for its channel.
    pub fn components(&self, bytes: &[u8]) -> [u32; 3] {
        let value = self.read_pixel(bytes);
        [
            (value >> self.red_shift) & self.red_max as u32,
            (value >> self.green_shift) & self.green_max as u32,
            (value >> self.blue_shift) & self.blue_max as u32,
        ]
    }

    /// The per-channel maxima, red first, in the order [`Self::components`]
    /// returns.
    pub fn maxima(&self) -> [u32; 3] {
        [
            self.red_max as u32,
            self.green_max as u32,
            self.blue_max as u32,
        ]
    }

    /// Scale unscaled red, green and blue intensities to BGRA.
    pub fn bgra_from_components(&self, [r, g, b]: [u32; 3]) -> [u8; 4] {
        let scale = |raw: u32, max: u16| -> u8 {
            if max == 0 {
                0
            } else {
                // Scale to 0..=255 without a division by a non-power-of-two
                // mattering: max is 2^n - 1 in every real format.
                ((raw.min(max as u32) * 255 + max as u32 / 2) / max as u32) as u8
            }
        };
        [
            scale(b, self.blue_max),
            scale(g, self.green_max),
            scale(r, self.red_max),
            0xFF,
        ]
    }

    /// Convert a tightly packed run of pixels into BGRA.
    pub fn convert_run(&self, src: &[u8], dst: &mut Vec<u8>) {
        let bpp = self.bytes_per_pixel();
        if self.is_native_bgra() {
            // The common case: the server honoured SetPixelFormat.
            dst.extend_from_slice(src);
            for px in dst.chunks_exact_mut(4) {
                px[3] = 0xFF;
            }
            return;
        }
        for chunk in src.chunks_exact(bpp) {
            dst.extend_from_slice(&self.to_bgra(chunk));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_requested_format_round_trips() {
        assert_eq!(
            PixelFormat::parse(&PixelFormat::BGRA.to_bytes()).unwrap(),
            PixelFormat::BGRA
        );
    }

    #[test]
    fn native_bgra_is_recognised_and_copied() {
        let mut out = Vec::new();
        PixelFormat::BGRA.convert_run(&[1, 2, 3, 0, 4, 5, 6, 0], &mut out);
        assert_eq!(out, vec![1, 2, 3, 255, 4, 5, 6, 255]);
    }

    #[test]
    fn rgba_is_converted_rather_than_copied() {
        // Same width, shifts swapped: red low, blue high.
        let rgba = PixelFormat {
            red_shift: 0,
            blue_shift: 16,
            ..PixelFormat::BGRA
        };
        assert!(!rgba.is_native_bgra());
        // A pixel that is pure red in this format.
        let mut out = Vec::new();
        rgba.convert_run(&[0xFF, 0x00, 0x00, 0x00], &mut out);
        assert_eq!(out, vec![0x00, 0x00, 0xFF, 0xFF]); // B, G, R, A
    }

    #[test]
    fn sixteen_bit_565_scales_to_eight_bit() {
        let rgb565 = PixelFormat {
            bits_per_pixel: 16,
            depth: 16,
            big_endian: false,
            true_colour: true,
            red_max: 31,
            green_max: 63,
            blue_max: 31,
            red_shift: 11,
            green_shift: 5,
            blue_shift: 0,
        };
        // Pure white: all bits set.
        assert_eq!(rgb565.to_bgra(&[0xFF, 0xFF]), [255, 255, 255, 255]);
        // Pure black.
        assert_eq!(rgb565.to_bgra(&[0x00, 0x00]), [0, 0, 0, 255]);
        // Pure red: red_max << red_shift.
        let red = (31u16 << 11).to_le_bytes();
        assert_eq!(rgb565.to_bgra(&red), [0, 0, 255, 255]);
    }

    #[test]
    fn endianness_is_honoured() {
        let be = PixelFormat {
            big_endian: true,
            ..PixelFormat::BGRA
        };
        let le = PixelFormat::BGRA;
        assert_ne!(
            be.to_bgra(&[0x12, 0x34, 0x56, 0x00]),
            le.to_bgra(&[0x12, 0x34, 0x56, 0x00])
        );
    }

    /// The format comes off the wire, so an impossible one must be refused
    /// before any pixel is read through it.
    #[test]
    fn impossible_formats_are_refused() {
        let bad = |f: PixelFormat| f.validate().is_err();
        assert!(bad(PixelFormat {
            bits_per_pixel: 24,
            ..PixelFormat::BGRA
        }));
        assert!(bad(PixelFormat {
            true_colour: false,
            ..PixelFormat::BGRA
        }));
        assert!(bad(PixelFormat {
            red_max: 0,
            ..PixelFormat::BGRA
        }));
        assert!(bad(PixelFormat {
            depth: 0,
            ..PixelFormat::BGRA
        }));
        assert!(bad(PixelFormat {
            depth: 40,
            ..PixelFormat::BGRA
        }));
        assert!(bad(PixelFormat {
            red_shift: 32,
            ..PixelFormat::BGRA
        }));
        assert!(PixelFormat::BGRA.validate().is_ok());
    }
}
