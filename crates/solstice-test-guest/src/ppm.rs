//! The independent oracle.
//!
//! QMP `screendump` writes QEMU's own capture of the guest display. Asserting
//! a decoded framebuffer against *this* is a different claim from asserting it
//! against the colour the test asked the guest to paint: the latter only says
//! the client agrees with the test's intent, while this says it agrees with
//! what QEMU believes is on the screen.

use std::path::Path;

use crate::{Error, Result};

/// A binary PPM (`P6`), as QEMU's `screendump` writes it.
#[derive(Clone, PartialEq, Eq)]
pub struct Ppm {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Packed 8-bit RGB triples, row-major, `width * height * 3` bytes.
    pub rgb: Vec<u8>,
}

impl std::fmt::Debug for Ppm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (colour, share) = self.dominant();
        write!(
            f,
            "Ppm({}x{}, dominant #{:02x}{:02x}{:02x} at {:.1}%)",
            self.width,
            self.height,
            colour[0],
            colour[1],
            colour[2],
            share * 100.0
        )
    }
}

impl Ppm {
    /// Parse a binary PPM from disk.
    pub fn read(path: &Path) -> Result<Self> {
        Self::parse(&std::fs::read(path)?)
    }

    /// Parse a binary PPM from memory.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let bad = |why: &str| Error::Screendump(why.to_owned());

        // A header token is whitespace-delimited, and `#` runs to end of line.
        // Hand-rolled rather than closure-based so the cursor stays a plain
        // local that the raster offset below can also use.
        struct Lexer<'a> {
            bytes: &'a [u8],
            at: usize,
        }
        impl Lexer<'_> {
            fn token(&mut self) -> Option<&str> {
                loop {
                    while self.at < self.bytes.len() && self.bytes[self.at].is_ascii_whitespace() {
                        self.at += 1;
                    }
                    if self.at < self.bytes.len() && self.bytes[self.at] == b'#' {
                        while self.at < self.bytes.len() && self.bytes[self.at] != b'\n' {
                            self.at += 1;
                        }
                        continue;
                    }
                    break;
                }
                let start = self.at;
                while self.at < self.bytes.len() && !self.bytes[self.at].is_ascii_whitespace() {
                    self.at += 1;
                }
                (self.at > start)
                    .then(|| std::str::from_utf8(&self.bytes[start..self.at]).unwrap_or(""))
            }
        }

        let mut lexer = Lexer { bytes, at: 0 };
        let magic = lexer.token().ok_or_else(|| bad("empty file"))?;
        if magic != "P6" {
            return Err(bad(&format!("expected a P6 PPM, found {magic:?}")));
        }

        let number = |lexer: &mut Lexer, what: &str| -> Result<u32> {
            lexer
                .token()
                .ok_or_else(|| bad(&format!("truncated header, no {what}")))?
                .parse()
                .map_err(|_| bad(&format!("unparseable {what}")))
        };
        let width = number(&mut lexer, "width")?;
        let height = number(&mut lexer, "height")?;
        let max = number(&mut lexer, "maximum value")?;
        if max != 255 {
            return Err(bad(&format!(
                "expected 8-bit samples, found a maximum of {max}"
            )));
        }
        // Exactly one whitespace byte separates the header from the raster.
        let cursor = lexer.at + 1;

        let want = width as usize * height as usize * 3;
        let rgb = bytes
            .get(cursor..cursor + want)
            .ok_or_else(|| {
                bad(&format!(
                    "raster is {} bytes, expected {want} for {width}x{height}",
                    bytes.len().saturating_sub(cursor)
                ))
            })?
            .to_vec();

        Ok(Self { width, height, rgb })
    }

    /// The pixel at `(x, y)`.
    ///
    /// # Panics
    /// If the coordinate is outside the image.
    pub fn pixel(&self, x: u32, y: u32) -> [u8; 3] {
        assert!(
            x < self.width && y < self.height,
            "({x}, {y}) is outside {self:?}"
        );
        let i = (y as usize * self.width as usize + x as usize) * 3;
        [self.rgb[i], self.rgb[i + 1], self.rgb[i + 2]]
    }

    /// The single colour every pixel shares, or `None` if the image is mixed.
    pub fn uniform(&self) -> Option<[u8; 3]> {
        let first = self.rgb.get(..3)?;
        self.rgb
            .chunks_exact(3)
            .all(|p| p == first)
            .then(|| [first[0], first[1], first[2]])
    }

    /// The most common colour and the fraction of the image it covers.
    ///
    /// Useful in a failure message: "87% black" says the repaint never
    /// arrived, where "not uniform" does not.
    pub fn dominant(&self) -> ([u8; 3], f32) {
        let mut counts = std::collections::HashMap::<[u8; 3], usize>::new();
        for p in self.rgb.chunks_exact(3) {
            *counts.entry([p[0], p[1], p[2]]).or_default() += 1;
        }
        counts
            .into_iter()
            .max_by_key(|&(_, n)| n)
            .map(|(c, n)| (c, n as f32 / (self.width * self.height) as f32))
            .unwrap_or(([0, 0, 0], 0.0))
    }
}
