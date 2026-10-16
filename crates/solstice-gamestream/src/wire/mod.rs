//! Wire formats: packed layouts in, typed values out.
//!
//! Everything in this module is synchronous, allocation-light and free of I/O,
//! so the `cargo fuzz` targets can reach it without dragging in a video encoder
//! (`PROJECT-LAYOUT.md` §2). Every decoder takes a slice and returns a `Result`;
//! none of them panic on malformed input, and none of them trust a length field
//! without checking it against the remaining bytes.

pub mod audio;
pub mod control;
pub mod enet;
pub mod input;
pub mod ping;
pub mod rtp;
pub mod video;

/// A malformed packet.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The buffer ended before the structure did.
    #[error("truncated: need {need} bytes, have {have}")]
    Truncated {
        /// Bytes required.
        need: usize,
        /// Bytes available.
        have: usize,
    },
    /// A length field describes more data than the packet contains.
    #[error("length field {claimed} overruns {available} remaining bytes")]
    LengthOverrun {
        /// What the field said.
        claimed: usize,
        /// What was actually left.
        available: usize,
    },
    /// A constant field held something other than its constant.
    #[error("invalid {field}: {value:#x}")]
    InvalidField {
        /// Which field.
        field: &'static str,
        /// What it held.
        value: u64,
    },
    /// Bytes that should have been UTF-8 were not.
    #[error("invalid UTF-8 in {0}")]
    InvalidUtf8(&'static str),
}

/// Shorthand.
pub type Result<T> = std::result::Result<T, WireError>;

/// A bounds-checked forward cursor.
///
/// The decoders use nothing else, which is what makes "cannot over-read" a
/// property of the module rather than of each function.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a slice.
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Whether every byte has been consumed.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// The unconsumed bytes, without consuming them.
    pub fn peek_rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Consume `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(WireError::Truncated {
                need: n,
                have: self.remaining(),
            });
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Consume a fixed-size array.
    pub fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// Consume one byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Consume a big-endian `u16`.
    pub fn u16be(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    /// Consume a little-endian `u16`.
    pub fn u16le(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take_array()?))
    }

    /// Consume a big-endian `i16`.
    pub fn i16be(&mut self) -> Result<i16> {
        Ok(i16::from_be_bytes(self.take_array()?))
    }

    /// Consume a little-endian `i16`.
    pub fn i16le(&mut self) -> Result<i16> {
        Ok(i16::from_le_bytes(self.take_array()?))
    }

    /// Consume a big-endian `u32`.
    pub fn u32be(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    /// Consume a little-endian `u32`.
    pub fn u32le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take_array()?))
    }

    /// Skip `n` bytes.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_refuses_to_over_read() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.u16be().unwrap(), 0x0102);
        assert_eq!(r.remaining(), 1);
        assert_eq!(
            r.u32be().unwrap_err(),
            WireError::Truncated { need: 4, have: 1 }
        );
        // A failed read consumes nothing.
        assert_eq!(r.remaining(), 1);
        assert_eq!(r.u8().unwrap(), 3);
        assert!(r.is_empty());
    }

    #[test]
    fn endianness_helpers_disagree_as_they_should() {
        let mut r = Reader::new(&[0x01, 0x02, 0x01, 0x02]);
        assert_eq!(r.u16be().unwrap(), 0x0102);
        assert_eq!(r.u16le().unwrap(), 0x0201);
    }
}
