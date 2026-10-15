//! Bounds-checked little-endian reading and writing.
//!
//! Every integer on a SPICE connection is little-endian -- the opposite of
//! RFB and of GameStream's RTP headers, which makes three conventions in one
//! process and makes a helper that cannot be used the wrong way worth having
//! (`docs/spice-protocol.md` §1).
//!
//! The other reason this exists is the shape of SPICE's marshalling.
//! Variable-length members are not inline: a `Image *src_bitmap` is a **32-bit
//! offset from the start of the message body**, and the thing it points at is
//! somewhere further along (`spice-common/python_modules/ptypes.py:564-590`,
//! where `PointerType::primitive_type` is `uint32`). So a parser has to seek
//! around inside one message, and every seek is an opportunity to read
//! somebody else's memory in C or to panic in Rust. [`Reader`] therefore
//! carries the whole body and an offset, and every accessor returns
//! [`SpiceError::Truncated`] rather than panicking.

use crate::error::{Result, SpiceError};

/// A cursor over one message body.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    body: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Start at the beginning of `body`.
    pub const fn new(body: &'a [u8]) -> Self {
        Reader { body, pos: 0 }
    }

    /// The whole message body, regardless of where this cursor is.
    ///
    /// Pointer members are offsets from here, not from the cursor.
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// How far in the cursor is.
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Bytes left before the end of the body.
    pub const fn remaining(&self) -> usize {
        self.body.len() - self.pos
    }

    /// Whether the cursor is at the end.
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.body.len()
    }

    /// A second cursor over the same body, starting at `offset`.
    ///
    /// This is how a pointer member is followed. An offset of zero is the
    /// protocol's null, and the caller decides whether that is legal.
    pub fn at(&self, offset: usize) -> Result<Reader<'a>> {
        if offset > self.body.len() {
            return Err(SpiceError::Truncated {
                what: "pointer offset",
                wanted: offset,
                available: self.body.len(),
            });
        }
        Ok(Reader {
            body: self.body,
            pos: offset,
        })
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(SpiceError::Truncated {
            what,
            wanted: n,
            available: self.remaining(),
        })?;
        if end > self.body.len() {
            return Err(SpiceError::Truncated {
                what,
                wanted: n,
                available: self.remaining(),
            });
        }
        let out = &self.body[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Read `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n, "bytes")
    }

    /// Read everything that is left.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.body[self.pos..];
        self.pos = self.body.len();
        out
    }

    /// Skip `n` bytes.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n, "padding").map(|_| ())
    }

    /// `u8`.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1, "u8")?[0])
    }

    /// `i8`.
    pub fn i8(&mut self) -> Result<i8> {
        Ok(self.u8()? as i8)
    }

    /// `u16`.
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2, "u16")?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// `i16`.
    pub fn i16(&mut self) -> Result<i16> {
        Ok(self.u16()? as i16)
    }

    /// `u32`.
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4, "u32")?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// `i32`.
    pub fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    /// `u64`.
    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8, "u64")?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// A 32-bit pointer member: an offset into the body, or `None` for null.
    pub fn pointer(&mut self) -> Result<Option<usize>> {
        let offset = self.u32()?;
        Ok(if offset == 0 {
            None
        } else {
            Some(offset as usize)
        })
    }

    /// An element count, refused when it could not possibly fit.
    ///
    /// A count is a `u32` off the wire and the elements it counts are at
    /// least one byte each, so a count larger than the body cannot be
    /// honest. Checking it here keeps a `Vec::with_capacity` from being
    /// asked for four gigabytes before the first element is read.
    pub fn count(&self, n: u32, element_bytes: usize) -> Result<usize> {
        let n = n as usize;
        let needed = n.saturating_mul(element_bytes.max(1));
        if needed > self.remaining() {
            return Err(SpiceError::Truncated {
                what: "element count",
                wanted: needed,
                available: self.remaining(),
            });
        }
        Ok(n)
    }
}

/// A little-endian message builder.
#[derive(Clone, Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// An empty builder.
    pub const fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    /// An empty builder with room reserved.
    pub fn with_capacity(n: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(n),
        }
    }

    /// Bytes written so far.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing has been written.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Append a `u8`.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// Append a `u16`.
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Append a `u32`.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Append an `i32`.
    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Append a `u64`.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Append raw bytes.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// Append `n` zero bytes.
    pub fn zeros(&mut self, n: usize) -> &mut Self {
        self.buf.resize(self.buf.len() + n, 0);
        self
    }

    /// Finish.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip_little_endian() {
        let mut w = Writer::new();
        w.u8(0x11)
            .u16(0x2233)
            .u32(0x44556677)
            .u64(0x8899AABBCCDDEEFF);
        let buf = w.finish();
        assert_eq!(buf[0..3], [0x11, 0x33, 0x22]);
        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), 0x11);
        assert_eq!(r.u16().unwrap(), 0x2233);
        assert_eq!(r.u32().unwrap(), 0x44556677);
        assert_eq!(r.u64().unwrap(), 0x8899AABBCCDDEEFF);
        assert!(r.is_empty());
    }

    #[test]
    fn reading_past_the_end_is_an_error_not_a_panic() {
        let body = [1u8, 2, 3];
        let mut r = Reader::new(&body);
        assert!(r.u32().is_err());
        assert_eq!(r.position(), 0, "a failed read must not consume");
    }

    #[test]
    fn a_pointer_offset_past_the_body_is_refused() {
        let body = [0u8; 8];
        let r = Reader::new(&body);
        assert!(r.at(9).is_err());
        assert!(r.at(8).is_ok(), "one past the end is an empty cursor");
    }

    #[test]
    fn a_null_pointer_reads_as_none() {
        let body = [0u8; 4];
        let mut r = Reader::new(&body);
        assert_eq!(r.pointer().unwrap(), None);
    }

    #[test]
    fn an_element_count_larger_than_the_body_is_refused_before_allocating() {
        let body = [0xFFu8; 8];
        let r = Reader::new(&body);
        assert!(r.count(u32::MAX, 16).is_err());
        assert_eq!(r.count(2, 4).unwrap(), 2);
    }
}
