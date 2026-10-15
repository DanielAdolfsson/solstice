//! The cursor channel.
//!
//! In **client** mouse mode the guest stops drawing its own pointer and sends
//! the shape instead, leaving the client to draw it. That is the mode
//! Solstice asks for, because Moonlight's natural input is absolute
//! (`docs/spice-protocol.md` §4.1) -- so the pointer has to be composited
//! into the framebuffer here or it disappears from the stream entirely.
//!
//! # Shapes
//!
//! Five of SPICE's seven cursor types are decoded. The two that are not,
//! `COLOR8` and `COLOR24`, are the two `spice-gtk` does not decode either
//! (`channel-cursor.c:302-305` falls through to "unimplemented cursor type"),
//! which means no server in practice emits them.
//!
//! The masked types all share a quirk worth naming: the AND mask that follows
//! the colour data is a **flat bit array of `width * height` bits, with no
//! per-row padding**, unlike every other 1-bit bitmap in the protocol.
//! `get_pix_mask` at `channel-cursor.c:196-199` indexes it that way, and it
//! is the reference client.
//!
//! Windows' fourth mono combination -- AND set and XOR set, meaning "invert
//! whatever is underneath" -- has no equivalent in a composited framebuffer
//! that is about to be H.264 encoded. `spice-gtk` substitutes a contrasting
//! colour; this draws those pixels opaque black, which is the same choice
//! with less machinery and the same effect on the only thing it is used for,
//! which is the one-pixel outline around an I-beam.

use std::collections::HashMap;

use crate::error::{Result, SpiceError};
use crate::protocol::{cursor_flags, cursor_type};
use crate::wire::Reader;

/// A decoded cursor shape, as premultiplied BGRA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CursorShape {
    /// Width in pixels.
    pub width: u16,
    /// Height in pixels.
    pub height: u16,
    /// Where the hot spot sits inside the shape.
    pub hot_x: u16,
    /// Where the hot spot sits inside the shape.
    pub hot_y: u16,
    /// `width * height` BGRA pixels, top row first.
    pub data: Vec<u8>,
}

impl CursorShape {
    /// The pixel at a position inside the shape.
    pub fn pixel(&self, x: u32, y: u32) -> Option<[u8; 4]> {
        if x >= self.width as u32 || y >= self.height as u32 {
            return None;
        }
        let offset = (y as usize * self.width as usize + x as usize) * 4;
        Some([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ])
    }
}

/// Where the pointer is and what it looks like.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CursorState {
    /// The shape, or `None` when there is none.
    pub shape: Option<std::sync::Arc<CursorShape>>,
    /// Hot-spot position in surface coordinates.
    pub x: i32,
    /// Hot-spot position in surface coordinates.
    pub y: i32,
    /// Whether to draw it at all.
    pub visible: bool,
}

impl CursorState {
    /// The rectangle the cursor occupies, in surface coordinates.
    pub fn bounds(&self) -> Option<crate::display::types::SpiceRect> {
        let shape = self.shape.as_ref()?;
        if !self.visible {
            return None;
        }
        let left = self.x - shape.hot_x as i32;
        let top = self.y - shape.hot_y as i32;
        Some(crate::display::types::SpiceRect {
            top,
            left,
            bottom: top + shape.height as i32,
            right: left + shape.width as i32,
        })
    }
}

/// What a cursor-channel message asks the display to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CursorUpdate {
    /// Replace the shape and position.
    Set {
        /// The new shape, or `None` for "no cursor".
        shape: Option<std::sync::Arc<CursorShape>>,
        /// Hot-spot position.
        x: i32,
        /// Hot-spot position.
        y: i32,
        /// Whether to draw it.
        visible: bool,
    },
    /// Move the existing shape.
    Move {
        /// Hot-spot position.
        x: i32,
        /// Hot-spot position.
        y: i32,
    },
    /// Stop drawing it.
    Hide,
    /// Forget the shape entirely.
    Reset,
}

/// The largest cursor this client will decode.
///
/// `width` and `height` are `u16` so the format already bounds this at
/// 65535 x 65535, which is 17 gigabytes. Real cursors are 32 x 32 or 64 x 64;
/// 256 x 256 is past anything a desktop uses.
pub const MAX_CURSOR_DIMENSION: u16 = 256;

/// The most cursor shapes held in the cache at once.
pub const MAX_CACHED_CURSORS: usize = 256;

/// The cursor channel's own state: the shape cache, and nothing else.
#[derive(Debug, Default)]
pub struct CursorChannel {
    cache: HashMap<u64, std::sync::Arc<CursorShape>>,
    order: std::collections::VecDeque<u64>,
}

impl CursorChannel {
    /// A new one.
    pub fn new() -> Self {
        CursorChannel::default()
    }

    /// Forget every cached shape.
    pub fn clear(&mut self) {
        self.cache.clear();
        self.order.clear();
    }

    /// Forget one.
    pub fn invalidate(&mut self, id: u64) {
        self.cache.remove(&id);
        self.order.retain(|&k| k != id);
    }

    /// Handle one message, returning what the display should do about it.
    pub fn handle(&mut self, kind: u16, body: &[u8]) -> Result<Option<CursorUpdate>> {
        use crate::protocol::cursor_msg;
        let mut r = Reader::new(body);
        match kind {
            cursor_msg::INIT => {
                let position = crate::display::types::Point::parse16(&mut r)?;
                let _trail_length = r.u16()?;
                let _trail_frequency = r.u16()?;
                let visible = r.u8()? != 0;
                let shape = self.parse_cursor(&mut r)?;
                Ok(Some(CursorUpdate::Set {
                    shape,
                    x: position.x,
                    y: position.y,
                    visible,
                }))
            }
            cursor_msg::SET => {
                let position = crate::display::types::Point::parse16(&mut r)?;
                let visible = r.u8()? != 0;
                let shape = self.parse_cursor(&mut r)?;
                Ok(Some(CursorUpdate::Set {
                    shape,
                    x: position.x,
                    y: position.y,
                    visible,
                }))
            }
            cursor_msg::MOVE => {
                let position = crate::display::types::Point::parse16(&mut r)?;
                Ok(Some(CursorUpdate::Move {
                    x: position.x,
                    y: position.y,
                }))
            }
            cursor_msg::HIDE => Ok(Some(CursorUpdate::Hide)),
            cursor_msg::RESET => {
                self.clear();
                Ok(Some(CursorUpdate::Reset))
            }
            cursor_msg::INVAL_ONE => {
                let id = r.u64()?;
                self.invalidate(id);
                Ok(None)
            }
            cursor_msg::INVAL_ALL => {
                self.clear();
                Ok(None)
            }
            // Trails are a server-rendered flourish with no client side.
            cursor_msg::TRAIL => Ok(None),
            other => {
                tracing::debug!(kind = other, "ignoring cursor message");
                Ok(None)
            }
        }
    }

    fn insert(&mut self, id: u64, shape: std::sync::Arc<CursorShape>) {
        if self.cache.insert(id, shape).is_none() {
            self.order.push_back(id);
        }
        while self.order.len() > MAX_CACHED_CURSORS {
            if let Some(oldest) = self.order.pop_front() {
                self.cache.remove(&oldest);
            }
        }
    }

    /// Parse a `struct Cursor` and decode its shape.
    fn parse_cursor(&mut self, r: &mut Reader<'_>) -> Result<Option<std::sync::Arc<CursorShape>>> {
        let flags = r.u16()?;
        if flags & cursor_flags::NONE != 0 {
            return Ok(None);
        }
        let unique = r.u64()?;
        let kind = r.u8()?;
        let width = r.u16()?;
        let height = r.u16()?;
        let hot_x = r.u16()?;
        let hot_y = r.u16()?;

        if flags & cursor_flags::FROM_CACHE != 0 {
            return self
                .cache
                .get(&unique)
                .cloned()
                .map(Some)
                .ok_or_else(|| SpiceError::protocol(format!("cursor {unique:#x} is not cached")));
        }

        if width == 0 || height == 0 {
            return Ok(None);
        }
        if width > MAX_CURSOR_DIMENSION || height > MAX_CURSOR_DIMENSION {
            return Err(SpiceError::limit(format!(
                "cursor of {width}x{height} exceeds {MAX_CURSOR_DIMENSION} on a side"
            )));
        }

        // The hot spot may legitimately sit on the far edge; past it is a
        // server bug, and `channel-cursor.c:263-274` caps rather than
        // refusing.
        let hot_x = hot_x.min(width);
        let hot_y = hot_y.min(height);

        let data = r.rest();
        let Some(pixels) = decode_shape(kind, width, height, data) else {
            tracing::debug!(kind, "ignoring a cursor in an undecodable type");
            return Ok(None);
        };
        let shape = std::sync::Arc::new(CursorShape {
            width,
            height,
            hot_x,
            hot_y,
            data: pixels,
        });
        if flags & cursor_flags::CACHE_ME != 0 {
            self.insert(unique, shape.clone());
        }
        Ok(Some(shape))
    }
}

/// Read bit `index` of a flat, unpadded, most-significant-bit-first bit
/// array starting at `offset`.
fn mask_bit(data: &[u8], offset: usize, index: usize) -> bool {
    data.get(offset + (index >> 3))
        .is_some_and(|byte| byte & (0x80 >> (index % 8)) != 0)
}

/// Decode a cursor's pixels into premultiplied BGRA, or `None` for a type
/// this client does not decode.
fn decode_shape(kind: u8, width: u16, height: u16, data: &[u8]) -> Option<Vec<u8>> {
    let count = width as usize * height as usize;
    let mut out = vec![0u8; count * 4];

    match kind {
        cursor_type::ALPHA => {
            // Already BGRA, already premultiplied. `spice-gtk` memcpys it and
            // then swaps the red and blue bytes for GdkPixbuf's sake; the
            // framebuffer here wants the order it arrived in.
            let need = count * 4;
            if data.len() < need {
                return None;
            }
            out.copy_from_slice(&data[..need]);
        }
        cursor_type::MONO => {
            // Two 1-bit planes, AND first then XOR, each row padded to a
            // whole byte -- the one masked type that *is* padded, because
            // `mono_cursor` walks it with a bytes-per-line stride.
            let bpl = (width as usize).div_ceil(8);
            let plane = bpl * height as usize;
            if data.len() < plane * 2 {
                return None;
            }
            for y in 0..height as usize {
                for x in 0..width as usize {
                    let byte = y * bpl + x / 8;
                    let bit = 0x80 >> (x % 8);
                    let and = data[byte] & bit != 0;
                    let xor = data[plane + byte] & bit != 0;
                    let offset = (y * width as usize + x) * 4;
                    let pixel = match (and, xor) {
                        (false, false) => [0, 0, 0, 0xFF],
                        (false, true) => [0xFF, 0xFF, 0xFF, 0xFF],
                        (true, false) => [0, 0, 0, 0],
                        // "Invert the destination": drawn opaque black.
                        (true, true) => [0, 0, 0, 0xFF],
                    };
                    out[offset..offset + 4].copy_from_slice(&pixel);
                }
            }
        }
        cursor_type::COLOR32 => {
            let colour_bytes = count * 4;
            if data.len() < colour_bytes {
                return None;
            }
            for i in 0..count {
                let transparent = mask_bit(data, colour_bytes, i);
                out[i * 4] = data[i * 4];
                out[i * 4 + 1] = data[i * 4 + 1];
                out[i * 4 + 2] = data[i * 4 + 2];
                out[i * 4 + 3] = if transparent { 0 } else { 0xFF };
            }
        }
        cursor_type::COLOR16 => {
            let colour_bytes = count * 2;
            if data.len() < colour_bytes {
                return None;
            }
            for i in 0..count {
                let transparent = mask_bit(data, colour_bytes, i);
                let value = u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]);
                let r = ((value >> 10) & 0x1F) as u8;
                let g = ((value >> 5) & 0x1F) as u8;
                let b = (value & 0x1F) as u8;
                out[i * 4] = (b << 3) | (b >> 2);
                out[i * 4 + 1] = (g << 3) | (g >> 2);
                out[i * 4 + 2] = (r << 3) | (r >> 2);
                out[i * 4 + 3] = if transparent { 0 } else { 0xFF };
            }
        }
        cursor_type::COLOR4 => {
            // 4 bits a pixel with rows padded to a whole byte, then a
            // 16-entry palette, then the mask.
            let row = (width as usize).div_ceil(2);
            let colour_bytes = row * height as usize;
            let palette_at = colour_bytes;
            if data.len() < palette_at + 64 {
                return None;
            }
            let mut palette = [0u32; 16];
            for (i, slot) in palette.iter_mut().enumerate() {
                let at = palette_at + i * 4;
                *slot = u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
            }
            let mask_at = palette_at + 64;
            for y in 0..height as usize {
                for x in 0..width as usize {
                    let i = y * width as usize + x;
                    let byte = data[y * row + x / 2];
                    let index = if x % 2 == 0 { byte >> 4 } else { byte & 0x0F };
                    let colour = palette[index as usize].to_le_bytes();
                    let transparent = mask_bit(data, mask_at, i);
                    out[i * 4] = colour[0];
                    out[i * 4 + 1] = colour[1];
                    out[i * 4 + 2] = colour[2];
                    out[i * 4 + 3] = if transparent { 0 } else { 0xFF };
                }
            }
        }
        // COLOR8 and COLOR24, which the reference client does not decode
        // either.
        _ => return None,
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::cursor_msg;
    use crate::wire::Writer;

    fn cursor_bytes(
        flags: u16,
        unique: u64,
        kind: u8,
        width: u16,
        height: u16,
        data: &[u8],
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(flags);
        if flags & cursor_flags::NONE == 0 {
            w.u64(unique).u8(kind).u16(width).u16(height).u16(0).u16(0);
            w.bytes(data);
        }
        w.finish()
    }

    fn set_message(cursor: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(10).u16(20).u8(1);
        w.bytes(cursor);
        w.finish()
    }

    #[test]
    fn an_alpha_cursor_arrives_already_in_bgra_order() {
        let mut channel = CursorChannel::new();
        let pixels = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let body = set_message(&cursor_bytes(0, 1, cursor_type::ALPHA, 2, 1, &pixels));
        let update = channel.handle(cursor_msg::SET, &body).unwrap().unwrap();
        let CursorUpdate::Set {
            shape,
            x,
            y,
            visible,
        } = update
        else {
            panic!("expected a set");
        };
        assert_eq!((x, y, visible), (10, 20, true));
        let shape = shape.unwrap();
        assert_eq!(shape.pixel(0, 0), Some([1, 2, 3, 4]));
        assert_eq!(shape.pixel(1, 0), Some([5, 6, 7, 8]));
        assert_eq!(shape.pixel(2, 0), None);
    }

    #[test]
    fn a_mono_cursor_reads_its_and_plane_then_its_xor_plane() {
        let mut channel = CursorChannel::new();
        // 2x1: AND = 0b01xxxxxx, XOR = 0b10xxxxxx.
        // Pixel 0: and=0 xor=1 -> opaque white. Pixel 1: and=1 xor=0 ->
        // transparent.
        let data = [0b0100_0000u8, 0b1000_0000u8];
        let body = set_message(&cursor_bytes(0, 1, cursor_type::MONO, 2, 1, &data));
        let CursorUpdate::Set { shape, .. } =
            channel.handle(cursor_msg::SET, &body).unwrap().unwrap()
        else {
            panic!("expected a set");
        };
        let shape = shape.unwrap();
        assert_eq!(shape.pixel(0, 0), Some([0xFF, 0xFF, 0xFF, 0xFF]));
        assert_eq!(shape.pixel(1, 0), Some([0, 0, 0, 0]));
    }

    #[test]
    fn a_color32_cursors_mask_bit_means_transparent() {
        let mut channel = CursorChannel::new();
        let mut data = vec![9u8, 9, 9, 0, 8, 8, 8, 0];
        // Flat mask: bit 0 set, bit 1 clear.
        data.push(0b1000_0000);
        let body = set_message(&cursor_bytes(0, 1, cursor_type::COLOR32, 2, 1, &data));
        let CursorUpdate::Set { shape, .. } =
            channel.handle(cursor_msg::SET, &body).unwrap().unwrap()
        else {
            panic!("expected a set");
        };
        let shape = shape.unwrap();
        assert_eq!(shape.pixel(0, 0), Some([9, 9, 9, 0]));
        assert_eq!(shape.pixel(1, 0), Some([8, 8, 8, 0xFF]));
    }

    #[test]
    fn a_cached_cursor_comes_back_by_id_and_an_uncached_one_is_an_error() {
        let mut channel = CursorChannel::new();
        let pixels = [1u8, 2, 3, 4];
        let body = set_message(&cursor_bytes(
            cursor_flags::CACHE_ME,
            42,
            cursor_type::ALPHA,
            1,
            1,
            &pixels,
        ));
        channel.handle(cursor_msg::SET, &body).unwrap();

        let from_cache = set_message(&cursor_bytes(
            cursor_flags::FROM_CACHE,
            42,
            cursor_type::ALPHA,
            1,
            1,
            &[],
        ));
        let CursorUpdate::Set { shape, .. } = channel
            .handle(cursor_msg::SET, &from_cache)
            .unwrap()
            .unwrap()
        else {
            panic!("expected a set");
        };
        assert_eq!(shape.unwrap().pixel(0, 0), Some([1, 2, 3, 4]));

        let missing = set_message(&cursor_bytes(
            cursor_flags::FROM_CACHE,
            43,
            cursor_type::ALPHA,
            1,
            1,
            &[],
        ));
        assert!(channel.handle(cursor_msg::SET, &missing).is_err());
    }

    #[test]
    fn the_none_flag_means_there_is_no_cursor() {
        let mut channel = CursorChannel::new();
        let body = set_message(&cursor_bytes(cursor_flags::NONE, 0, 0, 0, 0, &[]));
        let CursorUpdate::Set { shape, .. } =
            channel.handle(cursor_msg::SET, &body).unwrap().unwrap()
        else {
            panic!("expected a set");
        };
        assert!(shape.is_none());
    }

    #[test]
    fn a_cursor_past_the_dimension_ceiling_is_refused_before_allocating() {
        let mut channel = CursorChannel::new();
        let body = set_message(&cursor_bytes(0, 1, cursor_type::ALPHA, 4096, 4096, &[]));
        assert!(channel.handle(cursor_msg::SET, &body).is_err());
    }

    #[test]
    fn a_truncated_shape_is_dropped_rather_than_read_past() {
        let mut channel = CursorChannel::new();
        let body = set_message(&cursor_bytes(0, 1, cursor_type::ALPHA, 8, 8, &[0; 4]));
        let CursorUpdate::Set { shape, .. } =
            channel.handle(cursor_msg::SET, &body).unwrap().unwrap()
        else {
            panic!("expected a set");
        };
        assert!(shape.is_none());
    }

    #[test]
    fn an_undecodable_cursor_type_is_ignored_rather_than_fatal() {
        let mut channel = CursorChannel::new();
        let body = set_message(&cursor_bytes(0, 1, cursor_type::COLOR24, 2, 2, &[0; 64]));
        let CursorUpdate::Set { shape, .. } =
            channel.handle(cursor_msg::SET, &body).unwrap().unwrap()
        else {
            panic!("expected a set");
        };
        assert!(shape.is_none());
    }

    #[test]
    fn move_and_hide_carry_what_the_display_needs() {
        let mut channel = CursorChannel::new();
        let mut w = Writer::new();
        w.u16(7).u16(9);
        assert_eq!(
            channel.handle(cursor_msg::MOVE, &w.finish()).unwrap(),
            Some(CursorUpdate::Move { x: 7, y: 9 })
        );
        assert_eq!(
            channel.handle(cursor_msg::HIDE, &[]).unwrap(),
            Some(CursorUpdate::Hide)
        );
    }

    #[test]
    fn the_shape_cache_is_bounded() {
        let mut channel = CursorChannel::new();
        for id in 0..(MAX_CACHED_CURSORS as u64 + 10) {
            let body = set_message(&cursor_bytes(
                cursor_flags::CACHE_ME,
                id,
                cursor_type::ALPHA,
                1,
                1,
                &[1, 2, 3, 4],
            ));
            channel.handle(cursor_msg::SET, &body).unwrap();
        }
        assert!(channel.cache.len() <= MAX_CACHED_CURSORS);
    }

    #[test]
    fn the_cursor_bounds_sit_at_the_hot_spot() {
        let state = CursorState {
            shape: Some(std::sync::Arc::new(CursorShape {
                width: 10,
                height: 10,
                hot_x: 3,
                hot_y: 4,
                data: vec![0; 400],
            })),
            x: 100,
            y: 200,
            visible: true,
        };
        let bounds = state.bounds().unwrap();
        assert_eq!(bounds.left, 97);
        assert_eq!(bounds.top, 196);
        assert_eq!(bounds.right, 107);

        let hidden = CursorState {
            visible: false,
            ..state
        };
        assert_eq!(hidden.bounds(), None);
    }
}
