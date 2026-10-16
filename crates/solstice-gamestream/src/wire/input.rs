//! The `0x0206` input batch decoder (`Input.h`, `InputStream.c`).
//!
//! A single control message carries a *batch* of magic-prefixed records, each
//! introduced by an `NV_INPUT_HEADER`:
//!
//! ```text
//! u32be size    // bytes that follow, magic included
//! u32le magic
//! ... body ...
//! ```
//!
//! Three published Sunshine advisories live in this parser -- an out-of-bounds
//! heap write (GHSA-26q2-58j6-qmvv), bad Unicode handling
//! (GHSA-6w33-pjh7-p77c) and length confusion. Rust removes the memory-safety
//! half; the rest is policy, implemented here as: every length is checked
//! against what remains, an unknown record is skipped by its own declared
//! length rather than guessed at, and the **whole batch is rejected on the
//! first malformed record** (`docs/security.md` §3).

use super::{Reader, Result, WireError};

/// Longest UTF-8 text event accepted (`NV_UNICODE_PACKET`).
pub const MAX_TEXT_BYTES: usize = 32;

/// Record magics, little-endian on the wire.
pub mod magic {
    #![allow(missing_docs)]
    pub const KEY_DOWN: u32 = 0x0000_0003;
    pub const KEY_UP: u32 = 0x0000_0004;
    pub const MOUSE_MOVE_ABS: u32 = 0x0000_0005;
    pub const MOUSE_MOVE_REL: u32 = 0x0000_0007;
    pub const MOUSE_BUTTON_DOWN: u32 = 0x0000_0008;
    pub const MOUSE_BUTTON_UP: u32 = 0x0000_0009;
    pub const SCROLL: u32 = 0x0000_000A;
    pub const MULTI_CONTROLLER: u32 = 0x0000_000C;
    pub const UTF8_TEXT: u32 = 0x0000_0017;
    pub const HSCROLL: u32 = 0x5500_0001;
    pub const TOUCH: u32 = 0x5500_0002;
    pub const PEN: u32 = 0x5500_0003;
    pub const CONTROLLER_ARRIVAL: u32 = 0x5500_0004;
    pub const CONTROLLER_TOUCH: u32 = 0x5500_0005;
    pub const CONTROLLER_MOTION: u32 = 0x5500_0006;
    pub const CONTROLLER_BATTERY: u32 = 0x5500_0007;
}

/// One decoded input record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputRecord {
    /// Key press or release. `key_code` is a Windows virtual-key code under a
    /// US-English layout assumption.
    Key {
        /// True for a press.
        down: bool,
        /// `SS_KBE_FLAG_*`.
        flags: u8,
        /// Windows virtual-key code.
        key_code: u16,
        /// `MODIFIER_*` bits, including `EXTENDED`.
        modifiers: u8,
    },
    /// Absolute pointer position, with the geometry it is relative to.
    MouseMoveAbs {
        /// X in reference coordinates.
        x: i16,
        /// Y in reference coordinates.
        y: i16,
        /// Reference width.
        width: u16,
        /// Reference height.
        height: u16,
    },
    /// Relative pointer motion; only sent when the client has captured the
    /// pointer.
    MouseMoveRel {
        /// Horizontal delta.
        dx: i16,
        /// Vertical delta.
        dy: i16,
    },
    /// Mouse button transition. Button numbering is `Limelight.h:687-691`.
    MouseButton {
        /// True for a press.
        down: bool,
        /// 1..=5.
        button: u8,
    },
    /// Wheel motion in 120-per-detent units.
    Scroll {
        /// Positive is up.
        amount: i16,
    },
    /// Horizontal wheel motion (Sunshine extension).
    HScroll {
        /// Positive is right.
        amount: i16,
    },
    /// A UTF-8 text event. Validated here, so the rest of the system never sees
    /// invalid UTF-8 (GHSA-6w33-pjh7-p77c).
    Text(String),
    /// A record we understand the framing of but deliberately do not act on:
    /// controllers, touch and pen have no representation in RFB or SPICE
    /// (`docs/bridging-design.md` §4.3).
    Unsupported {
        /// The record's magic.
        magic: u32,
        /// Its length in bytes, body only.
        len: usize,
    },
}

/// Decode a `0x0206` payload into records.
///
/// Returns an error -- and no records at all -- if any record in the batch is
/// malformed.
pub fn decode_batch(payload: &[u8]) -> Result<Vec<InputRecord>> {
    let mut out = Vec::new();
    let mut r = Reader::new(payload);
    while !r.is_empty() {
        // A trailing run of padding zeroes is not a record; anything shorter
        // than a header with a nonzero byte in it is malformed.
        if r.remaining() < 8 {
            return Err(WireError::Truncated {
                need: 8,
                have: r.remaining(),
            });
        }
        let size = r.u32be()? as usize;
        if size < 4 {
            return Err(WireError::InvalidField {
                field: "input record size",
                value: size as u64,
            });
        }
        let record = r.take(size - 4 + 4).map_err(|_| WireError::LengthOverrun {
            claimed: size,
            available: r.remaining(),
        })?;
        let mut rr = Reader::new(record);
        let magic = rr.u32le()?;
        out.push(decode_record(magic, &mut rr)?);
    }
    Ok(out)
}

fn decode_record(magic: u32, r: &mut Reader<'_>) -> Result<InputRecord> {
    Ok(match magic {
        magic::KEY_DOWN | magic::KEY_UP => {
            let flags = r.u8()?;
            // keyCode is written without a byte swap by the client, so it is
            // little-endian on every platform Moonlight runs on.
            let key_code = r.u16le()?;
            let modifiers = r.u8()?;
            InputRecord::Key {
                down: magic == magic::KEY_DOWN,
                flags,
                key_code,
                modifiers,
            }
        }
        magic::MOUSE_MOVE_ABS => InputRecord::MouseMoveAbs {
            x: r.i16be()?,
            y: r.i16be()?,
            // `unused`
            width: {
                r.skip(2)?;
                r.u16be()?
            },
            height: r.u16be()?,
        },
        magic::MOUSE_MOVE_REL => InputRecord::MouseMoveRel {
            dx: r.i16be()?,
            dy: r.i16be()?,
        },
        magic::MOUSE_BUTTON_DOWN | magic::MOUSE_BUTTON_UP => InputRecord::MouseButton {
            down: magic == magic::MOUSE_BUTTON_DOWN,
            button: r.u8()?,
        },
        // `NV_SCROLL_PACKET` is `scrollAmt1`, `scrollAmt2` (a copy) and
        // `zero3`, straight after the header (`Input.h:113-118`). There is no
        // padding byte in front: one was assumed here once, which read every
        // real client's 120 as 0x7800, and the encoder below agreed with it.
        // Caught by the captured session (`docs/roadmap.md` §4).
        magic::SCROLL => InputRecord::Scroll { amount: r.i16be()? },
        magic::HSCROLL => InputRecord::HScroll { amount: r.i16be()? },
        magic::UTF8_TEXT => {
            let bytes = r.peek_rest();
            if bytes.len() > MAX_TEXT_BYTES {
                return Err(WireError::LengthOverrun {
                    claimed: bytes.len(),
                    available: MAX_TEXT_BYTES,
                });
            }
            let text = std::str::from_utf8(bytes)
                .map_err(|_| WireError::InvalidUtf8("NV_UNICODE_PACKET"))?;
            InputRecord::Text(text.to_owned())
        }
        other => InputRecord::Unsupported {
            magic: other,
            len: r.remaining(),
        },
    })
}

/// Encode one record the way a client would. Test support, and the only reason
/// the hostile-client mock can be written in Rust.
pub fn encode_record(record: &InputRecord) -> Vec<u8> {
    let mut body = Vec::new();
    let magic = match record {
        InputRecord::Key {
            down,
            flags,
            key_code,
            modifiers,
        } => {
            body.push(*flags);
            body.extend_from_slice(&key_code.to_le_bytes());
            body.push(*modifiers);
            body.extend_from_slice(&0u16.to_le_bytes());
            if *down {
                magic::KEY_DOWN
            } else {
                magic::KEY_UP
            }
        }
        InputRecord::MouseMoveAbs {
            x,
            y,
            width,
            height,
        } => {
            body.extend_from_slice(&x.to_be_bytes());
            body.extend_from_slice(&y.to_be_bytes());
            body.extend_from_slice(&0u16.to_be_bytes());
            body.extend_from_slice(&width.to_be_bytes());
            body.extend_from_slice(&height.to_be_bytes());
            magic::MOUSE_MOVE_ABS
        }
        InputRecord::MouseMoveRel { dx, dy } => {
            body.extend_from_slice(&dx.to_be_bytes());
            body.extend_from_slice(&dy.to_be_bytes());
            magic::MOUSE_MOVE_REL
        }
        InputRecord::MouseButton { down, button } => {
            body.push(*button);
            if *down {
                magic::MOUSE_BUTTON_DOWN
            } else {
                magic::MOUSE_BUTTON_UP
            }
        }
        InputRecord::Scroll { amount } => {
            body.extend_from_slice(&amount.to_be_bytes());
            body.extend_from_slice(&amount.to_be_bytes());
            body.extend_from_slice(&0u16.to_be_bytes());
            magic::SCROLL
        }
        InputRecord::HScroll { amount } => {
            body.extend_from_slice(&amount.to_be_bytes());
            magic::HSCROLL
        }
        InputRecord::Text(s) => {
            body.extend_from_slice(s.as_bytes());
            magic::UTF8_TEXT
        }
        InputRecord::Unsupported { magic, len } => {
            body.resize(*len, 0);
            *magic
        }
    };
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(&magic.to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Encode a whole batch.
pub fn encode_batch(records: &[InputRecord]) -> Vec<u8> {
    records.iter().flat_map(encode_record).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(records: Vec<InputRecord>) {
        let encoded = encode_batch(&records);
        assert_eq!(decode_batch(&encoded).unwrap(), records);
    }

    #[test]
    fn every_record_kind_round_trips() {
        roundtrip(vec![
            InputRecord::Key {
                down: true,
                flags: 0,
                key_code: 0x0D,
                modifiers: 0x10,
            },
            InputRecord::Key {
                down: false,
                flags: 1,
                key_code: 0x41,
                modifiers: 0x01,
            },
            InputRecord::MouseMoveAbs {
                x: 100,
                y: -5,
                width: 1920,
                height: 1080,
            },
            InputRecord::MouseMoveRel { dx: -3, dy: 4 },
            InputRecord::MouseButton {
                down: true,
                button: 1,
            },
            InputRecord::Scroll { amount: -120 },
            InputRecord::HScroll { amount: 120 },
            InputRecord::Text("hej hopp".to_owned()),
        ]);
    }

    #[test]
    fn a_batch_decodes_in_order() {
        let records = vec![
            InputRecord::MouseButton {
                down: true,
                button: 1,
            },
            InputRecord::MouseMoveRel { dx: 1, dy: 1 },
            InputRecord::MouseButton {
                down: false,
                button: 1,
            },
        ];
        roundtrip(records);
    }

    #[test]
    fn unknown_records_are_skipped_by_their_declared_length() {
        let batch = encode_batch(&[
            InputRecord::Unsupported {
                magic: magic::MULTI_CONTROLLER,
                len: 24,
            },
            InputRecord::MouseButton {
                down: true,
                button: 3,
            },
        ]);
        let decoded = decode_batch(&batch).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(
            decoded[0],
            InputRecord::Unsupported {
                magic: magic::MULTI_CONTROLLER,
                len: 24
            }
        );
        assert_eq!(
            decoded[1],
            InputRecord::MouseButton {
                down: true,
                button: 3
            }
        );
    }

    /// GHSA-26q2-58j6-qmvv in shape: a size field larger than the data.
    #[test]
    fn a_size_field_that_overruns_rejects_the_whole_batch() {
        let mut batch = encode_batch(&[InputRecord::MouseButton {
            down: true,
            button: 1,
        }]);
        batch[0..4].copy_from_slice(&999u32.to_be_bytes());
        assert!(decode_batch(&batch).is_err());
    }

    /// The bytes `LiSendScrollEvent(-1)` produces (`InputStream.c:1225-1234`):
    /// a big-endian size of 10, the little-endian magic, then -120 twice and
    /// a zero.
    #[test]
    fn scroll_matches_the_reference_clients_layout() {
        let wire = [
            0x00, 0x00, 0x00, 0x0A, 0x0A, 0x00, 0x00, 0x00, 0xFF, 0x88, 0xFF, 0x88, 0x00, 0x00,
        ];
        assert_eq!(
            decode_batch(&wire).unwrap(),
            [InputRecord::Scroll { amount: -120 }]
        );
        assert_eq!(encode_batch(&[InputRecord::Scroll { amount: -120 }]), wire);
    }

    #[test]
    fn a_zero_size_field_is_rejected_rather_than_looping_forever() {
        let mut batch = Vec::new();
        batch.extend_from_slice(&0u32.to_be_bytes());
        batch.extend_from_slice(&magic::SCROLL.to_le_bytes());
        assert!(decode_batch(&batch).is_err());
    }

    /// GHSA-6w33-pjh7-p77c: invalid Unicode must not escape the parser.
    #[test]
    fn invalid_utf8_text_is_rejected() {
        let mut batch = Vec::new();
        let body = [0xF0u8, 0x28, 0x8C, 0x28]; // invalid UTF-8
        batch.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        batch.extend_from_slice(&magic::UTF8_TEXT.to_le_bytes());
        batch.extend_from_slice(&body);
        assert_eq!(
            decode_batch(&batch).unwrap_err(),
            WireError::InvalidUtf8("NV_UNICODE_PACKET")
        );
    }

    #[test]
    fn over_long_text_is_rejected() {
        let mut batch = Vec::new();
        let body = vec![b'a'; MAX_TEXT_BYTES + 1];
        batch.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        batch.extend_from_slice(&magic::UTF8_TEXT.to_le_bytes());
        batch.extend_from_slice(&body);
        assert!(decode_batch(&batch).is_err());
    }

    /// The decoder must terminate and never panic, whatever it is fed. This is
    /// the property the `input_batch` fuzz target checks continuously; running
    /// a deterministic sweep here keeps it honest between fuzz runs.
    #[test]
    fn every_truncation_of_a_valid_batch_is_handled() {
        let batch = encode_batch(&[
            InputRecord::Key {
                down: true,
                flags: 0,
                key_code: 0x41,
                modifiers: 0,
            },
            InputRecord::Text("abc".into()),
            InputRecord::MouseMoveAbs {
                x: 1,
                y: 2,
                width: 3,
                height: 4,
            },
        ]);
        for n in 0..batch.len() {
            let _ = decode_batch(&batch[..n]);
        }
        assert!(decode_batch(&batch).is_ok());
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0x12345678u32;
        for _ in 0..2000 {
            let len = (state % 64) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                buf.push((state >> 16) as u8);
            }
            let _ = decode_batch(&buf);
        }
    }
}
