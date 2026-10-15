//! Moonlight input records to backend-neutral events.
//!
//! The keyboard path carries **both** representations: an XT scancode, which is
//! what the remote desktop should normally act on, and the US-layout keysym
//! alongside. Which one a backend uses is a property of the peer -- RFB servers
//! without pseudo-encoding -258 have only the keysym -- so the choice is made
//! at the backend edge and not here (`docs/bridging-design.md` §4.1).
//!
//! Controllers, touch and pen have no representation in RFB or SPICE. They are
//! dropped, and counted, because quietly swallowing input is the kind of thing
//! that generates bug reports.

use solstice_backend::{InputEvent, KeyEvent, MouseButton};
use solstice_input::{keysym, scancode, vk};

use crate::wire::input::{magic, InputRecord};

/// What a batch translated into, plus what it could not.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Translation {
    /// Events to forward to the backend.
    pub events: Vec<InputEvent>,
    /// Records dropped because the backend protocols have no equivalent.
    pub dropped: Vec<DroppedInput>,
}

/// A record that was understood but cannot be forwarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DroppedInput {
    /// Gamepad state, arrival, rumble, motion or battery.
    Controller,
    /// Touchscreen.
    Touch,
    /// Stylus.
    Pen,
    /// A key with no XT scancode *and* no keysym.
    UnmappableKey {
        /// The virtual-key code.
        key_code: u16,
    },
    /// A record type this build does not know.
    Unknown {
        /// Its magic.
        magic: u32,
    },
}

/// Translate one decoded batch.
pub fn translate(records: &[InputRecord]) -> Translation {
    let mut out = Translation::default();
    for record in records {
        match record {
            InputRecord::Key {
                down,
                flags,
                key_code,
                modifiers,
            } => {
                let extended = modifiers & vk::modifier::EXTENDED != 0;
                let shift = modifiers & vk::modifier::SHIFT != 0;
                let sc = scancode(*key_code, extended);
                let ks = keysym(*key_code, extended, shift);
                if sc.is_none() && ks.is_none() {
                    out.dropped.push(DroppedInput::UnmappableKey {
                        key_code: *key_code,
                    });
                    continue;
                }
                out.events.push(InputEvent::Key(KeyEvent {
                    scancode: sc,
                    keysym: ks,
                    down: *down,
                    non_normalized: flags & vk::KBE_FLAG_NON_NORMALIZED != 0,
                }));
            }
            InputRecord::Text(text) => {
                if !text.is_empty() {
                    out.events.push(InputEvent::Text(text.clone()));
                }
            }
            InputRecord::MouseMoveAbs {
                x,
                y,
                width,
                height,
            } => {
                // A reference geometry of zero would make the backend's scaling
                // divide by zero; the client should never send it, so drop it
                // rather than inventing a denominator.
                if *width == 0 || *height == 0 {
                    continue;
                }
                out.events.push(InputEvent::PointerAbsolute {
                    x: *x,
                    y: *y,
                    ref_width: *width,
                    ref_height: *height,
                });
            }
            InputRecord::MouseMoveRel { dx, dy } => {
                out.events
                    .push(InputEvent::PointerRelative { dx: *dx, dy: *dy });
            }
            InputRecord::MouseButton { down, button } => match MouseButton::from_wire(*button) {
                Some(button) => out.events.push(InputEvent::Button {
                    button,
                    down: *down,
                }),
                None => out.dropped.push(DroppedInput::Unknown {
                    magic: *button as u32,
                }),
            },
            InputRecord::Scroll { amount } => {
                out.events.push(InputEvent::Scroll {
                    vertical: *amount,
                    horizontal: 0,
                });
            }
            InputRecord::HScroll { amount } => {
                out.events.push(InputEvent::Scroll {
                    vertical: 0,
                    horizontal: *amount,
                });
            }
            InputRecord::Unsupported { magic, .. } => out.dropped.push(match *magic {
                magic::MULTI_CONTROLLER
                | magic::CONTROLLER_ARRIVAL
                | magic::CONTROLLER_TOUCH
                | magic::CONTROLLER_MOTION
                | magic::CONTROLLER_BATTERY => DroppedInput::Controller,
                magic::TOUCH => DroppedInput::Touch,
                magic::PEN => DroppedInput::Pen,
                other => DroppedInput::Unknown { magic: other },
            }),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_carries_both_representations() {
        let t = translate(&[InputRecord::Key {
            down: true,
            flags: 0,
            key_code: vk::RETURN,
            modifiers: vk::modifier::EXTENDED,
        }]);
        assert_eq!(
            t.events,
            vec![InputEvent::Key(KeyEvent {
                scancode: Some(0xE01C),
                keysym: Some(0xFF8D),
                down: true,
                non_normalized: false,
            })]
        );
    }

    /// The expectation `docs/testing.md` §3.2 states for the mock RFB server:
    /// the same event must be usable by a server with -258 and by one without.
    #[test]
    fn the_worked_example_from_the_testing_doc() {
        let t = translate(&[InputRecord::Key {
            down: true,
            flags: 0,
            key_code: vk::RETURN,
            modifiers: vk::modifier::EXTENDED,
        }]);
        let InputEvent::Key(k) = &t.events[0] else {
            panic!()
        };
        assert_eq!(k.scancode, Some(0xE01C));
        assert_eq!(k.keysym, Some(0xFF8D));
        assert!(k.down);
    }

    #[test]
    fn shift_changes_the_keysym_but_not_the_scancode() {
        let plain = translate(&[InputRecord::Key {
            down: true,
            flags: 0,
            key_code: b'2' as u16,
            modifiers: 0,
        }]);
        let shifted = translate(&[InputRecord::Key {
            down: true,
            flags: 0,
            key_code: b'2' as u16,
            modifiers: vk::modifier::SHIFT,
        }]);
        let (InputEvent::Key(a), InputEvent::Key(b)) = (&plain.events[0], &shifted.events[0])
        else {
            panic!()
        };
        assert_eq!(a.scancode, b.scancode);
        assert_eq!(a.keysym, Some(b'2' as u32));
        assert_eq!(b.keysym, Some(b'@' as u32));
    }

    #[test]
    fn the_non_normalized_flag_is_carried_through() {
        let t = translate(&[InputRecord::Key {
            down: true,
            flags: vk::KBE_FLAG_NON_NORMALIZED,
            key_code: b'A' as u16,
            modifiers: 0,
        }]);
        let InputEvent::Key(k) = &t.events[0] else {
            panic!()
        };
        assert!(k.non_normalized);
    }

    #[test]
    fn pointer_and_buttons_translate() {
        let t = translate(&[
            InputRecord::MouseMoveAbs {
                x: 960,
                y: 540,
                width: 1920,
                height: 1080,
            },
            InputRecord::MouseButton {
                down: true,
                button: 1,
            },
            InputRecord::MouseButton {
                down: false,
                button: 5,
            },
            InputRecord::MouseMoveRel { dx: -4, dy: 7 },
            InputRecord::Scroll { amount: 120 },
            InputRecord::HScroll { amount: -120 },
        ]);
        assert_eq!(
            t.events,
            vec![
                InputEvent::PointerAbsolute {
                    x: 960,
                    y: 540,
                    ref_width: 1920,
                    ref_height: 1080
                },
                InputEvent::Button {
                    button: MouseButton::Left,
                    down: true
                },
                InputEvent::Button {
                    button: MouseButton::X2,
                    down: false
                },
                InputEvent::PointerRelative { dx: -4, dy: 7 },
                InputEvent::Scroll {
                    vertical: 120,
                    horizontal: 0
                },
                InputEvent::Scroll {
                    vertical: 0,
                    horizontal: -120
                },
            ]
        );
        assert!(t.dropped.is_empty());
    }

    #[test]
    fn a_zero_reference_geometry_is_dropped_rather_than_dividing_by_zero() {
        let t = translate(&[InputRecord::MouseMoveAbs {
            x: 1,
            y: 1,
            width: 0,
            height: 1080,
        }]);
        assert!(t.events.is_empty());
    }

    /// Dropped, but counted -- not silently swallowed.
    #[test]
    fn controllers_touch_and_pen_are_reported_as_dropped() {
        let t = translate(&[
            InputRecord::Unsupported {
                magic: magic::MULTI_CONTROLLER,
                len: 24,
            },
            InputRecord::Unsupported {
                magic: magic::TOUCH,
                len: 32,
            },
            InputRecord::Unsupported {
                magic: magic::PEN,
                len: 32,
            },
            InputRecord::Unsupported {
                magic: magic::CONTROLLER_BATTERY,
                len: 8,
            },
            InputRecord::Unsupported {
                magic: 0xDEADBEEF,
                len: 1,
            },
        ]);
        assert!(t.events.is_empty());
        assert_eq!(
            t.dropped,
            vec![
                DroppedInput::Controller,
                DroppedInput::Touch,
                DroppedInput::Pen,
                DroppedInput::Controller,
                DroppedInput::Unknown { magic: 0xDEADBEEF },
            ]
        );
    }

    #[test]
    fn an_unmappable_key_is_reported() {
        let t = translate(&[InputRecord::Key {
            down: true,
            flags: 0,
            key_code: 0x00,
            modifiers: 0,
        }]);
        assert!(t.events.is_empty());
        assert_eq!(t.dropped, vec![DroppedInput::UnmappableKey { key_code: 0 }]);
    }

    #[test]
    fn an_empty_text_event_produces_nothing() {
        let t = translate(&[InputRecord::Text(String::new())]);
        assert!(t.events.is_empty());
        assert!(t.dropped.is_empty());
    }

    /// Every VK a client can send must either translate or be reported.
    #[test]
    fn no_key_is_silently_lost() {
        for key_code in 0u16..=0xFFu16 {
            for modifiers in [0u8, vk::modifier::EXTENDED] {
                let t = translate(&[InputRecord::Key {
                    down: true,
                    flags: 0,
                    key_code,
                    modifiers,
                }]);
                assert_eq!(t.events.len() + t.dropped.len(), 1, "vk {key_code:#x}");
            }
        }
    }
}
