//! Backend-neutral input to RFB messages.
//!
//! Two things make this more than a lookup table.
//!
//! **RFB has no press or release for the pointer** -- it has a *button mask*,
//! and every change, motion included, is a full `PointerEvent` carrying the
//! current mask and position. So the mask and the cursor position are state
//! this module owns.
//!
//! **Scrolling is modelled as a momentary press and release** of mask bits 3
//! through 6, which means one scroll event becomes two messages.
//!
//! The keyboard picks its representation from what the server supports:
//! pseudo-encoding -258 if it advertised it, the US-layout keysym otherwise.
//! That fallback is not hypothetical -- libvncserver, and therefore `x11vnc`,
//! implements QEMU extended key events in its *client* only
//! (`docs/bridging-design.md` §4.1).

use solstice_backend::{InputEvent, KeyEvent, MouseButton};
use solstice_input::keysym::unicode_keysym;

use crate::protocol::client_msg;

/// RFB button-mask bits (`rfbproto.rst:1944-1955`).
pub mod button_bit {
    #![allow(missing_docs)]
    pub const LEFT: u8 = 1 << 0;
    pub const MIDDLE: u8 = 1 << 1;
    pub const RIGHT: u8 = 1 << 2;
    pub const SCROLL_UP: u8 = 1 << 3;
    pub const SCROLL_DOWN: u8 = 1 << 4;
    pub const SCROLL_LEFT: u8 = 1 << 5;
    pub const SCROLL_RIGHT: u8 = 1 << 6;
    pub const BACK: u8 = 1 << 7;
}

/// Pointer and keyboard state for one connection.
#[derive(Clone, Debug)]
pub struct InputState {
    buttons: u8,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    /// Whether the server advertised pseudo-encoding -258.
    pub qemu_extended_key: bool,
}

impl InputState {
    /// Start centred in a `width` x `height` framebuffer.
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            buttons: 0,
            x: width / 2,
            y: height / 2,
            width: width.max(1),
            height: height.max(1),
            qemu_extended_key: false,
        }
    }

    /// Update the framebuffer geometry after a resize.
    pub fn resize(&mut self, width: u32, height: u32) {
        self.width = width.max(1);
        self.height = height.max(1);
        self.x = self.x.min(self.width - 1);
        self.y = self.y.min(self.height - 1);
    }

    /// Current pointer position.
    pub fn position(&self) -> (u32, u32) {
        (self.x, self.y)
    }

    /// Current button mask.
    pub fn buttons(&self) -> u8 {
        self.buttons
    }

    /// Translate one event into the RFB messages it becomes.
    pub fn encode(&mut self, event: &InputEvent) -> Vec<Vec<u8>> {
        match event {
            InputEvent::Key(key) => self.key(key),
            InputEvent::Text(text) => text
                .chars()
                .flat_map(|c| {
                    let ks = unicode_keysym(c);
                    [key_event(true, ks), key_event(false, ks)]
                })
                .collect(),
            InputEvent::PointerAbsolute {
                x,
                y,
                ref_width,
                ref_height,
            } => {
                if *ref_width == 0 || *ref_height == 0 {
                    return Vec::new();
                }
                // The packet carries its own reference geometry, so the
                // conversion is exact rather than a guess
                // (`docs/bridging-design.md` §4.2).
                let x = (*x).max(0) as u64 * self.width as u64 / *ref_width as u64;
                let y = (*y).max(0) as u64 * self.height as u64 / *ref_height as u64;
                self.x = (x as u32).min(self.width - 1);
                self.y = (y as u32).min(self.height - 1);
                vec![self.pointer_event(self.buttons)]
            }
            InputEvent::PointerRelative { dx, dy } => {
                // RFB has no relative motion, so it is accumulated here.
                self.x = (self.x as i64 + *dx as i64).clamp(0, self.width as i64 - 1) as u32;
                self.y = (self.y as i64 + *dy as i64).clamp(0, self.height as i64 - 1) as u32;
                vec![self.pointer_event(self.buttons)]
            }
            InputEvent::Button { button, down } => {
                let Some(bit) = button_mask(*button) else {
                    // X2 has no RFB button; dropping it is better than
                    // pressing the wrong one.
                    return Vec::new();
                };
                if *down {
                    self.buttons |= bit;
                } else {
                    self.buttons &= !bit;
                }
                vec![self.pointer_event(self.buttons)]
            }
            InputEvent::Scroll {
                vertical,
                horizontal,
            } => {
                let mut out = Vec::new();
                for (amount, positive, negative) in [
                    (*vertical, button_bit::SCROLL_UP, button_bit::SCROLL_DOWN),
                    (
                        *horizontal,
                        button_bit::SCROLL_RIGHT,
                        button_bit::SCROLL_LEFT,
                    ),
                ] {
                    if amount == 0 {
                        continue;
                    }
                    let bit = if amount > 0 { positive } else { negative };
                    // Moonlight sends 120 units per detent; one detent is one
                    // click of the wheel.
                    let clicks = (amount.unsigned_abs() as u32).div_ceil(120).clamp(1, 16);
                    for _ in 0..clicks {
                        out.push(self.pointer_event(self.buttons | bit));
                        out.push(self.pointer_event(self.buttons));
                    }
                }
                out
            }
            _ => Vec::new(),
        }
    }

    fn key(&self, key: &KeyEvent) -> Vec<Vec<u8>> {
        // On the non-normalised flag the client could not produce a US-layout
        // scancode, so the keysym is the trustworthy field even where the
        // server supports -258.
        let prefer_scancode = self.qemu_extended_key && !key.non_normalized;
        match (
            prefer_scancode.then_some(key.scancode).flatten(),
            key.keysym,
        ) {
            (Some(scancode), keysym) => {
                vec![qemu_key_event(key.down, keysym.unwrap_or(0), scancode)]
            }
            (None, Some(keysym)) => vec![key_event(key.down, keysym)],
            (None, None) => Vec::new(),
        }
    }

    fn pointer_event(&self, mask: u8) -> Vec<u8> {
        let mut out = vec![client_msg::POINTER_EVENT, mask];
        out.extend_from_slice(&(self.x.min(u16::MAX as u32) as u16).to_be_bytes());
        out.extend_from_slice(&(self.y.min(u16::MAX as u32) as u16).to_be_bytes());
        out
    }
}

fn button_mask(button: MouseButton) -> Option<u8> {
    Some(match button {
        MouseButton::Left => button_bit::LEFT,
        MouseButton::Middle => button_bit::MIDDLE,
        MouseButton::Right => button_bit::RIGHT,
        MouseButton::X1 => button_bit::BACK,
        // There is no eighth mask bit left for X2.
        MouseButton::X2 => return None,
    })
}

/// Build a `KeyEvent` message.
pub fn key_event(down: bool, keysym: u32) -> Vec<u8> {
    let mut out = vec![client_msg::KEY_EVENT, u8::from(down), 0, 0];
    out.extend_from_slice(&keysym.to_be_bytes());
    out
}

/// Build a QEMU Extended Key Event message (255 / submessage 0).
pub fn qemu_key_event(down: bool, keysym: u32, keycode: u16) -> Vec<u8> {
    let mut out = vec![client_msg::QEMU, client_msg::QEMU_SUB_EXTENDED_KEY];
    out.extend_from_slice(&u16::from(down).to_be_bytes());
    out.extend_from_slice(&keysym.to_be_bytes());
    out.extend_from_slice(&(keycode as u32).to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use solstice_input::vk;

    fn state(qemu: bool) -> InputState {
        let mut s = InputState::new(1920, 1080);
        s.qemu_extended_key = qemu;
        s
    }

    fn key(scancode: Option<u16>, keysym: Option<u32>) -> InputEvent {
        InputEvent::Key(KeyEvent {
            scancode,
            keysym,
            down: true,
            non_normalized: false,
        })
    }

    /// The worked example from `docs/testing.md` §3.2, both halves.
    #[test]
    fn the_same_key_takes_either_path_depending_on_the_server() {
        let event = key(Some(0xE01C), Some(0xFF8D)); // VK_RETURN + EXTENDED

        let with_258 = state(true).encode(&event);
        assert_eq!(with_258.len(), 1);
        assert_eq!(with_258[0][0], client_msg::QEMU);
        assert_eq!(with_258[0][1], 0);
        assert_eq!(&with_258[0][2..4], &1u16.to_be_bytes()); // down
        assert_eq!(&with_258[0][8..12], &0xE01Cu32.to_be_bytes()); // keycode

        let without = state(false).encode(&event);
        assert_eq!(without.len(), 1);
        assert_eq!(without[0][0], client_msg::KEY_EVENT);
        assert_eq!(&without[0][4..8], &0xFF8Du32.to_be_bytes()); // KP_Enter
    }

    #[test]
    fn a_non_normalised_key_takes_the_keysym_path_even_with_258() {
        let event = InputEvent::Key(KeyEvent {
            scancode: Some(0x1E),
            keysym: Some(b'a' as u32),
            down: true,
            non_normalized: true,
        });
        let msgs = state(true).encode(&event);
        assert_eq!(msgs[0][0], client_msg::KEY_EVENT);
    }

    #[test]
    fn a_key_with_neither_representation_produces_nothing() {
        assert!(state(true).encode(&key(None, None)).is_empty());
    }

    #[test]
    fn a_key_with_only_a_keysym_still_works_against_a_258_server() {
        let msgs = state(true).encode(&key(None, Some(0xFF08)));
        assert_eq!(msgs[0][0], client_msg::KEY_EVENT);
    }

    /// The absolute-mouse packet carries its own reference geometry, so the
    /// conversion is exact.
    #[test]
    fn absolute_pointer_scaling_is_exact() {
        let mut s = state(false);
        s.encode(&InputEvent::PointerAbsolute {
            x: 640,
            y: 360,
            ref_width: 1280,
            ref_height: 720,
        });
        assert_eq!(s.position(), (960, 540));

        // A client reporting the same geometry as the framebuffer is identity.
        let mut s = InputState::new(1280, 720);
        s.encode(&InputEvent::PointerAbsolute {
            x: 17,
            y: 23,
            ref_width: 1280,
            ref_height: 720,
        });
        assert_eq!(s.position(), (17, 23));
    }

    #[test]
    fn pointer_coordinates_are_clamped_to_the_framebuffer() {
        let mut s = InputState::new(100, 100);
        s.encode(&InputEvent::PointerAbsolute {
            x: 9999,
            y: 9999,
            ref_width: 100,
            ref_height: 100,
        });
        assert_eq!(s.position(), (99, 99));
        s.encode(&InputEvent::PointerAbsolute {
            x: -50,
            y: -50,
            ref_width: 100,
            ref_height: 100,
        });
        assert_eq!(s.position(), (0, 0));
    }

    #[test]
    fn relative_motion_is_accumulated_because_rfb_has_none() {
        let mut s = InputState::new(100, 100);
        assert_eq!(s.position(), (50, 50));
        s.encode(&InputEvent::PointerRelative { dx: 10, dy: -5 });
        assert_eq!(s.position(), (60, 45));
        s.encode(&InputEvent::PointerRelative {
            dx: -1000,
            dy: 1000,
        });
        assert_eq!(s.position(), (0, 99));
    }

    /// RFB has a mask, not press and release, so the mask is state.
    #[test]
    fn the_button_mask_is_maintained_across_events() {
        let mut s = state(false);
        let down = |b| InputEvent::Button {
            button: b,
            down: true,
        };
        let up = |b| InputEvent::Button {
            button: b,
            down: false,
        };

        let msgs = s.encode(&down(MouseButton::Left));
        assert_eq!(msgs[0][1], button_bit::LEFT);
        let msgs = s.encode(&down(MouseButton::Right));
        assert_eq!(msgs[0][1], button_bit::LEFT | button_bit::RIGHT);
        let msgs = s.encode(&up(MouseButton::Left));
        assert_eq!(msgs[0][1], button_bit::RIGHT);

        // Motion while a button is held carries the mask with it.
        let msgs = s.encode(&InputEvent::PointerRelative { dx: 1, dy: 1 });
        assert_eq!(msgs[0][1], button_bit::RIGHT);
    }

    #[test]
    fn x1_maps_to_back_and_x2_is_dropped() {
        let mut s = state(false);
        let msgs = s.encode(&InputEvent::Button {
            button: MouseButton::X1,
            down: true,
        });
        assert_eq!(msgs[0][1], button_bit::BACK);
        assert!(s
            .encode(&InputEvent::Button {
                button: MouseButton::X2,
                down: true
            })
            .is_empty());
        // The dropped button did not disturb the mask.
        assert_eq!(s.buttons(), button_bit::BACK);
    }

    /// Scrolling is a momentary press *and release*.
    #[test]
    fn scrolling_presses_and_releases() {
        let mut s = state(false);
        let msgs = s.encode(&InputEvent::Scroll {
            vertical: 120,
            horizontal: 0,
        });
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0][1], button_bit::SCROLL_UP);
        assert_eq!(msgs[1][1], 0);

        let msgs = s.encode(&InputEvent::Scroll {
            vertical: -120,
            horizontal: 0,
        });
        assert_eq!(msgs[0][1], button_bit::SCROLL_DOWN);

        let msgs = s.encode(&InputEvent::Scroll {
            vertical: 0,
            horizontal: -120,
        });
        assert_eq!(msgs[0][1], button_bit::SCROLL_LEFT);
    }

    #[test]
    fn scrolling_while_a_button_is_held_keeps_the_button() {
        let mut s = state(false);
        s.encode(&InputEvent::Button {
            button: MouseButton::Left,
            down: true,
        });
        let msgs = s.encode(&InputEvent::Scroll {
            vertical: 120,
            horizontal: 0,
        });
        assert_eq!(msgs[0][1], button_bit::LEFT | button_bit::SCROLL_UP);
        assert_eq!(msgs[1][1], button_bit::LEFT);
    }

    #[test]
    fn multiple_detents_become_multiple_clicks() {
        let mut s = state(false);
        let msgs = s.encode(&InputEvent::Scroll {
            vertical: 360,
            horizontal: 0,
        });
        assert_eq!(msgs.len(), 6); // three press/release pairs
    }

    #[test]
    fn a_zero_scroll_produces_nothing() {
        let mut s = state(false);
        assert!(s
            .encode(&InputEvent::Scroll {
                vertical: 0,
                horizontal: 0
            })
            .is_empty());
    }

    /// Text events have no scancode representation at all, so they are typed as
    /// Unicode keysyms.
    #[test]
    fn text_becomes_keysym_pairs() {
        let mut s = state(true);
        let msgs = s.encode(&InputEvent::Text("hej".into()));
        assert_eq!(msgs.len(), 6);
        assert!(msgs.iter().all(|m| m[0] == client_msg::KEY_EVENT));
        assert_eq!(&msgs[0][4..8], &(b'h' as u32).to_be_bytes());
        assert_eq!(msgs[0][1], 1); // down
        assert_eq!(msgs[1][1], 0); // up
    }

    #[test]
    fn non_ascii_text_uses_the_unicode_keysym_convention() {
        let mut s = state(false);
        let msgs = s.encode(&InputEvent::Text("€".into()));
        assert_eq!(&msgs[0][4..8], &0x0100_20ACu32.to_be_bytes());
    }

    #[test]
    fn a_resize_clamps_the_cursor_inside_the_new_framebuffer() {
        let mut s = InputState::new(1920, 1080);
        s.encode(&InputEvent::PointerAbsolute {
            x: 1900,
            y: 1070,
            ref_width: 1920,
            ref_height: 1080,
        });
        s.resize(640, 480);
        assert_eq!(s.position(), (639, 479));
    }

    /// Table-driven over the whole VK space, both paths, as
    /// `docs/testing.md` §3.2 asks for.
    #[test]
    fn every_vk_produces_a_well_formed_message_on_both_paths() {
        for vk_code in 0u16..=0xFFu16 {
            for extended in [false, true] {
                let scancode = solstice_input::scancode(vk_code, extended);
                let ks = solstice_input::keysym(vk_code, extended, false);
                let event = key(scancode, ks);
                for qemu in [false, true] {
                    for msg in state(qemu).encode(&event) {
                        match msg[0] {
                            client_msg::QEMU => assert_eq!(msg.len(), 12),
                            client_msg::KEY_EVENT => assert_eq!(msg.len(), 8),
                            other => panic!("vk {vk_code:#x} produced message {other}"),
                        }
                    }
                }
            }
        }
        // Spot-check one mapping end to end.
        let scancode = solstice_input::scancode(vk::OEM_1, false);
        assert_eq!(scancode, Some(0x27));
    }
}
