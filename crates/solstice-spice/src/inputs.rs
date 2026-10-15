//! The inputs channel.
//!
//! The easy part, as `docs/spice-protocol.md` §8 says: SPICE carries **PC AT
//! (XT set 1) scancodes**, the same representation RFB's QEMU Extended Key
//! Event uses, so `solstice-input`'s VK-to-scancode table serves both
//! backends with no new table.
//!
//! Three things still need care.
//!
//! **The scancode is packed, not sent as a number.** `spice_make_scancode`
//! (`spice-util.c:137-148`) sets bit 7 for a release and, for an extended
//! key, byte-swaps `0xE0XX` so that the little-endian `u32` on the wire reads
//! `E0` then the code -- the raw byte sequence a PS/2 keyboard would emit.
//!
//! **Motion is flow-controlled.** At most
//! `SPICE_INPUT_MOTION_ACK_BUNCH * 2` motion or position messages may be
//! outstanding; each `MOUSE_MOTION_ACK` releases four
//! (`channel-inputs.c:246-250`). Past that the reference client *accumulates*
//! rather than dropping, and so does this: the deltas are summed and the
//! absolute position is overwritten, so the pointer ends up where it should
//! be however long the stall lasted.
//!
//! **Which message carries the pointer depends on the mouse mode.** Client
//! mode takes absolute positions and needs the guest agent; server mode takes
//! relative deltas. Moonlight's natural input is absolute, so Solstice asks
//! for client mode and converts to deltas when it cannot have it, with the
//! pointer drift every SPICE client accepts.

use solstice_backend::{InputEvent, KeyEvent, MouseButton};

use crate::channel::OutMessage;
use crate::protocol::{button_mask, inputs_msgc, mouse_button, INPUT_MOTION_ACK_BUNCH};
use crate::wire::Writer;

/// Which pointer representation the session negotiated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseMode {
    /// Relative deltas; the guest draws its own pointer.
    Server,
    /// Absolute positions; needs `spice-vdagent` in the guest.
    Client,
}

/// Pointer and keyboard state for one session.
#[derive(Clone, Debug)]
pub struct InputState {
    mode: MouseMode,
    buttons: u16,
    /// Absolute position, in surface coordinates.
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    /// Motion accumulated while the ack window was full.
    pending_dx: i32,
    pending_dy: i32,
    /// Whether an absolute position is waiting to be sent.
    position_dirty: bool,
    /// Motion messages sent and not yet acknowledged.
    outstanding: u32,
}

impl InputState {
    /// Start centred in a `width` x `height` surface, in server mode until
    /// the main channel says otherwise.
    pub fn new(width: u32, height: u32) -> Self {
        InputState {
            mode: MouseMode::Server,
            buttons: 0,
            x: width / 2,
            y: height / 2,
            width: width.max(1),
            height: height.max(1),
            pending_dx: 0,
            pending_dy: 0,
            position_dirty: false,
            outstanding: 0,
        }
    }

    /// The mouse mode in force.
    pub fn mode(&self) -> MouseMode {
        self.mode
    }

    /// Switch mode, as `MAIN_MOUSE_MODE` reports it.
    pub fn set_mode(&mut self, mode: MouseMode) {
        self.mode = mode;
    }

    /// Update the surface geometry after a resize.
    pub fn resize(&mut self, width: u32, height: u32) {
        self.width = width.max(1);
        self.height = height.max(1);
        self.x = self.x.min(self.width - 1);
        self.y = self.y.min(self.height - 1);
    }

    /// Current pointer position, for tests.
    pub fn position(&self) -> (u32, u32) {
        (self.x, self.y)
    }

    /// Current button mask.
    pub fn buttons(&self) -> u16 {
        self.buttons
    }

    /// Whether another motion message may be sent right now.
    fn may_send_motion(&self) -> bool {
        self.outstanding < INPUT_MOTION_ACK_BUNCH * 2
    }

    /// Handle `MOUSE_MOTION_ACK`, releasing a bunch and flushing whatever
    /// accumulated while the window was full.
    pub fn motion_ack(&mut self) -> Vec<OutMessage> {
        self.outstanding = self.outstanding.saturating_sub(INPUT_MOTION_ACK_BUNCH);
        self.flush_motion()
    }

    fn flush_motion(&mut self) -> Vec<OutMessage> {
        let mut out = Vec::new();
        if !self.may_send_motion() {
            return out;
        }
        match self.mode {
            MouseMode::Server => {
                if self.pending_dx != 0 || self.pending_dy != 0 {
                    out.push(self.motion_message(self.pending_dx, self.pending_dy));
                    self.pending_dx = 0;
                    self.pending_dy = 0;
                }
            }
            MouseMode::Client => {
                if self.position_dirty {
                    out.push(self.position_message());
                    self.position_dirty = false;
                }
            }
        }
        out
    }

    fn motion_message(&mut self, dx: i32, dy: i32) -> OutMessage {
        self.outstanding += 1;
        let mut w = Writer::new();
        w.i32(dx).i32(dy).u16(self.buttons);
        OutMessage::new(inputs_msgc::MOUSE_MOTION, w.finish())
    }

    fn position_message(&mut self) -> OutMessage {
        self.outstanding += 1;
        let mut w = Writer::new();
        // `display_id` is the monitor the position is relative to. Solstice
        // bridges one head, so it is always zero.
        w.u32(self.x).u32(self.y).u16(self.buttons).u8(0);
        OutMessage::new(inputs_msgc::MOUSE_POSITION, w.finish())
    }

    fn button_message(&self, kind: u16, button: u8) -> OutMessage {
        let mut w = Writer::new();
        w.u8(button).u16(self.buttons);
        OutMessage::new(kind, w.finish())
    }

    /// Translate one backend event into the messages it becomes.
    pub fn encode(&mut self, event: &InputEvent) -> Vec<OutMessage> {
        match event {
            InputEvent::Key(key) => self.key(key),

            InputEvent::Text(text) => {
                // SPICE has no text event: a keyboard channel carrying
                // scancodes cannot express a code point that the US layout
                // has no key for. Dropping it is better than synthesising a
                // key that would type something else.
                tracing::debug!(
                    len = text.len(),
                    "dropping a text event: SPICE has no equivalent"
                );
                Vec::new()
            }

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
                // conversion is exact rather than a guess.
                let new_x = ((*x).max(0) as u64 * self.width as u64 / *ref_width as u64) as u32;
                let new_y = ((*y).max(0) as u64 * self.height as u64 / *ref_height as u64) as u32;
                let new_x = new_x.min(self.width - 1);
                let new_y = new_y.min(self.height - 1);
                match self.mode {
                    MouseMode::Client => {
                        self.x = new_x;
                        self.y = new_y;
                        self.position_dirty = true;
                    }
                    MouseMode::Server => {
                        // Without the agent there is no absolute pointer, so
                        // an absolute event becomes the delta from where the
                        // client last believed the pointer was. The guest's
                        // own acceleration makes this drift, which is the
                        // compromise every SPICE client without an agent
                        // makes.
                        self.pending_dx += new_x as i32 - self.x as i32;
                        self.pending_dy += new_y as i32 - self.y as i32;
                        self.x = new_x;
                        self.y = new_y;
                    }
                }
                self.flush_motion()
            }

            InputEvent::PointerRelative { dx, dy } => {
                let new_x = (self.x as i64 + *dx as i64).clamp(0, self.width as i64 - 1) as u32;
                let new_y = (self.y as i64 + *dy as i64).clamp(0, self.height as i64 - 1) as u32;
                match self.mode {
                    MouseMode::Client => {
                        self.x = new_x;
                        self.y = new_y;
                        self.position_dirty = true;
                    }
                    MouseMode::Server => {
                        self.pending_dx += *dx as i32;
                        self.pending_dy += *dy as i32;
                        self.x = new_x;
                        self.y = new_y;
                    }
                }
                self.flush_motion()
            }

            InputEvent::Button { button, down } => {
                let Some((code, bit)) = button_codes(*button) else {
                    return Vec::new();
                };
                if *down {
                    self.buttons |= bit;
                    vec![self.button_message(inputs_msgc::MOUSE_PRESS, code)]
                } else {
                    self.buttons &= !bit;
                    vec![self.button_message(inputs_msgc::MOUSE_RELEASE, code)]
                }
            }

            InputEvent::Scroll {
                vertical,
                horizontal,
            } => {
                if *horizontal != 0 {
                    // SPICE's button numbering has no horizontal wheel:
                    // SIDE and EXTRA are the two thumb buttons, not tilt.
                    tracing::trace!("dropping horizontal scroll: SPICE has no horizontal wheel");
                }
                if *vertical == 0 {
                    return Vec::new();
                }
                let (code, bit) = if *vertical > 0 {
                    (mouse_button::UP, button_mask::UP)
                } else {
                    (mouse_button::DOWN, button_mask::DOWN)
                };
                // Moonlight sends 120 units per detent.
                let clicks = (vertical.unsigned_abs() as u32).div_ceil(120).clamp(1, 16);
                let mut out = Vec::with_capacity(clicks as usize * 2);
                for _ in 0..clicks {
                    self.buttons |= bit;
                    out.push(self.button_message(inputs_msgc::MOUSE_PRESS, code));
                    self.buttons &= !bit;
                    out.push(self.button_message(inputs_msgc::MOUSE_RELEASE, code));
                }
                out
            }

            _ => Vec::new(),
        }
    }

    fn key(&self, key: &KeyEvent) -> Vec<OutMessage> {
        let Some(scancode) = key.scancode else {
            // SPICE has no keysym path at all; a key with no XT
            // representation cannot be expressed.
            return Vec::new();
        };
        let code = wire_scancode(scancode, !key.down);
        let kind = if key.down {
            inputs_msgc::KEY_DOWN
        } else {
            inputs_msgc::KEY_UP
        };
        let mut w = Writer::new();
        w.u32(code);
        vec![OutMessage::new(kind, w.finish())]
    }

    /// Build a `KEY_MODIFIERS` message, mirroring the server's lock state
    /// back so the guest and the client agree.
    pub fn key_modifiers(modifiers: u16) -> OutMessage {
        let mut w = Writer::new();
        w.u16(modifiers);
        OutMessage::new(inputs_msgc::KEY_MODIFIERS, w.finish())
    }
}

/// Pack an XT scancode the way `SPICE_MSGC_INPUTS_KEY_DOWN` wants it.
///
/// `scancode` is the form `solstice_input::scancode` produces: a bare byte,
/// or `0xE0 << 8 | code` for an extended key. The result is a little-endian
/// `u32` whose bytes are the raw PS/2 sequence -- `E0` first for an extended
/// key, which is why `spice_make_scancode` byte-swaps.
pub fn wire_scancode(scancode: u16, release: bool) -> u32 {
    let extended = scancode & 0xFF00 == 0xE000;
    let mut code = (scancode & 0x7F) as u32;
    if release {
        code |= 0x80;
    }
    if extended {
        0xE0 | (code << 8)
    } else {
        code
    }
}

/// SPICE's button number and mask bit for a Moonlight button.
fn button_codes(button: MouseButton) -> Option<(u8, u16)> {
    Some(match button {
        MouseButton::Left => (mouse_button::LEFT, button_mask::LEFT),
        MouseButton::Middle => (mouse_button::MIDDLE, button_mask::MIDDLE),
        MouseButton::Right => (mouse_button::RIGHT, button_mask::RIGHT),
        MouseButton::X1 => (mouse_button::SIDE, button_mask::SIDE),
        MouseButton::X2 => (mouse_button::EXTRA, button_mask::EXTRA),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Reader;
    use solstice_input::{scancode, vk};

    fn state(mode: MouseMode) -> InputState {
        let mut state = InputState::new(1920, 1080);
        state.set_mode(mode);
        state
    }

    #[test]
    fn a_plain_key_is_its_scancode_with_bit_seven_for_the_release() {
        assert_eq!(wire_scancode(0x1E, false), 0x1E);
        assert_eq!(wire_scancode(0x1E, true), 0x9E);
    }

    #[test]
    fn an_extended_key_puts_the_e0_prefix_in_the_first_wire_byte() {
        // Right Control is E0 1D; its release is E0 9D.
        let code = wire_scancode(0xE01D, false);
        assert_eq!(code.to_le_bytes()[0], 0xE0);
        assert_eq!(code.to_le_bytes()[1], 0x1D);
        let code = wire_scancode(0xE01D, true);
        assert_eq!(code.to_le_bytes()[0], 0xE0);
        assert_eq!(code.to_le_bytes()[1], 0x9D);
    }

    #[test]
    fn the_scancode_table_is_shared_with_the_rfb_backend() {
        // The point of the table living in `solstice-input`: the same lookup
        // feeds both backends.
        let mut state = state(MouseMode::Client);
        let sc = scancode(vk::KEY_A, false).unwrap();
        let messages = state.encode(&InputEvent::Key(KeyEvent {
            scancode: Some(sc),
            keysym: Some(0x61),
            down: true,
            non_normalized: false,
        }));
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].kind, inputs_msgc::KEY_DOWN);
        assert_eq!(messages[0].body, 0x1Eu32.to_le_bytes());
    }

    #[test]
    fn a_key_with_no_scancode_produces_nothing_because_spice_has_no_keysyms() {
        let mut state = state(MouseMode::Client);
        let messages = state.encode(&InputEvent::Key(KeyEvent {
            scancode: None,
            keysym: Some(0xFF8D),
            down: true,
            non_normalized: false,
        }));
        assert!(messages.is_empty());
    }

    #[test]
    fn a_text_event_produces_nothing() {
        let mut state = state(MouseMode::Client);
        assert!(state.encode(&InputEvent::Text("hello".into())).is_empty());
    }

    #[test]
    fn client_mode_sends_an_absolute_position_scaled_to_the_surface() {
        let mut state = state(MouseMode::Client);
        let messages = state.encode(&InputEvent::PointerAbsolute {
            x: 640,
            y: 360,
            ref_width: 1280,
            ref_height: 720,
        });
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].kind, inputs_msgc::MOUSE_POSITION);
        let mut r = Reader::new(&messages[0].body);
        assert_eq!(r.u32().unwrap(), 960);
        assert_eq!(r.u32().unwrap(), 540);
        assert_eq!(r.u16().unwrap(), 0);
        assert_eq!(r.u8().unwrap(), 0, "one head, so display id zero");
    }

    #[test]
    fn server_mode_turns_an_absolute_event_into_the_delta_from_the_last_one() {
        let mut state = state(MouseMode::Server);
        // Starts centred at 960, 540.
        let messages = state.encode(&InputEvent::PointerAbsolute {
            x: 0,
            y: 0,
            ref_width: 1280,
            ref_height: 720,
        });
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].kind, inputs_msgc::MOUSE_MOTION);
        let mut r = Reader::new(&messages[0].body);
        assert_eq!(r.i32().unwrap(), -960);
        assert_eq!(r.i32().unwrap(), -540);
    }

    #[test]
    fn a_reference_geometry_of_zero_is_dropped_rather_than_dividing_by_it() {
        let mut state = state(MouseMode::Client);
        assert!(state
            .encode(&InputEvent::PointerAbsolute {
                x: 1,
                y: 1,
                ref_width: 0,
                ref_height: 720,
            })
            .is_empty());
    }

    #[test]
    fn motion_stops_at_the_ack_window_and_resumes_when_it_is_acknowledged() {
        let mut state = state(MouseMode::Client);
        let limit = INPUT_MOTION_ACK_BUNCH * 2;
        for i in 0..limit {
            let messages = state.encode(&InputEvent::PointerAbsolute {
                x: i as i16,
                y: 0,
                ref_width: 1920,
                ref_height: 1080,
            });
            assert_eq!(messages.len(), 1, "message {i} should have gone out");
        }
        // The window is full.
        let messages = state.encode(&InputEvent::PointerAbsolute {
            x: 100,
            y: 0,
            ref_width: 1920,
            ref_height: 1080,
        });
        assert!(messages.is_empty(), "past the window, nothing goes out");

        // The accumulated position is sent on the next acknowledgement, and
        // it is the *latest* one rather than the one that was blocked.
        let messages = state.motion_ack();
        assert_eq!(messages.len(), 1);
        let mut r = Reader::new(&messages[0].body);
        assert_eq!(r.u32().unwrap(), 100);
    }

    #[test]
    fn motion_blocked_in_server_mode_accumulates_rather_than_being_lost() {
        let mut state = state(MouseMode::Server);
        for _ in 0..INPUT_MOTION_ACK_BUNCH * 2 {
            state.encode(&InputEvent::PointerRelative { dx: 1, dy: 0 });
        }
        state.encode(&InputEvent::PointerRelative { dx: 3, dy: 4 });
        state.encode(&InputEvent::PointerRelative { dx: 5, dy: 6 });
        let messages = state.motion_ack();
        assert_eq!(messages.len(), 1);
        let mut r = Reader::new(&messages[0].body);
        assert_eq!(r.i32().unwrap(), 8, "the two blocked deltas, summed");
        assert_eq!(r.i32().unwrap(), 10);
    }

    #[test]
    fn an_acknowledgement_with_nothing_waiting_sends_nothing() {
        let mut state = state(MouseMode::Client);
        assert!(state.motion_ack().is_empty());
    }

    #[test]
    fn buttons_press_and_release_and_the_mask_follows() {
        let mut state = state(MouseMode::Client);
        let messages = state.encode(&InputEvent::Button {
            button: MouseButton::Right,
            down: true,
        });
        assert_eq!(messages[0].kind, inputs_msgc::MOUSE_PRESS);
        assert_eq!(messages[0].body[0], mouse_button::RIGHT);
        assert_eq!(state.buttons(), button_mask::RIGHT);

        let messages = state.encode(&InputEvent::Button {
            button: MouseButton::Right,
            down: false,
        });
        assert_eq!(messages[0].kind, inputs_msgc::MOUSE_RELEASE);
        assert_eq!(state.buttons(), 0);
    }

    #[test]
    fn the_side_buttons_map_onto_spices_own_rather_than_being_dropped() {
        // RFB has no mask bit left for X2 and drops it; SPICE has both.
        let mut state = state(MouseMode::Client);
        assert_eq!(
            state.encode(&InputEvent::Button {
                button: MouseButton::X2,
                down: true
            })[0]
                .body[0],
            mouse_button::EXTRA
        );
        assert_eq!(
            state.encode(&InputEvent::Button {
                button: MouseButton::X1,
                down: true
            })[0]
                .body[0],
            mouse_button::SIDE
        );
    }

    #[test]
    fn a_scroll_detent_is_a_press_and_a_release_of_the_wheel_button() {
        let mut state = state(MouseMode::Client);
        let messages = state.encode(&InputEvent::Scroll {
            vertical: 120,
            horizontal: 0,
        });
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].kind, inputs_msgc::MOUSE_PRESS);
        assert_eq!(messages[0].body[0], mouse_button::UP);
        assert_eq!(messages[1].kind, inputs_msgc::MOUSE_RELEASE);
        assert_eq!(state.buttons(), 0, "the wheel is not left held");

        let messages = state.encode(&InputEvent::Scroll {
            vertical: -360,
            horizontal: 0,
        });
        assert_eq!(messages.len(), 6, "three detents, two messages each");
        assert_eq!(messages[0].body[0], mouse_button::DOWN);
    }

    #[test]
    fn horizontal_scroll_is_dropped_because_spice_has_no_button_for_it() {
        let mut state = state(MouseMode::Client);
        assert!(state
            .encode(&InputEvent::Scroll {
                vertical: 0,
                horizontal: 120,
            })
            .is_empty());
    }

    #[test]
    fn a_resize_keeps_the_pointer_inside_the_new_surface() {
        let mut state = state(MouseMode::Client);
        state.resize(640, 480);
        let (x, y) = state.position();
        assert!(x < 640 && y < 480);
    }
}
