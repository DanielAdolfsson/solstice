//! Windows virtual-key constants, limited to the ones Moonlight can send.
//!
//! Names follow `winuser.h` with the `VK_` prefix dropped.

#![allow(missing_docs)]

pub const BACK: u16 = 0x08;
pub const TAB: u16 = 0x09;
pub const CLEAR: u16 = 0x0C;
pub const RETURN: u16 = 0x0D;
pub const SHIFT: u16 = 0x10;
pub const CONTROL: u16 = 0x11;
pub const MENU: u16 = 0x12;
pub const PAUSE: u16 = 0x13;
pub const CAPITAL: u16 = 0x14;
pub const KANA: u16 = 0x15;
pub const KANJI: u16 = 0x19;
pub const ESCAPE: u16 = 0x1B;
pub const CONVERT: u16 = 0x1C;
pub const NONCONVERT: u16 = 0x1D;
pub const SPACE: u16 = 0x20;
pub const PRIOR: u16 = 0x21;
pub const NEXT: u16 = 0x22;
pub const END: u16 = 0x23;
pub const HOME: u16 = 0x24;
pub const LEFT: u16 = 0x25;
pub const UP: u16 = 0x26;
pub const RIGHT: u16 = 0x27;
pub const DOWN: u16 = 0x28;
pub const SNAPSHOT: u16 = 0x2C;
pub const INSERT: u16 = 0x2D;
pub const DELETE: u16 = 0x2E;

pub const KEY_0: u16 = 0x30;
pub const KEY_9: u16 = 0x39;
pub const KEY_A: u16 = 0x41;
pub const KEY_Z: u16 = 0x5A;

pub const LWIN: u16 = 0x5B;
pub const RWIN: u16 = 0x5C;
pub const APPS: u16 = 0x5D;

pub const NUMPAD0: u16 = 0x60;
pub const NUMPAD9: u16 = 0x69;
pub const MULTIPLY: u16 = 0x6A;
pub const ADD: u16 = 0x6B;
pub const SEPARATOR: u16 = 0x6C;
pub const SUBTRACT: u16 = 0x6D;
pub const DECIMAL: u16 = 0x6E;
pub const DIVIDE: u16 = 0x6F;

pub const F1: u16 = 0x70;
pub const F12: u16 = 0x7B;
pub const F13: u16 = 0x7C;
pub const F24: u16 = 0x87;

pub const NUMLOCK: u16 = 0x90;
pub const SCROLL: u16 = 0x91;

pub const LSHIFT: u16 = 0xA0;
pub const RSHIFT: u16 = 0xA1;
pub const LCONTROL: u16 = 0xA2;
pub const RCONTROL: u16 = 0xA3;
pub const LMENU: u16 = 0xA4;
pub const RMENU: u16 = 0xA5;

pub const BROWSER_BACK: u16 = 0xA6;
pub const BROWSER_FORWARD: u16 = 0xA7;
pub const BROWSER_REFRESH: u16 = 0xA8;
pub const BROWSER_STOP: u16 = 0xA9;
pub const BROWSER_SEARCH: u16 = 0xAA;
pub const BROWSER_FAVORITES: u16 = 0xAB;
pub const BROWSER_HOME: u16 = 0xAC;
pub const VOLUME_MUTE: u16 = 0xAD;
pub const VOLUME_DOWN: u16 = 0xAE;
pub const VOLUME_UP: u16 = 0xAF;
pub const MEDIA_NEXT_TRACK: u16 = 0xB0;
pub const MEDIA_PREV_TRACK: u16 = 0xB1;
pub const MEDIA_STOP: u16 = 0xB2;
pub const MEDIA_PLAY_PAUSE: u16 = 0xB3;
pub const LAUNCH_MAIL: u16 = 0xB4;
pub const LAUNCH_MEDIA_SELECT: u16 = 0xB5;

pub const OEM_1: u16 = 0xBA; // ;:
pub const OEM_PLUS: u16 = 0xBB; // =+
pub const OEM_COMMA: u16 = 0xBC; // ,<
pub const OEM_MINUS: u16 = 0xBD; // -_
pub const OEM_PERIOD: u16 = 0xBE; // .>
pub const OEM_2: u16 = 0xBF; // /?
pub const OEM_3: u16 = 0xC0; // `~
pub const OEM_4: u16 = 0xDB; // [{
pub const OEM_5: u16 = 0xDC; // \|
pub const OEM_6: u16 = 0xDD; // ]}
pub const OEM_7: u16 = 0xDE; // '"
pub const OEM_8: u16 = 0xDF;
pub const OEM_102: u16 = 0xE2; // the key next to left shift on ISO boards

/// Modifier bits in `NV_KEYBOARD_PACKET.modifiers` (`Limelight.h:694-701`).
pub mod modifier {
    #![allow(missing_docs)]
    pub const SHIFT: u8 = 0x01;
    pub const CTRL: u8 = 0x02;
    pub const ALT: u8 = 0x04;
    pub const META: u8 = 0x08;
    /// "This key carries the 0xE0 scancode prefix."
    pub const EXTENDED: u8 = 0x10;
}

/// `SS_KBE_FLAG_NON_NORMALIZED`: the client could not normalise the key to a
/// US-layout scancode and is sending it raw.
pub const KBE_FLAG_NON_NORMALIZED: u8 = 0x01;
