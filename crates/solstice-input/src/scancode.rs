//! VK (+ extended flag) -> XT set-1 make scancode.
//!
//! The returned value is the scancode packed the way RFB's QEMU Extended Key
//! Event and SPICE's `SPICE_MSGC_INPUTS_KEY_DOWN` both want it: a single byte
//! for a normal key, or `0xE0 << 8 | code` for an extended one.

use crate::vk;

/// An XT make scancode, either one byte or 0xE0-prefixed.
pub type Scancode = u16;

const E0: u16 = 0xE000;

/// Translate a Windows virtual-key code to an XT make scancode.
///
/// `extended` is `MODIFIER_EXTENDED` from the keyboard packet. It disambiguates
/// the key pairs that share a VK code -- Return vs. KP_Enter, left vs. right
/// Control, the numeric keypad vs. the navigation cluster.
///
/// Returns `None` for keys with no XT representation; the caller should fall
/// back to the keysym path or drop the event.
pub fn scancode(vk_code: u16, extended: bool) -> Option<Scancode> {
    // Digits 1..9,0 occupy 0x02..=0x0B in that order.
    if (vk::KEY_0..=vk::KEY_9).contains(&vk_code) {
        return Some(match vk_code {
            vk::KEY_0 => 0x0B,
            n => 0x02 + (n - vk::KEY_0) - 1,
        });
    }
    if (vk::KEY_A..=vk::KEY_Z).contains(&vk_code) {
        const LETTERS: [u16; 26] = [
            0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31,
            0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
        ];
        return Some(LETTERS[(vk_code - vk::KEY_A) as usize]);
    }
    if (vk::NUMPAD0..=vk::NUMPAD9).contains(&vk_code) {
        const PAD: [u16; 10] = [0x52, 0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47, 0x48, 0x49];
        return Some(PAD[(vk_code - vk::NUMPAD0) as usize]);
    }
    if (vk::F1..=vk::F12).contains(&vk_code) {
        return Some(match vk_code - vk::F1 {
            n @ 0..=9 => 0x3B + n,
            10 => 0x57,
            _ => 0x58,
        });
    }
    if (vk::F13..=vk::F24).contains(&vk_code) {
        return Some(0x64 + (vk_code - vk::F13));
    }

    Some(match vk_code {
        vk::BACK => 0x0E,
        vk::TAB => 0x0F,
        vk::RETURN => {
            if extended {
                E0 | 0x1C
            } else {
                0x1C
            }
        }
        vk::SHIFT | vk::LSHIFT => 0x2A,
        vk::RSHIFT => 0x36,
        vk::CONTROL => {
            if extended {
                E0 | 0x1D
            } else {
                0x1D
            }
        }
        vk::LCONTROL => 0x1D,
        vk::RCONTROL => E0 | 0x1D,
        vk::MENU => {
            if extended {
                E0 | 0x38
            } else {
                0x38
            }
        }
        vk::LMENU => 0x38,
        vk::RMENU => E0 | 0x38,
        // Pause is XT `0xE1 0x1D 0x45`, which the one-or-two byte encodings used
        // by RFB and SPICE cannot express. Send Ctrl-Break (0xE0 0x46), which is
        // what the key produces with Control held and what QEMU's own table uses.
        vk::PAUSE => E0 | 0x46,
        vk::NUMLOCK => 0x45,
        vk::SCROLL => 0x46,
        vk::CAPITAL => 0x3A,
        vk::ESCAPE => 0x01,
        vk::SPACE => 0x39,
        // The navigation cluster is the extended form; the keypad duplicates are
        // the bare form, which is what a client sends with NumLock off.
        vk::PRIOR => nav(0x49, extended),
        vk::NEXT => nav(0x51, extended),
        vk::END => nav(0x4F, extended),
        vk::HOME => nav(0x47, extended),
        vk::LEFT => nav(0x4B, extended),
        vk::UP => nav(0x48, extended),
        vk::RIGHT => nav(0x4D, extended),
        vk::DOWN => nav(0x50, extended),
        vk::INSERT => nav(0x52, extended),
        vk::DELETE => nav(0x53, extended),
        vk::CLEAR => nav(0x4C, extended),
        vk::SNAPSHOT => E0 | 0x37,
        vk::LWIN => E0 | 0x5B,
        vk::RWIN => E0 | 0x5C,
        vk::APPS => E0 | 0x5D,
        vk::MULTIPLY => 0x37,
        vk::ADD => 0x4E,
        vk::SUBTRACT => 0x4A,
        vk::DECIMAL => 0x53,
        vk::DIVIDE => E0 | 0x35,
        vk::OEM_1 => 0x27,
        vk::OEM_PLUS => 0x0D,
        vk::OEM_COMMA => 0x33,
        vk::OEM_MINUS => 0x0C,
        vk::OEM_PERIOD => 0x34,
        vk::OEM_2 => 0x35,
        vk::OEM_3 => 0x29,
        vk::OEM_4 => 0x1A,
        vk::OEM_5 => 0x2B,
        vk::OEM_6 => 0x1B,
        vk::OEM_7 => 0x28,
        vk::OEM_102 => 0x56,
        vk::KANJI => 0x29,
        vk::CONVERT => 0x79,
        vk::NONCONVERT => 0x7B,
        vk::KANA => 0x70,
        vk::BROWSER_BACK => E0 | 0x6A,
        vk::BROWSER_FORWARD => E0 | 0x69,
        vk::BROWSER_REFRESH => E0 | 0x67,
        vk::BROWSER_STOP => E0 | 0x68,
        vk::BROWSER_SEARCH => E0 | 0x65,
        vk::BROWSER_FAVORITES => E0 | 0x66,
        vk::BROWSER_HOME => E0 | 0x32,
        vk::VOLUME_MUTE => E0 | 0x20,
        vk::VOLUME_DOWN => E0 | 0x2E,
        vk::VOLUME_UP => E0 | 0x30,
        vk::MEDIA_NEXT_TRACK => E0 | 0x19,
        vk::MEDIA_PREV_TRACK => E0 | 0x10,
        vk::MEDIA_STOP => E0 | 0x24,
        vk::MEDIA_PLAY_PAUSE => E0 | 0x22,
        vk::LAUNCH_MAIL => E0 | 0x6C,
        vk::LAUNCH_MEDIA_SELECT => E0 | 0x6D,
        _ => return None,
    })
}

fn nav(base: u16, extended: bool) -> Scancode {
    if extended {
        E0 | base
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_vs_keypad_enter() {
        assert_eq!(scancode(vk::RETURN, false), Some(0x1C));
        assert_eq!(scancode(vk::RETURN, true), Some(0xE01C));
    }

    #[test]
    fn control_and_alt_sides() {
        assert_eq!(scancode(vk::CONTROL, false), Some(0x1D));
        assert_eq!(scancode(vk::CONTROL, true), Some(0xE01D));
        assert_eq!(scancode(vk::LCONTROL, false), Some(0x1D));
        assert_eq!(scancode(vk::RCONTROL, false), Some(0xE01D));
        assert_eq!(scancode(vk::LMENU, false), Some(0x38));
        assert_eq!(scancode(vk::RMENU, false), Some(0xE038));
    }

    #[test]
    fn digit_row() {
        assert_eq!(scancode(b'1' as u16, false), Some(0x02));
        assert_eq!(scancode(b'9' as u16, false), Some(0x0A));
        assert_eq!(scancode(b'0' as u16, false), Some(0x0B));
    }

    #[test]
    fn letter_row_is_qwerty() {
        for (ch, code) in [
            (b'Q', 0x10),
            (b'W', 0x11),
            (b'E', 0x12),
            (b'A', 0x1E),
            (b'Z', 0x2C),
            (b'M', 0x32),
        ] {
            assert_eq!(scancode(ch as u16, false), Some(code), "{}", ch as char);
        }
    }

    #[test]
    fn function_keys() {
        assert_eq!(scancode(vk::F1, false), Some(0x3B));
        assert_eq!(scancode(vk::F1 + 9, false), Some(0x44)); // F10
        assert_eq!(scancode(vk::F1 + 10, false), Some(0x57)); // F11
        assert_eq!(scancode(vk::F12, false), Some(0x58));
        assert_eq!(scancode(vk::F13, false), Some(0x64));
        assert_eq!(scancode(vk::F24, false), Some(0x6F));
    }

    #[test]
    fn navigation_cluster_is_extended() {
        assert_eq!(scancode(vk::HOME, true), Some(0xE047));
        assert_eq!(scancode(vk::HOME, false), Some(0x47)); // keypad 7
        assert_eq!(scancode(vk::DELETE, true), Some(0xE053));
    }

    /// The worked example from `docs/bridging-design.md` §4.1: a Swedish user
    /// pressing the key labelled O-umlaut. Moonlight normalises it to the US
    /// VK for that physical position, and the scancode path must preserve the
    /// position so the remote keymap -- not ours -- decides the symbol.
    #[test]
    fn oem_keys_preserve_physical_position() {
        assert_eq!(scancode(vk::OEM_1, false), Some(0x27));
        assert_eq!(scancode(vk::OEM_102, false), Some(0x56));
    }

    #[test]
    fn unknown_vk_is_none() {
        assert_eq!(scancode(0x00, false), None);
        assert_eq!(scancode(0xFF, false), None);
    }

    /// Every scancode we emit must be representable the way RFB -258 and SPICE
    /// expect: one byte, or 0xE0 plus one byte.
    #[test]
    fn every_mapping_is_wire_representable() {
        for vk_code in 0u16..=0xFFu16 {
            for ext in [false, true] {
                if let Some(sc) = scancode(vk_code, ext) {
                    let hi = sc >> 8;
                    assert!(hi == 0 || hi == 0xE0, "vk {vk_code:#x} -> {sc:#x}");
                    assert_ne!(sc & 0xFF, 0, "vk {vk_code:#x} -> zero make code");
                }
            }
        }
    }
}
