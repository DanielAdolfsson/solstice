//! VK -> X11 keysym, the fallback path for RFB servers without pseudo-encoding
//! -258.
//!
//! This path is lossy by construction: it commits to the US-English reading of
//! the key, because a keysym names a *symbol* where a scancode names a
//! *position*. Use it only when the server gives no alternative
//! (`docs/bridging-design.md` §4.1), which in practice means libvncserver and
//! everything built on it.

use crate::vk;

/// An X11 keysym.
pub type Keysym = u32;

/// Translate a Windows virtual-key code to an X11 keysym.
///
/// `shift` must be the SHIFT bit from the keyboard packet's modifier byte: with
/// keysyms the client picks the symbol, so `2` and `@` are different requests.
/// `extended` separates Return from KP_Enter and the navigation cluster from
/// the keypad, exactly as on the scancode path.
pub fn keysym(vk_code: u16, extended: bool, shift: bool) -> Option<Keysym> {
    if (vk::KEY_A..=vk::KEY_Z).contains(&vk_code) {
        let base = if shift { b'A' } else { b'a' } as u32;
        return Some(base + (vk_code - vk::KEY_A) as u32);
    }
    if (vk::KEY_0..=vk::KEY_9).contains(&vk_code) {
        const SHIFTED: [u8; 10] = *b")!@#$%^&*(";
        return Some(if shift {
            SHIFTED[(vk_code - vk::KEY_0) as usize] as u32
        } else {
            (b'0' + (vk_code - vk::KEY_0) as u8) as u32
        });
    }
    if (vk::NUMPAD0..=vk::NUMPAD9).contains(&vk_code) {
        return Some(0xFFB0 + (vk_code - vk::NUMPAD0) as u32); // XK_KP_0..
    }
    if (vk::F1..=vk::F12).contains(&vk_code) {
        return Some(0xFFBE + (vk_code - vk::F1) as u32); // XK_F1..XK_F12
    }
    if (vk::F13..=vk::F24).contains(&vk_code) {
        return Some(0xFFCA + (vk_code - vk::F13) as u32); // XK_F13..XK_F24
    }

    let pair = |plain: u8, shifted: u8| Some(if shift { shifted } else { plain } as u32);

    match vk_code {
        vk::BACK => Some(0xFF08),
        vk::TAB => Some(0xFF09),
        vk::CLEAR => Some(0xFF0B),
        vk::RETURN => Some(if extended { 0xFF8D } else { 0xFF0D }), // KP_Enter / Return
        vk::SHIFT | vk::LSHIFT => Some(0xFFE1),
        vk::RSHIFT => Some(0xFFE2),
        vk::CONTROL => Some(if extended { 0xFFE4 } else { 0xFFE3 }),
        vk::LCONTROL => Some(0xFFE3),
        vk::RCONTROL => Some(0xFFE4),
        // Right Alt is AltGr on most non-US layouts, and ISO_Level3_Shift is the
        // keysym servers expect for it.
        vk::MENU => Some(if extended { 0xFE03 } else { 0xFFE9 }),
        vk::LMENU => Some(0xFFE9),
        vk::RMENU => Some(0xFE03),
        vk::PAUSE => Some(0xFF13),
        vk::CAPITAL => Some(0xFFE5),
        vk::ESCAPE => Some(0xFF1B),
        vk::SPACE => Some(0x20),
        vk::PRIOR => Some(if extended { 0xFF55 } else { 0xFF9A }),
        vk::NEXT => Some(if extended { 0xFF56 } else { 0xFF9B }),
        vk::END => Some(if extended { 0xFF57 } else { 0xFF9C }),
        vk::HOME => Some(if extended { 0xFF50 } else { 0xFF95 }),
        vk::LEFT => Some(if extended { 0xFF51 } else { 0xFF96 }),
        vk::UP => Some(if extended { 0xFF52 } else { 0xFF97 }),
        vk::RIGHT => Some(if extended { 0xFF53 } else { 0xFF98 }),
        vk::DOWN => Some(if extended { 0xFF54 } else { 0xFF99 }),
        vk::INSERT => Some(if extended { 0xFF63 } else { 0xFF9E }),
        vk::DELETE => Some(if extended { 0xFFFF } else { 0xFF9F }),
        vk::SNAPSHOT => Some(0xFF61),
        vk::LWIN => Some(0xFFEB),
        vk::RWIN => Some(0xFFEC),
        vk::APPS => Some(0xFF67),
        vk::NUMLOCK => Some(0xFF7F),
        vk::SCROLL => Some(0xFF14),
        vk::MULTIPLY => Some(0xFFAA),
        vk::ADD => Some(0xFFAB),
        vk::SEPARATOR => Some(0xFFAC),
        vk::SUBTRACT => Some(0xFFAD),
        vk::DECIMAL => Some(0xFFAE),
        vk::DIVIDE => Some(0xFFAF),
        vk::OEM_1 => pair(b';', b':'),
        vk::OEM_PLUS => pair(b'=', b'+'),
        vk::OEM_COMMA => pair(b',', b'<'),
        vk::OEM_MINUS => pair(b'-', b'_'),
        vk::OEM_PERIOD => pair(b'.', b'>'),
        vk::OEM_2 => pair(b'/', b'?'),
        vk::OEM_3 => pair(b'`', b'~'),
        vk::OEM_4 => pair(b'[', b'{'),
        vk::OEM_5 | vk::OEM_102 => pair(b'\\', b'|'),
        vk::OEM_6 => pair(b']', b'}'),
        vk::OEM_7 => pair(b'\'', b'"'),
        _ => None,
    }
}

/// The X11 convention for a Unicode code point with no dedicated keysym.
///
/// Used for Moonlight's UTF-8 text events (`0x00000017`), which have no
/// scancode representation at all.
pub fn unicode_keysym(c: char) -> Keysym {
    let cp = c as u32;
    // Latin-1 and the ASCII range have keysyms equal to their code point.
    if (0x20..=0x7E).contains(&cp) || (0xA0..=0xFF).contains(&cp) {
        cp
    } else {
        0x0100_0000 | cp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_follow_shift() {
        assert_eq!(keysym(b'A' as u16, false, false), Some(0x61)); // a
        assert_eq!(keysym(b'A' as u16, false, true), Some(0x41)); // A
        assert_eq!(keysym(b'Z' as u16, false, false), Some(0x7A));
    }

    #[test]
    fn digits_follow_shift() {
        assert_eq!(keysym(b'2' as u16, false, false), Some(0x32)); // 2
        assert_eq!(keysym(b'2' as u16, false, true), Some(0x40)); // @
        assert_eq!(keysym(b'0' as u16, false, true), Some(0x29)); // )
    }

    /// `docs/testing.md` §3.2 states this expectation directly.
    #[test]
    fn extended_return_is_kp_enter() {
        assert_eq!(keysym(vk::RETURN, true, false), Some(0xFF8D));
        assert_eq!(keysym(vk::RETURN, false, false), Some(0xFF0D));
    }

    #[test]
    fn oem_keys_take_the_us_reading() {
        // The lossy case the scancode path exists to avoid.
        assert_eq!(keysym(vk::OEM_1, false, false), Some(b';' as u32));
    }

    #[test]
    fn unicode_mapping() {
        assert_eq!(unicode_keysym('A'), 0x41);
        assert_eq!(unicode_keysym('ö'), 0xF6); // Latin-1 passthrough
        assert_eq!(unicode_keysym('€'), 0x0100_20AC);
        assert_eq!(unicode_keysym('🦀'), 0x0101_F980);
    }

    /// Anything the scancode table knows should also have a keysym, so a
    /// server without -258 is never silently deaf to a key we accepted.
    #[test]
    fn keysym_table_covers_the_scancode_table() {
        for vk_code in 0u16..=0xFFu16 {
            for ext in [false, true] {
                if crate::scancode(vk_code, ext).is_some() {
                    let has_keysym = keysym(vk_code, ext, false).is_some();
                    // Media and browser keys are the documented exception: they
                    // have XT codes but no portable keysym.
                    let media = (vk::BROWSER_BACK..=vk::LAUNCH_MEDIA_SELECT).contains(&vk_code)
                        || matches!(vk_code, vk::KANA | vk::KANJI | vk::CONVERT | vk::NONCONVERT);
                    assert!(has_keysym || media, "vk {vk_code:#x} has no keysym");
                }
            }
        }
    }
}
