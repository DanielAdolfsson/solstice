//! Backend-neutral input, already translated out of Moonlight's wire format.

/// A mouse button, in Moonlight's numbering (`Limelight.h:687-691`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseButton {
    /// Left.
    Left,
    /// Middle / wheel click.
    Middle,
    /// Right.
    Right,
    /// Side button 1 ("back").
    X1,
    /// Side button 2 ("forward").
    X2,
}

impl MouseButton {
    /// Decode the button number carried by `NV_MOUSE_BUTTON_PACKET`.
    pub fn from_wire(n: u8) -> Option<Self> {
        Some(match n {
            1 => MouseButton::Left,
            2 => MouseButton::Middle,
            3 => MouseButton::Right,
            4 => MouseButton::X1,
            5 => MouseButton::X2,
            _ => return None,
        })
    }
}

/// A key press or release.
///
/// Scancode first, keysym alongside: the backend picks whichever its peer
/// supports, so the lossy keysym reading stays at the edge rather than in
/// shared code (`docs/bridging-design.md` §4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    /// XT make scancode, 0xE0-prefixed where applicable. `None` when the VK
    /// code has no XT representation.
    pub scancode: Option<u16>,
    /// X11 keysym under a US-layout reading. `None` when there is none.
    pub keysym: Option<u32>,
    /// True for a press.
    pub down: bool,
    /// `SS_KBE_FLAG_NON_NORMALIZED`: the client could not normalise this key to
    /// a US-layout scancode. On this flag the keysym is the trustworthy field.
    pub non_normalized: bool,
}

/// An input event bound for the remote desktop.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InputEvent {
    /// Keyboard.
    Key(KeyEvent),
    /// A UTF-8 text event (`0x00000017`). No scancode representation exists.
    Text(String),
    /// Absolute pointer position, relative to the client's own reference
    /// geometry. The backend scales it to the framebuffer, which is the only
    /// place that knows the current size.
    PointerAbsolute {
        /// X in reference coordinates.
        x: i16,
        /// Y in reference coordinates.
        y: i16,
        /// Reference width the coordinates are relative to.
        ref_width: u16,
        /// Reference height the coordinates are relative to.
        ref_height: u16,
    },
    /// Relative pointer motion; only sent when the client has captured the
    /// pointer.
    PointerRelative {
        /// Horizontal delta.
        dx: i16,
        /// Vertical delta.
        dy: i16,
    },
    /// Mouse button transition.
    Button {
        /// Which button.
        button: MouseButton,
        /// True for a press.
        down: bool,
    },
    /// Wheel motion, in Moonlight's 120-per-detent units.
    Scroll {
        /// Vertical amount; positive is up.
        vertical: i16,
        /// Horizontal amount; positive is right.
        horizontal: i16,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn button_numbering_matches_limelight() {
        assert_eq!(MouseButton::from_wire(1), Some(MouseButton::Left));
        assert_eq!(MouseButton::from_wire(5), Some(MouseButton::X2));
        assert_eq!(MouseButton::from_wire(0), None);
        assert_eq!(MouseButton::from_wire(6), None);
    }
}
