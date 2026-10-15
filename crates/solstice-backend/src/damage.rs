//! What a backend tells the bridge has happened.

use crate::framebuffer::Rect;

/// An event from a backend session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackendEvent {
    /// Pixels inside `rect` changed. The framebuffer has already been updated.
    Damage(Rect),
    /// The remote desktop changed size; the framebuffer has been reallocated.
    Resize {
        /// New width.
        width: u32,
        /// New height.
        height: u32,
    },
    /// The backend connection ended.
    Disconnected,
}
