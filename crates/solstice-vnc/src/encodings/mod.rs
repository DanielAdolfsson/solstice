//! Rectangle decoders.
//!
//! Each decoder reads its rectangle from the connection and blits BGRA into the
//! framebuffer. They are `async` because Hextile in particular cannot be length
//! -delimited in advance -- its tile stream has to be parsed to know where it
//! ends -- so a "read the whole rect, then decode" shape would not work for it.
//! Tests drive them over an in-memory cursor, which is an `AsyncRead` like any
//! other.
//!
//! **Not implemented:** Tight (7) and its JPEG sub-encoding. Solstice does not
//! advertise it, so a conforming server will not send it; a server that sends
//! an unrequested encoding gets [`RfbError::UnsupportedEncoding`] rather than a
//! guess. ZRLE covers the same ground against every server in
//! `docs/testing.md` §3.

pub mod copy_rect;
pub mod hextile;
pub mod raw;
pub mod rre;
pub mod zrle;

use solstice_backend::{Framebuffer, Rect};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::protocol::{Result, RfbError};

/// Largest single rectangle accepted, in pixels.
///
/// The rectangle geometry comes off the wire. A server claiming a 65535x65535
/// rectangle would otherwise have the client try to allocate 17 GB
/// (`docs/security.md` §5.4).
pub const MAX_RECT_PIXELS: usize = 8192 * 8192;

/// Read exactly `n` bytes.
pub async fn read_exact<R: AsyncRead + Unpin>(reader: &mut R, n: usize) -> Result<Vec<u8>> {
    if n > MAX_RECT_PIXELS * 4 {
        return Err(RfbError::Limit(format!("refusing to read {n} bytes")));
    }
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Check a rectangle against the framebuffer before anything is written
/// through it.
pub fn check_rect(rect: Rect, fb: &Framebuffer) -> Result<()> {
    if rect.is_empty() {
        return Ok(());
    }
    let pixels = rect.width as usize * rect.height as usize;
    if pixels > MAX_RECT_PIXELS {
        return Err(RfbError::Limit(format!("rectangle of {pixels} pixels")));
    }
    if !rect.fits_in(fb.width(), fb.height()) {
        return Err(RfbError::Protocol(format!(
            "rectangle {}x{}+{}+{} does not fit in {}x{}",
            rect.width,
            rect.height,
            rect.x,
            rect.y,
            fb.width(),
            fb.height()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rectangles_outside_the_framebuffer_are_refused() {
        let fb = Framebuffer::new(64, 64);
        assert!(check_rect(
            Rect {
                x: 0,
                y: 0,
                width: 64,
                height: 64
            },
            &fb
        )
        .is_ok());
        assert!(check_rect(
            Rect {
                x: 1,
                y: 0,
                width: 64,
                height: 64
            },
            &fb
        )
        .is_err());
        assert!(check_rect(
            Rect {
                x: 0,
                y: 0,
                width: 65535,
                height: 65535
            },
            &fb
        )
        .is_err());
        assert!(check_rect(Rect::default(), &fb).is_ok());
    }

    #[tokio::test]
    async fn read_exact_refuses_an_absurd_length() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        assert!(read_exact(&mut cursor, usize::MAX / 2).await.is_err());
    }
}
