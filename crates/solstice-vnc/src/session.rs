//! The update loop.
//!
//! RFB is pull-based: the client asks for a region and the server replies with
//! the rectangles that bring it up to date. Exactly **one** request may be
//! outstanding -- pipelining more does not get more frames, it just confuses
//! flow control (`docs/rfb-vnc-protocol.md` §3.1).
//!
//! Where the server supports them, `EnableContinuousUpdates` (-313) turns that
//! into a push stream and removes a round trip from every frame, and `Fence`
//! (-312) gives a barrier so updates cannot queue unboundedly on a slow link.
//! Both are requested; both fall back cleanly.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use solstice_backend::{BackendEvent, Framebuffer, FramebufferHandle, Rect};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc};

use crate::cursor::Pointer;
use crate::encodings::tight::TightStreams;
use crate::encodings::zrle::ZlibStream;
use crate::encodings::{copy_rect, hextile, raw, rre, tight, zrle};
use crate::pixel::PixelFormat;
use crate::protocol::{client_msg, encoding, server_msg, RectHeader, Result, RfbError};

/// The encodings Solstice advertises, in preference order.
///
/// Only what this build decodes: advertising anything else would turn a
/// missing feature into a corrupt framebuffer. In particular no JPEG quality
/// level (−23..−32) is listed, which is what keeps Tight lossless.
pub const ENCODINGS: &[i32] = &[
    encoding::TIGHT,
    encoding::ZRLE,
    encoding::HEXTILE,
    encoding::RRE,
    encoding::COPY_RECT,
    encoding::RAW,
    encoding::PSEUDO_CONTINUOUS_UPDATES,
    encoding::PSEUDO_FENCE,
    encoding::PSEUDO_QEMU_EXTENDED_KEY,
    encoding::PSEUDO_EXTENDED_DESKTOP_SIZE,
    encoding::PSEUDO_DESKTOP_SIZE,
    encoding::PSEUDO_CURSOR,
    encoding::PSEUDO_LAST_RECT,
];

/// What the server turned out to support, learned from the pseudo-encodings it
/// sends back.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerCapabilities {
    /// Pseudo-encoding -313 was acknowledged.
    pub continuous_updates: bool,
    /// Pseudo-encoding -312 was acknowledged.
    pub fence: bool,
    /// Pseudo-encoding -258 was acknowledged.
    pub qemu_extended_key: bool,
    /// Pseudo-encoding -308 was acknowledged.
    pub extended_desktop_size: bool,
}

/// Build `SetPixelFormat`.
pub fn set_pixel_format(format: &PixelFormat) -> Vec<u8> {
    let mut out = vec![client_msg::SET_PIXEL_FORMAT, 0, 0, 0];
    out.extend_from_slice(&format.to_bytes());
    out
}

/// Build `SetEncodings`.
pub fn set_encodings(encodings: &[i32]) -> Vec<u8> {
    let mut out = vec![client_msg::SET_ENCODINGS, 0];
    out.extend_from_slice(&(encodings.len() as u16).to_be_bytes());
    for e in encodings {
        out.extend_from_slice(&e.to_be_bytes());
    }
    out
}

/// Build `FramebufferUpdateRequest`.
pub fn update_request(incremental: bool, rect: Rect) -> Vec<u8> {
    let mut out = vec![
        client_msg::FRAMEBUFFER_UPDATE_REQUEST,
        u8::from(incremental),
    ];
    out.extend_from_slice(&(rect.x as u16).to_be_bytes());
    out.extend_from_slice(&(rect.y as u16).to_be_bytes());
    out.extend_from_slice(&(rect.width as u16).to_be_bytes());
    out.extend_from_slice(&(rect.height as u16).to_be_bytes());
    out
}

/// Build `EnableContinuousUpdates`.
pub fn enable_continuous_updates(enable: bool, rect: Rect) -> Vec<u8> {
    let mut out = vec![client_msg::ENABLE_CONTINUOUS_UPDATES, u8::from(enable)];
    out.extend_from_slice(&(rect.x as u16).to_be_bytes());
    out.extend_from_slice(&(rect.y as u16).to_be_bytes());
    out.extend_from_slice(&(rect.width as u16).to_be_bytes());
    out.extend_from_slice(&(rect.height as u16).to_be_bytes());
    out
}

/// Build a `ClientFence` answering a `ServerFence`.
pub fn client_fence(flags: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![client_msg::CLIENT_FENCE, 0, 0, 0];
    out.extend_from_slice(&flags.to_be_bytes());
    out.push(payload.len() as u8);
    out.extend_from_slice(payload);
    out
}

/// Build `SetDesktopSize` (client message 251), the request half of
/// ExtendedDesktopSize.
pub fn set_desktop_size(width: u16, height: u16) -> Vec<u8> {
    let mut out = vec![251u8, 0];
    out.extend_from_slice(&width.to_be_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    out.push(1); // one screen
    out.push(0); // padding
                 // Screen: id, x, y, w, h, flags.
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&width.to_be_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

/// Drives one connection's reads.
pub struct UpdateLoop<R> {
    reader: R,
    format: PixelFormat,
    /// The composite this loop decodes into. Owned outright, so no lock is
    /// held across a decode -- decoders are `async`, and a guard that crossed
    /// an await would make the whole task non-`Send`, besides blocking the
    /// encoder for the length of a network read.
    local: Framebuffer,
    fb: FramebufferHandle,
    /// Composited at publication; see `crate::cursor`.
    pointer: Arc<Mutex<Pointer>>,
    events: broadcast::Sender<BackendEvent>,
    outgoing: mpsc::Sender<Vec<u8>>,
    zlib: ZlibStream,
    tight: TightStreams,
    caps: ServerCapabilities,
    continuous: bool,
    rectangles: BTreeMap<i32, u64>,
}

impl<R: AsyncRead + Unpin> UpdateLoop<R> {
    /// Build one.
    pub fn new(
        reader: R,
        format: PixelFormat,
        fb: FramebufferHandle,
        events: broadcast::Sender<BackendEvent>,
        outgoing: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        let (w, h) = {
            let guard = fb.read();
            (guard.width(), guard.height())
        };
        Self {
            reader,
            format,
            local: Framebuffer::new(w, h),
            fb,
            pointer: Arc::default(),
            events,
            outgoing,
            zlib: ZlibStream::new(),
            tight: TightStreams::new(),
            caps: ServerCapabilities::default(),
            continuous: false,
            rectangles: BTreeMap::new(),
        }
    }

    /// The pointer this loop draws, for the session to move.
    pub fn pointer(&self) -> Arc<Mutex<Pointer>> {
        self.pointer.clone()
    }

    /// What the server turned out to support.
    pub fn capabilities(&self) -> ServerCapabilities {
        self.caps
    }

    /// How many rectangles of each true encoding have been decoded. A server
    /// may answer with any encoding the client listed, so this is how a test
    /// learns which ones it actually got.
    pub fn rectangles_by_encoding(&self) -> &BTreeMap<i32, u64> {
        &self.rectangles
    }

    /// Read and dispatch one server message.
    pub async fn step(&mut self) -> Result<()> {
        let mut kind = [0u8; 1];
        self.reader.read_exact(&mut kind).await?;
        match kind[0] {
            server_msg::FRAMEBUFFER_UPDATE => self.framebuffer_update().await,
            server_msg::SET_COLOUR_MAP_ENTRIES => self.skip_colour_map().await,
            server_msg::BELL => Ok(()),
            server_msg::SERVER_CUT_TEXT => self.skip_cut_text().await,
            server_msg::END_OF_CONTINUOUS_UPDATES => {
                self.continuous = false;
                Ok(())
            }
            server_msg::SERVER_FENCE => self.server_fence().await,
            other => Err(RfbError::Protocol(format!(
                "unknown server message {other}"
            ))),
        }
    }

    async fn framebuffer_update(&mut self) -> Result<()> {
        let mut head = [0u8; 3];
        self.reader.read_exact(&mut head).await?;
        let count = u16::from_be_bytes([head[1], head[2]]);
        tracing::debug!(rectangles = count, "framebuffer update");

        let mut damage: Option<Rect> = None;
        let mut resized = None;
        for _ in 0..count {
            let mut raw_header = [0u8; 12];
            self.reader.read_exact(&mut raw_header).await?;
            let header = RectHeader::parse(&raw_header);

            match header.encoding {
                encoding::PSEUDO_LAST_RECT => break,
                encoding::PSEUDO_DESKTOP_SIZE => {
                    resized = self.size_change(header.width, header.height);
                    continue;
                }
                encoding::PSEUDO_EXTENDED_DESKTOP_SIZE => {
                    // Both the advertisement and the answer to a client's own
                    // `SetDesktopSize` arrive as this pseudo-rectangle, and
                    // TigerVNC sends one on every full update. Treating each as
                    // a resize reallocates the framebuffer, triggers another
                    // full request, and loops -- which is exactly what it did
                    // until this check was added. The geometry is what decides.
                    self.caps.extended_desktop_size = true;
                    self.skip_extended_desktop_size().await?;
                    resized = self.size_change(header.width, header.height);
                    continue;
                }
                encoding::PSEUDO_CONTINUOUS_UPDATES => {
                    self.caps.continuous_updates = true;
                    continue;
                }
                encoding::PSEUDO_FENCE => {
                    self.caps.fence = true;
                    continue;
                }
                encoding::PSEUDO_QEMU_EXTENDED_KEY => {
                    self.caps.qemu_extended_key = true;
                    continue;
                }
                encoding::PSEUDO_CURSOR => {
                    let shape =
                        crate::cursor::decode(&mut self.reader, &self.format, &header).await?;
                    let changed = {
                        let mut pointer = self.pointer.lock().expect("pointer lock");
                        pointer.set_shape(&mut self.fb.write(), shape)
                    };
                    if let Some(rect) = changed {
                        let _ = self.events.send(BackendEvent::Damage(rect));
                    }
                    continue;
                }
                _ => {}
            }

            let rect = header.rect();
            let fb = &mut self.local;
            match header.encoding {
                encoding::RAW => raw::decode(&mut self.reader, &self.format, rect, fb).await?,
                encoding::COPY_RECT => copy_rect::decode(&mut self.reader, rect, fb).await?,
                encoding::RRE => rre::decode(&mut self.reader, &self.format, rect, fb).await?,
                encoding::HEXTILE => {
                    hextile::decode(&mut self.reader, &self.format, rect, fb).await?
                }
                encoding::ZRLE => {
                    zrle::decode(&mut self.reader, &self.format, rect, fb, &mut self.zlib).await?
                }
                encoding::TIGHT => {
                    tight::decode(&mut self.reader, &self.format, rect, fb, &mut self.tight).await?
                }
                other => return Err(RfbError::UnsupportedEncoding(other)),
            }
            *self.rectangles.entry(header.encoding).or_default() += 1;
            damage = Some(damage.map_or(rect, |d| d.union(&rect)));
        }

        if let Some((width, height)) = resized {
            let (width, height) = (width as u32, height as u32);
            self.local.resize(width, height);
            {
                let mut pointer = self.pointer.lock().expect("pointer lock");
                self.fb.write().resize(width, height);
                pointer.forget_drawn();
            }
            let _ = self.events.send(BackendEvent::Resize { width, height });
            // The framebuffer is new, so everything in it is damage.
            let _ = self
                .events
                .send(BackendEvent::Damage(Rect::whole(width, height)));
            // Ask for a full update: an incremental one against a framebuffer
            // that no longer exists would arrive as nothing at all.
            let _ = self
                .outgoing
                .send(update_request(false, Rect::whole(width, height)))
                .await;
            return Ok(());
        }

        if let Some(rect) = damage {
            // Publish under a short lock, then announce. The encoder sees a
            // consistent region and never waits on a network read.
            self.pointer.lock().expect("pointer lock").publish(
                &mut self.fb.write(),
                &self.local,
                rect,
            );
            let _ = self.events.send(BackendEvent::Damage(rect));
        }
        if !self.continuous {
            let (w, h) = (self.local.width(), self.local.height());
            let _ = self
                .outgoing
                .send(update_request(true, Rect::whole(w, h)))
                .await;
        }
        Ok(())
    }

    /// `Some((w, h))` only when the geometry actually differs from what we
    /// already have.
    fn size_change(&self, width: u16, height: u16) -> Option<(u16, u16)> {
        let (w, h) = (width as u32, height as u32);
        if w == 0 || h == 0 || (w == self.local.width() && h == self.local.height()) {
            None
        } else {
            Some((width, height))
        }
    }

    async fn skip_extended_desktop_size(&mut self) -> Result<()> {
        let mut head = [0u8; 4];
        self.reader.read_exact(&mut head).await?;
        let screens = head[0] as usize;
        let mut rest = vec![0u8; screens * 16];
        self.reader.read_exact(&mut rest).await?;
        Ok(())
    }

    async fn skip_colour_map(&mut self) -> Result<()> {
        let mut head = [0u8; 5];
        self.reader.read_exact(&mut head).await?;
        let count = u16::from_be_bytes([head[3], head[4]]) as usize;
        let mut rest = vec![0u8; count * 6];
        self.reader.read_exact(&mut rest).await?;
        Ok(())
    }

    async fn skip_cut_text(&mut self) -> Result<()> {
        // Moonlight's protocol has no clipboard, so ServerCutText has nowhere
        // to go (`docs/bridging-design.md` §4.4). It is consumed rather than
        // ignored, because the bytes are in the stream either way.
        let mut head = [0u8; 7];
        self.reader.read_exact(&mut head).await?;
        let len = u32::from_be_bytes([head[3], head[4], head[5], head[6]]);
        if len > 1 << 20 {
            return Err(RfbError::Limit(format!("ServerCutText of {len} bytes")));
        }
        let mut rest = vec![0u8; len as usize];
        self.reader.read_exact(&mut rest).await?;
        Ok(())
    }

    async fn server_fence(&mut self) -> Result<()> {
        let mut head = [0u8; 8];
        self.reader.read_exact(&mut head).await?;
        let flags = u32::from_be_bytes([head[3], head[4], head[5], head[6]]);
        let len = head[7] as usize;
        let mut payload = vec![0u8; len];
        self.reader.read_exact(&mut payload).await?;
        // Bit 31 is "request"; echo it back with the request bit cleared.
        if flags & 0x8000_0000 != 0 {
            let _ = self
                .outgoing
                .send(client_fence(flags & !0x8000_0000, &payload))
                .await;
        }
        Ok(())
    }

    /// Note that continuous updates are now in effect.
    pub fn set_continuous(&mut self, on: bool) {
        self.continuous = on;
    }
}

/// Pump outgoing messages to the socket.
pub async fn writer_task<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    while let Some(message) = rx.recv().await {
        writer.write_all(&message).await?;
        writer.flush().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Framebuffer, event sender, outgoing receiver, outgoing sender.
    type Fixture = (
        FramebufferHandle,
        broadcast::Sender<BackendEvent>,
        mpsc::Receiver<Vec<u8>>,
        mpsc::Sender<Vec<u8>>,
    );

    fn fixture() -> Fixture {
        let fb = FramebufferHandle::with_size(16, 16);
        let (events, _) = broadcast::channel(16);
        let (tx, rx) = mpsc::channel(16);
        (fb, events, rx, tx)
    }

    #[test]
    fn set_encodings_lists_what_we_can_actually_decode() {
        let msg = set_encodings(ENCODINGS);
        assert_eq!(msg[0], client_msg::SET_ENCODINGS);
        assert_eq!(
            u16::from_be_bytes([msg[2], msg[3]]) as usize,
            ENCODINGS.len()
        );
        assert!(ENCODINGS.contains(&encoding::TIGHT));
        assert!(ENCODINGS.contains(&encoding::ZRLE));
        // No JPEG quality level, and no Tight PNG: Tight stays lossless, and
        // the decoder has no JPEG path to receive one.
        assert!(!ENCODINGS.iter().any(|e| (-32..=-23).contains(e)));
        assert!(!ENCODINGS.contains(&-260));
        assert!(ENCODINGS.contains(&encoding::PSEUDO_QEMU_EXTENDED_KEY));
    }

    #[test]
    fn update_requests_are_well_formed() {
        let msg = update_request(
            true,
            Rect {
                x: 1,
                y: 2,
                width: 3,
                height: 4,
            },
        );
        assert_eq!(msg, vec![3, 1, 0, 1, 0, 2, 0, 3, 0, 4]);
    }

    #[tokio::test]
    async fn a_raw_update_lands_in_the_framebuffer_and_raises_damage() {
        let (fb, events, mut rx, tx) = fixture();
        let mut rx_events = events.subscribe();

        let mut script = vec![server_msg::FRAMEBUFFER_UPDATE, 0];
        script.extend_from_slice(&1u16.to_be_bytes());
        script.extend_from_slice(
            &RectHeader {
                x: 0,
                y: 0,
                width: 2,
                height: 2,
                encoding: encoding::RAW,
            }
            .to_bytes(),
        );
        script.extend([1u8, 2, 3, 0].repeat(4));

        let mut loop_ = UpdateLoop::new(
            std::io::Cursor::new(script),
            PixelFormat::BGRA,
            fb.clone(),
            events,
            tx,
        );
        loop_.step().await.unwrap();

        assert_eq!(fb.read().pixel(0, 0), Some([1, 2, 3, 255]));
        assert_eq!(
            rx_events.recv().await.unwrap(),
            BackendEvent::Damage(Rect {
                x: 0,
                y: 0,
                width: 2,
                height: 2
            })
        );
        // And, with continuous updates off, the next request went out.
        assert_eq!(
            rx.recv().await.unwrap()[0],
            client_msg::FRAMEBUFFER_UPDATE_REQUEST
        );
    }

    #[tokio::test]
    async fn pseudo_encodings_are_recorded_as_capabilities() {
        let (fb, events, _rx, tx) = fixture();
        let mut script = vec![server_msg::FRAMEBUFFER_UPDATE, 0];
        script.extend_from_slice(&3u16.to_be_bytes());
        for e in [
            encoding::PSEUDO_CONTINUOUS_UPDATES,
            encoding::PSEUDO_FENCE,
            encoding::PSEUDO_QEMU_EXTENDED_KEY,
        ] {
            script.extend_from_slice(
                &RectHeader {
                    x: 0,
                    y: 0,
                    width: 0,
                    height: 0,
                    encoding: e,
                }
                .to_bytes(),
            );
        }
        let mut loop_ = UpdateLoop::new(
            std::io::Cursor::new(script),
            PixelFormat::BGRA,
            fb,
            events,
            tx,
        );
        loop_.step().await.unwrap();
        assert_eq!(
            loop_.capabilities(),
            ServerCapabilities {
                continuous_updates: true,
                fence: true,
                qemu_extended_key: true,
                extended_desktop_size: false
            }
        );
    }

    /// Found against TigerVNC: it sends an ExtendedDesktopSize pseudo-rectangle
    /// on every full update, not only when the size changes. Treating each one
    /// as a resize reallocated the framebuffer -- wiping it black -- and asked
    /// for another full update, which came back with another pseudo-rectangle.
    /// The session livelocked and the screen stayed black. The mock server
    /// could not have found this; only a real one sends that rectangle.
    #[tokio::test]
    async fn a_repeated_size_announcement_is_not_a_resize() {
        let (fb, events, mut rx, tx) = fixture();
        let mut rx_events = events.subscribe();

        let mut script = Vec::new();
        for _ in 0..3 {
            script.extend_from_slice(&[server_msg::FRAMEBUFFER_UPDATE, 0]);
            script.extend_from_slice(&1u16.to_be_bytes());
            script.extend_from_slice(
                &RectHeader {
                    x: 0,
                    y: 0,
                    width: 16,
                    height: 16,
                    encoding: encoding::PSEUDO_EXTENDED_DESKTOP_SIZE,
                }
                .to_bytes(),
            );
            // ExtendedDesktopSize payload: one screen.
            script.extend_from_slice(&[1, 0, 0, 0]);
            script.extend_from_slice(&[0u8; 16]);
        }

        let mut loop_ = UpdateLoop::new(
            std::io::Cursor::new(script),
            PixelFormat::BGRA,
            fb.clone(),
            events,
            tx,
        );
        for _ in 0..3 {
            loop_.step().await.unwrap();
        }

        assert!(loop_.capabilities().extended_desktop_size);
        assert_eq!((fb.read().width(), fb.read().height()), (16, 16));
        assert!(
            rx_events.try_recv().is_err(),
            "an unchanged size must not raise a Resize or a full-screen Damage"
        );
        // And no full-update request storm.
        let mut full_requests = 0;
        while let Ok(message) = rx.try_recv() {
            if message[0] == client_msg::FRAMEBUFFER_UPDATE_REQUEST && message[1] == 0 {
                full_requests += 1;
            }
        }
        assert_eq!(
            full_requests, 0,
            "an unchanged size asked for {full_requests} full updates"
        );
    }

    #[tokio::test]
    async fn a_desktop_size_change_resizes_and_asks_for_a_full_update() {
        let (fb, events, mut rx, tx) = fixture();
        let mut rx_events = events.subscribe();
        let mut script = vec![server_msg::FRAMEBUFFER_UPDATE, 0];
        script.extend_from_slice(&1u16.to_be_bytes());
        script.extend_from_slice(
            &RectHeader {
                x: 0,
                y: 0,
                width: 64,
                height: 32,
                encoding: encoding::PSEUDO_DESKTOP_SIZE,
            }
            .to_bytes(),
        );
        let mut loop_ = UpdateLoop::new(
            std::io::Cursor::new(script),
            PixelFormat::BGRA,
            fb.clone(),
            events,
            tx,
        );
        loop_.step().await.unwrap();

        assert_eq!((fb.read().width(), fb.read().height()), (64, 32));
        assert_eq!(
            rx_events.recv().await.unwrap(),
            BackendEvent::Resize {
                width: 64,
                height: 32
            }
        );
        let request = rx.recv().await.unwrap();
        assert_eq!(
            request[1], 0,
            "the request after a resize must not be incremental"
        );
    }

    #[tokio::test]
    async fn a_server_fence_is_echoed() {
        let (fb, events, mut rx, tx) = fixture();
        let mut script = vec![server_msg::SERVER_FENCE, 0, 0, 0];
        script.extend_from_slice(&0x8000_0001u32.to_be_bytes());
        script.push(3);
        script.extend_from_slice(b"abc");
        let mut loop_ = UpdateLoop::new(
            std::io::Cursor::new(script),
            PixelFormat::BGRA,
            fb,
            events,
            tx,
        );
        loop_.step().await.unwrap();
        let reply = rx.recv().await.unwrap();
        assert_eq!(reply[0], client_msg::CLIENT_FENCE);
        assert_eq!(
            u32::from_be_bytes([reply[4], reply[5], reply[6], reply[7]]),
            1
        );
        assert_eq!(&reply[9..], b"abc");
    }

    #[tokio::test]
    async fn an_unrequested_encoding_is_an_error_rather_than_a_guess() {
        let (fb, events, _rx, tx) = fixture();
        let mut script = vec![server_msg::FRAMEBUFFER_UPDATE, 0];
        script.extend_from_slice(&1u16.to_be_bytes());
        script.extend_from_slice(
            &RectHeader {
                x: 0,
                y: 0,
                width: 2,
                height: 2,
                encoding: encoding::ZLIB,
            }
            .to_bytes(),
        );
        let mut loop_ = UpdateLoop::new(
            std::io::Cursor::new(script),
            PixelFormat::BGRA,
            fb,
            events,
            tx,
        );
        assert!(matches!(
            loop_.step().await,
            Err(RfbError::UnsupportedEncoding(encoding::ZLIB))
        ));
    }

    #[tokio::test]
    async fn an_unknown_server_message_ends_the_connection() {
        let (fb, events, _rx, tx) = fixture();
        let mut loop_ = UpdateLoop::new(
            std::io::Cursor::new(vec![99u8]),
            PixelFormat::BGRA,
            fb,
            events,
            tx,
        );
        assert!(loop_.step().await.is_err());
    }

    #[tokio::test]
    async fn server_cut_text_is_consumed_not_ignored() {
        let (fb, events, _rx, tx) = fixture();
        let mut script = vec![server_msg::SERVER_CUT_TEXT, 0, 0, 0];
        script.extend_from_slice(&5u32.to_be_bytes());
        script.extend_from_slice(b"hello");
        script.push(server_msg::BELL);
        let mut loop_ = UpdateLoop::new(
            std::io::Cursor::new(script),
            PixelFormat::BGRA,
            fb,
            events,
            tx,
        );
        loop_.step().await.unwrap();
        // The Bell that follows must still parse, which it only does if the cut
        // text was consumed exactly.
        loop_.step().await.unwrap();
    }

    #[tokio::test]
    async fn an_absurd_cut_text_length_is_refused() {
        let (fb, events, _rx, tx) = fixture();
        let mut script = vec![server_msg::SERVER_CUT_TEXT, 0, 0, 0];
        script.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut loop_ = UpdateLoop::new(
            std::io::Cursor::new(script),
            PixelFormat::BGRA,
            fb,
            events,
            tx,
        );
        assert!(matches!(loop_.step().await, Err(RfbError::Limit(_))));
    }
}
