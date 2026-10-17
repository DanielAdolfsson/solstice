//! The display channel: surfaces, draw commands, video streams, and the
//! framebuffer the encoder reads.
//!
//! This is where SPICE differs most from RFB. RFB hands over rectangles of
//! pixels; SPICE hands over *drawing instructions* against a set of
//! server-side surfaces, with video streams layered on top of the result
//! (`docs/spice-protocol.md` §5). So the client has to keep every surface,
//! execute every command, composite the streams, and only then does it have
//! a picture to encode.
//!
//! # What owns what
//!
//! One task owns the surfaces, the image caches, the streams **and** the
//! cursor, and it is the only thing that writes to the framebuffer. The
//! cursor arrives on its own socket, so the cursor channel's task parses its
//! messages and forwards [`crate::cursor::CursorUpdate`]s into the same queue
//! the display's own messages arrive on.
//!
//! That is deliberate. The alternative -- a mutex around the framebuffer
//! shared between the two channels -- needs a third buffer to hold the
//! pixels under the cursor, because moving the pointer has to repaint what
//! was beneath it. With one owner, "repaint what was beneath it" is just
//! publishing the union of the old and new cursor rectangles out of the
//! primary surface, which is already there.
//!
//! # Batching
//!
//! Damage is accumulated and published when the queue goes momentarily
//! empty, rather than once per command. A full-screen redraw is hundreds of
//! draw commands, and a `BackendEvent::Damage` per command would hand the
//! frame clock hundreds of wake-ups for one frame.

pub mod commands;
pub mod image;
pub mod raster;
pub mod stream;
pub mod surface;
pub mod types;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use solstice_backend::{BackendEvent, FramebufferHandle};
use solstice_spice_codec::Limits;
use tokio::sync::{broadcast, mpsc};

use crate::channel::{Message, OutMessage};
use crate::cursor::{CursorState, CursorUpdate};
use crate::display::image::ImageDecoder;
use crate::display::stream::StreamSet;
use crate::display::surface::{Surface, SurfaceSet};
use crate::display::types::{Clip, SpiceRect};
use crate::error::{Result, SpiceError};
use crate::protocol::{display_msg, display_msgc, image_type, surface_fmt, video_codec};
use crate::wire::{Reader, Writer};

/// Something for the display task to act on.
#[derive(Clone, Debug)]
pub enum DisplayEvent {
    /// A message off the display channel.
    Message(Message),
    /// A pointer change off the cursor channel.
    Cursor(CursorUpdate),
    /// The cursor channel ended; stop drawing the pointer.
    CursorGone,
}

/// How much the client will hold on the display channel's behalf.
#[derive(Clone, Copy, Debug)]
pub struct DisplayLimits {
    /// Ceilings handed to the image decoders.
    pub codec: Limits,
    /// Bytes of decoded image kept in the pixmap cache.
    ///
    /// The number announced to the server in `DISPLAY_INIT` is derived from
    /// this, so the two ends cannot drift: a server told the cache is larger
    /// than it is will send `FROM_CACHE` for something already evicted.
    pub pixmap_cache_bytes: usize,
}

impl Default for DisplayLimits {
    fn default() -> Self {
        DisplayLimits {
            codec: Limits::default(),
            // `spice-gtk` defaults to the same order (its `cache-size`
            // property is 1 << 26 bytes).
            pixmap_cache_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Every message [`commands::execute`] runs, in the order `enums.h` numbers
/// them.
const DRAW_KINDS: [u16; 13] = [
    display_msg::COPY_BITS,
    display_msg::DRAW_FILL,
    display_msg::DRAW_OPAQUE,
    display_msg::DRAW_COPY,
    display_msg::DRAW_BLEND,
    display_msg::DRAW_BLACKNESS,
    display_msg::DRAW_WHITENESS,
    display_msg::DRAW_INVERS,
    display_msg::DRAW_ROP3,
    display_msg::DRAW_STROKE,
    display_msg::DRAW_TEXT,
    display_msg::DRAW_TRANSPARENT,
    display_msg::DRAW_ALPHA_BLEND,
];

/// Every image encoding [`image::ImageDecoder`] can be handed, by
/// `image_type` number.
const IMAGE_KINDS: [u8; 12] = [
    image_type::BITMAP,
    image_type::QUIC,
    image_type::LZ_PLT,
    image_type::LZ_RGB,
    image_type::GLZ_RGB,
    image_type::FROM_CACHE,
    image_type::SURFACE,
    image_type::JPEG,
    image_type::FROM_CACHE_LOSSLESS,
    image_type::ZLIB_GLZ_RGB,
    image_type::JPEG_ALPHA,
    image_type::LZ4,
];

/// How many of each draw command the display channel has executed, and how
/// many of each image encoding it has decoded.
///
/// A test can make a guest *emit* `DRAW_STROKE`, but without this it cannot
/// tell whether one arrived: a correct screen is equally consistent with the
/// server having rasterised the line itself and sent a `DRAW_COPY` of the
/// result. The same goes for images -- a soak that means to exercise GLZ's
/// window has to know that GLZ is what it got. Counted only on success, so a
/// command or image that was received and then dropped as undecodable does
/// not count as covered.
///
/// One atomic per kind rather than a map behind a lock, because the display
/// task bumps it once per command and a full-screen redraw is hundreds.
#[derive(Debug, Default)]
pub struct DisplayCounts {
    draws: [AtomicU64; DRAW_KINDS.len()],
    images: [AtomicU64; IMAGE_KINDS.len()],
}

impl DisplayCounts {
    fn record_draw(&self, kind: u16) {
        if let Some(i) = DRAW_KINDS.iter().position(|&k| k == kind) {
            self.draws[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_image(&self, kind: u8) {
        if let Some(i) = IMAGE_KINDS.iter().position(|&k| k == kind) {
            self.images[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The draw commands executed at least once, keyed by `display_msg`
    /// number.
    pub fn draws(&self) -> BTreeMap<u16, u64> {
        snapshot(&DRAW_KINDS, &self.draws)
    }

    /// The image encodings decoded at least once, keyed by `image_type`
    /// number.
    pub fn images(&self) -> BTreeMap<u8, u64> {
        snapshot(&IMAGE_KINDS, &self.images)
    }
}

fn snapshot<K: Copy + Ord>(kinds: &[K], counts: &[AtomicU64]) -> BTreeMap<K, u64> {
    kinds
        .iter()
        .zip(counts)
        .map(|(&kind, count)| (kind, count.load(Ordering::Relaxed)))
        .filter(|&(_, count)| count > 0)
        .collect()
}

/// The display channel's state.
pub struct DisplayChannel {
    surfaces: SurfaceSet,
    images: ImageDecoder,
    streams: StreamSet,
    cursor: CursorState,
    fb: FramebufferHandle,
    events: broadcast::Sender<BackendEvent>,
    outgoing: mpsc::Sender<OutMessage>,
    limits: DisplayLimits,
    /// Damage accumulated on the primary surface since the last publish.
    pending: SpiceRect,
    /// Where the cursor was when it was last drawn, so moving it can repaint
    /// what it was covering.
    drawn_cursor: Option<SpiceRect>,
    /// The primary surface's size, packed, for the session to read without
    /// taking the framebuffer lock the encoder is holding.
    dimensions: Arc<AtomicU64>,
    /// The `image_compression` to ask the server for, if any; see
    /// [`DisplayChannel::init_messages`].
    preferred_compression: Option<u8>,
    /// What has been executed and decoded; see [`DisplayCounts`]. Shared
    /// with the image decoder, which counts the images.
    counts: Arc<DisplayCounts>,
    /// Whether the server has said the primary surface is worth showing.
    ///
    /// `DISPLAY_MARK` is the server saying the surface has been filled in.
    /// Publishing before it shows a partially drawn screen; the flag costs
    /// nothing and a server that never sends it is handled by treating the
    /// first draw as the mark.
    marked: bool,
}

impl DisplayChannel {
    /// Build one over a framebuffer the encoder already holds.
    pub fn new(
        fb: FramebufferHandle,
        events: broadcast::Sender<BackendEvent>,
        outgoing: mpsc::Sender<OutMessage>,
        limits: DisplayLimits,
    ) -> Self {
        let images = ImageDecoder::new(limits.codec, limits.pixmap_cache_bytes);
        DisplayChannel {
            surfaces: SurfaceSet::new(),
            counts: images.counts(),
            images,
            preferred_compression: None,
            streams: StreamSet::new(),
            cursor: CursorState::default(),
            fb,
            events,
            outgoing,
            limits,
            pending: SpiceRect::default(),
            drawn_cursor: None,
            dimensions: Arc::new(AtomicU64::new(0)),
            marked: false,
        }
    }

    /// A handle to the primary surface's size, updated as it changes.
    ///
    /// Packed into one word so the session can read it without a lock: the
    /// framebuffer's own lock is held by the encoder for the length of a
    /// colour conversion, and `dimensions()` is called on the input path.
    pub fn dimensions_handle(&self) -> Arc<AtomicU64> {
        self.dimensions.clone()
    }

    /// Ask the server for one `image_compression` rather than leaving its
    /// configuration alone. `None`, the default, sends no preference.
    pub fn with_preferred_compression(mut self, preferred: Option<u8>) -> Self {
        self.preferred_compression = preferred;
        self
    }

    /// A handle to the counts of what has been executed and decoded.
    pub fn counts_handle(&self) -> Arc<DisplayCounts> {
        self.counts.clone()
    }

    /// The messages to send as soon as the channel is up.
    ///
    /// `DISPLAY_INIT` declares the pixmap cache and the GLZ window **in
    /// pixels**, which is why both are divided by four here -- the same
    /// conversion `channel-display.c:1173-1176` does.
    pub fn init_messages(&self) -> Vec<OutMessage> {
        let mut out = Vec::new();

        let mut init = Writer::new();
        init.u8(1) // pixmap_cache_id
            .u64((self.limits.pixmap_cache_bytes / 4) as u64)
            .u8(1) // glz_dictionary_id
            .u32((self.limits.codec.glz_window_bytes / 4) as u32);
        out.push(OutMessage::new(display_msgc::INIT, init.finish()));

        // Only when asked. `PREFERRED_COMPRESSION` is not a hint the server
        // weighs against its own configuration: `spice-server` adopts it
        // outright, so sending one overrides whatever `image-compression=`
        // the operator gave QEMU. `spice-gtk` sends nothing unless its user
        // set a preference, and this client follows it. (This used to send
        // `AUTO_GLZ` unconditionally, which is also how the real-server codec
        // sweep came to exercise GLZ under every name it forced.)
        if let Some(preferred) = self.preferred_compression {
            let mut compression = Writer::new();
            compression.u8(preferred);
            out.push(OutMessage::new(
                display_msgc::PREFERRED_COMPRESSION,
                compression.finish(),
            ));
        }

        // MJPEG is the only stream codec with a pure-Rust decoder in the
        // tree, and the frames are re-encoded immediately anyway; see
        // `stream.rs` for why that is the right trade rather than a gap.
        let mut codecs = Writer::new();
        codecs.u8(1).u8(video_codec::MJPEG);
        out.push(OutMessage::new(
            display_msgc::PREFERRED_VIDEO_CODEC_TYPE,
            codecs.finish(),
        ));

        out
    }

    /// The primary surface's size, if one exists.
    pub fn dimensions(&self) -> Option<(u32, u32)> {
        self.surfaces.primary().map(|s| (s.width(), s.height()))
    }

    /// Handle one event.
    ///
    /// Errors that [`SpiceError::is_recoverable`] accepts are logged and
    /// swallowed: a bitmap this client cannot decode costs one draw command,
    /// and tearing down a session over it would be worse than the hole it
    /// leaves.
    pub fn handle(&mut self, event: DisplayEvent) -> Result<()> {
        match event {
            DisplayEvent::Message(message) => match self.message(message.kind, &message.body) {
                Err(e) if e.is_recoverable() => {
                    tracing::warn!(error = %e, "dropping a spice draw command");
                    Ok(())
                }
                other => other,
            },
            DisplayEvent::Cursor(update) => {
                self.cursor_update(update);
                Ok(())
            }
            DisplayEvent::CursorGone => {
                self.cursor_update(CursorUpdate::Reset);
                Ok(())
            }
        }
    }

    fn message(&mut self, kind: u16, body: &[u8]) -> Result<()> {
        tracing::trace!(kind, len = body.len(), "spice display message");
        match kind {
            display_msg::MODE => {
                // Pre-surface servers announce the primary this way. Treat it
                // as a surface-0 creation so there is exactly one path that
                // allocates the framebuffer.
                let mut r = Reader::new(body);
                let width = r.u32()?;
                let height = r.u32()?;
                let _bits = r.u32()?;
                self.create_surface(0, width, height, surface_fmt::RGB32_XRGB, true)?;
            }
            display_msg::MARK => {
                self.marked = true;
                self.damage_whole_primary();
            }
            display_msg::RESET => {
                // Not "forget everything": the reference client clears the
                // primary surface's pixels and the palette cache, drops the
                // mark, and leaves the surfaces, the pixmap cache and the
                // GLZ window alone (`channel-display.c:1238-1252`). Clearing
                // more than the server did is how a client and a server stop
                // agreeing about what is cached.
                self.images.invalidate_all_palettes();
                self.marked = false;
                self.pending = SpiceRect::default();
                if let Some(id) = self.surfaces.primary_id() {
                    if let Some(primary) = self.surfaces.get_mut(id) {
                        let format = primary.format();
                        let (width, height) = (primary.width(), primary.height());
                        *primary = Surface::new(width, height, format);
                    }
                    self.damage_whole_primary();
                }
            }
            display_msg::SURFACE_CREATE => {
                let mut r = Reader::new(body);
                let id = r.u32()?;
                let width = r.u32()?;
                let height = r.u32()?;
                let format = r.u32()?;
                let flags = r.u32()?;
                let primary = flags & crate::protocol::surface_flags::PRIMARY != 0;
                self.create_surface(id, width, height, format, primary)?;
            }
            display_msg::SURFACE_DESTROY => {
                let mut r = Reader::new(body);
                let id = r.u32()?;
                self.surfaces.destroy(id);
            }
            display_msg::INVAL_LIST => {
                let mut r = Reader::new(body);
                let count = r.u16()?;
                let count = r.count(count as u32, 9)?;
                for _ in 0..count {
                    let _kind = r.u8()?;
                    self.images.invalidate_pixmap(r.u64()?);
                }
            }
            display_msg::INVAL_ALL_PIXMAPS => self.images.invalidate_all_pixmaps(),
            display_msg::INVAL_PALETTE => {
                let mut r = Reader::new(body);
                self.images.invalidate_palette(r.u64()?);
            }
            display_msg::INVAL_ALL_PALETTES => self.images.invalidate_all_palettes(),

            display_msg::STREAM_CREATE => {
                let (id, stream) = self.streams.create(body)?;
                tracing::debug!(
                    id,
                    codec = stream.codec,
                    width = stream.width,
                    height = stream.height,
                    decodable = stream.is_decodable(),
                    "spice stream created"
                );
            }
            display_msg::STREAM_DATA => {
                let frame = stream::parse_data(body)?;
                self.stream_frame(frame)?;
            }
            display_msg::STREAM_DATA_SIZED => {
                let frame = stream::parse_data_sized(body)?;
                self.stream_frame(frame)?;
            }
            display_msg::STREAM_CLIP => {
                let mut r = Reader::new(body);
                let id = r.u32()?;
                let clip = Clip::parse(&mut r)?;
                self.streams.set_clip(id, clip);
            }
            display_msg::STREAM_DESTROY => {
                let mut r = Reader::new(body);
                self.streams.destroy(r.u32()?);
            }
            display_msg::STREAM_DESTROY_ALL => self.streams.clear(),
            display_msg::STREAM_ACTIVATE_REPORT => {
                let mut r = Reader::new(body);
                let stream_id = r.u32()?;
                let unique_id = r.u32()?;
                let _max_window_size = r.u32()?;
                let _timeout_ms = r.u32()?;
                if let Some(stream) = self.streams.get_mut(stream_id) {
                    stream.report_id = Some(unique_id);
                }
            }

            display_msg::MONITORS_CONFIG => {
                // Informational here: the guest's monitor layout is set
                // through the agent, not read from this. Logged because a
                // mismatch between it and the primary surface is the first
                // sign a resize did not take.
                let mut r = Reader::new(body);
                let count = r.u16()?;
                let _max_allowed = r.u16()?;
                tracing::debug!(heads = count, "spice monitors config");
            }

            display_msg::GL_SCANOUT_UNIX | display_msg::GL_SCANOUT2_UNIX | display_msg::GL_DRAW => {
                // Local-only by construction: these pass a dmabuf file
                // descriptor. The capability is not advertised, so a server
                // sending them anyway is misbehaving rather than being
                // accommodated.
                return Err(SpiceError::protocol(
                    "server sent a GL scanout message to a client that did not advertise GL",
                ));
            }

            display_msg::DRAW_COMPOSITE => {
                // Same reasoning: `SPICE_DISPLAY_CAP_COMPOSITE` is not
                // advertised, so a conforming server will not send this.
                // Executing it wrongly would corrupt the framebuffer, which
                // is worse than refusing.
                return Err(SpiceError::protocol(
                    "server sent DRAW_COMPOSITE to a client that did not advertise the capability",
                ));
            }

            display_msg::DRAW_FILL
            | display_msg::DRAW_OPAQUE
            | display_msg::DRAW_COPY
            | display_msg::DRAW_BLEND
            | display_msg::DRAW_BLACKNESS
            | display_msg::DRAW_WHITENESS
            | display_msg::DRAW_INVERS
            | display_msg::DRAW_ROP3
            | display_msg::DRAW_STROKE
            | display_msg::DRAW_TEXT
            | display_msg::DRAW_TRANSPARENT
            | display_msg::DRAW_ALPHA_BLEND
            | display_msg::COPY_BITS => {
                let damage = commands::execute(kind, body, &mut self.surfaces, &mut self.images)?;
                self.counts.record_draw(kind);
                if let Some(damage) = damage {
                    self.marked = true;
                    self.accumulate(damage.surface_id, damage.rect);
                }
            }

            other => {
                // A message this client does not know is not a reason to
                // tear a session down: the protocol grows, and the framing
                // layer has already read the body, so the stream stays in
                // step.
                tracing::debug!(kind = other, "ignoring display message");
            }
        }
        Ok(())
    }

    fn create_surface(
        &mut self,
        id: u32,
        width: u32,
        height: u32,
        format: u32,
        primary: bool,
    ) -> Result<()> {
        self.surfaces.create(id, width, height, format, primary)?;
        if primary {
            self.dimensions
                .store(((width as u64) << 32) | height as u64, Ordering::Relaxed);
            let resized = {
                let mut fb = self.fb.write();
                if fb.width() != width || fb.height() != height {
                    fb.resize(width, height);
                    true
                } else {
                    false
                }
            };
            // The caches are deliberately *not* touched. A new primary
            // surface does not invalidate the pixmap cache or the GLZ
            // window on the server, so clearing them here would leave the
            // two ends disagreeing -- and a GLZ disagreement is the one that
            // cannot be recovered per-image.
            self.drawn_cursor = None;
            self.marked = false;
            self.pending = SpiceRect::default();
            if resized {
                let _ = self.events.send(BackendEvent::Resize { width, height });
            }
            tracing::info!(width, height, format, "spice primary surface");
        }
        Ok(())
    }

    fn stream_frame(&mut self, frame: stream::StreamFrame<'_>) -> Result<()> {
        let Some(stream) = self.streams.get(frame.id) else {
            // A frame for a stream that was destroyed is a race, not an
            // error: the destroy and the frame crossed on the wire.
            return Ok(());
        };
        let surface_id = stream.surface_id;
        let dest = frame.dest.unwrap_or(stream.dest);
        let clip = stream.clip.clone();
        let decodable = stream.is_decodable();
        let top_down = stream.top_down();
        let report_id = stream.report_id;
        let refused = stream.refused;

        if !decodable {
            if !refused {
                if let Some(stream) = self.streams.get_mut(frame.id) {
                    stream.refused = true;
                }
                let body = stream::unsupported_report(
                    frame.id,
                    report_id.unwrap_or(0),
                    frame.multi_media_time,
                );
                let _ = self
                    .outgoing
                    .try_send(OutMessage::new(display_msgc::STREAM_REPORT, body));
                tracing::warn!(
                    id = frame.id,
                    "told the server this client cannot decode the stream's codec"
                );
            }
            return Ok(());
        }

        let Some(surface) = self.surfaces.get(surface_id) else {
            return Ok(());
        };
        let max_pixels = (surface.width() as u64 * surface.height() as u64).max(1);
        let decoded = stream::decode_mjpeg(frame.data, max_pixels)?;
        let src = SpiceRect {
            top: 0,
            left: 0,
            bottom: decoded.height as i32,
            right: decoded.width as i32,
        };
        let sampler = raster::Sampler::new(&decoded, src, dest, raster::ScaleMode::Interpolate);
        let surface = self.surfaces.get_mut(surface_id).expect("checked above");
        if top_down {
            raster::draw(
                surface,
                &dest,
                &clip,
                None,
                raster::Rop::COPY,
                &raster::Source::Bitmap(sampler),
            );
        } else {
            // A bottom-up stream arrives last row first. Flipping the
            // sampler's reading is cheaper than flipping the frame.
            let flipped = flip_vertically(&decoded);
            let sampler = raster::Sampler::new(&flipped, src, dest, raster::ScaleMode::Interpolate);
            raster::draw(
                surface,
                &dest,
                &clip,
                None,
                raster::Rop::COPY,
                &raster::Source::Bitmap(sampler),
            );
        }
        self.marked = true;
        self.accumulate(surface_id, dest);
        Ok(())
    }

    fn cursor_update(&mut self, update: CursorUpdate) {
        match update {
            CursorUpdate::Set {
                shape,
                x,
                y,
                visible,
            } => {
                self.cursor.shape = shape;
                self.cursor.x = x;
                self.cursor.y = y;
                self.cursor.visible = visible && self.cursor.shape.is_some();
            }
            CursorUpdate::Move { x, y } => {
                self.cursor.x = x;
                self.cursor.y = y;
                self.cursor.visible = self.cursor.shape.is_some();
            }
            CursorUpdate::Hide => self.cursor.visible = false,
            CursorUpdate::Reset => {
                self.cursor.shape = None;
                self.cursor.visible = false;
            }
        }
        // Repaint both where it was and where it is now.
        if let Some(old) = self.drawn_cursor {
            self.pending = self.pending.union(&old);
        }
        if let Some(new) = self.cursor.bounds() {
            self.pending = self.pending.union(&new);
        }
    }

    fn accumulate(&mut self, surface_id: u32, rect: SpiceRect) {
        // Only the primary surface is visible. Off-screen surfaces are
        // scratch space the guest blits from, and their damage reaches the
        // screen as a later draw command.
        if self.surfaces.primary_id() == Some(surface_id) {
            self.pending = self.pending.union(&rect);
        }
    }

    fn damage_whole_primary(&mut self) {
        if let Some(primary) = self.surfaces.primary() {
            self.pending = self.pending.union(&SpiceRect {
                top: 0,
                left: 0,
                bottom: primary.height() as i32,
                right: primary.width() as i32,
            });
        }
    }

    /// Copy the damaged region of the primary surface into the framebuffer,
    /// draw the cursor over it, and tell the bridge.
    pub fn publish(&mut self) {
        if !self.marked || self.pending.is_empty() {
            return;
        }
        let Some(primary) = self.surfaces.primary() else {
            self.pending = SpiceRect::default();
            return;
        };
        let (width, height) = (primary.width(), primary.height());
        let Some(rect) = self.pending.clamp_to(width, height) else {
            self.pending = SpiceRect::default();
            return;
        };

        {
            let mut fb = self.fb.write();
            if fb.width() != width || fb.height() != height {
                // The framebuffer and the surface disagree, which can only
                // happen between a resize and its first publish. Dropping
                // this one is correct: the next carries the whole surface.
                self.pending = SpiceRect::default();
                return;
            }
            let stride = fb.stride();
            let row_bytes = rect.width as usize * 4;
            let source_stride = primary.stride();
            let data = fb.data_mut();
            for row in 0..rect.height as usize {
                let from = (rect.y as usize + row) * source_stride + rect.x as usize * 4;
                let to = (rect.y as usize + row) * stride + rect.x as usize * 4;
                data[to..to + row_bytes].copy_from_slice(&primary.data()[from..from + row_bytes]);
            }
            if let (Some(shape), true) = (self.cursor.shape.as_ref(), self.cursor.visible) {
                overlay_cursor(
                    data,
                    width,
                    height,
                    shape,
                    self.cursor.x,
                    self.cursor.y,
                    rect,
                );
            }
        }

        self.drawn_cursor = self.cursor.bounds();
        self.pending = SpiceRect::default();
        let _ = self.events.send(BackendEvent::Damage(rect));
    }

    /// Tell the bridge the display is gone.
    pub fn disconnect(&self) {
        let _ = self.events.send(BackendEvent::Disconnected);
    }

    /// The surfaces, for tests.
    #[cfg(test)]
    fn surfaces(&self) -> &SurfaceSet {
        &self.surfaces
    }
}

/// Alpha-blend a cursor shape into the framebuffer, clipped to `rect`.
///
/// SPICE's `ALPHA` cursors are premultiplied, which is why this is a multiply
/// and an add rather than an interpolation; the masked types are decoded to
/// fully opaque or fully transparent, where the two are the same.
fn overlay_cursor(
    data: &mut [u8],
    width: u32,
    height: u32,
    shape: &crate::cursor::CursorShape,
    x: i32,
    y: i32,
    rect: solstice_backend::Rect,
) {
    let left = x - shape.hot_x as i32;
    let top = y - shape.hot_y as i32;
    let stride = width as usize * 4;
    for row in 0..shape.height as i32 {
        let dest_y = top + row;
        if dest_y < rect.y as i32 || dest_y >= rect.bottom() as i32 || dest_y >= height as i32 {
            continue;
        }
        for column in 0..shape.width as i32 {
            let dest_x = left + column;
            if dest_x < rect.x as i32 || dest_x >= rect.right() as i32 || dest_x >= width as i32 {
                continue;
            }
            let Some(src) = shape.pixel(column as u32, row as u32) else {
                continue;
            };
            if src[3] == 0 {
                continue;
            }
            let offset = dest_y as usize * stride + dest_x as usize * 4;
            let inverse = 255 - src[3] as u32;
            for channel in 0..3 {
                data[offset + channel] = (src[channel] as u32
                    + (data[offset + channel] as u32 * inverse) / 255)
                    .min(255) as u8;
            }
            data[offset + 3] = 0xFF;
        }
    }
}

fn flip_vertically(image: &image::DecodedImage) -> image::DecodedImage {
    let stride = image.stride();
    let mut data = Vec::with_capacity(image.data.len());
    for row in (0..image.height as usize).rev() {
        let start = row * stride;
        match image.data.get(start..start + stride) {
            Some(line) => data.extend_from_slice(line),
            None => data.resize(data.len() + stride, 0),
        }
    }
    image::DecodedImage {
        data,
        ..image.clone()
    }
}

/// Read the display channel and forward its messages into the shared queue.
pub async fn reader_task<R>(
    mut reader: crate::channel::ChannelReader<R>,
    events: mpsc::Sender<DisplayEvent>,
) where
    R: tokio::io::AsyncRead + Unpin,
{
    loop {
        match reader.next().await {
            Ok(Some(message)) => {
                if events.send(DisplayEvent::Message(message)).await.is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, "spice display channel ended");
                break;
            }
        }
    }
}

/// Read the cursor channel and forward its updates into the shared queue.
pub async fn cursor_task<R>(
    mut reader: crate::channel::ChannelReader<R>,
    events: mpsc::Sender<DisplayEvent>,
) where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut channel = crate::cursor::CursorChannel::new();
    loop {
        match reader.next().await {
            Ok(Some(message)) => match channel.handle(message.kind, &message.body) {
                Ok(Some(update)) => {
                    if events.send(DisplayEvent::Cursor(update)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "spice cursor message dropped");
                }
            },
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, "spice cursor channel ended");
                break;
            }
        }
    }
    let _ = events.send(DisplayEvent::CursorGone).await;
}

/// The longest the display task batches commands before publishing what it
/// has. Under a client's frame interval at any rate it streams at, so a busy
/// server costs batching, never frames.
const MAX_BATCH: std::time::Duration = std::time::Duration::from_millis(8);

/// Own the surfaces and publish frames until the queue closes.
pub async fn display_task(
    mut display: DisplayChannel,
    mut events: mpsc::Receiver<DisplayEvent>,
    outgoing: mpsc::Sender<OutMessage>,
) {
    for message in display.init_messages() {
        if outgoing.send(message).await.is_err() {
            return;
        }
    }

    while let Some(event) = events.recv().await {
        if let Err(e) = display.handle(event) {
            tracing::warn!(error = %e, "spice display error");
            display.disconnect();
            return;
        }
        // Drain whatever else is already queued before painting, so one
        // frame's worth of commands produces one damage event -- but only for
        // so long. A server drawing faster than this client rasterises keeps
        // the queue from ever going empty, and waiting for that published
        // nothing at all: the picture froze while decoding carried on.
        let batch_started = std::time::Instant::now();
        while batch_started.elapsed() < MAX_BATCH {
            match events.try_recv() {
                Ok(event) => {
                    if let Err(e) = display.handle(event) {
                        tracing::warn!(error = %e, "spice display error");
                        display.disconnect();
                        return;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    display.publish();
                    display.disconnect();
                    return;
                }
            }
        }
        display.publish();
    }
    // Every sender is gone, which means both channel readers ended.
    display.disconnect();
}

/// How large a surface is, for the backend's `dimensions`.
pub fn surface_size(surface: &Surface) -> (u32, u32) {
    (surface.width(), surface.height())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{brush_type, clip_type, ropd, surface_flags};

    fn channel() -> (
        DisplayChannel,
        broadcast::Receiver<BackendEvent>,
        mpsc::Receiver<OutMessage>,
    ) {
        let fb = FramebufferHandle::with_size(1, 1);
        let (events, rx) = broadcast::channel(64);
        let (outgoing, out_rx) = mpsc::channel(64);
        (
            DisplayChannel::new(fb, events, outgoing, DisplayLimits::default()),
            rx,
            out_rx,
        )
    }

    fn surface_create(id: u32, width: u32, height: u32, primary: bool) -> Message {
        let mut w = Writer::new();
        w.u32(id)
            .u32(width)
            .u32(height)
            .u32(surface_fmt::RGB32_XRGB);
        w.u32(if primary { surface_flags::PRIMARY } else { 0 });
        Message {
            kind: display_msg::SURFACE_CREATE,
            body: w.finish(),
        }
    }

    fn fill(surface_id: u32, left: i32, top: i32, right: i32, bottom: i32, colour: u32) -> Message {
        let mut w = Writer::new();
        w.u32(surface_id);
        w.i32(top).i32(left).i32(bottom).i32(right);
        w.u8(clip_type::NONE);
        w.u8(brush_type::SOLID).u32(colour);
        w.u16(ropd::OP_PUT);
        w.u8(0).i32(0).i32(0).u32(0);
        Message {
            kind: display_msg::DRAW_FILL,
            body: w.finish(),
        }
    }

    /// A server that draws faster than this client rasterises keeps the
    /// queue from ever going empty. Publishing only on an empty queue then
    /// published nothing, ever: the picture froze while decoding carried on.
    /// A real guest under KVM did exactly this to a debug build.
    ///
    /// Modelled as a queue holding far more work than one batch may take: the
    /// first damage must arrive while most of it is still queued.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_queue_that_never_empties_still_publishes() {
        const QUEUED: usize = 64;
        let (display, mut damage, _) = channel();
        let (queue, rx) = mpsc::channel(QUEUED + 2);
        let (outgoing, _out_rx) = mpsc::channel(64);
        queue
            .try_send(DisplayEvent::Message(surface_create(0, 640, 480, true)))
            .unwrap();
        queue
            .try_send(DisplayEvent::Message(Message {
                kind: display_msg::MARK,
                body: Vec::new(),
            }))
            .unwrap();
        for n in 0..QUEUED as u32 {
            queue
                .try_send(DisplayEvent::Message(fill(0, 0, 0, 640, 480, n * 0x010101)))
                .unwrap();
        }
        let task = tokio::spawn(display_task(display, rx, outgoing));

        let first = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                if let Ok(BackendEvent::Damage(_)) = damage.recv().await {
                    return;
                }
            }
        })
        .await;
        // `capacity` is the free slots, so what is still queued is the rest.
        let still_queued = queue.max_capacity() - queue.capacity();
        task.abort();
        assert!(first.is_ok(), "nothing was ever published");
        assert!(
            still_queued > QUEUED / 2,
            "the first publish waited for the queue to drain ({still_queued} of {QUEUED} left)"
        );
    }

    #[test]
    fn the_init_messages_declare_the_cache_in_pixels_and_ask_for_mjpeg() {
        let (display, _, _) = channel();
        let messages = display.init_messages();
        assert_eq!(messages[0].kind, display_msgc::INIT);
        let mut r = Reader::new(&messages[0].body);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(
            r.u64().unwrap(),
            (DisplayLimits::default().pixmap_cache_bytes / 4) as u64
        );
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(
            r.u32().unwrap(),
            (Limits::default().glz_window_bytes / 4) as u32
        );

        let codecs = messages
            .iter()
            .find(|m| m.kind == display_msgc::PREFERRED_VIDEO_CODEC_TYPE)
            .unwrap();
        assert_eq!(codecs.body, vec![1, video_codec::MJPEG]);
    }

    #[test]
    fn no_compression_is_preferred_unless_one_was_asked_for() {
        let (display, _, _) = channel();
        assert!(
            !display
                .init_messages()
                .iter()
                .any(|m| m.kind == display_msgc::PREFERRED_COMPRESSION),
            "a preference overrides the server's own image-compression="
        );

        let display =
            display.with_preferred_compression(Some(crate::protocol::image_compression::QUIC));
        let preferred = display
            .init_messages()
            .into_iter()
            .find(|m| m.kind == display_msgc::PREFERRED_COMPRESSION)
            .expect("an explicit preference should be sent");
        assert_eq!(
            preferred.body,
            vec![crate::protocol::image_compression::QUIC]
        );
    }

    #[test]
    fn a_primary_surface_resizes_the_framebuffer_and_says_so() {
        let (mut display, mut events, _) = channel();
        display
            .handle(DisplayEvent::Message(surface_create(0, 64, 32, true)))
            .unwrap();
        assert_eq!(display.dimensions(), Some((64, 32)));
        assert_eq!(
            events.try_recv().unwrap(),
            BackendEvent::Resize {
                width: 64,
                height: 32
            }
        );
    }

    #[test]
    fn a_draw_on_the_primary_surface_reaches_the_framebuffer_once_published() {
        let (mut display, mut events, _) = channel();
        display
            .handle(DisplayEvent::Message(surface_create(0, 8, 8, true)))
            .unwrap();
        let _ = events.try_recv();
        display
            .handle(DisplayEvent::Message(fill(0, 1, 1, 3, 3, 0x0000_FF00)))
            .unwrap();

        // Nothing is visible until it is published.
        assert_eq!(display.fb.read().pixel(1, 1), Some([0, 0, 0, 255]));
        display.publish();
        assert_eq!(display.fb.read().pixel(1, 1), Some([0x00, 0xFF, 0x00, 255]));
        assert_eq!(display.fb.read().pixel(5, 5), Some([0, 0, 0, 255]));

        let BackendEvent::Damage(rect) = events.try_recv().unwrap() else {
            panic!("expected damage");
        };
        assert_eq!(
            rect,
            solstice_backend::Rect {
                x: 1,
                y: 1,
                width: 2,
                height: 2
            }
        );
    }

    #[test]
    fn damage_from_several_commands_is_published_as_one_rectangle() {
        let (mut display, mut events, _) = channel();
        display
            .handle(DisplayEvent::Message(surface_create(0, 8, 8, true)))
            .unwrap();
        let _ = events.try_recv();
        display
            .handle(DisplayEvent::Message(fill(0, 0, 0, 1, 1, 0x00FF_0000)))
            .unwrap();
        display
            .handle(DisplayEvent::Message(fill(0, 6, 6, 8, 8, 0x00FF_0000)))
            .unwrap();
        display.publish();
        let BackendEvent::Damage(rect) = events.try_recv().unwrap() else {
            panic!("expected damage");
        };
        assert_eq!(rect, solstice_backend::Rect::whole(8, 8));
        assert!(events.try_recv().is_err(), "one event, not two");
    }

    #[test]
    fn drawing_on_an_off_screen_surface_does_not_damage_the_screen() {
        let (mut display, mut events, _) = channel();
        display
            .handle(DisplayEvent::Message(surface_create(0, 8, 8, true)))
            .unwrap();
        let _ = events.try_recv();
        display
            .handle(DisplayEvent::Message(surface_create(1, 4, 4, false)))
            .unwrap();
        display
            .handle(DisplayEvent::Message(fill(1, 0, 0, 4, 4, 0x00FF_FFFF)))
            .unwrap();
        display.publish();
        assert!(events.try_recv().is_err());
        assert_eq!(
            display.surfaces().get(1).unwrap().pixel(0, 0),
            Some([0xFF, 0xFF, 0xFF, 0xFF])
        );
    }

    #[test]
    fn the_cursor_is_composited_over_the_surface_and_repainted_when_it_moves() {
        let (mut display, mut events, _) = channel();
        display
            .handle(DisplayEvent::Message(surface_create(0, 8, 8, true)))
            .unwrap();
        let _ = events.try_recv();
        display
            .handle(DisplayEvent::Message(fill(0, 0, 0, 8, 8, 0x0000_0000)))
            .unwrap();
        display.publish();
        let _ = events.try_recv();

        let shape = std::sync::Arc::new(crate::cursor::CursorShape {
            width: 1,
            height: 1,
            hot_x: 0,
            hot_y: 0,
            data: vec![0xFF, 0xFF, 0xFF, 0xFF],
        });
        display
            .handle(DisplayEvent::Cursor(CursorUpdate::Set {
                shape: Some(shape),
                x: 2,
                y: 2,
                visible: true,
            }))
            .unwrap();
        display.publish();
        assert_eq!(
            display.fb.read().pixel(2, 2),
            Some([0xFF, 0xFF, 0xFF, 0xFF])
        );

        display
            .handle(DisplayEvent::Cursor(CursorUpdate::Move { x: 5, y: 5 }))
            .unwrap();
        display.publish();
        // The old position is repainted from the surface underneath.
        assert_eq!(display.fb.read().pixel(2, 2), Some([0, 0, 0, 0xFF]));
        assert_eq!(
            display.fb.read().pixel(5, 5),
            Some([0xFF, 0xFF, 0xFF, 0xFF])
        );
    }

    #[test]
    fn a_reset_clears_the_primary_surface_but_keeps_it() {
        let (mut display, _, _) = channel();
        display
            .handle(DisplayEvent::Message(surface_create(0, 8, 8, true)))
            .unwrap();
        display
            .handle(DisplayEvent::Message(fill(0, 0, 0, 8, 8, 0x00FF_FFFF)))
            .unwrap();
        assert_eq!(
            display.surfaces().primary().unwrap().pixel(0, 0),
            Some([0xFF, 0xFF, 0xFF, 0xFF])
        );

        display
            .handle(DisplayEvent::Message(Message {
                kind: display_msg::RESET,
                body: Vec::new(),
            }))
            .unwrap();
        // The surface survives, its pixels do not.
        assert_eq!(display.dimensions(), Some((8, 8)));
        assert_eq!(
            display.surfaces().primary().unwrap().pixel(0, 0),
            Some([0, 0, 0, 0xFF])
        );
    }

    #[test]
    fn a_new_primary_surface_does_not_clear_the_caches_the_server_still_believes_in() {
        let (mut display, _, _) = channel();
        display
            .handle(DisplayEvent::Message(surface_create(0, 8, 8, true)))
            .unwrap();
        // Put something in the pixmap cache by hand, then replace the
        // primary surface. The cache must survive: the server does not
        // forget it, and a client that did would ask for an image the
        // server will never send again.
        display.images.cache_for_test(
            7,
            crate::display::image::DecodedImage {
                width: 1,
                height: 1,
                format: crate::display::image::Format::Bgra8,
                has_alpha: false,
                data: vec![1, 2, 3, 4],
            },
        );
        display
            .handle(DisplayEvent::Message(surface_create(0, 16, 16, true)))
            .unwrap();
        assert!(display.images.is_cached_for_test(7));
    }

    #[test]
    fn messages_whose_capability_was_never_offered_are_refused() {
        for kind in [
            display_msg::GL_SCANOUT_UNIX,
            display_msg::GL_SCANOUT2_UNIX,
            display_msg::GL_DRAW,
            display_msg::DRAW_COMPOSITE,
        ] {
            let (mut display, _, _) = channel();
            let err = display
                .handle(DisplayEvent::Message(Message {
                    kind,
                    body: vec![0; 64],
                }))
                .unwrap_err();
            assert!(matches!(err, SpiceError::Protocol(_)), "{kind}: {err}");
        }
    }

    #[test]
    fn a_display_message_this_client_does_not_know_is_ignored_rather_than_fatal() {
        let (mut display, _, _) = channel();
        assert!(display
            .handle(DisplayEvent::Message(Message {
                kind: display_msg::QUALITY_INDICATOR,
                body: vec![0; 8],
            }))
            .is_ok());
        assert!(display
            .handle(DisplayEvent::Message(Message {
                kind: 9999,
                body: Vec::new(),
            }))
            .is_ok());
    }

    #[test]
    fn a_stream_in_an_undecodable_codec_is_reported_once_and_then_ignored() {
        let (mut display, _, mut outgoing) = channel();
        display
            .handle(DisplayEvent::Message(surface_create(0, 64, 64, true)))
            .unwrap();

        let mut w = Writer::new();
        w.u32(0).u32(1).u8(0).u8(video_codec::H264).u64(0);
        w.u32(32).u32(32).u32(32).u32(32);
        w.i32(0).i32(0).i32(32).i32(32);
        w.u8(clip_type::NONE);
        display
            .handle(DisplayEvent::Message(Message {
                kind: display_msg::STREAM_CREATE,
                body: w.finish(),
            }))
            .unwrap();

        let mut frame = Writer::new();
        frame.u32(1).u32(100).u32(1).u8(0);
        let frame = Message {
            kind: display_msg::STREAM_DATA,
            body: frame.finish(),
        };
        display
            .handle(DisplayEvent::Message(frame.clone()))
            .unwrap();
        display.handle(DisplayEvent::Message(frame)).unwrap();

        let report = outgoing.try_recv().unwrap();
        assert_eq!(report.kind, display_msgc::STREAM_REPORT);
        assert!(
            outgoing.try_recv().is_err(),
            "the server should be told once, not once a frame"
        );
    }

    #[test]
    fn a_frame_for_a_destroyed_stream_is_dropped_rather_than_erroring() {
        let (mut display, _, _) = channel();
        display
            .handle(DisplayEvent::Message(surface_create(0, 8, 8, true)))
            .unwrap();
        let mut frame = Writer::new();
        frame.u32(9).u32(0).u32(0);
        assert!(display
            .handle(DisplayEvent::Message(Message {
                kind: display_msg::STREAM_DATA,
                body: frame.finish(),
            }))
            .is_ok());
    }

    #[test]
    fn executed_draw_commands_are_counted_by_kind() {
        let (mut display, _, _) = channel();
        let counts = display.counts_handle();
        display
            .handle(DisplayEvent::Message(surface_create(0, 8, 8, true)))
            .unwrap();
        assert!(counts.draws().is_empty(), "a surface is not a draw");
        for _ in 0..3 {
            display
                .handle(DisplayEvent::Message(fill(0, 0, 0, 4, 4, 0x00FF_0000)))
                .unwrap();
        }
        assert_eq!(
            counts.draws(),
            BTreeMap::from([(display_msg::DRAW_FILL, 3)])
        );
        assert!(counts.images().is_empty(), "a solid fill carries no image");
    }

    #[test]
    fn an_undecodable_image_costs_one_command_rather_than_the_session() {
        let (mut display, _, _) = channel();
        let counts = display.counts_handle();
        display
            .handle(DisplayEvent::Message(surface_create(0, 8, 8, true)))
            .unwrap();
        // A DRAW_COPY whose image is QUIC with a bad magic number.
        let mut w = Writer::new();
        w.u32(0);
        w.i32(0).i32(0).i32(2).i32(2);
        w.u8(clip_type::NONE);
        let image_at = w.len() + 4 + 16 + 2 + 1 + 13;
        w.u32(image_at as u32);
        w.i32(0).i32(0).i32(2).i32(2);
        w.u16(ropd::OP_PUT);
        w.u8(1);
        w.u8(0).i32(0).i32(0).u32(0);
        w.u64(1)
            .u8(crate::protocol::image_type::QUIC)
            .u8(0)
            .u32(2)
            .u32(2);
        w.u32(8).bytes(&[0; 8]);
        assert!(display
            .handle(DisplayEvent::Message(Message {
                kind: display_msg::DRAW_COPY,
                body: w.finish(),
            }))
            .is_ok());
        // Received and dropped is not executed: a test that relied on the
        // count to prove a kind was covered would otherwise be fooled.
        assert!(counts.draws().is_empty(), "{:?}", counts.draws());
        assert!(counts.images().is_empty(), "{:?}", counts.images());
    }
}
