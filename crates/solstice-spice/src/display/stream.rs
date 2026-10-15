//! Video streams layered over the draw commands.
//!
//! When `spice-server` decides a region of the screen is video-like it stops
//! sending draw commands for it and opens a **stream**: a clipped
//! sub-rectangle carrying MJPEG, VP8, H.264, VP9 or H.265
//! (`docs/spice-protocol.md` §5.2). The rest of the screen keeps arriving as
//! draw commands, so a client has to composite the two.
//!
//! # Why not forward the H.264
//!
//! Because there is no whole-screen H.264 to forward. A stream covers only
//! the part of the screen the server's heuristic classified as video, it can
//! be destroyed and recreated at any moment, and there is no way to ask it
//! for a keyframe. Moonlight needs a continuous full-screen stream with
//! keyframes on demand, which is a different thing; composite-then-re-encode
//! is the only correct path and it is the one Solstice takes.
//!
//! # Why only MJPEG
//!
//! Following from that: the stream is decoded only to be composited and
//! re-encoded, so the decoder is pure overhead and the cheapest correct one
//! wins. MJPEG has a pure-Rust decoder already in the tree for SPICE's own
//! JPEG images; VP8, VP9 and H.265 do not, and pulling a native decoder in
//! for a format Solstice immediately throws away is the wrong trade
//! (`docs/security.md` §5.5 on native dependencies).
//!
//! So the client advertises `CODEC_MJPEG` and asks for it with
//! `PREFERRED_VIDEO_CODEC_TYPE`. A server that opens a stream in something
//! else anyway gets told so: `STREAM_REPORT` with `num_frames = 0` and
//! `num_drops = 0xffffffff` is the protocol's way of saying "not supported or
//! could not decode" (`spice.proto:1011-1017`), and `spice-server` responds
//! by dropping the stream and going back to draw commands.

use std::collections::HashMap;

use crate::display::image::DecodedImage;
use crate::display::types::{Clip, SpiceRect};
use crate::error::{Result, SpiceError};
use crate::protocol::{stream_flags, video_codec, MAX_NUM_STREAMS};
use crate::wire::Reader;

/// One open stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    /// Which surface it draws onto.
    pub surface_id: u32,
    /// `SPICE_VIDEO_CODEC_TYPE_*`.
    pub codec: u8,
    /// `SPICE_STREAM_FLAGS_*`.
    pub flags: u8,
    /// Frame width.
    pub width: u32,
    /// Frame height.
    pub height: u32,
    /// Where frames land on the surface.
    pub dest: SpiceRect,
    /// The clip frames are subject to.
    pub clip: Clip,
    /// The id the server gave for reports, once it has asked for them.
    pub report_id: Option<u32>,
    /// Whether this client has already told the server it cannot decode the
    /// stream, so it is told once rather than once a frame.
    pub refused: bool,
}

impl Stream {
    /// Whether this client can decode the stream's codec.
    pub fn is_decodable(&self) -> bool {
        self.codec == video_codec::MJPEG
    }

    /// Whether frames arrive with their first row at the top.
    pub fn top_down(&self) -> bool {
        self.flags & stream_flags::TOP_DOWN != 0
    }
}

/// Every stream a display channel has open.
#[derive(Debug, Default)]
pub struct StreamSet {
    streams: HashMap<u32, Stream>,
}

impl StreamSet {
    /// An empty set.
    pub fn new() -> Self {
        StreamSet::default()
    }

    /// Parse and record a `STREAM_CREATE`.
    pub fn create(&mut self, body: &[u8]) -> Result<(u32, Stream)> {
        let mut r = Reader::new(body);
        let surface_id = r.u32()?;
        let id = r.u32()?;
        let flags = r.u8()?;
        let codec = r.u8()?;
        let _stamp = r.u64()?;
        let width = r.u32()?;
        let height = r.u32()?;
        let _src_width = r.u32()?;
        let _src_height = r.u32()?;
        let dest = SpiceRect::parse(&mut r)?;
        let clip = Clip::parse(&mut r)?;

        if id >= MAX_NUM_STREAMS {
            return Err(SpiceError::protocol(format!(
                "stream id {id} is outside [0, {MAX_NUM_STREAMS})"
            )));
        }
        let stream = Stream {
            surface_id,
            codec,
            flags,
            width,
            height,
            dest,
            clip,
            report_id: None,
            refused: false,
        };
        self.streams.insert(id, stream.clone());
        Ok((id, stream))
    }

    /// Borrow one.
    pub fn get(&self, id: u32) -> Option<&Stream> {
        self.streams.get(&id)
    }

    /// Borrow one mutably.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut Stream> {
        self.streams.get_mut(&id)
    }

    /// Replace a stream's clip (`STREAM_CLIP`).
    pub fn set_clip(&mut self, id: u32, clip: Clip) {
        if let Some(stream) = self.streams.get_mut(&id) {
            stream.clip = clip;
        }
    }

    /// Forget one.
    pub fn destroy(&mut self, id: u32) {
        self.streams.remove(&id);
    }

    /// Forget all of them.
    pub fn clear(&mut self) {
        self.streams.clear();
    }

    /// How many are open.
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Whether none are.
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }
}

/// A frame off a stream, before decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamFrame<'a> {
    /// Which stream.
    pub id: u32,
    /// The server's media clock for this frame.
    pub multi_media_time: u32,
    /// Where it lands, when the message carried its own rectangle.
    ///
    /// `STREAM_DATA` uses the stream's own destination; `STREAM_DATA_SIZED`
    /// carries a new one, which is the whole point of the `SIZED_STREAM`
    /// capability -- a stream whose source changes size mid-flight.
    pub dest: Option<SpiceRect>,
    /// The frame's own dimensions, for a sized frame.
    pub size: Option<(u32, u32)>,
    /// The compressed frame.
    pub data: &'a [u8],
}

/// Parse `STREAM_DATA`.
pub fn parse_data(body: &[u8]) -> Result<StreamFrame<'_>> {
    let mut r = Reader::new(body);
    let id = r.u32()?;
    let multi_media_time = r.u32()?;
    let data_size = r.u32()?;
    let len = r.count(data_size, 1)?;
    let data = r.bytes(len)?;
    Ok(StreamFrame {
        id,
        multi_media_time,
        dest: None,
        size: None,
        data,
    })
}

/// Parse `STREAM_DATA_SIZED`.
pub fn parse_data_sized(body: &[u8]) -> Result<StreamFrame<'_>> {
    let mut r = Reader::new(body);
    let id = r.u32()?;
    let multi_media_time = r.u32()?;
    let width = r.u32()?;
    let height = r.u32()?;
    let dest = SpiceRect::parse(&mut r)?;
    let data_size = r.u32()?;
    let len = r.count(data_size, 1)?;
    let data = r.bytes(len)?;
    Ok(StreamFrame {
        id,
        multi_media_time,
        dest: Some(dest),
        size: Some((width, height)),
        data,
    })
}

/// Decode one MJPEG frame.
///
/// An MJPEG stream is a run of complete JPEG images, so each frame decodes on
/// its own with no inter-frame state -- which is the other reason it is the
/// codec worth supporting in a bridge that re-encodes everything anyway.
pub fn decode_mjpeg(data: &[u8], max_pixels: u64) -> Result<DecodedImage> {
    crate::display::image::decode_jpeg_frame(data, max_pixels)
}

/// Build a `STREAM_REPORT` body.
///
/// `spice.proto:1003-1027`. The all-ones `num_drops` with a zero
/// `num_frames` is the "cannot decode" signal.
pub fn stream_report(
    stream_id: u32,
    unique_id: u32,
    start_mm_time: u32,
    end_mm_time: u32,
    num_frames: u32,
    num_drops: u32,
) -> Vec<u8> {
    let mut w = crate::wire::Writer::new();
    w.u32(stream_id)
        .u32(unique_id)
        .u32(start_mm_time)
        .u32(end_mm_time)
        .u32(num_frames)
        .u32(num_drops)
        .u32(0) // last_frame_delay
        .u32(0xFFFF_FFFF); // audio_delay: no audio playback timing to report
    w.finish()
}

/// The report that says "this client cannot decode this stream".
pub fn unsupported_report(stream_id: u32, unique_id: u32, mm_time: u32) -> Vec<u8> {
    stream_report(stream_id, unique_id, mm_time, mm_time, 0, 0xFFFF_FFFF)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::clip_type;
    use crate::wire::Writer;

    fn create_body(id: u32, codec: u8) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(0) // surface_id
            .u32(id)
            .u8(stream_flags::TOP_DOWN)
            .u8(codec)
            .u64(0)
            .u32(320)
            .u32(240)
            .u32(320)
            .u32(240);
        w.i32(10).i32(20).i32(250).i32(340); // dest: top, left, bottom, right
        w.u8(clip_type::NONE);
        w.finish()
    }

    #[test]
    fn a_stream_create_records_its_geometry_and_codec() {
        let mut streams = StreamSet::new();
        let (id, stream) = streams.create(&create_body(3, video_codec::MJPEG)).unwrap();
        assert_eq!(id, 3);
        assert_eq!(stream.width, 320);
        assert_eq!(stream.dest.left, 20);
        assert_eq!(stream.dest.top, 10);
        assert!(stream.is_decodable());
        assert!(stream.top_down());
        assert_eq!(streams.len(), 1);
    }

    #[test]
    fn a_stream_in_a_codec_this_client_cannot_decode_is_recorded_but_not_decodable() {
        let mut streams = StreamSet::new();
        let (_, stream) = streams.create(&create_body(0, video_codec::H264)).unwrap();
        assert!(!stream.is_decodable());
    }

    #[test]
    fn a_stream_id_outside_the_protocols_range_is_refused() {
        let mut streams = StreamSet::new();
        assert!(streams.create(&create_body(MAX_NUM_STREAMS, 1)).is_err());
        assert!(streams.is_empty());
    }

    #[test]
    fn a_truncated_stream_create_is_an_error_rather_than_a_panic() {
        let mut streams = StreamSet::new();
        let body = create_body(0, video_codec::MJPEG);
        for cut in 0..body.len() {
            let _ = streams.create(&body[..cut]);
        }
        assert!(streams.create(&body[..4]).is_err());
    }

    #[test]
    fn stream_data_carries_its_frame_without_copying_it() {
        let mut w = Writer::new();
        w.u32(2).u32(12345).u32(3).bytes(&[7, 8, 9]);
        let body = w.finish();
        let frame = parse_data(&body).unwrap();
        assert_eq!(frame.id, 2);
        assert_eq!(frame.multi_media_time, 12345);
        assert_eq!(frame.data, &[7, 8, 9]);
        assert_eq!(frame.dest, None);
    }

    #[test]
    fn a_sized_frame_carries_its_own_destination() {
        let mut w = Writer::new();
        w.u32(1).u32(0).u32(64).u32(32);
        w.i32(0).i32(0).i32(32).i32(64);
        w.u32(1).u8(0xFF);
        let body = w.finish();
        let frame = parse_data_sized(&body).unwrap();
        assert_eq!(frame.size, Some((64, 32)));
        assert_eq!(frame.dest.unwrap().right, 64);
    }

    #[test]
    fn a_frame_whose_length_overruns_the_message_is_refused() {
        let mut w = Writer::new();
        w.u32(0).u32(0).u32(1000).u8(1);
        assert!(parse_data(&w.finish()).is_err());
    }

    #[test]
    fn the_unsupported_report_is_zero_frames_and_all_ones_drops() {
        let body = unsupported_report(4, 9, 77);
        let mut r = Reader::new(&body);
        assert_eq!(r.u32().unwrap(), 4);
        assert_eq!(r.u32().unwrap(), 9);
        assert_eq!(r.u32().unwrap(), 77);
        assert_eq!(r.u32().unwrap(), 77);
        assert_eq!(r.u32().unwrap(), 0);
        assert_eq!(r.u32().unwrap(), 0xFFFF_FFFF);
    }

    #[test]
    fn a_clip_update_replaces_the_streams_clip() {
        let mut streams = StreamSet::new();
        streams.create(&create_body(0, video_codec::MJPEG)).unwrap();
        streams.set_clip(
            0,
            Clip {
                rects: Some(vec![SpiceRect {
                    top: 0,
                    left: 0,
                    bottom: 1,
                    right: 1,
                }]),
            },
        );
        assert!(streams.get(0).unwrap().clip.rects.is_some());
        streams.destroy(0);
        assert!(streams.get(0).is_none());
    }
}
