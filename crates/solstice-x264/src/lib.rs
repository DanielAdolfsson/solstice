//! A thin, safe wrapper over the system libx264.
//!
//! This is the only crate in the workspace with `unsafe` code, and it is kept
//! that way on purpose (`docs/security.md` §5.5): the boundary is a handful of
//! calls, and everything that could make one of them misbehave is checked on
//! the Rust side first. A frame's geometry and plane sizes are validated
//! before its pointers cross into C, and nothing x264 returns is read beyond
//! the length it reports.
//!
//! The settings are fixed for one workload, a live desktop stream, rather than
//! exposing x264's parameter set:
//!
//! - **No delay.** `tune=zerolatency`: no B-frames, no lookahead, no frame
//!   threads. Every [`Encoder::encode`] returns the access unit for the frame
//!   it was given.
//! - **Keyframes on request only.** No periodic IDR and no scene-cut IDR; a
//!   keyframe costs bandwidth the client did not ask for. SPS and PPS ride
//!   along with each one, for a client that joins or recovers mid-stream.
//! - **Annex-B output**, start codes included, which is what the packetiser
//!   carries.
//! - **Unchanged macroblocks can be named.** A [`Change`] with each frame
//!   tells x264 what did not move since the last one, and x264 stops
//!   analysing it: half the time of a near-still 1080p frame, and few of the
//!   bits it would spend re-polishing a static screen. It does not freeze a
//!   block at whatever quality it was last coded at. After a starved
//!   keyframe a hinted still screen sharpens as fast as an unhinted one, at
//!   5 Mbit/s as at 20, which the tests in `solstice-video` hold it to.
//! - **Average bitrate with a VBV cap** at the client's bitrate and half a
//!   second of buffer. Smaller buffers starve the keyframe a client asks for
//!   on connect: one frame of buffer gave a 16.5 dB IDR at 1080p and 20 Mbit/s,
//!   half a second 36.5 dB, at the size OpenH264 sends unconstrained.

use std::ffi::CStr;
use std::ptr::NonNull;

use x264_sys as ffi;

/// What went wrong.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// The settings cannot describe an encoder.
    #[error("invalid settings: {0}")]
    Settings(&'static str),
    /// libx264 refused the parameters.
    #[error("x264_encoder_open failed")]
    Open,
    /// A frame's planes do not match the encoder's geometry.
    #[error("frame planes are {y}/{u}/{v} bytes, the encoder expects {want_y}/{want_c}/{want_c}")]
    Planes {
        /// Luma plane length.
        y: usize,
        /// Cb plane length.
        u: usize,
        /// Cr plane length.
        v: usize,
        /// Expected luma length.
        want_y: usize,
        /// Expected length of each chroma plane.
        want_c: usize,
    },
    /// libx264 failed to encode a frame.
    #[error("x264_encoder_encode failed")]
    Encode,
    /// libx264 held a frame back. `zerolatency` rules this out, so it would
    /// mean the settings did not take.
    #[error("x264 buffered a frame instead of returning it")]
    Delayed,
}

/// How to build an [`Encoder`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Width in pixels; even.
    pub width: u32,
    /// Height in pixels; even.
    pub height: u32,
    /// Frames per second, the rate control's denominator.
    pub fps: u32,
    /// Target and maximum bitrate.
    pub bitrate_kbps: u32,
    /// Slices per frame. `0` and `1` both mean one.
    pub slices: u32,
    /// Encoder threads, which with `zerolatency` are slice threads. `0` lets
    /// x264 choose.
    pub threads: u32,
    /// x264 preset name, `"ultrafast"` to `"placebo"`.
    pub preset: &'static CStr,
}

/// What changed in a frame since the previous one handed to the encoder.
///
/// x264 trusts this: a macroblock outside a [`Change::Within`] rectangle is
/// coded as unchanged, so a change the rectangle misses stays off the screen
/// until that block changes again. Use [`Change::Unknown`] whenever the claim
/// cannot be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// No claim: x264 analyses every macroblock.
    Unknown,
    /// Nothing changed.
    Nothing,
    /// Nothing changed outside this rectangle, in pixels. It may extend past
    /// the frame; only the part inside counts.
    Within {
        /// Left edge.
        x: u32,
        /// Top edge.
        y: u32,
        /// Width.
        width: u32,
        /// Height.
        height: u32,
    },
}

/// One encoded access unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Annex-B bytes, start codes included.
    pub data: Vec<u8>,
    /// Whether x264 coded this frame as an IDR.
    pub keyframe: bool,
}

/// An open libx264 encoder.
#[derive(Debug)]
pub struct Encoder {
    raw: NonNull<ffi::x264_t>,
    width: usize,
    height: usize,
    pts: i64,
    /// One `X264_MBINFO_*` byte per macroblock, rewritten for each hinted
    /// frame. Owned here so it outlives every call that hands it to x264.
    mb_info: Vec<u8>,
    /// Whether a frame has gone in, so that the next one has a predecessor
    /// for a [`Change`] to describe.
    started: bool,
}

// SAFETY: an `x264_t` holds no thread-affine state. libx264 manages its own
// worker threads internally, and every call here takes `&mut self`, so the
// handle is only ever used from one thread at a time.
unsafe impl Send for Encoder {}

impl Encoder {
    /// Open an encoder.
    pub fn new(settings: &Settings) -> Result<Self, Error> {
        let Settings {
            width,
            height,
            fps,
            bitrate_kbps,
            slices,
            threads,
            preset,
        } = *settings;
        if width == 0 || height == 0 || width % 2 != 0 || height % 2 != 0 {
            return Err(Error::Settings(
                "width and height must be even and non-zero",
            ));
        }
        // x264's limit, and far past anything a client asks for; it also keeps
        // every product below inside an `i32`.
        if width > 16384 || height > 16384 {
            return Err(Error::Settings("width and height must be at most 16384"));
        }
        if fps == 0 || fps > 1000 {
            return Err(Error::Settings("fps must be in 1..=1000"));
        }
        if bitrate_kbps == 0 || bitrate_kbps > 1_000_000 {
            return Err(Error::Settings("bitrate must be in 1..=1000000 kbit/s"));
        }
        if slices > 256 || threads > 256 {
            return Err(Error::Settings("slices and threads must be at most 256"));
        }

        // SAFETY: `x264_param_t` is a plain C struct that
        // `x264_param_default_preset` fully initialises; zeroing it first only
        // means no field is ever read uninitialised. Both strings are
        // NUL-terminated `CStr`s that outlive the call.
        let mut param: ffi::x264_param_t = unsafe { std::mem::zeroed() };
        let applied = unsafe {
            ffi::x264_param_default_preset(&mut param, preset.as_ptr(), c"zerolatency".as_ptr())
        };
        if applied != 0 {
            return Err(Error::Settings("unknown x264 preset"));
        }

        param.i_log_level = ffi::X264_LOG_ERROR as i32;
        param.i_threads = threads as i32;
        param.i_width = width as i32;
        param.i_height = height as i32;
        param.i_csp = ffi::X264_CSP_I420 as i32;
        param.i_fps_num = fps;
        param.i_fps_den = 1;
        param.i_keyint_max = ffi::X264_KEYINT_MAX_INFINITE as i32;
        param.i_scenecut_threshold = 0;
        param.b_intra_refresh = 0;
        param.b_repeat_headers = 1;
        param.b_annexb = 1;
        param.i_slice_count = slices.max(1) as i32;
        param.rc.i_rc_method = ffi::X264_RC_ABR as i32;
        param.rc.i_bitrate = bitrate_kbps as i32;
        param.rc.i_vbv_max_bitrate = bitrate_kbps as i32;
        param.rc.i_vbv_buffer_size = (bitrate_kbps / 2).max(1) as i32;
        // Lets a frame carry `prop.mb_info`. A frame without one is analysed
        // as usual.
        param.analyse.b_mb_info = 1;

        // SAFETY: `param` is initialised above. x264 copies what it needs and
        // keeps no pointer into it.
        let raw = unsafe { ffi::x264_encoder_open(&mut param) };
        let raw = NonNull::new(raw).ok_or(Error::Open)?;
        let mbs = (width as usize).div_ceil(16) * (height as usize).div_ceil(16);
        Ok(Self {
            raw,
            width: width as usize,
            height: height as usize,
            pts: 0,
            mb_info: vec![0; mbs],
            started: false,
        })
    }

    /// Fill `mb_info` for `change`. `false` when there is nothing to say.
    fn describe(&mut self, change: Change) -> bool {
        const CONSTANT: u8 = ffi::X264_MBINFO_CONSTANT as u8;
        let mbs_wide = self.width.div_ceil(16);
        let mbs_high = self.height.div_ceil(16);
        match change {
            Change::Unknown => false,
            Change::Nothing => {
                self.mb_info.fill(CONSTANT);
                true
            }
            Change::Within {
                x,
                y,
                width,
                height,
            } => {
                self.mb_info.fill(CONSTANT);
                // Out to whole macroblocks, and in to the frame.
                let (x, y) = (x as usize, y as usize);
                let x_end = x.saturating_add(width as usize).min(self.width);
                let y_end = y.saturating_add(height as usize).min(self.height);
                if x < x_end && y < y_end {
                    for row in y / 16..y_end.div_ceil(16).min(mbs_high) {
                        let line = &mut self.mb_info[row * mbs_wide..(row + 1) * mbs_wide];
                        line[x / 16..x_end.div_ceil(16).min(mbs_wide)].fill(0);
                    }
                }
                true
            }
        }
    }

    /// Encode one I420 frame: three tightly packed planes, luma `width` bytes
    /// per row and chroma `width / 2`.
    ///
    /// `force_idr` makes this frame a keyframe, which is what the control
    /// stream's `0x0302` asks for. `change` says what moved since the last
    /// frame; a keyframe, and the first frame, ignore it.
    pub fn encode(
        &mut self,
        y: &[u8],
        u: &[u8],
        v: &[u8],
        force_idr: bool,
        change: Change,
    ) -> Result<Frame, Error> {
        let want_y = self.width * self.height;
        let want_c = (self.width / 2) * (self.height / 2);
        if y.len() != want_y || u.len() != want_c || v.len() != want_c {
            return Err(Error::Planes {
                y: y.len(),
                u: u.len(),
                v: v.len(),
                want_y,
                want_c,
            });
        }

        // SAFETY: `x264_picture_init` fills in every field of a plain C struct.
        let mut pic: ffi::x264_picture_t = unsafe { std::mem::zeroed() };
        unsafe { ffi::x264_picture_init(&mut pic) };
        pic.img.i_csp = ffi::X264_CSP_I420 as i32;
        pic.img.i_plane = 3;
        pic.img.i_stride = [
            self.width as i32,
            (self.width / 2) as i32,
            (self.width / 2) as i32,
            0,
        ];
        // x264 takes `*mut` but only reads the input planes, and copies them
        // into its own frame before `x264_encoder_encode` returns.
        pic.img.plane = [
            y.as_ptr().cast_mut(),
            u.as_ptr().cast_mut(),
            v.as_ptr().cast_mut(),
            std::ptr::null_mut(),
        ];
        pic.i_type = if force_idr {
            ffi::X264_TYPE_IDR as i32
        } else {
            ffi::X264_TYPE_AUTO as i32
        };
        pic.i_pts = self.pts;
        self.pts += 1;
        // A keyframe, and the first frame, are coded from nothing.
        let hinted = self.started && !force_idr && self.describe(change);
        self.started = true;
        // x264 reads the map during this call, and with `zerolatency` the
        // frame is finished before the call returns (`Error::Delayed` below
        // is the check). No free callback: the buffer is ours, and it lives
        // until the encoder is closed.
        pic.prop.mb_info = if hinted {
            self.mb_info.as_mut_ptr()
        } else {
            std::ptr::null_mut()
        };
        pic.prop.mb_info_free = None;

        let mut nals: *mut ffi::x264_nal_t = std::ptr::null_mut();
        let mut nal_count: i32 = 0;
        // SAFETY: as above, for the output picture.
        let mut out: ffi::x264_picture_t = unsafe { std::mem::zeroed() };
        // SAFETY: `self.raw` is an open encoder. The planes were checked
        // against the geometry it was opened with, with strides that match
        // their lengths, and they outlive the call.
        let size = unsafe {
            ffi::x264_encoder_encode(
                self.raw.as_ptr(),
                &mut nals,
                &mut nal_count,
                &mut pic,
                &mut out,
            )
        };
        if size < 0 {
            return Err(Error::Encode);
        }
        if size == 0 || nals.is_null() || nal_count <= 0 {
            return Err(Error::Delayed);
        }
        // SAFETY: x264 guarantees the payloads of all the NALs it returns are
        // sequential in memory and `size` bytes long in total (x264.h,
        // `x264_encoder_encode`). They stay valid until the next call on this
        // encoder, and are copied out here before then.
        let data = unsafe { std::slice::from_raw_parts((*nals).p_payload, size as usize) }.to_vec();
        Ok(Frame {
            data,
            keyframe: out.b_keyframe != 0,
        })
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        // SAFETY: `self.raw` came from `x264_encoder_open` and is closed once.
        unsafe { ffi::x264_encoder_close(self.raw.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(width: u32, height: u32) -> Settings {
        Settings {
            width,
            height,
            fps: 60,
            bitrate_kbps: 4000,
            slices: 1,
            threads: 1,
            preset: c"ultrafast",
        }
    }

    fn grey(width: usize, height: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let c = (width / 2) * (height / 2);
        (vec![128; width * height], vec![128; c], vec![128; c])
    }

    #[test]
    fn every_frame_comes_back_from_its_own_call() {
        let mut e = Encoder::new(&settings(320, 240)).unwrap();
        let (y, u, v) = grey(320, 240);
        let first = e.encode(&y, &u, &v, false, Change::Unknown).unwrap();
        assert!(first.keyframe, "the first frame must be an IDR");
        assert_eq!(&first.data[..4], &[0, 0, 0, 1]);
        for _ in 0..10 {
            let next = e.encode(&y, &u, &v, false, Change::Unknown).unwrap();
            assert!(!next.keyframe, "an unrequested keyframe");
            assert!(!next.data.is_empty());
        }
    }

    #[test]
    fn a_keyframe_arrives_on_the_frame_that_asked() {
        let mut e = Encoder::new(&settings(320, 240)).unwrap();
        let (y, u, v) = grey(320, 240);
        e.encode(&y, &u, &v, false, Change::Unknown).unwrap();
        e.encode(&y, &u, &v, false, Change::Unknown).unwrap();
        assert!(
            e.encode(&y, &u, &v, true, Change::Unknown)
                .unwrap()
                .keyframe
        );
        assert!(
            !e.encode(&y, &u, &v, false, Change::Unknown)
                .unwrap()
                .keyframe
        );
    }

    #[test]
    fn planes_of_the_wrong_size_never_reach_c() {
        let mut e = Encoder::new(&settings(320, 240)).unwrap();
        let (y, u, v) = grey(320, 240);
        assert!(matches!(
            e.encode(&y[1..], &u, &v, false, Change::Unknown),
            Err(Error::Planes { .. })
        ));
        assert!(matches!(
            e.encode(&y, &u, &v[..10], false, Change::Unknown),
            Err(Error::Planes { .. })
        ));
        // The encoder is still usable after a refusal.
        assert!(
            e.encode(&y, &u, &v, false, Change::Unknown)
                .unwrap()
                .keyframe
        );
    }

    #[test]
    fn settings_that_cannot_work_are_refused_before_x264_sees_them() {
        for bad in [
            settings(0, 240),
            settings(321, 240),
            settings(320, 239),
            settings(20000, 240),
            Settings {
                fps: 0,
                ..settings(320, 240)
            },
            Settings {
                bitrate_kbps: 0,
                ..settings(320, 240)
            },
            Settings {
                slices: 1000,
                ..settings(320, 240)
            },
            Settings {
                preset: c"warp-speed",
                ..settings(320, 240)
            },
        ] {
            assert!(
                matches!(Encoder::new(&bad), Err(Error::Settings(_))),
                "{bad:?} was accepted"
            );
        }
    }

    /// The map for a 64x48 frame: 4x3 macroblocks, as a string per row with
    /// `#` for "may have changed".
    fn map(e: &mut Encoder, change: Change) -> Option<Vec<String>> {
        e.describe(change).then(|| {
            e.mb_info
                .chunks(4)
                .map(|row| {
                    row.iter()
                        .map(|&b| if b == 0 { '#' } else { '.' })
                        .collect()
                })
                .collect()
        })
    }

    #[test]
    fn a_change_marks_every_macroblock_it_touches() {
        let mut e = Encoder::new(&settings(64, 48)).unwrap();
        assert_eq!(map(&mut e, Change::Unknown), None);
        assert_eq!(
            map(&mut e, Change::Nothing).unwrap(),
            ["....", "....", "...."]
        );
        // One pixel inside the second macroblock of the middle row.
        let one = Change::Within {
            x: 17,
            y: 20,
            width: 1,
            height: 1,
        };
        assert_eq!(map(&mut e, one).unwrap(), ["....", ".#..", "...."]);
        // Straddling four macroblocks.
        let straddle = Change::Within {
            x: 15,
            y: 15,
            width: 2,
            height: 2,
        };
        assert_eq!(map(&mut e, straddle).unwrap(), ["##..", "##..", "...."]);
        // Past the frame's edge: clamped, not wrapped and not panicking.
        let past = Change::Within {
            x: 60,
            y: 40,
            width: u32::MAX,
            height: 100,
        };
        assert_eq!(map(&mut e, past).unwrap(), ["....", "....", "...#"]);
        // Wholly outside, or empty: nothing inside the frame changed.
        let outside = Change::Within {
            x: 64,
            y: 0,
            width: 10,
            height: 10,
        };
        assert_eq!(map(&mut e, outside).unwrap(), ["....", "....", "...."]);
        let empty = Change::Within {
            x: 8,
            y: 8,
            width: 0,
            height: 5,
        };
        assert_eq!(map(&mut e, empty).unwrap(), ["....", "....", "...."]);
    }

    /// A frame whose width is not a multiple of 16 still has a last, partial
    /// macroblock column, and a change there must reach it.
    #[test]
    fn a_partial_macroblock_at_the_edge_is_covered() {
        let mut e = Encoder::new(&settings(40, 34)).unwrap();
        assert_eq!(e.mb_info.len(), 3 * 3);
        assert!(e.describe(Change::Within {
            x: 39,
            y: 33,
            width: 1,
            height: 1
        }));
        assert_eq!(e.mb_info.iter().filter(|&&b| b == 0).count(), 1);
        assert_eq!(e.mb_info[8], 0);
    }

    #[test]
    fn hinted_frames_encode() {
        let mut e = Encoder::new(&settings(320, 240)).unwrap();
        let (y, u, v) = grey(320, 240);
        // The first frame has no predecessor, so its hint is ignored.
        assert!(
            e.encode(&y, &u, &v, false, Change::Nothing)
                .unwrap()
                .keyframe
        );
        for _ in 0..5 {
            let f = e.encode(&y, &u, &v, false, Change::Nothing).unwrap();
            assert!(!f.keyframe && !f.data.is_empty());
        }
        let changed = Change::Within {
            x: 0,
            y: 0,
            width: 16,
            height: 16,
        };
        assert!(!e.encode(&y, &u, &v, false, changed).unwrap().keyframe);
        // A keyframe ignores its hint too.
        assert!(
            e.encode(&y, &u, &v, true, Change::Nothing)
                .unwrap()
                .keyframe
        );
    }

    #[test]
    fn encoders_can_move_between_threads() {
        let mut e = Encoder::new(&settings(320, 240)).unwrap();
        let (y, u, v) = grey(320, 240);
        e.encode(&y, &u, &v, false, Change::Unknown).unwrap();
        let handle = std::thread::spawn(move || {
            let (y, u, v) = grey(320, 240);
            e.encode(&y, &u, &v, false, Change::Unknown)
                .map(|f| f.keyframe)
        });
        assert_eq!(handle.join().unwrap(), Ok(false));
    }
}
