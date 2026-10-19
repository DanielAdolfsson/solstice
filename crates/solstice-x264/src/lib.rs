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

        // SAFETY: `param` is initialised above. x264 copies what it needs and
        // keeps no pointer into it.
        let raw = unsafe { ffi::x264_encoder_open(&mut param) };
        let raw = NonNull::new(raw).ok_or(Error::Open)?;
        Ok(Self {
            raw,
            width: width as usize,
            height: height as usize,
            pts: 0,
        })
    }

    /// Encode one I420 frame: three tightly packed planes, luma `width` bytes
    /// per row and chroma `width / 2`.
    ///
    /// `force_idr` makes this frame a keyframe, which is what the control
    /// stream's `0x0302` asks for.
    pub fn encode(
        &mut self,
        y: &[u8],
        u: &[u8],
        v: &[u8],
        force_idr: bool,
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
        let first = e.encode(&y, &u, &v, false).unwrap();
        assert!(first.keyframe, "the first frame must be an IDR");
        assert_eq!(&first.data[..4], &[0, 0, 0, 1]);
        for _ in 0..10 {
            let next = e.encode(&y, &u, &v, false).unwrap();
            assert!(!next.keyframe, "an unrequested keyframe");
            assert!(!next.data.is_empty());
        }
    }

    #[test]
    fn a_keyframe_arrives_on_the_frame_that_asked() {
        let mut e = Encoder::new(&settings(320, 240)).unwrap();
        let (y, u, v) = grey(320, 240);
        e.encode(&y, &u, &v, false).unwrap();
        e.encode(&y, &u, &v, false).unwrap();
        assert!(e.encode(&y, &u, &v, true).unwrap().keyframe);
        assert!(!e.encode(&y, &u, &v, false).unwrap().keyframe);
    }

    #[test]
    fn planes_of_the_wrong_size_never_reach_c() {
        let mut e = Encoder::new(&settings(320, 240)).unwrap();
        let (y, u, v) = grey(320, 240);
        assert!(matches!(
            e.encode(&y[1..], &u, &v, false),
            Err(Error::Planes { .. })
        ));
        assert!(matches!(
            e.encode(&y, &u, &v[..10], false),
            Err(Error::Planes { .. })
        ));
        // The encoder is still usable after a refusal.
        assert!(e.encode(&y, &u, &v, false).unwrap().keyframe);
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

    #[test]
    fn encoders_can_move_between_threads() {
        let mut e = Encoder::new(&settings(320, 240)).unwrap();
        let (y, u, v) = grey(320, 240);
        e.encode(&y, &u, &v, false).unwrap();
        let handle = std::thread::spawn(move || {
            let (y, u, v) = grey(320, 240);
            e.encode(&y, &u, &v, false).map(|f| f.keyframe)
        });
        assert_eq!(handle.join().unwrap(), Ok(false));
    }
}
