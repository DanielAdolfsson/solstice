//! Where the CPU in this pipeline actually goes.
//!
//! Ignored by default. Run with:
//!
//! ```sh
//! cargo test -p solstice-video --release --test encode_cost -- --ignored --nocapture
//! ```
//!
//! The bridge does `decode backend -> composite -> colour convert -> encode
//! H.264` for every frame. This measures the last two stages so they can be
//! compared against `solstice-vnc`'s `encoding_bench`, which measures the
//! first. Optimising the cheap stage is not optimising.
//!
//! The last two rows per encoder are per second of a still session rather
//! than per frame: `frames/s` is how many frames the clock emitted, and
//! `core %` is what they cost, at the stream's rate and at the keep-alive
//! rate (`docs/roadmap.md` §6).

use std::time::{Duration, Instant};

use solstice_backend::{Framebuffer, Rect};
use solstice_video::convert::{convert_full, convert_rect};
use solstice_video::encoder::{EncoderConfig, FrameDamage, VideoEncoder};
use solstice_video::testsrc::TestPattern;
use solstice_video::{FrameClock, I420Frame};

fn cpu_seconds() -> f64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let Some((_, after_comm)) = stat.rsplit_once(')') else {
        return 0.0;
    };
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let ticks = fields
        .get(11)
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0)
        + fields
            .get(12)
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0);
    ticks / 100.0
}

#[test]
#[ignore = "measurement, not an assertion"]
fn what_the_encode_path_costs() {
    const FRAMES: usize = 300;
    println!();
    println!(
        "{:<44} {:>10} {:>10} {:>12} {:>10}",
        "stage", "ms/frame", "frames/s", "core % @60", "mean bytes"
    );

    for (w, h) in [(1280u32, 720u32), (1920, 1080)] {
        let mut fb = Framebuffer::new(w, h);
        let mut frame = I420Frame::new(w, h);
        let mut pattern = TestPattern::new();

        pattern.render(&mut fb);
        let cpu0 = cpu_seconds();
        let t0 = Instant::now();
        for _ in 0..FRAMES {
            convert_full(&fb, &mut frame);
        }
        report(
            &format!("{w}x{h} BGRA->I420, whole frame"),
            t0,
            cpu0,
            FRAMES,
            None,
        );

        // The common case: only a small region changed.
        let damage = Rect {
            x: 0,
            y: 0,
            width: 320,
            height: 200,
        };
        let cpu0 = cpu_seconds();
        let t0 = Instant::now();
        for _ in 0..FRAMES {
            convert_rect(&fb, damage, &mut frame);
        }
        report(
            &format!("{w}x{h} BGRA->I420, 320x200 rect"),
            t0,
            cpu0,
            FRAMES,
            None,
        );

        let config = EncoderConfig {
            width: w,
            height: h,
            fps: 60,
            bitrate_kbps: 20_000,
            slices_per_frame: 1,
        };
        for mut encoder in encoders(config) {
            let name = encoder.name();
            pattern = TestPattern::new();

            let mut bytes = 0usize;
            let cpu0 = cpu_seconds();
            let t0 = Instant::now();
            for _ in 0..FRAMES {
                pattern.render(&mut fb);
                convert_full(&fb, &mut frame);
                bytes += encoder.encode(&frame, false).unwrap().data.len();
            }
            report(
                &format!("{w}x{h} convert + {name}, moving"),
                t0,
                cpu0,
                FRAMES,
                Some(bytes as f64 / FRAMES as f64),
            );

            // A desktop is mostly still, and a still frame is what the
            // synthetic frame clock emits over and over.
            let mut still = 0usize;
            let cpu0 = cpu_seconds();
            let t0 = Instant::now();
            for _ in 0..FRAMES {
                still += encoder.encode(&frame, false).unwrap().data.len();
            }
            report(
                &format!("{w}x{h} {name}, unchanged frame"),
                t0,
                cpu0,
                FRAMES,
                Some(still as f64 / FRAMES as f64),
            );

            // The same, told so, as the pipeline tells it.
            let mut still = 0usize;
            let cpu0 = cpu_seconds();
            let t0 = Instant::now();
            for _ in 0..FRAMES {
                still += encoder
                    .encode_with_damage(&frame, false, FrameDamage::Nothing)
                    .unwrap()
                    .data
                    .len();
            }
            report(
                &format!("{w}x{h} {name}, unchanged, told so"),
                t0,
                cpu0,
                FRAMES,
                Some(still as f64 / FRAMES as f64),
            );

            // What a still screen costs per second of session, with the frame
            // clock deciding how many of those unchanged frames there are.
            for idle_fps in [60, 5] {
                let mut encodes = 0;
                let cpu0 = cpu_seconds();
                let t0 = Instant::now();
                for_each_still_tick(idle_fps, SESSION, || {
                    encoder
                        .encode_with_damage(&frame, false, FrameDamage::Nothing)
                        .unwrap();
                    encodes += 1;
                });
                report_session(
                    &format!("{w}x{h} {name} still, idle_fps {idle_fps}"),
                    t0,
                    cpu0,
                    encodes,
                );
            }
        }
        println!();
    }
}

/// Every encoder this build has, for the same rows.
// Each push is behind its own feature, which `vec![]` cannot say.
#[allow(clippy::vec_init_then_push)]
fn encoders(config: EncoderConfig) -> Vec<Box<dyn VideoEncoder>> {
    let mut all: Vec<Box<dyn VideoEncoder>> = Vec::new();
    #[cfg(feature = "x264")]
    all.push(Box::new(
        solstice_video::x264::X264Encoder::new(config).unwrap(),
    ));
    #[cfg(feature = "openh264")]
    all.push(Box::new(
        solstice_video::openh264::OpenH264Encoder::new(config).unwrap(),
    ));
    let _ = config;
    all
}

/// Simulated session length for the still-screen rows.
const SESSION: Duration = Duration::from_secs(10);

/// Run `f` for every frame a 60 fps clock emits over `session` of a screen
/// that changed once, at the start. Virtual time: the clock is polled at its
/// own deadlines, so this counts frames rather than waiting for them.
fn for_each_still_tick(idle_fps: u32, session: Duration, mut f: impl FnMut()) {
    let start = Instant::now();
    let mut clock = FrameClock::new(60, start).with_idle_rate(idle_fps);
    let mut now = start;
    while now < start + session {
        if clock.poll(now).is_some() {
            f();
        }
        now += clock.time_until_next(now).max(Duration::from_micros(1));
    }
}

fn report_session(name: &str, t0: Instant, cpu0: f64, encodes: usize) {
    let wall = t0.elapsed().as_secs_f64();
    let cpu = cpu_seconds() - cpu0;
    // Encodes per second of session, and the share of a core they cost.
    let rate = encodes as f64 / SESSION.as_secs_f64();
    let core_pct = cpu / SESSION.as_secs_f64() * 100.0;
    println!(
        "{:<44} {:>10.3} {:>10.1} {:>12.1} {:>10}",
        name,
        wall / encodes as f64 * 1000.0,
        rate,
        core_pct,
        ""
    );
}

fn report(name: &str, t0: Instant, cpu0: f64, frames: usize, mean_bytes: Option<f64>) {
    let wall = t0.elapsed().as_secs_f64();
    let cpu = cpu_seconds() - cpu0;
    let ms = wall / frames as f64 * 1000.0;
    // What fraction of one core a 60 fps stream would spend here.
    let core_pct = cpu / frames as f64 * 60.0 * 100.0;
    match mean_bytes {
        Some(b) => println!(
            "{:<44} {:>10.3} {:>10.0} {:>12.1} {:>10.0}",
            name,
            ms,
            frames as f64 / wall,
            core_pct,
            b
        ),
        None => println!(
            "{:<44} {:>10.3} {:>10.0} {:>12.1} {:>10}",
            name,
            ms,
            frames as f64 / wall,
            core_pct,
            ""
        ),
    }
}
