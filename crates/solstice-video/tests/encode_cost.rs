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

use std::time::Instant;

use solstice_backend::{Framebuffer, Rect};
use solstice_video::convert::{convert_full, convert_rect};
use solstice_video::encoder::{EncoderConfig, VideoEncoder};
use solstice_video::testsrc::TestPattern;
use solstice_video::I420Frame;

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
        "{:<36} {:>10} {:>10} {:>12} {:>10}",
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

        let mut encoder = solstice_video::openh264::OpenH264Encoder::new(EncoderConfig {
            width: w,
            height: h,
            fps: 60,
            bitrate_kbps: 20_000,
            slices_per_frame: 1,
        })
        .unwrap();

        let mut bytes = 0usize;
        let cpu0 = cpu_seconds();
        let t0 = Instant::now();
        for _ in 0..FRAMES {
            pattern.render(&mut fb);
            convert_full(&fb, &mut frame);
            bytes += encoder.encode(&frame, false).unwrap().data.len();
        }
        report(
            &format!("{w}x{h} convert + H.264, moving"),
            t0,
            cpu0,
            FRAMES,
            Some(bytes as f64 / FRAMES as f64),
        );

        // A desktop is mostly still, and a still frame is what the synthetic
        // frame clock emits over and over.
        let mut still = 0usize;
        let cpu0 = cpu_seconds();
        let t0 = Instant::now();
        for _ in 0..FRAMES {
            still += encoder.encode(&frame, false).unwrap().data.len();
        }
        report(
            &format!("{w}x{h} H.264, unchanged frame"),
            t0,
            cpu0,
            FRAMES,
            Some(still as f64 / FRAMES as f64),
        );
        println!();
    }
}

fn report(name: &str, t0: Instant, cpu0: f64, frames: usize, mean_bytes: Option<f64>) {
    let wall = t0.elapsed().as_secs_f64();
    let cpu = cpu_seconds() - cpu0;
    let ms = wall / frames as f64 * 1000.0;
    // What fraction of one core a 60 fps stream would spend here.
    let core_pct = cpu / frames as f64 * 60.0 * 100.0;
    match mean_bytes {
        Some(b) => println!(
            "{:<36} {:>10.3} {:>10.0} {:>12.1} {:>10.0}",
            name,
            ms,
            frames as f64 / wall,
            core_pct,
            b
        ),
        None => println!(
            "{:<36} {:>10.3} {:>10.0} {:>12.1} {:>10}",
            name,
            ms,
            frames as f64 / wall,
            core_pct,
            ""
        ),
    }
}
