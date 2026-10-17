//! What one full-screen raw `DRAW_COPY` costs to execute.
//!
//! Ignored by default. Run with:
//!
//! ```sh
//! cargo test -p solstice-spice --release --test raster_cost -- --ignored --nocapture
//! ```
//!
//! KWin on a QXL guest sends every frame as one full-screen `DRAW_COPY`, and
//! with `image-compression=off` its bitmap is raw 32-bit pixels, so this is
//! the per-frame cost of that guest before anything is encoded
//! (`docs/roadmap.md` §2.7). The rows split it into the bitmap's conversion
//! and the blit, so a change to one can be told from a change to the other.

use std::time::Instant;

use solstice_spice::display::commands::execute;
use solstice_spice::display::image::{DecodedImage, Format, ImageDecoder};
use solstice_spice::display::raster::{self, Rop, Sampler, ScaleMode, Source};
use solstice_spice::display::surface::SurfaceSet;
use solstice_spice::display::types::{Clip, SpiceRect};
use solstice_spice::protocol::{
    bitmap_flags, bitmap_fmt, clip_type, display_msg, image_type, ropd, surface_fmt,
};
use solstice_spice::wire::Writer;
use solstice_spice_codec::Limits;

const ITERATIONS: u32 = 200;

/// A `DRAW_COPY` of a raw 32-bit bitmap covering the whole surface.
fn full_screen_copy(width: u32, height: u32, top_down: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(0);
    w.i32(0).i32(0).i32(height as i32).i32(width as i32);
    w.u8(clip_type::NONE);
    // 4 (ptr) + 16 (src_area) + 2 (rop) + 1 (scale) + 13 (mask).
    let image_at = w.len() + 4 + 16 + 2 + 1 + 13;
    w.u32(image_at as u32);
    w.i32(0).i32(0).i32(height as i32).i32(width as i32);
    w.u16(ropd::OP_PUT);
    w.u8(1);
    w.u8(0).i32(0).i32(0).u32(0);
    assert_eq!(w.len(), image_at);

    let flags = if top_down { bitmap_flags::TOP_DOWN } else { 0 };
    w.u64(1).u8(image_type::BITMAP).u8(0).u32(width).u32(height);
    w.u8(bitmap_fmt::BIT32).u8(flags);
    w.u32(width).u32(height).u32(width * 4);
    w.u32(0);
    let pixels: Vec<u8> = (0..width as usize * height as usize * 4)
        .map(|i| (i * 7 + i / 4093) as u8)
        .collect();
    w.bytes(&pixels);
    w.finish()
}

fn report(label: &str, started: Instant) {
    let ms = started.elapsed().as_secs_f64() * 1000.0 / ITERATIONS as f64;
    println!("{label:<44} {ms:>8.2}");
}

#[test]
#[ignore = "measurement, not an assertion"]
fn what_a_raw_full_screen_copy_costs() {
    println!();
    println!("{:<44} {:>8}", "stage", "ms/frame");
    for (width, height) in [(1280u32, 720u32), (1920, 1080)] {
        let mut set = SurfaceSet::new();
        set.create(0, width, height, surface_fmt::RGB32_XRGB, true)
            .unwrap();

        for top_down in [true, false] {
            let body = full_screen_copy(width, height, top_down);
            let mut images = ImageDecoder::new(Limits::default(), 1 << 20);
            let order = if top_down { "top-down" } else { "bottom-up" };
            let started = Instant::now();
            for _ in 0..ITERATIONS {
                execute(display_msg::DRAW_COPY, &body, &mut set, &mut images).unwrap();
            }
            report(&format!("{width}x{height} DRAW_COPY, {order}"), started);
        }

        let image = DecodedImage {
            width,
            height,
            format: Format::Bgra8,
            has_alpha: false,
            data: vec![0x5A; width as usize * height as usize * 4],
        };
        let rect = SpiceRect {
            top: 0,
            left: 0,
            bottom: height as i32,
            right: width as i32,
        };
        let surface = set.get_mut(0).unwrap();
        let started = Instant::now();
        for _ in 0..ITERATIONS {
            let sampler = Sampler::new(&image, rect, rect, ScaleMode::Nearest);
            raster::draw(
                surface,
                &rect,
                &Clip { rects: None },
                None,
                Rop::COPY,
                &Source::Bitmap(sampler),
            );
        }
        report(&format!("{width}x{height} blit alone"), started);
    }
}
