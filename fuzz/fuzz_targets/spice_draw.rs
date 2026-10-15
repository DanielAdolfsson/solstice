//! SPICE draw commands, which arrive from the backend and are executed
//! against a framebuffer. A VM the operator does not fully control is an
//! inbound attack surface (`docs/security.md` §5.4), and a draw command is
//! the richest message SPICE has: a destination rectangle, a clip region, a
//! brush, a stencil mask and a bitmap, each reached through a 32-bit offset
//! into the same message body.
//!
//! The first byte selects which command the rest is parsed as, so one corpus
//! entry reaches every handler rather than the fuzzer having to guess a
//! message number.
#![no_main]
use libfuzzer_sys::fuzz_target;
use solstice_spice::display::commands;
use solstice_spice::display::image::ImageDecoder;
use solstice_spice::display::surface::SurfaceSet;
use solstice_spice::protocol::{display_msg, surface_fmt};
use solstice_spice_codec::Limits;

const COMMANDS: &[u16] = &[
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
    display_msg::COPY_BITS,
];

fuzz_target!(|data: &[u8]| {
    let Some((selector, body)) = data.split_first() else {
        return;
    };
    let kind = COMMANDS[*selector as usize % COMMANDS.len()];

    let mut surfaces = SurfaceSet::new();
    surfaces
        .create(0, 64, 48, surface_fmt::RGB32_XRGB, true)
        .expect("a 64x48 surface is inside every limit");
    // An off-screen ARGB surface too: alpha handling differs, and a command
    // naming surface 1 should reach it rather than being refused.
    surfaces
        .create(1, 16, 16, surface_fmt::RGB32_ARGB, false)
        .expect("a 16x16 surface is inside every limit");

    let mut images = ImageDecoder::new(Limits::default(), 1 << 20);
    let _ = commands::execute(kind, body, &mut surfaces, &mut images);
});
