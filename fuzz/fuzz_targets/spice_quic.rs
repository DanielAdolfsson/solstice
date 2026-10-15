//! The QUIC decode entry point, which `docs/roadmap.md` §2.2 asked for on day
//! one: this is a from-scratch port of an adaptive codec whose model state the
//! bitstream controls, running on data from the backend
//! (`docs/security.md` §5.4).
//!
//! What this is looking for is a panic, which in a `#![forbid(unsafe_code)]`
//! crate is the whole failure surface -- an index out of range, an arithmetic
//! overflow in a debug build, or an allocation the header talked the decoder
//! into. Wrong pixels are not a crash and are the differential vectors' job.
#![no_main]
use libfuzzer_sys::fuzz_target;
use solstice_spice_codec::{Limits, QuicDecoder};

fuzz_target!(|data: &[u8]| {
    // The first five words are the header, and a fuzzer spends a long time
    // guessing a 32-bit magic. Prepending a valid one for half the corpus
    // keeps the other half honest about header validation while letting the
    // rest reach the actual decoder.
    // A small pixel ceiling keeps the fuzzer out of multi-second decodes of
    // images no real server sends, where it would spend its whole budget on
    // one input. The ceiling itself is tested by the unit tests, not here.
    let mut decoder = QuicDecoder::with_limits(Limits {
        max_pixels: 1 << 18,
        ..Limits::default()
    });
    let _ = decoder.decode(data);

    if data.len() > 8 {
        let mut primed = Vec::with_capacity(data.len() + 8);
        primed.extend_from_slice(&0x4349_5551u32.to_le_bytes()); // "QUIC"
        primed.extend_from_slice(&0u32.to_le_bytes()); // version 0.0
        primed.extend_from_slice(&data[8..]);
        let _ = decoder.decode(&primed);
    }
});
