//! The LZ and GLZ decode entry points. Both are dictionary codecs, so unlike
//! QUIC the *input* chooses where the decoder writes -- every offset and
//! length is attacker-controlled (`docs/security.md` §5.4).
//!
//! GLZ is fuzzed through a decoder that already holds one image, so the
//! cross-image match path is reachable: with an empty window every long-range
//! match fails at the lookup and the interesting arithmetic never runs.
#![no_main]
use libfuzzer_sys::fuzz_target;
use solstice_spice_codec::{glz::GlzDecoder, lz, Limits, Palette};

/// "LZ  " then version 1.1, the prefix both formats share.
fn prefix() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x2020_5a4cu32.to_be_bytes());
    out.extend_from_slice(&((1u32 << 16) | 1).to_be_bytes());
    out
}

/// One 2x1 BGRA image at id 0, so the window is not empty.
fn seed_image() -> Vec<u8> {
    let mut out = prefix();
    out.push(8 | 0x10); // RGB32, top-down
    out.extend_from_slice(&2u32.to_be_bytes()); // width
    out.extend_from_slice(&1u32.to_be_bytes()); // height
    out.extend_from_slice(&8u32.to_be_bytes()); // stride
    out.extend_from_slice(&0u64.to_be_bytes()); // id
    out.extend_from_slice(&0u32.to_be_bytes()); // win_head_dist
    out.extend_from_slice(&[0x01, 1, 2, 3, 4, 5, 6]);
    out
}

fuzz_target!(|data: &[u8]| {
    let palette = Palette {
        entries: (0..256).map(|i| i * 0x0001_0101).collect(),
    };

    // A small pixel ceiling keeps the fuzzer out of multi-second decodes of
    // images no real server sends, where it would spend its whole budget on
    // one input. The ceiling itself is tested by the unit tests, not here.
    let limits = Limits {
        max_pixels: 1 << 18,
        glz_window_bytes: 1 << 20,
    };

    let _ = lz::decode_with_limits(data, Some(&palette), &limits);
    let _ = lz::decode_with_limits(data, None, &limits);

    let mut glz = GlzDecoder::with_limits(limits);
    let _ = glz.decode(&seed_image(), None);
    let _ = glz.decode(data, Some(&palette));

    if data.len() > 8 {
        let mut primed = prefix();
        primed.extend_from_slice(&data[8..]);
        let _ = lz::decode_with_limits(&primed, Some(&palette), &limits);
        let _ = glz.decode(&primed, Some(&palette));
    }
});
