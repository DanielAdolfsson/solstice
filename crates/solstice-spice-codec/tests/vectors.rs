//! Differential vectors against the real `spice-common` codecs.
//!
//! `tests/vectors/spice/dump.c` links the actual C encoders QEMU uses,
//! compresses a set of deterministic images, and records both the compressed
//! bytes and the pixels the C *decoder* reconstructs from them. This test
//! replays that: the Rust decoder must produce the same pixels from the same
//! bytes, for every image type the format defines.
//!
//! That is the whole argument for the port being correct. QUIC's model
//! evolves pseudo-randomly and GLZ's dictionary spans images, so neither can
//! be checked by inspection, and a round-trip against a Rust encoder would
//! only prove the port is self-consistent. These vectors prove it agrees with
//! the implementation on the other end of the wire.
//!
//! Regenerate with:
//! `python3 -I tests/tools/gen_spice_vectors.py <path-to-spice-dump>`
//!
//! See `tests/vectors/spice/README.md` for how to build `<path-to-spice-dump>`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use serde::Deserialize;
use solstice_spice_codec::{glz::GlzDecoder, lz, quic::QuicDecoder, Palette, PixelFormat};

#[derive(Deserialize)]
struct Case {
    codec: String,
    name: String,
    image_type: String,
    width: u32,
    height: u32,
    #[allow(dead_code)]
    pattern: String,
    #[serde(default)]
    top_down: bool,
    /// GLZ only: images in one window, decoded in this order.
    #[serde(default)]
    id: u64,
    #[serde(default)]
    window: String,
    #[serde(with = "hex_bytes")]
    compressed: Vec<u8>,
    #[serde(with = "hex_bytes")]
    decoded: Vec<u8>,
    /// GLZ palette images only.
    #[serde(default)]
    palette: Vec<u32>,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(serde::de::Error::custom))
            .collect()
    }
}

fn load() -> Vec<Case> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/vectors/spice/vectors.json.gz"
    );
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("opening {path}: {e}"));
    let mut json = String::new();
    flate2::read::GzDecoder::new(file)
        .read_to_string(&mut json)
        .unwrap_or_else(|e| panic!("decompressing {path}: {e}"));
    serde_json::from_str(&json).unwrap_or_else(|e| panic!("parsing {path}: {e}"))
}

/// Report the first differing byte rather than dumping two megabytes of hex.
fn assert_pixels_match(case: &Case, got: &[u8], want: &[u8]) {
    if got == want {
        return;
    }
    assert_eq!(
        got.len(),
        want.len(),
        "{}: decoded {} bytes, C produced {}",
        case.name,
        got.len(),
        want.len()
    );
    let at = got
        .iter()
        .zip(want)
        .position(|(a, b)| a != b)
        .expect("lengths match and contents differ");
    panic!(
        "{}: first difference at byte {at} (pixel {}): got {:#04x}, C produced {:#04x}",
        case.name,
        at / 4,
        got[at],
        want[at]
    );
}

/// Every QUIC image type, every pattern, every size in the vector file.
#[test]
fn quic_decodes_what_the_c_encoder_produced() {
    let cases = load();
    let mut decoder = QuicDecoder::new();
    let mut types = BTreeSet::new();

    for case in cases.iter().filter(|c| c.codec == "quic") {
        let image = decoder
            .decode(&case.compressed)
            .unwrap_or_else(|e| panic!("{}: {e}", case.name));

        assert_eq!(image.width, case.width, "{}: width", case.name);
        assert_eq!(image.height, case.height, "{}: height", case.name);
        assert!(image.top_down, "{}: QUIC is always top-down", case.name);
        assert_eq!(
            image.format,
            if case.image_type == "gray" {
                PixelFormat::Gray8
            } else {
                PixelFormat::Bgra8
            },
            "{}: output format",
            case.name
        );
        assert_pixels_match(case, &image.data, &case.decoded);
        types.insert(case.image_type.as_str());
    }

    // The vector file is generated, so the real risk is that it silently
    // stops covering a type rather than that a case fails.
    assert_eq!(
        types,
        BTreeSet::from(["gray", "rgb16", "rgb24", "rgb32", "rgba"]),
        "the vectors no longer cover every QUIC image type"
    );
}

/// The same for LZ, including the alpha-only types the display channel uses
/// for masks.
#[test]
fn lz_decodes_what_the_c_encoder_produced() {
    let cases = load();
    let mut types = BTreeSet::new();

    for case in cases.iter().filter(|c| c.codec == "lz") {
        let image =
            lz::decode(&case.compressed, None).unwrap_or_else(|e| panic!("{}: {e}", case.name));

        assert_eq!(image.width, case.width, "{}: width", case.name);
        assert_eq!(image.height, case.height, "{}: height", case.name);
        assert_eq!(image.top_down, case.top_down, "{}: orientation", case.name);
        assert_pixels_match(case, &image.data, &case.decoded);
        types.insert(case.image_type.as_str());
    }

    assert_eq!(
        types,
        BTreeSet::from(["a8", "rgb16", "rgb24", "rgb32", "rgba", "xxxa"]),
        "the vectors no longer cover every LZ image type the C encoder emits"
    );
}

/// GLZ, replayed as whole windows.
///
/// A GLZ image cannot be decoded alone: the point of the codec is that a
/// match may reach into an image sent earlier, so the vectors come in named
/// windows and each window is replayed in order through one decoder. Decoding
/// them out of order, or through separate decoders, must fail -- which the
/// unit tests in the crate check.
#[test]
fn glz_decodes_whole_windows_the_c_encoder_produced() {
    let cases = load();
    let mut windows: BTreeMap<&str, Vec<&Case>> = BTreeMap::new();
    for case in cases.iter().filter(|c| c.codec == "glz") {
        windows.entry(&case.window).or_default().push(case);
    }
    assert!(!windows.is_empty(), "no GLZ vectors in the file");
    let mut types = BTreeSet::new();

    for (window, mut images) in windows {
        images.sort_by_key(|c| c.id);
        let mut decoder = GlzDecoder::new();

        for case in images {
            let palette = (!case.palette.is_empty()).then(|| Palette {
                entries: case.palette.clone(),
            });
            let image = decoder
                .decode(&case.compressed, palette.as_ref())
                .unwrap_or_else(|e| panic!("{window}/{}: {e}", case.name));

            assert_eq!(image.width, case.width, "{}: width", case.name);
            assert_eq!(image.height, case.height, "{}: height", case.name);
            assert_pixels_match(case, &image.data, &case.decoded);
            types.insert(case.image_type.as_str());
        }
    }

    assert_eq!(
        types,
        BTreeSet::from([
            "plt1_be", "plt1_le", "plt4_be", "plt4_le", "plt8", "rgb16", "rgb24", "rgb32", "rgba",
        ]),
        "the vectors no longer cover every image type GLZ codes"
    );
}
