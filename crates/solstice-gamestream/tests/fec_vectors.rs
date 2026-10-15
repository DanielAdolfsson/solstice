//! T1: differential FEC vectors against the real `nanors`.
//!
//! The vectors in `tests/vectors/fec/` were produced by linking the actual C
//! implementation Moonlight uses (`tests/vectors/fec/dump.c`) and cross-checked
//! against an independent Python reimplementation before being frozen. If this
//! test fails, recovery under packet loss silently corrupts video -- the
//! failure mode is a client that shows a green smear and reports nothing.
//!
//! Regenerate with:
//! `python3 -I tests/tools/gen_fec_vectors.py <path-to-fec-dump>`

use serde::Deserialize;
use solstice_gamestream::stream::fec::{inv, mul, Rs};

#[derive(Deserialize)]
struct VectorFile {
    source: String,
    polynomial: u16,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    data_shards: usize,
    parity_shards: usize,
    blocksize: usize,
    matrix: Vec<u8>,
    parity: Vec<String>,
}

fn load(name: &str) -> VectorFile {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/vectors/fec/").to_owned() + name;
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing {path}: {e}"))
}

/// The byte pattern `dump.c` fills its shards with.
fn test_data(data_shards: usize, blocksize: usize) -> Vec<Vec<u8>> {
    (0..data_shards)
        .map(|k| {
            (0..blocksize)
                .map(|b| (k * 31 + b * 7 + 11) as u8)
                .collect()
        })
        .collect()
}

fn check(file: &VectorFile, rs_for: impl Fn(&Case) -> Rs) {
    assert_eq!(
        file.polynomial,
        solstice_gamestream::stream::fec::POLYNOMIAL
    );
    assert!(!file.cases.is_empty(), "{} produced no cases", file.source);
    for case in &file.cases {
        let rs = rs_for(case);
        assert_eq!(
            rs.matrix(),
            case.matrix.as_slice(),
            "{}: parity matrix differs",
            case.name
        );

        let data = test_data(case.data_shards, case.blocksize);
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        let parity = rs.encode(&refs).unwrap();
        assert_eq!(parity.len(), case.parity_shards);
        for (j, expected_hex) in case.parity.iter().enumerate() {
            let expected = hex::decode(expected_hex).unwrap();
            assert_eq!(
                parity[j], expected,
                "{}: parity shard {j} differs",
                case.name
            );
        }

        // And the other direction: every single-shard loss recovers exactly.
        for lost in 0..(case.data_shards + case.parity_shards) {
            let mut shards: Vec<Option<Vec<u8>>> = data
                .iter()
                .cloned()
                .map(Some)
                .chain(parity.iter().cloned().map(Some))
                .collect();
            shards[lost] = None;
            rs.reconstruct(&mut shards).unwrap();
            for (i, original) in data.iter().enumerate() {
                assert_eq!(
                    shards[i].as_ref().unwrap(),
                    original,
                    "{}: losing shard {lost} corrupted data shard {i}",
                    case.name
                );
            }
        }
    }
}

#[test]
fn video_cauchy_matches_nanors() {
    let file = load("video_cauchy.json");
    check(&file, |c| {
        Rs::video(c.data_shards, c.parity_shards).unwrap()
    });
}

#[test]
fn audio_matches_the_nvidia_matrix() {
    let file = load("audio_nvidia.json");
    check(&file, |c| {
        assert_eq!((c.data_shards, c.parity_shards), (4, 2));
        Rs::audio()
    });
}

#[derive(Deserialize)]
struct SpotChecks {
    mul: Vec<[u16; 3]>,
    inv: Vec<[u16; 2]>,
}

#[test]
fn the_field_is_gf256_with_polynomial_285() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/vectors/fec/gf256_spot_checks.json"
    );
    let spot: SpotChecks = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for [a, b, want] in spot.mul {
        assert_eq!(mul(a as u8, b as u8), want as u8, "mul({a:#x}, {b:#x})");
    }
    for [a, want] in spot.inv {
        assert_eq!(inv(a as u8), want as u8, "inv({a:#x})");
    }
}
