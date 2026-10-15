//! The 0x0206 input batch decoder.
//!
//! Three published Sunshine advisories live in this parser: an out-of-bounds
//! heap write (GHSA-26q2-58j6-qmvv), bad Unicode handling
//! (GHSA-6w33-pjh7-p77c) and length confusion.
#![no_main]
use libfuzzer_sys::fuzz_target;
use solstice_gamestream::wire::input::{decode_batch, encode_batch};

fuzz_target!(|data: &[u8]| {
    if let Ok(records) = decode_batch(data) {
        // Anything that decodes must re-encode and decode back identically:
        // a decoder that silently reinterpreted a length would not round-trip.
        let reencoded = encode_batch(&records);
        assert_eq!(decode_batch(&reencoded).unwrap(), records);
    }
});
