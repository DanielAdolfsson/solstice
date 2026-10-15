//! The RTSP parser: a non-RFC dialect written against observed bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must terminate and must never panic, whatever arrives on TCP 48010.
    let _ = solstice_gamestream::rtsp::message::parse_request(data);
});
