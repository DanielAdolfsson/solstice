//! The ANNOUNCE attribute parser -- the client's configuration channel.
#![no_main]
use libfuzzer_sys::fuzz_target;
use solstice_gamestream::rtsp::sdp::{encryption, parse_announce, Limits};

fuzz_target!(|data: &[u8]| {
    let limits = Limits::default();
    if let Ok(config) = parse_announce(data, Some("10.0.0.1"), &limits, encryption::ALL) {
        // Whatever the input said, the ceilings must hold: an authenticated
        // client must not be able to talk the host into 4K120.
        assert!(config.width <= limits.max_width);
        assert!(config.height <= limits.max_height);
        assert!(config.fps <= limits.max_fps);
        assert!(config.bitrate_kbps <= limits.max_bitrate_kbps);
        assert!(config.packet_size <= limits.max_packet_size);
        assert!(config.encryption_enabled & encryption::ALL == encryption::ALL);
    }
});
