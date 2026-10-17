//! The audio bridge: backend frames in, the client's packets out.
//!
//! Frames come from the SPICE server, which picks the Opus bytes, the raw
//! sample count and the channel count, and the bridge decodes, remixes and
//! re-encodes them. The first byte picks the layout and packet duration a
//! client could have negotiated; the rest is a run of frames, each a format
//! byte, a little-endian length and that many bytes, with a tick after each.
#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use solstice_audio::codec::Layout;
use solstice_audio::{AudioBridge, OutputConfig};
use solstice_backend::{AudioFormat, AudioFrame};

const LAYOUTS: [Layout; 3] = [
    Layout::STEREO,
    Layout {
        channels: 6,
        streams: 4,
        coupled_streams: 2,
        mapping: [0, 1, 2, 3, 4, 5, 0, 0],
    },
    Layout {
        channels: 8,
        streams: 8,
        coupled_streams: 0,
        mapping: [0, 1, 2, 3, 4, 5, 6, 7],
    },
];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, mut rest)) = data.split_first() else {
        return;
    };
    let Ok(mut bridge) = AudioBridge::new(OutputConfig {
        layout: LAYOUTS[selector as usize % LAYOUTS.len()],
        bitrate: 96_000,
        packet_ms: [5, 10, 20][(selector as usize / 3) % 3],
    }) else {
        return;
    };
    while rest.len() >= 3 {
        let kind = rest[0];
        let len = (u16::from_le_bytes([rest[1], rest[2]]) as usize).min(rest.len() - 3);
        let body = &rest[3..3 + len];
        rest = &rest[3 + len..];
        // Mostly 48 kHz, which is what gets past the rate check; the channel
        // count is the server's to choose and goes up to the eight the
        // playback channel accepts.
        let sample_rate = if kind & 0x80 == 0 { 48_000 } else { 44_100 };
        let channels = (kind >> 1) & 0x7;
        let format = if kind & 1 == 0 {
            AudioFormat::Opus {
                sample_rate,
                channels: channels + 1,
            }
        } else {
            AudioFormat::Pcm16 {
                sample_rate,
                channels: channels + 1,
            }
        };
        bridge.push(&AudioFrame {
            format,
            data: Bytes::copy_from_slice(body),
        });
        let _ = bridge.tick();
    }
});
