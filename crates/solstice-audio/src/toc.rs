//! How long an Opus packet plays, from its first byte or two.
//!
//! RFC 6716 §3.1: the TOC byte's top five bits pick the mode and the frame
//! size, and its bottom two say how many frames follow. Code 3 puts the count
//! in the next byte. Read here rather than asked of libopus so the decision to
//! pass a packet through costs no decoder.

use crate::SAMPLES_PER_MS;

/// Samples per channel at 48 kHz in one packet, or `None` for a packet too
/// short to say or a frame count of zero.
pub fn samples_48k(packet: &[u8]) -> Option<usize> {
    let toc = *packet.first()?;
    let config = toc >> 3;
    // In tenths of a millisecond, because CELT's shortest frame is 2.5 ms.
    let tenths = match config {
        0..=11 => [100, 200, 400, 600][config as usize % 4],
        12..=15 => [100, 200][config as usize % 2],
        _ => [25, 50, 100, 200][config as usize % 4],
    };
    let frames = match toc & 0x3 {
        0 => 1,
        1 | 2 => 2,
        _ => usize::from(*packet.get(1)? & 0x3f),
    };
    if frames == 0 {
        return None;
    }
    Some(frames * tenths * SAMPLES_PER_MS / 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_durations_spice_and_moonlight_use() {
        // What spice-server sends: CELT fullband 10 ms, one frame.
        assert_eq!(samples_48k(&[(30 << 3) | 0x04, 0]), Some(480));
        // CELT fullband 5 ms.
        assert_eq!(samples_48k(&[29 << 3]), Some(240));
        // CELT 2.5 ms.
        assert_eq!(samples_48k(&[28 << 3]), Some(120));
    }

    #[test]
    fn frame_counts_multiply() {
        // Two 10 ms SILK frames.
        assert_eq!(samples_48k(&[1]), Some(960));
        assert_eq!(samples_48k(&[(1 << 3) | 2]), Some(1920));
        // Code 3: three 20 ms CELT frames.
        assert_eq!(samples_48k(&[(31 << 3) | 3, 3]), Some(2880));
    }

    #[test]
    fn short_and_empty_packets_say_nothing() {
        assert_eq!(samples_48k(&[]), None);
        assert_eq!(samples_48k(&[(31 << 3) | 3]), None);
        assert_eq!(samples_48k(&[(31 << 3) | 3, 0]), None);
    }
}
