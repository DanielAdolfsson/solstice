//! Changing the channel count.
//!
//! Output channels are in Moonlight's order: FL FR C LFE RL RR SL SR. A
//! backend's stereo lands in FL and FR and every other channel is silent. That
//! is an upmix in the narrowest sense, and deliberately so: inventing a centre
//! or a surround field from stereo is a matter of taste, and the client's own
//! speakers are a better place for that than a desktop bridge.
//!
//! Downmixing has no source today. QEMU's SPICE audio is stereo, so more
//! channels in than out keeps the first ones and drops the rest.

/// Append `input`, interleaved with `from` channels, to `out` with `to`.
pub fn remix(input: &[i16], from: usize, to: usize, out: &mut Vec<i16>) {
    if from == 0 || to == 0 {
        return;
    }
    if from == to {
        out.extend_from_slice(input);
        return;
    }
    out.reserve(input.len() / from * to);
    for frame in input.chunks_exact(from) {
        match (from, to) {
            // Mono goes to both fronts, not just the left.
            (1, _) => {
                out.push(frame[0]);
                out.extend(std::iter::repeat_n(frame[0], (to - 1).min(1)));
                out.extend(std::iter::repeat_n(0, to.saturating_sub(2)));
            }
            (_, 1) => out.push(((frame[0] as i32 + frame[1] as i32) / 2) as i16),
            _ => {
                let kept = from.min(to);
                out.extend_from_slice(&frame[..kept]);
                out.extend(std::iter::repeat_n(0, to - kept));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remixed(input: &[i16], from: usize, to: usize) -> Vec<i16> {
        let mut out = Vec::new();
        remix(input, from, to, &mut out);
        out
    }

    #[test]
    fn stereo_lands_in_the_front_pair_of_a_surround_layout() {
        assert_eq!(
            remixed(&[1, 2, 3, 4], 2, 6),
            vec![1, 2, 0, 0, 0, 0, 3, 4, 0, 0, 0, 0]
        );
        assert_eq!(remixed(&[1, 2], 2, 8), vec![1, 2, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn mono_goes_to_both_fronts() {
        assert_eq!(remixed(&[7, 9], 1, 2), vec![7, 7, 9, 9]);
        assert_eq!(remixed(&[7], 1, 6), vec![7, 7, 0, 0, 0, 0]);
    }

    #[test]
    fn fewer_channels_out_keeps_the_first_ones() {
        assert_eq!(remixed(&[1, 2, 3, 4, 5, 6], 6, 2), vec![1, 2]);
        assert_eq!(remixed(&[100, 200, -100, -300], 2, 1), vec![150, -200]);
    }

    #[test]
    fn the_same_count_is_a_copy_and_a_ragged_tail_is_dropped() {
        assert_eq!(remixed(&[1, 2, 3], 3, 3), vec![1, 2, 3]);
        assert_eq!(remixed(&[1, 2, 3], 2, 6), vec![1, 2, 0, 0, 0, 0]);
    }
}
