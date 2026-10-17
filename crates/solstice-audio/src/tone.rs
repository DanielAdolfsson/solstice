//! A test tone, and a way to tell whether one came out the other end.
//!
//! Public because the tests that need it are in other crates: the real-guest
//! SPICE test and the real-Moonlight test both decode what reached the far
//! side and ask whether it is still the tone that went in. A sine is the
//! signal for that because a lossy codec is entitled to change every sample
//! but not the pitch.

use std::f64::consts::TAU;

use crate::SAMPLE_RATE;

/// An endless sine at 48 kHz, the same in every channel, at half scale.
#[derive(Clone, Debug)]
pub struct Sine {
    step: f64,
    phase: f64,
    channels: usize,
}

impl Sine {
    /// A tone of `hz` in `channels` channels.
    pub fn new(hz: f64, channels: usize) -> Self {
        Sine {
            step: TAU * hz / SAMPLE_RATE as f64,
            phase: 0.0,
            channels,
        }
    }

    /// The next `samples` sample frames, interleaved.
    pub fn take(&mut self, samples: usize) -> Vec<i16> {
        let mut out = Vec::with_capacity(samples * self.channels);
        for _ in 0..samples {
            let v = (self.phase.sin() * i16::MAX as f64 / 2.0) as i16;
            out.extend(std::iter::repeat_n(v, self.channels));
            self.phase = (self.phase + self.step) % TAU;
        }
        out
    }
}

/// One channel out of interleaved PCM.
pub fn channel(pcm: &[i16], channels: usize, index: usize) -> Vec<i16> {
    pcm.iter().skip(index).step_by(channels).copied().collect()
}

/// Root-mean-square level, in sample units.
pub fn rms(samples: &[i16]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum: f64 = samples.iter().map(|&s| (s as f64).powi(2)).sum();
    (sum / samples.len() as f64).sqrt()
}

/// How much of the signal's power is at `hz`, from 0 to 1.
///
/// Goertzel at the one frequency, against the total power. A clean tone
/// through Opus scores above 0.9; silence and noise score near zero.
pub fn purity(samples: &[i16], hz: f64) -> f64 {
    let n = samples.len();
    if n == 0 {
        return 0.0;
    }
    let w = TAU * hz / SAMPLE_RATE as f64;
    let coeff = 2.0 * w.cos();
    let (mut s1, mut s2) = (0.0f64, 0.0f64);
    let mut total = 0.0f64;
    for &x in samples {
        let x = x as f64;
        total += x * x;
        let s0 = x + coeff * s1 - s2;
        s2 = s1;
        s1 = s0;
    }
    if total == 0.0 {
        return 0.0;
    }
    let power = s1 * s1 + s2 * s2 - coeff * s1 * s2;
    // A pure sine of amplitude A over n samples gives power (A n / 2)^2 and
    // total A^2 n / 2, so this ratio is 1 for a pure tone.
    (2.0 * power / (n as f64 * total)).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sine_is_pure_at_its_own_frequency_and_not_at_another() {
        let pcm = Sine::new(440.0, 1).take(48_000);
        assert!(purity(&pcm, 440.0) > 0.99);
        assert!(purity(&pcm, 1000.0) < 0.01);
    }

    #[test]
    fn silence_is_not_a_tone() {
        assert_eq!(purity(&[0; 4800], 440.0), 0.0);
        assert_eq!(rms(&[0; 4800]), 0.0);
    }

    #[test]
    fn channels_are_interleaved_and_separable() {
        let pcm = Sine::new(440.0, 2).take(10);
        assert_eq!(channel(&pcm, 2, 0), channel(&pcm, 2, 1));
        assert_eq!(channel(&pcm, 2, 0).len(), 10);
        assert!(rms(&Sine::new(440.0, 1).take(48_000)) > 8_000.0);
    }
}
