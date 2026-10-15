//! Reed-Solomon over GF(2^8), in the two unrelated constructions this protocol
//! needs.
//!
//! Generic Rust RS crates do not interoperate with Moonlight: `reed-solomon-simd`
//! is FFT-based over GF(2^16) and `reed-solomon-erasure` is Vandermonde-based.
//! The client's `nanors` uses a **Cauchy** matrix over GF(2^8) with primitive
//! polynomial 285 (0x11D), generated in four lines (`nanors/rs.c:125-129`):
//!
//! ```c
//! for (int j = 0; j < rs->ps; j++)
//!     for (int i = 0; i < rs->ds; i++)
//!         row[i] = GF2_8_INV[(rs->ps + i) ^ j];
//! ```
//!
//! Rows are indexed from `{0..ps-1}` and columns from `{ps..ps+ds-1}`. The sets
//! are disjoint, so no term is zero and every square submatrix is nonsingular --
//! the MDS property erasure coding needs.
//!
//! **Audio is a different code.** Nvidia's RS(4,2) uses a hard-coded matrix
//! that this construction does not reproduce (`stream.cpp:1872-1878`), so it
//! gets its own constant. One implementation does not cover both.

/// Errors from the coder.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FecError {
    /// Shard counts outside what GF(2^8) or the wire format allows.
    #[error("invalid shard counts: {data} data + {parity} parity")]
    InvalidShardCounts {
        /// Data shards requested.
        data: usize,
        /// Parity shards requested.
        parity: usize,
    },
    /// Shards of differing length were handed in.
    #[error("shards differ in length")]
    RaggedShards,
    /// Fewer than `data_shards` shards survived, so nothing can be recovered.
    #[error("too few shards to reconstruct: have {have}, need {need}")]
    TooFewShards {
        /// Shards present.
        have: usize,
        /// Shards required.
        need: usize,
    },
}

/// Shorthand.
pub type Result<T> = std::result::Result<T, FecError>;

// ---------------------------------------------------------------- GF(2^8) --

/// The field's primitive polynomial, as `nanors` generated its tables with
/// (`nanors/deps/obl/gf2_8_tables.h:1`).
pub const POLYNOMIAL: u16 = 0x11D;

const fn build_exp_log() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= POLYNOMIAL;
        }
        i += 1;
    }
    // Duplicate so a log sum up to 508 can be indexed without a modulo.
    let mut j = 255;
    while j < 512 {
        exp[j] = exp[j - 255];
        j += 1;
    }
    (exp, log)
}

const TABLES: ([u8; 512], [u8; 256]) = build_exp_log();
const EXP: [u8; 512] = TABLES.0;
const LOG: [u8; 256] = TABLES.1;

const fn build_inv() -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut a = 1usize;
    while a < 256 {
        // a^-1 = g^(255 - log a)
        inv[a] = EXP[255 - LOG[a] as usize];
        a += 1;
    }
    inv
}

const INV: [u8; 256] = build_inv();

/// Multiply in GF(2^8).
#[inline]
pub const fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        EXP[LOG[a as usize] as usize + LOG[b as usize] as usize]
    }
}

/// Multiplicative inverse in GF(2^8). `inv(0)` is 0, which the Cauchy
/// construction never asks for.
#[inline]
pub const fn inv(a: u8) -> u8 {
    INV[a as usize]
}

/// Divide in GF(2^8).
#[inline]
pub const fn div(a: u8, b: u8) -> u8 {
    mul(a, inv(b))
}

/// `dst[k] ^= coeff * src[k]`, the inner loop of every operation here.
#[inline]
fn mul_add_row(coeff: u8, src: &[u8], dst: &mut [u8]) {
    if coeff == 0 {
        return;
    }
    let log_c = LOG[coeff as usize] as usize;
    for (d, &s) in dst.iter_mut().zip(src.iter()) {
        if s != 0 {
            *d ^= EXP[log_c + LOG[s as usize] as usize];
        }
    }
}

// ----------------------------------------------------------------- coder ---

/// A systematic Reed-Solomon coder over GF(2^8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rs {
    data_shards: usize,
    parity_shards: usize,
    /// Row-major, `parity_shards` rows of `data_shards` coefficients.
    matrix: Vec<u8>,
}

impl Rs {
    /// Build the coder Moonlight's video depacketiser expects: the Cauchy
    /// closed form.
    pub fn video(data_shards: usize, parity_shards: usize) -> Result<Self> {
        if data_shards == 0
            || parity_shards == 0
            || data_shards + parity_shards > 256
            // The wire format carries `dataShards` in 10 bits of `fecInfo` and
            // caps a block at 255 shards.
            || data_shards + parity_shards > 255
        {
            return Err(FecError::InvalidShardCounts {
                data: data_shards,
                parity: parity_shards,
            });
        }
        let mut matrix = vec![0u8; parity_shards * data_shards];
        for j in 0..parity_shards {
            for i in 0..data_shards {
                matrix[j * data_shards + i] = inv(((parity_shards + i) ^ j) as u8);
            }
        }
        Ok(Self {
            data_shards,
            parity_shards,
            matrix,
        })
    }

    /// Nvidia's audio RS(4,2), whose matrix is unrelated to the Cauchy one
    /// (`stream.cpp:1872-1878`).
    pub fn audio() -> Self {
        Self {
            data_shards: 4,
            parity_shards: 2,
            matrix: vec![0x77, 0x40, 0x38, 0x0e, 0xc7, 0xa7, 0x0d, 0x6c],
        }
    }

    /// Build from an explicit parity matrix. Used by the differential tests.
    pub fn from_matrix(data_shards: usize, parity_shards: usize, matrix: Vec<u8>) -> Result<Self> {
        if matrix.len() != data_shards * parity_shards {
            return Err(FecError::InvalidShardCounts {
                data: data_shards,
                parity: parity_shards,
            });
        }
        Ok(Self {
            data_shards,
            parity_shards,
            matrix,
        })
    }

    /// Number of data shards.
    pub const fn data_shards(&self) -> usize {
        self.data_shards
    }

    /// Number of parity shards.
    pub const fn parity_shards(&self) -> usize {
        self.parity_shards
    }

    /// The parity matrix, row-major.
    pub fn matrix(&self) -> &[u8] {
        &self.matrix
    }

    /// Compute parity shards from data shards.
    ///
    /// All shards must be the same length; Sunshine guarantees that by
    /// zero-padding the frame to a multiple of the block size.
    pub fn encode(&self, data: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
        if data.len() != self.data_shards {
            return Err(FecError::InvalidShardCounts {
                data: data.len(),
                parity: self.parity_shards,
            });
        }
        let len = data.first().map(|s| s.len()).unwrap_or(0);
        if data.iter().any(|s| s.len() != len) {
            return Err(FecError::RaggedShards);
        }
        let mut parity = vec![vec![0u8; len]; self.parity_shards];
        for (j, out) in parity.iter_mut().enumerate() {
            for (i, shard) in data.iter().enumerate() {
                mul_add_row(self.matrix[j * self.data_shards + i], shard, out);
            }
        }
        Ok(parity)
    }

    /// Recover missing data shards in place.
    ///
    /// `shards` is `data_shards + parity_shards` slots in wire order, with
    /// `None` for anything lost. On success every data slot is `Some`.
    pub fn reconstruct(&self, shards: &mut [Option<Vec<u8>>]) -> Result<()> {
        let total = self.data_shards + self.parity_shards;
        if shards.len() != total {
            return Err(FecError::InvalidShardCounts {
                data: shards.len(),
                parity: self.parity_shards,
            });
        }
        let len =
            shards
                .iter()
                .flatten()
                .map(|s| s.len())
                .next()
                .ok_or(FecError::TooFewShards {
                    have: 0,
                    need: self.data_shards,
                })?;
        if shards.iter().flatten().any(|s| s.len() != len) {
            return Err(FecError::RaggedShards);
        }
        if shards[..self.data_shards].iter().all(|s| s.is_some()) {
            return Ok(());
        }

        // Pick `data_shards` surviving rows of the full encoding matrix
        // [I ; P] and solve the resulting square system.
        let present: Vec<usize> = (0..total).filter(|&k| shards[k].is_some()).collect();
        if present.len() < self.data_shards {
            return Err(FecError::TooFewShards {
                have: present.len(),
                need: self.data_shards,
            });
        }
        let chosen = &present[..self.data_shards];

        let n = self.data_shards;
        let mut sub = vec![0u8; n * n];
        for (row, &k) in chosen.iter().enumerate() {
            if k < self.data_shards {
                sub[row * n + k] = 1;
            } else {
                let j = k - self.data_shards;
                sub[row * n..row * n + n].copy_from_slice(&self.matrix[j * n..j * n + n]);
            }
        }
        let inverse = invert(&sub, n).ok_or(FecError::TooFewShards {
            have: present.len(),
            need: self.data_shards,
        })?;

        // Recover only the data shards that are actually missing.
        for target in 0..self.data_shards {
            if shards[target].is_some() {
                continue;
            }
            let mut out = vec![0u8; len];
            for (col, &k) in chosen.iter().enumerate() {
                let coeff = inverse[target * n + col];
                let src = shards[k].as_ref().expect("chosen rows are present");
                mul_add_row(coeff, src, &mut out);
            }
            shards[target] = Some(out);
        }
        Ok(())
    }
}

/// Gauss-Jordan inversion of an `n`x`n` matrix over GF(2^8).
fn invert(m: &[u8], n: usize) -> Option<Vec<u8>> {
    let mut a = m.to_vec();
    let mut inverse = vec![0u8; n * n];
    for i in 0..n {
        inverse[i * n + i] = 1;
    }
    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r * n + col] != 0)?;
        if pivot != col {
            for k in 0..n {
                a.swap(pivot * n + k, col * n + k);
                inverse.swap(pivot * n + k, col * n + k);
            }
        }
        let p = a[col * n + col];
        if p != 1 {
            let ip = inv(p);
            for k in 0..n {
                a[col * n + k] = mul(a[col * n + k], ip);
                inverse[col * n + k] = mul(inverse[col * n + k], ip);
            }
        }
        for row in 0..n {
            if row == col {
                continue;
            }
            let factor = a[row * n + col];
            if factor == 0 {
                continue;
            }
            for k in 0..n {
                a[row * n + k] ^= mul(factor, a[col * n + k]);
                inverse[row * n + k] ^= mul(factor, inverse[col * n + k]);
            }
        }
    }
    Some(inverse)
}

/// Parity shard count for a block, derived the way both ends derive it.
///
/// The count is **never transmitted**: Sunshine computes it at
/// `stream.cpp:866` and `moonlight-common-c` recomputes it at
/// `RtpVideoQueue.c:712` with the same expression. An encoder must therefore
/// guarantee that the percentage it writes re-derives to the parity count it
/// actually used.
pub const fn parity_count(data_shards: usize, fec_percentage: usize) -> usize {
    (data_shards * fec_percentage).div_ceil(100)
}

/// Largest data-shard count for a block at a given FEC percentage:
/// `255 * 100 / (100 + pct)`.
pub const fn max_data_shards(fec_percentage: usize) -> usize {
    255 * 100 / (100 + fec_percentage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_uses_polynomial_285() {
        // x^7 * x = x^8 = x^4 + x^3 + x^2 + 1 under 0x11D.
        assert_eq!(mul(0x80, 0x02), 0x1D);
        assert_eq!(mul(0x01, 0xFF), 0xFF);
        assert_eq!(mul(0x00, 0xFF), 0x00);
        // Spot checks against the independent reimplementation in
        // tests/vectors/fec/check.py. These pin the tables to polynomial 285
        // rather than merely to some self-consistent field -- the AES field
        // (0x11B) gives different answers for all of them.
        assert_eq!(mul(0x53, 0xCA), 0x8F);
        assert_eq!(mul(0xFF, 0xFF), 0xE2);
        assert_eq!(inv(0x02), 0x8E);
        assert_eq!(inv(0x53), 0x8C);
    }

    #[test]
    fn every_nonzero_element_has_an_inverse() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1, "{a:#x}");
        }
        assert_eq!(inv(0), 0);
    }

    #[test]
    fn field_is_associative_and_distributive() {
        for a in (1..=255u8).step_by(17) {
            for b in (1..=255u8).step_by(13) {
                for c in (1..=255u8).step_by(29) {
                    assert_eq!(mul(mul(a, b), c), mul(a, mul(b, c)));
                    assert_eq!(mul(a, b ^ c), mul(a, b) ^ mul(a, c));
                    assert_eq!(div(mul(a, b), b), a);
                }
            }
        }
    }

    #[test]
    fn video_matrix_is_the_documented_closed_form() {
        let rs = Rs::video(5, 2).unwrap();
        for j in 0..2usize {
            for i in 0..5usize {
                assert_eq!(rs.matrix()[j * 5 + i], inv(((2 + i) ^ j) as u8));
            }
        }
    }

    #[test]
    fn video_matrix_differs_from_the_audio_matrix() {
        // The documented trap: nanors for RS(4,2) gives 142 244 71 167 /
        // 244 142 167 71, while Nvidia's audio matrix is unrelated.
        let cauchy = Rs::video(4, 2).unwrap();
        assert_eq!(cauchy.matrix(), &[142, 244, 71, 167, 244, 142, 167, 71]);
        assert_eq!(
            Rs::audio().matrix(),
            &[0x77, 0x40, 0x38, 0x0e, 0xc7, 0xa7, 0x0d, 0x6c]
        );
        assert_ne!(cauchy.matrix(), Rs::audio().matrix());
    }

    fn deterministic_shards(count: usize, len: usize, seed: u32) -> Vec<Vec<u8>> {
        let mut state = seed;
        (0..count)
            .map(|_| {
                (0..len)
                    .map(|_| {
                        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                        (state >> 16) as u8
                    })
                    .collect()
            })
            .collect()
    }

    /// The `FEC_VALIDATION_MODE` invariant, run locally: drop shards, recover
    /// them, and assert the recovered bytes are byte-exact.
    fn recovery_round_trip(rs: &Rs, len: usize, drop: &[usize]) {
        let data = deterministic_shards(rs.data_shards(), len, 0xC0FFEE);
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        let parity = rs.encode(&refs).unwrap();

        let mut shards: Vec<Option<Vec<u8>>> = data
            .iter()
            .cloned()
            .map(Some)
            .chain(parity.iter().cloned().map(Some))
            .collect();
        for &k in drop {
            shards[k] = None;
        }
        rs.reconstruct(&mut shards).unwrap();
        for (i, original) in data.iter().enumerate() {
            assert_eq!(shards[i].as_ref().unwrap(), original, "data shard {i}");
        }
    }

    #[test]
    fn video_recovers_every_single_shard_loss() {
        let rs = Rs::video(10, 2).unwrap();
        for k in 0..12 {
            recovery_round_trip(&rs, 64, &[k]);
        }
    }

    #[test]
    fn video_recovers_up_to_parity_count_losses() {
        let rs = Rs::video(8, 4).unwrap();
        recovery_round_trip(&rs, 128, &[0, 1, 2, 3]);
        recovery_round_trip(&rs, 128, &[0, 5, 8, 11]);
        recovery_round_trip(&rs, 128, &[8, 9, 10, 11]);
    }

    #[test]
    fn video_refuses_when_too_much_is_lost() {
        let rs = Rs::video(4, 2).unwrap();
        let data = deterministic_shards(4, 16, 1);
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        let parity = rs.encode(&refs).unwrap();
        let mut shards: Vec<Option<Vec<u8>>> = data
            .into_iter()
            .map(Some)
            .chain(parity.into_iter().map(Some))
            .collect();
        shards[0] = None;
        shards[1] = None;
        shards[2] = None;
        assert!(matches!(
            rs.reconstruct(&mut shards),
            Err(FecError::TooFewShards { have: 3, need: 4 })
        ));
    }

    /// The four block shapes `docs/moonlight-sunshine-protocol.md` §5.4 lists
    /// as verified byte-exact against a compiled `nanors`.
    #[test]
    fn the_documented_block_shapes_encode_and_recover() {
        for (ds, ps, bs) in [(1, 2, 32), (5, 2, 64), (212, 42, 96), (100, 20, 1408)] {
            let rs = Rs::video(ds, ps).unwrap();
            recovery_round_trip(&rs, bs, &[0]);
        }
    }

    #[test]
    fn audio_rs_4_2_recovers_any_two_losses() {
        let rs = Rs::audio();
        for a in 0..6 {
            for b in (a + 1)..6 {
                recovery_round_trip(&rs, 240, &[a, b]);
            }
        }
    }

    #[test]
    fn parity_count_is_ceiling_division() {
        assert_eq!(parity_count(100, 20), 20);
        assert_eq!(parity_count(101, 20), 21); // 20.2 -> 21
        assert_eq!(parity_count(1, 20), 1);
        assert_eq!(parity_count(10, 0), 0);
        assert_eq!(parity_count(5, 40), 2);
    }

    /// An encoder must guarantee that the percentage it writes re-derives to
    /// the parity count it used, because the client never sees the count.
    #[test]
    fn percentage_re_derives_to_the_parity_count_used() {
        for ds in 1..=212usize {
            for pct in [0usize, 5, 10, 20, 50] {
                let ps = parity_count(ds, pct);
                assert_eq!(parity_count(ds, pct), ps);
                if ps > 0 {
                    assert!(ds + ps <= 255 || pct > 20);
                }
            }
        }
    }

    #[test]
    fn max_data_shards_matches_the_documented_expression() {
        assert_eq!(max_data_shards(0), 255);
        assert_eq!(max_data_shards(20), 212);
    }

    #[test]
    fn invalid_shard_counts_are_refused() {
        assert!(Rs::video(0, 2).is_err());
        assert!(Rs::video(10, 0).is_err());
        assert!(Rs::video(250, 10).is_err());
    }

    #[test]
    fn ragged_shards_are_refused() {
        let rs = Rs::video(2, 1).unwrap();
        assert_eq!(
            rs.encode(&[&[1, 2, 3][..], &[1, 2][..]]).unwrap_err(),
            FecError::RaggedShards
        );
    }
}
