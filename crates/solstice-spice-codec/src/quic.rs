//! QUIC -- SPICE's own lossless image codec.
//!
//! Despite the name this has nothing to do with the transport protocol. It is
//! Red Hat's derivative of Roman Starosolski's **SFALIC**, and the three
//! moving parts are:
//!
//! 1. **Prediction.** Each colour channel is predicted from its left
//!    neighbour (`a`) and the pixel above (`b`) as `(a + b) / 2`, and only the
//!    residual is coded. The first row has no `b` and uses `a` alone; the
//!    first pixel of a row has no `a` and uses `b` alone.
//! 2. **An adaptive Golomb-Rice model.** Residuals are mapped to a
//!    zigzag-like distribution and coded with one of `bpc` Golomb codes. Which
//!    code is chosen depends on a *bucket* selected by the previous residual,
//!    and each bucket keeps a running cost for every code and switches to
//!    whichever is winning. Encoder and decoder update these counters in
//!    lockstep, so the model is never transmitted -- and a single bit error
//!    desynchronises the rest of the image.
//! 3. **A melcode run mode.** When the pixel above and its left neighbour are
//!    equal, and so are the two pixels to the left, both sides switch to
//!    coding a run length with an adaptive Golomb code of its own.
//!
//! Two subtleties are load-bearing and easy to lose in a port:
//!
//! - **The model is not updated on every pixel.** It is updated at pseudo-
//!   random intervals driven by `TABRAND_CHAOS`, a fixed 256-entry table,
//!   with both sides walking it identically. The interval widens as the image
//!   goes on (`wmidx`), so the model settles.
//! - **The RGB channels share one `CommonState`** -- one run mode, one
//!   random walk, one wait counter -- while each keeps its *own* bucket set.
//!   Grey and the alpha plane of RGBA instead use the state attached to their
//!   channel. Getting this wrong decodes the first few hundred pixels
//!   correctly and then drifts, which is exactly the bug the differential
//!   vectors in `tests/quic_vectors.rs` are there to catch.
//!
//! Ported from `common/quic.c`, `common/quic_tmpl.c` and
//! `common/quic_family_tmpl.c` in `spice-common`.

use crate::bits::BitReader;
use crate::{Error, Image, Limits, PixelFormat};

/// ASCII `"QUIC"`, little-endian.
const QUIC_MAGIC: u32 = 0x4349_5551;
/// Major 0, minor 0. The only version that has ever existed.
const QUIC_VERSION: u32 = 0;

/// Golomb codes per family: one per bit of the channel, up to 8.
const MAX_NUM_CODES: usize = 8;
/// Codeword length limit, `DEFmaxclen`. Bounds every codeword at 26 bits.
const MAX_CODEWORD_LEN: u32 = 26;
/// `DEFwmistart` -- the wait-mask index a channel starts at.
const WM_START: u32 = 0;
/// `DEFwmimax` -- the index it stops growing at.
const WM_MAX: u32 = 6;
/// `DEFwminext` -- symbols coded at one index before moving to the next.
const WM_NEXT: u32 = 2048;
/// `stabrand()` -- the seed both sides start their random walk from.
const TABRAND_SEED: u32 = 0xff;
/// Number of melcode states.
const MELC_STATES: usize = 32;

/// `n` ones in the low bits. `bppmask` in the C, which indexes it up to 32.
#[inline]
const fn bpp_mask(n: u32) -> u32 {
    if n >= 32 {
        u32::MAX
    } else {
        (1u32 << n) - 1
    }
}

include!("quic_tables.rs");

/// Melcode run-length orders, `J` in the C.
const J: [u32; MELC_STATES] = [
    0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 9, 10, 11, 12, 13,
    14, 15,
];

/// Counter-halving thresholds by wait-mask index, `besttrigtab[DEFevol / 2]`.
///
/// The C table has three rows, one per legal `DEFevol`, and `DEFevol` is fixed
/// at 3 by a compile-time assertion -- it is part of the bitstream format, not
/// a tuning knob, since both sides must evolve their models identically. Only
/// the row for 3 can ever be read, so only that row is here.
const BEST_TRIG_TAB: [u32; 11] = [110, 550, 900, 800, 550, 400, 350, 250, 140, 160, 140];

/// The image types a QUIC stream can declare, `QuicImageType` in `quic.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicImageType {
    /// One 8-bit channel. SPICE uses this for A8 alpha masks.
    Gray,
    /// Three 5-bit channels packed into 16 bits.
    Rgb16,
    /// Three 8-bit channels, 24 bits per pixel.
    Rgb24,
    /// Three 8-bit channels, 32 bits per pixel, the fourth byte unused.
    Rgb32,
    /// Three 8-bit colour channels plus a separately coded 8-bit alpha plane.
    Rgba,
}

impl QuicImageType {
    fn from_wire(v: u32) -> Result<Self, Error> {
        // 0 is QUIC_IMAGE_TYPE_INVALID, which the C names but never emits.
        Ok(match v {
            1 => QuicImageType::Gray,
            2 => QuicImageType::Rgb16,
            3 => QuicImageType::Rgb24,
            4 => QuicImageType::Rgb32,
            5 => QuicImageType::Rgba,
            got => return Err(Error::BadImageType { codec: "QUIC", got }),
        })
    }

    /// How many channels are modelled, and at what depth.
    ///
    /// `quic_image_params`. The channel count drives how much model state is
    /// reset per image, and the depth selects which Golomb family is used.
    fn params(self) -> (usize, u32) {
        match self {
            QuicImageType::Gray => (1, 8),
            QuicImageType::Rgb16 => (3, 5),
            QuicImageType::Rgb24 | QuicImageType::Rgb32 => (3, 8),
            QuicImageType::Rgba => (4, 8),
        }
    }
}

// ---------------------------------------------------------------------------
// The Golomb families
// ---------------------------------------------------------------------------

/// The Golomb code family for one channel depth.
///
/// Derived from `bpc` and the codeword-length limit alone, so both sides
/// compute it rather than transmitting it. `family_init` in the C builds it
/// once into a static; here it is built once per depth and shared.
struct Family {
    /// Residuals below this use the plain Golomb-Rice codeword.
    n_gr_codewords: [u32; MAX_NUM_CODES],
    /// Codeword length of the escape ("not-GR") form.
    not_gr_cw_len: [u32; MAX_NUM_CODES],
    /// A peeked word above this is a Golomb-Rice codeword, below it an escape.
    not_gr_prefix_mask: [u32; MAX_NUM_CODES],
    /// Suffix length of the escape form.
    not_gr_suffix_len: [u32; MAX_NUM_CODES],
    /// Codeword length per residual value and code number; drives the model.
    golomb_code_len: [[u32; MAX_NUM_CODES]; 256],
    /// Maps a coded residual back to a signed difference.
    ///
    /// 256 entries regardless of depth, with only the low `2^bpc` filled: a
    /// corrupt stream can produce an index above the depth's range, and the C
    /// reads the zeroed tail of a static rather than bounds-checking. Keeping
    /// the tail zeroed reproduces that exactly.
    xlat_l2u: [u32; 256],
}

impl Family {
    fn new(bpc: u32, limit: u32) -> Self {
        let mut f = Family {
            n_gr_codewords: [0; MAX_NUM_CODES],
            not_gr_cw_len: [0; MAX_NUM_CODES],
            not_gr_prefix_mask: [0; MAX_NUM_CODES],
            not_gr_suffix_len: [0; MAX_NUM_CODES],
            golomb_code_len: [[0; MAX_NUM_CODES]; 256],
            xlat_l2u: [0; 256],
        };

        for l in 0..bpc as usize {
            let alt_prefix_len = (limit - bpc).min(bpp_mask(bpc - l as u32));
            let alt_codewords = bpp_mask(bpc) + 1 - (alt_prefix_len << l);

            f.n_gr_codewords[l] = alt_prefix_len << l;
            f.not_gr_suffix_len[l] = ceil_log2(alt_codewords);
            f.not_gr_cw_len[l] = alt_prefix_len + f.not_gr_suffix_len[l];
            f.not_gr_prefix_mask[l] = bpp_mask(32 - alt_prefix_len);

            // `golomb_coding_slow`, kept only for its length: the decoder
            // never needs the codeword itself, but the model is driven by how
            // long each candidate code *would* have been.
            for (n, lens) in f.golomb_code_len.iter_mut().enumerate() {
                lens[l] = if (n as u32) < f.n_gr_codewords[l] {
                    (n as u32 >> l) + l as u32 + 1
                } else {
                    f.not_gr_cw_len[l]
                };
            }
        }

        // correlate_init
        let pixel_bit_mask = bpp_mask(bpc);
        for s in 0..=pixel_bit_mask {
            f.xlat_l2u[s as usize] = if s & 1 == 1 {
                pixel_bit_mask - (s >> 1)
            } else {
                s >> 1
            };
        }

        f
    }

    /// Read one codeword under code number `l` from the 32 bits in `bits`.
    ///
    /// Returns the residual and how many bits it used. Truncating to `u8` is
    /// deliberate: the escape form can decode above the channel's range on a
    /// corrupt stream and the C stores the result in a `BYTE`, so the wrap is
    /// part of the behaviour being reproduced.
    #[inline]
    fn decode(&self, l: u32, bits: u32) -> (u8, u32) {
        let l = l as usize;
        if bits > self.not_gr_prefix_mask[l] {
            let zero_prefix = bits.leading_zeros();
            let cw_len = zero_prefix + 1 + l as u32;
            let value = (zero_prefix << l) | ((bits >> (32 - cw_len)) & bpp_mask(l as u32));
            (value as u8, cw_len)
        } else {
            let cw_len = self.not_gr_cw_len[l];
            let value = self.n_gr_codewords[l]
                + ((bits >> (32 - cw_len)) & bpp_mask(self.not_gr_suffix_len[l]));
            (value as u8, cw_len)
        }
    }
}

/// `ceil(log_2(val))`, matching the C's loop including `val == 1 => 0`.
fn ceil_log2(val: u32) -> u32 {
    if val <= 1 {
        return 0;
    }
    32 - (val - 1).leading_zeros()
}

fn family_8bpc() -> &'static Family {
    static F: std::sync::OnceLock<Family> = std::sync::OnceLock::new();
    F.get_or_init(|| Family::new(8, MAX_CODEWORD_LEN))
}

fn family_5bpc() -> &'static Family {
    static F: std::sync::OnceLock<Family> = std::sync::OnceLock::new();
    F.get_or_init(|| Family::new(5, MAX_CODEWORD_LEN))
}

// ---------------------------------------------------------------------------
// Model state
// ---------------------------------------------------------------------------

/// The state shared by the channels that code together.
///
/// One of these covers all three RGB channels; grey and the alpha plane each
/// get the one attached to their own channel. It holds everything that must
/// advance identically on both sides but is not per-channel: the random walk,
/// the model-update schedule, and the run-mode position.
#[derive(Debug, Clone, Default)]
struct CommonState {
    /// Pixels left before the next model update.
    wait_cnt: u32,
    /// Cursor into [`TABRAND_CHAOS`].
    tabrand_seed: u32,
    /// Counter value above which a bucket halves its counters.
    wm_trigger: u32,
    /// Wait-mask index: how wide the gap between model updates has grown.
    wm_idx: u32,
    /// Symbols left to code before `wm_idx` advances.
    wm_left: u32,
    /// Index into [`J`].
    melc_state: usize,
    /// `J[melc_state]` -- the expected run length is `2^melc_len`.
    melc_len: u32,
    /// `1 << melc_len`.
    melc_order: u32,
}

impl CommonState {
    /// `encoder_reset` plus `encoder_init_rle`, for one state.
    fn reset(&mut self) {
        self.wait_cnt = 0;
        self.tabrand_seed = TABRAND_SEED;
        self.wm_idx = WM_START;
        self.wm_left = WM_NEXT;
        self.set_wm_trigger();
        self.melc_state = 0;
        self.melc_len = J[0];
        self.melc_order = 1 << self.melc_len;
    }

    fn set_wm_trigger(&mut self) {
        self.wm_trigger = BEST_TRIG_TAB[self.wm_idx.min(10) as usize];
    }

    #[inline]
    fn tabrand(&mut self) -> u32 {
        self.tabrand_seed = self.tabrand_seed.wrapping_add(1);
        TABRAND_CHAOS[(self.tabrand_seed & 0xff) as usize]
    }

    /// Read a run length in run mode, `decode_state_run`.
    ///
    /// Terminates on any input: the leading-ones scan stops as soon as a zero
    /// bit appears, and past the end of the stream the reader supplies zeroes.
    fn decode_run(&mut self, io: &mut BitReader<'_>) -> u32 {
        let mut run_len: u32 = 0;

        loop {
            // Leading ones in the top byte of the window, up to 8.
            let leading_ones = (!(io.peek() >> 24) as u8).leading_zeros();
            for _ in 0..leading_ones {
                run_len = run_len.saturating_add(self.melc_order);
                if self.melc_state < MELC_STATES - 1 {
                    self.melc_state += 1;
                    self.melc_len = J[self.melc_state];
                    self.melc_order = 1 << self.melc_len;
                }
            }
            if leading_ones != 8 {
                // Consume the ones and the zero that ends them.
                io.eat(leading_ones + 1);
                break;
            }
            io.eat(8);
        }

        if self.melc_len != 0 {
            run_len = run_len.saturating_add(io.peek() >> (32 - self.melc_len));
            io.eat(self.melc_len);
        }

        if self.melc_state != 0 {
            self.melc_state -= 1;
            self.melc_len = J[self.melc_state];
            self.melc_order = 1 << self.melc_len;
        }

        run_len
    }
}

/// One bucket of the adaptive model: a running cost per code, and the winner.
#[derive(Debug, Clone)]
struct Bucket {
    counters: [u32; MAX_NUM_CODES],
    best_code: u32,
}

/// Per-channel model state.
struct Channel {
    /// Coded residuals for the row in progress.
    ///
    /// Index `i + 1` is pixel `i`; index 0 is the C's `correlate_row[-1]`,
    /// which carries the last residual of the previous row into the bucket
    /// choice for the first pixel of this one.
    correlate_row: Vec<u8>,
    /// Which bucket each previous-residual value selects.
    bucket_of_level: Vec<u16>,
    buckets: Vec<Bucket>,
}

impl Channel {
    fn new() -> Self {
        Channel {
            correlate_row: Vec::new(),
            bucket_of_level: Vec::new(),
            buckets: Vec::new(),
        }
    }

    /// `encoder_reset_channels` for one channel: resize the row buffer, zero
    /// the counters, and put every bucket back on the widest code.
    fn reset(&mut self, width: usize, bpc: u32) {
        self.correlate_row.clear();
        self.correlate_row.resize(width + 1, 0);

        let levels = 1usize << bpc;
        if self.bucket_of_level.len() != levels {
            build_buckets(levels, &mut self.bucket_of_level, &mut self.buckets);
        }
        for bucket in &mut self.buckets {
            bucket.counters = [0; MAX_NUM_CODES];
            bucket.best_code = bpc - 1;
        }
    }

    #[inline]
    fn bucket_for(&self, level: u8, bpc_mask: u32) -> usize {
        // The mask is the C's defence against a corrupt residual indexing out
        // of the table, and is cheaper there than a comparison.
        self.bucket_of_level[(level as u32 & bpc_mask) as usize] as usize
    }

    /// `update_model`: charge every code for what it would have spent on
    /// `cur_val`, adopt the cheapest, and halve when the cheapest gets large.
    #[inline]
    fn update_model(
        &mut self,
        family: &Family,
        bucket: usize,
        cur_val: u8,
        bpc: u32,
        trigger: u32,
    ) {
        let bucket = &mut self.buckets[bucket];
        let lens = &family.golomb_code_len[cur_val as usize];

        let mut best_code = bpc - 1;
        bucket.counters[best_code as usize] =
            bucket.counters[best_code as usize].wrapping_add(lens[best_code as usize]);
        let mut best_len = bucket.counters[best_code as usize];

        for i in (0..bpc - 1).rev() {
            let counter = &mut bucket.counters[i as usize];
            *counter = counter.wrapping_add(lens[i as usize]);
            if *counter < best_len {
                best_code = i;
                best_len = *counter;
            }
        }

        bucket.best_code = best_code;

        if best_len > trigger {
            for counter in bucket.counters.iter_mut().take(bpc as usize) {
                *counter >>= 1;
            }
        }
    }
}

/// `find_model_params` + `fill_model_structures` for `DEFevol == 3`.
///
/// Buckets grow geometrically -- 1, 2, 4, 8, ... contexts each -- so that
/// rarely-seen residual values share statistics and common ones get their own.
/// The last bucket swallows whatever is left rather than being allowed to run
/// past `levels`.
fn build_buckets(levels: usize, bucket_of_level: &mut Vec<u16>, buckets: &mut Vec<Bucket>) {
    bucket_of_level.clear();
    bucket_of_level.resize(levels, 0);
    buckets.clear();

    // DEFevol == 3: rep_first = rep_next = 1, first_size = 1, mul_size = 2.
    let mut rep_cntr = 2u32;
    let mut bsize = 1usize;
    let mut bend = 0usize;

    loop {
        let bstart = if buckets.is_empty() { 0 } else { bend + 1 };

        rep_cntr -= 1;
        if rep_cntr == 0 {
            rep_cntr = 1;
            bsize *= 2;
        }

        bend = bstart + bsize - 1;
        if bend + bsize >= levels {
            bend = levels - 1;
        }

        let index = buckets.len() as u16;
        buckets.push(Bucket {
            counters: [0; MAX_NUM_CODES],
            best_code: 0,
        });
        for slot in &mut bucket_of_level[bstart..=bend] {
            *slot = index;
        }

        if bend >= levels - 1 {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Pixel layouts
// ---------------------------------------------------------------------------

/// How one decoded row is addressed.
///
/// The C generates six variants of the row loops with the preprocessor, one
/// per `(source depth, output layout)` pair. This crate needs four, because it
/// only ever writes BGRA or 8-bit grey. Channel 0 is red, 1 green, 2 blue --
/// the order the codewords arrive in, which is not the order they sit in
/// memory.
trait Format {
    /// Bits per channel: 8, or 5 for a 16-bit source.
    const BPC: u32;
    /// Channels coded together under one [`CommonState`].
    const CHANNELS: usize;
    /// Bytes one pixel occupies in the output.
    const PIXEL_BYTES: usize;

    fn get(row: &[u8], i: usize, ch: usize) -> u32;
    fn set(row: &mut [u8], i: usize, ch: usize, v: u32);
    /// `UNCOMPRESS_PIX_START`: clear whatever the channel writes will not.
    fn start(row: &mut [u8], i: usize);
}

/// 8 bits per channel into BGRA. Serves source types RGB32 and RGB24 alike:
/// they differ only in output layout, and this crate has one output layout.
struct Rgb32;

impl Format for Rgb32 {
    const BPC: u32 = 8;
    const CHANNELS: usize = 3;
    const PIXEL_BYTES: usize = 4;

    #[inline]
    fn get(row: &[u8], i: usize, ch: usize) -> u32 {
        // ch 0 = r at byte 2, 1 = g at byte 1, 2 = b at byte 0.
        row[i * 4 + (2 - ch)] as u32
    }
    #[inline]
    fn set(row: &mut [u8], i: usize, ch: usize, v: u32) {
        row[i * 4 + (2 - ch)] = v as u8;
    }
    #[inline]
    fn start(row: &mut [u8], i: usize) {
        row[i * 4 + 3] = 0;
    }
}

/// 5 bits per channel, expanded into BGRA on the way out.
///
/// The expansion replicates the top bits into the bottom, so a 5-bit 0x1f
/// becomes 0xff rather than 0xf8, and `get` is its exact inverse -- which it
/// has to be, because the predictor reads pixels back out of the output
/// buffer it just wrote.
struct Rgb16To32;

impl Format for Rgb16To32 {
    const BPC: u32 = 5;
    const CHANNELS: usize = 3;
    const PIXEL_BYTES: usize = 4;

    #[inline]
    fn get(row: &[u8], i: usize, ch: usize) -> u32 {
        (row[i * 4 + (2 - ch)] >> 3) as u32
    }
    #[inline]
    fn set(row: &mut [u8], i: usize, ch: usize, v: u32) {
        row[i * 4 + (2 - ch)] = ((v << 3) | ((v & 0x1f) >> 2)) as u8;
    }
    #[inline]
    fn start(row: &mut [u8], i: usize) {
        row[i * 4 + 3] = 0;
    }
}

/// A single 8-bit plane, one byte per pixel. Grey images.
struct OneByte;

impl Format for OneByte {
    const BPC: u32 = 8;
    const CHANNELS: usize = 1;
    const PIXEL_BYTES: usize = 1;

    #[inline]
    fn get(row: &[u8], i: usize, _ch: usize) -> u32 {
        row[i] as u32
    }
    #[inline]
    fn set(row: &mut [u8], i: usize, _ch: usize, v: u32) {
        row[i] = v as u8;
    }
    #[inline]
    fn start(_row: &mut [u8], _i: usize) {}
}

/// A single 8-bit plane strided across BGRA: the alpha byte of an RGBA image.
///
/// RGBA is coded as an RGB image followed by a second, independent pass over
/// the same pixels carrying alpha. The C reaches it by casting the buffer to
/// a four-byte pixel type whose first field lands on byte 3.
struct AlphaPlane;

impl Format for AlphaPlane {
    const BPC: u32 = 8;
    const CHANNELS: usize = 1;
    const PIXEL_BYTES: usize = 4;

    #[inline]
    fn get(row: &[u8], i: usize, _ch: usize) -> u32 {
        row[i * 4 + 3] as u32
    }
    #[inline]
    fn set(row: &mut [u8], i: usize, _ch: usize, v: u32) {
        row[i * 4 + 3] = v as u8;
    }
    #[inline]
    fn start(_row: &mut [u8], _i: usize) {}
}

#[inline]
fn same_pixel<F: Format>(row: &[u8], a: usize, b: usize) -> bool {
    (0..F::CHANNELS).all(|ch| F::get(row, a, ch) == F::get(row, b, ch))
}

/// `COPY_PIXEL`: copy only the channels the format codes, leaving whatever
/// [`Format::start`] cleared cleared.
#[inline]
fn copy_pixel<F: Format>(row: &mut [u8], dst: usize, src: usize) {
    let mut tmp = [0u32; 3];
    for (ch, slot) in tmp.iter_mut().enumerate().take(F::CHANNELS) {
        *slot = F::get(row, src, ch);
    }
    for (ch, value) in tmp.iter().enumerate().take(F::CHANNELS) {
        F::set(row, dst, ch, *value);
    }
}

// ---------------------------------------------------------------------------
// Row decoding
// ---------------------------------------------------------------------------

/// Everything the row loops touch, gathered so the per-pixel code can borrow
/// the reader and the channels at once.
struct Rows<'a, 'i> {
    io: &'a mut BitReader<'i>,
    state: &'a mut CommonState,
    channels: &'a mut [Channel],
    family: &'static Family,
}

impl Rows<'_, '_> {
    /// Decode one channel's residual, returning it and leaving the reader
    /// past the codeword. `prev_level` selects the bucket.
    #[inline]
    fn residual<F: Format>(&mut self, ch: usize, prev_level: u8) -> u8 {
        let bucket = self.channels[ch].bucket_for(prev_level, bpp_mask(F::BPC));
        let code = self.channels[ch].buckets[bucket].best_code;
        let (value, len) = self.family.decode(code, self.io.peek());
        self.io.eat(len);
        value
    }

    /// `UPDATE_MODEL(index)` across every channel of the format.
    #[inline]
    fn update_model<F: Format>(&mut self, index: usize) {
        let trigger = self.state.wm_trigger;
        for ch in 0..F::CHANNELS {
            let prev = self.channels[ch].correlate_row[index];
            let cur = self.channels[ch].correlate_row[index + 1];
            let bucket = self.channels[ch].bucket_for(prev, bpp_mask(F::BPC));
            self.channels[ch].update_model(self.family, bucket, cur, F::BPC, trigger);
        }
    }

    /// The first row of an image: predicted from the left neighbour alone.
    fn row0_seg<F: Format>(&mut self, mut i: usize, cur: &mut [u8], end: usize, wait_mask: u32) {
        let bpc_mask = bpp_mask(F::BPC);

        if i == 0 {
            F::start(cur, 0);
            for ch in 0..F::CHANNELS {
                let prev_level = self.channels[ch].correlate_row[0];
                let value = self.residual::<F>(ch, prev_level);
                self.channels[ch].correlate_row[1] = value;
                // No left neighbour: the residual is the pixel.
                F::set(cur, 0, ch, self.family.xlat_l2u[value as usize]);
            }

            if self.state.wait_cnt > 0 {
                self.state.wait_cnt -= 1;
            } else {
                self.state.wait_cnt = self.state.tabrand() & wait_mask;
                self.update_model::<F>(0);
            }
            i += 1;
        }
        let mut stop_at = i + self.state.wait_cnt as usize;

        while stop_at < end {
            while i <= stop_at {
                self.pixel_row0::<F>(cur, i, bpc_mask);
                i += 1;
            }
            self.update_model::<F>(stop_at);
            stop_at = i + (self.state.tabrand() & wait_mask) as usize;
        }

        while i < end {
            self.pixel_row0::<F>(cur, i, bpc_mask);
            i += 1;
        }
        self.state.wait_cnt = (stop_at - end) as u32;
    }

    #[inline]
    fn pixel_row0<F: Format>(&mut self, cur: &mut [u8], i: usize, bpc_mask: u32) {
        F::start(cur, i);
        for ch in 0..F::CHANNELS {
            let prev_level = self.channels[ch].correlate_row[i];
            let value = self.residual::<F>(ch, prev_level);
            self.channels[ch].correlate_row[i + 1] = value;
            let left = F::get(cur, i - 1, ch);
            F::set(
                cur,
                i,
                ch,
                (self.family.xlat_l2u[value as usize] + left) & bpc_mask,
            );
        }
    }

    /// `uncompress_row0`: split the row at each wait-mask-index change.
    fn row0<F: Format>(&mut self, cur: &mut [u8], mut width: usize) {
        let mut pos = 0usize;

        while WM_MAX > self.state.wm_idx && (self.state.wm_left as usize) <= width {
            let left = self.state.wm_left as usize;
            if left > 0 {
                let mask = bpp_mask(self.state.wm_idx);
                self.row0_seg::<F>(pos, cur, pos + left, mask);
                pos += left;
                width -= left;
            }
            self.state.wm_idx += 1;
            self.state.set_wm_trigger();
            self.state.wm_left = WM_NEXT;
        }

        if width > 0 {
            let mask = bpp_mask(self.state.wm_idx);
            self.row0_seg::<F>(pos, cur, pos + width, mask);
            if WM_MAX > self.state.wm_idx {
                self.state.wm_left -= width as u32;
            }
        }
    }

    /// Every row after the first: predicted from `(left + above) / 2`, with
    /// run mode available.
    fn row_seg<F: Format>(
        &mut self,
        prev: &[u8],
        cur: &mut [u8],
        mut i: usize,
        end: usize,
    ) -> Result<(), Error> {
        let bpc_mask = bpp_mask(F::BPC);
        let wait_mask = bpp_mask(self.state.wm_idx);
        let mut run_index = 0usize;

        if i == 0 {
            F::start(cur, 0);
            for ch in 0..F::CHANNELS {
                let prev_level = self.channels[ch].correlate_row[0];
                let value = self.residual::<F>(ch, prev_level);
                self.channels[ch].correlate_row[1] = value;
                // No left neighbour: predict from the pixel above alone.
                let above = F::get(prev, 0, ch);
                F::set(
                    cur,
                    0,
                    ch,
                    (self.family.xlat_l2u[value as usize] + above) & bpc_mask,
                );
            }

            if self.state.wait_cnt > 0 {
                self.state.wait_cnt -= 1;
            } else {
                self.state.wait_cnt = self.state.tabrand() & wait_mask;
                self.update_model::<F>(0);
            }
            i += 1;
        }
        let mut stop_at = i + self.state.wait_cnt as usize;

        // The C reaches run mode with a `goto` out of two nested loops and
        // falls back in at the top; `continue 'restart` is that edge.
        'restart: loop {
            while stop_at < end {
                while i <= stop_at {
                    if run_predicted::<F>(prev, cur, i, run_index) {
                        self.state.wait_cnt = (stop_at - i) as u32;
                        run_index = i;
                        i = self.run::<F>(cur, i, end)?;
                        if i == end {
                            return Ok(());
                        }
                        stop_at = i + self.state.wait_cnt as usize;
                        continue 'restart;
                    }
                    self.pixel::<F>(prev, cur, i, bpc_mask);
                    i += 1;
                }
                self.update_model::<F>(stop_at);
                stop_at = i + (self.state.tabrand() & wait_mask) as usize;
            }

            while i < end {
                if run_predicted::<F>(prev, cur, i, run_index) {
                    self.state.wait_cnt = (stop_at - i) as u32;
                    run_index = i;
                    i = self.run::<F>(cur, i, end)?;
                    if i == end {
                        return Ok(());
                    }
                    stop_at = i + self.state.wait_cnt as usize;
                    continue 'restart;
                }
                self.pixel::<F>(prev, cur, i, bpc_mask);
                i += 1;
            }

            self.state.wait_cnt = (stop_at - end) as u32;
            return Ok(());
        }
    }

    #[inline]
    fn pixel<F: Format>(&mut self, prev: &[u8], cur: &mut [u8], i: usize, bpc_mask: u32) {
        F::start(cur, i);
        for ch in 0..F::CHANNELS {
            let prev_level = self.channels[ch].correlate_row[i];
            let value = self.residual::<F>(ch, prev_level);
            self.channels[ch].correlate_row[i + 1] = value;
            let predicted = (F::get(cur, i - 1, ch) + F::get(prev, i, ch)) >> 1;
            let v = (self.family.xlat_l2u[value as usize] + predicted) & bpc_mask;
            F::set(cur, i, ch, v);
        }
    }

    /// Run mode: copy the left neighbour for the decoded run length.
    fn run<F: Format>(&mut self, cur: &mut [u8], i: usize, end: usize) -> Result<usize, Error> {
        let run_len = self.state.decode_run(self.io) as usize;
        let remaining = end - i;
        if run_len > remaining {
            return Err(Error::BadRunLength {
                length: run_len as i64,
                remaining: remaining as i64,
            });
        }

        for at in i..i + run_len {
            F::start(cur, at);
            copy_pixel::<F>(cur, at, at - 1);
        }
        Ok(i + run_len)
    }

    /// `uncompress_row`, the wait-mask-index split for a non-first row.
    fn row<F: Format>(
        &mut self,
        prev: &[u8],
        cur: &mut [u8],
        mut width: usize,
    ) -> Result<(), Error> {
        let mut pos = 0usize;

        while WM_MAX > self.state.wm_idx && (self.state.wm_left as usize) <= width {
            let left = self.state.wm_left as usize;
            if left > 0 {
                self.row_seg::<F>(prev, cur, pos, pos + left)?;
                pos += left;
                width -= left;
            }
            self.state.wm_idx += 1;
            self.state.set_wm_trigger();
            self.state.wm_left = WM_NEXT;
        }

        if width > 0 {
            self.row_seg::<F>(prev, cur, pos, pos + width)?;
            if WM_MAX > self.state.wm_idx {
                self.state.wm_left -= width as u32;
            }
        }
        Ok(())
    }
}

/// `RLE_PRED_IMP`: enter run mode when the row above is flat here *and* the
/// two pixels already written to the left are equal.
///
/// `run_index != i` is what stops a zero-length run from being re-entered
/// forever at the same position.
#[inline]
fn run_predicted<F: Format>(prev: &[u8], cur: &[u8], i: usize, run_index: usize) -> bool {
    same_pixel::<F>(prev, i - 1, i) && run_index != i && i > 2 && same_pixel::<F>(cur, i - 1, i - 2)
}

// ---------------------------------------------------------------------------
// The decoder
// ---------------------------------------------------------------------------

/// A reusable QUIC decoder.
///
/// QUIC images are self-contained -- unlike GLZ, nothing carries from one to
/// the next -- so this type exists only to keep the model allocations around
/// between images. A fresh [`QuicDecoder::default`] decodes identically.
pub struct QuicDecoder {
    limits: Limits,
    channels: [Channel; 4],
    /// Per-channel run-mode and schedule state.
    ///
    /// Separate from [`Channel`] rather than inside it because a grey or alpha
    /// plane drives its run mode from the state belonging to the very channel
    /// it is decoding, and both have to be borrowed at once.
    states: [CommonState; 4],
    /// The state the three colour channels share.
    rgb_state: CommonState,
}

impl Default for QuicDecoder {
    fn default() -> Self {
        QuicDecoder {
            limits: Limits::default(),
            channels: [
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
            ],
            states: Default::default(),
            rgb_state: CommonState::default(),
        }
    }
}

/// Which [`CommonState`] a plane's run mode and random walk come from.
#[derive(Clone, Copy)]
enum StateOf {
    /// The state the three colour channels share.
    Rgb,
    /// The state belonging to one channel: grey, or an alpha plane.
    Channel(usize),
}

impl QuicDecoder {
    /// A new decoder with [`Limits::default`].
    pub fn new() -> Self {
        Self::default()
    }

    /// A decoder that will not allocate past `limits`.
    ///
    /// A SPICE backend should set [`Limits::max_pixels`] from the surface it
    /// is decoding into; see the type's documentation for why.
    pub fn with_limits(limits: Limits) -> Self {
        QuicDecoder {
            limits,
            ..Self::default()
        }
    }

    /// Decode a complete QUIC stream.
    ///
    /// The output is BGRA for every source type but [`QuicImageType::Gray`],
    /// which stays one byte per pixel.
    pub fn decode(&mut self, input: &[u8]) -> Result<Image, Error> {
        let mut io = BitReader::new(input).ok_or(Error::Truncated)?;

        let magic = io.read_u32();
        if magic != QUIC_MAGIC {
            return Err(Error::BadMagic {
                codec: "QUIC",
                expected: QUIC_MAGIC,
                got: magic,
            });
        }
        let version = io.read_u32();
        if version != QUIC_VERSION {
            return Err(Error::BadVersion {
                codec: "QUIC",
                expected: QUIC_VERSION,
                got: version,
            });
        }

        let image_type = QuicImageType::from_wire(io.read_u32())?;
        // The C reads these into `int` and rejects <= 0, so a header field
        // with the top bit set is a negative size there, not a huge one.
        let width = io.read_u32() as i32;
        let height = io.read_u32() as i32;
        if width <= 0 || height <= 0 {
            return Err(Error::BadSize {
                width: i64::from(width),
                height: i64::from(height),
            });
        }
        let (width, height) = (width as u32, height as u32);

        self.limits
            .check_pixels(u64::from(width) * u64::from(height))?;

        let (n_channels, bpc) = image_type.params();
        for channel in &mut self.channels[..n_channels] {
            channel.reset(width as usize, bpc);
        }
        for state in &mut self.states[..n_channels] {
            state.reset();
        }
        self.rgb_state.reset();

        let format = match image_type {
            QuicImageType::Gray => PixelFormat::Gray8,
            _ => PixelFormat::Bgra8,
        };
        let stride = width as usize * format.bytes_per_pixel();
        // Bounded by `limits.max_pixels` above, which is what stops a
        // twenty-byte header from asking for a gigabyte.
        let mut data = vec![0u8; stride * height as usize];

        match image_type {
            QuicImageType::Rgb16 => {
                self.one_plane::<Rgb16To32>(&mut io, &mut data, height, stride, 0, StateOf::Rgb)?
            }
            QuicImageType::Rgb24 | QuicImageType::Rgb32 => {
                self.one_plane::<Rgb32>(&mut io, &mut data, height, stride, 0, StateOf::Rgb)?
            }
            QuicImageType::Gray => self.one_plane::<OneByte>(
                &mut io,
                &mut data,
                height,
                stride,
                0,
                StateOf::Channel(0),
            )?,
            QuicImageType::Rgba => self.rgba(&mut io, &mut data, height, stride)?,
        }

        if io.overran() {
            return Err(Error::Truncated);
        }

        Ok(Image {
            format,
            width,
            height,
            has_alpha: image_type == QuicImageType::Rgba,
            top_down: true,
            data,
        })
    }

    /// Borrow the reader, one state and a run of channels at once.
    ///
    /// Destructuring `self` is what makes the three borrows provably
    /// disjoint; going through `self.states[i]` and `self.channels[..]`
    /// separately would not be.
    fn rows<'a, 'i>(
        &'a mut self,
        io: &'a mut BitReader<'i>,
        state_of: StateOf,
        channels: std::ops::Range<usize>,
        family: &'static Family,
    ) -> Rows<'a, 'i> {
        let QuicDecoder {
            channels: chans,
            states,
            rgb_state,
            ..
        } = self;
        let state = match state_of {
            StateOf::Rgb => rgb_state,
            StateOf::Channel(i) => &mut states[i],
        };
        Rows {
            io,
            state,
            channels: &mut chans[channels],
            family,
        }
    }

    /// Carry the last residual of the previous row into this one, which is
    /// `correlate_row[-1] = correlate_row[0]` in the C. On the first row there
    /// is nothing to carry and it starts at zero.
    fn prime<F: Format>(&mut self, first: usize, first_row: bool) {
        for ch in first..first + F::CHANNELS {
            self.channels[ch].correlate_row[0] = if first_row {
                0
            } else {
                self.channels[ch].correlate_row[1]
            };
        }
    }

    /// Decode one row of one plane. `row == 0` takes the no-row-above path.
    fn plane_row<F: Format>(
        &mut self,
        io: &mut BitReader<'_>,
        data: &mut [u8],
        row: usize,
        stride: usize,
        first: usize,
        state_of: StateOf,
    ) -> Result<(), Error> {
        let width = stride / F::PIXEL_BYTES;
        let family = if F::BPC == 5 {
            family_5bpc()
        } else {
            family_8bpc()
        };

        self.prime::<F>(first, row == 0);
        let channels = first..first + F::CHANNELS;

        if row == 0 {
            self.rows(io, state_of, channels, family)
                .row0::<F>(&mut data[..stride], width);
            Ok(())
        } else {
            let (before, cur) = data.split_at_mut(row * stride);
            let prev = &before[(row - 1) * stride..];
            let cur = &mut cur[..stride];
            self.rows(io, state_of, channels, family)
                .row::<F>(prev, cur, width)
        }
    }

    /// An image that is one plane: RGB of any depth, or grey.
    fn one_plane<F: Format>(
        &mut self,
        io: &mut BitReader<'_>,
        data: &mut [u8],
        height: u32,
        stride: usize,
        first: usize,
        state_of: StateOf,
    ) -> Result<(), Error> {
        for row in 0..height as usize {
            self.plane_row::<F>(io, data, row, stride, first, state_of)?;
        }
        Ok(())
    }

    /// RGBA: colour and alpha are two independently modelled planes whose
    /// codewords **interleave by row**, not by image. Row 0's colour is
    /// followed by row 0's alpha, then row 1's colour, and so on -- so the
    /// two passes cannot be run one after the other.
    fn rgba(
        &mut self,
        io: &mut BitReader<'_>,
        data: &mut [u8],
        height: u32,
        stride: usize,
    ) -> Result<(), Error> {
        for row in 0..height as usize {
            self.plane_row::<Rgb32>(io, data, row, stride, 0, StateOf::Rgb)?;
            self.plane_row::<AlphaPlane>(io, data, row, stride, 3, StateOf::Channel(3))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;

    /// A QUIC header, which is five little-endian words at the very start of
    /// the stream -- the encoder writes them before any codeword, so they sit
    /// on word boundaries and can be built by hand.
    fn header(image_type: u32, width: u32, height: u32) -> Vec<u8> {
        let mut out = Vec::new();
        for word in [QUIC_MAGIC, QUIC_VERSION, image_type, width, height] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }

    #[test]
    fn a_stream_without_the_magic_is_refused() {
        let mut input = header(4, 2, 2);
        input[0] ^= 0xff;
        input.resize(256, 0);
        assert!(matches!(
            QuicDecoder::new().decode(&input),
            Err(Error::BadMagic { codec: "QUIC", .. })
        ));
    }

    #[test]
    fn a_future_version_is_refused_rather_than_guessed_at() {
        let mut input = header(4, 2, 2);
        input[4..8].copy_from_slice(&1u32.to_le_bytes());
        input.resize(256, 0);
        assert!(matches!(
            QuicDecoder::new().decode(&input),
            Err(Error::BadVersion { codec: "QUIC", .. })
        ));
    }

    /// Type 0 is `QUIC_IMAGE_TYPE_INVALID`, which the C names and never
    /// emits; getting the off-by-one wrong here decodes every image as the
    /// wrong type.
    #[test]
    fn image_type_zero_and_anything_past_rgba_are_refused() {
        for bad in [0u32, 6, 7, u32::MAX] {
            let mut input = header(bad, 2, 2);
            input.resize(256, 0);
            assert!(
                matches!(
                    QuicDecoder::new().decode(&input),
                    Err(Error::BadImageType { codec: "QUIC", .. })
                ),
                "type {bad} should be refused"
            );
        }
    }

    #[test]
    fn a_zero_or_negative_dimension_is_refused() {
        for (w, h) in [(0, 4), (4, 0), (0, 0), (0x8000_0000, 4), (4, 0x8000_0000)] {
            let mut input = header(4, w, h);
            input.resize(256, 0);
            assert!(
                matches!(
                    QuicDecoder::new().decode(&input),
                    Err(Error::BadSize { .. })
                ),
                "{w}x{h} should be refused"
            );
        }
    }

    /// Two positive dimensions can still multiply out past the pixel ceiling,
    /// and the product is what drives the allocation.
    #[test]
    fn an_image_past_the_pixel_ceiling_is_refused_before_allocating() {
        let mut input = header(4, 0x7fff_ffff, 0x7fff_ffff);
        input.resize(256, 0);
        assert!(matches!(
            QuicDecoder::new().decode(&input),
            Err(Error::TooLarge { .. })
        ));
    }

    /// The input a fuzzer found in minutes: twenty-three bytes claiming
    /// 96 x 393433. Under the format's own ceiling it is legal, and decoding
    /// it costs 151 MiB and tens of millions of pixels of work before
    /// anything turns out to be wrong. The default limit is what stops it.
    #[test]
    fn a_tiny_header_cannot_ask_for_a_hundred_and_fifty_megabyte_image() {
        let mut input = header(5, 96, 393_433);
        input.extend_from_slice(&[0, 0, 0]);
        assert_eq!(
            QuicDecoder::new().decode(&input),
            Err(Error::TooLarge {
                pixels: 96 * 393_433,
                limit: Limits::DEFAULT_MAX_PIXELS,
            })
        );
    }

    /// A backend that knows its surface size should say so, and get a
    /// refusal for anything larger.
    #[test]
    fn a_caller_can_tighten_the_ceiling_to_its_surface() {
        let mut decoder = QuicDecoder::with_limits(Limits {
            max_pixels: 64,
            ..Limits::default()
        });
        let mut input = header(4, 16, 5); // 80 pixels
        input.resize(256, 0);
        assert_eq!(
            decoder.decode(&input),
            Err(Error::TooLarge {
                pixels: 80,
                limit: 64
            })
        );

        // And the same decoder still takes anything that fits.
        let mut ok = header(4, 8, 8); // 64 pixels
        ok.resize(256, 0);
        assert!(!matches!(decoder.decode(&ok), Err(Error::TooLarge { .. })));
    }

    /// No setting of the limit can lift the format's own ceiling.
    #[test]
    fn the_format_ceiling_cannot_be_raised_past() {
        let mut decoder = QuicDecoder::with_limits(Limits {
            max_pixels: u64::MAX,
            ..Limits::default()
        });
        let mut input = header(4, 0x7fff_ffff, 0x7fff_ffff);
        input.resize(256, 0);
        assert_eq!(
            decoder.decode(&input),
            Err(Error::TooLarge {
                pixels: 0x7fff_ffffu64 * 0x7fff_ffffu64,
                limit: crate::MAX_IMAGE_PIXELS,
            })
        );
    }

    #[test]
    fn a_header_with_no_body_is_truncated_not_a_panic() {
        let input = header(4, 8, 8);
        assert_eq!(QuicDecoder::new().decode(&input), Err(Error::Truncated));
    }

    #[test]
    fn an_empty_input_is_refused() {
        assert_eq!(QuicDecoder::new().decode(&[]), Err(Error::Truncated));
        assert_eq!(QuicDecoder::new().decode(&[1, 2, 3]), Err(Error::Truncated));
    }

    /// The decoder must be total. The bitstream can ask for any residual, any
    /// run length and any model state, and none of that may escape the buffer
    /// the header sized -- so a valid header followed by arbitrary bytes has
    /// to come back as pixels or as an error, never as a panic.
    #[test]
    fn a_valid_header_followed_by_garbage_never_panics() {
        let mut state = 0x9e37_79b9u32;
        let mut decoder = QuicDecoder::new();

        for image_type in 1..=5u32 {
            for trial in 0..64 {
                let mut input = header(image_type, 7 + trial % 11, 3 + trial % 5);
                for _ in 0..600 {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    input.extend_from_slice(&state.to_le_bytes());
                }
                // Whatever comes back, it must come back.
                let _ = decoder.decode(&input);
            }
        }
    }

    /// Reusing a decoder must not carry model state between images, or the
    /// second image of a session decodes differently from the first.
    #[test]
    fn a_reused_decoder_decodes_an_image_the_same_way_twice() {
        let mut input = header(4, 9, 4);
        let mut state = 0x1234_5678u32;
        for _ in 0..400 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            input.extend_from_slice(&state.to_le_bytes());
        }

        let mut shared = QuicDecoder::new();
        let first = shared.decode(&input);
        let second = shared.decode(&input);
        let fresh = QuicDecoder::new().decode(&input);

        assert_eq!(first, second, "the model leaked between images");
        assert_eq!(first, fresh, "a reused decoder differs from a fresh one");
    }

    /// `ceil_log_2` in the C returns 0 for 1, not 1, and the escape codeword
    /// length is built on it.
    #[test]
    fn ceil_log2_matches_the_c_including_the_value_one() {
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(2), 1);
        assert_eq!(ceil_log2(3), 2);
        assert_eq!(ceil_log2(4), 2);
        assert_eq!(ceil_log2(255), 8);
        assert_eq!(ceil_log2(256), 8);
        assert_eq!(ceil_log2(257), 9);
    }

    /// Every codeword the families can produce has to fit the bit reader's
    /// `1..=31` contract, or a hostile stream reaches a shift of 32.
    #[test]
    fn no_codeword_length_can_reach_the_shift_limit() {
        for family in [family_8bpc(), family_5bpc()] {
            for l in 0..8u32 {
                if family.not_gr_cw_len[l as usize] == 0 {
                    continue; // code number past this family's depth
                }
                for bits in [0u32, 1, 0x8000_0000, 0xffff_ffff, 0x0001_0000, 0x7fff_ffff] {
                    let (_, len) = family.decode(l, bits);
                    assert!(
                        (1..32).contains(&len),
                        "code {l} on {bits:#010x} gave length {len}"
                    );
                }
            }
        }
    }

    /// The bucket table has to cover every level exactly once, or a residual
    /// selects a bucket that was never initialised.
    #[test]
    fn every_residual_level_maps_to_a_bucket() {
        for bpc in [5u32, 8] {
            let mut of_level = Vec::new();
            let mut buckets = Vec::new();
            build_buckets(1 << bpc, &mut of_level, &mut buckets);

            assert_eq!(of_level.len(), 1 << bpc);
            assert!(of_level.iter().all(|&b| (b as usize) < buckets.len()));
            // Buckets are assigned in order and all of them are used.
            assert_eq!(of_level[0], 0);
            assert_eq!(
                *of_level.last().unwrap() as usize,
                buckets.len() - 1,
                "the last bucket must swallow the tail"
            );
            assert!(of_level.windows(2).all(|w| w[1] >= w[0]), "not monotonic");
        }
    }
}
