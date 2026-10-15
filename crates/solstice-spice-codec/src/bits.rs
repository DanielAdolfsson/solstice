//! The QUIC bitstream reader.
//!
//! QUIC's codewords are variable length and read MSB-first, but the stream is
//! a sequence of **little-endian 32-bit words**, not a byte stream. The reader
//! keeps a 32-bit window plus the word after it, which is what lets
//! `golomb_decoding` look at 32 bits at once and only then say how many of
//! them it used. Ported from `decode_eatbits` and friends in `common/quic.c`.

/// A 32-bit sliding window over a little-endian word stream.
pub(crate) struct BitReader<'a> {
    words: &'a [u8],
    /// Index of the next *word* to load, not the next byte.
    pos: usize,
    /// The 32 bits the decoder is currently looking at, MSB first.
    word: u32,
    /// The word after the window, partly merged into `word`.
    next_word: u32,
    /// How many bits of `next_word` have not been merged into `word` yet.
    ///
    /// Always in `0..=31`; see the shift-safety argument in [`BitReader::eat`].
    available_bits: u32,
    /// Latched once a read ran past the end of the input.
    ///
    /// QUIC's writes are addressed by the header's width and height rather
    /// than by the bitstream, so reading zeroes past the end is harmless --
    /// it produces wrong pixels, not a wrong pointer. Decoding therefore runs
    /// to completion and the caller turns this flag into an error afterwards,
    /// which keeps the per-pixel path free of error handling.
    overrun: bool,
}

impl<'a> BitReader<'a> {
    /// Start reading `input`, whose length is rounded down to a whole number
    /// of words exactly as `quic_decode_begin` does.
    ///
    /// Returns `None` for an input with no complete word in it, the case
    /// `quic_decode_begin` rejects as `!num_io_words`.
    pub(crate) fn new(input: &'a [u8]) -> Option<Self> {
        let n_words = input.len() / 4;
        if n_words == 0 {
            return None;
        }
        let mut reader = BitReader {
            words: &input[..n_words * 4],
            pos: 0,
            word: 0,
            next_word: 0,
            available_bits: 0,
            overrun: false,
        };
        // init_decode_io: the first word lands in both halves of the window.
        let first = reader.load();
        reader.word = first;
        reader.next_word = first;
        Some(reader)
    }

    /// The next word, or zero past the end with the overrun latched.
    fn load(&mut self) -> u32 {
        let at = self.pos * 4;
        match self.words.get(at..at + 4) {
            Some(b) => {
                self.pos += 1;
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            }
            None => {
                self.overrun = true;
                0
            }
        }
    }

    /// The 32 bits under the cursor, MSB first.
    #[inline]
    pub(crate) fn peek(&self) -> u32 {
        self.word
    }

    /// Advance by `len` bits, `1 <= len <= 31`.
    ///
    /// Every shift here is by `available_bits`, by `len`, or by `32 - delta`.
    /// `available_bits` stays in `0..=31` because the first branch leaves it
    /// at `available_bits - len <= 31 - 1` and the second at `32 - delta`
    /// where `delta = len - available_bits` is in `1..=31`. With `len` bounded
    /// by the caller, no shift can reach 32.
    #[inline]
    pub(crate) fn eat(&mut self, len: u32) {
        debug_assert!(len > 0 && len < 32, "codeword length {len} out of range");
        // A caller that violated the bound would otherwise shift by >= 32,
        // which panics in debug and silently masks in release. Neither is a
        // useful failure, and the stream is already unrecoverable by then.
        if len == 0 || len >= 32 {
            self.overrun = true;
            return;
        }

        self.word <<= len;

        if let Some(remaining) = self.available_bits.checked_sub(len) {
            self.available_bits = remaining;
            self.word |= self.next_word >> remaining;
            return;
        }

        let delta = len - self.available_bits;
        self.word |= self.next_word << delta;
        self.next_word = self.load();
        self.available_bits = 32 - delta;
        self.word |= self.next_word >> self.available_bits;
    }

    /// Read a whole 32-bit header field, as `decode_eat32bits` does.
    ///
    /// The window is only 32 bits wide, so this is two 16-bit steps: the value
    /// has to be taken before the first step, not after the second.
    #[inline]
    pub(crate) fn read_u32(&mut self) -> u32 {
        let value = self.word;
        self.eat(16);
        self.eat(16);
        value
    }

    /// Whether any read has run past the end of the input.
    pub(crate) fn overran(&self) -> bool {
        self.overrun
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reader must reproduce the bit order the C encoder writes: words are
    /// little-endian, bits within the window are MSB first.
    #[test]
    fn bits_come_out_most_significant_first_within_a_little_endian_word() {
        // One word, 0xdeadbeef, written little-endian.
        let input = 0xdead_beef_u32.to_le_bytes();
        let mut r = BitReader::new(&input).unwrap();
        assert_eq!(r.peek(), 0xdead_beef);
        r.eat(4);
        assert_eq!(r.peek() >> 28, 0xe); // second nibble of 0xdeadbeef
    }

    /// `read_u32` takes the value from before the window moves, which is how
    /// the five header fields come out in order.
    #[test]
    fn consecutive_header_words_read_back_in_order() {
        let mut input = Vec::new();
        for w in [1u32, 2, 3, 4, 5, 0, 0] {
            input.extend_from_slice(&w.to_le_bytes());
        }
        let mut r = BitReader::new(&input).unwrap();
        assert_eq!([r.read_u32(), r.read_u32(), r.read_u32()], [1, 2, 3]);
        assert!(!r.overran());
    }

    /// Past the end the reader yields zeroes and latches, rather than
    /// panicking or wrapping round to the start of the buffer.
    #[test]
    fn reading_past_the_end_yields_zeroes_and_latches_the_overrun() {
        let input = 0xffff_ffff_u32.to_le_bytes();
        let mut r = BitReader::new(&input).unwrap();
        assert!(!r.overran());
        for _ in 0..8 {
            r.eat(16);
        }
        assert!(r.overran());
        assert_eq!(r.peek(), 0);
    }

    /// An input too short to hold one word is the `!num_io_words` rejection.
    #[test]
    fn an_input_shorter_than_one_word_is_refused() {
        assert!(BitReader::new(&[]).is_none());
        assert!(BitReader::new(&[1, 2, 3]).is_none());
        assert!(BitReader::new(&[1, 2, 3, 4]).is_some());
    }

    /// Trailing bytes that do not complete a word are dropped, as
    /// `num_io_bytes / 4` does in the C.
    #[test]
    fn a_partial_trailing_word_is_ignored() {
        let input = [0xef, 0xbe, 0xad, 0xde, 0x99, 0x99];
        let mut r = BitReader::new(&input).unwrap();
        assert_eq!(r.peek(), 0xdead_beef);
        r.eat(31);
        r.eat(31);
        assert!(r.overran(), "the stray two bytes must not become a word");
    }
}
