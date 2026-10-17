//! The Opus multistream layouts: what DESCRIBE offers, and what the client
//! will decode with once ANNOUNCE has picked one.
//!
//! The client builds its decoder from the host's DESCRIBE, not from anything
//! it negotiates (`RtspConnection.c`, `parseOpusConfigurations`):
//!
//! - **Stereo** is hard-coded: one coupled stream, mapping `0 1`. The
//!   `surround-params` lines are not read at all.
//! - **5.1 and 7.1** come from the first `a=fmtp:97 surround-params=<n>...`
//!   line for that channel count (normal quality) and the second (high
//!   quality). The value is `<channels><streams><coupled><mapping...>`, one
//!   decimal digit each.
//! - **Normal quality is rotated.** GFE advertised its normal-quality mapping
//!   in a different channel order from the one Moonlight decodes to, so the
//!   client moves the last entry to index 3 and slides 3.. up by one. A host
//!   that wants the client to end up with mapping `M` must therefore advertise
//!   `M` rotated the other way. Sunshine does the same (`rtsp.cpp`,
//!   `cmd_describe`).
//! - **High quality is chosen by the client**, by sending
//!   `x-nv-audio.surround.AudioQuality:1`. It only does so when DESCRIBE
//!   offered a second line, and from then on decodes with that second layout:
//!   one uncoupled stream per channel.
//!
//! Without a line for its channel count a 5.1 client falls back to a
//! hard-coded layout, and a 7.1 client fails the connection outright. So
//! DESCRIBE advertises all six layouts, whatever the backend can produce: a
//! stereo source is upmixed into a surround layout rather than refused.
//!
//! Every layout here leaves the client with the **identity** mapping, so
//! encoder input channel `j` is the client's output channel `j`, in the order
//! Moonlight renders: FL FR C LFE RL RR SL SR.

use crate::rtsp::sdp::StreamConfig;

/// One multistream layout, as the client's decoder will be configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpusLayout {
    /// Output channels, in Moonlight's order: FL FR C LFE RL RR SL SR.
    pub channels: u8,
    /// Elementary Opus streams in each packet.
    pub streams: u8,
    /// How many of those are coupled (two channels each). They come first.
    pub coupled_streams: u8,
    /// `mapping[j]` is the decoded channel that output channel `j` is taken
    /// from, as `opus_multistream_decoder_create` reads it. Only the first
    /// `channels` entries are meaningful.
    pub mapping: [u8; 8],
    /// Total bitrate, bits per second. Sunshine's figures (`audio.cpp`,
    /// `stream_configs`), so a client sees the bandwidth it would from a
    /// Sunshine host.
    pub bitrate: u32,
}

const IDENTITY: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

impl OpusLayout {
    /// Stereo: what every client decodes unless it asked for surround.
    pub const STEREO: OpusLayout = OpusLayout {
        channels: 2,
        streams: 1,
        coupled_streams: 1,
        mapping: IDENTITY,
        bitrate: 96_000,
    };
    /// Stereo when the client signalled high quality. The same layout, at a
    /// higher bitrate: stereo's layout is fixed in the client.
    pub const HIGH_STEREO: OpusLayout = OpusLayout {
        bitrate: 512_000,
        ..OpusLayout::STEREO
    };
    /// 5.1: FL+FR and C+LFE as coupled streams, RL and RR mono. The pairing
    /// is what the identity mapping implies, and what Sunshine's 5.1 line
    /// also leaves the client with.
    pub const SURROUND_51: OpusLayout = OpusLayout {
        channels: 6,
        streams: 4,
        coupled_streams: 2,
        mapping: IDENTITY,
        bitrate: 256_000,
    };
    /// 5.1, one stream per channel.
    pub const HIGH_SURROUND_51: OpusLayout = OpusLayout {
        channels: 6,
        streams: 6,
        coupled_streams: 0,
        mapping: IDENTITY,
        bitrate: 1_536_000,
    };
    /// 7.1: FL+FR, C+LFE and RL+RR coupled, SL and SR mono.
    pub const SURROUND_71: OpusLayout = OpusLayout {
        channels: 8,
        streams: 5,
        coupled_streams: 3,
        mapping: IDENTITY,
        bitrate: 450_000,
    };
    /// 7.1, one stream per channel.
    pub const HIGH_SURROUND_71: OpusLayout = OpusLayout {
        channels: 8,
        streams: 8,
        coupled_streams: 0,
        mapping: IDENTITY,
        bitrate: 2_048_000,
    };

    /// Every layout DESCRIBE offers, in the order it offers them. For each
    /// surround channel count the normal-quality line must come first: the
    /// client takes the first match as normal and the second as high.
    pub const ADVERTISED: [OpusLayout; 6] = [
        OpusLayout::STEREO,
        OpusLayout::HIGH_STEREO,
        OpusLayout::SURROUND_51,
        OpusLayout::HIGH_SURROUND_51,
        OpusLayout::SURROUND_71,
        OpusLayout::HIGH_SURROUND_71,
    ];

    /// The layout the client will decode this session with.
    ///
    /// A channel count other than 2, 6 or 8 cannot come from Moonlight,
    /// which offers only those three, and the client would have failed on
    /// DESCRIBE before asking. It is answered with stereo.
    pub fn negotiated(config: &StreamConfig) -> OpusLayout {
        let high = config.audio_high_quality;
        match (config.audio_channels, high) {
            (6, false) => OpusLayout::SURROUND_51,
            (6, true) => OpusLayout::HIGH_SURROUND_51,
            (8, false) => OpusLayout::SURROUND_71,
            (8, true) => OpusLayout::HIGH_SURROUND_71,
            (_, false) => OpusLayout::STEREO,
            (_, true) => OpusLayout::HIGH_STEREO,
        }
    }

    /// The meaningful part of [`mapping`](Self::mapping).
    pub fn mapping(&self) -> &[u8] {
        &self.mapping[..self.channels as usize]
    }

    /// Whether this is one of the high-quality layouts, which the client
    /// reads from the *second* `surround-params` line for its channel count.
    fn is_high_quality(&self) -> bool {
        self.channels > 2 && self.coupled_streams == 0
    }

    /// The `surround-params` value that leaves the client decoding with
    /// exactly this layout.
    pub fn surround_params(&self) -> String {
        let n = self.channels as usize;
        let mut advertised = self.mapping;
        if n > 2 && !self.is_high_quality() {
            // Undo the client's rotation: it will set `m[3] = a[n-1]` and
            // `m[4..n] = a[3..n-1]`, so advertise `a[3..n-1] = m[4..n]` and
            // `a[n-1] = m[3]`.
            advertised[3..n - 1].copy_from_slice(&self.mapping[4..n]);
            advertised[n - 1] = self.mapping[3];
        }
        let mut s = format!("{}{}{}", self.channels, self.streams, self.coupled_streams);
        for m in &advertised[..n] {
            s.push(char::from(b'0' + m));
        }
        s
    }
}

/// The `a=fmtp:97 surround-params=` lines for DESCRIBE, CRLF-terminated.
pub fn describe_lines() -> String {
    OpusLayout::ADVERTISED
        .iter()
        .map(|layout| format!("a=fmtp:97 surround-params={}\r\n", layout.surround_params()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client's parser, transcribed from `RtspConnection.c`
    /// (`parseOpusConfigurations` and `parseOpusConfigFromParamString`), so the
    /// layouts are checked against what it does rather than what this module
    /// intends. Returns (normal, high), the second only where offered.
    fn client_parse(payload: &str, channels: u8) -> (OpusLayout, Option<OpusLayout>) {
        if channels == 2 {
            return (OpusLayout::STEREO, None);
        }
        let prefix = format!("a=fmtp:97 surround-params={channels}");
        let parse = |at: &str| -> OpusLayout {
            let d: Vec<u8> = at.bytes().map(|b| b.wrapping_sub(b'0')).collect();
            assert!(d[..2 + channels as usize].iter().all(|&x| x <= 9));
            let mut mapping = [0u8; 8];
            mapping[..channels as usize].copy_from_slice(&d[2..2 + channels as usize]);
            OpusLayout {
                channels,
                streams: d[0],
                coupled_streams: d[1],
                mapping,
                bitrate: 0,
            }
        };
        let first = payload
            .find(&prefix)
            .expect("no surround-params for this count");
        let rest = &payload[first + prefix.len()..];
        let mut normal = parse(rest);
        // "GFE's normal-quality channel mapping differs from the one our
        // clients use" -- the rotation.
        let original = normal.mapping;
        let n = channels as usize;
        normal.mapping[3] = original[n - 1];
        normal.mapping[4..n].copy_from_slice(&original[3..n - 1]);
        let high = rest.find(&prefix).map(|i| parse(&rest[i + prefix.len()..]));
        (normal, high)
    }

    fn same_decoder(a: &OpusLayout, b: &OpusLayout) -> bool {
        (a.channels, a.streams, a.coupled_streams, a.mapping())
            == (b.channels, b.streams, b.coupled_streams, b.mapping())
    }

    #[test]
    fn the_client_decodes_every_layout_with_the_identity_mapping() {
        let payload = describe_lines();
        for (channels, normal, high) in [
            (6, OpusLayout::SURROUND_51, OpusLayout::HIGH_SURROUND_51),
            (8, OpusLayout::SURROUND_71, OpusLayout::HIGH_SURROUND_71),
        ] {
            let (parsed_normal, parsed_high) = client_parse(&payload, channels);
            assert!(same_decoder(&parsed_normal, &normal), "{parsed_normal:?}");
            let parsed_high = parsed_high.expect("high quality must be offered");
            assert!(same_decoder(&parsed_high, &high), "{parsed_high:?}");
            assert_eq!(parsed_normal.mapping(), &IDENTITY[..channels as usize]);
            assert_eq!(parsed_high.mapping(), &IDENTITY[..channels as usize]);
        }
    }

    /// Sunshine's 5.1 line, as a cross-check that the rotation is the right
    /// way round: `rtsp.cpp` rotates `012345` left from index 3.
    #[test]
    fn the_51_line_matches_sunshines() {
        assert_eq!(OpusLayout::SURROUND_51.surround_params(), "642012453");
        assert_eq!(OpusLayout::HIGH_SURROUND_51.surround_params(), "660012345");
        assert_eq!(OpusLayout::STEREO.surround_params(), "21101");
    }

    #[test]
    fn every_layout_is_one_a_multistream_decoder_accepts() {
        for layout in OpusLayout::ADVERTISED {
            let decoded = layout.streams + layout.coupled_streams;
            assert!(layout.streams >= 1 && layout.coupled_streams <= layout.streams);
            assert!(decoded <= layout.channels);
            assert!(layout.mapping().iter().all(|&m| m < decoded));
            // Each value is one digit on the wire.
            assert!(layout.channels <= 9 && layout.streams <= 9);
        }
    }

    fn config(channels: u32, high: bool) -> StreamConfig {
        let mut attrs = format!(
            "a=x-nv-audio.surround.numChannels:{channels}\r\n\
             a=x-ss-general.encryptionEnabled:0\r\n"
        );
        if channels > 2 {
            attrs.push_str(&format!(
                "a=x-nv-audio.surround.AudioQuality:{}\r\n",
                u8::from(high)
            ));
        }
        let host = if high && channels == 2 {
            "10.0.0.1"
        } else {
            "0.0.0.0"
        };
        crate::rtsp::sdp::parse_announce(attrs.as_bytes(), Some(host), &Default::default(), 0)
            .unwrap()
    }

    #[test]
    fn the_negotiated_layout_follows_the_channel_count_and_quality() {
        assert_eq!(
            OpusLayout::negotiated(&config(2, false)),
            OpusLayout::STEREO
        );
        assert_eq!(
            OpusLayout::negotiated(&config(2, true)),
            OpusLayout::HIGH_STEREO
        );
        assert_eq!(
            OpusLayout::negotiated(&config(6, false)),
            OpusLayout::SURROUND_51
        );
        assert_eq!(
            OpusLayout::negotiated(&config(6, true)),
            OpusLayout::HIGH_SURROUND_51
        );
        assert_eq!(
            OpusLayout::negotiated(&config(8, false)),
            OpusLayout::SURROUND_71
        );
        assert_eq!(
            OpusLayout::negotiated(&config(8, true)),
            OpusLayout::HIGH_SURROUND_71
        );
        assert_eq!(
            OpusLayout::negotiated(&config(4, false)),
            OpusLayout::STEREO
        );
    }
}
