//! The ANNOUNCE attribute soup, and the DESCRIBE body.
//!
//! ANNOUNCE is where the client states what it wants
//! (`docs/moonlight-sunshine-protocol.md` §4.2). Everything in it is
//! attacker-influenced once a client is paired, so every value is parsed into a
//! typed field with a default and then **clamped against configured ceilings**
//! -- an authenticated client that asks for 4K120 must not be able to pin a CPU
//! (`docs/security.md` §5.3).

use std::collections::BTreeMap;

/// `SS_ENC_*` (`Limelight-internal.h:48-50`).
pub mod encryption {
    #![allow(missing_docs)]
    pub const CONTROL_V2: u32 = 0x01;
    pub const VIDEO: u32 = 0x02;
    pub const AUDIO: u32 = 0x04;
    /// What Solstice asks for by default: the stream is someone's screen, not a
    /// game (`docs/security.md` §2.2).
    pub const ALL: u32 = CONTROL_V2 | VIDEO | AUDIO;
}

/// `x-nv-vqos[0].bitStreamFormat`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitstreamFormat {
    /// H.264.
    H264,
    /// HEVC.
    Hevc,
    /// AV1.
    Av1,
}

impl BitstreamFormat {
    fn from_wire(v: u32) -> Option<Self> {
        Some(match v {
            0 => BitstreamFormat::H264,
            1 => BitstreamFormat::Hevc,
            2 => BitstreamFormat::Av1,
            _ => return None,
        })
    }
}

/// The server-side ceilings an ANNOUNCE is clamped to.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum width.
    pub max_width: u32,
    /// Maximum height.
    pub max_height: u32,
    /// Maximum framerate.
    pub max_fps: u32,
    /// Maximum bitrate.
    pub max_bitrate_kbps: u32,
    /// Maximum UDP payload the packetiser will produce.
    pub max_packet_size: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_width: 1920,
            max_height: 1080,
            max_fps: 60,
            max_bitrate_kbps: 20_000,
            max_packet_size: 1392,
        }
    }
}

/// What the client asked for, after parsing and clamping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamConfig {
    /// Client display name, from the SDP `s=` line.
    pub client_name: String,
    /// Requested width.
    pub width: u32,
    /// Requested height.
    pub height: u32,
    /// Requested framerate.
    pub fps: u32,
    /// Maximum UDP payload, which drives the shard size.
    pub packet_size: u32,
    /// Slices per frame the encoder should produce.
    pub slices_per_frame: u32,
    /// Reference frames the decoder will hold.
    pub max_reference_frames: u32,
    /// Codec.
    pub bitstream_format: BitstreamFormat,
    /// Target bitrate.
    pub bitrate_kbps: u32,
    /// `fec.minRequiredFecPackets`.
    pub min_required_fec_packets: u32,
    /// HDR request; Solstice does not offer it, so this is only recorded.
    pub dynamic_range_mode: u32,
    /// 0 = 4:2:0, 1 = 4:4:4.
    pub chroma_sampling_type: u32,
    /// Audio channel count.
    pub audio_channels: u32,
    /// Audio channel mask.
    pub audio_channel_mask: u32,
    /// Opus packet duration in milliseconds.
    pub audio_packet_duration: u32,
    /// Whether the client asked for high-quality stereo. See the `Host:`
    /// header quirk in [`parse_announce`].
    pub audio_high_quality: bool,
    /// `x-nv-general.useReliableUdp`: 13 means the control stream is encrypted.
    pub use_reliable_udp: u32,
    /// `SS_ENC_*` bitmask the client agreed to.
    pub encryption_enabled: u32,
    /// Everything parsed, for logging and for attributes we do not model.
    pub attributes: BTreeMap<String, String>,
}

impl StreamConfig {
    /// Whether the control stream must be AES-GCM wrapped.
    pub fn control_encrypted(&self) -> bool {
        self.use_reliable_udp == 13
    }

    /// Whether video shards must be encrypted.
    pub fn video_encrypted(&self) -> bool {
        self.encryption_enabled & encryption::VIDEO != 0
    }

    /// Whether audio packets must be encrypted.
    pub fn audio_encrypted(&self) -> bool {
        self.encryption_enabled & encryption::AUDIO != 0
    }
}

/// Why an ANNOUNCE was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SdpError {
    /// The body was not UTF-8.
    #[error("ANNOUNCE body is not UTF-8")]
    NotUtf8,
    /// A numeric attribute did not parse.
    #[error("attribute {0} is not a number")]
    NotANumber(String),
    /// The client asked for a codec Solstice does not serve.
    #[error("unsupported bitstream format {0}")]
    UnsupportedCodec(u32),
    /// The client would not negotiate the encryption the host requires.
    #[error("client refused required encryption: offered {offered:#x}, require {required:#x}")]
    EncryptionRefused {
        /// What the client agreed to.
        offered: u32,
        /// What the host insists on.
        required: u32,
    },
    /// A dimension or rate was zero or absurd.
    #[error("invalid geometry {width}x{height}@{fps}")]
    InvalidGeometry {
        /// Requested width.
        width: u32,
        /// Requested height.
        height: u32,
        /// Requested framerate.
        fps: u32,
    },
}

/// Parse the attribute lines out of an SDP body.
pub fn parse_attributes(body: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in body.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("a=") {
            if let Some((name, value)) = rest.split_once(':') {
                out.insert(name.trim().to_owned(), value.trim().to_owned());
            } else {
                out.insert(rest.trim().to_owned(), String::new());
            }
        }
    }
    out
}

fn session_name(body: &str) -> String {
    body.lines()
        .find_map(|l| l.trim_end_matches('\r').strip_prefix("s="))
        .unwrap_or("")
        .trim()
        .to_owned()
}

fn number(attrs: &BTreeMap<String, String>, key: &str, default: u32) -> Result<u32, SdpError> {
    match attrs.get(key) {
        None => Ok(default),
        Some(v) if v.is_empty() => Ok(default),
        Some(v) => v
            .trim()
            .parse()
            .map_err(|_| SdpError::NotANumber(key.to_owned())),
    }
}

/// Parse an ANNOUNCE body into a clamped [`StreamConfig`].
///
/// `host_header` is the RTSP `Host:` header, which carries the stereo audio
/// quality flag: "high quality" is signalled by whether it is `0.0.0.0` (low)
/// or a real address (high) (`rtsp.cpp:1163-1172`). Genuinely.
///
/// `required_encryption` is refused outright rather than silently downgraded.
pub fn parse_announce(
    body: &[u8],
    host_header: Option<&str>,
    limits: &Limits,
    required_encryption: u32,
) -> Result<StreamConfig, SdpError> {
    let text = std::str::from_utf8(body).map_err(|_| SdpError::NotUtf8)?;
    let attrs = parse_attributes(text);

    let width = number(&attrs, "x-nv-video[0].clientViewportWd", 1280)?;
    let height = number(&attrs, "x-nv-video[0].clientViewportHt", 720)?;
    let fps = number(&attrs, "x-nv-video[0].maxFPS", 60)?;
    if width == 0 || height == 0 || fps == 0 {
        return Err(SdpError::InvalidGeometry { width, height, fps });
    }

    let format_raw = number(&attrs, "x-nv-vqos[0].bitStreamFormat", 0)?;
    let bitstream_format =
        BitstreamFormat::from_wire(format_raw).ok_or(SdpError::UnsupportedCodec(format_raw))?;
    if bitstream_format != BitstreamFormat::H264 {
        return Err(SdpError::UnsupportedCodec(format_raw));
    }

    let encryption_enabled = number(&attrs, "x-ss-general.encryptionEnabled", 0)?;
    if encryption_enabled & required_encryption != required_encryption {
        return Err(SdpError::EncryptionRefused {
            offered: encryption_enabled,
            required: required_encryption,
        });
    }

    let packet_size =
        number(&attrs, "x-nv-video[0].packetSize", 1024)?.clamp(256, limits.max_packet_size);
    let audio_channels = number(&attrs, "x-nv-audio.surround.numChannels", 2)?.clamp(1, 8);

    Ok(StreamConfig {
        client_name: session_name(text),
        width: width.min(limits.max_width),
        height: height.min(limits.max_height),
        fps: fps.clamp(1, limits.max_fps),
        packet_size,
        slices_per_frame: number(&attrs, "x-nv-video[0].videoEncoderSlicesPerFrame", 1)?
            .clamp(1, 32),
        max_reference_frames: number(&attrs, "x-nv-video[0].maxNumReferenceFrames", 1)?
            .clamp(1, 16),
        bitstream_format,
        bitrate_kbps: number(&attrs, "x-nv-vqos[0].bw.maximumBitrateKbps", 10_000)?
            .clamp(500, limits.max_bitrate_kbps),
        min_required_fec_packets: number(&attrs, "x-nv-vqos[0].fec.minRequiredFecPackets", 0)?
            .min(16),
        dynamic_range_mode: number(&attrs, "x-nv-video[0].dynamicRangeMode", 0)?,
        chroma_sampling_type: number(&attrs, "x-ss-video[0].chromaSamplingType", 0)?,
        audio_channels,
        audio_channel_mask: number(&attrs, "x-nv-audio.surround.channelMask", 3)?,
        audio_packet_duration: number(&attrs, "x-nv-aqos.packetDuration", 5)?.clamp(1, 60),
        audio_high_quality: host_header.is_some_and(|h| !h.starts_with("0.0.0.0")),
        use_reliable_udp: number(&attrs, "x-nv-general.useReliableUdp", 1)?,
        encryption_enabled,
        attributes: attrs,
    })
}

/// Build the DESCRIBE body.
///
/// Advertising H.264 only is deliberate: the client treats the *absence* of
/// `sprop-parameter-sets=AAAAAU` as "no HEVC" and the absence of
/// `a=rtpmap:98 AV1/90000` as "no AV1", so a desktop bridge says nothing about
/// either (`docs/moonlight-sunshine-protocol.md` §2.2).
pub fn describe_body(supported_encryption: u32, requested_encryption: u32) -> String {
    let mut sdp = String::new();
    sdp.push_str("a=fmtp:97 surround-params=NONE\r\n");
    sdp.push_str(&format!(
        "a=x-ss-general.encryptionSupported:{supported_encryption}\r\n"
    ));
    sdp.push_str(&format!(
        "a=x-ss-general.encryptionRequested:{requested_encryption}\r\n"
    ));
    sdp
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic ANNOUNCE, in the shape moonlight-qt sends.
    fn announce(extra: &str) -> Vec<u8> {
        let mut s = String::from(
            "v=0\r\n\
             o=android 0 14 IN IPv4 0.0.0.0\r\n\
             s=NVIDIA Streaming Client\r\n\
             a=x-nv-video[0].clientViewportWd:1920\r\n\
             a=x-nv-video[0].clientViewportHt:1080\r\n\
             a=x-nv-video[0].maxFPS:60\r\n\
             a=x-nv-video[0].packetSize:1392\r\n\
             a=x-nv-video[0].videoEncoderSlicesPerFrame:1\r\n\
             a=x-nv-video[0].maxNumReferenceFrames:1\r\n\
             a=x-nv-vqos[0].bitStreamFormat:0\r\n\
             a=x-nv-vqos[0].bw.maximumBitrateKbps:20000\r\n\
             a=x-nv-vqos[0].fec.minRequiredFecPackets:2\r\n\
             a=x-nv-audio.surround.numChannels:2\r\n\
             a=x-nv-audio.surround.channelMask:3\r\n\
             a=x-nv-aqos.packetDuration:5\r\n\
             a=x-nv-general.useReliableUdp:13\r\n\
             a=x-ss-general.encryptionEnabled:7\r\n",
        );
        s.push_str(extra);
        s.into_bytes()
    }

    #[test]
    fn parses_a_realistic_announce() {
        let cfg = parse_announce(
            &announce(""),
            Some("10.0.0.5"),
            &Limits::default(),
            encryption::ALL,
        )
        .unwrap();
        assert_eq!(cfg.client_name, "NVIDIA Streaming Client");
        assert_eq!((cfg.width, cfg.height, cfg.fps), (1920, 1080, 60));
        assert_eq!(cfg.packet_size, 1392);
        assert_eq!(cfg.bitrate_kbps, 20_000);
        assert_eq!(cfg.min_required_fec_packets, 2);
        assert!(cfg.control_encrypted());
        assert!(cfg.video_encrypted());
        assert!(cfg.audio_encrypted());
        assert!(cfg.audio_high_quality);
    }

    /// The documented `Host: 0.0.0.0` quirk.
    #[test]
    fn stereo_quality_comes_from_the_host_header() {
        let low = parse_announce(
            &announce(""),
            Some("0.0.0.0"),
            &Limits::default(),
            encryption::ALL,
        )
        .unwrap();
        assert!(!low.audio_high_quality);
        let none =
            parse_announce(&announce(""), None, &Limits::default(), encryption::ALL).unwrap();
        assert!(!none.audio_high_quality);
    }

    #[test]
    fn missing_attributes_take_their_documented_defaults() {
        let body = b"v=0\r\ns=client\r\na=x-ss-general.encryptionEnabled:7\r\n";
        let cfg = parse_announce(body, None, &Limits::default(), encryption::ALL).unwrap();
        assert_eq!((cfg.width, cfg.height, cfg.fps), (1280, 720, 60));
        assert_eq!(cfg.audio_packet_duration, 5);
        assert_eq!(cfg.dynamic_range_mode, 0);
        assert_eq!(cfg.chroma_sampling_type, 0);
        assert_eq!(cfg.use_reliable_udp, 1);
    }

    /// An authenticated client must not be able to request 4K120 and pin a CPU.
    #[test]
    fn absurd_requests_are_clamped_to_the_configured_ceilings() {
        let body = announce("a=x-nv-video[0].videoEncoderSlicesPerFrame:9999\r\n");
        let body = String::from_utf8(body)
            .unwrap()
            .replace("clientViewportWd:1920", "clientViewportWd:3840")
            .replace("clientViewportHt:1080", "clientViewportHt:2160")
            .replace("maxFPS:60", "maxFPS:240")
            .replace("maximumBitrateKbps:20000", "maximumBitrateKbps:500000")
            .replace("packetSize:1392", "packetSize:65000");
        let cfg =
            parse_announce(body.as_bytes(), None, &Limits::default(), encryption::ALL).unwrap();
        assert_eq!((cfg.width, cfg.height, cfg.fps), (1920, 1080, 60));
        assert_eq!(cfg.bitrate_kbps, 20_000);
        assert_eq!(cfg.packet_size, 1392);
        assert_eq!(cfg.slices_per_frame, 32);
    }

    #[test]
    fn zero_geometry_is_refused_rather_than_clamped_upward() {
        let body = String::from_utf8(announce(""))
            .unwrap()
            .replace("maxFPS:60", "maxFPS:0");
        assert!(matches!(
            parse_announce(body.as_bytes(), None, &Limits::default(), encryption::ALL),
            Err(SdpError::InvalidGeometry { fps: 0, .. })
        ));
    }

    #[test]
    fn a_client_that_will_not_encrypt_is_refused() {
        let body = String::from_utf8(announce(""))
            .unwrap()
            .replace("encryptionEnabled:7", "encryptionEnabled:1");
        let err =
            parse_announce(body.as_bytes(), None, &Limits::default(), encryption::ALL).unwrap_err();
        assert_eq!(
            err,
            SdpError::EncryptionRefused {
                offered: 1,
                required: encryption::ALL
            }
        );

        // ...but the opt-out for trusted LAN use still works.
        assert!(parse_announce(
            body.as_bytes(),
            None,
            &Limits::default(),
            encryption::CONTROL_V2
        )
        .is_ok());
    }

    #[test]
    fn non_h264_codecs_are_refused() {
        for (raw, _name) in [(1u32, "hevc"), (2, "av1"), (7, "nonsense")] {
            let body = String::from_utf8(announce(""))
                .unwrap()
                .replace("bitStreamFormat:0", &format!("bitStreamFormat:{raw}"));
            assert!(matches!(
                parse_announce(body.as_bytes(), None, &Limits::default(), encryption::ALL),
                Err(SdpError::UnsupportedCodec(_))
            ));
        }
    }

    #[test]
    fn duplicated_and_absurd_attributes_do_not_crash_the_parser() {
        let body = announce(
            "a=x-nv-video[0].maxFPS:60\r\n\
             a=x-nv-video[0].maxFPS:60\r\n\
             a=no-colon-here\r\n\
             a=:empty-name\r\n\
             garbage line\r\n",
        );
        assert!(parse_announce(&body, None, &Limits::default(), encryption::ALL).is_ok());
    }

    #[test]
    fn a_non_numeric_attribute_is_an_error() {
        let body = String::from_utf8(announce(""))
            .unwrap()
            .replace("maxFPS:60", "maxFPS:fast");
        assert!(matches!(
            parse_announce(body.as_bytes(), None, &Limits::default(), encryption::ALL),
            Err(SdpError::NotANumber(_))
        ));
    }

    #[test]
    fn invalid_utf8_is_an_error() {
        assert_eq!(
            parse_announce(&[0xFF, 0xFE], None, &Limits::default(), 0).unwrap_err(),
            SdpError::NotUtf8
        );
    }

    #[test]
    fn describe_advertises_h264_only() {
        let sdp = describe_body(encryption::ALL, encryption::ALL);
        assert!(sdp.contains("a=x-ss-general.encryptionSupported:7"));
        assert!(sdp.contains("a=x-ss-general.encryptionRequested:7"));
        // The two markers the client reads as "HEVC" and "AV1" must be absent.
        assert!(!sdp.contains("sprop-parameter-sets=AAAAAU"));
        assert!(!sdp.contains("AV1/90000"));
    }
}
