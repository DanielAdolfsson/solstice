//! T1: a real Moonlight session, captured and replayed.
//!
//! `tests/vectors/capture/session.json.gz` is a packet capture of the real
//! `moonlight-common-c` (`tests/tools/mlc-probe`) streaming from this host,
//! decrypted offline by an independent Python implementation and checked,
//! before it was frozen, against the elementary streams the client itself
//! recorded. `docs/roadmap.md` §4 has the reasoning; the vectors' README has
//! the provenance.
//!
//! Two kinds of assertion, and the difference matters:
//!
//! - **What the client sent is ground truth.** The RTSP requests, the
//!   ANNOUNCE, the pings and every control message came out of the reference
//!   client, so parsing them is checked against the protocol rather than
//!   against our own notes. A wrong field offset here fails without needing
//!   the probe.
//! - **What the host sent is pinned.** It was Solstice's own output, accepted
//!   by the reference client at capture time -- FEC-validated, decoded and
//!   recorded. Replaying the same inputs through the packetisers and the RTSP
//!   state machine must reproduce it byte for byte, so any change to the wire
//!   format shows up in CI as a diff against a session a real client accepted.
//!
//! Regenerate with `tests/tools/capture-session.sh`.

use std::io::Read;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use solstice_backend::{InputEvent, KeyEvent, MouseButton};
use solstice_gamestream::crypto::gcm::{cbc_decrypt, SessionCrypto};
use solstice_gamestream::input::{translate, DroppedInput};
use solstice_gamestream::rtsp::sdp::{encryption, BitstreamFormat, Limits, StreamConfig};
use solstice_gamestream::rtsp::{
    encrypted, message, RtspOutcome, RtspServer, SessionParams, StreamPorts,
};
use solstice_gamestream::stream::audio_tx::{AudioConfig, AudioPacketizer};
use solstice_gamestream::stream::control::{ControlCodec, ControlMessage};
use solstice_gamestream::stream::video_tx::{VideoConfig, VideoPacketizer};
use solstice_gamestream::wire::audio::audio_iv;
use solstice_gamestream::wire::control::{control_iv, msg, EncryptedPacket, Origin};
use solstice_gamestream::wire::ping::Ping;
use solstice_gamestream::wire::video::{EncPrefix, FrameType, VideoPacketHeader};

// ------------------------------------------------------------ the vectors --

#[derive(Deserialize)]
struct Vectors {
    source: String,
    session: Session,
    rtsp: Vec<Exchange>,
    pings: Pings,
    control: Control,
    video: Video,
    audio: Audio,
}

#[derive(Deserialize)]
struct Session {
    #[serde(with = "hex_bytes")]
    rikey: Vec<u8>,
    rikey_id: i32,
    width: u32,
    height: u32,
    fps: u32,
    ports: Ports,
    host: HostSettings,
    session_id: String,
    ping_payload: String,
    connect_data: u32,
}

#[derive(Deserialize)]
struct Ports {
    video: u16,
    audio: u16,
    control: u16,
}

#[derive(Deserialize)]
struct HostSettings {
    max_width: u32,
    max_height: u32,
    max_fps: u32,
    max_bitrate_kbps: u32,
    fec_percentage: u32,
    require_encryption: bool,
}

#[derive(Deserialize)]
struct Exchange {
    #[serde(with = "hex_bytes")]
    client_wire: Vec<u8>,
    request: String,
    host_sequence: u32,
    #[serde(with = "hex_bytes")]
    host_wire: Vec<u8>,
    response: String,
}

#[derive(Deserialize)]
struct Pings {
    #[serde(with = "hex_list")]
    video: Vec<Vec<u8>>,
    #[serde(with = "hex_list")]
    audio: Vec<Vec<u8>>,
}

#[derive(Deserialize)]
struct Control {
    connect_data: u32,
    client: Vec<ControlRecord>,
    host: Vec<ControlRecord>,
}

#[derive(Deserialize)]
struct ControlRecord {
    #[serde(with = "hex_bytes")]
    wire: Vec<u8>,
    sequence: u32,
    #[serde(rename = "type")]
    msg_type: u16,
    #[serde(with = "hex_bytes")]
    payload: Vec<u8>,
}

#[derive(Deserialize)]
struct Video {
    payload_blocksize: usize,
    recorded_frames: usize,
    recording_sha256: String,
    frames: Vec<VideoFrame>,
}

#[derive(Deserialize)]
struct VideoFrame {
    frame_index: u32,
    timestamp: u32,
    frame_type: u8,
    latency: u16,
    #[serde(with = "hex_bytes")]
    access_unit: Vec<u8>,
    padded_length: usize,
    packets: Vec<VideoPacket>,
}

#[derive(Deserialize)]
struct VideoPacket {
    #[serde(with = "hex_bytes")]
    wire: Vec<u8>,
    #[serde(with = "hex_bytes")]
    plaintext: Vec<u8>,
    sequence: u16,
    stream_packet_index: u32,
    flags: u8,
    multi_fec_blocks: u8,
    fec_info: u32,
}

#[derive(Deserialize)]
struct Audio {
    recorded_packets: usize,
    packets: Vec<AudioPacket>,
}

#[derive(Deserialize)]
struct AudioPacket {
    #[serde(with = "hex_bytes")]
    wire: Vec<u8>,
    /// Present on data packets, absent on parity.
    #[serde(default, with = "hex_option")]
    opus: Option<Vec<u8>>,
    sequence: u16,
}

mod hex_bytes {
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

mod hex_list {
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let v = <Vec<String> as serde::Deserialize>::deserialize(d)?;
        v.into_iter()
            .map(|s| hex::decode(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

mod hex_option {
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        let s = <Option<String> as serde::Deserialize>::deserialize(d)?;
        s.map(|s| hex::decode(s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

fn load() -> Vectors {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/vectors/capture/session.json.gz"
    );
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("opening {path}: {e}"));
    let mut json = String::new();
    flate2::read::GzDecoder::new(file)
        .read_to_string(&mut json)
        .unwrap_or_else(|e| panic!("decompressing {path}: {e}"));
    let vectors: Vectors =
        serde_json::from_str(&json).unwrap_or_else(|e| panic!("parsing {path}: {e}"));
    assert!(!vectors.source.is_empty());
    vectors
}

fn key(v: &Vectors) -> [u8; 16] {
    v.session
        .rikey
        .as_slice()
        .try_into()
        .expect("rikey is 16 bytes")
}

/// The RTSP server the daemon would have built for this session
/// (`crates/solstice/src/net/rtsp.rs`, `supervisor.rs`).
fn rtsp_server(v: &Vectors) -> RtspServer {
    let host = &v.session.host;
    RtspServer::new(
        StreamPorts {
            video: v.session.ports.video,
            audio: v.session.ports.audio,
            control: v.session.ports.control,
        },
        Limits {
            max_width: host.max_width,
            max_height: host.max_height,
            max_fps: host.max_fps,
            max_bitrate_kbps: host.max_bitrate_kbps,
            max_packet_size: 1392,
        },
        encryption::ALL,
        if host.require_encryption {
            encryption::ALL
        } else {
            encryption::CONTROL_V2
        },
        SessionParams {
            session_id: v.session.session_id.clone(),
            control_connect_data: v.session.connect_data,
            ping_payload: v
                .session
                .ping_payload
                .as_bytes()
                .try_into()
                .expect("the ping payload is 16 characters"),
        },
    )
}

/// Replay the transcript and return what PLAY started the stream with.
fn negotiate(v: &Vectors) -> StreamConfig {
    let mut server = rtsp_server(v);
    let crypto = SessionCrypto::new(&key(v));
    for exchange in &v.rtsp {
        let (plaintext, _) = encrypted::open(&crypto, Origin::Client, &exchange.client_wire)
            .unwrap()
            .unwrap();
        let (request, _) = message::parse_request(&plaintext).unwrap().unwrap();
        if let RtspOutcome::Play(_, config) = server.handle(&request) {
            return *config;
        }
    }
    panic!("the transcript never reached PLAY");
}

// --------------------------------------------------------------- RTSP --

#[test]
fn the_real_clients_rtsp_requests_decrypt_and_parse() {
    let v = load();
    let crypto = SessionCrypto::new(&key(&v));
    let methods: Vec<String> = v
        .rtsp
        .iter()
        .map(|exchange| {
            let (plaintext, used) = encrypted::open(&crypto, Origin::Client, &exchange.client_wire)
                .expect("the client's envelope did not authenticate")
                .expect("the client's envelope was incomplete");
            assert_eq!(used, exchange.client_wire.len());
            assert_eq!(plaintext, exchange.request.as_bytes());
            let (request, used) = message::parse_request(&plaintext)
                .unwrap_or_else(|e| panic!("{e}: {}", exchange.request))
                .expect("a whole message");
            assert_eq!(used, plaintext.len());
            request.method
        })
        .collect();
    // moonlight-common-c's order (`RtspConnection.c`, `performRtspHandshake`).
    assert_eq!(
        methods,
        ["OPTIONS", "DESCRIBE", "SETUP", "SETUP", "SETUP", "ANNOUNCE", "PLAY"]
    );
}

#[test]
fn the_real_clients_announce_says_what_the_probe_asked_for() {
    let v = load();
    let config = negotiate(&v);
    // `tests/tools/mlc-probe/probe.c` and `real_moonlight.rs` set these.
    assert_eq!(config.width, v.session.width);
    assert_eq!(config.height, v.session.height);
    assert_eq!(config.fps, v.session.fps);
    // The probe asks for 1024; with video encrypted the client takes the
    // 32-byte `ENC_VIDEO_HEADER` off before advertising it
    // (`SdpGenerator.c:325-327`), so the datagram stays at 1024 + 16.
    assert_eq!(config.packet_size, 1024 - 32);
    // The probe asks for 10 Mbit/s; the client advertises 80% of it and
    // leaves the rest for FEC (`SdpGenerator.c:337-338`).
    assert_eq!(config.bitrate_kbps, 8_000);
    assert_eq!(config.bitstream_format, BitstreamFormat::H264);
    assert_eq!(config.audio_channels, 2);
    // `ENCFLG_ALL`, and `useReliableUdp = 13` for the encrypted control
    // stream that goes with it.
    assert_eq!(config.encryption_enabled, encryption::ALL);
    assert!(config.control_encrypted());
    // Moonlight asks for two, and the FEC geometry depends on it.
    assert_eq!(config.min_required_fec_packets, 2);
}

#[test]
fn the_rtsp_responses_replay_byte_for_byte() {
    let v = load();
    let mut server = rtsp_server(&v);
    let crypto = SessionCrypto::new(&key(&v));
    // The host's counter runs across connections (`net/rtsp.rs`).
    for (tx_sequence, exchange) in (0u32..).zip(&v.rtsp) {
        let (request, _) = message::parse_request(exchange.request.as_bytes())
            .unwrap()
            .unwrap();
        let response = match server.handle(&request) {
            RtspOutcome::Reply(r) | RtspOutcome::Play(r, _) => r,
            RtspOutcome::Close(r) => panic!(
                "the replay refused {}: {}",
                request.method,
                String::from_utf8_lossy(&r.to_bytes())
            ),
        };
        let bytes = response.to_bytes();
        assert_eq!(
            String::from_utf8_lossy(&bytes),
            exchange.response,
            "the {} response changed",
            request.method
        );
        assert_eq!(exchange.host_sequence, tx_sequence);
        let sealed = encrypted::seal(&crypto, tx_sequence, Origin::Host, &bytes).unwrap();
        assert_eq!(
            sealed, exchange.host_wire,
            "the {} envelope changed",
            request.method
        );
    }
}

// --------------------------------------------------------------- pings --

#[test]
fn the_real_clients_pings_carry_the_payload_setup_handed_out() {
    let v = load();
    for (channel, pings) in [("video", &v.pings.video), ("audio", &v.pings.audio)] {
        assert!(!pings.is_empty(), "no {channel} ping");
        let mut last = None;
        for datagram in pings {
            let ping = Ping::parse(datagram)
                .unwrap_or_else(|e| panic!("{channel} ping {datagram:02x?}: {e}"));
            assert_eq!(&ping.payload, v.session.ping_payload.as_bytes());
            if let Some(last) = last {
                assert!(
                    ping.sequence_number > last,
                    "{channel} ping sequence went backwards"
                );
            }
            last = Some(ping.sequence_number);
        }
    }
}

// ------------------------------------------------------------- control --

#[test]
fn the_real_client_connected_with_the_connect_data_setup_handed_out() {
    let v = load();
    assert_eq!(v.control.connect_data, v.session.connect_data);
}

#[test]
fn the_real_clients_control_messages_decrypt_and_decode() {
    let v = load();
    let crypto = SessionCrypto::new(&key(&v));
    let mut codec = ControlCodec::new(Some(&key(&v)));
    let mut records = Vec::new();
    let mut messages = Vec::new();
    for record in &v.control.client {
        // The envelope and the GCM, checked directly against the plaintext
        // the generator recovered independently.
        let packet = EncryptedPacket::parse(&record.wire).unwrap();
        assert_eq!(packet.header.sequence, record.sequence);
        let plaintext = crypto
            .decrypt(
                &control_iv(record.sequence, Origin::Client),
                packet.ciphertext,
                packet.tag,
            )
            .unwrap();
        assert_eq!(&plaintext[..2], &record.msg_type.to_le_bytes());
        assert_eq!(&plaintext[4..], record.payload.as_slice());

        // And the codec the control thread actually runs.
        let message = codec
            .decode(&record.wire)
            .unwrap_or_else(|e| panic!("message {:#06x}: {e}", record.msg_type));
        if let ControlMessage::Input(batch) = &message {
            records.extend(batch.iter().cloned());
        }
        messages.push(message);
    }

    // Moonlight asks for an IDR before anything else
    // (`ControlStream.c`, `controlReceiveThreadFunc` start-up).
    assert_eq!(messages.first(), Some(&ControlMessage::RequestIdr));
    assert!(messages.iter().any(
        |m| matches!(m, ControlMessage::Unknown { msg_type, .. } if *msg_type == msg::START_B)
    ));

    // Every input event the session carried, in order.
    let translation = translate(&records);
    // The client enables haptics on its own as soon as input starts
    // (`InputStream.c:637`, `ENABLE_HAPTICS_MAGIC`). Neither backend has a
    // controller, so that one record is dropped -- and counted -- and nothing
    // else is.
    assert!(
        matches!(
            translation.dropped.as_slice(),
            [DroppedInput::Unknown { magic: 0x0D }]
        ),
        "{:?}",
        translation.dropped
    );
    let expected = [
        // The client wiggles the mouse to wake the display before it reports
        // the connection as started (`Connection.c:534-537`).
        InputEvent::PointerRelative { dx: 1, dy: 1 },
        InputEvent::PointerRelative { dx: -1, dy: -1 },
        // Then the probe's own script.
        InputEvent::PointerRelative { dx: 40, dy: 30 },
        // The client sends the reference size *minus one*
        // (`InputStream.c:458-459`); the host passes it on as sent.
        InputEvent::PointerAbsolute {
            x: 100,
            y: 50,
            ref_width: v.session.width as u16 - 1,
            ref_height: v.session.height as u16 - 1,
        },
        InputEvent::Button {
            button: MouseButton::Left,
            down: true,
        },
        InputEvent::Button {
            button: MouseButton::Left,
            down: false,
        },
    ];
    assert_eq!(&translation.events[..expected.len()], &expected);
    let rest = &translation.events[expected.len()..];
    // `VK_A` is 0x41, XT scancode 0x1E.
    assert!(
        matches!(
            rest,
            [
                InputEvent::Key(KeyEvent {
                    scancode: Some(0x1E),
                    down: true,
                    ..
                }),
                InputEvent::Key(KeyEvent {
                    scancode: Some(0x1E),
                    down: false,
                    ..
                }),
                // One click is `LI_WHEEL_DELTA`, 120 (`InputStream.c:37`).
                InputEvent::Scroll {
                    vertical: 120,
                    horizontal: 0
                },
            ]
        ),
        "{rest:?}"
    );
}

#[test]
fn host_control_messages_replay_byte_for_byte() {
    let v = load();
    let mut codec = ControlCodec::new(Some(&key(&v)));
    for record in &v.control.host {
        assert_eq!(
            codec.encode(record.msg_type, &record.payload).unwrap(),
            record.wire
        );
    }
}

// --------------------------------------------------------------- video --

#[test]
fn video_packets_decrypt_and_parse_as_the_generator_read_them() {
    let v = load();
    let crypto = SessionCrypto::new(&key(&v));
    for frame in &v.video.frames {
        for packet in &frame.packets {
            let (prefix, ciphertext) = EncPrefix::parse(&packet.wire).unwrap();
            assert_eq!(prefix.frame_number, frame.frame_index);
            let mut body = ciphertext.to_vec();
            crypto
                .decrypt_detached(&prefix.iv, &mut body, &prefix.tag)
                .expect("a video shard did not authenticate");
            assert_eq!(body, packet.plaintext);

            let (header, payload) = VideoPacketHeader::parse(&body).unwrap();
            assert_eq!(header.rtp.sequence_number, packet.sequence);
            assert_eq!(header.rtp.timestamp, frame.timestamp);
            assert_eq!(header.nv.frame_index, frame.frame_index);
            assert_eq!(header.nv.stream_packet_index, packet.stream_packet_index);
            assert_eq!(header.nv.multi_fec_blocks, packet.multi_fec_blocks);
            assert_eq!(header.nv.fec_info, packet.fec_info);
            assert_eq!(header.nv.flags, packet.flags);
            assert_eq!(payload.len(), v.video.payload_blocksize);
        }
    }
}

#[test]
fn the_client_recorded_exactly_these_frames() {
    let v = load();
    // What `LC_DEBUG_RECORD_MODE` wrote: each frame's payload, frame header
    // stripped, FEC zero padding kept.
    let mut hasher = Sha256::new();
    for frame in &v.video.frames[..v.video.recorded_frames] {
        hasher.update(&frame.access_unit);
        hasher.update(vec![0u8; frame.padded_length - frame.access_unit.len()]);
    }
    assert_eq!(hex::encode(hasher.finalize()), v.video.recording_sha256);
    // The session starts on a keyframe the client actually decoded.
    assert_eq!(v.video.frames[0].frame_type, FrameType::Idr as u8);
}

#[test]
fn video_repacketises_byte_for_byte() {
    let v = load();
    let config = negotiate(&v);
    let mut packetizer = VideoPacketizer::new(
        VideoConfig {
            packet_size: config.packet_size as usize,
            fec_percentage: v.session.host.fec_percentage,
            min_required_fec_packets: config.min_required_fec_packets,
            encrypt: config.video_encrypted(),
        },
        Some(&key(&v)),
    );
    assert_eq!(packetizer.payload_blocksize(), v.video.payload_blocksize);
    for frame in &v.video.frames {
        let frame_type = match frame.frame_type {
            1 => FrameType::P,
            2 => FrameType::Idr,
            other => panic!("frame type {other}"),
        };
        let built = packetizer
            .packetize(
                &frame.access_unit,
                frame_type,
                frame.timestamp,
                frame.latency,
            )
            .unwrap();
        assert_eq!(built.frame_index, frame.frame_index);
        assert_eq!(
            built.packets.len(),
            frame.packets.len(),
            "frame {} has a different shard count",
            frame.frame_index
        );
        for (i, (got, want)) in built.packets.iter().zip(&frame.packets).enumerate() {
            assert!(
                got == &want.wire,
                "frame {} shard {i} differs from the one the client accepted",
                frame.frame_index
            );
        }
    }
}

// --------------------------------------------------------------- audio --

#[test]
fn audio_decrypts_and_repacketises_byte_for_byte() {
    let v = load();
    let config = negotiate(&v);
    let key = key(&v);
    let mut packetizer = AudioPacketizer::new(
        AudioConfig {
            packet_duration_ms: config.audio_packet_duration,
            encrypt: config.audio_encrypted(),
            rikey_id: v.session.rikey_id,
        },
        Some(&key),
    );

    let mut expected = v.audio.packets.iter();
    for packet in &v.audio.packets {
        let Some(opus) = &packet.opus else { continue };
        let plaintext = cbc_decrypt(
            &key,
            &audio_iv(v.session.rikey_id, packet.sequence as u32),
            &packet.wire[12..],
        )
        .expect("an audio packet did not decrypt");
        assert_eq!(&plaintext, opus);

        for got in packetizer.packetize(opus) {
            let want = expected.next().expect("the replay produced more packets");
            assert!(
                got == want.wire,
                "audio sequence {} differs from the one the client accepted",
                want.sequence
            );
        }
    }
    assert!(
        expected.next().is_none(),
        "the replay produced fewer packets"
    );
    assert!(v.audio.recorded_packets > 0, "the client recorded no audio");
}
