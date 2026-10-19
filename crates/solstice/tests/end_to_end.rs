//! The first milestone, asserted: colour bars through the full GameStream host
//! stack until a client can decode them.
//!
//! This drives every half of the system that fails silently -- pairing, mutual
//! TLS, `/launch`, encrypted RTSP, the SDP negotiation, the UDP peer binding,
//! the packetiser, the FEC geometry and the video encryption -- and finishes by
//! decoding the H.264 that came out and reading the frame counter back off the
//! picture (`README.md`, `docs/bridging-design.md` §7, `docs/testing.md` §2.3).
//!
//! It is deliberately one test rather than several: the point is that the whole
//! chain works, and a chain that works for the first eight links and not the
//! ninth is a failure of the chain.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use solstice::config::{Backend, BackendKind, Config, Encoder};
use solstice::endpoint::{self, Endpoints, Entry};
use solstice::testpattern::TestPatternBackend;
use solstice_gamestream::crypto::certs::HostIdentity;
use solstice_gamestream::crypto::gcm::SessionCrypto;
use solstice_gamestream::rtsp::encrypted;
use solstice_gamestream::wire::control::Origin;
use solstice_gamestream::wire::ping::Ping;
use solstice_gamestream::wire::video::{
    flags, EncPrefix, FrameHeader, NvVideoPacket, VideoPacketHeader,
};
use solstice_gamestream::wire::Reader;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

mod common;
use common::{
    http_get, https_client, https_get, pair, start_daemon, start_daemon_endpoints, Ports, PIN,
};

// ------------------------------------------------------------------- rtsp --

/// A client that opens a connection per message, the way
/// `moonlight-common-c` does (`RtspConnection.c:386-517`).
///
/// This used to hold one connection open for the whole negotiation, which
/// worked only because the host did too -- the shape of agreement that
/// `docs/testing.md` §0 warns about. The reference client never does this, so
/// neither does this one any more.
struct Rtsp {
    ports: Ports,
    crypto: SessionCrypto,
    sequence: u32,
    cseq: u32,
}

impl Rtsp {
    async fn connect(ports: Ports, key: &[u8; 16]) -> Self {
        Self {
            ports,
            crypto: SessionCrypto::new(key),
            sequence: 0,
            cseq: 0,
        }
    }

    async fn request(&mut self, method: &str, uri: &str, body: &str) -> String {
        self.cseq += 1;
        let mut message = format!(
            "{method} {uri} RTSP/1.0\r\nCSeq: {}\r\nHost: 127.0.0.1\r\n",
            self.cseq
        );
        if !body.is_empty() {
            message.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        message.push_str("\r\n");
        message.push_str(body);

        let sealed = encrypted::seal(
            &self.crypto,
            self.sequence,
            Origin::Client,
            message.as_bytes(),
        )
        .unwrap();
        self.sequence += 1;

        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, self.ports.rtsp))
            .await
            .unwrap();
        stream.set_nodelay(true).unwrap();
        stream.write_all(&sealed).await.unwrap();
        stream.flush().await.unwrap();

        // Read to end of stream: the host's close is the message terminator.
        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
            .await
            .expect("RTSP response timed out")
            .unwrap();
        assert!(
            !buf.is_empty(),
            "the host closed without answering {method}"
        );
        let (plaintext, _) = encrypted::open(&self.crypto, Origin::Host, &buf)
            .unwrap()
            .unwrap_or_else(|| panic!("truncated RTSP response to {method}"));
        String::from_utf8_lossy(&plaintext).into_owned()
    }
}

fn announce_body(width: u32, height: u32, fps: u32) -> String {
    format!(
        "v=0\r\n\
         o=android 0 14 IN IPv4 0.0.0.0\r\n\
         s=solstice end-to-end test\r\n\
         a=x-nv-video[0].clientViewportWd:{width}\r\n\
         a=x-nv-video[0].clientViewportHt:{height}\r\n\
         a=x-nv-video[0].maxFPS:{fps}\r\n\
         a=x-nv-video[0].packetSize:1024\r\n\
         a=x-nv-video[0].videoEncoderSlicesPerFrame:1\r\n\
         a=x-nv-video[0].maxNumReferenceFrames:1\r\n\
         a=x-nv-vqos[0].bitStreamFormat:0\r\n\
         a=x-nv-vqos[0].bw.maximumBitrateKbps:10000\r\n\
         a=x-nv-vqos[0].fec.minRequiredFecPackets:2\r\n\
         a=x-nv-audio.surround.numChannels:2\r\n\
         a=x-nv-aqos.packetDuration:5\r\n\
         a=x-nv-general.useReliableUdp:13\r\n\
         a=x-ss-general.encryptionEnabled:7\r\n"
    )
}

// ----------------------------------------------------------- reassembly ----

/// Collect data shards into whole access units, the way
/// `moonlight-common-c`'s depacketiser does.
///
/// The subtlety that catches a naive implementation: a frame is not complete
/// when its *first* shard arrives. `fecInfo` declares how many data shards the
/// block has and `multiFecBlocks` declares how many blocks the frame has, and a
/// frame is complete only when every block's every data shard is present.
/// Reassembling early yields a truncated access unit, which the decoder reports
/// as a bitstream error several frames later.
#[derive(Default)]
struct Depacketizer {
    frames: std::collections::BTreeMap<u32, PartialFrame>,
}

#[derive(Default)]
struct PartialFrame {
    block_count: u8,
    /// block index -> (declared data shard count, shard index -> payload)
    blocks: std::collections::BTreeMap<u8, (u32, std::collections::BTreeMap<u32, Vec<u8>>)>,
}

impl Depacketizer {
    fn push(&mut self, header: &VideoPacketHeader, payload: &[u8]) {
        let (shard_index, data_shards, _) = NvVideoPacket::unpack_fec_info(header.nv.fec_info);
        if shard_index >= data_shards {
            return; // parity
        }
        let (block_index, block_count) =
            NvVideoPacket::unpack_multi_fec_blocks(header.nv.multi_fec_blocks);
        let frame = self.frames.entry(header.nv.frame_index).or_default();
        frame.block_count = block_count;
        let block = frame
            .blocks
            .entry(block_index)
            .or_insert((data_shards, Default::default()));
        block.0 = data_shards;
        block.1.insert(shard_index, payload.to_vec());
    }

    fn take_complete(&mut self, payload_blocksize: usize) -> Option<(u32, Vec<u8>)> {
        let complete = self.frames.iter().find_map(|(index, frame)| {
            let blocks_present = frame.blocks.len() as u8 == frame.block_count;
            let shards_present = frame
                .blocks
                .values()
                .all(|(declared, shards)| shards.len() as u32 == *declared);
            (blocks_present && shards_present).then_some(*index)
        })?;
        let frame = self.frames.remove(&complete)?;

        // Blocks in order, shards in order within each block.
        let ordered: Vec<&Vec<u8>> = frame
            .blocks
            .values()
            .flat_map(|(_, shards)| shards.values())
            .collect();
        let header = FrameHeader::parse(&mut Reader::new(ordered[0])).ok()?;
        let last = header.last_payload_len as usize;

        let mut out = Vec::new();
        for (i, payload) in ordered.iter().enumerate() {
            if i + 1 == ordered.len() {
                out.extend_from_slice(&payload[..last.min(payload.len())]);
            } else {
                out.extend_from_slice(payload);
            }
        }
        assert_eq!(
            out.len(),
            (ordered.len() - 1) * payload_blocksize + last,
            "frame {complete} reassembled to the wrong length"
        );
        Some((complete, out[8..].to_vec()))
    }
}

// ------------------------------------------------------------- the harness --

/// A frame that came back off the wire, decoded.
struct DecodedFrame {
    index: u32,
    framebuffer: solstice_backend::Framebuffer,
}

/// Drive a full client session against an already-running daemon, launching
/// `app_id`, and return the frames that decoded.
#[allow(clippy::too_many_arguments)]
async fn run_client(
    ports: Ports,
    host: &Arc<solstice_gamestream::nvhttp::Host>,
    app_id: u32,
    width: u32,
    height: u32,
    fps: u32,
    want_frames: usize,
) -> Vec<DecodedFrame> {
    // --- 1. serverinfo over plaintext --------------------------------------
    let xml = http_get(ports.http, "/serverinfo").await;
    assert!(xml.contains("<appversion>7.1.431.-1</appversion>"), "{xml}");
    assert!(xml.contains("<PairStatus>0</PairStatus>"));
    assert!(
        xml.contains("<mac>00:00:00:00:00:00</mac>"),
        "the plaintext listener leaked the MAC"
    );

    // --- 2. the four-phase PIN handshake -----------------------------------
    let client_identity = HostIdentity::generate("moonlight-e2e").unwrap();
    pair(ports, &client_identity).await;
    assert!(host.is_paired(client_identity.cert_der()));

    // --- 3. serverinfo and applist over mutual TLS -------------------------
    let https = https_client(&client_identity);
    let xml = https_get(&https, ports, "/serverinfo").await;
    assert!(xml.contains("<PairStatus>1</PairStatus>"), "{xml}");
    let xml = https_get(&https, ports, "/applist").await;
    assert!(xml.contains(&format!("<ID>{app_id}</ID>")), "{xml}");

    // --- 4. launch ----------------------------------------------------------
    let rikey: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
    let rikey_id: i32 = 0x1234_5678;
    let xml = https_get(
        &https,
        ports,
        &format!(
            "/launch?rikey={}&rikeyid={rikey_id}&localAudioPlayMode=0&appid={app_id}&mode={width}x{height}x{fps}&corever=1",
            hex::encode(rikey)
        ),
    )
    .await;
    assert!(
        xml.contains("rtspenc://"),
        "launch did not offer encrypted RTSP: {xml}"
    );

    let ping_payload = {
        let sessions = host.sessions.lock().unwrap();
        assert_eq!(sessions.len(), 1);
        sessions[0].av_ping_payload
    };

    // --- 5. the RTSP negotiation -------------------------------------------
    let mut rtsp = Rtsp::connect(ports, &rikey).await;
    let response = rtsp.request("OPTIONS", "rtsp://127.0.0.1:48010", "").await;
    assert!(response.starts_with("RTSP/1.0 200"), "{response}");

    let describe = rtsp.request("DESCRIBE", "rtsp://127.0.0.1:48010", "").await;
    assert!(
        describe.contains("x-ss-general.encryptionSupported:7"),
        "{describe}"
    );
    assert!(
        !describe.contains("sprop-parameter-sets=AAAAAU"),
        "HEVC must not be advertised"
    );

    for stream in ["audio/0/0", "video/0/0", "control/13/0"] {
        let response = rtsp
            .request("SETUP", &format!("streamid={stream}"), "")
            .await;
        assert!(response.contains("server_port="), "{stream}: {response}");
        if stream.starts_with("audio") {
            assert!(
                response.contains("Session:"),
                "the audio SETUP must carry a Session"
            );
        }
    }

    let response = rtsp
        .request(
            "ANNOUNCE",
            "streamid=control/13/0",
            &announce_body(width, height, fps),
        )
        .await;
    assert!(
        response.starts_with("RTSP/1.0 200"),
        "ANNOUNCE rejected: {response}"
    );

    // --- 6. bind the UDP channels, then PLAY --------------------------------
    let video = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let audio = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();

    let response = rtsp.request("PLAY", "rtsp://127.0.0.1:48010", "").await;
    assert!(response.starts_with("RTSP/1.0 200"), "{response}");

    // The host learns where to send by matching this payload.
    let ping = Ping {
        payload: ping_payload,
        sequence_number: 0,
    };
    for _ in 0..40 {
        let _ = video
            .send_to(&ping.to_bytes(), (Ipv4Addr::LOCALHOST, ports.video))
            .await;
        let _ = audio
            .send_to(&ping.to_bytes(), (Ipv4Addr::LOCALHOST, ports.audio))
            .await;
        if video.readable().now_or_never().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // --- 7. receive, decrypt, reassemble, decode ----------------------------
    let crypto = SessionCrypto::new(&rikey);
    let mut depacketizer = Depacketizer::default();
    let mut decoder = openh264::decoder::Decoder::new().unwrap();
    let payload_blocksize = 1024 + 16 - 32; // packetSize + MAX_RTP_HEADER_SIZE - header

    let mut buf = vec![0u8; 4096];
    let mut frames = Vec::new();
    let mut datagrams = 0usize;
    let mut saw_parity = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);

    while tokio::time::Instant::now() < deadline && frames.len() < want_frames {
        let Ok(Ok((len, _))) =
            tokio::time::timeout(Duration::from_millis(500), video.recv_from(&mut buf)).await
        else {
            // Keep nudging the host until the peer binding takes.
            let _ = video
                .send_to(&ping.to_bytes(), (Ipv4Addr::LOCALHOST, ports.video))
                .await;
            continue;
        };
        datagrams += 1;

        // Every shard is encrypted, because the client asked for SS_ENC_VIDEO.
        let (prefix, ciphertext) = EncPrefix::parse(&buf[..len]).unwrap();
        assert_eq!(prefix.iv[11], b'V');
        let plaintext = crypto
            .decrypt(&prefix.iv, ciphertext, &prefix.tag)
            .expect("a shard failed authentication");

        let (header, payload) = VideoPacketHeader::parse(&plaintext).unwrap();
        assert_eq!(header.rtp.header, 0x90);
        // A shard is parity by its index within the block, not by its flags:
        // a parity shard's `flags` and `multiFecFlags` bytes are Reed-Solomon
        // output, because the host writes them before the encode and never
        // again (`stream.cpp:1704-1711`).
        let (shard_index, data_shards, _) = NvVideoPacket::unpack_fec_info(header.nv.fec_info);
        if shard_index >= data_shards {
            saw_parity = true;
        } else {
            assert_eq!(header.nv.multi_fec_flags, 0x10);
            assert_ne!(header.nv.flags & flags::CONTAINS_PIC_DATA, 0);
        }
        depacketizer.push(&header, payload);

        while let Some((frame_index, access_unit)) = depacketizer.take_complete(payload_blocksize) {
            if std::env::var("E2E_DEBUG").is_ok() {
                eprintln!("frame {frame_index}: {} bytes", access_unit.len());
            }
            let picture = match decoder.decode(&access_unit) {
                Ok(Some(p)) => p,
                Ok(None) => continue,
                Err(e) => {
                    if std::env::var("E2E_DEBUG").is_ok() {
                        eprintln!("  decode error: {e}");
                    }
                    continue;
                }
            };
            use openh264::formats::YUVSource;
            let (w, h) = picture.dimensions();
            let mut rgb = vec![0u8; w * h * 3];
            picture.write_rgb8(&mut rgb);

            let mut fb = solstice_backend::Framebuffer::new(w as u32, h as u32);
            for y in 0..h {
                for x in 0..w {
                    let i = (y * w + x) * 3;
                    fb.blit(
                        solstice_backend::Rect {
                            x: x as u32,
                            y: y as u32,
                            width: 1,
                            height: 1,
                        },
                        &[rgb[i + 2], rgb[i + 1], rgb[i], 255],
                    );
                }
            }
            frames.push(DecodedFrame {
                index: frame_index,
                framebuffer: fb,
            });
        }
    }

    assert!(datagrams > 0, "no video datagrams arrived at all");
    assert!(saw_parity, "no FEC parity shards were sent");
    assert!(
        frames.len() >= want_frames,
        "only decoded {} of {want_frames} frames from {datagrams} datagrams",
        frames.len()
    );
    frames
}

// ------------------------------------------------------------------- tests --

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_pairs_launches_and_decodes_the_colour_bars() {
    decodes_the_colour_bars(Encoder::for_this_build(), Ports::from_base(49089), "bars").await;
}

/// The same through OpenH264, the fallback encoder.
#[cfg(feature = "openh264")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_decodes_the_colour_bars_through_openh264() {
    decodes_the_colour_bars(Encoder::OpenH264, Ports::from_base(50289), "bars-openh264").await;
}

async fn decodes_the_colour_bars(encoder: Encoder, ports: Ports, tag: &str) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let mut config = Config::default();
    config.server.port = ports.http;
    config.backend = Some(Backend::default());
    config.video.encoder = encoder;
    config.limits.max_width = 640;
    config.limits.max_height = 480;
    config.limits.max_fps = 30;

    let (host, state_dir) = start_daemon(config, tag);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Eight frames rather than three: the clock deliberately emits repeats, so
    // a short window can legitimately contain two copies of the same generator
    // frame and say nothing about whether the picture moves.
    let frames = run_client(ports, &host, 1, 640, 480, 30, 8).await;

    // The barcode in the pattern is the generator's frame counter, so it tells
    // duplicate frames from dropped ones and proves the picture is moving.
    let counters: Vec<u32> = frames
        .iter()
        .filter_map(|f| solstice_video::testsrc::decode_barcode(&f.framebuffer))
        .collect();
    assert!(
        counters.len() >= 4,
        "only {} frames carried a readable barcode",
        counters.len()
    );
    assert!(
        counters.windows(2).all(|w| w[1] >= w[0]),
        "the frame counter went backwards: {counters:?}"
    );
    assert!(
        counters.last().unwrap() > counters.first().unwrap(),
        "the picture never changed: {counters:?}"
    );
    assert!(frames.last().unwrap().index > frames[0].index);

    let _ = std::fs::remove_dir_all(&state_dir);
}

/// Several endpoints are several apps, and a launch dials the one it named
/// and no other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_streams_from_the_endpoint_it_named() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    const PORTS: Ports = Ports::from_base(49889);
    let mut config = Config::default();
    config.server.port = PORTS.http;
    config.video.encoder = Encoder::for_this_build();
    config.limits.max_width = 320;
    config.limits.max_height = 240;
    config.limits.max_fps = 30;

    let first = Arc::new(TestPatternBackend::new(320, 240, 30));
    let second = Arc::new(TestPatternBackend::new(320, 240, 30));
    let entry = |name: &str, backend: &Arc<TestPatternBackend>| Entry {
        id: endpoint::app_id(name),
        name: name.into(),
        detail: "testpattern".into(),
        backend: backend.clone(),
    };
    let endpoints = Endpoints::new(vec![entry("First", &first), entry("Second", &second)]).unwrap();
    let (host, state_dir) = start_daemon_endpoints(config, "endpoints", endpoints);
    host.pairing
        .lock()
        .unwrap()
        .open(PIN, Duration::from_secs(120), std::time::Instant::now())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let frames = run_client(PORTS, &host, endpoint::app_id("Second"), 320, 240, 30, 3).await;
    assert!(!frames.is_empty());
    assert_eq!(second.sessions_opened(), 1);
    assert_eq!(first.sessions_opened(), 0, "the other endpoint was dialled");

    let _ = std::fs::remove_dir_all(&state_dir);
}

/// The whole point of the project, in one test: a Moonlight-shaped client
/// receives the pixels of a real VNC desktop.
///
/// The desktop is a QEMU guest serving RFB, the same one the backend tests
/// use. Skipped with a printed note when QEMU or the guest image is missing;
/// `tests/guest/build-image.sh` builds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_receives_the_pixels_of_a_real_vnc_desktop() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    const PORTS: Ports = Ports::from_base(49189);

    let Some(guest) = solstice_test_guest::Guest::start(
        solstice_test_guest::GuestConfig::new()
            .geometry(640, 480)
            .vnc(),
    ) else {
        return;
    };

    // Paint the root a colour that is unambiguous after a lossy encode, and
    // keep painting it. QEMU renders guest damage into its console surface
    // only while a display client is attached, and nothing is attached until
    // the daemon dials the backend -- so a single paint now would be dropped
    // outright. Repainting until the frames are collected is what makes the
    // colour reliably present once anyone is looking.
    let painter = {
        let guest = std::sync::Arc::new(guest);
        let handle = std::sync::Arc::clone(&guest);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&stop);
        std::thread::spawn(move || {
            while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = handle.fill("0000ff");
                std::thread::sleep(Duration::from_millis(400));
            }
        });
        (guest, stop)
    };
    let (guest, stop) = painter;

    let mut config = Config::default();
    config.server.port = PORTS.http;
    let mut backend = Backend {
        kind: BackendKind::Vnc,
        ..Backend::default()
    };
    backend.vnc.host = "127.0.0.1".into();
    backend.vnc.port = guest.vnc_port();
    // Loopback, which is the only place `none` is permitted.
    backend.vnc.security = solstice::config::VncSecurityKind::None;
    config.backend = Some(backend);
    config.video.encoder = Encoder::for_this_build();
    config.limits.max_width = 640;
    config.limits.max_height = 480;
    config.limits.max_fps = 30;

    let (host, state_dir) = start_daemon(config, "vnc");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let frames = run_client(PORTS, &host, 1, 640, 480, 30, 4).await;

    // The desktop is solid blue, so the decoded picture must be too. Tolerance
    // is wide: this has been through BGRA -> I420 -> H.264 -> I420 -> RGB.
    let last = &frames.last().unwrap().framebuffer;
    let [b, g, r, _] = last.pixel(320, 240).expect("no centre pixel");
    assert!(
        b > 150 && r < 90 && g < 90,
        "the decoded desktop was not blue: B={b} G={g} R={r}"
    );

    // And the whole frame, not just the middle.
    for (x, y) in [(40, 40), (600, 40), (40, 440), (600, 440)] {
        let [b, g, r, _] = last.pixel(x, y).unwrap();
        assert!(
            b > 120 && r < 110 && g < 110,
            "({x},{y}) was not blue: B={b} G={g} R={r}"
        );
    }

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    drop(guest);
    let _ = std::fs::remove_dir_all(&state_dir);
}

use futures_lite_shim::FutureExt as _;
mod futures_lite_shim {
    //! `now_or_never`, without taking a dependency for one line.
    use std::future::Future;
    use std::task::{Context, Poll, Wake, Waker};

    pub trait FutureExt: Future + Sized {
        fn now_or_never(self) -> Option<Self::Output> {
            struct NoopWaker;
            impl Wake for NoopWaker {
                fn wake(self: std::sync::Arc<Self>) {}
            }
            let waker = Waker::from(std::sync::Arc::new(NoopWaker));
            let mut cx = Context::from_waker(&waker);
            let mut future = Box::pin(self);
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(value) => Some(value),
                Poll::Pending => None,
            }
        }
    }
    impl<F: Future> FutureExt for F {}
}
