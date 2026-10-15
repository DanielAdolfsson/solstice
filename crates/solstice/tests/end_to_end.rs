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

use solstice::config::{BackendKind, Config, Encoder};
use solstice::supervisor::{build_host, Supervisor};
use solstice_gamestream::crypto::certs::{ClientStore, HostIdentity};
use solstice_gamestream::crypto::gcm::SessionCrypto;
use solstice_gamestream::crypto::pairing::client::ClientPairing;
use solstice_gamestream::rtsp::encrypted;
use solstice_gamestream::wire::ping::Ping;
use solstice_gamestream::wire::video::{
    flags, EncPrefix, FrameHeader, NvVideoPacket, VideoPacketHeader,
};
use solstice_gamestream::wire::Reader;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const PIN: &str = "4242";

/// Base ports well away from the defaults, so a developer running a real
/// Sunshine or Solstice does not collide with the test. One per test, because
/// the suite runs them concurrently.
#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
    video: u16,
    audio: u16,
    rtsp: u16,
}

impl Ports {
    const fn from_base(base: u16) -> Self {
        Self {
            http: base,
            https: base - 5,
            video: base + 9,
            audio: base + 11,
            rtsp: base + 21,
        }
    }
}

// ----------------------------------------------------------------- client --

/// Moonlight pins the certificate it saw at pairing time; there is no CA and no
/// chain. The test client does the same thing, which means accepting whatever
/// the host presents on the first connection.
#[derive(Debug)]
struct PinnedServerCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for PinnedServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

async fn http_get(port: u16, target: &str) -> String {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let request = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

async fn https_get(client: &HttpsClient, ports: Ports, target: &str) -> String {
    let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, ports.https))
        .await
        .unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = client.connector.connect(name, stream).await.unwrap();
    let request = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let _ = tls.read_to_end(&mut response).await;
    String::from_utf8_lossy(&response).into_owned()
}

struct HttpsClient {
    connector: tokio_rustls::TlsConnector,
}

fn https_client(identity: &HostIdentity) -> HttpsClient {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certs = vec![rustls::pki_types::CertificateDer::from(
        identity.cert_der().to_vec(),
    )];
    let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(identity.key_pem().as_bytes()))
        .unwrap()
        .unwrap();
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerCert(provider)))
        .with_client_auth_cert(certs, key)
        .unwrap();
    HttpsClient {
        connector: tokio_rustls::TlsConnector::from(Arc::new(config)),
    }
}

fn xml_field<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(&xml[start..end])
}

// ---------------------------------------------------------------- pairing --

async fn pair(ports: Ports, client_identity: &HostIdentity) {
    let salt = [0x5Au8; 16];
    let client_cert_pem = client_identity.cert_pem();

    let response = http_get(
        ports.http,
        &format!(
            "/pair?devicename=test&updateState=1&phrase=getservercert&salt={}&clientcert={}",
            hex::encode(salt),
            hex::encode(client_cert_pem.as_bytes())
        ),
    )
    .await;
    assert!(
        response.contains("<paired>1</paired>"),
        "step 1 failed: {response}"
    );
    let plaincert = xml_field(&response, "plaincert").expect("no plaincert");
    let host_cert_pem = String::from_utf8(hex::decode(plaincert).unwrap()).unwrap();
    let host_cert_der = solstice_gamestream::crypto::certs::pem_to_der(&host_cert_pem).unwrap();

    let mut pairing = ClientPairing::new(&salt, PIN);
    let challenge = pairing.client_challenge().unwrap();
    let response = http_get(
        ports.http,
        &format!("/pair?clientchallenge={}", hex::encode(&challenge)),
    )
    .await;
    let challenge_response = xml_field(&response, "challengeresponse")
        .unwrap_or_else(|| panic!("step 2 failed: {response}"));

    let step3 = pairing
        .server_challenge_response(
            &hex::decode(challenge_response).unwrap(),
            &host_cert_der,
            &client_identity.signature().unwrap(),
        )
        .unwrap();
    let response = http_get(
        ports.http,
        &format!("/pair?serverchallengeresp={}", hex::encode(&step3)),
    )
    .await;
    assert!(
        response.contains("<pairingsecret>"),
        "step 3 failed: {response}"
    );

    let body = pairing
        .client_pairing_secret(|m| client_identity.sign(m))
        .unwrap();
    let response = http_get(
        ports.http,
        &format!("/pair?clientpairingsecret={}", hex::encode(&body)),
    )
    .await;
    assert!(
        response.contains("<paired>1</paired>"),
        "step 4 failed: {response}"
    );
}

// ------------------------------------------------------------------- rtsp --

struct Rtsp {
    stream: TcpStream,
    crypto: SessionCrypto,
    sequence: u32,
    cseq: u32,
}

impl Rtsp {
    async fn connect(ports: Ports, key: &[u8; 16]) -> Self {
        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, ports.rtsp))
            .await
            .unwrap();
        stream.set_nodelay(true).unwrap();
        Self {
            stream,
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

        let sealed = encrypted::seal(&self.crypto, self.sequence, message.as_bytes()).unwrap();
        self.sequence += 1;
        self.stream.write_all(&sealed).await.unwrap();
        self.stream.flush().await.unwrap();

        let mut buf = Vec::new();
        loop {
            let mut chunk = [0u8; 4096];
            let read = tokio::time::timeout(Duration::from_secs(5), self.stream.read(&mut chunk))
                .await
                .expect("RTSP response timed out")
                .unwrap();
            assert!(read > 0, "RTSP connection closed during {method}");
            buf.extend_from_slice(&chunk[..read]);
            if let Some((plaintext, used)) = encrypted::open(&self.crypto, &buf).unwrap() {
                buf.drain(..used);
                return String::from_utf8_lossy(&plaintext).into_owned();
            }
        }
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
        if header.nv.flags & flags::CONTAINS_PIC_DATA == 0 {
            return; // parity
        }
        let (shard_index, data_shards, _) = NvVideoPacket::unpack_fec_info(header.nv.fec_info);
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

/// Drive a full client session against an already-running daemon and return
/// the frames that decoded.
async fn run_client(
    ports: Ports,
    host: &Arc<solstice_gamestream::nvhttp::Host>,
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
    assert!(xml.contains("<AppTitle>Desktop</AppTitle>"), "{xml}");

    // --- 4. launch ----------------------------------------------------------
    let rikey: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
    let rikey_id: i32 = 0x1234_5678;
    let xml = https_get(
        &https,
        ports,
        &format!(
            "/launch?rikey={}&rikeyid={rikey_id}&localAudioPlayMode=0&appid=1&mode={width}x{height}x{fps}&corever=1",
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
        assert_eq!(header.nv.multi_fec_flags, 0x10);
        if header.nv.flags & flags::CONTAINS_PIC_DATA == 0 {
            saw_parity = true;
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

/// Start a daemon with a pairing window already open.
fn start_daemon(
    config: Config,
    tag: &str,
) -> (Arc<solstice_gamestream::nvhttp::Host>, std::path::PathBuf) {
    let state_dir = std::env::temp_dir().join(format!("solstice-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state_dir);
    let mut config = config;
    config.server.state_dir = state_dir.clone();

    let identity = HostIdentity::load_or_generate(&state_dir, "solstice-e2e").unwrap();
    let clients = ClientStore::load(state_dir.join("clients.tsv")).unwrap();
    let host = Arc::new(build_host(&config, identity, clients));

    // `solstice pair` would do this over the management socket; the window is
    // opened directly here because that socket is not built yet.
    host.pairing
        .lock()
        .unwrap()
        .open(PIN, Duration::from_secs(120), std::time::Instant::now())
        .unwrap();

    let backend = solstice::backend_factory::build(&config).unwrap();
    let supervisor = Supervisor::new(config, host.clone(), backend);
    tokio::spawn(async move {
        if let Err(e) = supervisor.run().await {
            eprintln!("supervisor ended: {e}");
        }
    });
    (host, state_dir)
}

// ------------------------------------------------------------------- tests --

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_pairs_launches_and_decodes_the_colour_bars() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    const PORTS: Ports = Ports::from_base(49089);
    let mut config = Config::default();
    config.server.port = PORTS.http;
    config.backend.kind = BackendKind::TestPattern;
    config.video.encoder = Encoder::OpenH264;
    config.limits.max_width = 640;
    config.limits.max_height = 480;
    config.limits.max_fps = 30;

    let (host, state_dir) = start_daemon(config, "bars");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Eight frames rather than three: the clock deliberately emits repeats, so
    // a short window can legitimately contain two copies of the same generator
    // frame and say nothing about whether the picture moves.
    let frames = run_client(PORTS, &host, 640, 480, 30, 8).await;

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

/// The whole point of the project, in one test: a Moonlight-shaped client
/// receives the pixels of a real VNC desktop.
///
/// Skipped with a printed note when `Xvnc` is not installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_receives_the_pixels_of_a_real_vnc_desktop() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    const PORTS: Ports = Ports::from_base(49189);
    const DISPLAY: u32 = 95;
    const VNC_PORT: u16 = 5900 + DISPLAY as u16;

    if std::process::Command::new("Xvnc")
        .arg("-version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("skipping: Xvnc is not installed (apt install tigervnc-standalone-server)");
        return;
    }
    let mut xvnc = std::process::Command::new("Xvnc")
        .arg(format!(":{DISPLAY}"))
        .args(["-geometry", "640x480"])
        .args(["-depth", "24"])
        .args(["-SecurityTypes", "None"])
        .args(["-rfbport", &VNC_PORT.to_string()])
        .arg("-localhost")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("could not start Xvnc");

    // Paint the root a colour that is unambiguous after a lossy encode.
    let mut painted = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, VNC_PORT))
            .await
            .is_err()
        {
            continue;
        }
        if let Ok(status) = std::process::Command::new("xsetroot")
            .env("DISPLAY", format!(":{DISPLAY}"))
            .args(["-solid", "#0000ff"])
            .status()
        {
            painted = status.success();
        }
        break;
    }
    if !painted {
        eprintln!("skipping: could not paint the Xvnc root (apt install x11-xserver-utils)");
        let _ = xvnc.kill();
        let _ = xvnc.wait();
        return;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut config = Config::default();
    config.server.port = PORTS.http;
    config.backend.kind = BackendKind::Vnc;
    config.backend.vnc.host = "127.0.0.1".into();
    config.backend.vnc.port = VNC_PORT;
    // Loopback, which is the only place `none` is permitted.
    config.backend.vnc.security = solstice::config::VncSecurityKind::None;
    config.video.encoder = Encoder::OpenH264;
    config.limits.max_width = 640;
    config.limits.max_height = 480;
    config.limits.max_fps = 30;

    let (host, state_dir) = start_daemon(config, "vnc");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let frames = run_client(PORTS, &host, 640, 480, 30, 4).await;

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

    let _ = xvnc.kill();
    let _ = xvnc.wait();
    let _ = std::fs::remove_file(format!("/tmp/.X11-unix/X{DISPLAY}"));
    let _ = std::fs::remove_file(format!("/tmp/.X{DISPLAY}-lock"));
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
