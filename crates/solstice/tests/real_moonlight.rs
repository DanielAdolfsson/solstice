//! The host half, judged by the reference client.
//!
//! Every other GameStream test in this repository drives Solstice with a
//! client written from the same research as the server, so an assumption that
//! is wrong at *both* ends still passes. This one runs `mlc-probe`, which
//! links the real `moonlight-common-c` -- the library every Moonlight port
//! shares -- built with `LC_DEBUG` (FEC validation plus the `LC_ASSERT_VT`
//! checks on host-supplied values) and `LC_DEBUG_RECORD_MODE` (the recorder
//! callbacks that write out the elementary streams).
//!
//! Pairing, `/serverinfo` and `/launch` stay on this side: they are mutual-TLS
//! HTTP that each Moonlight port implements in its own app layer rather than
//! in `moonlight-common-c`. What the probe covers is everything the launch
//! hands over to -- the encrypted RTSP handshake, the ENet control channel,
//! the UDP media binding, the packetiser, the FEC geometry and input.
//!
//! Skipped with a printed note when the probe has not been built;
//! `tests/tools/mlc-probe/build.sh` builds it (`docs/testing.md` §2.2).
//!
//! With `SOLSTICE_CAPTURE_DIR` set, a passing run also leaves behind what
//! `tests/tools/capture-session.sh` needs to turn a packet capture of it into
//! golden vectors: the session keys and ports, and the client's recordings.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use solstice::config::{BackendKind, Config, Encoder};
use solstice::testpattern::TestPatternBackend;
use solstice_backend::{InputEvent, KeyEvent, MouseButton};
use solstice_gamestream::crypto::certs::HostIdentity;

mod common;
use common::{https_client, https_get, pair, start_daemon_with, xml_field, Ports};

const WIDTH: u32 = 640;
const HEIGHT: u32 = 480;
const FPS: u32 = 30;
/// Enough frames that a host which sends one IDR and then stalls fails, and
/// enough FEC blocks that the validation mode has something to validate.
const WANT_FRAMES: u32 = 30;

// ------------------------------------------------------------- the probe --

/// Where `tests/tools/mlc-probe/build.sh` leaves its output.
fn probe_path() -> PathBuf {
    if let Ok(explicit) = std::env::var("SOLSTICE_MLC_PROBE") {
        return PathBuf::from(explicit);
    }
    let base = std::env::var("SOLSTICE_MLC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let cache = std::env::var("XDG_CACHE_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".cache")
                });
            cache.join("solstice/mlc")
        });
    base.join("mlc-probe")
}

/// Everything the probe reported, keyed by the first word of each `PROBE`
/// line. The probe prints one line per event and a `summary` at the end; the
/// summary is what the assertions are made of.
#[derive(Debug, Default)]
struct ProbeReport {
    lines: Vec<String>,
    summary: HashMap<String, String>,
    result_ok: bool,
    stages_failed: Vec<String>,
    connected: bool,
    video_setup: HashMap<String, String>,
    audio_setup: HashMap<String, String>,
}

impl ProbeReport {
    fn count(&self, key: &str) -> u64 {
        self.summary
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }
}

/// Split `a=1 b=2` into pairs, ignoring anything without an `=`.
fn fields(rest: &str) -> HashMap<String, String> {
    rest.split_whitespace()
        .filter_map(|token| token.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn parse_probe_output(stdout: &str) -> ProbeReport {
    let mut report = ProbeReport::default();
    for line in stdout.lines() {
        let Some(rest) = line.strip_prefix("PROBE ") else {
            continue;
        };
        report.lines.push(rest.to_string());
        let (event, rest) = rest.split_once(' ').unwrap_or((rest, ""));
        match event {
            "summary" => report.summary = fields(rest),
            "result" => report.result_ok = fields(rest).get("ok").map(String::as_str) == Some("1"),
            "stage-failed" => report.stages_failed.push(rest.to_string()),
            "connected" => report.connected = true,
            "video-setup" => report.video_setup = fields(rest),
            "audio-setup" => report.audio_setup = fields(rest),
            _ => {}
        }
    }
    report
}

/// What `/launch` hands a Moonlight port to pass to `LiStartConnection`.
struct Launched {
    /// The paired client, for the tests that revoke it.
    client: HostIdentity,
    session_url: String,
    rikey: [u8; 16],
    rikey_id: i32,
    app_version: String,
    codec_support: String,
}

/// Pair and launch, exactly as a Moonlight port's app layer would.
async fn pair_and_launch(ports: Ports) -> Launched {
    let client_identity = HostIdentity::generate("mlc-probe").unwrap();
    pair(ports, &client_identity).await;

    let https = https_client(&client_identity);
    let serverinfo = https_get(&https, ports, "/serverinfo").await;
    assert!(
        serverinfo.contains("<PairStatus>1</PairStatus>"),
        "{serverinfo}"
    );
    let app_version = xml_field(&serverinfo, "appversion")
        .expect("no appversion")
        .to_string();
    let codec_support = xml_field(&serverinfo, "ServerCodecModeSupport")
        .expect("no ServerCodecModeSupport")
        .to_string();

    let rikey: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(53).wrapping_add(7));
    let rikey_id: i32 = 0x0BAD_F00D_u32 as i32;
    // `&corever=1` is `LiGetLaunchUrlQueryParameters()` verbatim
    // (`Connection.c:550-553`): the client appends it, so the harness does too.
    let launch = https_get(
        &https,
        ports,
        &format!(
            "/launch?rikey={}&rikeyid={rikey_id}&localAudioPlayMode=0&appid=1\
             &mode={WIDTH}x{HEIGHT}x{FPS}&corever=1",
            hex::encode(rikey)
        ),
    )
    .await;
    let session_url = xml_field(&launch, "sessionUrl0")
        .unwrap_or_else(|| panic!("launch returned no sessionUrl0: {launch}"))
        .to_string();
    assert!(
        session_url.starts_with("rtspenc://"),
        "the probe is built to exercise encrypted RTSP: {session_url}"
    );
    Launched {
        client: client_identity,
        session_url,
        rikey,
        rikey_id,
        app_version,
        codec_support,
    }
}

/// The probe's command line for a launched session, minus the options that
/// differ between tests.
fn probe_command(probe: &std::path::Path, launched: &Launched) -> std::process::Command {
    let mut command = std::process::Command::new(probe);
    command
        .arg("address=127.0.0.1")
        .arg(format!("rtspurl={}", launched.session_url))
        .arg(format!("rikey={}", hex::encode(launched.rikey)))
        .arg(format!("rikeyid={}", launched.rikey_id))
        .arg(format!("appversion={}", launched.app_version))
        .arg(format!("codecsupport={}", launched.codec_support))
        .arg(format!("width={WIDTH}"))
        .arg(format!("height={HEIGHT}"))
        .arg(format!("fps={FPS}"))
        .arg("bitrate=10000");
    command
}

// -------------------------------------------------------------- the test --

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_reference_moonlight_client_streams_from_this_host() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // `RUST_LOG` is honoured here because when the reference client refuses
    // something, the host's own view of the exchange is half the diagnosis.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .try_init();

    let probe = probe_path();
    if !probe.is_file() {
        eprintln!(
            "skipping: no mlc-probe at {} -- build it with tests/tools/mlc-probe/build.sh",
            probe.display()
        );
        return;
    }

    const PORTS: Ports = Ports::from_base(49289);
    let mut config = Config::default();
    config.server.port = PORTS.http;
    config.backend.kind = BackendKind::TestPattern;
    config.video.encoder = Encoder::OpenH264;
    config.limits.max_width = WIDTH;
    config.limits.max_height = HEIGHT;
    config.limits.max_fps = FPS;

    // What a replay of this session needs to rebuild the host's side of it,
    // taken before the daemon has the config.
    let host_settings = serde_json::json!({
        "max_width": config.limits.max_width,
        "max_height": config.limits.max_height,
        "max_fps": config.limits.max_fps,
        "max_bitrate_kbps": config.limits.max_bitrate_kbps,
        "fec_percentage": config.video.fec_percentage,
        "require_encryption": config.security.require_encryption,
    });

    // Built here rather than by the factory so the input the client sends can
    // be read back off the backend at the end.
    let backend = Arc::new(TestPatternBackend::new(WIDTH, HEIGHT, FPS));
    let (_host, state_dir) = start_daemon_with(config, "mlc", backend.clone());
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- pair and launch, exactly as a Moonlight port's app layer would ----
    let launched = pair_and_launch(PORTS).await;
    // Kept for the capture sidecar, after the probe has taken the rest.
    let (rikey, rikey_id) = (launched.rikey, launched.rikey_id);

    // --- hand over to the reference client ---------------------------------
    let recording = state_dir.join("recorded.h264");
    let audio_recording = state_dir.join("recorded.opus");
    let output = tokio::task::spawn_blocking({
        let probe = probe.clone();
        let recording = recording.clone();
        let audio_recording = audio_recording.clone();
        move || {
            probe_command(&probe, &launched)
                .arg(format!("frames={WANT_FRAMES}"))
                .arg("timeout=30")
                .arg(format!("video={}", recording.display()))
                .arg(format!("audio={}", audio_recording.display()))
                .output()
                .expect("failed to run mlc-probe")
        }
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let report = parse_probe_output(&stdout);

    // The client's own log is the diagnosis when any of this fails, so print
    // it before asserting rather than after.
    if !report.result_ok || std::env::var("MLC_DEBUG").is_ok() {
        eprintln!("--- mlc-probe stdout ---\n{stdout}");
        eprintln!("--- mlc-probe stderr ---\n{stderr}");
    }

    assert!(
        report.stages_failed.is_empty(),
        "the reference client failed a connection stage: {:?}",
        report.stages_failed
    );
    assert!(
        report.connected,
        "LiStartConnection never reported a established connection"
    );
    assert!(
        output.status.success() && report.result_ok,
        "mlc-probe exited {:?}; summary {:?}",
        output.status.code(),
        report.summary
    );

    // --- what the reference client made of the stream ----------------------
    assert_eq!(
        report.video_setup.get("format").map(String::as_str),
        Some("0x1"),
        "the client negotiated something other than H.264"
    );
    assert_eq!(
        report.video_setup.get("width").map(String::as_str),
        Some(WIDTH.to_string().as_str())
    );
    assert!(
        report.count("frames") >= WANT_FRAMES as u64,
        "only {} frames reached the decoder",
        report.count("frames")
    );
    assert!(
        report.count("idr") >= 1,
        "no key frame ever arrived, so nothing was decodable"
    );
    // `LC_DEBUG_RECORD_MODE` only tags SPS/PPS when the depacketiser found
    // them where the format says they are.
    assert_eq!(report.summary.get("sps").map(String::as_str), Some("1"));
    assert_eq!(report.summary.get("pps").map(String::as_str), Some("1"));
    assert!(
        report.count("audio") >= 1,
        "the audio channel produced nothing the client could unwrap"
    );
    assert_eq!(
        report.summary.get("terminated").map(String::as_str),
        Some("0"),
        "the client reported an unexpected termination"
    );

    // --- the recorded elementary stream is the picture we sent -------------
    //
    // This is the assertion the mock client cannot make honestly: these bytes
    // were reassembled, FEC-recovered and ordered by moonlight-common-c, not
    // by a depacketiser written from the same notes as the packetiser.
    let recorded = std::fs::read(&recording).expect("no recording was written");
    assert!(
        recorded.len() > 1000,
        "the recording is {} bytes, which is not a stream",
        recorded.len()
    );
    let counters = decode_barcodes(&recorded);
    assert!(
        counters.len() >= 4,
        "only {} recorded frames carried a readable barcode",
        counters.len()
    );
    assert!(
        counters.windows(2).all(|w| w[1] >= w[0]),
        "the frame counter went backwards in the recording: {counters:?}"
    );
    assert!(
        counters.last().unwrap() > counters.first().unwrap(),
        "the picture never changed: {counters:?}"
    );

    // --- the input the client sent arrived -----------------------------------
    //
    // Input rides the ENet control channel, which is the piece of this host
    // with no other real-peer coverage at all (`docs/roadmap.md` §7).
    let received = backend.received_input();
    assert!(
        received
            .iter()
            .any(|e| matches!(e, InputEvent::PointerRelative { .. })),
        "no relative pointer motion arrived over ENet: {received:?}"
    );
    assert!(
        received
            .iter()
            .any(|e| matches!(e, InputEvent::PointerAbsolute { .. })),
        "no absolute pointer position arrived over ENet: {received:?}"
    );
    assert!(
        received.iter().any(|e| matches!(
            e,
            InputEvent::Button {
                button: MouseButton::Left,
                down: true
            }
        )),
        "no button press arrived over ENet: {received:?}"
    );
    // `VK_A` is 0x41, which the translation table turns into XT scancode 0x1E.
    assert!(
        received.iter().any(|e| matches!(
            e,
            InputEvent::Key(KeyEvent {
                scancode: Some(0x1E),
                down: true,
                ..
            })
        )),
        "the 'A' key press did not arrive intact over ENet: {received:?}"
    );
    // One click is `LI_WHEEL_DELTA`, 120 (`InputStream.c:37`). Asserting the
    // value and not just the event matters: a phantom padding byte in the
    // decoder once turned this into 30720 and still passed `Scroll { .. }`.
    assert!(
        received.iter().any(|e| matches!(
            e,
            InputEvent::Scroll {
                vertical: 120,
                horizontal: 0
            }
        )),
        "no one-click scroll arrived over ENet: {received:?}"
    );

    if let Ok(dir) = std::env::var("SOLSTICE_CAPTURE_DIR") {
        write_capture_sidecar(
            std::path::Path::new(&dir),
            PORTS,
            host_settings,
            &rikey,
            rikey_id,
            &recording,
            &audio_recording,
        );
    }

    let _ = std::fs::remove_dir_all(&state_dir);
}

/// Roadmap §6: on a still screen the host drops from the stream's rate to
/// `video.idle_fps`. That is only safe if the reference client agrees, so it
/// is held still here for longer than any timeout `moonlight-common-c` has
/// (`FIRST_FRAME_TIMEOUT_SEC`, 10 s), then moved again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_reference_client_sits_through_a_still_screen_at_the_idle_rate() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let probe = probe_path();
    if !probe.is_file() {
        eprintln!(
            "skipping: no mlc-probe at {} -- build it with tests/tools/mlc-probe/build.sh",
            probe.display()
        );
        return;
    }

    /// Moving, still, moving again.
    const MOVING: Duration = Duration::from_secs(1);
    const STILL: Duration = Duration::from_secs(12);
    const AFTER: Duration = Duration::from_secs(2);
    const IDLE_FPS: u32 = 5;

    const PORTS: Ports = Ports::from_base(49489);
    let mut config = Config::default();
    config.server.port = PORTS.http;
    config.backend.kind = BackendKind::TestPattern;
    config.video.encoder = Encoder::OpenH264;
    config.video.idle_fps = IDLE_FPS;
    config.limits.max_width = WIDTH;
    config.limits.max_height = HEIGHT;
    config.limits.max_fps = FPS;

    let backend = Arc::new(TestPatternBackend::new(WIDTH, HEIGHT, FPS));
    let (_host, state_dir) = start_daemon_with(config, "mlc-still", backend.clone());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let launched = pair_and_launch(PORTS).await;

    let recording = state_dir.join("recorded.h264");
    // Held for the whole script plus slack; the probe's clock starts before
    // the stream is up, so it outlasts the timeline below.
    let hold = (MOVING + STILL + AFTER).as_secs() + 3;
    let probe_run = tokio::task::spawn_blocking({
        let recording = recording.clone();
        move || {
            probe_command(&probe, &launched)
                .arg("frames=1")
                .arg(format!("hold={hold}"))
                .arg(format!("timeout={}", hold + 30))
                .arg(format!("video={}", recording.display()))
                .output()
                .expect("failed to run mlc-probe")
        }
    });

    // The probe sends its input once two frames have arrived, so input on the
    // backend means the stream is up.
    let up = tokio::time::timeout(Duration::from_secs(30), async {
        while backend.received_input().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(up.is_ok(), "the stream never came up");
    tokio::time::sleep(MOVING).await;
    backend.set_frozen(true);
    tokio::time::sleep(STILL).await;
    backend.set_frozen(false);

    let output = probe_run.await.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let report = parse_probe_output(&stdout);
    if !report.result_ok || std::env::var("MLC_DEBUG").is_ok() {
        eprintln!("--- mlc-probe stdout ---\n{stdout}");
        eprintln!(
            "--- mlc-probe stderr ---\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    eprintln!("still-screen summary: {:?}", report.summary);
    assert!(
        output.status.success() && report.result_ok,
        "mlc-probe exited {:?}; summary {:?}",
        output.status.code(),
        report.summary
    );

    // The client kept the session and was content with it throughout.
    assert_eq!(
        report.summary.get("terminated").map(String::as_str),
        Some("0"),
        "the client ended the session during the still"
    );
    assert_eq!(
        report.count("poor"),
        0,
        "the client reported a poor connection"
    );
    // A client that thought it had lost a frame asks for a keyframe. It also
    // asks for one as it starts, which the host honours on the next frame, so
    // only a keyframe after start-up would mean recovery.
    let late_idrs: Vec<&String> = report
        .lines
        .iter()
        .filter(|line| line.starts_with("frame ") && line.contains("type=idr"))
        .filter(|line| fields(line).get("n").and_then(|n| n.parse::<u32>().ok()) > Some(4))
        .collect();
    assert!(
        late_idrs.is_empty(),
        "the client asked for recovery: {late_idrs:?}"
    );

    // The back-off happened, and was a keep-alive rather than a silence.
    let max_gap = Duration::from_millis(report.count("maxgap"));
    let idle_interval = Duration::from_secs(1) / IDLE_FPS;
    assert!(
        max_gap >= idle_interval * 3 / 4,
        "the longest gap was {max_gap:?}: the host never slowed down"
    );
    assert!(
        max_gap < idle_interval * 3,
        "the longest gap was {max_gap:?}: more than a keep-alive interval"
    );
    let full_rate_frames = hold * FPS as u64;
    assert!(
        report.count("frames") < full_rate_frames * 6 / 10,
        "{} frames in {hold} s is not much below the full rate's {full_rate_frames}",
        report.count("frames")
    );

    // And the picture: frozen for the still, moving again after it.
    let counters = decode_barcodes(&std::fs::read(&recording).expect("no recording"));
    let (frozen_at, run) = longest_run(&counters);
    assert!(
        run as u64 >= STILL.as_secs() * IDLE_FPS as u64 / 2,
        "the longest still run is {run} frames: {counters:?}"
    );
    assert!(
        counters.last().unwrap() > &frozen_at,
        "the picture never moved after the still: {counters:?}"
    );

    let _ = std::fs::remove_dir_all(&state_dir);
}

/// The value repeated longest in a row, and how many times.
/// Roadmap §5: revoking a client ends a stream it already has running, and
/// says so, rather than only refusing the next one (`docs/security.md` §3.4).
/// The reference client is the judge of "says so": it must read the host's
/// `TERMINATION` as a graceful end, promptly, instead of timing out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoking_the_client_ends_its_running_stream() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .try_init();
    let probe = probe_path();
    if !probe.is_file() {
        eprintln!(
            "skipping: no mlc-probe at {} -- build it with tests/tools/mlc-probe/build.sh",
            probe.display()
        );
        return;
    }

    /// Far longer than the test should take: a probe that sits it out was not
    /// told anything.
    const HOLD: u64 = 60;
    /// `CONTROL_STREAM_TIMEOUT_SEC` is 10: a client that noticed only by
    /// timing out would take at least that long.
    const PROMPT: Duration = Duration::from_secs(5);

    const PORTS: Ports = Ports::from_base(49689);
    let mut config = Config::default();
    config.server.port = PORTS.http;
    config.backend.kind = BackendKind::TestPattern;
    config.video.encoder = Encoder::OpenH264;
    config.limits.max_width = WIDTH;
    config.limits.max_height = HEIGHT;
    config.limits.max_fps = FPS;

    let backend = Arc::new(TestPatternBackend::new(WIDTH, HEIGHT, FPS));
    let (host, state_dir) = start_daemon_with(config, "mlc-revoke", backend);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let launched = pair_and_launch(PORTS).await;

    let mut command = probe_command(&probe, &launched);
    command
        .arg("frames=1")
        .arg(format!("hold={HOLD}"))
        .arg(format!("timeout={}", HOLD + 30));
    let mut child = tokio::process::Command::from(command)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to run mlc-probe");

    // The probe's own report of a decoded frame is what "up" means. Input on
    // the backend would be a weaker signal: the probe sends it once, and the
    // loss script can drop it.
    let (first_frame, up) = tokio::sync::oneshot::channel();
    let stdout_reader = tokio::spawn({
        use tokio::io::AsyncBufReadExt;
        let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let mut first_frame = Some(first_frame);
        async move {
            let mut all = String::new();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.starts_with("PROBE frame ") {
                    if let Some(tx) = first_frame.take() {
                        let _ = tx.send(());
                    }
                }
                all.push_str(&line);
                all.push('\n');
            }
            all
        }
    });
    let stderr_reader = tokio::spawn({
        use tokio::io::AsyncReadExt;
        let mut stderr = child.stderr.take().unwrap();
        async move {
            let mut all = String::new();
            let _ = stderr.read_to_string(&mut all).await;
            all
        }
    });
    if !matches!(
        tokio::time::timeout(Duration::from_secs(30), up).await,
        Ok(Ok(()))
    ) {
        let _ = child.kill().await;
        panic!(
            "the stream never came up; the probe said:\n{}\n{}",
            stdout_reader.await.unwrap(),
            stderr_reader.await.unwrap()
        );
    }

    // Revoke a stream that is running, not one still being set up: the
    // host's half of the ENet handshake can finish after the first frame, and
    // under the loss script that can take a retransmission or two.
    // `net/control.rs` covers a revocation inside that window.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // The same call the management socket's `revoke` makes; `management.rs`
    // drives that path with the real binary.
    let revoked_at = std::time::Instant::now();
    assert!(host.revoke(launched.client.cert_der()));

    tokio::time::timeout(PROMPT * 3, child.wait())
        .await
        .expect("the client was still streaming long after the revoke")
        .unwrap();
    let ended_after = revoked_at.elapsed();
    let stdout = stdout_reader.await.unwrap();
    let report = parse_probe_output(&stdout);
    if std::env::var("MLC_DEBUG").is_ok() || ended_after >= PROMPT {
        eprintln!("--- mlc-probe stdout ---\n{stdout}");
        eprintln!("--- mlc-probe stderr ---\n{}", stderr_reader.await.unwrap());
    }
    eprintln!("revoked; the client stopped after {ended_after:?}");

    assert!(report.connected, "the stream never connected");
    assert!(
        ended_after < PROMPT,
        "the client took {ended_after:?} to stop: it was not told"
    );
    // `ML_ERROR_GRACEFUL_TERMINATION` is 0: the client read the host's
    // `NVST_DISCONN_SERVER_TERMINATED_CLOSED` after seeing frames.
    let terminated: Vec<&String> = report
        .lines
        .iter()
        .filter(|line| line.starts_with("terminated "))
        .collect();
    assert_eq!(
        terminated,
        ["terminated code=0"],
        "the client did not see a graceful termination"
    );
    assert!(host.sessions.lock().unwrap().is_empty());

    // The revoked certificate is refused; the host itself is not stuck. A
    // newly paired client streams on the same ports, which a control thread
    // left holding its socket would prevent.
    let refused = https_get(&https_client(&launched.client), PORTS, "/applist").await;
    assert!(refused.contains("401"), "{refused}");
    host.pairing
        .lock()
        .unwrap()
        .open(
            common::PIN,
            Duration::from_secs(60),
            std::time::Instant::now(),
        )
        .unwrap();
    let again = pair_and_launch(PORTS).await;
    let output = tokio::task::spawn_blocking(move || {
        probe_command(&probe, &again)
            .arg(format!("frames={WANT_FRAMES}"))
            .arg("timeout=30")
            .output()
            .expect("failed to run mlc-probe")
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let report = parse_probe_output(&stdout);
    if !report.result_ok {
        eprintln!("--- mlc-probe stdout ---\n{stdout}");
        eprintln!(
            "--- mlc-probe stderr ---\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(
        output.status.success() && report.result_ok,
        "the next client could not stream: {:?}",
        report.summary
    );

    let _ = std::fs::remove_dir_all(&state_dir);
}

fn longest_run(values: &[u32]) -> (u32, usize) {
    let mut best = (0, 0);
    let mut i = 0;
    while i < values.len() {
        let len = values[i..].iter().take_while(|&&v| v == values[i]).count();
        if len > best.1 {
            best = (values[i], len);
        }
        i += len;
    }
    best
}

/// Everything a packet capture of this session cannot say for itself.
///
/// The keys are the important part: `rikey` is generated by the *client*, so
/// whoever drives the client can decrypt the whole session offline -- RTSP,
/// control, video and audio (`docs/testing.md` §2.4). Written only after every
/// assertion above has passed, so a capture of a broken session never becomes
/// a golden vector.
fn write_capture_sidecar(
    dir: &std::path::Path,
    ports: Ports,
    host_settings: serde_json::Value,
    rikey: &[u8; 16],
    rikey_id: i32,
    recording: &std::path::Path,
    audio_recording: &std::path::Path,
) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::copy(recording, dir.join("recorded.h264")).unwrap();
    std::fs::copy(audio_recording, dir.join("recorded.opus")).unwrap();
    let session = serde_json::json!({
        "rikey": hex::encode(rikey),
        "rikey_id": rikey_id,
        "width": WIDTH,
        "height": HEIGHT,
        "fps": FPS,
        "host": host_settings,
        "ports": {
            "rtsp": ports.rtsp,
            "video": ports.video,
            "control": ports.video + 1,
            "audio": ports.audio,
        },
    });
    std::fs::write(
        dir.join("session.json"),
        serde_json::to_string_pretty(&session).unwrap(),
    )
    .unwrap();
}

/// Decode the recorded Annex B stream and read the test pattern's barcode off
/// each picture.
fn decode_barcodes(annex_b: &[u8]) -> Vec<u32> {
    let mut decoder = openh264::decoder::Decoder::new().unwrap();
    let mut counters = Vec::new();
    for packet in openh264::nal_units(annex_b) {
        let Ok(Some(picture)) = decoder.decode(packet) else {
            continue;
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
        if let Some(counter) = solstice_video::testsrc::decode_barcode(&fb) {
            counters.push(counter);
        }
    }
    counters
}
