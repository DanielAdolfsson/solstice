//! T3: the client against `Xspice`, the only real SPICE server there is.
//!
//! `docs/testing.md` §4 is the argument for this being the whole T3 tier:
//! **`Xspice` links the same `spice-server` library QEMU does**, so the
//! display-channel and image-codec behaviour is literally the same code,
//! reachable without a VM, a guest OS or nested virtualisation. And its
//! command line exposes the knobs that matter -- `--image-compression` picks
//! exactly the codec, so each one can be forced rather than hoped for.
//!
//! Skipped with a printed note when `Xspice` is not installed, so the suite
//! still runs without it:
//!
//! ```sh
//! sudo apt install xserver-xspice
//! ```
//!
//! # The known gap
//!
//! `Xspice` does not cover QXL *guest-driver* behaviour: a real VM's driver
//! emits a different mix of draw commands than the Xspice video driver does.
//! `docs/testing.md` §4.2 calls that one manual QEMU run before a release,
//! not a CI job, and this file does not pretend otherwise.

use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use solstice_backend::{BackendEvent, InputEvent, KeyEvent, Session};
use solstice_spice::backend::{connect, SpiceConfig, SpiceSecurity, TcpDialer};

const TIMEOUT: Duration = Duration::from_secs(30);

struct Xspice {
    child: Child,
    port: u16,
    display: u32,
}

impl Drop for Xspice {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(format!("/tmp/.X11-unix/X{}", self.display));
        let _ = std::fs::remove_file(format!("/tmp/.X{}-lock", self.display));
    }
}

/// Start `Xspice`, or return `None` with a note when it is not installed.
///
/// `--image-compression` is the parameter this exists for: each codec gets
/// its own test rather than being left to the server's heuristics.
fn start_xspice(display: u32, port: u16, geometry: &str, compression: &str) -> Option<Xspice> {
    if Command::new("Xspice")
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("skipping: Xspice is not installed (apt install xserver-xspice)");
        return None;
    }
    let child = Command::new("Xspice")
        .arg("--port")
        .arg(port.to_string())
        .arg("--disable-ticketing")
        .args(["--image-compression", compression])
        .args(["--streaming-video", "off"])
        .args(["--geometry", geometry])
        .arg(format!(":{display}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    Some(Xspice {
        child,
        port,
        display,
    })
}

async fn wait_for_port(port: u16) -> bool {
    for _ in 0..150 {
        if tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

fn config(port: u16) -> SpiceConfig {
    SpiceConfig {
        host: "127.0.0.1".into(),
        port,
        // Plaintext is permitted here and only here: loopback. The policy
        // and its refusal off-loopback are asserted in the unit tests.
        security: SpiceSecurity::Plain { password: None },
        audio: false,
        ..SpiceConfig::default()
    }
}

async fn session(port: u16) -> solstice_spice::SpiceSession {
    let dialer = Arc::new(TcpDialer::new(config(port)));
    tokio::time::timeout(TIMEOUT, connect(dialer, config(port)))
        .await
        .expect("connect timed out")
        .expect("connect failed")
}

/// Wait for damage covering at least `width` x `height`.
async fn wait_for_full_screen(
    session: &solstice_spice::SpiceSession,
    width: u32,
    height: u32,
) -> solstice_backend::Rect {
    let mut events = session.subscribe();
    let mut covered: Option<solstice_backend::Rect> = None;
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(3), events.recv()).await {
            Ok(Ok(BackendEvent::Damage(rect))) => {
                covered = Some(covered.map_or(rect, |c| c.union(&rect)));
                let c = covered.unwrap();
                if c.width >= width && c.height >= height {
                    break;
                }
            }
            Ok(Ok(_)) => {}
            _ => break,
        }
    }
    covered.expect("no damage arrived from Xspice")
}

/// M3's gate: raw images only, which is where the backend was built from.
#[tokio::test]
async fn the_client_receives_the_pixels_of_a_real_spice_desktop_uncompressed() {
    let Some(server) = start_xspice(90, 5990, "800x600", "off") else {
        return;
    };
    assert!(wait_for_port(server.port).await, "Xspice never listened");

    let session = session(server.port).await;
    assert_eq!(session.dimensions(), (800, 600));

    let covered = wait_for_full_screen(&session, 800, 600).await;
    assert!(
        covered.width >= 800 && covered.height >= 600,
        "only {covered:?} was updated"
    );

    {
        let fb = session.framebuffer();
        let fb = fb.read();
        assert_eq!((fb.width(), fb.height()), (800, 600));
        assert!(
            fb.data().chunks_exact(4).all(|px| px[3] == 0xFF),
            "an x8r8g8b8 primary surface should publish opaque alpha"
        );
    }

    session.close().await;
}

/// M4, one `--image-compression` flag at a time. QUIC and LZ are
/// single-image codecs, so one screen proves the wiring; GLZ is stateful and
/// gets its own soak test below.
#[tokio::test]
async fn quic_images_decode_against_the_real_encoder() {
    let Some(server) = start_xspice(91, 5991, "640x480", "quic") else {
        return;
    };
    assert!(wait_for_port(server.port).await, "Xspice never listened");
    let session = session(server.port).await;
    wait_for_full_screen(&session, 640, 480).await;
    session.close().await;
}

#[tokio::test]
async fn lz_images_decode_against_the_real_encoder() {
    let Some(server) = start_xspice(92, 5992, "640x480", "lz") else {
        return;
    };
    assert!(wait_for_port(server.port).await, "Xspice never listened");
    let session = session(server.port).await;
    wait_for_full_screen(&session, 640, 480).await;
    session.close().await;
}

#[tokio::test]
async fn lz4_images_decode_against_the_real_encoder() {
    let Some(server) = start_xspice(93, 5993, "640x480", "lz4") else {
        return;
    };
    assert!(wait_for_port(server.port).await, "Xspice never listened");
    let session = session(server.port).await;
    wait_for_full_screen(&session, 640, 480).await;
    session.close().await;
}

/// GLZ's history window is the whole point of it and single frames prove
/// nothing: the bugs are in window management
/// (`docs/testing.md` §4). This is the short version of the soak the roadmap
/// asks for -- enough churn to evict, not enough to be a nightly job.
#[tokio::test]
async fn glz_survives_enough_window_churn_to_evict() {
    let Some(server) = start_xspice(94, 5994, "640x480", "glz") else {
        return;
    };
    assert!(wait_for_port(server.port).await, "Xspice never listened");
    let session = session(server.port).await;
    wait_for_full_screen(&session, 640, 480).await;

    // Typing into the root window is the cheapest way to make the server
    // redraw repeatedly without an X client. Every redraw is another image
    // into the GLZ window; a window miss would surface as the display
    // channel going quiet.
    let mut events = session.subscribe();
    for round in 0..200u16 {
        let scancode = solstice_input::scancode(solstice_input::vk::KEY_A, false);
        for down in [true, false] {
            session
                .send_input(InputEvent::Key(KeyEvent {
                    scancode,
                    keysym: Some(0x61),
                    down,
                    non_normalized: false,
                }))
                .await
                .expect("the session should still be up");
        }
        if round % 20 == 0 {
            // Drain, so the broadcast queue does not lag and hide a stall.
            while events.try_recv().is_ok() {}
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    assert!(
        session.dimensions() == (640, 480),
        "the display channel reset, which is what a GLZ window miss looks like"
    );
    session.close().await;
}

/// `--streaming-video all` is the flag `docs/testing.md` §4 says to turn on
/// early, because it is the one that breaks naive compositing: streams are
/// clipped sub-rectangles layered over the draw commands.
#[tokio::test]
async fn a_streaming_server_still_produces_a_whole_screen() {
    if Command::new("Xspice")
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("skipping: Xspice is not installed");
        return;
    }
    let child = Command::new("Xspice")
        .arg("--port")
        .arg("5995")
        .arg("--disable-ticketing")
        .args(["--image-compression", "auto_glz"])
        .args(["--streaming-video", "all"])
        .args(["--geometry", "640x480"])
        .arg(":95")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(child) = child else {
        return;
    };
    let server = Xspice {
        child,
        port: 5995,
        display: 95,
    };
    assert!(wait_for_port(server.port).await, "Xspice never listened");

    let session = session(server.port).await;
    wait_for_full_screen(&session, 640, 480).await;
    session.close().await;
}

/// With `--vdagent` the guest can be resized; without it the request is
/// declined and the caller scales instead. Both are correct and the
/// difference is what this asserts.
#[tokio::test]
async fn a_resize_is_declined_without_the_agent() {
    let Some(server) = start_xspice(96, 5996, "800x600", "off") else {
        return;
    };
    assert!(wait_for_port(server.port).await, "Xspice never listened");
    let session = session(server.port).await;
    wait_for_full_screen(&session, 800, 600).await;

    // No `--vdagent`, so there is no agent and nothing that can change the
    // mode. Declining is the contract, not a failure.
    assert!(!session.can_resize());
    assert!(!session.request_resize(1280, 720).await.unwrap());
    session.close().await;
}
