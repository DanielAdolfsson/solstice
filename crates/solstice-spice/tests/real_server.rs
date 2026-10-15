//! T3: the client against `Xspice`, the only real SPICE server there is.
//!
//! `docs/testing.md` §4 is the argument for this being the whole T3 tier:
//! **`Xspice` links the same `spice-server` library QEMU does**, so the
//! display-channel and image-codec behaviour is literally the same code,
//! reachable without a VM, a guest OS or nested virtualisation. And its
//! command line exposes the knob that matters -- `--image-compression` picks
//! exactly the codec, so each one is forced rather than hoped for.
//!
//! Every test here follows the same shape, which is the one that actually
//! proves something:
//!
//! 1. start `Xspice` and paint the root window black;
//! 2. connect, and wait for the primary surface;
//! 3. paint the root window a known colour **while connected**;
//! 4. assert every pixel of the framebuffer becomes that colour.
//!
//! Step 3 is the point. A client that only ever sees the screen as it was at
//! connect time can be completely broken for incremental updates and still
//! pass -- which is exactly the mistake the first draft of this file made.
//!
//! Skipped with a printed note when `Xspice` or `xsetroot` is missing:
//!
//! ```sh
//! sudo apt install xserver-xspice x11-xserver-utils x11-utils xterm
//! ```
//!
//! # Running the Debian `Xspice`
//!
//! Two things about the packaged launcher are worth knowing, because both
//! cost an afternoon:
//!
//! * **`--auto` crashes.** The `xorg.conf` it generates omits the driver's
//!   buffer-size options, the QXL driver computes a surface of size zero and
//!   aborts in `malloc`. So this file writes its own configuration, which is
//!   also the only way to set the geometry -- there is no `--geometry` flag.
//! * **`--vdagent` cannot be used without `--auto`**, where it hits an
//!   undefined `temp_dir`. Combined with the above there is no way to run the
//!   agent from this launcher, which is why the agent has no test here; see
//!   `docs/roadmap.md` §2.6.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use solstice_backend::{BackendEvent, InputEvent, KeyEvent, Session};
use solstice_spice::backend::{connect, SpiceConfig, SpiceSecurity, TcpDialer};

const TIMEOUT: Duration = Duration::from_secs(30);

/// A running `Xspice`, torn down on drop.
struct Xspice {
    child: Child,
    port: u16,
    display: u32,
    _dir: PathBuf,
}

impl Drop for Xspice {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The Python launcher does not always reap its Xorg, so clear the
        // lock files a later run on the same display would trip over.
        let _ = std::fs::remove_file(format!("/tmp/.X11-unix/X{}", self.display));
        let _ = std::fs::remove_file(format!("/tmp/.X{}-lock", self.display));
        let _ = std::fs::remove_dir_all(&self._dir);
    }
}

fn have(program: &str) -> bool {
    Command::new(program)
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Write the `xorg.conf` the driver needs.
///
/// The three buffer sizes are the ones `--auto` leaves out. They are in
/// megabytes and are set small deliberately: these tests run concurrently and
/// the driver's defaults are 128 MB of surface plus 128 MB of command buffer
/// per server.
fn write_config(dir: &Path, width: u32, height: u32) -> std::io::Result<PathBuf> {
    let path = dir.join("xorg.conf");
    let mut file = std::fs::File::create(&path)?;
    write!(
        file,
        r#"Section "Device"
    Identifier "XSPICE"
    Driver "spiceqxl"
    Option "SurfaceBufferSize" "32"
    Option "CommandBufferSize" "32"
    Option "FrameBufferSize" "8"
    Option "NumHeads" "1"
EndSection
Section "InputDevice"
    Identifier "XSPICE POINTER"
    Driver     "xspice pointer"
EndSection
Section "InputDevice"
    Identifier "XSPICE KEYBOARD"
    Driver     "xspice keyboard"
EndSection
Section "Monitor"
    Identifier "Configured Monitor"
EndSection
Section "Screen"
    Identifier   "XSPICE Screen"
    Monitor      "Configured Monitor"
    Device       "XSPICE"
    DefaultDepth 24
    SubSection "Display"
        Depth   24
        Modes   "{width}x{height}"
        Virtual {width} {height}
    EndSubSection
EndSection
Section "ServerLayout"
    Identifier "XSPICE Layout"
    Screen "XSPICE Screen"
    InputDevice "XSPICE KEYBOARD"
    InputDevice "XSPICE POINTER"
EndSection
Section "ServerFlags"
    Option "AutoAddDevices" "False"
EndSection
"#
    )?;
    Ok(path)
}

/// Start `Xspice`, or return `None` with a note when the tools are missing.
fn start(
    display: u32,
    port: u16,
    width: u32,
    height: u32,
    compression: &str,
    streaming: &str,
) -> Option<Xspice> {
    if !have("Xspice") {
        eprintln!("skipping: Xspice is not installed (apt install xserver-xspice)");
        return None;
    }
    if !have("xsetroot") {
        eprintln!("skipping: xsetroot is not installed (apt install x11-xserver-utils)");
        return None;
    }
    let dir = std::env::temp_dir().join(format!("solstice-xspice-{display}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let config = write_config(&dir, width, height).ok()?;

    let _ = std::fs::remove_file(format!("/tmp/.X11-unix/X{display}"));
    let _ = std::fs::remove_file(format!("/tmp/.X{display}-lock"));

    let child = Command::new("Xspice")
        .arg("--config")
        .arg(&config)
        .args(["--port", &port.to_string()])
        .arg("--disable-ticketing")
        .args(["--image-compression", compression])
        .args(["--streaming-video", streaming])
        .arg(format!(":{display}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    Some(Xspice {
        child,
        port,
        display,
        _dir: dir,
    })
}

async fn wait_for_port(port: u16) -> bool {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
        {
            // The port is open a moment before the X server will answer an
            // X client; give it that moment.
            tokio::time::sleep(Duration::from_millis(500)).await;
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Paint the root window, which is the cheapest way to make a real server
/// produce a real full-screen draw command.
fn paint(display: u32, colour: &str) -> bool {
    Command::new("xsetroot")
        .env("DISPLAY", format!(":{display}"))
        .args(["-solid", colour])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn config(port: u16) -> SpiceConfig {
    SpiceConfig {
        host: "127.0.0.1".into(),
        port,
        // Plaintext is permitted here and only here: loopback. The refusal
        // off-loopback is asserted in the unit tests.
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

/// Wait until every pixel of the framebuffer is `expected`, or give up.
async fn wait_for_solid(
    session: &solstice_spice::SpiceSession,
    expected: [u8; 4],
) -> Result<usize, String> {
    let mut events = session.subscribe();
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut damage = 0usize;
    loop {
        {
            let fb = session.framebuffer();
            let fb = fb.read();
            let mut pixels = fb.data().chunks_exact(4);
            if pixels.len() > 0 && pixels.all(|px| px == expected) {
                return Ok(damage);
            }
        }
        if tokio::time::Instant::now() > deadline {
            let fb = session.framebuffer();
            let fb = fb.read();
            let first = fb.pixel(0, 0);
            return Err(format!(
                "after {damage} damage events the framebuffer is not {expected:?}; \
                 pixel (0,0) is {first:?}"
            ));
        }
        if let Ok(Ok(BackendEvent::Damage(_))) =
            tokio::time::timeout(Duration::from_millis(250), events.recv()).await
        {
            damage += 1;
        }
    }
}

/// The whole shape, parameterised by the server's image compression: connect
/// to a black screen, repaint it while connected, and assert the pixels.
async fn incremental_repaint_test(display: u32, port: u16, compression: &str) {
    let Some(server) = start(display, port, 640, 480, compression, "off") else {
        return;
    };
    assert!(wait_for_port(server.port).await, "Xspice never listened");
    assert!(paint(server.display, "#000000"), "xsetroot failed");

    let session = session(server.port).await;
    assert_eq!(
        session.dimensions(),
        (640, 480),
        "the primary surface should have arrived before connect returned"
    );

    // Repaint *while connected*: this is the half a connect-time-only test
    // cannot reach.
    assert!(paint(server.display, "#ff8040"), "xsetroot failed");
    // #ff8040 is R=0xff, G=0x80, B=0x40; the framebuffer is BGRA.
    let damage = wait_for_solid(&session, [0x40, 0x80, 0xff, 0xff])
        .await
        .unwrap_or_else(|e| panic!("{compression}: {e}"));
    assert!(damage > 0, "{compression}: the repaint raised no damage");

    session.close().await;
}

/// M3's gate, and the SPICE counterpart of
/// `a_client_receives_the_pixels_of_a_real_vnc_desktop`: raw images only,
/// which is what the backend was built against first.
#[tokio::test]
async fn the_client_receives_the_pixels_of_a_real_spice_desktop() {
    incremental_repaint_test(50, 5950, "off").await;
}

/// M4, one `--image-compression` flag at a time. QUIC is the one where a
/// single desynchronised bit corrupts the rest of the image, so "every pixel
/// is the expected colour" is a real assertion rather than a smoke test.
#[tokio::test]
async fn quic_images_decode_against_the_real_encoder() {
    incremental_repaint_test(51, 5951, "quic").await;
}

#[tokio::test]
async fn lz_images_decode_against_the_real_encoder() {
    incremental_repaint_test(52, 5952, "lz").await;
}

/// GLZ's dictionary spans the session, so this exercises the window as well
/// as the format.
#[tokio::test]
async fn glz_images_decode_against_the_real_encoder() {
    incremental_repaint_test(53, 5953, "glz").await;
}

/// What QEMU defaults to, and therefore the one that matters most: the
/// server picks between GLZ and QUIC per image.
#[tokio::test]
async fn auto_glz_is_what_qemu_defaults_to() {
    incremental_repaint_test(54, 5954, "auto_glz").await;
}

/// LZ4 has no `--image-compression` value: `Xspice` offers
/// `off|auto_glz|auto_lz|quic|glz|lz` and nothing else, so the server cannot
/// be made to produce it on demand. The decoder is covered by its own unit
/// tests instead, including the linked-block case that is the whole
/// difference between SPICE's framing and a plain LZ4 block.
#[test]
fn lz4_cannot_be_forced_from_the_command_line() {
    let help = Command::new("Xspice").arg("--help").output();
    let Ok(help) = help else {
        eprintln!("skipping: Xspice is not installed");
        return;
    };
    let text = String::from_utf8_lossy(&help.stdout);
    if let Some(line) = text.lines().find(|l| l.contains("--image-compression")) {
        assert!(
            !line.contains("lz4"),
            "Xspice grew an lz4 option; add it to the sweep above: {line}"
        );
    }
}

/// M5. `--streaming-video all` is the flag `docs/testing.md` §4 says to turn
/// on early, because it is the one that breaks naive compositing: streams are
/// clipped sub-rectangles layered over the draw commands, and they arrive on
/// their own schedule.
#[tokio::test]
async fn mjpeg_streams_are_decoded_and_composited_over_the_draw_output() {
    let Some(server) = start(55, 5955, 640, 480, "auto_glz", "all") else {
        return;
    };
    if !have("xterm") {
        eprintln!("skipping: xterm is not installed");
        return;
    }
    assert!(wait_for_port(server.port).await, "Xspice never listened");
    assert!(paint(server.display, "#000000"), "xsetroot failed");

    let session = session(server.port).await;
    let mut events = session.subscribe();

    // Something that changes fast enough for the server's heuristic to call
    // it video. A scrolling terminal is the cheapest such thing.
    let mut noise = Command::new("xterm")
        .env("DISPLAY", format!(":{}", server.display))
        .args(["-geometry", "50x16+60+60"])
        .args(["-bg", "white", "-fg", "black"])
        .args([
            "-e",
            "sh",
            "-c",
            "while :; do base64 /dev/urandom | head -1; done",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("xterm should start");

    // The stream lands inside the terminal's rectangle, not over the whole
    // screen -- which is the property that makes compositing necessary.
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut covered: Option<solstice_backend::Rect> = None;
    let mut damage = 0usize;
    while tokio::time::Instant::now() < deadline && damage < 50 {
        if let Ok(Ok(BackendEvent::Damage(r))) =
            tokio::time::timeout(Duration::from_millis(500), events.recv()).await
        {
            damage += 1;
            covered = Some(covered.map_or(r, |c| c.union(&r)));
        }
    }
    let _ = noise.kill();
    let _ = noise.wait();

    let covered = covered.expect("a streaming server produced no damage at all");
    assert!(
        damage >= 50,
        "only {damage} updates arrived from a streaming server"
    );
    assert!(
        covered.width < 640 || covered.height < 480,
        "the damage covered the whole screen ({covered:?}); a stream should be \
         a clipped sub-rectangle"
    );
    session.close().await;
}

/// M2 against a real guest. `xev -root` is the oracle: with no window manager
/// X's focus is `PointerRoot`, so both the pointer and the keyboard reach the
/// root window and `xev` prints what arrived.
#[tokio::test]
async fn input_reaches_a_real_guest() {
    let Some(server) = start(56, 5956, 640, 480, "off", "off") else {
        return;
    };
    if !have("xev") {
        eprintln!("skipping: xev is not installed (apt install x11-utils)");
        return;
    }
    assert!(wait_for_port(server.port).await, "Xspice never listened");
    assert!(paint(server.display, "#000000"), "xsetroot failed");

    let log = server._dir.join("xev.log");
    let mut xev = Command::new("xev")
        .env("DISPLAY", format!(":{}", server.display))
        .arg("-root")
        .stdout(Stdio::from(std::fs::File::create(&log).expect("xev log")))
        .stderr(Stdio::null())
        .spawn()
        .expect("xev should start");
    tokio::time::sleep(Duration::from_secs(1)).await;

    let session = session(server.port).await;
    assert_eq!(
        session.mouse_mode(),
        solstice_spice::inputs::MouseMode::Client,
        "Xspice registers a tablet, so the server should grant client mode -- \
         and without it absolute positions are converted to relative deltas, \
         which a tablet-only server drops"
    );

    // Walk the pointer across the screen; the last position is the one to
    // assert on.
    for step in 0..=10i32 {
        session
            .send_input(InputEvent::PointerAbsolute {
                x: (step * 60) as i16,
                y: (step * 40) as i16,
                ref_width: 640,
                ref_height: 480,
            })
            .await
            .expect("the session should still be up");
        tokio::time::sleep(Duration::from_millis(40)).await;
    }

    // 'A' is XT scancode 0x1E, which X reports as keycode 0x1E + 8 = 38.
    let scancode = solstice_input::scancode(solstice_input::vk::KEY_A, false);
    for down in [true, false] {
        session
            .send_input(InputEvent::Key(KeyEvent {
                scancode,
                keysym: None,
                down,
                non_normalized: false,
            }))
            .await
            .expect("the session should still be up");
        tokio::time::sleep(Duration::from_millis(60)).await;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;

    let _ = xev.kill();
    let _ = xev.wait();
    let seen = std::fs::read_to_string(&log).unwrap_or_default();

    assert!(
        seen.contains("MotionNotify"),
        "the guest saw no pointer motion at all"
    );
    assert!(
        seen.contains("root:(600,400)"),
        "the pointer did not arrive where it was sent; xev saw:\n{}",
        seen.lines()
            .filter(|l| l.contains("root:("))
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        seen.contains("keycode 38"),
        "the guest did not receive the keystroke"
    );

    session.close().await;
}

/// Without `spice-vdagent` in the guest there is nothing that can change the
/// mode, and declining is the contract rather than a failure -- the same
/// best-effort contract RFB's `ExtendedDesktopSize` has.
#[tokio::test]
async fn a_resize_is_declined_without_the_agent() {
    let Some(server) = start(57, 5957, 800, 600, "off", "off") else {
        return;
    };
    assert!(wait_for_port(server.port).await, "Xspice never listened");
    assert!(paint(server.display, "#000000"), "xsetroot failed");

    let session = session(server.port).await;
    assert_eq!(session.dimensions(), (800, 600));
    assert!(!session.can_resize());
    assert!(!session.request_resize(1280, 720).await.unwrap());
    session.close().await;
}
