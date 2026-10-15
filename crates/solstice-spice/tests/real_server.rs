//! T3: the client against a real QEMU guest.
//!
//! This tier used to be `Xspice`, which links the same `spice-server` library
//! QEMU does and could therefore cover the protocol without a VM. It covered
//! it well. What it could not reach was everything *above* the protocol: the
//! packaged launcher cannot start a `spice-vdagent` at all, and its video
//! driver renders through the frame buffer, so every draw command it ever
//! sent was a `DRAW_COPY` or a `DRAW_FILL`. A real guest closes both at once,
//! and `-spice` exposes the same knobs the `Xspice` launcher did --
//! `image-compression`, `streaming-video`, the WAN compression pair -- so
//! nothing was given up in the move. `docs/testing.md` §4 is the argument.
//!
//! Every test here keeps the shape the `Xspice` tests established:
//!
//! 1. boot a guest and paint its root window black;
//! 2. connect, and wait for the primary surface;
//! 3. repaint the root window a known colour **while connected**;
//! 4. assert every pixel of the framebuffer becomes that colour.
//!
//! Step 3 is the point, and against QEMU it is also mandatory rather than
//! merely wise: QEMU renders guest damage into its console surface only while
//! a display client is attached, so a repaint performed before connecting is
//! dropped outright. A test written the other way round fails for a reason
//! that has nothing to do with Solstice.
//!
//! Skipped with a printed note when QEMU or the guest image is missing:
//!
//! ```sh
//! ./tests/guest/build-image.sh
//! cargo test -p solstice-spice --test real_server -- --test-threads=4
//! ```

use std::sync::Arc;
use std::time::Duration;

use solstice_backend::{BackendEvent, InputEvent, KeyEvent, Session};
use solstice_spice::backend::{connect, SpiceConfig, SpiceSecurity, TcpDialer};
use solstice_test_guest::{Guest, GuestConfig, Spice};

const TIMEOUT: Duration = Duration::from_secs(30);

/// Boot a guest serving SPICE with one image codec and streaming mode forced.
///
/// Forcing beats hoping: the server's heuristics would otherwise pick, and a
/// test that does not know which codec it exercised has not covered one.
fn start(width: u32, height: u32, compression: &str, streaming: &str) -> Option<Guest> {
    Guest::start(
        GuestConfig::new().geometry(width, height).spice(
            Spice::new()
                .image_compression(compression)
                .streaming_video(streaming),
        ),
    )
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
    within: Duration,
) -> Result<usize, String> {
    let mut events = session.subscribe();
    let deadline = tokio::time::Instant::now() + within;
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

/// Paint the root window and wait for every pixel to become that colour,
/// re-issuing the paint if it does not land.
///
/// The retry is not papering over flakiness, it is the documented behaviour:
/// QEMU renders guest damage into its console surface only once a display
/// client is attached, and `connect` returning means the session is up, which
/// is a slightly earlier moment. A paint issued in that window is dropped
/// outright, with no error anywhere. Waiting for a damage event instead does
/// not work either -- the server's first update can precede `subscribe`, so
/// the wait simply hangs. Re-issuing is what actually converges.
async fn paint_and_wait(
    guest: &Guest,
    session: &solstice_spice::SpiceSession,
    colour: &str,
    expected: [u8; 4],
) -> Result<usize, String> {
    let overall = tokio::time::Instant::now() + TIMEOUT;
    let mut last = "the paint was never issued".to_owned();
    while tokio::time::Instant::now() < overall {
        guest.fill(colour).map_err(|e| e.to_string())?;
        match wait_for_solid(session, expected, Duration::from_secs(4)).await {
            Ok(damage) => return Ok(damage),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// The whole shape, parameterised by the server's image compression.
async fn incremental_repaint_test(compression: &str) {
    let Some(guest) = start(640, 480, compression, "off") else {
        return;
    };
    guest.fill("000000").expect("painting the guest black");

    let session = session(guest.spice_port()).await;
    assert_eq!(
        session.dimensions(),
        (640, 480),
        "the primary surface should have arrived before connect returned"
    );

    // Repaint *while connected*: the half a connect-time-only test cannot
    // reach, and the half QEMU will not render if nothing is attached.
    // #ff8040 is R=0xff, G=0x80, B=0x40; the framebuffer is BGRA.
    let damage = paint_and_wait(&guest, &session, "ff8040", [0x40, 0x80, 0xff, 0xff])
        .await
        .unwrap_or_else(|e| panic!("{compression}: {e}"));
    assert!(damage > 0, "{compression}: the repaint raised no damage");

    session.close().await;
}

/// The SPICE counterpart of `a_client_receives_the_pixels_of_a_real_vnc_desktop`:
/// raw images only, which is what the backend was built against first.
#[tokio::test]
async fn the_client_receives_the_pixels_of_a_real_spice_desktop() {
    incremental_repaint_test("off").await;
}

/// One `image-compression` value at a time. QUIC is the one where a single
/// desynchronised bit corrupts the rest of the image, so "every pixel is the
/// expected colour" is a real assertion rather than a smoke test.
#[tokio::test]
async fn quic_images_decode_against_the_real_encoder() {
    incremental_repaint_test("quic").await;
}

#[tokio::test]
async fn lz_images_decode_against_the_real_encoder() {
    incremental_repaint_test("lz").await;
}

/// GLZ is stateful: its dictionary spans the session, so a repaint that
/// refers back to an earlier image is the case worth having.
#[tokio::test]
async fn glz_images_decode_against_the_real_encoder() {
    incremental_repaint_test("glz").await;
}

/// What QEMU picks when nothing forces its hand.
#[tokio::test]
async fn auto_glz_is_what_qemu_defaults_to() {
    incremental_repaint_test("auto_glz").await;
}

/// LZ4 is in the protocol and in our decoder, but no server offers it from
/// the command line, so there is no end-to-end test to write. The decoder is
/// covered by its own unit tests instead, including the linked-block case
/// that is the whole difference between SPICE's framing and a plain LZ4
/// block. This asserts the premise rather than trusting it: if QEMU ever
/// accepts `lz4`, this fails and the sweep above should grow a case.
#[tokio::test]
async fn lz4_cannot_be_forced_from_the_command_line() {
    if solstice_test_guest::image_dir().join("vmlinuz").exists() {
        let rejected = std::process::Command::new("qemu-system-x86_64")
            .args(["-display", "none", "-monitor", "none", "-serial", "none"])
            .args(["-spice", "port=5999,addr=127.0.0.1,disable-ticketing=on,image-compression=lz4"])
            .output();
        let Ok(out) = rejected else {
            eprintln!("skipping: qemu-system-x86_64 is not installed");
            return;
        };
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(
            said.contains("invalid image compression"),
            "QEMU grew an lz4 option; add it to the sweep above. It said: {said}"
        );
    }
}

/// `streaming-video=all` is the flag `docs/testing.md` §4 says to turn on
/// early, because it is the one that breaks naive compositing: streams are
/// clipped sub-rectangles layered over the draw commands, and they arrive on
/// their own schedule.
#[tokio::test]
async fn mjpeg_streams_are_decoded_and_composited_over_the_draw_output() {
    let Some(guest) = start(640, 480, "auto_glz", "all") else {
        return;
    };
    guest.fill("000000").expect("painting the guest black");

    let session = session(guest.spice_port()).await;
    let mut events = session.subscribe();

    // Something that changes fast enough for the server's heuristic to call
    // it video. A scrolling terminal is the cheapest such thing.
    guest
        .sh("nohup xterm -geometry 50x16+60+60 -bg white -fg black \
             -e sh -c 'while :; do base64 /dev/urandom | head -1; done' \
             >/dev/null 2>&1 & echo started")
        .expect("starting the noise generator");

    // The stream lands inside the terminal's rectangle, not over the whole
    // screen -- which is the property that makes compositing necessary.
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut damage = 0usize;
    let mut full_surface = 0usize;
    let mut clipped: Option<solstice_backend::Rect> = None;
    while tokio::time::Instant::now() < deadline && damage < 50 {
        if let Ok(Ok(BackendEvent::Damage(r))) =
            tokio::time::timeout(Duration::from_millis(500), events.recv()).await
        {
            damage += 1;
            // QEMU repaints the whole surface once when a client attaches,
            // which is correct and says nothing about streaming. Unioning it
            // in would mask the property under test, so it is counted
            // separately rather than discarded silently.
            if r.width >= 640 && r.height >= 480 {
                full_surface += 1;
            } else {
                clipped = Some(clipped.map_or(r, |c| c.union(&r)));
            }
        }
    }
    let _ = guest.sh("pkill xterm");

    assert!(
        damage >= 50,
        "only {damage} updates arrived from a streaming server"
    );
    assert!(
        full_surface <= 2,
        "{full_surface} of {damage} updates repainted the whole surface; a \
         stream should be a clipped sub-rectangle layered over the draw output"
    );
    let covered = clipped.expect("every update repainted the whole surface");
    assert!(
        covered.width < 640 && covered.height < 480,
        "the clipped updates still covered the whole screen ({covered:?})"
    );
    session.close().await;
}

/// Input against a real guest. `xev -root` is the oracle: with no window
/// manager X's focus is `PointerRoot`, so both the pointer and the keyboard
/// reach the root window and `xev` prints what arrived.
#[tokio::test]
async fn input_reaches_a_real_guest() {
    let Some(guest) = start(640, 480, "off", "off") else {
        return;
    };
    guest.fill("000000").expect("painting the guest black");
    guest
        .sh("nohup xev -root >/tmp/xev.log 2>&1 & echo started")
        .expect("starting xev");

    let session = session(guest.spice_port()).await;
    assert_eq!(
        session.mouse_mode(),
        solstice_spice::inputs::MouseMode::Client,
        "with spice-vdagent running the server should grant client mode -- and \
         without it absolute positions are converted to relative deltas, which \
         a tablet-only server drops"
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

    let seen = guest.sh("cat /tmp/xev.log").unwrap_or_default();

    assert!(
        seen.contains("MotionNotify"),
        "the guest saw no pointer motion at all"
    );
    // Where the pointer actually landed. QEMU carries absolute positions over
    // a normalised 32768-step axis and the guest's device scales back one
    // short, so every position in the sweep arrives exactly one pixel low --
    // measured, not assumed: sending 60,40 through 600,400 in steps produced
    // 59,39 through 599,399, a uniform -1 rather than edge clamping. Solstice
    // sends the requested value unchanged (`inputs.rs` converts with the
    // packet's own reference geometry), so the pixel is lost below us and a
    // one-pixel tolerance is the honest assertion. It still catches a wrong
    // axis, a wrong scale, an inverted coordinate or a dropped event.
    let landed: Vec<(i32, i32)> = seen
        .lines()
        .filter_map(|l| l.split("root:(").nth(1))
        .filter_map(|l| l.split(')').next())
        .filter_map(|p| {
            let (x, y) = p.split_once(',')?;
            Some((x.trim().parse().ok()?, y.trim().parse().ok()?))
        })
        .collect();
    let near = |(x, y): (i32, i32), (tx, ty): (i32, i32)| {
        (x - tx).abs() <= 1 && (y - ty).abs() <= 1
    };
    assert!(
        landed.iter().any(|&p| near(p, (600, 400))),
        "the pointer never arrived where it was sent; xev saw: {:?}",
        landed.iter().rev().take(4).collect::<Vec<_>>()
    );
    // The whole sweep, not just its last point: a scale error that happens to
    // land the final position correctly is still a scale error.
    for step in 1..=10i32 {
        let target = (step * 60, step * 40);
        assert!(
            landed.iter().any(|&p| near(p, target)),
            "no pointer event near {target:?}; xev saw: {landed:?}"
        );
    }
    assert!(
        seen.contains("keycode 38"),
        "the guest did not receive the keystroke"
    );

    session.close().await;
}

/// Without `spice-vdagent` there is nothing that can change the mode, and
/// declining is the contract rather than a failure -- the same best-effort
/// contract RFB's `ExtendedDesktopSize` has.
///
/// Against `Xspice` this was the only configuration testable at all. Here it
/// has to be asked for, which is the better position to be in.
#[tokio::test]
async fn a_resize_is_declined_without_the_agent() {
    let Some(guest) = Guest::start(
        GuestConfig::new()
            .geometry(800, 600)
            .spice(Spice::new().image_compression("off").without_agent()),
    ) else {
        return;
    };
    guest.fill("000000").expect("painting the guest black");

    let session = session(guest.spice_port()).await;
    assert_eq!(session.dimensions(), (800, 600));
    assert!(!session.can_resize());
    assert!(!session.request_resize(1280, 720).await.unwrap());
    session.close().await;
}

/// Wait for a condition on the guest, polling rather than sleeping.
async fn guest_eventually(guest: &Guest, script: &str, wanted: &str) -> Result<String, String> {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut last = String::new();
    while tokio::time::Instant::now() < deadline {
        last = guest.sh(script).unwrap_or_default();
        if last.contains(wanted) {
            return Ok(last);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err(format!("`{script}` never produced {wanted:?}; last saw: {last:?}"))
}

/// `docs/roadmap.md` §2.7's first bullet: the client half is now validated,
/// and the guest half cannot be validated in this configuration.
///
/// Ignored because it cannot pass here, not because it is unfinished. What is
/// established, each by measurement:
///
/// - A real `spice-vdagent` and `spice-vdagentd` run and connect, the server
///   grants the agent tunnel 10 tokens, the guest announces its capabilities,
///   `can_resize()` becomes true, and mouse mode flips to `Client`. (Getting
///   there needed three guest fixes, each of which fails silently:
///   `spice-vdagentd` takes `-x` not `-X`; it needs the `uinput` module; and
///   it needs `/run/spice-vdagentd/` plus a machine-id.)
///
/// - **Solstice's agent tunnel is correct.** A `CLIPBOARD_GRAB` emitted in the
///   same drain, immediately before the monitors config, arrives at
///   `spice-vdagentd` and is forwarded to `spice-vdagent`. So the
///   `VDAgentMessage` framing, the `AGENT_DATA` carriage and the token flow
///   all work; this was the question that mattered and it is answered.
///
/// - The `MONITORS_CONFIG` itself is well-formed: one 48-byte `AGENT_DATA`,
///   a 20-byte header and a 28-byte body of `num_of_monitors=1, flags=0,
///   height, width, depth=32, x=0, y=0`, exactly as `vd_agent.h` specifies.
///
/// - It never reaches the agent, and that is `spice-server` behaving as
///   designed: it intercepts `VD_AGENT_MONITORS_CONFIG` rather than
///   forwarding it, and applies it to the QXL device itself. The device then
///   does not act on it -- the kernel's preferred mode never moves.
///
/// - **A reference client cannot resize this guest either.** `remote-viewer`,
///   with auto-resize enabled, scales the display instead and sends no
///   monitors config at all, while its other agent messages (max-clipboard,
///   volume sync, clipboard grab) arrive normally. A known-good client
///   declining to even try is its own evidence about the guest side.
///
/// So the remaining gap is QEMU's QXL monitors-config handling in this
/// configuration, not Solstice. What stays genuinely unvalidated is the
/// *response* path -- that Solstice tracks a geometry change the guest
/// actually makes -- which needs a guest that can resize at all. Worth
/// revisiting with a different QXL device configuration, or a `virtio-gpu`
/// guest, before concluding anything about the backend.
///
/// `a_resize_is_declined_without_the_agent` is unaffected and still passes.
#[tokio::test]
#[ignore = "QEMU's QXL does not act on a monitors config here; remote-viewer cannot resize this guest either"]
async fn a_real_agent_grants_and_applies_a_resize() {
    let Some(guest) = start(800, 600, "off", "off") else {
        return;
    };
    let session = session(guest.spice_port()).await;
    assert_eq!(session.dimensions(), (800, 600));

    // The agent connects once a client attaches, so its capabilities arrive
    // shortly after `connect` returns rather than during it. This part works.
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while tokio::time::Instant::now() < deadline && !session.can_resize() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        session.can_resize(),
        "spice-vdagent is running, so the server should have advertised \
         MONITORS_CONFIG; the guest said: {}",
        guest.sh("pgrep -a spice-vdagent").unwrap_or_default()
    );

    assert!(
        session
            .request_resize(1152, 864)
            .await
            .expect("the session should still be up"),
        "a resize was declined with the agent running"
    );

    // 1152x864 deliberately, not 1024x768: the latter is already this
    // device's default preferred mode, so asking for it would be
    // indistinguishable from nothing happening.
    guest_eventually(&guest, "head -1 /sys/class/drm/card0-Virtual-1/modes", "1152x864")
        .await
        .unwrap_or_else(|e| {
            panic!(
                "the request never reached the guest's device: {e}\n--- vdagentd ---\n{}",
                guest.sh("tail -20 /var/log/vdagentd.log").unwrap_or_default()
            )
        });

    guest_eventually(&guest, "xdpyinfo | grep dimensions", "1152x864")
        .await
        .unwrap_or_else(|e| panic!("the guest never changed mode: {e}"));

    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while tokio::time::Instant::now() < deadline && session.dimensions() != (1152, 864) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        session.dimensions(),
        (1152, 864),
        "the guest resized but the client's geometry did not follow"
    );

    session.close().await;
}
