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
//! Every test runs on a **multi-threaded** runtime, and that is load-bearing
//! rather than a speed-up. The `Guest` calls block: they poll the guest agent
//! with `std::thread::sleep`. On the default single-threaded runtime that
//! freezes the client for as long as the guest command runs -- no reads, no
//! `ACK`s, no `PONG`s. A command that draws more than the server's ack
//! window (40 messages) then deadlocks: `spice-server` stops sending until it
//! is acked, stops draining the QXL command ring while its pipe is full, the
//! guest's X server blocks in `qxl_ring_push`, and the command never returns.
//! After 30 s without a pong the server drops the client, everything
//! unblocks, and the test fails with a timeout that looks like a slow guest.
//! A 64-line stroke is ~480 commands and reproduces it every time.
//!
//! A multi-threaded runtime is not enough on its own either, which is why the
//! `Guest` here is a wrapper that blocks through `block_in_place`; its doc
//! comment has the reason.
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
use solstice_spice::{ClipboardEvent, ClipboardType};
use solstice_test_guest::{Display, GuestConfig, Spice};

const TIMEOUT: Duration = Duration::from_secs(30);

/// The harness's guest, with every call that can block made through
/// `block_in_place`.
///
/// A multi-threaded runtime is necessary but not obviously sufficient: a
/// worker blocked in a guest call can still be holding the session's next
/// task in its LIFO slot, which other workers do not steal, and the client
/// would then freeze as it does on one thread (see the module comment).
/// `block_in_place` hands the worker's queue to another thread before
/// blocking, which closes that possibility. The GLZ soak still stalls under
/// TCG, and that one is the guest's QXL driver rather than the client:
/// `docs/roadmap.md` §2.7, and [`Guest::stall_report`] for how it was found.
struct Guest(solstice_test_guest::Guest);

impl Guest {
    fn start(config: GuestConfig) -> Option<Self> {
        tokio::task::block_in_place(|| solstice_test_guest::Guest::start(config)).map(Guest)
    }

    fn spice_port(&self) -> u16 {
        self.0.spice_port()
    }

    fn fill(&self, rrggbb: &str) -> solstice_test_guest::Result<()> {
        tokio::task::block_in_place(|| self.0.fill(rrggbb))
    }

    fn draw(&self, primitive: &str, args: &[&str]) -> solstice_test_guest::Result<()> {
        tokio::task::block_in_place(|| self.0.draw(primitive, args))
    }

    fn sh(&self, script: &str) -> solstice_test_guest::Result<String> {
        tokio::task::block_in_place(|| self.0.sh(script))
    }

    fn screendump(&self) -> solstice_test_guest::Result<solstice_test_guest::Ppm> {
        tokio::task::block_in_place(|| self.0.screendump())
    }

    fn stall_report(&self) -> String {
        tokio::task::block_in_place(|| self.0.stall_report())
    }
}

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
    // Warnings on by default: the client reports a display error by logging
    // it and closing the display, and without a subscriber that looked like a
    // server that had simply gone quiet (`docs/roadmap.md` §2.7).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_test_writer()
        .try_init();
    let dialer = Arc::new(TcpDialer::new(config(port)));
    tokio::time::timeout(TIMEOUT, connect(dialer, config(port)))
        .await
        .expect("connect timed out")
        .expect("connect failed")
}

/// Wait until every pixel of the framebuffer is `expected`, or give up,
/// counting the damage events seen on `events` along the way.
///
/// The receiver comes from the caller so that it can subscribe *before* it
/// paints: subscribing here, after the paint was issued, raced the paint on a
/// multi-threaded runtime and counted zero damage for a repaint that had
/// already landed.
async fn wait_for_solid(
    session: &solstice_spice::SpiceSession,
    events: &mut tokio::sync::broadcast::Receiver<BackendEvent>,
    expected: [u8; 4],
    within: Duration,
) -> Result<usize, String> {
    let deadline = tokio::time::Instant::now() + within;
    let mut damage = 0usize;
    loop {
        {
            let fb = session.framebuffer();
            let fb = fb.read();
            let mut pixels = fb.data().chunks_exact(4);
            if pixels.len() > 0 && pixels.all(|px| px == expected) {
                break;
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
    // The display task writes the framebuffer *then* announces the damage,
    // so the pixels can be seen before the event that put them there. Give
    // that event a moment rather than reporting a repaint with no damage.
    let settle = tokio::time::Instant::now() + Duration::from_secs(1);
    while damage == 0 && tokio::time::Instant::now() < settle {
        if let Ok(Ok(BackendEvent::Damage(_))) =
            tokio::time::timeout(Duration::from_millis(100), events.recv()).await
        {
            damage += 1;
        }
    }
    Ok(damage)
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
    let mut events = session.subscribe();
    while tokio::time::Instant::now() < overall {
        guest.fill(colour).map_err(|e| e.to_string())?;
        match wait_for_solid(session, &mut events, expected, Duration::from_secs(4)).await {
            Ok(damage) => return Ok(damage),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// The `image_type`s a forced `image-compression` may legitimately produce.
///
/// More than one each, because the server falls back: QUIC is skipped for
/// images too small to be worth it, LZ picks the palette variant for few
/// colours, and the GLZ modes send plain LZ for anything that will not
/// enter the shared window.
fn image_kinds_for(compression: &str) -> &'static [u8] {
    use solstice_spice::protocol::image_type::*;
    match compression {
        "off" => &[BITMAP],
        "quic" => &[QUIC],
        "lz" => &[LZ_RGB, LZ_PLT],
        "glz" => &[GLZ_RGB, ZLIB_GLZ_RGB],
        "auto_glz" => &[GLZ_RGB, ZLIB_GLZ_RGB, QUIC],
        other => panic!("no expectation for image-compression={other}"),
    }
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

    // A solid repaint is not enough on its own. It arrives as a `DRAW_FILL`,
    // which carries no image, so until the counts below existed this sweep
    // passed for every codec while decoding exactly one `LZ_RGB` image -- the
    // screen QEMU sends on connect -- whatever was forced. Glyphs and an XOR
    // stipple are what make the guest's QXL driver send bitmaps
    // (`DRAW_COPY`), and holding the result against QEMU's screendump makes
    // every decoded pixel count, not only the ones a colour predicted.
    //
    // Counted from here rather than from connect, because that first screen
    // is sent before the server has heard anything from this client and so
    // says nothing about the codec being forced.
    let before = session.image_counts();
    guest.draw("text", &[]).unwrap_or_else(|e| {
        panic!(
            "{}: {e}\nin the guest:\n{}",
            "drawing text",
            guest.stall_report()
        )
    });
    guest.draw("rop3", &["16"]).expect("drawing a stipple");
    wait_for_screendump(&session, &guest, TIMEOUT)
        .await
        .unwrap_or_else(|e| panic!("{compression}: {e}"));

    let decoded: std::collections::BTreeMap<u8, u64> = session
        .image_counts()
        .into_iter()
        .map(|(kind, n)| (kind, n - before.get(&kind).copied().unwrap_or(0)))
        .filter(|&(_, n)| n > 0)
        .collect();
    let expected = image_kinds_for(compression);
    assert!(
        !decoded.is_empty() && decoded.keys().all(|kind| expected.contains(kind)),
        "{compression}: expected only image types {expected:?} after the repaint, \
         decoded {decoded:?}; draws {:?}",
        session.draw_counts()
    );

    session.close().await;
}

/// The SPICE counterpart of `a_client_receives_the_pixels_of_a_real_vnc_desktop`:
/// raw images only, which is what the backend was built against first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_client_receives_the_pixels_of_a_real_spice_desktop() {
    incremental_repaint_test("off").await;
}

/// One `image-compression` value at a time. QUIC is the one where a single
/// desynchronised bit corrupts the rest of the image, so "every pixel is the
/// expected colour" is a real assertion rather than a smoke test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_images_decode_against_the_real_encoder() {
    incremental_repaint_test("quic").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lz_images_decode_against_the_real_encoder() {
    incremental_repaint_test("lz").await;
}

/// GLZ is stateful: its dictionary spans the session, so a repaint that
/// refers back to an earlier image is the case worth having.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn glz_images_decode_against_the_real_encoder() {
    incremental_repaint_test("glz").await;
}

/// What QEMU picks when nothing forces its hand.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_glz_is_what_qemu_defaults_to() {
    incremental_repaint_test("auto_glz").await;
}

/// LZ4 is in the protocol and in our decoder, but no server offers it from
/// the command line, so there is no end-to-end test to write. The decoder is
/// covered by its own unit tests instead, including the linked-block case
/// that is the whole difference between SPICE's framing and a plain LZ4
/// block. This asserts the premise rather than trusting it: if QEMU ever
/// accepts `lz4`, this fails and the sweep above should grow a case.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lz4_cannot_be_forced_from_the_command_line() {
    if solstice_test_guest::image_dir().join("vmlinuz").exists() {
        let rejected = std::process::Command::new("qemu-system-x86_64")
            .args(["-display", "none", "-monitor", "none", "-serial", "none"])
            .args([
                "-spice",
                "port=5999,addr=127.0.0.1,disable-ticketing=on,image-compression=lz4",
            ])
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

/// How many pixels differ between the session's framebuffer and QEMU's own
/// capture of the same screen, and where the first one is.
fn compare_with_screendump(
    session: &solstice_spice::SpiceSession,
    guest: &Guest,
) -> (usize, Option<(u32, u32)>) {
    let Ok(dump) = guest.screendump() else {
        return (usize::MAX, None);
    };
    let fb = session.framebuffer();
    let fb = fb.read();
    assert_eq!((dump.width, dump.height), (fb.width(), fb.height()));
    let mut differ = 0;
    let mut first = None;
    for (i, (bgra, rgb)) in fb
        .data()
        .chunks_exact(4)
        .zip(dump.rgb.chunks_exact(3))
        .enumerate()
    {
        if [bgra[2], bgra[1], bgra[0]] != [rgb[0], rgb[1], rgb[2]] {
            differ += 1;
            first.get_or_insert((i as u32 % fb.width(), i as u32 / fb.width()));
        }
    }
    (differ, first)
}

/// `docs/roadmap.md` §2.7 had `DRAW_STROKE`, `DRAW_TEXT` and `DRAW_ROP3` as
/// "reachable but not asserted": `solstice-draw stroke|text|rop3` drives the
/// core X11 primitives that were meant to force them out of the QXL driver.
/// Counting what arrives shows they are not reachable from this guest at
/// all. `xf86-video-qxl` accelerates only solid fills, copies, composites and
/// uploads; everything else is rendered in software and sent as the result:
///
/// | primitive | what arrives |
/// |---|---|
/// | `stroke 1` | ~480 one-pixel `DRAW_FILL`s, one per span of the line |
/// | `text` | a `DRAW_COPY` per glyph run |
/// | `rop3` | a `DRAW_COPY` per rectangle, the XOR already applied |
///
/// So this asserts what *is* true -- each primitive's output is exact
/// against QEMU's screendump, through the commands it really produces --
/// and keeps the original premise as a tripwire. A guest whose driver starts
/// emitting one of the three fails here, and that failure is the news: the
/// executor for it exists and is unit-tested, and this is where it would
/// first meet a real server. Until then the route to them is a Windows guest,
/// whose QXL driver is the one that does emit them.
///
/// One session for all three, in sequence, so each lands on the previous
/// one's output: the stipple is an XOR, and XOR over lines and glyphs is a
/// stronger test than XOR over a flat background.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn core_x11_primitives_reach_the_screen_exactly_through_fills_and_copies() {
    use solstice_spice::protocol::display_msg;

    let Some(guest) = start(640, 480, "off", "off") else {
        return;
    };
    guest.fill("000000").expect("painting the guest black");
    let session = session(guest.spice_port()).await;
    paint_and_wait(&guest, &session, "2e3436", [0x36, 0x34, 0x2e, 0xff])
        .await
        .expect("the background never arrived");

    for (primitive, args, carrier) in [
        ("stroke", &["64"][..], display_msg::DRAW_FILL),
        ("text", &[][..], display_msg::DRAW_COPY),
        ("rop3", &["16"][..], display_msg::DRAW_COPY),
    ] {
        let before = session.draw_counts().get(&carrier).copied().unwrap_or(0);
        guest.draw(primitive, args).expect("drawing in the guest");
        wait_for_screendump(&session, &guest, TIMEOUT)
            .await
            .unwrap_or_else(|e| panic!("{primitive}: {e}"));
        let after = session.draw_counts().get(&carrier).copied().unwrap_or(0);
        assert!(
            after > before,
            "{primitive}: no command of kind {carrier} arrived; the session saw {:?}",
            session.draw_counts()
        );
    }

    let draws = session.draw_counts();
    for kind in [
        display_msg::DRAW_STROKE,
        display_msg::DRAW_TEXT,
        display_msg::DRAW_ROP3,
    ] {
        assert!(
            !draws.contains_key(&kind),
            "the guest emitted draw kind {kind}, which xf86-video-qxl was not \
             known to; update docs/roadmap.md §2.7 and assert it here instead. \
             Draws: {draws:?}"
        );
    }
    session.close().await;
}

/// Input against a real guest. `xev -root` is the oracle: with no window
/// manager X's focus is `PointerRoot`, so both the pointer and the keyboard
/// reach the root window and `xev` prints what arrived.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn input_reaches_a_real_guest() {
    let Some(guest) = start(640, 480, "off", "off") else {
        return;
    };
    guest.fill("000000").expect("painting the guest black");
    guest
        .sh("nohup xev -root >/tmp/xev.log 2>&1 & echo started")
        .expect("starting xev");

    let session = session(guest.spice_port()).await;
    // Waited for rather than asserted at connect: the agent may attach after
    // this client did, and then client mode is offered in a later
    // `MAIN_MOUSE_MODE` and has to be asked for again. Under TCG it reliably
    // is later. Before the client re-asked, this never arrived at all.
    let waited = tokio::time::Instant::now();
    while session.mouse_mode() != solstice_spice::inputs::MouseMode::Client
        && waited.elapsed() < TIMEOUT
    {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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
    let near =
        |(x, y): (i32, i32), (tx, ty): (i32, i32)| (x - tx).abs() <= 1 && (y - ty).abs() <= 1;
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    Err(format!(
        "`{script}` never produced {wanted:?}; last saw: {last:?}"
    ))
}

/// The same resize on QXL, which no client can do here.
///
/// Ignored because the device cannot serve it in this configuration, which
/// was established by controlled experiment rather than inferred. Pointing
/// `remote-viewer` at a freshly booted QXL guest -- same image, same age,
/// same guest userspace as this test's -- also only scales: the guest's
/// resolution does not change. Against virtio-gpu the same client resizes
/// correctly, and so does Solstice. **Solstice therefore behaves exactly as
/// the reference client does on both devices**, which is the result that
/// matters; the earlier suspicion that it had a QXL-specific bug came from
/// comparing a fresh guest against a long-lived one and is withdrawn.
///
/// (A long-running QXL guest did once accept a monitors config from
/// remote-viewer, moving its preferred mode to the window's client area. A
/// fresh one does not, from either client. Whatever changes in that guest
/// over time is a QEMU/QXL curiosity and not a property of this client.)
///
/// Along the way, ruled out as causes on our side: the message encoding,
/// verified byte by byte against `vd_agent.h`; the capability gate; token
/// starvation; the `AGENT_START` token count; the requested size; guest
/// settling time; and the `flags`, `depth` and `num_of_monitors` fields.
///
/// The practical consequence is in [`Display`]: agent tests use
/// `VirtioGpu`, and `Qxl` stays the default for the image-codec and
/// draw-command tests, which need the device a real SPICE guest has.
///
/// `a_resize_is_declined_without_the_agent` is unaffected and still passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "QXL cannot resize here; remote-viewer fails identically on a fresh QXL guest"]
async fn a_real_agent_grants_and_applies_a_resize() {
    resize_test(Display::Qxl).await;
}

/// The same thing on `virtio-gpu`, where `spice-server` has no QXL instance
/// to hand the monitors config to and should forward it to the agent instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_agent_grants_and_applies_a_resize_on_virtio_gpu() {
    resize_test(Display::VirtioGpu).await;
}

async fn resize_test(display: Display) {
    let Some(guest) = Guest::start(
        GuestConfig::new()
            .geometry(800, 600)
            .display(display)
            .spice(Spice::new().image_compression("off")),
    ) else {
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
    guest_eventually(&guest, "xdpyinfo | grep dimensions", "1152x864")
        .await
        .unwrap_or_else(|e| {
            panic!(
                "{display:?}: the guest never changed mode: {e}\n--- drm preferred ---\n{}\n--- drm modes ---\n{}",
                guest.sh("head -1 /sys/class/drm/card0-Virtual-1/modes").unwrap_or_default(),
                guest.sh("head -c 90 /sys/class/drm/card0-Virtual-1/modes | tr '\\n' ' '").unwrap_or_default(),
            )
        });

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

// ---------------------------------------------------------------------------
// The clipboard, against a real `spice-vdagent`.
//
// `docs/roadmap.md` §2.7 recorded this as unfinished rather than untested:
// the agent could encode every clipboard message and nothing above it could
// ask for one. These are what make it reachable, and they are the first
// thing to point at a real agent -- a mock cannot say whether vdagent agrees
// with this client about the capability gate, the framing, or whether a
// selection word belongs in front of the type.
// ---------------------------------------------------------------------------

/// Wait for a clipboard event matching `want`, discarding the ones before it.
///
/// Discarding rather than asserting on the first: a real agent announces, and
/// X's selection ownership changes, on their own schedule, so an unrelated
/// grab arriving first is normal rather than a failure.
async fn clipboard_event(
    guest: &Guest,
    events: &mut tokio::sync::broadcast::Receiver<ClipboardEvent>,
    want: impl Fn(&ClipboardEvent) -> bool,
) -> ClipboardEvent {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut seen = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, events.recv()).await {
            Ok(Ok(event)) if want(&event) => return event,
            Ok(Ok(event)) => seen.push(event),
            Ok(Err(e)) => panic!("the clipboard channel ended: {e}; saw {seen:?}"),
            // The guest's own logs, because every way this times out is a
            // disagreement with the agent and the agent is the one keeping
            // notes: a refused capability, a message it could not parse, or
            // a selection it never took ownership of.
            Err(_) => panic!(
                "no matching clipboard event in {TIMEOUT:?}; saw {seen:?}\n\
                 --- vdagent ---\n{}\n--- vdagentd ---\n{}",
                guest
                    .sh("tail -25 /var/log/vdagent.log")
                    .unwrap_or_default(),
                guest
                    .sh("tail -25 /var/log/vdagentd.log")
                    .unwrap_or_default(),
            ),
        }
    }
}

/// A session whose guest agent has announced that it will do clipboards.
///
/// Like `can_resize`, this is false when `connect` returns and becomes true
/// shortly afterwards: the agent attaches once a client does.
async fn clipboard_session(guest: &Guest) -> solstice_spice::SpiceSession {
    let session = session(guest.spice_port()).await;
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while tokio::time::Instant::now() < deadline && !session.can_clipboard() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        session.can_clipboard(),
        "spice-vdagent is running, so it should have announced CLIPBOARD and \
         CLIPBOARD_BY_DEMAND; the guest said: {}\n--- vdagent ---\n{}",
        guest.sh("pgrep -a spice-vdagent").unwrap_or_default(),
        guest
            .sh("tail -20 /var/log/vdagent.log")
            .unwrap_or_default(),
    );
    session
}

/// Guest to client: a copy inside the guest is offered, asked for, and
/// arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_agent_hands_over_the_guests_clipboard() {
    let Some(guest) = start(640, 480, "off", "off") else {
        return;
    };
    let session = clipboard_session(&guest).await;
    let mut events = session.subscribe_clipboard();

    // `-loops 0` keeps xclip serving the selection rather than exiting after
    // the first paste: vdagent reads it once to answer this client, and a
    // re-run of the test should not depend on how many times it asked.
    guest
        .sh(
            "printf 'solstice says hello' | nohup xclip -selection clipboard -loops 0 -i \
             >/tmp/xclip.log 2>&1 & echo started",
        )
        .expect("setting the guest clipboard");

    let offer = clipboard_event(
        &guest,
        &mut events,
        |e| matches!(e, ClipboardEvent::Offered(types) if types.contains(&ClipboardType::Utf8Text)),
    )
    .await;
    assert!(
        matches!(&offer, ClipboardEvent::Offered(types) if types.contains(&ClipboardType::Utf8Text)),
        "{offer:?}"
    );

    assert!(
        session
            .request_clipboard(ClipboardType::Utf8Text)
            .await
            .expect("the session should still be up"),
        "a request was declined with the agent running"
    );

    let data = clipboard_event(&guest, &mut events, |e| {
        matches!(e, ClipboardEvent::Data { .. } | ClipboardEvent::Unavailable)
    })
    .await;
    match data {
        ClipboardEvent::Data { kind, data } => {
            assert_eq!(kind, ClipboardType::Utf8Text);
            assert_eq!(
                String::from_utf8_lossy(&data),
                "solstice says hello",
                "the payload is not what the guest copied"
            );
        }
        other => panic!(
            "the guest refused its own offer: {other:?}\n--- vdagent ---\n{}",
            guest
                .sh("tail -20 /var/log/vdagent.log")
                .unwrap_or_default()
        ),
    }

    session.close().await;
}

/// Client to guest: an offer, the guest's request for it, and the answer
/// landing in a guest-side paste.
///
/// This is the half a mock cannot settle. The guest only asks once X tells
/// `spice-vdagent` the selection changed owner, and it only pastes once the
/// answer comes back through the same tunnel -- so a wrong capability gate, a
/// wrong framing, or a missing reply all show up here as a paste that never
/// completes.
///
/// Both ends retry, and both for the same reason: an offer and an X selection
/// ownership change are not the same event. `xclip -o` run before
/// `spice-vdagent` owns the selection exits immediately with "target not
/// available" rather than waiting, so the guest asks in a loop -- and every
/// one of those attempts is a real request this client has to answer, which
/// is why the answering is a task rather than one call. A consumer that
/// answered only the first request would hang the guest on the second.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_agent_takes_the_clipboard_this_client_offers() {
    let Some(guest) = start(640, 480, "off", "off") else {
        return;
    };
    let session = Arc::new(clipboard_session(&guest).await);
    let mut events = session.subscribe_clipboard();

    let answered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let answering = tokio::spawn({
        let session = session.clone();
        let answered = answered.clone();
        async move {
            while let Ok(event) = events.recv().await {
                if event != ClipboardEvent::Requested(ClipboardType::Utf8Text) {
                    continue;
                }
                session
                    .send_clipboard(ClipboardType::Utf8Text, b"solstice answers")
                    .await
                    .expect("the session should still be up");
                answered.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    });

    assert!(
        session
            .offer_clipboard(&[ClipboardType::Utf8Text])
            .await
            .expect("the session should still be up"),
        "an offer was declined with the agent running"
    );

    guest
        .sh("nohup sh -c 'for _ in $(seq 1 60); do \
                 xclip -selection clipboard -o >/tmp/paste.txt 2>/tmp/paste.err; \
                 [ -s /tmp/paste.txt ] && break; sleep 0.5; \
             done' >/dev/null 2>&1 & echo started")
        .expect("starting the guest-side paste");

    guest_eventually(&guest, "cat /tmp/paste.txt", "solstice answers")
        .await
        .unwrap_or_else(|e| {
            panic!(
                "the guest never pasted what this client sent: {e}\n\
                 answered {} request(s)\n--- xclip ---\n{}\n--- vdagent ---\n{}",
                answered.load(std::sync::atomic::Ordering::Relaxed),
                guest.sh("cat /tmp/paste.err").unwrap_or_default(),
                guest
                    .sh("tail -25 /var/log/vdagent.log")
                    .unwrap_or_default(),
            )
        });
    assert!(
        answered.load(std::sync::atomic::Ordering::Relaxed) >= 1,
        "the guest pasted without ever asking this client for the bytes"
    );

    // And withdrawing the offer is heard: `spice-vdagent` gives up ownership
    // of the X selection, so a guest-side paste stops finding one.
    assert!(session
        .release_clipboard()
        .await
        .expect("the session should still be up"));
    guest_eventually(
        &guest,
        "rm -f /tmp/after.txt; xclip -selection clipboard -o >/tmp/after.txt 2>&1; \
         cat /tmp/after.txt",
        "target STRING not available",
    )
    .await
    .expect("the agent kept serving a clipboard this client had withdrawn");

    answering.abort();
    session.close().await;
}

/// Without `spice-vdagent` there is no clipboard at all, and declining is
/// the contract rather than a failure -- the same shape
/// `a_resize_is_declined_without_the_agent` asserts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_clipboard_is_declined_without_the_agent() {
    let Some(guest) = Guest::start(
        GuestConfig::new()
            .geometry(640, 480)
            .spice(Spice::new().image_compression("off").without_agent()),
    ) else {
        return;
    };
    let session = session(guest.spice_port()).await;
    assert!(!session.can_clipboard());
    assert!(!session
        .offer_clipboard(&[ClipboardType::Utf8Text])
        .await
        .unwrap());
    assert!(!session
        .request_clipboard(ClipboardType::Utf8Text)
        .await
        .unwrap());
    assert!(!session
        .send_clipboard(ClipboardType::Utf8Text, b"nobody is listening")
        .await
        .unwrap());
    session.close().await;
}

/// How long one Opus packet plays, in tenths of a millisecond, read from its
/// TOC byte (RFC 6716 §3.1). Tenths because CELT's shortest frame is 2.5 ms.
fn opus_packet_tenths_ms(packet: &[u8]) -> Option<u32> {
    let toc = *packet.first()?;
    let config = toc >> 3;
    let frame = match config {
        0..=11 => [100, 200, 400, 600][config as usize % 4],
        12..=15 => [100, 200][config as usize % 2],
        _ => [25, 50, 100, 200][config as usize % 4],
    };
    let frames = match toc & 0x3 {
        0 => 1,
        1 | 2 => 2,
        _ => u32::from(*packet.get(1)? & 0x3f),
    };
    Some(frame * frames)
}

/// `docs/roadmap.md` §2.7 asks whether guest audio can be **repacketised**
/// into GameStream rather than transcoded, and says the answer turns on the
/// Opus frame duration matching `x-nv-aqos.packetDuration`. This measures
/// the duration a real `spice-server` produces instead of guessing it.
///
/// A sine from `speaker-test` rather than silence, because an encoder is
/// entitled to treat silence specially.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_audio_arrives_as_opus_packets_of_one_fixed_duration() {
    let Some(guest) = Guest::start(
        GuestConfig::new()
            .geometry(640, 480)
            .spice(Spice::new().audio()),
    ) else {
        return;
    };
    let config = SpiceConfig {
        audio: true,
        ..config(guest.spice_port())
    };
    let dialer = Arc::new(TcpDialer::new(config.clone()));
    let session = tokio::time::timeout(TIMEOUT, connect(dialer, config))
        .await
        .expect("connect timed out")
        .expect("connect failed");
    let mut audio = session
        .take_audio()
        .expect("the server should offer a playback channel");

    guest
        .sh("nohup speaker-test -t sine -f 440 -c 2 -r 48000 -l 0 \
             >/tmp/speaker-test.log 2>&1 & echo started")
        .expect("starting the tone");

    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut frames = Vec::new();
    while frames.len() < 200 && tokio::time::Instant::now() < deadline {
        if let Ok(Some(frame)) =
            tokio::time::timeout(Duration::from_millis(500), audio.recv()).await
        {
            frames.push(frame);
        }
    }
    let _ = guest.sh("pkill speaker-test");
    assert!(
        frames.len() >= 200,
        "only {} audio frames arrived; the guest said: {}",
        frames.len(),
        guest.sh("cat /tmp/speaker-test.log").unwrap_or_default()
    );

    for frame in &frames {
        assert_eq!(
            frame.format,
            solstice_backend::AudioFormat::Opus {
                sample_rate: 48_000,
                channels: 2
            },
            "the server should honour the OPUS capability this client asked for"
        );
    }
    let durations: std::collections::BTreeMap<Option<u32>, usize> =
        frames.iter().fold(Default::default(), |mut seen, frame| {
            *seen.entry(opus_packet_tenths_ms(&frame.data)).or_default() += 1;
            seen
        });
    eprintln!("opus packet durations (tenths of a ms -> count): {durations:?}");
    assert_eq!(
        durations.keys().copied().collect::<Vec<_>>(),
        vec![Some(100)],
        "every packet should be one 10 ms frame"
    );
    session.close().await;
}

/// Wait until the session's framebuffer equals QEMU's screendump, or give up
/// with how far apart they were.
async fn wait_for_screendump(
    session: &solstice_spice::SpiceSession,
    guest: &Guest,
    within: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let (differ, first) = compare_with_screendump(session, guest);
        if differ == 0 {
            return Ok(());
        }
        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "{differ} pixels differ from QEMU's screendump, the first at {first:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// `docs/roadmap.md` §2.7: GLZ's dictionary spans the session, and its bugs
/// are in window management -- eviction, wrap-around, an image referring to
/// one that has since left the window -- none of which a single repaint
/// reaches. This drives the window well past full with changing content and
/// holds the screen against QEMU's screendump as it goes.
///
/// Not a merge gate: it is minutes long under TCG. Run it on demand, with
/// `SOLSTICE_GLZ_SOAK_ROUNDS` to make it longer still:
///
/// ```sh
/// cargo test -p solstice-spice --test real_server -- --ignored glz_soak
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a soak, not a merge gate: run with --ignored"]
async fn glz_soak_keeps_the_screen_exact_across_thousands_of_images() {
    let rounds: usize = std::env::var("SOLSTICE_GLZ_SOAK_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400);
    // Twice QEMU's default QXL RAM. With the default, the guest kernel's
    // QXL driver runs out under TCG and blocks waiting for the device to
    // release memory, which stalls the soak for reasons that have nothing to
    // do with GLZ (`docs/roadmap.md` §2.7).
    let Some(guest) = Guest::start(
        GuestConfig::new()
            .geometry(640, 480)
            .qxl_ram_mb(128)
            .spice(Spice::new().image_compression("glz").streaming_video("off")),
    ) else {
        return;
    };
    guest.fill("000000").expect("painting the guest black");
    let session = session(guest.spice_port()).await;
    paint_and_wait(&guest, &session, "202020", [0x20, 0x20, 0x20, 0xff])
        .await
        .expect("the first paint never arrived");

    for round in 0..rounds {
        // A colour per round from a cheap mixing step, so consecutive
        // repaints neither repeat nor share a palette, then glyphs and
        // lines over it so the images are not all flat.
        let mixed = (round as u32).wrapping_mul(0x9E37_79B9) >> 8;
        guest.fill(&format!("{mixed:06x}")).unwrap_or_else(|e| {
            panic!(
                "{}: {e}\nin the guest:\n{}",
                "painting the guest",
                guest.stall_report()
            )
        });
        guest
            .draw("text", &[&format!("glz soak round {round}")])
            .unwrap_or_else(|e| {
                panic!("drawing text: {e}\nin the guest:\n{}", guest.stall_report())
            });
        guest
            .draw("stroke", &[&(8 + round % 56).to_string()])
            .unwrap_or_else(|e| {
                panic!(
                    "{}: {e}\nin the guest:\n{}",
                    "drawing lines",
                    guest.stall_report()
                )
            });
        if round % 20 == 19 || round + 1 == rounds {
            wait_for_screendump(&session, &guest, TIMEOUT)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "round {round}: {e}; images so far {:?}",
                        session.image_counts()
                    )
                });
        }
    }

    use solstice_spice::protocol::image_type::{GLZ_RGB, ZLIB_GLZ_RGB};
    let images = session.image_counts();
    let glz = images.get(&GLZ_RGB).copied().unwrap_or(0)
        + images.get(&ZLIB_GLZ_RGB).copied().unwrap_or(0);
    eprintln!(
        "after {rounds} rounds: images {images:?}, draws {:?}",
        session.draw_counts()
    );
    assert!(
        glz as usize >= rounds,
        "only {glz} GLZ images in {rounds} rounds: {images:?}"
    );
    session.close().await;
}
