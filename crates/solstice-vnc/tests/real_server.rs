//! T3: the client against a real RFB server.
//!
//! This tier used to be TigerVNC's `Xvnc`, chosen as the "feature-rich pole"
//! of `docs/testing.md` §3. It is now QEMU's own RFB server, running on the
//! same guest image the SPICE tests use -- one server implementation, one
//! image, one harness, instead of two X servers with separate launchers.
//!
//! **What that trade costs, measured rather than assumed.** QEMU's RFB server
//! was probed directly before the move. It serves Raw, Hextile, zlib, Tight
//! and ZRLE natively, and -- the one that matters most here -- it supports
//! **QEMU Extended Key Event (−258)**, which it invented, so scancodes still
//! meet a real server. It offers ExtendedDesktopSize (−308) and LEDState
//! (−261). It does *not* implement RRE, CoRRE or ZlibHex, and it does not
//! implement **Fence (−312) or ContinuousUpdates (−313)**: a ClientFence
//! makes it close the connection outright.
//!
//! So `backend.rs`'s continuous-updates path no longer runs against a
//! third-party server. It is still covered by `mock_server.rs`, whose mock
//! offers both and tests the negative -- but only against an implementation
//! of our own reading of the spec, which is exactly the class of mistake
//! `docs/roadmap.md` §3 warns about. That is a deliberate, recorded trade,
//! not an oversight.
//!
//! ```sh
//! ./tests/guest/build-image.sh
//! cargo test -p solstice-vnc --test real_server -- --test-threads=4
//! ```

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use solstice_backend::{
    BackendEvent, FramebufferHandle, InputEvent, KeyEvent, MouseButton, Rect, Session,
};
use solstice_test_guest::{Display, Guest, GuestConfig};
use solstice_vnc::pixel::PixelFormat;
use solstice_vnc::protocol::encoding;
use solstice_vnc::session::{self, UpdateLoop};
use solstice_vnc::{VncConfig, VncSecurity};
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, mpsc};

const TIMEOUT: Duration = Duration::from_secs(30);

/// The guest gets virtio-gpu rather than the harness's default QXL. Nothing
/// on the RFB side needs QXL -- QEMU's VNC server reads the same console
/// surface whatever the device -- and QXL needs QEMU's SPICE module, which a
/// machine that only tests VNC has no reason to install.
fn start(width: u32, height: u32) -> Option<Guest> {
    Guest::start(
        GuestConfig::new()
            .geometry(width, height)
            .display(Display::VirtioGpu)
            .vnc(),
    )
}

fn config(port: u16) -> VncConfig {
    VncConfig {
        host: "127.0.0.1".into(),
        port,
        // `None` is permitted here and only here: loopback. The policy test
        // below asserts the refusal off-loopback.
        security: VncSecurity::None,
        shared: true,
        allow_insecure: false,
    }
}

async fn session(guest: &Guest) -> solstice_vnc::backend::VncSession {
    tokio::time::timeout(TIMEOUT, solstice_vnc::connect(&config(guest.vnc_port())))
        .await
        .expect("connect timed out")
        .expect("connect failed")
}

#[tokio::test]
async fn the_client_connects_to_a_real_server_and_receives_a_framebuffer() {
    let Some(guest) = start(800, 600) else {
        return;
    };
    let session = session(&guest).await;

    assert_eq!(session.dimensions(), (800, 600));

    // The first full update must arrive and raise damage covering the screen.
    let mut events = session.subscribe();
    let mut covered = None;
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), events.recv()).await {
            Ok(Ok(BackendEvent::Damage(rect))) => {
                covered = Some(covered.map_or(rect, |c: solstice_backend::Rect| c.union(&rect)));
                if covered.unwrap().width >= 800 && covered.unwrap().height >= 600 {
                    break;
                }
            }
            Ok(Ok(_)) => {}
            _ => break,
        }
    }
    let covered = covered.expect("no damage arrived from the server");
    assert!(
        covered.width >= 800 && covered.height >= 600,
        "only {covered:?} was updated"
    );

    // The framebuffer is opaque and was actually written to. Scoped, so the
    // read guard is gone before the next await.
    {
        let fb = session.framebuffer();
        let fb = fb.read();
        assert_eq!(fb.width(), 800);
        assert!(fb.pixel(400, 300).is_some());
        assert!(
            fb.data().chunks_exact(4).all(|px| px[3] == 0xFF),
            "alpha was not set"
        );
    }

    session.close().await;
}

/// QEMU advertises pseudo-encoding −258 -- it is QEMU's own extension -- so
/// this remains the one place the scancode path meets a real server.
#[tokio::test]
async fn a_real_server_accepts_both_keyboard_paths_and_pointer_input() {
    let Some(guest) = start(640, 480) else {
        return;
    };
    let session = session(&guest).await;

    // Let the first update land so the server's capabilities are known.
    let mut events = session.subscribe();
    let _ = tokio::time::timeout(TIMEOUT, events.recv()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // A key with both representations: this takes the scancode path.
    for down in [true, false] {
        session
            .send_input(InputEvent::Key(KeyEvent {
                scancode: Some(0x1E), // XT 'a'
                keysym: Some(b'a' as u32),
                down,
                non_normalized: false,
            }))
            .await
            .expect("key event rejected");
    }

    // A key with no scancode at all, which must still go out as a keysym.
    for down in [true, false] {
        session
            .send_input(InputEvent::Key(KeyEvent {
                scancode: None,
                keysym: Some(0xFF08), // BackSpace
                down,
                non_normalized: false,
            }))
            .await
            .expect("keysym-only event rejected");
    }

    session
        .send_input(InputEvent::PointerAbsolute {
            x: 320,
            y: 240,
            ref_width: 640,
            ref_height: 480,
        })
        .await
        .expect("pointer move rejected");
    for down in [true, false] {
        session
            .send_input(InputEvent::Button {
                button: MouseButton::Left,
                down,
            })
            .await
            .expect("button rejected");
    }
    session
        .send_input(InputEvent::Scroll {
            vertical: 120,
            horizontal: 0,
        })
        .await
        .expect("scroll rejected");
    session
        .send_input(InputEvent::Text("hej".into()))
        .await
        .expect("text rejected");

    // The connection survived all of it, which it would not have if the server
    // had rejected a malformed message.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(session.dimensions(), (640, 480));
    session.close().await;
}

/// Pixels actually change when the desktop does.
///
/// Connect first and repaint second: QEMU renders guest damage into its
/// console surface only while a display client is attached, so painting
/// before connecting would be dropped and this test would fail for a reason
/// unrelated to the client.
#[tokio::test]
async fn a_change_on_the_desktop_reaches_the_framebuffer() {
    let Some(guest) = start(640, 480) else {
        return;
    };
    guest.fill("000000").expect("painting the guest black");

    // `RUST_LOG=solstice_vnc=debug` turns the update loop's tracing on, which
    // is how the ExtendedDesktopSize loop this test now guards against was
    // found in the first place.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let session = session(&guest).await;
    let mut events = session.subscribe();
    let _ = tokio::time::timeout(TIMEOUT, events.recv()).await;

    guest.fill("102030").expect("repainting the guest");

    let fb = session.framebuffer();
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut seen = None;
    while tokio::time::Instant::now() < deadline {
        let _ = tokio::time::timeout(Duration::from_millis(500), events.recv()).await;
        let pixel = fb.read().pixel(320, 240);
        // BGRA, so #102030 arrives as [0x30, 0x20, 0x10, 0xFF].
        if pixel == Some([0x30, 0x20, 0x10, 0xFF]) {
            seen = pixel;
            break;
        }
        seen = pixel;
    }
    assert_eq!(
        seen,
        Some([0x30, 0x20, 0x10, 0xFF]),
        "the repaint never reached the framebuffer"
    );
    session.close().await;
}

/// A session that lists exactly `encodings` and nothing else, so the server
/// has no choice in what it sends (`docs/testing.md` §3.1). Returns the
/// framebuffer it decodes into, and how many rectangles of each encoding have
/// arrived so far; the update loop runs until the guest goes away.
async fn offer_only(
    port: u16,
    encodings: &[i32],
) -> (FramebufferHandle, Arc<Mutex<BTreeMap<i32, u64>>>) {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let version = solstice_vnc::handshake::negotiate_version(&mut stream)
        .await
        .unwrap();
    let offered = solstice_vnc::handshake::read_security_types(&mut stream, version)
        .await
        .unwrap();
    assert!(offered.contains(&1), "the guest's server must offer `None`");
    stream.write_all(&[1]).await.unwrap();
    stream.flush().await.unwrap();
    solstice_vnc::handshake::authenticate(&mut stream, version, &VncSecurity::None)
        .await
        .unwrap();
    let init = solstice_vnc::handshake::initialise(&mut stream, true)
        .await
        .unwrap();
    let (width, height) = (init.width as u32, init.height as u32);

    let (reader, writer) = tokio::io::split(stream);
    let (outgoing, outgoing_rx) = mpsc::channel(256);
    let (events, _) = broadcast::channel(4096);
    let fb = FramebufferHandle::with_size(width, height);
    for message in [
        session::set_pixel_format(&PixelFormat::BGRA),
        session::set_encodings(encodings),
        session::update_request(false, Rect::whole(width, height)),
    ] {
        outgoing.send(message).await.unwrap();
    }
    tokio::spawn(session::writer_task(writer, outgoing_rx));

    // The loop runs in its own task rather than under a timeout here: a step
    // cancelled half-way through a rectangle would leave the stream mid-
    // message, and the test would be measuring that instead of the decoder.
    let counts = Arc::new(Mutex::new(BTreeMap::new()));
    let mut update_loop = UpdateLoop::new(reader, PixelFormat::BGRA, fb.clone(), events, outgoing);
    let published = counts.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = update_loop.step().await {
                eprintln!("update loop ended: {e}");
                return;
            }
            *published.lock().unwrap() = update_loop.rectangles_by_encoding().clone();
        }
    });
    (fb, counts)
}

/// How many pixels differ between the decoded framebuffer and QEMU's own
/// capture of the same screen, and where the first one is.
fn compare_with_screendump(fb: &FramebufferHandle, guest: &Guest) -> (usize, Option<(u32, u32)>) {
    let Ok(dump) = guest.screendump() else {
        return (usize::MAX, None);
    };
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

/// Offer QEMU **only** Tight (`docs/roadmap.md` §1), paint something with
/// more than one colour, and require the decoded framebuffer to equal QEMU's
/// screendump pixel for pixel. Tight here is lossless -- no quality level is
/// offered, so QEMU sends no JPEG -- which is what makes exact equality the
/// right assertion rather than a tolerance.
#[tokio::test]
async fn a_real_server_offered_only_tight_reproduces_the_screen_exactly() {
    let Some(guest) = start(800, 600) else {
        return;
    };
    let (fb, counts) = offer_only(guest.vnc_port(), &[encoding::TIGHT]).await;

    // Connect first, paint second: see `a_change_on_the_desktop_reaches_the_
    // framebuffer`. Fills, two-colour text, many-coloured lines and an XOR
    // stipple between them give QEMU's encoder a reason to use each of its
    // lossless paths.
    tokio::time::sleep(Duration::from_millis(500)).await;
    guest.fill("2e3436").expect("painting the background");
    guest.draw("stroke", &["64"]).expect("drawing lines");
    guest.draw("text", &[]).expect("drawing text");
    guest.draw("rop3", &["16"]).expect("drawing a stipple");

    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut result = (usize::MAX, None);
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
        result = compare_with_screendump(&fb, &guest);
        if result.0 == 0 {
            break;
        }
    }
    assert_eq!(
        result.0, 0,
        "{} pixels differ from QEMU's screendump, the first at {:?}",
        result.0, result.1
    );

    let counts = counts.lock().unwrap().clone();
    assert!(
        counts.get(&encoding::TIGHT).copied().unwrap_or(0) > 0,
        "no Tight rectangles arrived: {counts:?}"
    );
    assert_eq!(
        counts.keys().copied().collect::<Vec<_>>(),
        vec![encoding::TIGHT],
        "the server sent an encoding it was not offered"
    );
}

/// A refusal test is a security test (`docs/security.md` §4.1).
#[test]
fn weak_security_types_are_refused_against_a_non_loopback_peer() {
    let remote = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    for security in [
        VncSecurity::None,
        VncSecurity::VncAuth {
            password: "hunter2".into(),
        },
    ] {
        assert!(security.choose(&[1, 2, 19], loopback).is_ok());
        assert!(
            security.choose(&[1, 2, 19], remote).is_err(),
            "{security:?} was accepted against a remote peer"
        );
    }
    let vencrypt = VncSecurity::VeNCrypt {
        password: None,
        ca_file: None,
    };
    assert!(vencrypt.choose(&[1, 2, 19], remote).is_ok());
}
