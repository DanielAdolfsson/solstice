//! T3: the client against TigerVNC's `Xvnc`, the feature-rich pole.
//!
//! `docs/testing.md` §3 argues for two poles rather than a matrix of servers:
//! a real one with everything present, and a deliberately minimal mock with
//! nothing optional present. `mock_server.rs` is the second pole; this is the
//! first.
//!
//! `Xvnc` is a self-contained X server with a VNC frontend -- no Xvfb, no
//! compositor, no VM -- and it covers every axis this client depends on:
//! ZRLE and Hextile, ContinuousUpdates and Fence, ExtendedDesktopSize, and
//! **QEMU Extended Key Event server-side**, which is the only way to exercise
//! the scancode path against a real server.
//!
//! Skipped with a printed note when `Xvnc` is not installed, so the suite still
//! runs on a machine without it:
//!
//! ```sh
//! sudo apt install tigervnc-standalone-server
//! ```

use std::net::{IpAddr, Ipv4Addr};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use solstice_backend::{BackendEvent, InputEvent, KeyEvent, MouseButton, Session};
use solstice_vnc::{VncConfig, VncSecurity};

const TIMEOUT: Duration = Duration::from_secs(20);

struct Xvnc {
    child: Child,
    port: u16,
    display: u32,
}

impl Drop for Xvnc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(format!("/tmp/.X11-unix/X{}", self.display));
        let _ = std::fs::remove_file(format!("/tmp/.X{}-lock", self.display));
    }
}

fn start_xvnc(display: u32, geometry: &str) -> Option<Xvnc> {
    if Command::new("Xvnc")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("skipping: Xvnc is not installed (apt install tigervnc-standalone-server)");
        return None;
    }
    let port = 5900 + display as u16;
    let child = Command::new("Xvnc")
        .arg(format!(":{display}"))
        .args(["-geometry", geometry])
        .args(["-depth", "24"])
        .args(["-SecurityTypes", "None"])
        .args(["-rfbport", &port.to_string()])
        .arg("-AlwaysShared")
        .arg("-localhost")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    Some(Xvnc {
        child,
        port,
        display,
    })
}

async fn wait_for_port(port: u16) -> bool {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

fn config(port: u16) -> VncConfig {
    VncConfig {
        host: "127.0.0.1".into(),
        port,
        // `None` is permitted here and only here: loopback. The policy test
        // below asserts the refusal off-loopback.
        security: VncSecurity::None,
        shared: true,
    }
}

#[tokio::test]
async fn the_client_connects_to_xvnc_and_receives_a_framebuffer() {
    let Some(server) = start_xvnc(97, "800x600") else {
        return;
    };
    assert!(wait_for_port(server.port).await, "Xvnc never listened");

    let session = tokio::time::timeout(TIMEOUT, solstice_vnc::connect(&config(server.port)))
        .await
        .expect("connect timed out")
        .expect("connect failed");

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
    let covered = covered.expect("no damage arrived from Xvnc");
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

/// TigerVNC advertises pseudo-encoding -258, so this is the only place the
/// scancode path meets a real server.
#[tokio::test]
async fn xvnc_accepts_both_keyboard_paths_and_pointer_input() {
    let Some(server) = start_xvnc(98, "640x480") else {
        return;
    };
    assert!(wait_for_port(server.port).await, "Xvnc never listened");

    let session = tokio::time::timeout(TIMEOUT, solstice_vnc::connect(&config(server.port)))
        .await
        .expect("connect timed out")
        .expect("connect failed");

    // Let the first update land so the server's capabilities are known.
    let mut events = session.subscribe();
    let _ = tokio::time::timeout(TIMEOUT, events.recv()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // A key with both representations: against TigerVNC this takes the
    // scancode path.
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

/// Pixels actually change when the desktop does. `xsetroot` is the smallest
/// thing that repaints the root window.
#[tokio::test]
async fn a_change_on_the_desktop_reaches_the_framebuffer() {
    let Some(server) = start_xvnc(99, "640x480") else {
        return;
    };
    assert!(wait_for_port(server.port).await, "Xvnc never listened");

    // `RUST_LOG=solstice_vnc=debug` turns the update loop's tracing on, which
    // is how the ExtendedDesktopSize loop this test now guards against was
    // found in the first place.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let session = tokio::time::timeout(TIMEOUT, solstice_vnc::connect(&config(server.port)))
        .await
        .expect("connect timed out")
        .expect("connect failed");
    let mut events = session.subscribe();
    let _ = tokio::time::timeout(TIMEOUT, events.recv()).await;

    let paint = |colour: &str| {
        Command::new("xsetroot")
            .env("DISPLAY", format!(":{}", server.display))
            .args(["-solid", colour])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    };
    match paint("#102030") {
        Ok(status) if status.success() => {}
        Ok(status) => {
            eprintln!("skipping the repaint check: xsetroot exited {status}");
            session.close().await;
            return;
        }
        Err(e) => {
            eprintln!("skipping the repaint check: xsetroot is unavailable ({e})");
            session.close().await;
            return;
        }
    }

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
