//! A throwaway probe against a live `Xspice`, for the manual validation
//! `docs/roadmap.md` §2.6 asks for. Not a test; a pair of eyes.
#![allow(missing_docs)]
use std::sync::Arc;
use std::time::Duration;

use solstice_backend::{BackendEvent, InputEvent, KeyEvent, MouseButton, Session};
use solstice_spice::backend::{connect, SpiceConfig, SpiceSecurity, TcpDialer};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("solstice_spice=info")),
        )
        .init();
    let port: u16 = std::env::args().nth(1).unwrap().parse().unwrap();
    let what = std::env::args().nth(2).unwrap_or_else(|| "pixels".into());

    let config = SpiceConfig {
        host: "127.0.0.1".into(),
        port,
        security: SpiceSecurity::Plain { password: None },
        audio: false,
        ..SpiceConfig::default()
    };
    let dialer = Arc::new(TcpDialer::new(config.clone()));
    let session = match tokio::time::timeout(Duration::from_secs(20), connect(dialer, config)).await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            println!("CONNECT FAILED: {e}");
            return;
        }
        Err(_) => {
            println!("CONNECT TIMED OUT");
            return;
        }
    };
    println!("connected: dimensions = {:?}", session.dimensions());
    println!("mouse mode: {:?}", session.mouse_mode());
    println!("can_resize: {}", session.can_resize());

    let mut events = session.subscribe();
    match what.as_str() {
        "typeat" => {
            // No window manager, so X's focus is PointerRoot: the keyboard
            // follows the pointer. Home the pointer with a large negative
            // relative move -- the X server clamps at the edge -- then step
            // onto the window before typing.
            for _ in 0..3 {
                session
                    .send_input(InputEvent::PointerRelative {
                        dx: -2000,
                        dy: -2000,
                    })
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(60)).await;
            }
            session
                .send_input(InputEvent::PointerRelative { dx: 100, dy: 60 })
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            for (vk, extended) in [
                (0x48u16, false),
                (0x45, false),
                (0x4C, false),
                (0x4C, false),
                (0x4F, false),
                (0x0D, false),
            ] {
                let scancode = solstice_input::scancode(vk, extended);
                for down in [true, false] {
                    session
                        .send_input(InputEvent::Key(KeyEvent {
                            scancode,
                            keysym: None,
                            down,
                            non_normalized: false,
                        }))
                        .await
                        .unwrap();
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            }
            println!("moved the pointer onto the window and typed HELLO + Return");
        }
        "keys" => {
            // Type "hello" and a Return into whatever has focus.
            for (vk, extended) in [
                (0x48u16, false), // H
                (0x45, false),    // E
                (0x4C, false),    // L
                (0x4C, false),    // L
                (0x4F, false),    // O
                (0x0D, false),    // Return
            ] {
                let scancode = solstice_input::scancode(vk, extended);
                for down in [true, false] {
                    session
                        .send_input(InputEvent::Key(KeyEvent {
                            scancode,
                            keysym: None,
                            down,
                            non_normalized: false,
                        }))
                        .await
                        .unwrap();
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
            println!("typed HELLO + Return");
        }
        "mouse" => {
            let (w, h) = session.dimensions();
            for i in 0..20 {
                session
                    .send_input(InputEvent::PointerAbsolute {
                        x: (i * w as i32 / 20) as i16,
                        y: (i * h as i32 / 20) as i16,
                        ref_width: w as u16,
                        ref_height: h as u16,
                    })
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            session
                .send_input(InputEvent::Button {
                    button: MouseButton::Left,
                    down: true,
                })
                .await
                .unwrap();
            session
                .send_input(InputEvent::Button {
                    button: MouseButton::Left,
                    down: false,
                })
                .await
                .unwrap();
            println!("moved the pointer across the screen and clicked");
        }
        "resize" => {
            let granted = session.request_resize(1024, 768).await.unwrap();
            println!("resize granted: {granted}");
            let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
            while tokio::time::Instant::now() < deadline {
                if let Ok(Ok(BackendEvent::Resize { width, height })) =
                    tokio::time::timeout(Duration::from_secs(2), events.recv()).await
                {
                    println!("resized to {width}x{height}");
                    break;
                }
            }
        }
        _ => {}
    }

    // Watch for a while, then dump what the framebuffer holds.
    let watch: u64 = std::env::var("PROBE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(12);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(watch);
    let mut damage = 0usize;
    let mut covered: Option<solstice_backend::Rect> = None;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), events.recv()).await {
            Ok(Ok(BackendEvent::Damage(r))) => {
                damage += 1;
                covered = Some(covered.map_or(r, |c| c.union(&r)));
            }
            Ok(Ok(BackendEvent::Resize { width, height })) => println!("resize {width}x{height}"),
            Ok(Ok(BackendEvent::Disconnected)) => {
                println!("DISCONNECTED");
                break;
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                println!("events ended: {e}");
                break;
            }
            // A quiet moment is not the end of the session: keep watching
            // until the deadline.
            Err(_) => continue,
        }
    }
    println!("damage events: {damage}, covered: {covered:?}");

    let fb = session.framebuffer();
    let fb = fb.read();
    println!("framebuffer: {}x{}", fb.width(), fb.height());
    let mut histogram = std::collections::HashMap::new();
    for px in fb.data().chunks_exact(4) {
        *histogram
            .entry([px[0], px[1], px[2], px[3]])
            .or_insert(0usize) += 1;
    }
    let mut top: Vec<_> = histogram.into_iter().collect();
    top.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let total: usize = top.iter().map(|(_, n)| n).sum();
    println!("distinct colours: {}, total pixels: {total}", top.len());
    for (colour, count) in top.iter().take(6) {
        println!("  bgra {colour:?} x{count}");
    }
}
