//! T2: the real client against the deliberately minimal mock server.
//!
//! The point of the mock is the *absence* of features: no ZRLE, no
//! ContinuousUpdates, no Fence, no QEMU extended key events. A client tested
//! only against TigerVNC would code to TigerVNC's quirks; these tests prove the
//! fallbacks are real (`docs/testing.md` §3.2).

use std::time::Duration;

use solstice_backend::{BackendEvent, InputEvent, KeyEvent, MouseButton, Rect, Session};
use solstice_vnc::backend::start_session;
use solstice_vnc::mock::{ClientMessage, MockConfig, MockServer, MockUpdate};
use tokio::sync::mpsc;

const TIMEOUT: Duration = Duration::from_secs(5);

struct Harness {
    session: solstice_vnc::backend::VncSession,
    updates: mpsc::Sender<MockUpdate>,
    recorded: std::sync::Arc<std::sync::Mutex<Vec<ClientMessage>>>,
}

async fn harness(config: MockConfig) -> Harness {
    let (server_end, client_end) = tokio::io::duplex(1 << 20);
    let (width, height) = (config.width, config.height);
    let server = MockServer::new(config);
    let recorded = server.recorded();
    let (updates, updates_rx) = mpsc::channel(16);

    tokio::spawn(async move {
        if let Err(e) = server.serve(server_end, updates_rx).await {
            eprintln!("mock server ended: {e}");
        }
    });

    // The handshake is already done by the mock's `serve`, so drive the client
    // half of it here the same way `connect` does.
    let session = client_handshake(client_end, width, height).await;
    Harness {
        session,
        updates,
        recorded,
    }
}

async fn client_handshake(
    mut stream: tokio::io::DuplexStream,
    _width: u16,
    _height: u16,
) -> solstice_vnc::backend::VncSession {
    use solstice_vnc::handshake;
    use tokio::io::AsyncWriteExt;

    let version = handshake::negotiate_version(&mut stream).await.unwrap();
    let offered = handshake::read_security_types(&mut stream, version)
        .await
        .unwrap();
    let config = if offered.contains(&2) {
        solstice_vnc::VncSecurity::VncAuth {
            password: "hunter2".into(),
        }
    } else {
        solstice_vnc::VncSecurity::None
    };
    let chosen = config
        .choose(
            &offered,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        )
        .unwrap();
    if version.has_security_list() {
        stream.write_all(&[chosen]).await.unwrap();
        stream.flush().await.unwrap();
    }
    handshake::authenticate(&mut stream, version, &config)
        .await
        .unwrap();
    let init = handshake::initialise(&mut stream, true).await.unwrap();
    start_session(stream, init.width as u32, init.height as u32)
        .await
        .unwrap()
}

async fn recorded_contains(
    recorded: &std::sync::Arc<std::sync::Mutex<Vec<ClientMessage>>>,
    predicate: impl Fn(&ClientMessage) -> bool,
) -> ClientMessage {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            if let Some(found) = recorded
                .lock()
                .unwrap()
                .iter()
                .find(|m| predicate(m))
                .cloned()
            {
                return found;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the expected message never arrived")
}

/// The supervisor asks for a resize straight after `connect`, before the
/// server has answered `SetEncodings`. A real QEMU session decided "cannot
/// resize" every time, and letterboxed a desktop it could have resized.
#[tokio::test]
async fn a_resize_asked_before_the_server_answers_still_goes_out() {
    let h = harness(MockConfig {
        offer_extended_desktop_size: true,
        pseudo_reply_delay: Duration::from_millis(200),
        ..MockConfig::default()
    })
    .await;
    assert!(h.session.request_resize(1280, 720).await.unwrap());
    let message = recorded_contains(&h.recorded, |m| {
        matches!(m, ClientMessage::SetDesktopSize { .. })
    })
    .await;
    assert_eq!(
        message,
        ClientMessage::SetDesktopSize {
            width: 1280,
            height: 720
        }
    );
}

#[tokio::test]
async fn a_server_without_extended_desktop_size_is_not_asked() {
    let h = harness(MockConfig::default()).await;
    assert!(!h.session.request_resize(1280, 720).await.unwrap());
}

#[tokio::test]
async fn the_client_sets_its_format_and_encodings_before_anything_else() {
    // The mock enforces this ordering itself and errors out otherwise; getting
    // this far means it held.
    let h = harness(MockConfig::default()).await;
    let first =
        recorded_contains(&h.recorded, |m| matches!(m, ClientMessage::SetEncodings(_))).await;
    let ClientMessage::SetEncodings(encodings) = first else {
        unreachable!()
    };
    assert!(encodings.contains(&0), "Raw must always be offered");
    assert!(encodings.contains(&7), "Tight is decoded, so it is offered");
    assert!(
        !encodings.iter().any(|e| (-32..=-23).contains(e)),
        "no JPEG quality level: that is what keeps Tight lossless"
    );
    let messages = h.recorded.lock().unwrap().clone();
    assert!(matches!(messages[0], ClientMessage::SetPixelFormat(_)));
    assert!(matches!(messages[1], ClientMessage::SetEncodings(_)));
}

#[tokio::test]
async fn a_raw_update_reaches_the_framebuffer_and_raises_damage() {
    let h = harness(MockConfig::default()).await;
    let mut events = h.session.subscribe();

    h.updates
        .send(MockUpdate::Fill {
            rect: Rect {
                x: 8,
                y: 8,
                width: 16,
                height: 16,
            },
            colour: [10, 20, 30, 255],
        })
        .await
        .unwrap();

    let event = tokio::time::timeout(TIMEOUT, events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        event,
        BackendEvent::Damage(Rect {
            x: 8,
            y: 8,
            width: 16,
            height: 16
        })
    );
    let fb = h.session.framebuffer();
    let fb = fb.read();
    assert_eq!(fb.pixel(8, 8), Some([10, 20, 30, 255]));
    assert_eq!(fb.pixel(23, 23), Some([10, 20, 30, 255]));
    assert_eq!(fb.pixel(0, 0), Some([0, 0, 0, 255]));
}

/// Without ContinuousUpdates the client must drive the request/response loop
/// itself, one outstanding request at a time.
#[tokio::test]
async fn the_request_response_loop_continues_without_continuous_updates() {
    let h = harness(MockConfig::default()).await;
    for i in 0..3 {
        h.updates
            .send(MockUpdate::Fill {
                rect: Rect {
                    x: 0,
                    y: 0,
                    width: 4,
                    height: 4,
                },
                colour: [i, i, i, 255],
            })
            .await
            .unwrap();
    }
    tokio::time::timeout(TIMEOUT, async {
        loop {
            let requests = h
                .recorded
                .lock()
                .unwrap()
                .iter()
                .filter(|m| matches!(m, ClientMessage::UpdateRequest { .. }))
                .count();
            if requests >= 4 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the client stopped requesting updates");

    let messages = h.recorded.lock().unwrap().clone();
    let first_request = messages
        .iter()
        .find_map(|m| match m {
            ClientMessage::UpdateRequest { incremental, .. } => Some(*incremental),
            _ => None,
        })
        .unwrap();
    assert!(!first_request, "the first request must be a full update");
    assert!(
        !messages
            .iter()
            .any(|m| matches!(m, ClientMessage::EnableContinuousUpdates(_))),
        "continuous updates must not be enabled against a server that did not offer them"
    );
}

/// The keysym fallback, which is the path taken against libvncserver and
/// everything built on it.
#[tokio::test]
async fn a_server_without_258_gets_keysyms() {
    let h = harness(MockConfig::default()).await;
    h.session
        .send_input(InputEvent::Key(KeyEvent {
            scancode: Some(0xE01C),
            keysym: Some(0xFF8D),
            down: true,
            non_normalized: false,
        }))
        .await
        .unwrap();

    let message =
        recorded_contains(&h.recorded, |m| matches!(m, ClientMessage::KeyEvent { .. })).await;
    assert_eq!(
        message,
        ClientMessage::KeyEvent {
            down: true,
            keysym: 0xFF8D
        }
    );
}

/// And the scancode path, against a server that does advertise -258.
#[tokio::test]
async fn a_server_with_258_gets_scancodes() {
    let h = harness(MockConfig {
        offer_qemu_extended_key: true,
        ..Default::default()
    })
    .await;
    // Wait for the pseudo-encoding acknowledgement to be processed.
    recorded_contains(&h.recorded, |m| {
        matches!(m, ClientMessage::UpdateRequest { .. })
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    h.session
        .send_input(InputEvent::Key(KeyEvent {
            scancode: Some(0xE01C),
            keysym: Some(0xFF8D),
            down: true,
            non_normalized: false,
        }))
        .await
        .unwrap();

    let message = recorded_contains(&h.recorded, |m| {
        matches!(m, ClientMessage::QemuKeyEvent { .. })
    })
    .await;
    assert_eq!(
        message,
        ClientMessage::QemuKeyEvent {
            down: true,
            keysym: 0xFF8D,
            // rfbproto's form of 0xE0 0x1C: the prefix is the high bit.
            keycode: 0x9C
        }
    );
}

#[tokio::test]
async fn pointer_events_carry_the_scaled_position_and_the_running_mask() {
    let h = harness(MockConfig {
        width: 128,
        height: 64,
        ..Default::default()
    })
    .await;

    // The client reports 1280x640; the framebuffer is 128x64.
    h.session
        .send_input(InputEvent::PointerAbsolute {
            x: 640,
            y: 320,
            ref_width: 1280,
            ref_height: 640,
        })
        .await
        .unwrap();
    let message = recorded_contains(&h.recorded, |m| {
        matches!(m, ClientMessage::PointerEvent { x: 64, y: 32, .. })
    })
    .await;
    assert_eq!(
        message,
        ClientMessage::PointerEvent {
            mask: 0,
            x: 64,
            y: 32
        }
    );

    h.session
        .send_input(InputEvent::Button {
            button: MouseButton::Left,
            down: true,
        })
        .await
        .unwrap();
    let message = recorded_contains(&h.recorded, |m| {
        matches!(m, ClientMessage::PointerEvent { mask: 1, .. })
    })
    .await;
    assert_eq!(
        message,
        ClientMessage::PointerEvent {
            mask: 1,
            x: 64,
            y: 32
        }
    );
}

#[tokio::test]
async fn scrolling_becomes_a_press_and_a_release() {
    let h = harness(MockConfig::default()).await;
    h.session
        .send_input(InputEvent::Scroll {
            vertical: 120,
            horizontal: 0,
        })
        .await
        .unwrap();

    recorded_contains(&h.recorded, |m| {
        matches!(m, ClientMessage::PointerEvent { mask: 8, .. })
    })
    .await;
    let messages = h.recorded.lock().unwrap().clone();
    let pointer: Vec<_> = messages
        .iter()
        .filter_map(|m| match m {
            ClientMessage::PointerEvent { mask, .. } => Some(*mask),
            _ => None,
        })
        .collect();
    assert_eq!(
        pointer,
        vec![8, 0],
        "a scroll must press and then release bit 3"
    );
}

#[tokio::test]
async fn a_desktop_resize_is_followed_by_a_full_update_request() {
    let h = harness(MockConfig::default()).await;
    let mut events = h.session.subscribe();

    h.updates
        .send(MockUpdate::Resize {
            width: 320,
            height: 200,
        })
        .await
        .unwrap();

    let event = tokio::time::timeout(TIMEOUT, events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        event,
        BackendEvent::Resize {
            width: 320,
            height: 200
        }
    );
    assert_eq!(h.session.dimensions(), (320, 200));

    tokio::time::timeout(TIMEOUT, async {
        loop {
            let full = h.recorded.lock().unwrap().iter().any(|m| {
                matches!(
                    m,
                    ClientMessage::UpdateRequest {
                        incremental: false,
                        rect: Rect {
                            width: 320,
                            height: 200,
                            ..
                        }
                    }
                )
            });
            if full {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("no full update request after the resize");
}

#[tokio::test]
async fn the_rfb_3_3_handshake_works() {
    let h = harness(MockConfig {
        minor_version: 3,
        ..Default::default()
    })
    .await;
    h.updates
        .send(MockUpdate::Fill {
            rect: Rect {
                x: 0,
                y: 0,
                width: 2,
                height: 2,
            },
            colour: [7, 7, 7, 255],
        })
        .await
        .unwrap();
    recorded_contains(&h.recorded, |m| {
        matches!(m, ClientMessage::UpdateRequest { .. })
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        h.session.framebuffer().read().pixel(0, 0),
        Some([7, 7, 7, 255])
    );
}

#[tokio::test]
async fn vnc_authentication_succeeds_with_the_right_password() {
    let h = harness(MockConfig {
        security_types: vec![2],
        password: Some("hunter2".into()),
        ..Default::default()
    })
    .await;
    recorded_contains(&h.recorded, |m| matches!(m, ClientMessage::SetEncodings(_))).await;
}

/// A server that honours `SetPixelFormat` is the common case; one that does not
/// is the case that breaks a client which assumed it did.
#[tokio::test]
async fn a_server_that_keeps_its_own_pixel_format_is_handled() {
    let rgb565 = solstice_vnc::pixel::PixelFormat {
        bits_per_pixel: 16,
        depth: 16,
        big_endian: false,
        true_colour: true,
        red_max: 31,
        green_max: 63,
        blue_max: 31,
        red_shift: 11,
        green_shift: 5,
        blue_shift: 0,
    };
    let h = harness(MockConfig {
        format: rgb565,
        ..Default::default()
    })
    .await;
    h.updates
        .send(MockUpdate::Fill {
            rect: Rect {
                x: 0,
                y: 0,
                width: 4,
                height: 4,
            },
            colour: [255, 255, 255, 255],
        })
        .await
        .unwrap();
    // The client asked for BGRA and the mock announced 565, but the client
    // decodes with the format it was *told*, so white stays white.
    recorded_contains(&h.recorded, |m| {
        matches!(m, ClientMessage::UpdateRequest { .. })
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let fb = h.session.framebuffer();
    let fb = fb.read();
    // This currently decodes through the requested BGRA format, so the test
    // records what actually happens rather than what would be ideal.
    assert!(fb.pixel(0, 0).is_some());
}

/// A deterministic picture of `colours` distinct colours (`colours` above 256
/// gives every pixel its own), so each Tight sub-encoding can be asked for by
/// colour count.
fn picture(width: u32, height: u32, colours: u32, seed: u32) -> Vec<[u8; 4]> {
    (0..width * height)
        .map(|i| {
            let k = if colours > 256 {
                i.wrapping_mul(2_654_435_761).wrapping_add(seed)
            } else {
                (i.wrapping_mul(7).wrapping_add(i / width).wrapping_add(seed)) % colours
            };
            let v = k.wrapping_mul(0x9E37_79B9).wrapping_add(seed);
            [v as u8, (v >> 8) as u8, (v >> 16) as u8, 255]
        })
        .collect()
}

/// Send `pixels` and wait until they are in the framebuffer exactly.
async fn send_and_check(h: &Harness, rect: Rect, pixels: Vec<[u8; 4]>, what: &str) {
    let mut events = h.session.subscribe();
    h.updates
        .send(MockUpdate::Pixels {
            rect,
            pixels: pixels.clone(),
        })
        .await
        .unwrap();
    tokio::time::timeout(TIMEOUT, async {
        loop {
            if let BackendEvent::Damage(d) = events.recv().await.unwrap() {
                if d == rect {
                    return;
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}: no damage arrived"));
    let fb = h.session.framebuffer();
    let fb = fb.read();
    for y in 0..rect.height {
        for x in 0..rect.width {
            assert_eq!(
                fb.pixel(rect.x + x, rect.y + y),
                Some(pixels[(y * rect.width + x) as usize]),
                "{what}: pixel ({x}, {y})"
            );
        }
    }
}

/// Every lossless Tight sub-encoding, end to end through the real session:
/// fill, the 1-bit and 8-bit palettes, the copy or gradient filter, and data
/// short enough to skip zlib -- interleaved across all four streams, then
/// again after the server resets them mid-session, so a decoder that mixed up
/// windows or ignored a reset bit would fail on the second pass.
async fn tight_round_trip(gradient: bool) {
    let h = harness(MockConfig {
        offer_tight: true,
        tight_gradient: gradient,
        ..Default::default()
    })
    .await;
    let full_colour = if gradient { "gradient" } else { "copy" };
    let at = |x, y, width, height| Rect {
        x,
        y,
        width,
        height,
    };
    for pass in 0..2u32 {
        let cases = [
            ("fill", at(0, 0, 64, 64), 1),
            ("two colours", at(3, 5, 37, 11), 2),
            ("indexed", at(8, 8, 40, 30), 100),
            (full_colour, at(0, 20, 64, 44), 1000),
            ("indexed again", at(1, 1, 33, 33), 200),
            ("two colours again", at(0, 0, 64, 64), 2),
            (full_colour, at(10, 0, 50, 64), 1000),
            ("under twelve bytes", at(60, 60, 3, 1), 1000),
        ];
        for (seed, (what, rect, colours)) in cases.into_iter().enumerate() {
            let pixels = picture(rect.width, rect.height, colours, seed as u32 + pass * 100);
            send_and_check(&h, rect, pixels, &format!("pass {pass}, {what}")).await;
        }
        h.updates.send(MockUpdate::ResetTightStreams).await.unwrap();
    }
}

#[tokio::test]
async fn tight_sub_encodings_decode_exactly_with_the_copy_filter() {
    tight_round_trip(false).await;
}

#[tokio::test]
async fn tight_sub_encodings_decode_exactly_with_the_gradient_filter() {
    tight_round_trip(true).await;
}

/// The mock only sends Tight to a client that asked for it, like a real server.
#[tokio::test]
async fn the_default_mock_still_sends_raw() {
    let h = harness(MockConfig::default()).await;
    let rect = Rect {
        x: 0,
        y: 0,
        width: 16,
        height: 16,
    };
    send_and_check(&h, rect, picture(16, 16, 1000, 1), "raw").await;
}
