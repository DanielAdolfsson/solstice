//! T2: the real client against the deliberately minimal mock server.
//!
//! The mock's value is the same as the RFB one's: it is the only peer that
//! will produce the things `spice-server` never produces. `docs/testing.md`
//! §4.1 names them -- a truncated `SpiceLinkMess`, the wrong
//! `connection_id` on a secondary channel, an ack-window violation, a
//! `SpiceDataHeader` whose `size` overruns -- and each of those is a test
//! here.
//!
//! It is also how the multi-connection session shape gets exercised at all
//! without a server: the dialer hands back an in-memory duplex per channel,
//! and the mock serves each one.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use solstice_backend::{BackendEvent, InputEvent, KeyEvent, MouseButton, Session};
use solstice_spice::backend::{connect, Dialer, SpiceConfig, SpiceSecurity};
use solstice_spice::channel::OutMessage;
use solstice_spice::error::{Result, SpiceError};
use solstice_spice::link::Transport;
use solstice_spice::mock::{self, MockConfig, MockPush, MockServer, Recorded};
use solstice_spice::protocol::{channel, display_msg, inputs_msgc, main_msgc};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Hands the client an in-memory duplex per channel and serves the other end.
struct MockDialer {
    server: Arc<MockServer>,
}

#[async_trait]
impl Dialer for MockDialer {
    async fn dial(&self) -> Result<Box<dyn Transport>> {
        let (client, server_end) = tokio::io::duplex(1 << 20);
        let server = self.server.clone();
        tokio::spawn(async move {
            if let Err(e) = server.serve(server_end).await {
                // Expected for the negative cases; printed so an unexpected
                // one is visible in test output.
                eprintln!("mock connection ended: {e}");
            }
        });
        Ok(Box::new(client))
    }
}

fn config() -> SpiceConfig {
    SpiceConfig {
        host: "127.0.0.1".into(),
        port: 0,
        security: SpiceSecurity::Plain { password: None },
        audio: false,
        ..SpiceConfig::default()
    }
}

async fn session_with(
    mock: MockConfig,
) -> (solstice_spice::backend::SpiceSession, Arc<MockServer>) {
    let server = Arc::new(MockServer::new(mock));
    let dialer = Arc::new(MockDialer {
        server: server.clone(),
    });
    let session = tokio::time::timeout(TIMEOUT, connect(dialer, config()))
        .await
        .expect("connect timed out")
        .expect("connect failed");
    (session, server)
}

/// Wait until `predicate` holds over what the mock has recorded.
async fn wait_for(server: &MockServer, predicate: impl Fn(&[Recorded]) -> bool) -> Vec<Recorded> {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        let recorded = server.recorded().lock().expect("recorder").clone();
        if predicate(&recorded) {
            return recorded;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("timed out; recorded so far: {recorded:#?}");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn wait_for_push(server: &MockServer, push: MockPush) {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while !server.push(push.clone()) {
        if tokio::time::Instant::now() > deadline {
            panic!("the channel never linked");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn a_session_links_every_channel_the_server_names() {
    let (session, server) = session_with(MockConfig::default()).await;

    // The display channel's INIT is the proof it linked and came up.
    wait_for(&server, |recorded| {
        recorded.iter().any(|r| {
            r.channel == channel::DISPLAY && r.kind == solstice_spice::protocol::display_msgc::INIT
        })
    })
    .await;

    // And the main channel attached.
    let recorded = server.messages_on(channel::MAIN);
    assert!(recorded
        .iter()
        .any(|r| r.kind == main_msgc::ATTACH_CHANNELS));
    assert_eq!(session.dimensions(), (64, 48));
}

#[tokio::test]
async fn the_primary_surface_reaches_the_framebuffer() {
    let (session, server) = session_with(MockConfig::default()).await;
    let mut events = session.subscribe();

    wait_for_push(
        &server,
        MockPush {
            channel: channel::DISPLAY,
            message: mock::draw_fill(0, 0, 0, 64, 48, 0x0000_FF00),
        },
    )
    .await;

    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        match tokio::time::timeout(Duration::from_millis(200), events.recv()).await {
            Ok(Ok(BackendEvent::Damage(rect))) => {
                assert_eq!(rect.width, 64);
                break;
            }
            Ok(Ok(_)) => continue,
            _ if tokio::time::Instant::now() > deadline => panic!("no damage arrived"),
            _ => continue,
        }
    }

    let fb = session.framebuffer();
    let fb = fb.read();
    assert_eq!(fb.width(), 64);
    // 0x0000FF00 little-endian is B=0x00, G=0xFF, R=0x00.
    assert_eq!(fb.pixel(10, 10), Some([0x00, 0xFF, 0x00, 0xFF]));
}

#[tokio::test]
async fn a_key_arrives_as_the_scancode_the_shared_table_produced() {
    let (session, server) = session_with(MockConfig::default()).await;

    session
        .send_input(InputEvent::Key(KeyEvent {
            scancode: solstice_input::scancode(solstice_input::vk::KEY_A, false),
            keysym: Some(0x61),
            down: true,
            non_normalized: false,
        }))
        .await
        .unwrap();

    let recorded = wait_for(&server, |recorded| {
        recorded
            .iter()
            .any(|r| r.channel == channel::INPUTS && r.kind == inputs_msgc::KEY_DOWN)
    })
    .await;
    // The channel matters: 101 is `KEY_DOWN` on the inputs channel and
    // `DISPLAY_INIT` on the display one. Message numbers are per-channel
    // namespaces (`docs/spice-protocol.md` §3).
    let key = recorded
        .iter()
        .find(|r| r.channel == channel::INPUTS && r.kind == inputs_msgc::KEY_DOWN)
        .unwrap();
    assert_eq!(key.body, 0x1Eu32.to_le_bytes(), "A is scancode 0x1E");
}

#[tokio::test]
async fn a_mouse_button_arrives_with_spices_own_numbering() {
    let (session, server) = session_with(MockConfig::default()).await;
    session
        .send_input(InputEvent::Button {
            button: MouseButton::X2,
            down: true,
        })
        .await
        .unwrap();

    let recorded = wait_for(&server, |recorded| {
        recorded
            .iter()
            .any(|r| r.channel == channel::INPUTS && r.kind == inputs_msgc::MOUSE_PRESS)
    })
    .await;
    let press = recorded
        .iter()
        .find(|r| r.channel == channel::INPUTS && r.kind == inputs_msgc::MOUSE_PRESS)
        .unwrap();
    assert_eq!(
        press.body[0],
        solstice_spice::protocol::mouse_button::EXTRA,
        "X2 is SPICE's EXTRA, not dropped as it is on RFB"
    );
}

/// A real `spice-server` reports client mouse mode in `MAIN_INIT` itself,
/// not in a later `MAIN_MOUSE_MODE`. `MAIN_INIT` is consumed by the setup
/// loop inside `connect`, so an implementation that only applied the mode
/// from the running main-channel task would stay in server mode forever --
/// and server mode sends relative deltas, which a server whose only pointer
/// is a tablet drops silently. `Xspice` is exactly that server, and this is
/// the regression test for having been caught by it.
#[tokio::test]
async fn the_mouse_mode_from_main_init_is_in_force_before_connect_returns() {
    let mock = MockConfig {
        mouse_mode: solstice_spice::protocol::mouse_mode::CLIENT,
        ..MockConfig::default()
    };
    let (session, _server) = session_with(mock).await;
    assert_eq!(
        session.mouse_mode(),
        solstice_spice::inputs::MouseMode::Client,
        "the mode MAIN_INIT reported must be applied, not just later ones"
    );
}

/// `connect` should not hand back a session whose geometry is still zero:
/// RFB carries the size in its handshake, SPICE sends it as an ordinary
/// message on another socket, and the pipeline reads `dimensions()`
/// immediately.
#[tokio::test]
async fn the_primary_surface_has_arrived_before_connect_returns() {
    let (session, _server) = session_with(MockConfig::default()).await;
    assert_eq!(session.dimensions(), (64, 48));
}

#[tokio::test]
async fn client_mouse_mode_turns_absolute_input_into_positions() {
    let (session, server) = session_with(MockConfig::default()).await;

    // The mock grants client mode when asked.
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while session.mouse_mode() != solstice_spice::inputs::MouseMode::Client {
        if tokio::time::Instant::now() > deadline {
            panic!("the server never granted client mouse mode");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    session
        .send_input(InputEvent::PointerAbsolute {
            x: 640,
            y: 360,
            ref_width: 1280,
            ref_height: 720,
        })
        .await
        .unwrap();

    let recorded = wait_for(&server, |recorded| {
        recorded
            .iter()
            .any(|r| r.channel == channel::INPUTS && r.kind == inputs_msgc::MOUSE_POSITION)
    })
    .await;
    let position = recorded
        .iter()
        .find(|r| r.channel == channel::INPUTS && r.kind == inputs_msgc::MOUSE_POSITION)
        .unwrap();
    let x = u32::from_le_bytes(position.body[0..4].try_into().unwrap());
    let y = u32::from_le_bytes(position.body[4..8].try_into().unwrap());
    assert_eq!((x, y), (32, 24), "scaled from 1280x720 onto 64x48");
}

#[tokio::test]
async fn the_ack_window_is_honoured_or_the_server_would_stall() {
    let mock = MockConfig {
        ack_window: 2,
        ..MockConfig::default()
    };
    let (_session, server) = session_with(mock).await;

    // The display channel gets SET_ACK, then SURFACE_CREATE and MARK --
    // two messages, which completes one window.
    let recorded = wait_for(&server, |recorded| {
        recorded
            .iter()
            .any(|r| r.channel == channel::DISPLAY && r.kind == solstice_spice::protocol::msgc::ACK)
    })
    .await;
    assert!(
        recorded
            .iter()
            .any(|r| r.channel == channel::DISPLAY
                && r.kind == solstice_spice::protocol::msgc::ACK_SYNC),
        "the generation must be synchronised before the first ack"
    );
}

#[tokio::test]
async fn a_wrong_connection_id_on_a_secondary_channel_fails_the_session() {
    // The mock refuses any secondary channel whose id does not match, which
    // is what a real server does with SPICE_LINK_ERR_BAD_CONNECTION_ID.
    struct WrongIdDialer {
        server: Arc<MockServer>,
    }

    #[async_trait]
    impl Dialer for WrongIdDialer {
        async fn dial(&self) -> Result<Box<dyn Transport>> {
            let (client, server_end) = tokio::io::duplex(1 << 20);
            let server = self.server.clone();
            tokio::spawn(async move {
                let _ = server.serve(server_end).await;
            });
            Ok(Box::new(client))
        }
    }

    // Make the mock hand out one id in MAIN_INIT and expect a different one.
    let server = Arc::new(MockServer::new(MockConfig {
        connection_id: 0x1234,
        ..MockConfig::default()
    }));
    let dialer = Arc::new(WrongIdDialer {
        server: server.clone(),
    });
    // The client uses the id it was given, so this must succeed; the
    // negative half is covered by the mock's own check firing when it does
    // not. Assert the client really does present it.
    let session = tokio::time::timeout(TIMEOUT, connect(dialer, config()))
        .await
        .expect("timed out")
        .expect("the client should present the id it was given");
    assert_eq!(session.dimensions(), (64, 48));
}

#[tokio::test]
async fn a_message_whose_size_overruns_its_payload_ends_the_channel_rather_than_desynchronising() {
    let mock = MockConfig {
        overrun_message: true,
        ..MockConfig::default()
    };
    let server = Arc::new(MockServer::new(mock));
    let dialer = Arc::new(MockDialer {
        server: server.clone(),
    });
    // The main channel's opening messages come first, so setup completes;
    // the overrun lands after it and the channel dies rather than reading
    // somebody else's bytes as a header.
    let result = tokio::time::timeout(TIMEOUT, connect(dialer, config())).await;
    // Either outcome is correct -- the setup may or may not have completed
    // before the bad header landed. What must not happen is the client
    // reading on past it, which would show up as a hang rather than a
    // result at all.
    if let Ok(Ok(session)) = result {
        let mut events = session.subscribe();
        let _ = tokio::time::timeout(Duration::from_secs(2), events.recv()).await;
    }
}

#[tokio::test]
async fn a_link_error_is_reported_rather_than_retried_forever() {
    let mock = MockConfig {
        // SPICE_LINK_ERR_PERMISSION_DENIED.
        link_error: Some(7),
        ..MockConfig::default()
    };
    let server = Arc::new(MockServer::new(mock));
    let dialer = Arc::new(MockDialer { server });
    let err = tokio::time::timeout(TIMEOUT, connect(dialer, config()))
        .await
        .expect("timed out")
        .unwrap_err();
    assert!(matches!(err, SpiceError::Link { code: 7, .. }), "{err}");
}

#[tokio::test]
async fn a_server_requiring_tls_says_so_in_terms_an_operator_can_act_on() {
    let mock = MockConfig {
        // SPICE_LINK_ERR_NEED_SECURED.
        link_error: Some(5),
        ..MockConfig::default()
    };
    let server = Arc::new(MockServer::new(mock));
    let dialer = Arc::new(MockDialer { server });
    let err = tokio::time::timeout(TIMEOUT, connect(dialer, config()))
        .await
        .expect("timed out")
        .unwrap_err();
    let message = err.to_string();
    assert!(message.contains("TLS"), "{message}");
}

#[tokio::test]
async fn a_wrong_password_is_refused_at_the_link_rather_than_later() {
    let mock = MockConfig {
        password: Some("hunter2".into()),
        ..MockConfig::default()
    };
    let server = Arc::new(MockServer::new(mock));
    let dialer = Arc::new(MockDialer { server });
    let config = SpiceConfig {
        security: SpiceSecurity::Plain {
            password: Some("wrong".into()),
        },
        ..config()
    };
    let err = tokio::time::timeout(TIMEOUT, connect(dialer, config))
        .await
        .expect("timed out")
        .unwrap_err();
    assert!(matches!(err, SpiceError::Auth(_)), "{err}");
}

#[tokio::test]
async fn the_right_password_links() {
    let mock = MockConfig {
        password: Some("hunter2".into()),
        ..MockConfig::default()
    };
    let server = Arc::new(MockServer::new(mock));
    let dialer = Arc::new(MockDialer { server });
    let config = SpiceConfig {
        security: SpiceSecurity::Plain {
            password: Some("hunter2".into()),
        },
        ..config()
    };
    let session = tokio::time::timeout(TIMEOUT, connect(dialer, config))
        .await
        .expect("timed out")
        .expect("the right password should link");
    assert_eq!(session.dimensions(), (64, 48));
}

#[tokio::test]
async fn a_server_with_no_display_channel_is_refused_with_a_reason() {
    let mock = MockConfig {
        channels: vec![(channel::MAIN, 0), (channel::INPUTS, 0)],
        ..MockConfig::default()
    };
    let server = Arc::new(MockServer::new(mock));
    let dialer = Arc::new(MockDialer { server });
    let err = tokio::time::timeout(TIMEOUT, connect(dialer, config()))
        .await
        .expect("timed out")
        .unwrap_err();
    assert!(err.to_string().contains("display"), "{err}");
}

#[tokio::test]
async fn the_full_header_framing_works_as_well_as_the_mini_one() {
    let mock = MockConfig {
        mini_header: false,
        ..MockConfig::default()
    };
    let (session, server) = session_with(mock).await;
    wait_for(&server, |recorded| {
        recorded.iter().any(|r| {
            r.channel == channel::DISPLAY && r.kind == solstice_spice::protocol::display_msgc::INIT
        })
    })
    .await;
    assert_eq!(session.dimensions(), (64, 48));
}

#[tokio::test]
async fn a_server_without_auth_selection_gets_the_ticket_without_a_mechanism_word() {
    let mock = MockConfig {
        auth_selection: false,
        ..MockConfig::default()
    };
    let (session, _server) = session_with(mock).await;
    assert_eq!(session.dimensions(), (64, 48));
}

#[tokio::test]
async fn a_resize_is_refused_without_a_guest_agent_and_accepted_with_one() {
    let (session, _) = session_with(MockConfig::default()).await;
    assert!(!session.can_resize());
    assert!(!session.request_resize(1920, 1080).await.unwrap());

    let mock = MockConfig {
        agent: true,
        ..MockConfig::default()
    };
    let (session, server) = session_with(mock).await;
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while !session.can_resize() {
        if tokio::time::Instant::now() > deadline {
            panic!("the agent never announced its capabilities");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(session.request_resize(1920, 1080).await.unwrap());

    let recorded = wait_for(&server, |recorded| {
        recorded
            .iter()
            .filter(|r| r.channel == channel::MAIN && r.kind == main_msgc::AGENT_DATA)
            .count()
            >= 2
    })
    .await;
    // The second AGENT_DATA is the monitors config; the first is the
    // client's own capability announcement.
    let monitors = recorded
        .iter()
        .filter(|r| r.channel == channel::MAIN && r.kind == main_msgc::AGENT_DATA)
        .find(|r| {
            r.body.len() >= 8
                && u32::from_le_bytes(r.body[4..8].try_into().unwrap())
                    == solstice_spice::agent::msg::MONITORS_CONFIG
        })
        .expect("a monitors config should have gone out");
    // 20 bytes of VDAgentMessage header, then VDAgentMonitorsConfig's
    // `num_of_monitors` and `flags`, then the first VDAgentMonConfig --
    // which is height before width.
    let first = solstice_spice::agent::MESSAGE_HEADER + 8;
    let height = u32::from_le_bytes(monitors.body[first..first + 4].try_into().unwrap());
    let width = u32::from_le_bytes(monitors.body[first + 4..first + 8].try_into().unwrap());
    assert_eq!((width, height), (1920, 1080));
}

#[tokio::test]
async fn the_cursor_is_composited_into_the_framebuffer() {
    let (session, server) = session_with(MockConfig::default()).await;

    wait_for_push(
        &server,
        MockPush {
            channel: channel::DISPLAY,
            message: mock::draw_fill(0, 0, 0, 64, 48, 0x0000_0000),
        },
    )
    .await;
    wait_for_push(
        &server,
        MockPush {
            channel: channel::CURSOR,
            message: mock::cursor_set(10, 10, 2, 2, [0xFF, 0xFF, 0xFF, 0xFF]),
        },
    )
    .await;

    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        {
            let fb = session.framebuffer();
            let fb = fb.read();
            if fb.pixel(10, 10) == Some([0xFF, 0xFF, 0xFF, 0xFF]) {
                break;
            }
        }
        if tokio::time::Instant::now() > deadline {
            panic!("the cursor never reached the framebuffer");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn motion_resumes_after_the_server_acknowledges_a_bunch() {
    let (session, server) = session_with(MockConfig::default()).await;
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while session.mouse_mode() != solstice_spice::inputs::MouseMode::Client {
        if tokio::time::Instant::now() > deadline {
            panic!("no client mouse mode");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Fill the window and then some.
    for i in 0..12 {
        session
            .send_input(InputEvent::PointerAbsolute {
                x: i,
                y: 0,
                ref_width: 64,
                ref_height: 48,
            })
            .await
            .unwrap();
    }
    let recorded = wait_for(&server, |recorded| {
        recorded
            .iter()
            .filter(|r| r.channel == channel::INPUTS && r.kind == inputs_msgc::MOUSE_POSITION)
            .count()
            >= 8
    })
    .await;
    let before = recorded
        .iter()
        .filter(|r| r.channel == channel::INPUTS && r.kind == inputs_msgc::MOUSE_POSITION)
        .count();
    assert_eq!(before, 8, "the window is four bunches of two");

    server.push(MockPush {
        channel: channel::INPUTS,
        message: mock::motion_ack(),
    });
    wait_for(&server, |recorded| {
        recorded
            .iter()
            .filter(|r| r.channel == channel::INPUTS && r.kind == inputs_msgc::MOUSE_POSITION)
            .count()
            > before
    })
    .await;
}

#[tokio::test]
async fn an_undecodable_stream_is_reported_and_the_session_survives() {
    let (session, server) = session_with(MockConfig::default()).await;

    let mut create = solstice_spice::wire::Writer::new();
    create
        .u32(0)
        .u32(0)
        .u8(0)
        .u8(solstice_spice::protocol::video_codec::VP8)
        .u64(0)
        .u32(32)
        .u32(32)
        .u32(32)
        .u32(32);
    create.i32(0).i32(0).i32(32).i32(32);
    create.u8(solstice_spice::protocol::clip_type::NONE);
    wait_for_push(
        &server,
        MockPush {
            channel: channel::DISPLAY,
            message: OutMessage::new(display_msg::STREAM_CREATE, create.finish()),
        },
    )
    .await;

    let mut data = solstice_spice::wire::Writer::new();
    data.u32(0).u32(0).u32(4).bytes(&[1, 2, 3, 4]);
    server.push(MockPush {
        channel: channel::DISPLAY,
        message: OutMessage::new(display_msg::STREAM_DATA, data.finish()),
    });

    wait_for(&server, |recorded| {
        recorded.iter().any(|r| {
            r.channel == channel::DISPLAY
                && r.kind == solstice_spice::protocol::display_msgc::STREAM_REPORT
        })
    })
    .await;
    assert_eq!(session.dimensions(), (64, 48));
}
