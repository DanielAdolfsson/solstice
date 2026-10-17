//! The harness proving itself, so a failing backend test is not the first
//! place anyone finds out the guest is broken.

use solstice_test_guest::{Guest, GuestConfig, Spice};

#[test]
fn the_guest_boots_and_answers_on_both_channels() {
    let Some(guest) = Guest::start(GuestConfig::new().geometry(800, 600).vnc()) else {
        return;
    };

    // The agent channel.
    let uname = guest.sh("uname -s -m").expect("uname in the guest");
    assert!(
        uname.contains("Linux"),
        "unexpected guest kernel: {uname:?}"
    );

    // The QMP channel, and the geometry that came off the kernel command line.
    let shot = guest.screendump().expect("screendump");
    assert_eq!(
        (shot.width, shot.height),
        (800, 600),
        "the guest did not take the requested geometry; console:\n{}",
        guest.console()
    );

    assert!(guest.vnc_port() > 5900, "no VNC port");
}

#[test]
fn a_fill_is_visible_to_qemus_own_capture() {
    let Some(guest) = Guest::start(GuestConfig::new().geometry(640, 480).vnc()) else {
        return;
    };

    // Each colour has to survive the painting process exiting, which is the
    // whole reason `fill` is solstice-draw and not xsetroot.
    for (name, hex, rgb) in [
        ("red", "ff0000", [0xff, 0x00, 0x00]),
        ("green", "00ff00", [0x00, 0xff, 0x00]),
        ("blue", "0000ff", [0x00, 0x00, 0xff]),
    ] {
        guest
            .fill(hex)
            .unwrap_or_else(|e| panic!("fill {name}: {e}"));
        let shot = guest.screendump().expect("screendump");
        assert_eq!(
            shot.uniform(),
            Some(rgb),
            "after painting {name} the capture was {shot:?}"
        );
    }
}

#[test]
fn the_core_x11_primitives_run_in_the_guest() {
    let Some(guest) = Guest::start(GuestConfig::new().geometry(640, 480).vnc()) else {
        return;
    };

    guest.fill("000000").expect("fill");
    for primitive in ["stroke", "text", "rop3"] {
        guest
            .draw(primitive, &[])
            .unwrap_or_else(|e| panic!("solstice-draw {primitive}: {e}"));
    }

    // Each primitive leaves marks, so the screen must no longer be one colour.
    let shot = guest.screendump().expect("screendump");
    assert!(
        shot.uniform().is_none(),
        "the primitives drew nothing: {shot:?}"
    );
}

#[test]
fn a_spice_guest_comes_up_with_its_agent() {
    let Some(guest) = Guest::start(
        GuestConfig::new().spice(
            Spice::new()
                .image_compression("quic")
                .streaming_video("off"),
        ),
    ) else {
        return;
    };

    assert!(guest.spice_port() > 5900, "no SPICE port");

    let spice = guest
        .qmp("query-spice", serde_json::json!({}))
        .expect("query-spice");
    assert_eq!(spice["enabled"], true, "SPICE is not enabled: {spice}");

    let agent = guest.sh("pgrep -c spice-vdagent || true").expect("pgrep");
    assert_ne!(
        agent.trim(),
        "0",
        "spice-vdagent is not running; console:\n{}",
        guest.console()
    );
}
