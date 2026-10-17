//! `solstice pair`, `status`, `list-clients` and `revoke`, run as the real
//! binary against a running daemon over its management socket.
//!
//! The binary rather than `management::call`, because what was missing was a
//! *second process* reaching the daemon: the old `solstice pair` refused to
//! run, and the old `revoke` edited `clients.tsv` while the daemon went on
//! trusting the client it held in memory. A test in one process could not have
//! seen either.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{
    https_client, https_get, pair, start_daemon_closed, start_daemon_endpoints, Ports, PIN,
};
use solstice::config::Config;
use solstice::testpattern::TestPatternBackend;
use solstice_gamestream::crypto::certs::{ClientStore, HostIdentity, PairedClient};
use solstice_gamestream::nvhttp::applist::PLACEHOLDER_APP_ID;
use solstice_gamestream::nvhttp::Host;
use tokio::process::Command;

fn daemon(base: u16, tag: &str) -> (Arc<Host>, PathBuf, PathBuf) {
    let mut config = Config::default();
    config.server.port = base;
    let (host, state_dir) =
        start_daemon_closed(config, tag, Arc::new(TestPatternBackend::new(320, 240, 30)));
    (host, state_dir.clone(), config_file(&state_dir))
}

/// The CLI finds the socket through the configuration, as it does in a real
/// deployment, so each test writes one naming its state directory.
fn config_file(state_dir: &Path) -> PathBuf {
    std::fs::create_dir_all(state_dir).unwrap();
    let path = state_dir.join("solstice.toml");
    std::fs::write(
        &path,
        format!(
            "[server]\nstate_dir = {:?}\n",
            state_dir.display().to_string()
        ),
    )
    .unwrap();
    path
}

fn solstice(config: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_solstice"));
    command
        .arg("--config")
        .arg(config)
        .args(args)
        .env("SOLSTICE_LOG", "warn")
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    command
}

struct Run {
    ok: bool,
    stdout: String,
    stderr: String,
}

async fn finish(child: tokio::process::Child) -> Run {
    let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .expect("the command did not finish")
        .unwrap();
    Run {
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

async fn run(config: &Path, args: &[&str]) -> Run {
    finish(solstice(config, args).spawn().unwrap()).await
}

async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn window_open(host: &Host) -> bool {
    host.pairing.lock().unwrap().is_open(Instant::now())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pair_status_list_and_revoke_reach_the_running_daemon() {
    const PORTS: Ports = Ports::from_base(49389);
    let (host, state_dir, config) = daemon(PORTS.http, "mgmt");
    let socket = state_dir.join("control.sock");
    eventually("the management socket", || socket.exists()).await;

    let status = run(&config, &["status"]).await;
    assert!(status.ok, "{}", status.stderr);
    assert!(
        status.stdout.contains("pairing: closed"),
        "{}",
        status.stdout
    );
    assert!(
        status
            .stdout
            .contains("endpoint: Desktop (app 1): testpattern"),
        "{}",
        status.stdout
    );

    // `solstice pair` holds on until the client has paired, as a script
    // alongside `moonlight pair -pin` needs it to.
    let pairing = solstice(&config, &["pair", "--pin", PIN, "--window", "30s"])
        .spawn()
        .unwrap();
    eventually("the window to open", || window_open(&host)).await;

    let status = run(&config, &["status"]).await;
    assert!(status.stdout.contains("pairing: open"), "{}", status.stdout);

    let client_identity = HostIdentity::generate("client").unwrap();
    pair(PORTS, &client_identity).await;

    let paired = finish(pairing).await;
    assert!(paired.ok, "pair failed: {}", paired.stderr);
    assert!(
        paired.stdout.contains("pairing is open for 30s"),
        "{}",
        paired.stdout
    );
    assert!(paired.stdout.contains("paired test ("), "{}", paired.stdout);
    assert!(!window_open(&host), "one pairing per window");

    let listed = run(&config, &["list-clients"]).await;
    assert!(listed.ok, "{}", listed.stderr);
    let line = listed.stdout.lines().next().expect("one client");
    assert!(line.contains("test"), "{line}");
    let fingerprint = line.split_whitespace().next().unwrap();

    // The point of revoking through the daemon: the client it holds in memory
    // goes, not just the line in the file.
    assert!(host.is_paired(client_identity.cert_der()));
    let revoked = run(&config, &["revoke", &fingerprint[..8]]).await;
    assert!(revoked.ok, "{}", revoked.stderr);
    assert!(
        revoked.stdout.contains("revoked test"),
        "{}",
        revoked.stdout
    );
    assert!(!host.is_paired(client_identity.cert_der()));
    assert!(ClientStore::load(state_dir.join("clients.tsv"))
        .unwrap()
        .is_empty());

    let listed = run(&config, &["list-clients"]).await;
    assert_eq!(listed.stdout.trim(), "no paired clients");

    let _ = std::fs::remove_dir_all(&state_dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupting_pair_closes_the_window() {
    let (host, state_dir, config) = daemon(49489, "mgmt-int");
    eventually("the management socket", || {
        state_dir.join("control.sock").exists()
    })
    .await;

    let mut pairing = solstice(&config, &["pair", "--pin", PIN]).spawn().unwrap();
    eventually("the window to open", || window_open(&host)).await;
    pairing.kill().await.unwrap();
    eventually("the window to close", || !window_open(&host)).await;

    let _ = std::fs::remove_dir_all(&state_dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_window_nobody_uses_fails_the_command() {
    let (host, state_dir, config) = daemon(49589, "mgmt-exp");
    eventually("the management socket", || {
        state_dir.join("control.sock").exists()
    })
    .await;

    let expired = run(&config, &["pair", "--pin", PIN, "--window", "1s"]).await;
    assert!(!expired.ok);
    assert!(
        expired.stderr.contains("closed before a client paired"),
        "{}",
        expired.stderr
    );
    assert!(!window_open(&host));

    for refused in [
        &["pair", "--pin", PIN, "--window", "11m"][..],
        &["pair", "--pin", "12"][..],
        &["revoke", "abc"][..],
    ] {
        let run = run(&config, refused).await;
        assert!(!run.ok, "{refused:?} succeeded");
    }
    assert!(!window_open(&host));

    let _ = std::fs::remove_dir_all(&state_dir);
}

/// With no daemon, `list-clients` and `revoke` work on the state directory;
/// `pair` and `status` say plainly that there is nothing to talk to.
#[tokio::test]
async fn without_a_daemon_the_client_list_is_edited_directly() {
    let state_dir =
        std::env::temp_dir().join(format!("solstice-e2e-mgmt-off-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state_dir);
    let config = config_file(&state_dir);
    let mut store = ClientStore::load(state_dir.join("clients.tsv")).unwrap();
    let identity = HostIdentity::generate("offline").unwrap();
    store
        .add(PairedClient {
            cert_der: identity.cert_der().to_vec(),
            device_name: "offline-tv".into(),
            unique_id: "0123456789ABCDEF".into(),
        })
        .unwrap();

    let listed = run(&config, &["list-clients"]).await;
    assert!(listed.ok, "{}", listed.stderr);
    let fingerprint = solstice::management::fingerprint(identity.cert_der());
    assert!(
        listed
            .stdout
            .starts_with(&format!("{}  offline-tv", &fingerprint[..16])),
        "{}",
        listed.stdout
    );

    let revoked = run(&config, &["revoke", &fingerprint[..6]]).await;
    assert!(revoked.ok, "{}", revoked.stderr);
    assert!(ClientStore::load(state_dir.join("clients.tsv"))
        .unwrap()
        .is_empty());

    for args in [&["pair", "--pin", PIN][..], &["status"][..]] {
        let run = run(&config, args).await;
        assert!(!run.ok);
        assert!(run.stderr.contains("not running"), "{}", run.stderr);
    }

    let _ = std::fs::remove_dir_all(&state_dir);
}

/// Endpoints from the configuration and from `--endpoint`, through the real
/// binary, and what `status` says about them -- none included.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn status_lists_the_endpoints_from_the_file_and_the_flags() {
    const PORTS: Ports = Ports::from_base(49989);
    let state_dir =
        std::env::temp_dir().join(format!("solstice-e2e-endpoints-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state_dir);
    let config = config_file(&state_dir);
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(&format!(
        "port = {}\n\n[[endpoint]]\nname = \"From the file\"\nkind = \"testpattern\"\n",
        PORTS.http
    ));
    std::fs::write(&config, text).unwrap();

    // A bad flag stops the daemon before it creates anything.
    let refused = run(
        &config,
        &["run", "--endpoint", "name=From the file,kind=testpattern"],
    )
    .await;
    assert!(!refused.ok);
    assert!(
        refused
            .stderr
            .contains("two endpoints are named `From the file`"),
        "{}",
        refused.stderr
    );

    let daemon = solstice(
        &config,
        &["run", "--endpoint", "name=From a flag, kind=testpattern"],
    )
    .spawn()
    .unwrap();
    let socket = state_dir.join("control.sock");
    eventually("the management socket", || socket.exists()).await;

    let status = run(&config, &["status"]).await;
    assert!(status.ok, "{}", status.stderr);
    for name in ["From the file", "From a flag"] {
        let id = solstice::endpoint::app_id(name);
        assert!(
            status
                .stdout
                .contains(&format!("endpoint: {name} (app {id}): testpattern")),
            "{}",
            status.stdout
        );
    }
    drop(daemon);
    let _ = std::fs::remove_dir_all(&state_dir);

    // And with none at all, which is a daemon that still pairs. On ports of
    // its own, so as not to race the killed one's.
    let mut config = Config::default();
    config.server.port = Ports::from_base(50089).http;
    let (_host, state_dir) = start_daemon_endpoints(
        config,
        "no-endpoints",
        solstice::endpoint::Endpoints::new(Vec::new()).unwrap(),
    );
    let config = config_file(&state_dir);
    let socket = state_dir.join("control.sock");
    eventually("the management socket", || socket.exists()).await;
    let status = run(&config, &["status"]).await;
    assert!(status.ok, "{}", status.stderr);
    assert!(
        status
            .stdout
            .contains("endpoints: none; Moonlight shows a \"No desktops\" placeholder"),
        "{}",
        status.stdout
    );
    let _ = std::fs::remove_dir_all(&state_dir);
}

/// `solstice endpoint add`, `list` and `remove` against a running daemon:
/// what Moonlight is offered follows at once, the startup refusals hold, and
/// removing an endpoint takes its session with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn endpoints_are_added_and_removed_on_a_running_daemon() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    const PORTS: Ports = Ports::from_base(50189);
    let mut config = Config::default();
    config.server.port = PORTS.http;
    let (host, state_dir) = start_daemon_endpoints(
        config,
        "endpoint-socket",
        solstice::endpoint::Endpoints::new(Vec::new()).unwrap(),
    );
    let config = config_file(&state_dir);
    eventually("the management socket", || {
        state_dir.join("control.sock").exists()
    })
    .await;
    host.pairing
        .lock()
        .unwrap()
        .open(PIN, Duration::from_secs(60), Instant::now())
        .unwrap();
    let client_identity = HostIdentity::generate("client").unwrap();
    pair(PORTS, &client_identity).await;
    let https = https_client(&client_identity);

    let listed = run(&config, &["endpoint", "list"]).await;
    assert!(listed.ok, "{}", listed.stderr);
    assert_eq!(listed.stdout.trim(), "no endpoints");
    let applist = https_get(&https, PORTS, "/applist").await;
    assert!(
        applist.contains(&format!("<ID>{PLACEHOLDER_APP_ID}</ID>"))
            && applist.matches("<App>").count() == 1,
        "only the placeholder: {applist}"
    );

    let id = solstice::endpoint::app_id("Colour bars");
    let added = run(
        &config,
        &["endpoint", "add", "name=Colour bars,kind=testpattern"],
    )
    .await;
    assert!(added.ok, "{}", added.stderr);
    assert_eq!(
        added.stdout.trim(),
        format!("added Colour bars (app {id}): testpattern")
    );
    let applist = https_get(&https, PORTS, "/applist").await;
    assert!(
        applist.contains(&format!("<AppTitle>Colour bars</AppTitle><ID>{id}</ID>")),
        "{applist}"
    );

    // The refusals a configuration file gets, from the daemon itself: the
    // request is sent raw, past the CLI's own checks.
    for (spec, why) in [
        ("name=Colour bars,kind=testpattern", "named `Colour bars`"),
        (
            "name=Far,kind=spice,host=10.0.0.1,security=plain",
            "refused against 10.0.0.1",
        ),
        ("name=Rel,kind=vnc,password_file=pw", "absolute path"),
    ] {
        let refused = raw(&state_dir, &format!("endpoint add {spec}"));
        assert!(refused.starts_with("err "), "{spec}: {refused}");
        assert!(refused.contains(why), "{spec}: {refused}");
    }
    assert_eq!(host.apps().len(), 1, "a refused add changes nothing");

    // A launch, then the endpoint goes: the session goes with it.
    let launched = https_get(
        &https,
        PORTS,
        &format!(
            "/launch?rikey=000102030405060708090a0b0c0d0e0f&rikeyid=1&localAudioPlayMode=0&appid={id}"
        ),
    )
    .await;
    assert!(launched.contains("sessionUrl0"), "{launched}");
    assert_eq!(host.sessions.lock().unwrap().len(), 1);

    let removed = run(&config, &["endpoint", "remove", "Colour bars"]).await;
    assert!(removed.ok, "{}", removed.stderr);
    assert_eq!(
        removed.stdout.trim(),
        "removed Colour bars; its stream was ended"
    );
    assert!(host.sessions.lock().unwrap().is_empty());
    let applist = https_get(&https, PORTS, "/applist").await;
    assert!(
        applist.contains(&format!("<ID>{PLACEHOLDER_APP_ID}</ID>"))
            && applist.matches("<App>").count() == 1,
        "only the placeholder: {applist}"
    );

    let again = run(&config, &["endpoint", "remove", "Colour bars"]).await;
    assert!(!again.ok);
    assert!(
        again.stderr.contains("no endpoint is named `Colour bars`"),
        "{}",
        again.stderr
    );

    let _ = std::fs::remove_dir_all(&state_dir);
}

/// One request line straight to the socket, and the reply's last line.
fn raw(state_dir: &Path, line: &str) -> String {
    use std::io::{BufRead, Write};
    let mut stream =
        std::os::unix::net::UnixStream::connect(state_dir.join("control.sock")).unwrap();
    writeln!(stream, "{line}").unwrap();
    std::io::BufReader::new(stream)
        .lines()
        .map(Result::unwrap)
        .last()
        .unwrap_or_default()
}
