//! A real QEMU guest, for the tests that need a real server.
//!
//! `docs/testing.md` used to put `Xvnc` and `Xspice` at this tier. Both are
//! gone: one QEMU boot now serves both backends from the same image, and it
//! reaches three things neither could. A real `spice-vdagent` answers, rather
//! than the mock -- the packaged `Xspice` launcher structurally cannot start
//! one. A real QXL guest driver emits the draw commands `Xspice` never sends,
//! because `Xspice` renders through the frame buffer and produces `DRAW_COPY`
//! and `DRAW_FILL` for everything. And QEMU's own `screendump` becomes an
//! independent oracle, which is a stronger claim than a test comparing pixels
//! against the colour it asked for. `docs/roadmap.md` §2.7 is the list.
//!
//! # The shape every test must keep
//!
//! **Connect first, repaint second.** QEMU only renders guest damage into the
//! console surface while a display client is attached: a repaint performed
//! with nothing connected is dropped, and a client connecting afterwards is
//! served a stale surface. A test that paints before connecting therefore
//! fails for a reason that has nothing to do with Solstice. This was already
//! the right shape for a different reason -- a client that only ever sees the
//! screen as it was at connect time can be broken for incremental updates and
//! still pass -- and here it is also mandatory.
//!
//! # Two channels, not one
//!
//! `screendump` is a QMP command and `guest-exec` is not; the guest agent
//! speaks its own protocol on its own socket. [`Guest`] holds both.
//!
//! ```no_run
//! # use solstice_test_guest::{Guest, GuestConfig, Spice};
//! let Some(guest) = Guest::start(
//!     GuestConfig::new().spice(Spice::new().image_compression("quic")),
//! ) else {
//!     return; // prerequisites absent; the note is already printed
//! };
//! // ... connect a client to 127.0.0.1:guest.spice_port() ...
//! guest.fill("ff0000").unwrap();
//! assert_eq!(guest.screendump().unwrap().uniform(), Some([0xff, 0, 0]));
//! ```

#![forbid(unsafe_code)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{json, Value};

mod ppm;
mod proto;

pub use ppm::Ppm;

/// How long to wait for the agent to answer and X to come up. Generous
/// because a host without `/dev/kvm` falls back to TCG, where this guest
/// boots in well under a minute but not in five seconds.
const READY_TIMEOUT: Duration = Duration::from_secs(120);

/// What went wrong.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An underlying I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A control channel produced something that was not JSON.
    #[error("malformed JSON on a control channel: {0}")]
    Json(#[from] serde_json::Error),
    /// QEMU or the guest agent refused a command.
    #[error("the {channel} channel rejected {command}: {message}")]
    Rejected {
        /// Which channel refused: `QMP` or `guest agent`.
        channel: &'static str,
        /// The command that was refused.
        command: String,
        /// The description the channel gave.
        message: String,
    },
    /// Something did not happen in time.
    #[error("timed out {0}")]
    Timeout(String),
    /// A command in the guest exited non-zero.
    #[error("`{command}` exited {code} in the guest: {stderr}")]
    Command {
        /// What was run.
        command: String,
        /// Its exit status.
        code: i64,
        /// Whatever it wrote to stderr.
        stderr: String,
    },
    /// A `screendump` could not be read.
    #[error("screendump: {0}")]
    Screendump(String),
}

/// Shorthand for this crate's results.
pub type Result<T> = std::result::Result<T, Error>;

/// The SPICE server's options, as `-spice` accepts them.
///
/// Every knob the `Xspice` launcher exposed is here, because `-spice` offers
/// the same set -- that parity is what made replacing `Xspice` possible.
#[derive(Clone, Debug)]
pub struct Spice {
    options: Vec<(String, String)>,
    agent: bool,
}

impl Default for Spice {
    fn default() -> Self {
        Self { options: Vec::new(), agent: true }
    }
}

impl Spice {
    /// A SPICE server with no options beyond the port and open ticketing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Boot without `spice-vdagent`'s transport, so the guest comes up
    /// agentless.
    ///
    /// Not a degraded guest but a distinct configuration worth testing:
    /// resize, clipboard and client-mode mouse all have a defined
    /// best-effort behaviour when no agent answers, and `Xspice` could only
    /// ever be tested in this state.
    pub fn without_agent(mut self) -> Self {
        self.agent = false;
        self
    }

    /// `off`, `auto_glz`, `auto_lz`, `quic`, `glz` or `lz`.
    ///
    /// Force one rather than letting the server's heuristics choose, so a
    /// test names the codec it is actually exercising.
    pub fn image_compression(self, mode: &str) -> Self {
        self.option("image-compression", mode)
    }

    /// `off`, `all` or `filter`.
    ///
    /// `all` is the one that breaks naive compositing, because streams are
    /// clipped sub-rectangles layered over the draw commands.
    pub fn streaming_video(self, mode: &str) -> Self {
        self.option("streaming-video", mode)
    }

    /// Any other `-spice` key, for the options no test has needed yet.
    pub fn option(mut self, key: &str, value: &str) -> Self {
        self.options.push((key.to_owned(), value.to_owned()));
        self
    }
}

/// How to start the guest.
#[derive(Clone, Debug)]
pub struct GuestConfig {
    width: u32,
    height: u32,
    memory_mb: u32,
    spice: Option<Spice>,
    vnc: bool,
}

impl Default for GuestConfig {
    fn default() -> Self {
        Self {
            width: 1280,
            height: 720,
            // The guest is an initramfs, so the whole rootfs lives in RAM.
            memory_mb: 1024,
            spice: None,
            vnc: false,
        }
    }
}

impl GuestConfig {
    /// A guest with neither display server enabled; add at least one.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the guest's screen size. Passed on the kernel command line and
    /// substituted into `xorg.conf` by the guest's `/init`.
    pub fn geometry(mut self, width: u32, height: u32) -> Self {
        self.width = width;
        self.height = height;
        self
    }

    /// Serve SPICE on [`Guest::spice_socket`].
    pub fn spice(mut self, spice: Spice) -> Self {
        self.spice = Some(spice);
        self
    }

    /// Serve RFB on [`Guest::vnc_socket`].
    pub fn vnc(mut self) -> Self {
        self.vnc = true;
        self
    }

    /// Guest memory in MiB.
    pub fn memory_mb(mut self, mb: u32) -> Self {
        self.memory_mb = mb;
        self
    }
}

/// A booted guest. Killed and cleaned up on drop.
pub struct Guest {
    child: Child,
    dir: PathBuf,
    qmp: Mutex<proto::Channel>,
    qga: Mutex<proto::Channel>,
    spice_port: Option<u16>,
    vnc_port: Option<u16>,
}

/// What a command left behind in the guest.
#[derive(Clone, Debug)]
pub struct Output {
    /// Exit status.
    pub code: i64,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
}

/// Where `tests/guest/build-image.sh` puts the kernel and initramfs.
pub fn image_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("SOLSTICE_GUEST_DIR") {
        return PathBuf::from(dir);
    }
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    cache.join("solstice/guest")
}

/// A free loopback port.
///
/// The old `Xspice` harness hard-coded one port per test, which collides the
/// moment two runs overlap. Asking the kernel is both shorter and correct.
/// The VNC server is addressed by display number rather than port, so this
/// stays above 5900 to keep that arithmetic valid.
fn free_port() -> Result<u16> {
    for _ in 0..64 {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        drop(listener);
        if port > 5900 {
            return Ok(port);
        }
    }
    Err(Error::Timeout("finding a free loopback port".to_owned()))
}

/// Why the guest cannot be started here, if it cannot.
fn unavailable() -> Option<String> {
    let runnable = Command::new("qemu-system-x86_64")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok();
    if !runnable {
        return Some("qemu-system-x86_64 is not installed".to_owned());
    }
    let dir = image_dir();
    for file in ["vmlinuz", "initramfs.gz"] {
        if !dir.join(file).exists() {
            return Some(format!(
                "the test guest is not built ({} is missing); run tests/guest/build-image.sh",
                dir.join(file).display()
            ));
        }
    }
    None
}

/// Warn, without failing, when the built image predates the committed lock.
fn warn_if_stale() {
    let built = image_dir().join("manifest.lock");
    let committed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/guest/manifest.lock");
    if let (Ok(a), Ok(b)) = (std::fs::read(&built), std::fs::read(&committed)) {
        if a != b {
            println!(
                "note: the built guest image does not match tests/guest/manifest.lock; \
                 re-run tests/guest/build-image.sh --force if a test fails oddly"
            );
        }
    }
}

impl Guest {
    /// Boot a guest, or return `None` with a printed note when the host
    /// cannot run one.
    ///
    /// Missing prerequisites skip; a guest that fails to boot panics, because
    /// that is a broken image rather than an absent tool.
    pub fn start(config: GuestConfig) -> Option<Self> {
        if let Some(why) = unavailable() {
            println!("skipping: {why}");
            return None;
        }
        warn_if_stale();
        match Self::boot(config) {
            Ok(guest) => Some(guest),
            Err(e) => panic!("the test guest failed to boot: {e}"),
        }
    }

    fn boot(config: GuestConfig) -> Result<Self> {
        let dir = std::env::temp_dir().join(format!(
            "solstice-guest-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir)?;

        let images = image_dir();
        let sock = |name: &str| dir.join(name);
        let mut qemu = Command::new("qemu-system-x86_64");
        qemu.args(["-machine", "q35"])
            .args(["-m", &config.memory_mb.to_string()])
            .args(["-smp", "2"])
            .args(["-kernel", &images.join("vmlinuz").to_string_lossy()])
            .args(["-initrd", &images.join("initramfs.gz").to_string_lossy()])
            .args([
                "-append",
                &format!(
                    "console=ttyS0 quiet solstice.geometry={}x{}",
                    config.width, config.height
                ),
            ])
            // QXL regardless of which protocol is under test: it is the
            // device a real SPICE guest has, and the VNC server renders the
            // same console surface either way.
            .args(["-vga", "qxl"])
            .args(["-qmp", &format!("unix:{},server=on,wait=off", sock("qmp.sock").display())])
            .args([
                "-chardev",
                &format!("socket,path={},server=on,wait=off,id=qga0", sock("qga.sock").display()),
            ])
            .args(["-device", "virtio-serial"])
            .args(["-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0"])
            .args(["-serial", &format!("file:{}", sock("console.log").display())])
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        // KVM where it exists, TCG where it does not: a CI runner without
        // nested virtualisation still runs these, just slower.
        if Path::new("/dev/kvm").exists() {
            qemu.args(["-accel", "kvm"]);
        }

        // Both display protocols go over TCP rather than a unix socket: the
        // clients under test dial a host and port, and teaching them unix
        // sockets purely for the harness would be testing something nobody
        // ships.
        let mut spice_port = None;
        if let Some(spice) = &config.spice {
            let port = free_port()?;
            spice_port = Some(port);
            let mut value =
                format!("port={port},addr=127.0.0.1,disable-ticketing=on");
            for (key, option) in &spice.options {
                value.push_str(&format!(",{key}={option}"));
            }
            qemu.args(["-spice", &value]);
            if spice.agent {
                // Without this pair spice-vdagentd has no port and the guest
                // comes up agentless.
                qemu.args(["-chardev", "spicevmc,id=vdagent,name=vdagent"]);
                qemu.args(["-device", "virtserialport,chardev=vdagent,name=com.redhat.spice.0"]);
            }
        }
        let mut vnc_port = None;
        if config.vnc {
            let port = free_port()?;
            vnc_port = Some(port);
            qemu.args(["-vnc", &format!("127.0.0.1:{}", port - 5900)]);
        }

        let child = qemu.spawn()?;

        let mut qmp = proto::Channel::connect(&sock("qmp.sock"), "QMP", Duration::from_secs(20))?;
        qmp.qmp_handshake()?;
        let qga =
            proto::Channel::connect(&sock("qga.sock"), "guest agent", Duration::from_secs(20))?;

        let guest = Self {
            child,
            dir,
            qmp: Mutex::new(qmp),
            qga: Mutex::new(qga),
            spice_port,
            vnc_port,
        };
        guest.wait_until_ready()?;
        Ok(guest)
    }

    /// Block until the agent answers and X is serving.
    ///
    /// One mechanism for both: the agent has to be up to run anything, and
    /// `xdpyinfo` only succeeds once X is. No side channel, so no race
    /// between a readiness signal and the thing it claims is ready.
    fn wait_until_ready(&self) -> Result<()> {
        let deadline = Instant::now() + READY_TIMEOUT;
        while Instant::now() < deadline {
            if self.qga("guest-ping", json!({})).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        while Instant::now() < deadline {
            if matches!(self.exec(&["xdpyinfo"]), Ok(out) if out.code == 0) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(Error::Timeout(format!(
            "waiting for the guest to serve X; console said:\n{}",
            std::fs::read_to_string(self.dir.join("console.log")).unwrap_or_default()
        )))
    }

    /// Issue a QMP command.
    pub fn qmp(&self, command: &str, args: Value) -> Result<Value> {
        self.qmp.lock().expect("QMP channel poisoned").cmd(command, args)
    }

    /// Issue a guest-agent command.
    pub fn qga(&self, command: &str, args: Value) -> Result<Value> {
        self.qga.lock().expect("agent channel poisoned").cmd(command, args)
    }

    /// Run a program in the guest and wait for it, capturing both streams.
    ///
    /// `DISPLAY` is set to `:0`: the agent hands its children no environment,
    /// and the guest only ever runs one X server.
    pub fn exec(&self, argv: &[&str]) -> Result<Output> {
        let (path, args) = argv.split_first().expect("exec needs a program");
        let pid = self
            .qga(
                "guest-exec",
                json!({
                    "path": path,
                    "arg": args,
                    "env": ["DISPLAY=:0"],
                    "capture-output": true,
                }),
            )?
            .get("pid")
            .and_then(Value::as_i64)
            .ok_or_else(|| Error::Screendump("guest-exec returned no pid".to_owned()))?;

        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            let status = self.qga("guest-exec-status", json!({ "pid": pid }))?;
            if status.get("exited").and_then(Value::as_bool) == Some(true) {
                let decode = |key: &str| -> String {
                    status
                        .get(key)
                        .and_then(Value::as_str)
                        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                        .unwrap_or_default()
                };
                return Ok(Output {
                    code: status.get("exitcode").and_then(Value::as_i64).unwrap_or(-1),
                    stdout: decode("out-data"),
                    stderr: decode("err-data"),
                });
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Err(Error::Timeout(format!("running {argv:?} in the guest")))
    }

    /// [`Guest::exec`], failing when the command does.
    pub fn run(&self, argv: &[&str]) -> Result<String> {
        let out = self.exec(argv)?;
        if out.code != 0 {
            return Err(Error::Command {
                command: argv.join(" "),
                code: out.code,
                stderr: out.stderr,
            });
        }
        Ok(out.stdout)
    }

    /// Run a shell snippet in the guest.
    pub fn sh(&self, script: &str) -> Result<String> {
        self.run(&["/bin/sh", "-c", script])
    }

    /// Paint the whole root window one colour, given as `RRGGBB`.
    ///
    /// Uses the guest's `solstice-draw` rather than `xsetroot`, which does not
    /// work here: it leaves `_XSETROOT_ID` unset and the root reverts to black
    /// the moment it exits, because the background is only retained for a
    /// client that asked for `RetainPermanent`.
    pub fn fill(&self, rrggbb: &str) -> Result<()> {
        self.run(&["solstice-draw", "fill", rrggbb]).map(drop)
    }

    /// Draw with a core X11 primitive: `stroke`, `text` or `rop3`.
    ///
    /// These are what force `DRAW_STROKE`, `DRAW_TEXT` and `DRAW_ROP3` out of
    /// the QXL driver -- the commands `docs/roadmap.md` §2.7 records as never
    /// having been seen from any real server.
    pub fn draw(&self, primitive: &str, args: &[&str]) -> Result<()> {
        let mut argv = vec!["solstice-draw", primitive];
        argv.extend_from_slice(args);
        self.run(&argv).map(drop)
    }

    /// QEMU's own capture of the guest display.
    pub fn screendump(&self) -> Result<Ppm> {
        let path = self.dir.join("screen.ppm");
        let _ = std::fs::remove_file(&path);
        self.qmp(
            "screendump",
            json!({ "filename": path.to_string_lossy(), "format": "ppm" }),
        )?;
        Ppm::read(&path)
    }

    /// The loopback port the SPICE server is on.
    ///
    /// # Panics
    /// If the guest was not configured with [`GuestConfig::spice`].
    pub fn spice_port(&self) -> u16 {
        self.spice_port.expect("this guest has no SPICE server")
    }

    /// The loopback port the RFB server is on.
    ///
    /// # Panics
    /// If the guest was not configured with [`GuestConfig::vnc`].
    pub fn vnc_port(&self) -> u16 {
        self.vnc_port.expect("this guest has no VNC server")
    }

    /// Everything the guest wrote to its serial console, for failure messages.
    pub fn console(&self) -> String {
        std::fs::read_to_string(self.dir.join("console.log")).unwrap_or_default()
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
