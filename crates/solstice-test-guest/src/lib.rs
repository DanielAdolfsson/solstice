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
    audio: bool,
}

impl Default for Spice {
    fn default() -> Self {
        Self {
            options: Vec::new(),
            agent: true,
            audio: false,
        }
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

    /// Give the guest a sound card whose output is the SPICE playback
    /// channel.
    ///
    /// Off by default because it is a PCI device every other test would
    /// boot for nothing. The guest's `linux-virt` kernel already carries
    /// `snd-hda-intel`, and `eudev` loads it, so `aplay` and `speaker-test`
    /// find a card with no change to the image.
    pub fn audio(mut self) -> Self {
        self.audio = true;
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

/// Which display device the guest gets.
///
/// This is not a cosmetic choice. `spice-server` intercepts a client's
/// `VD_AGENT_MONITORS_CONFIG` to hand it to a QXL instance rather than
/// forwarding it to `spice-vdagent`, so on [`Display::Qxl`] a resize request
/// never reaches the agent and the device does not act on it either. With no
/// QXL instance the message falls through to the agent, which applies the
/// mode itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Display {
    /// `-vga qxl` with the `qxl` X driver. What a real SPICE guest has, and
    /// what the image-codec and draw-command tests want.
    Qxl,
    /// `-vga virtio` with the generic KMS `modesetting` X driver.
    VirtioGpu,
}

impl Display {
    fn vga(self) -> &'static str {
        match self {
            Self::Qxl => "qxl",
            Self::VirtioGpu => "virtio",
        }
    }

    fn x_driver(self) -> &'static str {
        match self {
            Self::Qxl => "qxl",
            Self::VirtioGpu => "modesetting",
        }
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
    display: Display,
    qxl_ram_mb: Option<u32>,
}

impl Default for GuestConfig {
    fn default() -> Self {
        Self {
            width: 1280,
            height: 720,
            // The guest is an initramfs, so the whole rootfs lives in RAM and
            // the kernel needs room to unpack it. Below about 1 GiB the
            // unpack truncates, which the guest survives in a way that looks
            // like anything but a memory problem -- see the check in
            // `tests/guest/init`.
            memory_mb: 1024,
            spice: None,
            vnc: false,
            display: Display::Qxl,
            qxl_ram_mb: None,
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

    /// Pick the display device; see [`Display`].
    pub fn display(mut self, display: Display) -> Self {
        self.display = display;
        self
    }

    /// Guest memory in MiB.
    pub fn memory_mb(mut self, mb: u32) -> Self {
        self.memory_mb = mb;
        self
    }

    /// The QXL device's RAM in MiB, which holds the commands and images the
    /// guest hands the device; QEMU's default is 64. Only for QXL.
    ///
    /// The GLZ soak needs more. Under TCG with the default, the guest's QXL
    /// driver ran out and blocked waiting for the device to release memory
    /// (`docs/roadmap.md` §2.7), which is a known regression in the guest
    /// kernel rather than anything a SPICE client controls.
    pub fn qxl_ram_mb(mut self, mb: u32) -> Self {
        self.qxl_ram_mb = Some(mb);
        self
    }
}

/// A booted guest. Killed and cleaned up on drop.
pub struct Guest {
    child: Child,
    dir: PathBuf,
    _slot: Slot,
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

/// A cross-process cap on how many guests run at once.
///
/// `cargo test` runs each test binary as its own process, so an in-process
/// semaphore would not see the other binaries' guests. Three crates now boot
/// guests, and on a machine with a few gigabytes free the result is a suite
/// that passes alone and fails together -- the worst kind of flake, because
/// every individual test looks correct.
///
/// A slot is a directory, because `create_dir` is atomic and needs no
/// dependency and no `unsafe`. A slot whose owning process is gone is
/// reclaimed *and its guest killed*: `Drop` cleans up a guest when a test
/// fails, but not when the test process itself is killed -- an interrupted
/// `cargo test` otherwise leaves a gigabyte of QEMU behind, and a few of
/// those turn every later run into a memory-pressure flake that looks like a
/// bug in whatever test drew the short straw.
struct Slot(PathBuf);

impl Drop for Slot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Slot {
    /// Record the guest this slot is holding, so a later run can kill it if
    /// this process does not survive to do so itself.
    fn record_guest(&self, pid: u32) {
        let _ = std::fs::write(self.0.join("qemu"), pid.to_string());
    }
}

fn process_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// How many guests may run at once: `SOLSTICE_GUEST_PARALLEL`, or a figure
/// derived from how much memory the machine actually has free right now.
fn slot_count() -> usize {
    if let Some(n) = std::env::var("SOLSTICE_GUEST_PARALLEL")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        return n.max(1);
    }
    // A guest is 1 GiB plus QEMU's own overhead; leave a gigabyte for
    // everything else on the machine.
    (available_mb().saturating_sub(1024) / 1280).clamp(1, 4)
}

/// Block until a slot is free, then hold it until the guest is dropped.
fn acquire_slot() -> Slot {
    let root = std::env::temp_dir().join("solstice-guest-slots");
    let _ = std::fs::create_dir_all(&root);
    let slots = slot_count();
    loop {
        for i in 0..slots {
            let path = root.join(format!("slot-{i}"));
            if std::fs::create_dir(&path).is_ok() {
                let _ = std::fs::write(path.join("pid"), std::process::id().to_string());
                return Slot(path);
            }
            // Reclaim a slot whose owner is gone, taking its guest with it.
            let owner = std::fs::read_to_string(path.join("pid"))
                .ok()
                .and_then(|p| p.trim().parse::<u32>().ok());
            if owner.is_some_and(process_alive) {
                continue;
            }
            if let Some(stale) = std::fs::read_to_string(path.join("qemu"))
                .ok()
                .and_then(|p| p.trim().parse::<u32>().ok())
                .filter(|&pid| process_alive(pid))
            {
                let _ = Command::new("kill")
                    .arg(stale.to_string())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            let _ = std::fs::remove_dir_all(&path);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
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

/// Megabytes of memory the machine says are available right now.
fn available_mb() -> usize {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|info| {
            info.lines()
                .find(|l| l.starts_with("MemAvailable:"))?
                .split_whitespace()
                .nth(1)?
                .parse::<usize>()
                .ok()
        })
        .map(|kb| kb / 1024)
        .unwrap_or(usize::MAX)
}

/// Why the guest cannot be started here, if it cannot.
fn unavailable(need_mb: u32) -> Option<String> {
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
    // Not enough free memory is a missing prerequisite like any other, and
    // skipping says so. Booting anyway produces a guest whose initramfs
    // truncates, which fails later and looks like nothing of the sort.
    let available = available_mb();
    let need = need_mb as usize + 256;
    if available < need {
        return Some(format!(
            "only {available} MiB of memory are available and this guest needs \
             about {need} MiB; close something or set GuestConfig::memory_mb"
        ));
    }
    None
}

/// Warn, without failing, when the built image predates the committed lock.
fn warn_if_stale() {
    let built = image_dir().join("manifest.lock");
    let committed = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/guest/manifest.lock");
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
        if let Some(why) = unavailable(config.memory_mb) {
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
        // Taken before QEMU starts and held until the guest is dropped.
        let slot = acquire_slot();
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
                    "console=ttyS0 quiet solstice.geometry={}x{} solstice.xdriver={}",
                    config.width,
                    config.height,
                    config.display.x_driver()
                ),
            ])
            .args(["-vga", config.display.vga()])
            .args([
                "-qmp",
                &format!("unix:{},server=on,wait=off", sock("qmp.sock").display()),
            ])
            .args([
                "-chardev",
                &format!(
                    "socket,path={},server=on,wait=off,id=qga0",
                    sock("qga.sock").display()
                ),
            ])
            .args(["-device", "virtio-serial"])
            .args([
                "-device",
                "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
            ])
            .args([
                "-serial",
                &format!("file:{}", sock("console.log").display()),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        // KVM where it is usable, TCG where it is not: a CI runner without
        // nested virtualisation still runs these, just slower. "Usable" means
        // openable, not merely present -- a user outside the `kvm` group sees
        // the device node, and `-accel kvm` then fails before QMP is up, which
        // surfaces as a boot timeout that names nothing useful.
        if let (Display::Qxl, Some(mb)) = (config.display, config.qxl_ram_mb) {
            qemu.args(["-global", &format!("qxl-vga.ram_size_mb={mb}")]);
        }

        // `SOLSTICE_GUEST_ACCEL=tcg` forces TCG on a host that has KVM, to
        // reproduce what a slower runner sees: a guest that is slow relative
        // to the client changes which races a test can hit.
        let force_tcg = std::env::var("SOLSTICE_GUEST_ACCEL").is_ok_and(|v| v == "tcg");
        if !force_tcg
            && std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/kvm")
                .is_ok()
        {
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
            let mut value = format!("port={port},addr=127.0.0.1,disable-ticketing=on");
            for (key, option) in &spice.options {
                value.push_str(&format!(",{key}={option}"));
            }
            qemu.args(["-spice", &value]);
            if spice.agent {
                // Without this pair spice-vdagentd has no port and the guest
                // comes up agentless.
                qemu.args(["-chardev", "spicevmc,id=vdagent,name=vdagent"]);
                qemu.args([
                    "-device",
                    "virtserialport,chardev=vdagent,name=com.redhat.spice.0",
                ]);
            }
            if spice.audio {
                qemu.args(["-audiodev", "spice,id=snd0"]);
                qemu.args(["-device", "intel-hda"]);
                qemu.args(["-device", "hda-output,audiodev=snd0"]);
            }
        }
        let mut vnc_port = None;
        if config.vnc {
            let port = free_port()?;
            vnc_port = Some(port);
            qemu.args(["-vnc", &format!("127.0.0.1:{}", port - 5900)]);
        }

        let child = qemu.spawn()?;
        slot.record_guest(child.id());

        let mut qmp = proto::Channel::connect(&sock("qmp.sock"), "QMP", Duration::from_secs(20))?;
        qmp.qmp_handshake()?;
        let qga =
            proto::Channel::connect(&sock("qga.sock"), "guest agent", Duration::from_secs(20))?;

        let guest = Self {
            child,
            dir,
            _slot: slot,
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
        let console = std::fs::read_to_string(self.dir.join("console.log")).unwrap_or_default();
        let hint = if console.contains("Initramfs unpacking failed") {
            "\n\nthe initramfs did not unpack: the guest has too little memory \
             for it. Raise GuestConfig::memory_mb."
        } else {
            ""
        };
        Err(Error::Timeout(format!(
            "waiting for the guest to serve X; console said:\n{console}{hint}"
        )))
    }

    /// Issue a QMP command.
    pub fn qmp(&self, command: &str, args: Value) -> Result<Value> {
        self.qmp
            .lock()
            .expect("QMP channel poisoned")
            .cmd(command, args)
    }

    /// Issue a guest-agent command.
    pub fn qga(&self, command: &str, args: Value) -> Result<Value> {
        self.qga
            .lock()
            .expect("agent channel poisoned")
            .cmd(command, args)
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

    /// Where the guest's X server and drawing clients are blocked, for a
    /// command that timed out.
    ///
    /// The guest agent is separate from X, so it still answers when X is
    /// stuck. Each process's state, kernel wait channel and kernel stack say
    /// whether it is waiting on the display device, on a client or on nothing,
    /// and `dmesg` carries anything the driver logged. This is what showed the
    /// GLZ soak's stalls to be the guest's QXL driver waiting for the device to
    /// release memory, with the client idle and up to date
    /// (`docs/roadmap.md` §2.7).
    pub fn stall_report(&self) -> String {
        match self.sh(STALL_REPORT) {
            Ok(report) => report,
            Err(e) => format!("the guest agent did not answer either: {e}"),
        }
    }

    /// Everything the guest wrote to its serial console, for failure messages.
    pub fn console(&self) -> String {
        std::fs::read_to_string(self.dir.join("console.log")).unwrap_or_default()
    }
}

/// What [`Guest::stall_report`] runs in the guest.
const STALL_REPORT: &str = "for p in $(pidof Xorg X solstice-draw xterm); do \
    echo \"== $p $(cat /proc/$p/comm): wchan=$(cat /proc/$p/wchan), \
    $(grep State /proc/$p/status)\"; head -20 /proc/$p/stack 2>&1; done; \
    echo '== dmesg'; dmesg | tail -20";

impl Drop for Guest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    /// The report runs only when a guest command has already hung, which is
    /// the worst moment to find out its quoting is broken.
    #[test]
    fn the_stall_report_is_valid_shell() {
        let status = std::process::Command::new("sh")
            .args(["-n", "-c", super::STALL_REPORT])
            .status()
            .unwrap();
        assert!(status.success());
    }
}
