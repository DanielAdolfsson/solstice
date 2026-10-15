//! What each RFB encoding actually costs this client.
//!
//! Ignored by default -- it is a measurement, not an assertion. Run it with:
//!
//! ```sh
//! cargo test -p solstice-vnc --release --test encoding_bench -- --ignored --nocapture
//! ```
//!
//! The question it answers is narrow and specific: in a bridge that re-encodes
//! everything to H.264 anyway, the backend encoding is not a bandwidth decision
//! -- `docs/security.md` §6.8 puts the VNC hop on loopback or an SSH tunnel --
//! it is a **CPU and latency** decision. So this measures bytes *and* the
//! client CPU burned decoding them, per encoding, against the same content.

use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use solstice_backend::{BackendEvent, FramebufferHandle, Rect};
use solstice_vnc::pixel::PixelFormat;
use solstice_vnc::protocol::encoding;
use solstice_vnc::session::{self, UpdateLoop};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tokio::sync::{broadcast, mpsc};

const DISPLAY: u32 = 94;
const PORT: u16 = 5900 + DISPLAY as u16;
const GEOMETRY: &str = "1280x720";
const MEASURE: Duration = Duration::from_secs(6);

/// Counts every byte that comes off the socket.
struct Counting<R> {
    inner: R,
    bytes: Arc<AtomicUsize>,
}

impl<R: AsyncRead + Unpin> AsyncRead for Counting<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            self.bytes
                .fetch_add(buf.filled().len() - before, Ordering::Relaxed);
        }
        result
    }
}

/// Process CPU time (user + system) in seconds, from `/proc/self/stat`.
fn cpu_seconds() -> f64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    // Fields 14 and 15 after the comm field, which may contain spaces.
    let Some(after_comm) = stat.rsplit_once(')') else {
        return 0.0;
    };
    let fields: Vec<&str> = after_comm.1.split_whitespace().collect();
    let ticks = fields
        .get(11)
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0)
        + fields
            .get(12)
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0);
    ticks / 100.0 // _SC_CLK_TCK is 100 on every Linux this runs on
}

struct Xvnc(Child);

impl Drop for Xvnc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_file(format!("/tmp/.X11-unix/X{DISPLAY}"));
        let _ = std::fs::remove_file(format!("/tmp/.X{DISPLAY}-lock"));
    }
}

fn start_server() -> Option<(Xvnc, Vec<Child>)> {
    if Command::new("Xvnc")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("skipping: Xvnc is not installed");
        return None;
    }
    let server = Xvnc(
        Command::new("Xvnc")
            .arg(format!(":{DISPLAY}"))
            .args(["-geometry", GEOMETRY])
            .args(["-depth", "24"])
            .args(["-SecurityTypes", "None"])
            .args(["-rfbport", &PORT.to_string()])
            .arg("-localhost")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?,
    );
    std::thread::sleep(Duration::from_millis(1500));

    let display = format!(":{DISPLAY}");
    let _ = Command::new("xsetroot")
        .env("DISPLAY", &display)
        .args(["-solid", "#2e3436"])
        .status();

    // A desktop-shaped screen: scrolling text, which is where encodings differ
    // most, plus two vector-ish windows.
    let mut apps = Vec::new();
    if let Ok(child) = Command::new("xterm")
        .env("DISPLAY", &display)
        .args(["-geometry", "100x40+10+10"])
        .args(["-fa", "Monospace"])
        .args(["-fs", "10"])
        .args([
            "-e",
            "sh",
            "-c",
            "while :; do ls -lR /usr/share/doc 2>/dev/null; done",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        apps.push(child);
    } else {
        eprintln!("note: xterm is unavailable, so the text-heavy case is missing");
    }
    for app in ["xeyes", "xclock"] {
        if let Ok(child) = Command::new(app)
            .env("DISPLAY", &display)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            apps.push(child);
        }
    }
    std::thread::sleep(Duration::from_millis(1500));
    Some((server, apps))
}

struct Measurement {
    name: &'static str,
    bytes: usize,
    updates: usize,
    damaged_pixels: u64,
    cpu: f64,
    wall: Duration,
}

async fn measure(name: &'static str, encodings: &[i32]) -> Measurement {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", PORT))
        .await
        .unwrap();
    stream.set_nodelay(true).unwrap();
    let mut stream = stream;

    let version = solstice_vnc::handshake::negotiate_version(&mut stream)
        .await
        .unwrap();
    let offered = solstice_vnc::handshake::read_security_types(&mut stream, version)
        .await
        .unwrap();
    assert!(offered.contains(&1), "the bench server must offer `None`");
    stream.write_all(&[1]).await.unwrap();
    stream.flush().await.unwrap();
    solstice_vnc::handshake::authenticate(&mut stream, version, &solstice_vnc::VncSecurity::None)
        .await
        .unwrap();
    let init = solstice_vnc::handshake::initialise(&mut stream, true)
        .await
        .unwrap();

    let (reader, writer) = tokio::io::split(stream);
    let bytes = Arc::new(AtomicUsize::new(0));
    let reader = Counting {
        inner: reader,
        bytes: bytes.clone(),
    };

    let (outgoing, outgoing_rx) = mpsc::channel::<Vec<u8>>(256);
    let (events, mut events_rx) = broadcast::channel(4096);
    let fb = FramebufferHandle::with_size(init.width as u32, init.height as u32);

    outgoing
        .send(session::set_pixel_format(&PixelFormat::BGRA))
        .await
        .unwrap();
    outgoing
        .send(session::set_encodings(encodings))
        .await
        .unwrap();
    outgoing
        .send(session::update_request(
            false,
            Rect::whole(init.width as u32, init.height as u32),
        ))
        .await
        .unwrap();
    tokio::spawn(session::writer_task(writer, outgoing_rx));

    let mut loop_ = UpdateLoop::new(reader, PixelFormat::BGRA, fb, events, outgoing);

    // Warm up: let the first full screen land and settle before measuring.
    let warmup = Instant::now();
    while warmup.elapsed() < Duration::from_millis(1500) {
        if tokio::time::timeout(Duration::from_millis(200), loop_.step())
            .await
            .is_err()
        {
            break;
        }
    }
    while events_rx.try_recv().is_ok() {}

    let start_bytes = bytes.load(Ordering::Relaxed);
    let start_cpu = cpu_seconds();
    let start = Instant::now();
    let mut updates = 0usize;
    while start.elapsed() < MEASURE {
        match tokio::time::timeout(Duration::from_millis(250), loop_.step()).await {
            Ok(Ok(())) => updates += 1,
            Ok(Err(e)) => {
                eprintln!("{name}: session ended: {e}");
                break;
            }
            Err(_) => {}
        }
    }
    let wall = start.elapsed();
    let cpu = cpu_seconds() - start_cpu;
    let bytes = bytes.load(Ordering::Relaxed) - start_bytes;

    let mut damaged_pixels = 0u64;
    while let Ok(event) = events_rx.try_recv() {
        if let BackendEvent::Damage(rect) = event {
            damaged_pixels += rect.width as u64 * rect.height as u64;
        }
    }

    Measurement {
        name,
        bytes,
        updates,
        damaged_pixels,
        cpu,
        wall,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement, not an assertion; needs Xvnc and takes about a minute"]
async fn what_each_encoding_costs() {
    let Some((_server, mut apps)) = start_server() else {
        return;
    };

    let pseudo = [encoding::PSEUDO_LAST_RECT, encoding::PSEUDO_DESKTOP_SIZE];
    let cases: Vec<(&'static str, Vec<i32>)> = vec![
        ("Raw", vec![encoding::RAW]),
        ("Hextile", vec![encoding::HEXTILE, encoding::RAW]),
        ("ZRLE", vec![encoding::ZRLE, encoding::RAW]),
        (
            "ZRLE + CopyRect",
            vec![encoding::ZRLE, encoding::COPY_RECT, encoding::RAW],
        ),
        ("what Solstice ships", session::ENCODINGS.to_vec()),
    ];

    let mut results = Vec::new();
    for (name, mut encodings) in cases {
        encodings.extend_from_slice(&pseudo);
        results.push(measure(name, &encodings).await);
    }

    println!("\n{GEOMETRY} Xvnc, scrolling text plus two windows, {MEASURE:?} per case\n");
    println!(
        "{:<22} {:>10} {:>9} {:>9} {:>10} {:>12}",
        "encoding", "MB/s", "updates", "CPU %", "MPixel/s", "bytes/pixel"
    );
    for r in &results {
        let secs = r.wall.as_secs_f64();
        let mbps = r.bytes as f64 / secs / 1e6;
        let cpu_pct = r.cpu / secs * 100.0;
        let mpixels = r.damaged_pixels as f64 / secs / 1e6;
        let bpp = if r.damaged_pixels > 0 {
            r.bytes as f64 / r.damaged_pixels as f64
        } else {
            f64::NAN
        };
        println!(
            "{:<22} {:>10.2} {:>9} {:>9.1} {:>10.2} {:>12.3}",
            r.name, mbps, r.updates, cpu_pct, mpixels, bpp
        );
    }
    println!();

    for app in &mut apps {
        let _ = app.kill();
        let _ = app.wait();
    }
}
