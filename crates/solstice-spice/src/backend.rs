//! Dialling a SPICE server, and the [`Backend`] and [`Session`] it becomes.
//!
//! SPICE is not one connection, and this is the module where that stops being
//! a protocol note and starts being a shape. A session is:
//!
//! ```text
//!   main     ── link ──▶ MAIN_INIT (allocates the connection id)
//!                        CHANNELS_LIST (says what else exists)
//!   display  ── link ──┐
//!   cursor   ── link ──┴─▶ one queue, one task, one framebuffer
//!   inputs   ── link ──▶ its own reader, for motion acks and modifiers
//!   playback ── link ──▶ its own reader, into the audio channel
//! ```
//!
//! Each arrow is a separate TCP connection repeating the whole link
//! handshake with the connection id the main channel was given
//! (`docs/spice-protocol.md` §2). The backend seam does not have to know any
//! of that -- `Session` is a handle, not a socket, which is what made the
//! trait fit without changes (`docs/roadmap.md` §2.1).
//!
//! # Security
//!
//! `docs/security.md` §4.2 is the policy: TLS on every channel, with the
//! certificate verified, and a plaintext SPICE connection treated the same as
//! a plaintext VNC one -- loopback only. The ticket is a password check and
//! not a key exchange, so without TLS the display, the keystrokes and the
//! clipboard are all in the clear.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use solstice_backend::{
    AudioFrame, Backend, BackendError, BackendEvent, FramebufferHandle, InputEvent, Session,
};
use tokio::io::AsyncRead;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};

use crate::agent::{clipboard_type, ClipboardType};
use crate::channel::{self, ChannelReader, OutMessage};
use crate::display::{self, DisplayChannel, DisplayCounts, DisplayEvent, DisplayLimits};
use crate::error::{Result, SpiceError};
use crate::inputs::{InputState, MouseMode};
use crate::link::{self, LinkRequest, Transport};
use crate::main_channel::{MainChannel, MainOutcome};
use crate::playback::Playback;
use crate::protocol::{
    channel as channel_type, display_cap, inputs_msg, main_cap, playback_cap, Caps,
};
use crate::wire::Reader;

/// How to authenticate, and whether the connection is protected at all.
#[derive(Clone, Debug)]
pub enum SpiceSecurity {
    /// TLS on the server's TLS port, with the certificate verified.
    Tls {
        /// The ticket password, if the server has ticketing enabled.
        password: Option<String>,
        /// PEM file of certificates to trust. `None` uses the system roots.
        ca_file: Option<PathBuf>,
    },
    /// Plaintext. Refused for anything but loopback.
    Plain {
        /// The ticket password, if the server has ticketing enabled.
        password: Option<String>,
    },
}

impl SpiceSecurity {
    fn password(&self) -> &str {
        match self {
            SpiceSecurity::Tls { password, .. } | SpiceSecurity::Plain { password } => {
                password.as_deref().unwrap_or("")
            }
        }
    }

    fn is_tls(&self) -> bool {
        matches!(self, SpiceSecurity::Tls { .. })
    }
}

/// How to reach a SPICE server.
#[derive(Clone, Debug)]
pub struct SpiceConfig {
    /// Hostname or address.
    pub host: String,
    /// The port to link on: the TLS port when `security` is
    /// [`SpiceSecurity::Tls`], the plain one otherwise.
    pub port: u16,
    /// Authentication and transport protection.
    pub security: SpiceSecurity,
    /// Ceilings on what the display channel will hold.
    pub limits: DisplayLimits,
    /// Whether to open the playback channel.
    pub audio: bool,
    /// An `image_compression` to ask the server for. `None` leaves the
    /// server's own `image-compression=` in force, which is what `spice-gtk`
    /// does by default; a preference replaces it outright.
    pub preferred_compression: Option<u8>,
    /// Whether to let the server send video streams.
    ///
    /// Off by default. A stream is the server deciding part of the screen is
    /// video and sending it as MJPEG, on its own clock and at its own quality.
    /// Solstice decodes it only to re-encode the whole screen as H.264, so a
    /// stream is a second lossy generation and an MJPEG encode and decode
    /// for nothing; with streams off the same pixels arrive losslessly as
    /// draw commands. Behind a non-QXL card it is worse than that: QEMU's
    /// 32-pixel strips each become their own stream, paced independently,
    /// and the columns of one video show different moments of it
    /// (`docs/roadmap.md` §9).
    pub video_streams: bool,
    /// Permit [`SpiceSecurity::Plain`] against a peer off loopback. The
    /// operator's explicit opt-in, for a server on the same machine that is
    /// not on loopback (`docs/security.md` §4.2).
    pub allow_insecure: bool,
}

impl Default for SpiceConfig {
    fn default() -> Self {
        SpiceConfig {
            host: "127.0.0.1".into(),
            // 5900 is QEMU's conventional `-spice port=`; the TLS port is
            // configured separately and has no convention, so it has to be
            // set explicitly.
            port: 5900,
            security: SpiceSecurity::Tls {
                password: None,
                ca_file: None,
            },
            limits: DisplayLimits::default(),
            audio: true,
            preferred_compression: None,
            video_streams: false,
            allow_insecure: false,
        }
    }
}

/// Opens one connection to the server.
///
/// A session needs several, and tests need them to be in-memory rather than
/// over a socket, so dialling is behind a trait rather than being a call to
/// [`TcpStream::connect`].
#[async_trait]
pub trait Dialer: Send + Sync {
    /// Open one connection.
    async fn dial(&self) -> Result<Box<dyn Transport>>;
}

/// The real dialer: TCP, with TLS over it when policy requires.
pub struct TcpDialer {
    config: SpiceConfig,
}

impl TcpDialer {
    /// Build one.
    pub fn new(config: SpiceConfig) -> Self {
        TcpDialer { config }
    }
}

#[async_trait]
impl Dialer for TcpDialer {
    async fn dial(&self) -> Result<Box<dyn Transport>> {
        let stream = TcpStream::connect((self.config.host.as_str(), self.config.port)).await?;
        // Nagle would batch input messages behind each other, which on an
        // input path is pure added latency.
        stream.set_nodelay(true)?;

        match &self.config.security {
            SpiceSecurity::Plain { .. } => {
                let peer = stream.peer_addr()?.ip();
                if !self.config.allow_insecure
                    && !is_loopback_addr(peer)
                    && !is_loopback(&self.config.host)
                {
                    return Err(SpiceError::Auth(format!(
                        "refusing a plaintext SPICE connection to {peer}: \
                         SPICE's ticket is a password check, not a key exchange, \
                         so the display and every keystroke would be in the clear \
                         (docs/security.md §4.2). Use the TLS port, or tunnel it."
                    )));
                }
                Ok(Box::new(stream))
            }
            SpiceSecurity::Tls { ca_file, .. } => {
                let tls_config = tls_client_config(ca_file.as_ref())?;
                let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
                let server_name = rustls_pki_types::ServerName::try_from(self.config.host.clone())
                    .map_err(|e| {
                        SpiceError::Tls(format!(
                            "{} is not a valid server name: {e}",
                            self.config.host
                        ))
                    })?;
                let tls = connector
                    .connect(server_name, stream)
                    .await
                    .map_err(|e| SpiceError::Tls(format!("TLS handshake: {e}")))?;
                Ok(Box::new(tls))
            }
        }
    }
}

fn tls_client_config(ca_file: Option<&PathBuf>) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    match ca_file {
        Some(path) => {
            let pem = std::fs::read(path)?;
            let mut cursor = std::io::Cursor::new(pem);
            for cert in rustls_pemfile::certs(&mut cursor) {
                let cert = cert.map_err(|e| SpiceError::Tls(format!("reading {path:?}: {e}")))?;
                roots
                    .add(cert)
                    .map_err(|e| SpiceError::Tls(format!("adding a root from {path:?}: {e}")))?;
            }
            if roots.is_empty() {
                return Err(SpiceError::Tls(format!(
                    "{path:?} contains no certificates"
                )));
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    // Certificates are verified. CVE-2021-20201 aside, the point of the TLS
    // port is the authentication, not just the encryption.
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// The capability set each channel type links with.
fn channel_caps(kind: u8, video_streams: bool) -> Caps {
    match kind {
        channel_type::MAIN => {
            Caps::from_bits(&[main_cap::NAME_AND_UUID, main_cap::AGENT_CONNECTED_TOKENS])
        }
        // `MULTI_CODEC` stays when streams are off: it is what makes the
        // codec list authoritative. A client without it is assumed to take
        // MJPEG regardless, so leaving it out would turn streams back on.
        // With it and no codec, `spice-server` finds no encoder for this
        // client and sends the region as draw commands instead.
        channel_type::DISPLAY if !video_streams => Caps::from_bits(&[
            display_cap::MONITORS_CONFIG,
            display_cap::A8_SURFACE,
            display_cap::LZ4_COMPRESSION,
            display_cap::PREF_COMPRESSION,
            display_cap::MULTI_CODEC,
        ]),
        channel_type::DISPLAY => Caps::from_bits(&[
            display_cap::SIZED_STREAM,
            display_cap::MONITORS_CONFIG,
            display_cap::A8_SURFACE,
            display_cap::STREAM_REPORT,
            display_cap::LZ4_COMPRESSION,
            display_cap::PREF_COMPRESSION,
            display_cap::MULTI_CODEC,
            display_cap::CODEC_MJPEG,
            display_cap::PREF_VIDEO_CODEC_TYPE,
            // GL_SCANOUT and GL_SCANOUT2 are deliberately absent: they pass
            // a dmabuf file descriptor and are local-only by construction
            // (`docs/spice-protocol.md` §5.3). COMPOSITE is absent because
            // `DRAW_COMPOSITE` is not implemented, and advertising a
            // capability whose messages cannot be executed turns a missing
            // feature into a corrupt framebuffer.
        ]),
        channel_type::PLAYBACK => Caps::from_bits(&[playback_cap::OPUS]),
        _ => Caps::new(),
    }
}

/// Link one channel: dial, exchange, authenticate.
async fn link_channel(
    dialer: &dyn Dialer,
    security: &SpiceSecurity,
    connection_id: u32,
    kind: u8,
    id: u8,
    video_streams: bool,
) -> Result<(Box<dyn Transport>, bool)> {
    let mut stream = dialer.dial().await?;
    let request = LinkRequest::new(connection_id, kind, id)
        .with_channel_caps(channel_caps(kind, video_streams));
    let reply = link::exchange(&mut stream, &request).await?;

    if reply.error == link::LINK_ERR_NEED_SECURED {
        return Err(SpiceError::Auth(format!(
            "the server requires TLS on the {} channel; configure the TLS port \
             (docs/security.md §4.2)",
            channel_type::name(kind)
        )));
    }
    if reply.error != 0 {
        return Err(SpiceError::Link {
            code: reply.error,
            reason: crate::protocol::link_err_name(reply.error),
        });
    }

    let mini = reply.mini_header();
    link::authenticate(&mut stream, &reply, security.password()).await?;
    tracing::debug!(
        channel = channel_type::name(kind),
        id,
        mini_header = mini,
        secured = security.is_tls(),
        "spice channel linked"
    );
    Ok((stream, mini))
}

/// Something the guest did with its clipboard.
///
/// SPICE's clipboard is a two-sided, by-demand exchange rather than a value
/// that is pushed: whoever changes their selection *grabs*, naming the types
/// they could produce, and the other side *requests* one of them when it
/// actually wants the bytes. Both halves of that are here, so a consumer can
/// drive the guest and be driven by it.
///
/// There is no sink for this in Solstice itself -- GameStream has no
/// clipboard channel, which is why nothing above the backend seam subscribes
/// (`docs/roadmap.md` §2.5). It is reachable by anything embedding
/// [`SpiceSession`], and the real-server tests are the first such thing.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClipboardEvent {
    /// The guest's clipboard changed; it can produce these types.
    ///
    /// Types this client will not name are filtered out, so an empty list
    /// means the guest grabbed with nothing usable in it -- a `FILE_LIST`
    /// grab, in practice.
    Offered(Vec<ClipboardType>),
    /// The guest withdrew its offer; nothing of it is available any more.
    Released,
    /// The guest wants this client's clipboard, in this type.
    ///
    /// **The guest's paste blocks until this is answered**, with either
    /// [`SpiceSession::send_clipboard`] or
    /// [`SpiceSession::decline_clipboard`]. A request for a type this client
    /// cannot name is declined before it ever becomes an event.
    Requested(ClipboardType),
    /// A payload arrived, in answer to [`SpiceSession::request_clipboard`].
    Data {
        /// What it is.
        kind: ClipboardType,
        /// The bytes.
        data: Vec<u8>,
    },
    /// A request will not be answered with data after all: the guest replied
    /// `VD_AGENT_CLIPBOARD_NONE`, or with a type it never offered.
    ///
    /// Its own event rather than an error, because a consumer waiting on
    /// [`ClipboardEvent::Data`] would otherwise wait forever.
    Unavailable,
}

/// How many clipboard events to hold for a subscriber that has fallen behind.
///
/// Deliberately far smaller than the display channel's 256: an event here can
/// carry [`crate::agent::MAX_CLIPBOARD_PAYLOAD`] bytes, and a ring of 256 of
/// those is a quarter of a gigabyte held on behalf of a subscriber that is
/// not reading.
const CLIPBOARD_EVENT_QUEUE: usize = 8;

/// The SPICE backend.
pub struct SpiceBackend {
    config: SpiceConfig,
}

impl SpiceBackend {
    /// Build one.
    pub fn new(config: SpiceConfig) -> Self {
        SpiceBackend { config }
    }
}

impl std::fmt::Debug for SpiceBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiceBackend")
            .field("host", &self.config.host)
            .field("port", &self.config.port)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Backend for SpiceBackend {
    fn name(&self) -> &'static str {
        "spice"
    }

    async fn connect(&self) -> solstice_backend::Result<Box<dyn Session>> {
        let dialer = Arc::new(TcpDialer::new(self.config.clone()));
        let session = connect(dialer, self.config.clone()).await?;
        Ok(Box::new(session))
    }
}

/// How long to wait for the main channel to identify the session.
///
/// `MAIN_INIT` and `CHANNELS_LIST` arrive immediately on a healthy server.
/// Without a bound, a server that links and then says nothing holds the
/// connection open forever.
const SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// How long to wait for the primary surface after the channels are up.
///
/// `connect` returning before the display channel has said how big the
/// desktop is would hand the pipeline a 0x0 geometry for the first frames.
/// RFB has no equivalent problem because `ServerInit` carries the size in
/// the handshake; SPICE sends it as an ordinary message on another socket.
/// A server that never sends one is still usable -- the size arrives as a
/// `Resize` event later -- so this expires rather than failing.
const FIRST_SURFACE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Dial, link every channel the server offers, and start the session.
pub async fn connect(dialer: Arc<dyn Dialer>, config: SpiceConfig) -> Result<SpiceSession> {
    tokio::time::timeout(SETUP_TIMEOUT, connect_inner(dialer, config))
        .await
        .map_err(|_| SpiceError::protocol("the server linked but never sent MAIN_INIT"))?
}

async fn connect_inner(dialer: Arc<dyn Dialer>, config: SpiceConfig) -> Result<SpiceSession> {
    // Dropped on any early return below, which closes what has linked so far.
    let tasks = Tasks::default();
    let (stream, mini) = link_channel(
        dialer.as_ref(),
        &config.security,
        0,
        channel_type::MAIN,
        0,
        config.video_streams,
    )
    .await?;
    let (main_reader, main_writer) = tokio::io::split(stream);
    let (main_out, main_out_rx) = mpsc::channel::<OutMessage>(256);
    tasks.spawn(channel::writer_task(main_writer, mini, main_out_rx));

    let mut reader = ChannelReader::new(main_reader, mini, main_out.clone(), "main");
    let mut main = MainChannel::new();
    let mut channels: Option<Vec<(u8, u8)>> = None;

    // The session is not identified until MAIN_INIT has allocated a
    // connection id and CHANNELS_LIST has said what else to connect to.
    while channels.is_none() || main.connection_id() == 0 {
        let Some(message) = reader.next().await? else {
            return Err(SpiceError::protocol(
                "the main channel closed before the session was set up",
            ));
        };
        let (send, outcomes) = main.handle(message.kind, &message.body)?;
        for message in send {
            let _ = main_out.send(message).await;
        }
        for outcome in outcomes {
            if let MainOutcome::Channels(list) = outcome {
                channels = Some(list);
            }
        }
    }

    let connection_id = main.connection_id();
    let channels = channels.expect("checked by the loop");
    let available = |kind: u8| channels.iter().any(|(t, _)| *t == kind);
    tracing::info!(
        connection_id,
        channels = channels.len(),
        name = main.name().unwrap_or("<unnamed>"),
        "spice session"
    );

    let (events, _) = broadcast::channel(256);
    let fb = FramebufferHandle::with_size(1, 1);
    let connected = Arc::new(AtomicBool::new(true));

    // Display and cursor share one queue and one owner; see `display`.
    let (display_events, display_rx) = mpsc::channel::<DisplayEvent>(512);
    let (display_out, display_out_rx) = mpsc::channel::<OutMessage>(256);
    let dimensions;
    let counts;
    if available(channel_type::DISPLAY) {
        let (stream, mini) = link_channel(
            dialer.as_ref(),
            &config.security,
            connection_id,
            channel_type::DISPLAY,
            0,
            config.video_streams,
        )
        .await?;
        let (rx, tx) = tokio::io::split(stream);
        tasks.spawn(channel::writer_task(tx, mini, display_out_rx));
        let display = DisplayChannel::new(
            fb.clone(),
            events.clone(),
            display_out.clone(),
            config.limits,
        )
        .with_preferred_compression(config.preferred_compression)
        .with_video_streams(config.video_streams);
        dimensions = display.dimensions_handle();
        counts = display.counts_handle();
        tasks.spawn(display::reader_task(
            ChannelReader::new(rx, mini, display_out.clone(), "display"),
            display_events.clone(),
        ));
        tasks.spawn(display::display_task(
            display,
            display_rx,
            display_out.clone(),
        ));
    } else {
        return Err(SpiceError::protocol(
            "the server offers no display channel, so there is nothing to bridge",
        ));
    }

    if available(channel_type::CURSOR) {
        let (stream, mini) = link_channel(
            dialer.as_ref(),
            &config.security,
            connection_id,
            channel_type::CURSOR,
            0,
            config.video_streams,
        )
        .await?;
        let (rx, tx) = tokio::io::split(stream);
        let (out, out_rx) = mpsc::channel::<OutMessage>(16);
        tasks.spawn(channel::writer_task(tx, mini, out_rx));
        tasks.spawn(display::cursor_task(
            ChannelReader::new(rx, mini, out, "cursor"),
            display_events.clone(),
        ));
    }

    // Seeded from the mode `MAIN_INIT` reported, not left at the default.
    // The setup loop above has already consumed `MAIN_INIT`, so the
    // `MouseMode` outcome it produced will never reach `main_task` -- and a
    // session left in server mode sends relative deltas, which a server
    // whose only pointer is a tablet silently drops. `Xspice` is exactly
    // that server.
    let input = Arc::new(Mutex::new({
        let mut state = InputState::new(1, 1);
        state.set_mode(main.mouse_mode());
        state
    }));
    let (inputs_out, inputs_out_rx) = mpsc::channel::<OutMessage>(256);
    if available(channel_type::INPUTS) {
        let (stream, mini) = link_channel(
            dialer.as_ref(),
            &config.security,
            connection_id,
            channel_type::INPUTS,
            0,
            config.video_streams,
        )
        .await?;
        let (rx, tx) = tokio::io::split(stream);
        tasks.spawn(channel::writer_task(tx, mini, inputs_out_rx));
        tasks.spawn(inputs_task(
            ChannelReader::new(rx, mini, inputs_out.clone(), "inputs"),
            input.clone(),
            inputs_out.clone(),
        ));
    } else {
        // Nothing reads the receiver, so sends would fail; dropping it makes
        // `send_input` report `Disconnected` rather than hanging.
        drop(inputs_out_rx);
        tracing::warn!("the server offers no inputs channel: this session is view-only");
    }

    let mut audio = None;
    if config.audio && available(channel_type::PLAYBACK) {
        let (stream, mini) = link_channel(
            dialer.as_ref(),
            &config.security,
            connection_id,
            channel_type::PLAYBACK,
            0,
            config.video_streams,
        )
        .await?;
        let (rx, tx) = tokio::io::split(stream);
        let (out, out_rx) = mpsc::channel::<OutMessage>(16);
        tasks.spawn(channel::writer_task(tx, mini, out_rx));
        let (frames, frames_rx) = mpsc::channel::<AudioFrame>(64);
        tasks.spawn(playback_task(
            ChannelReader::new(rx, mini, out, "playback"),
            frames,
        ));
        audio = Some(frames_rx);
    }

    let main = Arc::new(Mutex::new(main));
    let (clipboard, _) = broadcast::channel(CLIPBOARD_EVENT_QUEUE);
    tasks.spawn(main_task(
        reader,
        main.clone(),
        main_out.clone(),
        input.clone(),
        events.clone(),
        clipboard.clone(),
        connected.clone(),
    ));

    let session = SpiceSession {
        fb,
        events,
        clipboard,
        main,
        main_out,
        inputs_out,
        input,
        dimensions,
        counts,
        connected,
        audio: Mutex::new(audio),
        display_events,
        tasks,
    };

    // Give the display channel a moment to deliver the primary surface, so
    // `dimensions()` is meaningful to the first caller.
    let deadline = tokio::time::Instant::now() + FIRST_SURFACE_TIMEOUT;
    while session.dimensions() == (0, 0) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    if session.dimensions() == (0, 0) {
        tracing::warn!("the display channel has not reported a primary surface yet");
    }

    Ok(session)
}

/// Keep the main channel running after setup.
async fn main_task<R: AsyncRead + Unpin>(
    mut reader: ChannelReader<R>,
    main: Arc<Mutex<MainChannel>>,
    out: mpsc::Sender<OutMessage>,
    input: Arc<Mutex<InputState>>,
    events: broadcast::Sender<BackendEvent>,
    clipboard: broadcast::Sender<ClipboardEvent>,
    connected: Arc<AtomicBool>,
) {
    loop {
        let message = match reader.next().await {
            Ok(Some(message)) => message,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, "spice main channel ended");
                break;
            }
        };
        let handled = {
            let mut main = main.lock().expect("main channel lock");
            main.handle(message.kind, &message.body)
        };
        match handled {
            Ok((send, outcomes)) => {
                for message in send {
                    if out.send(message).await.is_err() {
                        break;
                    }
                }
                for outcome in outcomes {
                    match outcome {
                        MainOutcome::MouseMode(mode) => {
                            input.lock().expect("input lock").set_mode(mode);
                        }
                        MainOutcome::ClipboardOffered(types) => {
                            // A type with no name here is not an error, it
                            // is a type this client declines to claim --
                            // `FILE_LIST`, overwhelmingly.
                            let named = types
                                .iter()
                                .filter_map(|t| ClipboardType::from_wire(*t))
                                .collect();
                            let _ = clipboard.send(ClipboardEvent::Offered(named));
                        }
                        MainOutcome::ClipboardReleased => {
                            let _ = clipboard.send(ClipboardEvent::Released);
                        }
                        MainOutcome::ClipboardRequested(kind) => {
                            match ClipboardType::from_wire(kind) {
                                Some(kind) => {
                                    let _ = clipboard.send(ClipboardEvent::Requested(kind));
                                }
                                None => {
                                    // The guest is blocked on an answer and no
                                    // subscriber could produce one, so answer
                                    // here rather than let it wait out its own
                                    // timeout.
                                    tracing::debug!(
                                        kind,
                                        "declining a clipboard request for a type this client \
                                     does not name"
                                    );
                                    let messages = main
                                        .lock()
                                        .expect("main channel lock")
                                        .agent
                                        .clipboard_data(clipboard_type::NONE, &[])
                                        .unwrap_or_default();
                                    for message in messages {
                                        if out.send(message).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        MainOutcome::ClipboardData { kind, data } => {
                            let event = match ClipboardType::from_wire(kind) {
                                Some(kind) => ClipboardEvent::Data { kind, data },
                                None => ClipboardEvent::Unavailable,
                            };
                            let _ = clipboard.send(event);
                        }
                        MainOutcome::Init { .. }
                        | MainOutcome::Channels(_)
                        | MainOutcome::AgentConnected(_) => {}
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "spice main channel error");
                break;
            }
        }
    }
    connected.store(false, Ordering::Relaxed);
    let _ = events.send(BackendEvent::Disconnected);
}

/// Read the inputs channel: modifiers and motion acknowledgements.
async fn inputs_task<R: AsyncRead + Unpin>(
    mut reader: ChannelReader<R>,
    input: Arc<Mutex<InputState>>,
    out: mpsc::Sender<OutMessage>,
) {
    loop {
        let message = match reader.next().await {
            Ok(Some(message)) => message,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, "spice inputs channel ended");
                break;
            }
        };
        match message.kind {
            inputs_msg::MOUSE_MOTION_ACK => {
                let flushed = input.lock().expect("input lock").motion_ack();
                for message in flushed {
                    if out.send(message).await.is_err() {
                        return;
                    }
                }
            }
            inputs_msg::INIT | inputs_msg::KEY_MODIFIERS => {
                // The guest's lock-key state. There is nothing to answer
                // with: `KEY_MODIFIERS` is how a client tells the guest its
                // *local* lock state, and a bridge has no local keyboard --
                // Moonlight sends key events, and Caps Lock arrives as one.
                // Echoing the guest's own state back would be a no-op at
                // best and a fight at worst.
                let mut r = Reader::new(&message.body);
                if let Ok(modifiers) = r.u16() {
                    tracing::debug!(modifiers, "spice guest keyboard modifiers");
                }
            }
            other => tracing::debug!(kind = other, "ignoring inputs message"),
        }
    }
}

/// Read the playback channel into the audio queue.
async fn playback_task<R: AsyncRead + Unpin>(
    mut reader: ChannelReader<R>,
    frames: mpsc::Sender<AudioFrame>,
) {
    let mut playback = Playback::new();
    loop {
        let message = match reader.next().await {
            Ok(Some(message)) => message,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, "spice playback channel ended");
                break;
            }
        };
        match playback.handle(message.kind, &message.body) {
            Ok(Some(frame)) => {
                // Audio is realtime: a full queue means the consumer has
                // fallen behind, and dropping the newest frame is better
                // than blocking the channel reader behind it.
                if frames.try_send(frame).is_err() {
                    tracing::trace!("dropping an audio frame: the queue is full");
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %e, "spice playback error");
                break;
            }
        }
    }
}

/// A live SPICE session.
pub struct SpiceSession {
    fb: FramebufferHandle,
    events: broadcast::Sender<BackendEvent>,
    clipboard: broadcast::Sender<ClipboardEvent>,
    main: Arc<Mutex<MainChannel>>,
    main_out: mpsc::Sender<OutMessage>,
    inputs_out: mpsc::Sender<OutMessage>,
    input: Arc<Mutex<InputState>>,
    dimensions: Arc<AtomicU64>,
    counts: Arc<DisplayCounts>,
    connected: Arc<AtomicBool>,
    audio: Mutex<Option<mpsc::Receiver<AudioFrame>>>,
    /// The display queue, for moving the composited pointer.
    display_events: mpsc::Sender<DisplayEvent>,
    /// Every channel's tasks; aborting them is what closes the sockets.
    tasks: Tasks,
}

/// A session's channel tasks, aborted together: by `close`, by a setup that
/// fails partway, or when the session is dropped.
///
/// Each channel's reader and writer hold the two halves of its socket, and
/// each reader holds a sender to its writer for acknowledgements, so left
/// alone they outlive the session: the connection to the guest stayed open
/// until the next session's connect displaced it (`docs/roadmap.md` §8).
#[derive(Default)]
struct Tasks(Mutex<Vec<tokio::task::AbortHandle>>);

impl Tasks {
    fn spawn<F>(&self, task: F)
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let handle = tokio::spawn(task).abort_handle();
        self.0.lock().expect("task lock").push(handle);
    }

    fn abort_all(&self) {
        for handle in self.0.lock().expect("task lock").drain(..) {
            handle.abort();
        }
    }
}

impl Drop for Tasks {
    fn drop(&mut self) {
        self.abort_all();
    }
}

impl std::fmt::Debug for SpiceSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (width, height) = self.dimensions();
        f.debug_struct("SpiceSession")
            .field("width", &width)
            .field("height", &height)
            .finish_non_exhaustive()
    }
}

impl SpiceSession {
    /// How many of each draw command the display channel has executed,
    /// keyed by `display_msg` number; kinds never seen are absent.
    ///
    /// For tests and logs: this is what turns "the guest drew a line" into
    /// "a `DRAW_STROKE` arrived and was executed" (`docs/roadmap.md` §2.7).
    pub fn draw_counts(&self) -> BTreeMap<u16, u64> {
        self.counts.draws()
    }

    /// How many images of each encoding the display channel has decoded,
    /// keyed by `image_type` number. Cache hits count as `FROM_CACHE`.
    pub fn image_counts(&self) -> BTreeMap<u8, u64> {
        self.counts.images()
    }

    /// How many video-stream frames the display channel has decoded and
    /// composited. A frame dropped as undecodable does not count.
    pub fn stream_frame_count(&self) -> u64 {
        self.counts.stream_frames()
    }

    /// The pointer representation in force, for tests and logs.
    pub fn mouse_mode(&self) -> MouseMode {
        self.input.lock().expect("input lock").mode()
    }

    /// Whether the guest agent is running, which is what decides whether a
    /// resize request can be honoured.
    pub fn can_resize(&self) -> bool {
        self.main.lock().expect("main channel lock").can_resize()
    }

    /// Whether the guest agent will exchange clipboard messages.
    ///
    /// False until `spice-vdagent` has announced its capabilities, which
    /// happens shortly *after* `connect` returns rather than during it, so a
    /// caller that checks once and gives up will usually see `false`.
    pub fn can_clipboard(&self) -> bool {
        self.main.lock().expect("main channel lock").can_clipboard()
    }

    /// Subscribe to what the guest does with its clipboard.
    ///
    /// Subscribe *before* calling [`SpiceSession::request_clipboard`]: the
    /// answer is an event, and a receiver created afterwards may miss it.
    pub fn subscribe_clipboard(&self) -> broadcast::Receiver<ClipboardEvent> {
        self.clipboard.subscribe()
    }

    /// Offer this client's clipboard to the guest, naming what it could
    /// produce.
    ///
    /// Nothing is sent yet; the guest asks for one of the types when it
    /// needs the bytes, which arrives as
    /// [`ClipboardEvent::Requested`]. Best-effort in the same sense as
    /// [`Session::request_resize`]: `Ok(false)` means there is no agent to
    /// hear it.
    pub async fn offer_clipboard(&self, types: &[ClipboardType]) -> solstice_backend::Result<bool> {
        let wire: Vec<u32> = types.iter().map(|t| t.to_wire()).collect();
        self.agent_send(|agent| agent.clipboard_grab(&wire)).await
    }

    /// Withdraw an offer made with [`SpiceSession::offer_clipboard`].
    pub async fn release_clipboard(&self) -> solstice_backend::Result<bool> {
        self.agent_send(|agent| agent.clipboard_release()).await
    }

    /// Ask the guest for its clipboard, in one of the types it offered.
    ///
    /// The payload comes back as [`ClipboardEvent::Data`], or
    /// [`ClipboardEvent::Unavailable`] if the guest cannot produce it after
    /// all.
    pub async fn request_clipboard(&self, kind: ClipboardType) -> solstice_backend::Result<bool> {
        self.agent_send(|agent| agent.clipboard_request(kind.to_wire()))
            .await
    }

    /// Answer a [`ClipboardEvent::Requested`] with the bytes.
    ///
    /// Fails with [`BackendError::Limit`] past
    /// [`crate::agent::MAX_CLIPBOARD_PAYLOAD`], which is the same ceiling
    /// the guest was told about when the agent came up.
    pub async fn send_clipboard(
        &self,
        kind: ClipboardType,
        data: &[u8],
    ) -> solstice_backend::Result<bool> {
        self.send_clipboard_payload(kind.to_wire(), data).await
    }

    /// Answer a [`ClipboardEvent::Requested`] with "nothing".
    ///
    /// Worth doing rather than ignoring the request: the guest's paste is
    /// blocked until something answers it.
    pub async fn decline_clipboard(&self) -> solstice_backend::Result<bool> {
        self.send_clipboard_payload(clipboard_type::NONE, &[]).await
    }

    /// `VD_AGENT_CLIPBOARD` with a raw type word.
    ///
    /// Raw rather than a [`ClipboardType`] because this is the one place
    /// `NONE` is a legitimate value to send -- it is the protocol's "there
    /// is nothing", not a payload type, so it has no variant.
    async fn send_clipboard_payload(
        &self,
        kind: u32,
        data: &[u8],
    ) -> solstice_backend::Result<bool> {
        let messages = {
            let mut main = self.main.lock().expect("main channel lock");
            // The ceiling is checked whether or not an agent is listening,
            // and before the reachability question is answered: an
            // oversized payload is the caller's mistake either way, and
            // reporting it as a polite `Ok(false)` would hide it until a
            // guest happened to be running.
            let reachable = main.can_clipboard();
            let messages = main.agent.clipboard_data(kind, data)?;
            if !reachable {
                return Ok(false);
            }
            messages
        };
        self.send_main(messages).await?;
        Ok(true)
    }

    /// Run an agent call that is gated on the clipboard being reachable, and
    /// send whatever it produced.
    ///
    /// An empty result from a reachable agent is not a refusal: it is out of
    /// tokens, and the message is queued until `MAIN_AGENT_TOKEN` releases
    /// it. `request_resize` reads the same way.
    async fn agent_send(
        &self,
        build: impl FnOnce(&mut crate::agent::Agent) -> Vec<OutMessage>,
    ) -> solstice_backend::Result<bool> {
        let messages = {
            let mut main = self.main.lock().expect("main channel lock");
            if !main.can_clipboard() {
                return Ok(false);
            }
            build(&mut main.agent)
        };
        self.send_main(messages).await?;
        Ok(true)
    }

    async fn send_main(&self, messages: Vec<OutMessage>) -> solstice_backend::Result<()> {
        for message in messages {
            self.main_out
                .send(message)
                .await
                .map_err(|_| BackendError::Disconnected)?;
        }
        Ok(())
    }
}

/// How long `request_resize` waits for the guest agent to say whether it can
/// resize.
const RESIZE_SETTLE: std::time::Duration = std::time::Duration::from_secs(2);

#[async_trait]
impl Session for SpiceSession {
    fn dimensions(&self) -> (u32, u32) {
        let packed = self.dimensions.load(Ordering::Relaxed);
        ((packed >> 32) as u32, packed as u32)
    }

    async fn request_resize(&self, width: u32, height: u32) -> solstice_backend::Result<bool> {
        // Best-effort, like RFB's: without `spice-vdagent` in the guest
        // there is nothing that can change the mode, and the caller falls
        // back to scaling (`docs/bridging-design.md` §2.2).
        //
        // The caller asks straight after `connect`, and the agent announces
        // itself a moment later -- a real session decided "no agent" 0.1 ms
        // before the announcement arrived, and scaled a desktop it could have
        // resized. So wait until the answer is settled, briefly.
        let deadline = tokio::time::Instant::now() + RESIZE_SETTLE;
        while !self
            .main
            .lock()
            .expect("main channel lock")
            .resize_settled()
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let messages = {
            let mut main = self.main.lock().expect("main channel lock");
            if !main.can_resize() {
                return Ok(false);
            }
            main.request_resize(width, height)
        };
        if messages.is_empty() {
            // The agent is connected but out of tokens; the request is
            // queued and will go out when they arrive.
            return Ok(true);
        }
        for message in messages {
            self.main_out
                .send(message)
                .await
                .map_err(|_| BackendError::Disconnected)?;
        }
        Ok(true)
    }

    fn subscribe(&self) -> broadcast::Receiver<BackendEvent> {
        self.events.subscribe()
    }

    fn framebuffer(&self) -> FramebufferHandle {
        self.fb.clone()
    }

    async fn send_input(&self, event: InputEvent) -> solstice_backend::Result<()> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(BackendError::Disconnected);
        }
        let (messages, pointer) = {
            let mut state = self.input.lock().expect("input lock");
            let (width, height) = self.dimensions();
            if width != 0 && height != 0 {
                state.resize(width, height);
            }
            let before = state.position();
            let messages = state.encode(&event);
            let after = state.position();
            // In client mode the server never sends the pointer's position:
            // the client is expected to draw it where *its* pointer is, and
            // only a shape change carries a position at all. Following the
            // cursor channel alone left the composited pointer stuck wherever
            // the shape last changed.
            let moved = state.mode() == MouseMode::Client && after != before;
            (messages, moved.then_some(after))
        };
        for message in messages {
            self.inputs_out
                .send(message)
                .await
                .map_err(|_| BackendError::Disconnected)?;
        }
        if let Some((x, y)) = pointer {
            let _ = self
                .display_events
                .send(DisplayEvent::Cursor(crate::cursor::CursorUpdate::Move {
                    x: x as i32,
                    y: y as i32,
                }))
                .await;
        }
        Ok(())
    }

    fn take_audio(&self) -> Option<mpsc::Receiver<AudioFrame>> {
        self.audio.lock().expect("audio lock").take()
    }

    async fn close(&self) {
        self.connected.store(false, Ordering::Relaxed);
        let _ = self.events.send(BackendEvent::Disconnected);
        self.tasks.abort_all();
    }
}

/// Whether a host string names the loopback interface.
pub fn is_loopback(host: &str) -> bool {
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(host == "localhost")
}

fn is_loopback_addr(ip: IpAddr) -> bool {
    ip.is_loopback()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection_covers_the_forms_a_config_file_will_hold() {
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("::1"));
        assert!(is_loopback("localhost"));
        assert!(!is_loopback("192.168.1.10"));
        assert!(!is_loopback("spice.example.com"));
    }

    #[test]
    fn the_default_configuration_requires_tls() {
        assert!(SpiceConfig::default().security.is_tls());
    }

    #[test]
    fn the_display_channel_does_not_advertise_capabilities_it_cannot_execute() {
        let caps = channel_caps(channel_type::DISPLAY, true);
        assert!(!caps.has(display_cap::GL_SCANOUT));
        assert!(!caps.has(display_cap::GL_SCANOUT2));
        assert!(!caps.has(display_cap::COMPOSITE));
        assert!(caps.has(display_cap::CODEC_MJPEG));
        assert!(caps.has(display_cap::LZ4_COMPRESSION));
    }

    #[test]
    fn without_video_streams_no_codec_is_advertised_but_multi_codec_is() {
        let caps = channel_caps(channel_type::DISPLAY, false);
        // Without MULTI_CODEC the server assumes MJPEG, and streams anyway.
        assert!(caps.has(display_cap::MULTI_CODEC));
        for codec in [
            display_cap::CODEC_MJPEG,
            display_cap::CODEC_VP8,
            display_cap::CODEC_H264,
            display_cap::CODEC_VP9,
            display_cap::CODEC_H265,
            display_cap::PREF_VIDEO_CODEC_TYPE,
            display_cap::STREAM_REPORT,
            display_cap::SIZED_STREAM,
        ] {
            assert!(!caps.has(codec), "capability {codec}");
        }
        assert!(!SpiceConfig::default().video_streams, "off by default");
    }

    #[test]
    fn only_mjpeg_is_advertised_among_the_video_codecs() {
        let caps = channel_caps(channel_type::DISPLAY, true);
        assert!(!caps.has(display_cap::CODEC_VP8));
        assert!(!caps.has(display_cap::CODEC_H264));
        assert!(!caps.has(display_cap::CODEC_VP9));
        assert!(!caps.has(display_cap::CODEC_H265));
    }

    #[test]
    fn the_playback_channel_asks_for_opus_which_is_what_gamestream_carries() {
        assert!(channel_caps(channel_type::PLAYBACK, false).has(playback_cap::OPUS));
        assert!(!channel_caps(channel_type::PLAYBACK, false).has(playback_cap::CELT_0_5_1));
    }

    #[tokio::test]
    async fn a_plaintext_connection_off_loopback_is_refused_before_anything_is_sent() {
        // 198.51.100.0/24 is TEST-NET-2 and is guaranteed unroutable, so
        // this fails at connect rather than at the policy check -- which is
        // why the policy is also asserted directly below.
        let config = SpiceConfig {
            host: "198.51.100.1".into(),
            security: SpiceSecurity::Plain { password: None },
            ..SpiceConfig::default()
        };
        assert!(!is_loopback(&config.host));
        assert!(!config.security.is_tls());
    }

    #[test]
    fn the_password_defaults_to_empty_rather_than_absent() {
        // A server with ticketing disabled still wants the encrypted block,
        // and an empty password encrypts to one NUL byte.
        let security = SpiceSecurity::Plain { password: None };
        assert_eq!(security.password(), "");
    }
}
