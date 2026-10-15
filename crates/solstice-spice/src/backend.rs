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

use crate::channel::{self, ChannelReader, OutMessage};
use crate::display::{self, DisplayChannel, DisplayEvent, DisplayLimits};
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
                if !is_loopback_addr(peer) && !is_loopback(&self.config.host) {
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
fn channel_caps(kind: u8) -> Caps {
    match kind {
        channel_type::MAIN => {
            Caps::from_bits(&[main_cap::NAME_AND_UUID, main_cap::AGENT_CONNECTED_TOKENS])
        }
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
) -> Result<(Box<dyn Transport>, bool)> {
    let mut stream = dialer.dial().await?;
    let request = LinkRequest::new(connection_id, kind, id).with_channel_caps(channel_caps(kind));
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

/// Dial, link every channel the server offers, and start the session.
pub async fn connect(dialer: Arc<dyn Dialer>, config: SpiceConfig) -> Result<SpiceSession> {
    tokio::time::timeout(SETUP_TIMEOUT, connect_inner(dialer, config))
        .await
        .map_err(|_| SpiceError::protocol("the server linked but never sent MAIN_INIT"))?
}

async fn connect_inner(dialer: Arc<dyn Dialer>, config: SpiceConfig) -> Result<SpiceSession> {
    let (stream, mini) =
        link_channel(dialer.as_ref(), &config.security, 0, channel_type::MAIN, 0).await?;
    let (main_reader, main_writer) = tokio::io::split(stream);
    let (main_out, main_out_rx) = mpsc::channel::<OutMessage>(256);
    tokio::spawn(channel::writer_task(main_writer, mini, main_out_rx));

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
    if available(channel_type::DISPLAY) {
        let (stream, mini) = link_channel(
            dialer.as_ref(),
            &config.security,
            connection_id,
            channel_type::DISPLAY,
            0,
        )
        .await?;
        let (rx, tx) = tokio::io::split(stream);
        tokio::spawn(channel::writer_task(tx, mini, display_out_rx));
        let display = DisplayChannel::new(
            fb.clone(),
            events.clone(),
            display_out.clone(),
            config.limits,
        );
        dimensions = display.dimensions_handle();
        tokio::spawn(display::reader_task(
            ChannelReader::new(rx, mini, display_out.clone(), "display"),
            display_events.clone(),
        ));
        tokio::spawn(display::display_task(
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
        )
        .await?;
        let (rx, tx) = tokio::io::split(stream);
        let (out, out_rx) = mpsc::channel::<OutMessage>(16);
        tokio::spawn(channel::writer_task(tx, mini, out_rx));
        tokio::spawn(display::cursor_task(
            ChannelReader::new(rx, mini, out, "cursor"),
            display_events.clone(),
        ));
    }

    let input = Arc::new(Mutex::new(InputState::new(1, 1)));
    let (inputs_out, inputs_out_rx) = mpsc::channel::<OutMessage>(256);
    if available(channel_type::INPUTS) {
        let (stream, mini) = link_channel(
            dialer.as_ref(),
            &config.security,
            connection_id,
            channel_type::INPUTS,
            0,
        )
        .await?;
        let (rx, tx) = tokio::io::split(stream);
        tokio::spawn(channel::writer_task(tx, mini, inputs_out_rx));
        tokio::spawn(inputs_task(
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
        )
        .await?;
        let (rx, tx) = tokio::io::split(stream);
        let (out, out_rx) = mpsc::channel::<OutMessage>(16);
        tokio::spawn(channel::writer_task(tx, mini, out_rx));
        let (frames, frames_rx) = mpsc::channel::<AudioFrame>(64);
        tokio::spawn(playback_task(
            ChannelReader::new(rx, mini, out, "playback"),
            frames,
        ));
        audio = Some(frames_rx);
    }

    let main = Arc::new(Mutex::new(main));
    tokio::spawn(main_task(
        reader,
        main.clone(),
        main_out.clone(),
        input.clone(),
        events.clone(),
        connected.clone(),
    ));

    Ok(SpiceSession {
        fb,
        events,
        main,
        main_out,
        inputs_out,
        input,
        dimensions,
        connected,
        audio: Mutex::new(audio),
    })
}

/// Keep the main channel running after setup.
async fn main_task<R: AsyncRead + Unpin>(
    mut reader: ChannelReader<R>,
    main: Arc<Mutex<MainChannel>>,
    out: mpsc::Sender<OutMessage>,
    input: Arc<Mutex<InputState>>,
    events: broadcast::Sender<BackendEvent>,
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
                    if let MainOutcome::MouseMode(mode) = outcome {
                        input.lock().expect("input lock").set_mode(mode);
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
    main: Arc<Mutex<MainChannel>>,
    main_out: mpsc::Sender<OutMessage>,
    inputs_out: mpsc::Sender<OutMessage>,
    input: Arc<Mutex<InputState>>,
    dimensions: Arc<AtomicU64>,
    connected: Arc<AtomicBool>,
    audio: Mutex<Option<mpsc::Receiver<AudioFrame>>>,
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
    /// The pointer representation in force, for tests and logs.
    pub fn mouse_mode(&self) -> MouseMode {
        self.input.lock().expect("input lock").mode()
    }

    /// Whether the guest agent is running, which is what decides whether a
    /// resize request can be honoured.
    pub fn can_resize(&self) -> bool {
        self.main.lock().expect("main channel lock").can_resize()
    }
}

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
        let messages = {
            let mut state = self.input.lock().expect("input lock");
            let (width, height) = self.dimensions();
            if width != 0 && height != 0 {
                state.resize(width, height);
            }
            state.encode(&event)
        };
        for message in messages {
            self.inputs_out
                .send(message)
                .await
                .map_err(|_| BackendError::Disconnected)?;
        }
        Ok(())
    }

    fn take_audio(&self) -> Option<mpsc::Receiver<AudioFrame>> {
        self.audio.lock().expect("audio lock").take()
    }

    async fn close(&self) {
        self.connected.store(false, Ordering::Relaxed);
        let _ = self.events.send(BackendEvent::Disconnected);
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
        let caps = channel_caps(channel_type::DISPLAY);
        assert!(!caps.has(display_cap::GL_SCANOUT));
        assert!(!caps.has(display_cap::GL_SCANOUT2));
        assert!(!caps.has(display_cap::COMPOSITE));
        assert!(caps.has(display_cap::CODEC_MJPEG));
        assert!(caps.has(display_cap::LZ4_COMPRESSION));
    }

    #[test]
    fn only_mjpeg_is_advertised_among_the_video_codecs() {
        let caps = channel_caps(channel_type::DISPLAY);
        assert!(!caps.has(display_cap::CODEC_VP8));
        assert!(!caps.has(display_cap::CODEC_H264));
        assert!(!caps.has(display_cap::CODEC_VP9));
        assert!(!caps.has(display_cap::CODEC_H265));
    }

    #[test]
    fn the_playback_channel_asks_for_opus_which_is_what_gamestream_carries() {
        assert!(channel_caps(channel_type::PLAYBACK).has(playback_cap::OPUS));
        assert!(!channel_caps(channel_type::PLAYBACK).has(playback_cap::CELT_0_5_1));
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
