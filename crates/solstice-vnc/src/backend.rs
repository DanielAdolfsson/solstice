//! The [`Backend`] implementation: dial, handshake, and run the session.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use solstice_backend::{
    Backend, BackendError, BackendEvent, FramebufferHandle, InputEvent, Rect, Session,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, watch};

use crate::auth::{vnc_auth_response, VncSecurity};
use crate::handshake::{self, RfbTransport};
use crate::input::InputState;
use crate::pixel::PixelFormat;
use crate::protocol::{vencrypt, Result, RfbError};
use crate::session::{self, UpdateLoop, ENCODINGS};

pub use crate::auth::VncSecurity as Security;

/// How to reach a VNC server.
#[derive(Clone, Debug)]
pub struct VncConfig {
    /// Hostname or address.
    pub host: String,
    /// TCP port, 5900 + display number.
    pub port: u16,
    /// Authentication method and its policy.
    pub security: VncSecurity,
    /// The RFB "shared" flag: whether other clients may stay connected.
    pub shared: bool,
}

impl Default for VncConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 5900,
            security: VncSecurity::VeNCrypt {
                password: None,
                ca_file: None,
            },
            shared: true,
        }
    }
}

/// The RFB backend.
#[derive(Debug)]
pub struct VncBackend {
    config: VncConfig,
}

impl VncBackend {
    /// Build one.
    pub fn new(config: VncConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Backend for VncBackend {
    fn name(&self) -> &'static str {
        "vnc"
    }

    async fn connect(&self) -> solstice_backend::Result<Box<dyn Session>> {
        let session = connect(&self.config).await.map_err(to_backend_error)?;
        Ok(Box::new(session))
    }
}

fn to_backend_error(e: RfbError) -> BackendError {
    match e {
        RfbError::Io(e) => BackendError::Io(e),
        RfbError::Auth(m) => BackendError::Auth(m),
        RfbError::Tls(m) => BackendError::Auth(m),
        RfbError::Limit(m) => BackendError::Limit(m),
        other => BackendError::Protocol(other.to_string()),
    }
}

/// Dial, handshake and start the session.
pub async fn connect(config: &VncConfig) -> Result<VncSession> {
    let stream = TcpStream::connect((config.host.as_str(), config.port)).await?;
    // Nagle batches our small input messages behind each other; on an input
    // path that is pure added latency.
    stream.set_nodelay(true)?;
    let peer = stream.peer_addr()?.ip();

    let mut stream: Box<dyn RfbTransport> = Box::new(stream);
    let version = handshake::negotiate_version(&mut stream).await?;
    let offered = handshake::read_security_types(&mut stream, version).await?;
    let chosen = handshake::choose_security(&config.security, &offered, peer)?;
    tracing::info!(%peer, version = ?version, chosen, "rfb handshake");

    if version.has_security_list() {
        stream.write_all(&[chosen]).await?;
        stream.flush().await?;
    }

    match &config.security {
        VncSecurity::VeNCrypt { password, ca_file } => {
            stream = vencrypt_upgrade(
                stream,
                config,
                version,
                password.as_deref(),
                ca_file.as_ref(),
            )
            .await?;
        }
        other => handshake::authenticate(&mut stream, version, other).await?,
    }

    let init = handshake::initialise(&mut stream, config.shared).await?;
    tracing::info!(
        width = init.width,
        height = init.height,
        name = %init.name,
        "rfb session established"
    );

    start_session(stream, init.width as u32, init.height as u32).await
}

async fn vencrypt_upgrade(
    mut stream: Box<dyn RfbTransport>,
    config: &VncConfig,
    version: handshake::Version,
    password: Option<&str>,
    ca_file: Option<&PathBuf>,
) -> Result<Box<dyn RfbTransport>> {
    use tokio::io::AsyncReadExt;

    let subtype = handshake::negotiate_vencrypt(&mut stream, password.is_some()).await?;
    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).await?;
    if ack[0] != 1 {
        return Err(RfbError::Auth(
            "server refused the VeNCrypt sub-type".into(),
        ));
    }

    let tls_config = tls_client_config(ca_file)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls_pki_types::ServerName::try_from(config.host.clone())
        .map_err(|e| RfbError::Tls(format!("{} is not a valid server name: {e}", config.host)))?;
    let mut tls: Box<dyn RfbTransport> = Box::new(
        connector
            .connect(server_name, stream)
            .await
            .map_err(|e| RfbError::Tls(format!("TLS handshake: {e}")))?,
    );

    // Inside the tunnel, the sub-type's own authentication runs.
    match subtype {
        vencrypt::X509_NONE => handshake::read_security_result(&mut tls, version).await?,
        vencrypt::X509_VNC => {
            let password = password.unwrap_or_default();
            let mut challenge = [0u8; 16];
            tls.read_exact(&mut challenge).await?;
            tls.write_all(&vnc_auth_response(password, &challenge))
                .await?;
            tls.flush().await?;
            handshake::read_security_result(&mut tls, version).await?;
        }
        other => {
            return Err(RfbError::Auth(format!(
                "unhandled VeNCrypt sub-type {other}"
            )))
        }
    }
    Ok(tls)
}

fn tls_client_config(ca_file: Option<&PathBuf>) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    match ca_file {
        Some(path) => {
            let pem = std::fs::read(path)?;
            let mut cursor = std::io::Cursor::new(pem);
            for cert in rustls_pemfile::certs(&mut cursor) {
                let cert = cert.map_err(|e| RfbError::Tls(format!("reading {path:?}: {e}")))?;
                roots
                    .add(cert)
                    .map_err(|e| RfbError::Tls(format!("adding a root from {path:?}: {e}")))?;
            }
            if roots.is_empty() {
                return Err(RfbError::Tls(format!("{path:?} contains no certificates")));
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    // Certificates are verified properly. Moonlight's habit of ignoring SSL
    // errors is not inherited here (`docs/security.md` §4.1).
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// Start the reader and writer tasks over an already-authenticated transport.
///
/// Public so the mock-server tests can drive a session over an in-memory
/// duplex rather than a socket.
pub async fn start_session<S>(stream: S, width: u32, height: u32) -> Result<VncSession>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, writer) = tokio::io::split(stream);
    let (outgoing, outgoing_rx) = mpsc::channel::<Vec<u8>>(256);
    let (events, _) = broadcast::channel(256);
    let fb = FramebufferHandle::with_size(width, height);

    // Ask for the format we want and the encodings we can decode, then pull the
    // first full update.
    outgoing
        .send(session::set_pixel_format(&PixelFormat::BGRA))
        .await
        .map_err(|_| RfbError::Protocol("session closed before setup".into()))?;
    let _ = outgoing.send(session::set_encodings(ENCODINGS)).await;
    let _ = outgoing
        .send(session::update_request(false, Rect::whole(width, height)))
        .await;

    tokio::spawn(session::writer_task(writer, outgoing_rx));

    let dimensions = Arc::new(AtomicU64::new(pack_dimensions(width, height)));
    let qemu_extended_key = Arc::new(AtomicBool::new(false));
    let extended_desktop_size = Arc::new(AtomicBool::new(false));
    let connected = Arc::new(AtomicBool::new(true));
    let (heard_tx, heard) = watch::channel(false);

    let mut update_loop = UpdateLoop::new(
        reader,
        PixelFormat::BGRA,
        fb.clone(),
        events.clone(),
        outgoing.clone(),
    );
    {
        let dimensions = dimensions.clone();
        let qemu = qemu_extended_key.clone();
        let eds = extended_desktop_size.clone();
        let connected = connected.clone();
        let events = events.clone();
        let outgoing = outgoing.clone();
        let fb = fb.clone();
        tokio::spawn(async move {
            let mut continuous_enabled = false;
            loop {
                if let Err(e) = update_loop.step().await {
                    if !matches!(&e, RfbError::Io(io) if io.kind() == std::io::ErrorKind::UnexpectedEof)
                    {
                        tracing::warn!(error = %e, "rfb session ended");
                    }
                    break;
                }
                let caps = update_loop.capabilities();
                qemu.store(caps.qemu_extended_key, Ordering::Relaxed);
                eds.store(caps.extended_desktop_size, Ordering::Relaxed);
                heard_tx.send_replace(true);
                {
                    let fb = fb.read();
                    dimensions.store(pack_dimensions(fb.width(), fb.height()), Ordering::Relaxed);
                }
                // Push beats pull: enable continuous updates as soon as the
                // server tells us it has them.
                if caps.continuous_updates && !continuous_enabled {
                    let (w, h) = {
                        let fb = fb.read();
                        (fb.width(), fb.height())
                    };
                    if outgoing
                        .send(session::enable_continuous_updates(true, Rect::whole(w, h)))
                        .await
                        .is_ok()
                    {
                        update_loop.set_continuous(true);
                        continuous_enabled = true;
                        tracing::debug!("continuous updates enabled");
                    }
                }
            }
            connected.store(false, Ordering::Relaxed);
            let _ = events.send(BackendEvent::Disconnected);
        });
    }

    Ok(VncSession {
        fb,
        events,
        outgoing,
        input: Mutex::new(InputState::new(width, height)),
        dimensions,
        qemu_extended_key,
        extended_desktop_size,
        heard,
        connected,
    })
}

/// How long `request_resize` waits to learn whether the server can resize.
const CAPABILITY_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

const fn pack_dimensions(width: u32, height: u32) -> u64 {
    ((width as u64) << 32) | height as u64
}

/// A live RFB session.
pub struct VncSession {
    fb: FramebufferHandle,
    events: broadcast::Sender<BackendEvent>,
    outgoing: mpsc::Sender<Vec<u8>>,
    input: Mutex<InputState>,
    dimensions: Arc<AtomicU64>,
    qemu_extended_key: Arc<AtomicBool>,
    extended_desktop_size: Arc<AtomicBool>,
    /// True once the server's first message has been read. What it supports
    /// is only known from the pseudo-rectangles in its replies, not from the
    /// handshake.
    heard: watch::Receiver<bool>,
    connected: Arc<AtomicBool>,
}

impl std::fmt::Debug for VncSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (w, h) = self.dimensions();
        f.debug_struct("VncSession")
            .field("width", &w)
            .field("height", &h)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Session for VncSession {
    fn dimensions(&self) -> (u32, u32) {
        let packed = self.dimensions.load(Ordering::Relaxed);
        ((packed >> 32) as u32, packed as u32)
    }

    async fn request_resize(&self, width: u32, height: u32) -> solstice_backend::Result<bool> {
        // Best-effort by construction: ExtendedDesktopSize lets a client *ask*,
        // and a server is free to decline. The caller falls back to scaling.
        //
        // The caller asks straight after `connect`, before the server has
        // answered `SetEncodings` -- so wait for that answer, or a server that
        // supports resizing is always reported as one that does not.
        let mut heard = self.heard.clone();
        let _ = tokio::time::timeout(CAPABILITY_WAIT, heard.wait_for(|h| *h)).await;
        if !self.extended_desktop_size.load(Ordering::Relaxed) {
            return Ok(false);
        }
        let message = session::set_desktop_size(width.min(65535) as u16, height.min(65535) as u16);
        self.outgoing
            .send(message)
            .await
            .map_err(|_| BackendError::Disconnected)?;
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
            let (w, h) = self.dimensions();
            state.resize(w, h);
            state.qemu_extended_key = self.qemu_extended_key.load(Ordering::Relaxed);
            state.encode(&event)
        };
        for message in messages {
            self.outgoing
                .send(message)
                .await
                .map_err(|_| BackendError::Disconnected)?;
        }
        Ok(())
    }

    async fn close(&self) {
        self.connected.store(false, Ordering::Relaxed);
        // Dropping the sender ends the writer task, which closes the socket.
        let _ = self.events.send(BackendEvent::Disconnected);
    }
}

/// Whether an address is one the weak security types may be used against.
pub fn is_loopback(host: &str) -> bool {
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(host == "localhost")
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
        assert!(!is_loopback("vnc.example.com"));
    }

    #[test]
    fn dimensions_pack_and_unpack() {
        assert_eq!(pack_dimensions(1920, 1080), (1920u64 << 32) | 1080);
    }

    #[test]
    fn the_default_config_requires_vencrypt() {
        let config = VncConfig::default();
        assert!(matches!(config.security, VncSecurity::VeNCrypt { .. }));
    }
}
