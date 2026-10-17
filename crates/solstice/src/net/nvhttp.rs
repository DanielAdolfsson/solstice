//! The two NVHTTP listeners.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use solstice_gamestream::nvhttp::http::{self, HttpResponse};
use solstice_gamestream::nvhttp::{handle, Host, RequestContext};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// How long a client has to send a complete request head.
const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The longest a `getservercert` is held waiting for `solstice pair`: the
/// longest window that command can open.
const PAIR_HOLD: std::time::Duration = crate::management::MAX_WINDOW;

/// How often a held `getservercert` looks at the window.
const PAIR_HOLD_POLL: std::time::Duration = std::time::Duration::from_millis(100);

/// Whether a `getservercert` is already being held. One at a time.
static PAIR_HOLDING: AtomicBool = AtomicBool::new(false);

/// Serve plaintext NVHTTP: `/serverinfo` and the PIN handshake.
pub async fn serve_plaintext(host: Arc<Host>, addr: SocketAddr) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "nvhttp (plaintext) listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let host = host.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_one(host, stream, peer, false, None).await {
                tracing::debug!(%peer, error = %e, "nvhttp connection ended");
            }
        });
    }
}

/// Serve mutual-TLS NVHTTP.
pub async fn serve_tls(
    host: Arc<Host>,
    addr: SocketAddr,
    config: Arc<rustls::ServerConfig>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    tracing::info!(%addr, "nvhttp (mutual TLS) listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let host = host.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(tls) => tls,
                Err(e) => {
                    tracing::debug!(%peer, error = %e, "TLS handshake failed");
                    return;
                }
            };
            // The exact DER of the presented certificate *is* the client's
            // identity; nothing else is compared (`docs/security.md` §3.3).
            let cert = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|c| c.as_ref().to_vec());
            if let Err(e) = serve_one(host, tls, peer, true, cert).await {
                tracing::debug!(%peer, error = %e, "nvhttp TLS connection ended");
            }
        });
    }
}

async fn serve_one<S>(
    host: Arc<Host>,
    mut stream: S,
    peer: SocketAddr,
    over_tls: bool,
    client_cert: Option<Vec<u8>>,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let request = loop {
        match http::parse_request(&buf) {
            Ok(Some((request, _))) => break request,
            Ok(None) => {}
            Err(reason) => {
                tracing::debug!(%peer, reason, "malformed NVHTTP request");
                let _ = stream
                    .write_all(&HttpResponse::status(400).to_bytes())
                    .await;
                return Ok(());
            }
        }
        let mut chunk = [0u8; 1024];
        let read = tokio::time::timeout(HEADER_TIMEOUT, stream.read(&mut chunk))
            .await
            .unwrap_or(Ok(0))?;
        if read == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.len() > http::MAX_REQUEST_LEN {
            let _ = stream
                .write_all(&HttpResponse::status(400).to_bytes())
                .await;
            return Ok(());
        }
    };

    if !over_tls && wants_pair_hold(&host, &request, peer) {
        if let Some(guard) = HoldGuard::take() {
            if !hold_for_pairing(&host, &mut stream, &request, peer).await {
                return Ok(());
            }
            drop(guard);
        }
    }

    let ctx = RequestContext {
        request: &request,
        over_tls,
        client_cert: client_cert.as_deref(),
        peer_ip: peer.ip(),
    };
    let response = handle(&host, &ctx);
    tracing::debug!(%peer, path = %request.path, status = response.status, outcome = response.outcome, over_tls, "nvhttp");
    stream.write_all(&response.to_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Whether this is a `getservercert` that arrived before `solstice pair`.
///
/// Moonlight makes the PIN up, shows it, and sends `getservercert` at once,
/// expecting the host to hold the request until someone types the PIN in --
/// Sunshine does exactly that. Refusing it instead would make pairing
/// impossible from a real client: the window can only be opened with a PIN the
/// client has not shown until it sends this request. Only an allowed source is
/// held, and never while pairing is locked out; anything else is answered at
/// once, as before.
fn wants_pair_hold(host: &Host, request: &http::HttpRequest, peer: SocketAddr) -> bool {
    if request.path != "/pair" || request.param("phrase") != Some("getservercert") {
        return false;
    }
    if !host.pairing_allowed_from(peer.ip()) {
        return false;
    }
    let mgr = host.pairing.lock().expect("pairing lock");
    !mgr.is_locked_out() && !mgr.is_open(Instant::now())
}

/// The one held `getservercert`, released on drop.
struct HoldGuard;

impl HoldGuard {
    fn take() -> Option<Self> {
        PAIR_HOLDING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then_some(Self)
    }
}

impl Drop for HoldGuard {
    fn drop(&mut self) {
        PAIR_HOLDING.store(false, Ordering::Release);
    }
}

/// Wait for the window to open. False if the client hung up first, in which
/// case there is no one to answer. A hold that runs out, or ends in a lockout,
/// is answered as a closed window by the handler.
async fn hold_for_pairing<S>(
    host: &Host,
    stream: &mut S,
    request: &http::HttpRequest,
    peer: SocketAddr,
) -> bool
where
    S: tokio::io::AsyncRead + Unpin,
{
    let device = request.param("devicename").unwrap_or("unknown");
    tracing::info!(
        %peer,
        device,
        "a client is waiting to pair: run `solstice pair --pin <the PIN it shows>`"
    );
    let deadline = tokio::time::Instant::now() + PAIR_HOLD;
    let mut scratch = [0u8; 64];
    loop {
        {
            let mgr = host.pairing.lock().expect("pairing lock");
            if mgr.is_open(Instant::now()) || mgr.is_locked_out() {
                return true;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            tracing::info!(%peer, "gave up holding a pairing request: no window opened");
            return true;
        }
        tokio::select! {
            _ = tokio::time::sleep(PAIR_HOLD_POLL) => {}
            // The client sends nothing more on this connection; a read ending
            // means it cancelled.
            read = stream.read(&mut scratch) => {
                if matches!(read, Ok(0) | Err(_)) {
                    tracing::info!(%peer, "the waiting client cancelled pairing");
                    return false;
                }
            }
        }
    }
}

/// Convenience for tests: run one request against an in-memory stream.
pub async fn handle_request_bytes(
    host: &Host,
    raw: &[u8],
    peer: SocketAddr,
    over_tls: bool,
    client_cert: Option<&[u8]>,
) -> Option<HttpResponse> {
    let (request, _) = http::parse_request(raw).ok()??;
    let ctx = RequestContext {
        request: &request,
        over_tls,
        client_cert,
        peer_ip: peer.ip(),
    };
    Some(handle(host, &ctx))
}
