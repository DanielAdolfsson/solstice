//! The two NVHTTP listeners.

use std::net::SocketAddr;
use std::sync::Arc;

use solstice_gamestream::nvhttp::http::{self, HttpResponse};
use solstice_gamestream::nvhttp::{handle, Host, RequestContext};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// How long a client has to send a complete request head.
const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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

    let ctx = RequestContext {
        request: &request,
        over_tls,
        client_cert: client_cert.as_deref(),
        peer_ip: peer.ip(),
    };
    let response = handle(&host, &ctx);
    tracing::debug!(%peer, path = %request.path, status = response.status, over_tls, "nvhttp");
    stream.write_all(&response.to_bytes()).await?;
    stream.flush().await?;
    Ok(())
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
