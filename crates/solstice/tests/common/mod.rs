//! What every Moonlight-shaped client in this suite needs before it can
//! stream: the two HTTP listeners, the four-phase PIN handshake, and a daemon
//! started with a pairing window already open.
//!
//! Shared rather than copied because both integration tests drive the same
//! host through the same door -- `end_to_end.rs` with a client written here,
//! and `real_moonlight.rs` with the reference client. A second copy of the
//! pairing sequence is a second place for it to drift.
#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use solstice::config::Config;
use solstice::supervisor::{build_host, Supervisor};
use solstice_backend::Backend;
use solstice_gamestream::crypto::certs::{ClientStore, HostIdentity};
use solstice_gamestream::crypto::pairing::client::ClientPairing;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const PIN: &str = "4242";

/// Base ports well away from the defaults, so a developer running a real
/// Sunshine or Solstice does not collide with the test. One per test, because
/// the suite runs them concurrently.
#[derive(Clone, Copy)]
pub struct Ports {
    pub http: u16,
    pub https: u16,
    pub video: u16,
    pub audio: u16,
    pub rtsp: u16,
}

impl Ports {
    pub const fn from_base(base: u16) -> Self {
        Self {
            http: base,
            https: base - 5,
            video: base + 9,
            audio: base + 11,
            rtsp: base + 21,
        }
    }
}

// ----------------------------------------------------------------- client --

/// Moonlight pins the certificate it saw at pairing time; there is no CA and no
/// chain. The test client does the same thing, which means accepting whatever
/// the host presents on the first connection.
#[derive(Debug)]
pub struct PinnedServerCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for PinnedServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub async fn http_get(port: u16, target: &str) -> String {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let request = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

pub async fn https_get(client: &HttpsClient, ports: Ports, target: &str) -> String {
    let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, ports.https))
        .await
        .unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = client.connector.connect(name, stream).await.unwrap();
    let request = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let _ = tls.read_to_end(&mut response).await;
    String::from_utf8_lossy(&response).into_owned()
}

pub struct HttpsClient {
    pub connector: tokio_rustls::TlsConnector,
}

pub fn https_client(identity: &HostIdentity) -> HttpsClient {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certs = vec![rustls::pki_types::CertificateDer::from(
        identity.cert_der().to_vec(),
    )];
    let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(identity.key_pem().as_bytes()))
        .unwrap()
        .unwrap();
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerCert(provider)))
        .with_client_auth_cert(certs, key)
        .unwrap();
    HttpsClient {
        connector: tokio_rustls::TlsConnector::from(Arc::new(config)),
    }
}

pub fn xml_field<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(&xml[start..end])
}

// ---------------------------------------------------------------- pairing --

pub async fn pair(ports: Ports, client_identity: &HostIdentity) {
    let salt = [0x5Au8; 16];
    let client_cert_pem = client_identity.cert_pem();

    let response = http_get(
        ports.http,
        &format!(
            "/pair?devicename=test&updateState=1&phrase=getservercert&salt={}&clientcert={}",
            hex::encode(salt),
            hex::encode(client_cert_pem.as_bytes())
        ),
    )
    .await;
    assert!(
        response.contains("<paired>1</paired>"),
        "step 1 failed: {response}"
    );
    let plaincert = xml_field(&response, "plaincert").expect("no plaincert");
    let host_cert_pem = String::from_utf8(hex::decode(plaincert).unwrap()).unwrap();
    let host_cert_der = solstice_gamestream::crypto::certs::pem_to_der(&host_cert_pem).unwrap();

    let mut pairing = ClientPairing::new(&salt, PIN);
    let challenge = pairing.client_challenge().unwrap();
    let response = http_get(
        ports.http,
        &format!("/pair?clientchallenge={}", hex::encode(&challenge)),
    )
    .await;
    let challenge_response = xml_field(&response, "challengeresponse")
        .unwrap_or_else(|| panic!("step 2 failed: {response}"));

    let step3 = pairing
        .server_challenge_response(
            &hex::decode(challenge_response).unwrap(),
            &host_cert_der,
            &client_identity.signature().unwrap(),
        )
        .unwrap();
    let response = http_get(
        ports.http,
        &format!("/pair?serverchallengeresp={}", hex::encode(&step3)),
    )
    .await;
    assert!(
        response.contains("<pairingsecret>"),
        "step 3 failed: {response}"
    );

    let body = pairing
        .client_pairing_secret(|m| client_identity.sign(m))
        .unwrap();
    let response = http_get(
        ports.http,
        &format!("/pair?clientpairingsecret={}", hex::encode(&body)),
    )
    .await;
    assert!(
        response.contains("<paired>1</paired>"),
        "step 4 failed: {response}"
    );
}

/// Start a daemon with a pairing window already open.
pub fn start_daemon(
    config: Config,
    tag: &str,
) -> (Arc<solstice_gamestream::nvhttp::Host>, std::path::PathBuf) {
    let backend = solstice::backend_factory::build(&config).unwrap();
    start_daemon_with(config, tag, backend)
}

/// The same, with a backend the caller already holds a handle to.
///
/// `backend_factory::build` hands back an `Arc<dyn Backend>` and nothing else,
/// which is all the daemon needs and one thing short of what a test needs: no
/// way to ask the backend afterwards what the client sent it.
pub fn start_daemon_with(
    config: Config,
    tag: &str,
    backend: Arc<dyn Backend>,
) -> (Arc<solstice_gamestream::nvhttp::Host>, std::path::PathBuf) {
    let (host, state_dir) = start_daemon_closed(config, tag, backend);
    // Opened directly rather than through `solstice pair`, so that a streaming
    // test does not also depend on the management socket; `management.rs`
    // drives that with the real binary.
    host.pairing
        .lock()
        .unwrap()
        .open(PIN, Duration::from_secs(120), std::time::Instant::now())
        .unwrap();
    (host, state_dir)
}

/// Start a daemon with pairing closed, as a real one starts.
pub fn start_daemon_closed(
    config: Config,
    tag: &str,
    backend: Arc<dyn Backend>,
) -> (Arc<solstice_gamestream::nvhttp::Host>, std::path::PathBuf) {
    let state_dir = std::env::temp_dir().join(format!("solstice-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state_dir);
    let mut config = config;
    config.server.state_dir = state_dir.clone();

    let identity = HostIdentity::load_or_generate(&state_dir, "solstice-e2e").unwrap();
    let clients = ClientStore::load(state_dir.join("clients.tsv")).unwrap();
    let host = Arc::new(build_host(&config, identity, clients));

    let supervisor = Supervisor::new(config, host.clone(), backend);
    tokio::spawn(async move {
        if let Err(e) = supervisor.run().await {
            eprintln!("supervisor ended: {e}");
        }
    });
    (host, state_dir)
}
