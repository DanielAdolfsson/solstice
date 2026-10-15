//! NVHTTP: the XML API Moonlight queries before it streams.
//!
//! Two listeners (`nvhttp.cpp:1734-1755`):
//!
//! | Endpoint | HTTP 47989 | HTTPS 47984 |
//! |---|---|---|
//! | `/serverinfo` | yes | yes |
//! | `/pair` | yes -- the real flow | `phrase=pairchallenge` only |
//! | `/applist`, `/appasset`, `/launch`, `/resume`, `/cancel` | no | yes |
//!
//! The dispatcher is a pure function of request plus context, so the policy
//! table above is testable without a socket, and the hostile-client tests in
//! `docs/testing.md` §2.5 can drive it directly.

pub mod applist;
pub mod http;
pub mod launch;
pub mod pair;
pub mod serverinfo;
pub mod session;
pub mod xml;

use std::net::IpAddr;
use std::sync::{Mutex, RwLock};

use http::{HttpRequest, HttpResponse};
use session::LaunchSession;
use xml::Root;

use crate::crypto::certs::{ClientStore, HostIdentity};
use crate::crypto::pairing::PairingManager;

/// Static configuration for the host half.
#[derive(Clone, Debug)]
pub struct HostConfig {
    /// Display name.
    pub name: String,
    /// Host UUID.
    pub uuid: String,
    /// Title of the single app offered.
    pub app_title: String,
    /// Base port; the plaintext HTTP listener.
    pub port: u16,
    /// The mutual-TLS listener, `port - 5`.
    pub https_port: u16,
    /// RTSP, `port + 21`.
    pub rtsp_port: u16,
    /// What `LocalIP` advertises. Must be IPv4.
    pub local_ip: String,
    /// What `mac` advertises over TLS.
    pub mac: String,
    /// Concurrent streaming sessions allowed.
    pub max_sessions: usize,
    /// Source addresses permitted to pair. Empty means loopback only.
    pub allow_pairing_from: Vec<ipnet::IpNet>,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            name: "solstice".into(),
            uuid: "0123456789ABCDEF0123456789ABCDEF".into(),
            app_title: "Desktop".into(),
            port: 47989,
            https_port: 47984,
            rtsp_port: 48010,
            local_ip: "127.0.0.1".into(),
            mac: "00:00:00:00:00:00".into(),
            max_sessions: 1,
            allow_pairing_from: Vec::new(),
        }
    }
}

/// Everything a request handler needs that is not in the request.
pub struct RequestContext<'a> {
    /// The request.
    pub request: &'a HttpRequest,
    /// Whether it arrived on the mutual-TLS listener.
    pub over_tls: bool,
    /// The exact DER of the client certificate, when one was presented.
    pub client_cert: Option<&'a [u8]>,
    /// Peer address, for the pairing source-address check.
    pub peer_ip: IpAddr,
}

/// The host half's shared state.
pub struct Host {
    /// Static configuration.
    pub config: HostConfig,
    /// Host key and certificate.
    pub identity: HostIdentity,
    /// Paired clients.
    pub clients: RwLock<ClientStore>,
    /// The pairing window and its in-flight handshake.
    pub pairing: Mutex<PairingManager>,
    /// Live launch sessions.
    pub sessions: Mutex<Vec<LaunchSession>>,
}

impl Host {
    /// Build one.
    pub fn new(config: HostConfig, identity: HostIdentity, clients: ClientStore) -> Self {
        Self {
            config,
            identity,
            clients: RwLock::new(clients),
            pairing: Mutex::new(PairingManager::default()),
            sessions: Mutex::new(Vec::new()),
        }
    }

    /// Whether this exact certificate is paired *right now*.
    pub fn is_paired(&self, cert_der: &[u8]) -> bool {
        self.clients
            .read()
            .expect("client store lock")
            .is_paired(cert_der)
    }

    /// The app id of the running session, or 0.
    pub fn current_app_id(&self) -> u32 {
        self.sessions
            .lock()
            .expect("session lock")
            .first()
            .map(|s| s.app_id)
            .unwrap_or(0)
    }

    /// Whether `peer` may attempt to pair.
    ///
    /// Default policy is loopback only: pairing runs over plaintext HTTP with a
    /// four-digit PIN, so a wider default would be indefensible
    /// (`docs/security.md` §1.1).
    pub fn pairing_allowed_from(&self, peer: IpAddr) -> bool {
        if self.config.allow_pairing_from.is_empty() {
            return peer.is_loopback();
        }
        peer.is_loopback()
            || self
                .config
                .allow_pairing_from
                .iter()
                .any(|net| net.contains(&peer))
    }

    /// Destroy any in-flight handshake. Called on every deviation.
    pub fn abandon_pairing(&self) {
        self.pairing.lock().expect("pairing lock").close();
    }

    /// Revoke a client and tear down its sessions, immediately.
    pub fn revoke(&self, cert_der: &[u8]) -> bool {
        let removed = self
            .clients
            .write()
            .expect("client store lock")
            .remove(cert_der)
            .unwrap_or(false);
        if removed {
            self.sessions
                .lock()
                .expect("session lock")
                .retain(|s| s.client_cert_der != cert_der);
        }
        removed
    }
}

/// Dispatch one request.
pub fn handle(host: &Host, ctx: &RequestContext) -> HttpResponse {
    if ctx.request.method != "GET" {
        return HttpResponse {
            status: 405,
            content_type: "text/plain",
            body: Vec::new(),
        };
    }

    // Everything but /serverinfo and /pair requires a paired client over TLS.
    let needs_paired_tls = !matches!(ctx.request.path.as_str(), "/serverinfo" | "/pair");
    if needs_paired_tls {
        if !ctx.over_tls {
            return xml_response(404, Root::error(404, "Not found").render());
        }
        match ctx.client_cert {
            Some(der) if host.is_paired(der) => {}
            _ => return xml_response(401, Root::error(401, "Not paired").render()),
        }
    }

    let (status, body) = match ctx.request.path.as_str() {
        "/serverinfo" => (200, serverinfo::serverinfo(host, ctx)),
        "/pair" => {
            // Over TLS, only the final probe is allowed: the handshake itself
            // belongs on the plaintext listener, and accepting it here would be
            // a second, untested path into the same state machine.
            if ctx.over_tls && ctx.request.param("phrase") != Some("pairchallenge") {
                (404, Root::error(404, "Not found").render())
            } else {
                pair::pair(host, ctx)
            }
        }
        "/applist" => (200, applist::applist(host)),
        "/appasset" => (404, Root::error(404, "No box art").render()),
        "/launch" => launch::launch(host, ctx),
        "/resume" => launch::resume(host, ctx),
        "/cancel" => launch::cancel(host, ctx),
        _ => (404, Root::error(404, "Not found").render()),
    };
    xml_response(status, body)
}

fn xml_response(status: u16, body: String) -> HttpResponse {
    HttpResponse {
        status,
        content_type: "application/xml",
        body: body.into_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn host() -> Host {
        use std::sync::OnceLock;
        static IDENTITY: OnceLock<String> = OnceLock::new();
        // Generate one key for the whole test module; HostIdentity is not Clone
        // so the PEM is what gets shared.
        let pem = IDENTITY.get_or_init(|| {
            HostIdentity::generate("solstice-test")
                .unwrap()
                .key_pem()
                .to_owned()
        });
        use rsa::pkcs8::DecodePrivateKey;
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(pem).unwrap();
        Host::new(
            HostConfig::default(),
            HostIdentity::from_key(key, "solstice-test").unwrap(),
            ClientStore::new(),
        )
    }

    fn request(target: &str) -> HttpRequest {
        let raw = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        http::parse_request(raw.as_bytes()).unwrap().unwrap().0
    }

    fn ctx<'a>(
        request: &'a HttpRequest,
        over_tls: bool,
        cert: Option<&'a [u8]>,
    ) -> RequestContext<'a> {
        RequestContext {
            request,
            over_tls,
            client_cert: cert,
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }

    fn body(response: &HttpResponse) -> String {
        String::from_utf8(response.body.clone()).unwrap()
    }

    #[test]
    fn serverinfo_is_served_on_both_listeners() {
        let h = host();
        for over_tls in [false, true] {
            let req = request("/serverinfo");
            let r = handle(&h, &ctx(&req, over_tls, None));
            assert_eq!(r.status, 200);
            let xml = body(&r);
            assert!(xml.contains("<appversion>7.1.431.-1</appversion>"));
            assert!(xml.contains("<ServerCodecModeSupport>1</ServerCodecModeSupport>"));
            assert!(xml.contains("<state>SUNSHINE_SERVER_FREE</state>"));
        }
    }

    /// The real MAC is only disclosed over mutual TLS.
    #[test]
    fn the_mac_is_withheld_on_the_plaintext_listener() {
        let mut h = host();
        h.config.mac = "aa:bb:cc:dd:ee:ff".into();
        let req = request("/serverinfo");
        assert!(body(&handle(&h, &ctx(&req, false, None))).contains("00:00:00:00:00:00"));
        assert!(body(&handle(&h, &ctx(&req, true, None))).contains("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn pair_status_reflects_the_presented_certificate() {
        let h = host();
        let der = vec![1u8, 2, 3];
        let req = request("/serverinfo");
        assert!(body(&handle(&h, &ctx(&req, true, Some(&der)))).contains("<PairStatus>0<"));

        h.clients
            .write()
            .unwrap()
            .add(crate::crypto::certs::PairedClient {
                cert_der: der.clone(),
                device_name: "d".into(),
                unique_id: "u".into(),
            })
            .unwrap();
        assert!(body(&handle(&h, &ctx(&req, true, Some(&der)))).contains("<PairStatus>1<"));
    }

    #[test]
    fn privileged_endpoints_are_absent_from_the_plaintext_listener() {
        let h = host();
        for path in ["/applist", "/launch", "/resume", "/cancel", "/appasset"] {
            let req = request(path);
            assert_eq!(handle(&h, &ctx(&req, false, None)).status, 404, "{path}");
        }
    }

    #[test]
    fn privileged_endpoints_require_a_paired_certificate() {
        let h = host();
        for path in ["/applist", "/launch", "/resume", "/cancel"] {
            let req = request(path);
            assert_eq!(
                handle(&h, &ctx(&req, true, None)).status,
                401,
                "{path} without a cert"
            );
            assert_eq!(
                handle(&h, &ctx(&req, true, Some(&[9, 9, 9]))).status,
                401,
                "{path} with an unpaired cert"
            );
        }
    }

    fn paired_host() -> (Host, Vec<u8>) {
        let h = host();
        let der = vec![0xAA, 0xBB, 0xCC];
        h.clients
            .write()
            .unwrap()
            .add(crate::crypto::certs::PairedClient {
                cert_der: der.clone(),
                device_name: "moonlight".into(),
                unique_id: "uid".into(),
            })
            .unwrap();
        (h, der)
    }

    #[test]
    fn applist_offers_exactly_one_app() {
        let (h, der) = paired_host();
        let req = request("/applist");
        let xml = body(&handle(&h, &ctx(&req, true, Some(&der))));
        assert_eq!(xml.matches("<App>").count(), 1);
        assert!(xml.contains("<AppTitle>Desktop</AppTitle>"));
        assert!(xml.contains("<ID>1</ID>"));
    }

    #[test]
    fn launch_mints_a_session_and_returns_an_encrypted_rtsp_url() {
        let (h, der) = paired_host();
        let req = request(
            "/launch?rikey=000102030405060708090a0b0c0d0e0f&rikeyid=-1234&localAudioPlayMode=0&appid=1&mode=1920x1080x60&corever=1",
        );
        let r = handle(&h, &ctx(&req, true, Some(&der)));
        assert_eq!(r.status, 200);
        let xml = body(&r);
        assert!(xml.contains("rtspenc://127.0.0.1:48010"), "{xml}");

        let sessions = h.sessions.lock().unwrap();
        assert_eq!(sessions.len(), 1);
        let s = &sessions[0];
        assert_eq!(s.rikey_id, -1234);
        assert_eq!(s.requested_mode, Some((1920, 1080, 60)));
        assert!(s.encrypted_rtsp);
        // 8 random bytes hex-encoded to 16 ASCII characters.
        assert!(s.av_ping_payload.iter().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn a_client_without_corever_gets_a_plaintext_rtsp_url() {
        let (h, der) = paired_host();
        let req = request(
            "/launch?rikey=000102030405060708090a0b0c0d0e0f&rikeyid=1&localAudioPlayMode=0&appid=1",
        );
        let xml = body(&handle(&h, &ctx(&req, true, Some(&der))));
        assert!(xml.contains("rtsp://127.0.0.1:48010"));
        assert!(!xml.contains("rtspenc://"));
    }

    #[test]
    fn launch_rejects_missing_or_malformed_parameters() {
        let (h, der) = paired_host();
        for target in [
            "/launch?rikeyid=1&localAudioPlayMode=0&appid=1",
            "/launch?rikey=00&rikeyid=1&localAudioPlayMode=0&appid=1",
            "/launch?rikey=zz&rikeyid=1&localAudioPlayMode=0&appid=1",
            "/launch?rikey=000102030405060708090a0b0c0d0e0f&localAudioPlayMode=0&appid=1",
            "/launch?rikey=000102030405060708090a0b0c0d0e0f&rikeyid=1&appid=1",
        ] {
            let req = request(target);
            assert_eq!(
                handle(&h, &ctx(&req, true, Some(&der))).status,
                400,
                "{target}"
            );
        }
        let req = request(
            "/launch?rikey=000102030405060708090a0b0c0d0e0f&rikeyid=1&localAudioPlayMode=0&appid=99",
        );
        assert_eq!(handle(&h, &ctx(&req, true, Some(&der))).status, 404);
        assert!(h.sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn a_second_session_is_refused_at_the_configured_ceiling() {
        let (h, der) = paired_host();
        let req = request(
            "/launch?rikey=000102030405060708090a0b0c0d0e0f&rikeyid=1&localAudioPlayMode=0&appid=1",
        );
        assert_eq!(handle(&h, &ctx(&req, true, Some(&der))).status, 200);
        assert_eq!(handle(&h, &ctx(&req, true, Some(&der))).status, 503);
    }

    /// Revocation takes effect now, and takes the session with it.
    #[test]
    fn revoking_a_client_tears_down_its_session() {
        let (h, der) = paired_host();
        let req = request(
            "/launch?rikey=000102030405060708090a0b0c0d0e0f&rikeyid=1&localAudioPlayMode=0&appid=1",
        );
        handle(&h, &ctx(&req, true, Some(&der)));
        assert_eq!(h.sessions.lock().unwrap().len(), 1);

        assert!(h.revoke(&der));
        assert!(h.sessions.lock().unwrap().is_empty());
        let req = request("/applist");
        assert_eq!(handle(&h, &ctx(&req, true, Some(&der))).status, 401);
    }

    #[test]
    fn resume_only_returns_a_session_belonging_to_the_same_certificate() {
        let (h, der) = paired_host();
        let other = vec![0x11, 0x22];
        h.clients
            .write()
            .unwrap()
            .add(crate::crypto::certs::PairedClient {
                cert_der: other.clone(),
                device_name: "other".into(),
                unique_id: "o".into(),
            })
            .unwrap();
        let req = request(
            "/launch?rikey=000102030405060708090a0b0c0d0e0f&rikeyid=1&localAudioPlayMode=0&appid=1",
        );
        handle(&h, &ctx(&req, true, Some(&der)));

        let req = request("/resume");
        assert_eq!(handle(&h, &ctx(&req, true, Some(&der))).status, 200);
        assert_eq!(handle(&h, &ctx(&req, true, Some(&other))).status, 404);
    }

    #[test]
    fn pairing_is_refused_when_no_window_is_open() {
        let h = host();
        let req = request(
            "/pair?phrase=getservercert&salt=00112233445566778899aabbccddeeff&clientcert=00",
        );
        let r = handle(&h, &ctx(&req, false, None));
        assert_eq!(r.status, 503);
        assert!(body(&r).contains("<paired>0</paired>"));
    }

    #[test]
    fn pairing_is_refused_from_a_disallowed_source_address() {
        let h = host();
        h.pairing
            .lock()
            .unwrap()
            .open("1234", Duration::from_secs(60), std::time::Instant::now())
            .unwrap();
        let req = request(
            "/pair?phrase=getservercert&salt=00112233445566778899aabbccddeeff&clientcert=00",
        );
        let remote = RequestContext {
            request: &req,
            over_tls: false,
            client_cert: None,
            peer_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
        };
        assert_eq!(handle(&h, &remote).status, 403);
    }

    #[test]
    fn the_handshake_is_not_reachable_over_tls() {
        let h = host();
        h.pairing
            .lock()
            .unwrap()
            .open("1234", Duration::from_secs(60), std::time::Instant::now())
            .unwrap();
        let req = request(
            "/pair?phrase=getservercert&salt=00112233445566778899aabbccddeeff&clientcert=00",
        );
        assert_eq!(handle(&h, &ctx(&req, true, None)).status, 404);
    }

    #[test]
    fn the_pairchallenge_probe_answers_over_tls() {
        let (h, der) = paired_host();
        let req = request("/pair?phrase=pairchallenge");
        assert!(body(&handle(&h, &ctx(&req, true, Some(&der)))).contains("<paired>1</paired>"));
        assert!(body(&handle(&h, &ctx(&req, true, Some(&[0u8; 4])))).contains("<paired>0</paired>"));
    }

    #[test]
    fn non_get_methods_are_refused() {
        let h = host();
        let mut req = request("/serverinfo");
        req.method = "POST".into();
        assert_eq!(handle(&h, &ctx(&req, true, None)).status, 405);
    }

    #[test]
    fn unknown_paths_are_not_found() {
        let (h, der) = paired_host();
        let req = request("/../../etc/passwd");
        assert_eq!(handle(&h, &ctx(&req, true, Some(&der))).status, 404);
    }
}
