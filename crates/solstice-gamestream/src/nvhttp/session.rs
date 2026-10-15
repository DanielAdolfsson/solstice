//! Launch sessions: what `/launch` mints and the media channels consume.

use std::time::Instant;

use zeroize::Zeroizing;

/// Length of the hex-encoded ping payload the client echoes on the UDP ports.
pub const PING_PAYLOAD_LEN: usize = 16;

/// One streaming session.
pub struct LaunchSession {
    /// Opaque id, also used as the RTSP `Session:` attribute.
    pub id: String,
    /// Exact DER of the client certificate that launched it. Revocation checks
    /// compare against this.
    pub client_cert_der: Vec<u8>,
    /// The AES-128 session key the client supplied as `rikey`.
    pub rikey: Zeroizing<[u8; 16]>,
    /// `rikeyid`, signed, which seeds the audio CBC IV.
    pub rikey_id: i32,
    /// 16 ASCII hex characters. A client proves where to send video and audio
    /// by echoing this; it is a 64-bit secret delivered over HTTPS, and the
    /// legacy address-only path is not implemented.
    pub av_ping_payload: [u8; PING_PAYLOAD_LEN],
    /// The u32 the client passes as ENet connect data.
    pub control_connect_data: u32,
    /// App the client asked for.
    pub app_id: u32,
    /// Requested geometry from the launch query string, before ANNOUNCE
    /// refines it.
    pub requested_mode: Option<(u32, u32, u32)>,
    /// Whether the client supports encrypted RTSP (`corever >= 1`).
    pub encrypted_rtsp: bool,
    /// When it started.
    pub started: Instant,
}

impl std::fmt::Debug for LaunchSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaunchSession")
            .field("id", &self.id)
            .field("app_id", &self.app_id)
            .field("encrypted_rtsp", &self.encrypted_rtsp)
            .finish_non_exhaustive()
    }
}

impl LaunchSession {
    /// Whether a ping payload matches this session's.
    ///
    /// Constant-time, because a timing oracle here would let an on-path
    /// observer find the payload byte by byte and have the stream delivered to
    /// them instead (`docs/security.md` §2.3).
    pub fn ping_matches(&self, payload: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        payload.len() == PING_PAYLOAD_LEN && bool::from(self.av_ping_payload.ct_eq(payload))
    }

    /// Parse the `mode=WxHxFPS` query parameter.
    pub fn parse_mode(mode: &str) -> Option<(u32, u32, u32)> {
        let mut parts = mode.split('x');
        let w = parts.next()?.parse().ok()?;
        let h = parts.next()?.parse().ok()?;
        let fps = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some((w, h, fps))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> LaunchSession {
        LaunchSession {
            id: "A".into(),
            client_cert_der: vec![1, 2, 3],
            rikey: Zeroizing::new([0; 16]),
            rikey_id: 0,
            av_ping_payload: *b"0123456789abcdef",
            control_connect_data: 7,
            app_id: 1,
            requested_mode: None,
            encrypted_rtsp: true,
            started: Instant::now(),
        }
    }

    #[test]
    fn ping_matching_is_exact() {
        let s = session();
        assert!(s.ping_matches(b"0123456789abcdef"));
        assert!(!s.ping_matches(b"0123456789abcdee"));
        assert!(!s.ping_matches(b"0123456789abcde"));
        assert!(!s.ping_matches(b""));
        assert!(!s.ping_matches(b"0123456789abcdef0"));
    }

    #[test]
    fn mode_parsing() {
        assert_eq!(
            LaunchSession::parse_mode("1920x1080x60"),
            Some((1920, 1080, 60))
        );
        assert_eq!(
            LaunchSession::parse_mode("1280x720x120"),
            Some((1280, 720, 120))
        );
        assert_eq!(LaunchSession::parse_mode("1920x1080"), None);
        assert_eq!(LaunchSession::parse_mode("axbxc"), None);
        assert_eq!(LaunchSession::parse_mode(""), None);
        assert_eq!(LaunchSession::parse_mode("1x2x3x4"), None);
    }
}
