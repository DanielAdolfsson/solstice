//! Configuration.
//!
//! The defaults are the deployment `docs/security.md` recommends: bound to
//! loopback, pairing closed, encryption mandatory, one session, and ceilings on
//! everything the client can ask for.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

/// The whole configuration file.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct Config {
    /// Listener and identity.
    pub server: Server,
    /// Security policy.
    pub security: Security,
    /// Resource ceilings.
    pub limits: Limits,
    /// Encoder settings.
    pub video: Video,
    /// Audio settings.
    pub audio: Audio,
    /// Which remote desktop to bridge.
    pub backend: Backend,
}

/// Listener and identity.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    /// Display name shown in Moonlight.
    pub name: String,
    /// Address to bind. **Not** `0.0.0.0` by default, and for good reason.
    pub bind: IpAddr,
    /// Base port; every other port is a fixed offset from it.
    pub port: u16,
    /// Where keys, certificates and the paired-client list live.
    pub state_dir: PathBuf,
    /// Title of the single app offered.
    pub app_title: String,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            name: "solstice".into(),
            // docs/security.md: put the listener on a private interface and
            // reach it over WireGuard or Tailscale.
            bind: "127.0.0.1".parse().expect("a literal address"),
            port: 47989,
            state_dir: PathBuf::from("/var/lib/solstice"),
            app_title: "Desktop".into(),
        }
    }
}

impl Server {
    /// The management socket `solstice pair` and friends talk to.
    pub fn control_socket(&self) -> PathBuf {
        self.state_dir.join("control.sock")
    }
    /// The mutual-TLS NVHTTP port, `port - 5`.
    pub fn https_port(&self) -> u16 {
        self.port.wrapping_sub(5)
    }
    /// UDP video, `port + 9`.
    pub fn video_port(&self) -> u16 {
        self.port.wrapping_add(9)
    }
    /// UDP control, `port + 10`.
    pub fn control_port(&self) -> u16 {
        self.port.wrapping_add(10)
    }
    /// UDP audio, `port + 11`.
    pub fn audio_port(&self) -> u16 {
        self.port.wrapping_add(11)
    }
    /// RTSP, `port + 21`.
    pub fn rtsp_port(&self) -> u16 {
        self.port.wrapping_add(21)
    }
}

/// Security policy.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Security {
    /// Require `SS_ENC_VIDEO | SS_ENC_AUDIO` as well as control encryption, and
    /// refuse clients that will not negotiate them.
    ///
    /// Sunshine's default is the opposite -- never on a LAN, opportunistic on a
    /// WAN -- but the content of this stream is someone's screen rather than a
    /// game (`docs/security.md` §2.2).
    pub require_encryption: bool,
    /// The old `pairing_enabled`, which never did anything: the window
    /// `solstice pair` opens is the only switch. Still accepted, so that a
    /// configuration copied from an older example keeps loading, and warned
    /// about when present.
    #[serde(rename = "pairing_enabled")]
    #[doc(hidden)]
    pub legacy_pairing_enabled: Option<bool>,
    /// How long `solstice pair` holds the window open.
    #[serde(with = "humantime_serde")]
    pub pairing_window: Duration,
    /// Failed handshakes before pairing locks out until a human re-enables it.
    pub max_pair_attempts: u32,
    /// Source networks allowed to pair. Empty means loopback only.
    pub allow_pairing_from: Vec<ipnet::IpNet>,
}

impl Default for Security {
    fn default() -> Self {
        Self {
            require_encryption: true,
            legacy_pairing_enabled: None,
            // The PIN is four digits and client-chosen, so the window and the
            // lockout are the real control.
            pairing_window: Duration::from_secs(60),
            max_pair_attempts: 3,
            allow_pairing_from: Vec::new(),
        }
    }
}

/// Resource ceilings.
///
/// One authenticated client becomes a full decode/encode pipeline, so a client
/// that asks for 4K120 could otherwise pin a CPU (`docs/security.md` §5.3).
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Concurrent streaming sessions.
    pub max_sessions: usize,
    /// Maximum width.
    pub max_width: u32,
    /// Maximum height.
    pub max_height: u32,
    /// Maximum framerate.
    pub max_fps: u32,
    /// Maximum bitrate.
    pub max_bitrate_kbps: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sessions: 1,
            max_width: 1920,
            max_height: 1080,
            max_fps: 60,
            max_bitrate_kbps: 20_000,
        }
    }
}

/// Encoder settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Video {
    /// Which encoder to use.
    pub encoder: Encoder,
    /// FEC percentage. `0` is legal and useful for bisecting the packetiser,
    /// but is not the shipping configuration.
    pub fec_percentage: u32,
    /// The keep-alive rate once the screen has been still for half a second.
    /// An unchanged frame costs the encoder nearly as much as a changed one,
    /// so this is most of an idle session's CPU (`docs/roadmap.md` §6). At or
    /// above the stream's rate, the stream stays fixed-rate.
    pub idle_fps: u32,
}

impl Default for Video {
    fn default() -> Self {
        Self {
            encoder: Encoder::OpenH264,
            fec_percentage: 20,
            idle_fps: 5,
        }
    }
}

/// Which encoder implementation to use.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Encoder {
    /// OpenH264: BSD-2, software, the default.
    OpenH264,
    /// A deterministic non-encoder, for testing the plumbing.
    Null,
}

/// Audio settings.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Audio {
    /// Whether to send anything at all. The RFB backend has no audio, so this
    /// sends Opus silence to keep the client out of its missing-stream paths.
    pub enabled: bool,
}

impl Default for Audio {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Which remote desktop to bridge.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Backend {
    /// `vnc`, `spice` or `testpattern`.
    pub kind: BackendKind,
    /// RFB settings.
    pub vnc: Vnc,
    /// SPICE settings.
    pub spice: Spice,
}

impl Default for Backend {
    fn default() -> Self {
        Self {
            kind: BackendKind::TestPattern,
            vnc: Vnc::default(),
            spice: Spice::default(),
        }
    }
}

/// Backend selection.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    /// RFB.
    Vnc,
    /// SPICE: QEMU/KVM's console protocol. Needs the `spice` feature.
    Spice,
    /// The built-in colour bars, for bringing the host half up on its own.
    TestPattern,
}

/// RFB backend settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Vnc {
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Security type: `none`, `vncauth` or `vencrypt`.
    pub security: VncSecurityKind,
    /// Password, for `vncauth` and the `X509Vnc` VeNCrypt sub-type.
    pub password: Option<String>,
    /// PEM file of certificates to trust for VeNCrypt.
    pub ca_file: Option<PathBuf>,
}

impl Default for Vnc {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 5900,
            // Refuse `none` and `vncauth` off-loopback is enforced in the
            // backend; the default here is the sound one.
            security: VncSecurityKind::VeNCrypt,
            password: None,
            ca_file: None,
        }
    }
}

/// SPICE backend settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Spice {
    /// Host.
    pub host: String,
    /// Port. The TLS port when `security = "tls"`, the plain one otherwise;
    /// SPICE configures the two independently and there is no convention for
    /// the TLS one, so it has to be set explicitly.
    pub port: u16,
    /// `tls` or `plain`. `plain` is refused off-loopback
    /// (`docs/security.md` §4.2).
    pub security: SpiceSecurityKind,
    /// The ticket password, where the server has ticketing enabled.
    pub password: Option<String>,
    /// PEM file of certificates to trust for TLS.
    pub ca_file: Option<PathBuf>,
    /// Whether to open the playback channel. SPICE's audio is Opus, which is
    /// also what GameStream carries.
    pub audio: bool,
}

impl Default for Spice {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 5900,
            // The sound default, for the same reason VeNCrypt is the RFB
            // one: the ticket authenticates and protects nothing.
            security: SpiceSecurityKind::Tls,
            password: None,
            ca_file: None,
            audio: true,
        }
    }
}

/// How a SPICE connection is protected.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SpiceSecurityKind {
    /// TLS with x509 server certificates, verified.
    Tls,
    /// Plaintext. Loopback only.
    Plain,
}

/// RFB security type.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VncSecurityKind {
    /// No authentication. Loopback only.
    None,
    /// DES challenge-response. Loopback only.
    VncAuth,
    /// TLS with x509 server certificates.
    VeNCrypt,
}

impl Config {
    /// Load from a TOML file.
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(path.display().to_string(), e))?;
        Self::parse(&text)
    }

    /// Parse TOML.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text).map_err(|e| ConfigError::Toml(e.to_string()))?;
        config.validate()?;
        if config.security.legacy_pairing_enabled.is_some() {
            tracing::warn!(
                "security.pairing_enabled is ignored and can be removed: \
                 pairing opens only with `solstice pair`"
            );
        }
        Ok(config)
    }

    /// Reject configurations that cannot work, or that are dangerous enough to
    /// be worth refusing rather than warning about.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.limits.max_sessions == 0 {
            return Err(ConfigError::Invalid(
                "limits.max_sessions must be at least 1".into(),
            ));
        }
        if self.limits.max_fps == 0 || self.limits.max_width == 0 || self.limits.max_height == 0 {
            return Err(ConfigError::Invalid("limits must be non-zero".into()));
        }
        if self.video.idle_fps == 0 {
            return Err(ConfigError::Invalid(
                "video.idle_fps must be at least 1: a stream that goes silent looks dead".into(),
            ));
        }
        if self.video.fec_percentage > 200 {
            return Err(ConfigError::Invalid(
                "video.fec_percentage above 200".into(),
            ));
        }
        if self.server.port < 6 {
            return Err(ConfigError::Invalid(
                "server.port must be at least 6".into(),
            ));
        }
        // The weak RFB security types are refused off-loopback by the backend
        // itself, but catching it here turns a runtime failure into a startup
        // one (`docs/security.md` §4.1).
        if self.backend.kind == BackendKind::Vnc
            && matches!(
                self.backend.vnc.security,
                VncSecurityKind::None | VncSecurityKind::VncAuth
            )
            && !is_loopback_host(&self.backend.vnc.host)
        {
            return Err(ConfigError::Invalid(format!(
                "backend.vnc.security = \"{:?}\" is refused against {}; \
                 use vencrypt or an SSH tunnel to loopback",
                self.backend.vnc.security, self.backend.vnc.host
            )));
        }
        // Same rule, same reason, for SPICE: its ticket is a password check
        // and not a key exchange, so a plaintext channel carries the display
        // and every keystroke in the clear (`docs/security.md` §4.2).
        if self.backend.kind == BackendKind::Spice
            && self.backend.spice.security == SpiceSecurityKind::Plain
            && !is_loopback_host(&self.backend.spice.host)
        {
            return Err(ConfigError::Invalid(format!(
                "backend.spice.security = \"plain\" is refused against {}; \
                 use tls or a tunnel to loopback",
                self.backend.spice.host
            )));
        }
        Ok(())
    }
}

fn is_loopback_host(host: &str) -> bool {
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(host == "localhost")
}

/// Why a configuration was rejected.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("reading {0}: {1}")]
    Io(String, #[source] std::io::Error),
    /// It was not valid TOML, or had unknown keys.
    #[error("parsing config: {0}")]
    Toml(String),
    /// It parsed but cannot be used.
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_the_recommended_deployment() {
        let config = Config::default();
        assert!(
            config.server.bind.is_loopback(),
            "the default bind must not be 0.0.0.0"
        );
        assert!(config.security.require_encryption);
        assert_eq!(config.limits.max_sessions, 1);
        assert!(config.security.allow_pairing_from.is_empty());
        config.validate().unwrap();
    }

    #[test]
    fn ports_are_the_documented_offsets() {
        let s = Server::default();
        assert_eq!(s.port, 47989);
        assert_eq!(s.https_port(), 47984);
        assert_eq!(s.video_port(), 47998);
        assert_eq!(s.control_port(), 47999);
        assert_eq!(s.audio_port(), 48000);
        assert_eq!(s.rtsp_port(), 48010);
    }

    /// A configuration from before the key was retired still loads.
    #[test]
    fn the_retired_pairing_enabled_key_is_accepted_and_ignored() {
        let config = Config::parse("[security]\npairing_enabled = true\n").unwrap();
        assert_eq!(config.security.legacy_pairing_enabled, Some(true));
        assert_eq!(Config::default().security.legacy_pairing_enabled, None);
    }

    #[test]
    fn the_example_config_parses() {
        let text = include_str!("../../../contrib/solstice.example.toml");
        let config = Config::parse(text).expect("the shipped example must parse");
        assert_eq!(config.server.port, 47989);
    }

    #[test]
    fn plaintext_spice_is_refused_against_a_remote_host() {
        let text = r#"
[backend]
kind = "spice"

[backend.spice]
host = "192.168.1.10"
security = "plain"
"#;
        assert!(matches!(Config::parse(text), Err(ConfigError::Invalid(_))));

        let text = r#"
[backend]
kind = "spice"

[backend.spice]
host = "127.0.0.1"
security = "plain"
"#;
        assert!(Config::parse(text).is_ok(), "loopback is the exception");
    }

    #[test]
    fn unknown_keys_are_refused_rather_than_ignored() {
        let err = Config::parse("[server]\nnmae = \"typo\"\n").unwrap_err();
        assert!(matches!(err, ConfigError::Toml(_)));
    }

    #[test]
    fn weak_vnc_security_is_refused_against_a_remote_host() {
        let text = r#"
[backend]
kind = "vnc"
[backend.vnc]
host = "192.168.1.10"
security = "vncauth"
password = "hunter2"
"#;
        assert!(matches!(Config::parse(text), Err(ConfigError::Invalid(_))));

        let loopback = text.replace("192.168.1.10", "127.0.0.1");
        assert!(Config::parse(&loopback).is_ok());
    }

    #[test]
    fn absurd_limits_are_refused() {
        assert!(Config::parse("[limits]\nmax_sessions = 0\n").is_err());
        assert!(Config::parse("[limits]\nmax_fps = 0\n").is_err());
        assert!(Config::parse("[video]\nidle_fps = 0\n").is_err());
        assert!(Config::parse("[video]\nfec_percentage = 500\n").is_err());
    }

    #[test]
    fn durations_are_human_readable() {
        let config = Config::parse("[security]\npairing_window = \"90s\"\n").unwrap();
        assert_eq!(config.security.pairing_window, Duration::from_secs(90));
    }
}
