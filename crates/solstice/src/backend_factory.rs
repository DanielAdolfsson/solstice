//! Configuration to a backend. This is where the feature flags land.

use std::sync::Arc;

use solstice_backend::Backend;

use crate::config::{BackendKind, Config};

/// Why a backend could not be built.
#[derive(Debug, thiserror::Error)]
pub enum FactoryError {
    /// The backend was excluded at compile time.
    #[error("backend `{0}` is not compiled into this build")]
    NotCompiledIn(&'static str),
    /// The backend exists but is not implemented.
    #[error("backend `{0}` is not implemented yet")]
    NotImplemented(&'static str),
    /// The configuration is inconsistent.
    #[error("{0}")]
    Config(String),
}

/// Build the configured backend.
pub fn build(config: &Config) -> Result<Arc<dyn Backend>, FactoryError> {
    match config.backend.kind {
        BackendKind::TestPattern => Ok(Arc::new(crate::testpattern::TestPatternBackend::new(
            config.limits.max_width,
            config.limits.max_height,
            config.limits.max_fps,
        ))),

        #[cfg(feature = "vnc")]
        BackendKind::Vnc => {
            use crate::config::VncSecurityKind;
            let vnc = &config.backend.vnc;
            let security = match vnc.security {
                VncSecurityKind::None => solstice_vnc::VncSecurity::None,
                VncSecurityKind::VncAuth => solstice_vnc::VncSecurity::VncAuth {
                    password: vnc.password.clone().ok_or_else(|| {
                        FactoryError::Config(
                            "backend.vnc.security = \"vncauth\" needs a password".into(),
                        )
                    })?,
                },
                VncSecurityKind::VeNCrypt => solstice_vnc::VncSecurity::VeNCrypt {
                    password: vnc.password.clone(),
                    ca_file: vnc.ca_file.clone(),
                },
            };
            Ok(Arc::new(solstice_vnc::VncBackend::new(
                solstice_vnc::VncConfig {
                    host: vnc.host.clone(),
                    port: vnc.port,
                    security,
                    shared: true,
                },
            )))
        }
        #[cfg(not(feature = "vnc"))]
        BackendKind::Vnc => Err(FactoryError::NotCompiledIn("vnc")),

        #[cfg(feature = "spice")]
        BackendKind::Spice => {
            use crate::config::SpiceSecurityKind;
            let spice = &config.backend.spice;
            let security = match spice.security {
                SpiceSecurityKind::Tls => solstice_spice::SpiceSecurity::Tls {
                    password: spice.password.clone(),
                    ca_file: spice.ca_file.clone(),
                },
                SpiceSecurityKind::Plain => {
                    // Refused off-loopback at dial time, where the resolved
                    // peer address is known; refusing the obvious case here
                    // turns a runtime failure into a startup one.
                    if !solstice_spice::backend::is_loopback(&spice.host) {
                        return Err(FactoryError::Config(format!(
                            "backend.spice.security = \"plain\" to {}: SPICE's ticket \
                             is a password check, not a key exchange, so the display \
                             and every keystroke would be in the clear. Use \"tls\", \
                             or tunnel it (docs/security.md §4.2)",
                            spice.host
                        )));
                    }
                    solstice_spice::SpiceSecurity::Plain {
                        password: spice.password.clone(),
                    }
                }
            };
            Ok(Arc::new(solstice_spice::SpiceBackend::new(
                solstice_spice::SpiceConfig {
                    host: spice.host.clone(),
                    port: spice.port,
                    security,
                    limits: Default::default(),
                    audio: spice.audio,
                },
            )))
        }
        #[cfg(not(feature = "spice"))]
        BackendKind::Spice => Err(FactoryError::NotCompiledIn("spice")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_test_pattern_backend_always_builds() {
        let config = Config::default();
        assert_eq!(build(&config).unwrap().name(), "testpattern");
    }

    #[cfg(not(feature = "spice"))]
    #[test]
    fn spice_says_it_was_excluded_rather_than_failing_obscurely() {
        let mut config = Config::default();
        config.backend.kind = BackendKind::Spice;
        assert!(matches!(
            build(&config),
            Err(FactoryError::NotCompiledIn("spice"))
        ));
    }

    #[cfg(feature = "spice")]
    #[test]
    fn a_tls_spice_backend_builds() {
        let mut config = Config::default();
        config.backend.kind = BackendKind::Spice;
        assert_eq!(build(&config).unwrap().name(), "spice");
    }

    #[cfg(feature = "spice")]
    #[test]
    fn plaintext_spice_to_a_remote_host_is_refused_at_startup() {
        let mut config = Config::default();
        config.backend.kind = BackendKind::Spice;
        config.backend.spice.security = crate::config::SpiceSecurityKind::Plain;
        config.backend.spice.host = "192.168.1.10".into();
        assert!(matches!(build(&config), Err(FactoryError::Config(_))));

        config.backend.spice.host = "127.0.0.1".into();
        assert!(build(&config).is_ok(), "loopback is the exception");
    }

    #[cfg(feature = "vnc")]
    #[test]
    fn vnc_auth_without_a_password_is_refused_at_startup() {
        let mut config = Config::default();
        config.backend.kind = BackendKind::Vnc;
        config.backend.vnc.security = crate::config::VncSecurityKind::VncAuth;
        config.backend.vnc.password = None;
        assert!(matches!(build(&config), Err(FactoryError::Config(_))));
    }

    #[cfg(feature = "vnc")]
    #[test]
    fn a_vencrypt_backend_builds() {
        let mut config = Config::default();
        config.backend.kind = BackendKind::Vnc;
        assert_eq!(build(&config).unwrap().name(), "vnc");
    }
}
