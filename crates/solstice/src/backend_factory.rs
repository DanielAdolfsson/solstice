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

        // SPICE is feature-gated and deferred: its image codecs -- QUIC and
        // GLZ -- have no Rust implementations, and GLZ is stateful across
        // images, so the backend needs an FFI binding to `spice-common` or a
        // port of its decoders (`docs/spice-protocol.md` §5.1).
        BackendKind::Spice => Err(FactoryError::NotImplemented("spice")),
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

    #[test]
    fn spice_reports_itself_as_unimplemented_rather_than_failing_obscurely() {
        let mut config = Config::default();
        config.backend.kind = BackendKind::Spice;
        assert!(matches!(
            build(&config),
            Err(FactoryError::NotImplemented("spice"))
        ));
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
