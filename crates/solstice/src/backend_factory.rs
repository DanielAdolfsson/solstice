//! Endpoints to backends. This is where the feature flags land.

use std::sync::Arc;

use solstice_backend::Backend;

use crate::config::Limits;
use crate::endpoint::{Endpoint, Endpoints, Entry, Target};

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

/// Build every endpoint's backend. Nothing is dialled: a backend connects
/// when a stream starts.
pub fn build_all(endpoints: &[Endpoint], limits: &Limits) -> Result<Endpoints, FactoryError> {
    let entries = endpoints
        .iter()
        .map(|endpoint| {
            let backend = build(endpoint, limits)
                .map_err(|e| FactoryError::Config(format!("endpoint `{}`: {e}", endpoint.name)))?;
            Ok(Entry {
                id: endpoint.id,
                name: endpoint.name.clone(),
                detail: endpoint.target.describe(),
                backend,
            })
        })
        .collect::<Result<Vec<_>, FactoryError>>()?;
    Endpoints::new(entries).map_err(FactoryError::Config)
}

/// Build one endpoint's backend.
pub fn build(endpoint: &Endpoint, limits: &Limits) -> Result<Arc<dyn Backend>, FactoryError> {
    match &endpoint.target {
        Target::TestPattern => Ok(Arc::new(crate::testpattern::TestPatternBackend::new(
            limits.max_width,
            limits.max_height,
            limits.max_fps,
        ))),

        #[cfg(feature = "vnc")]
        Target::Vnc(vnc) => {
            use crate::config::VncSecurityKind;
            let security = match vnc.security {
                VncSecurityKind::None => solstice_vnc::VncSecurity::None,
                VncSecurityKind::VncAuth => solstice_vnc::VncSecurity::VncAuth {
                    password: vnc.password.clone().ok_or_else(|| {
                        FactoryError::Config("security = \"vncauth\" needs a password".into())
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
        Target::Vnc(_) => Err(FactoryError::NotCompiledIn("vnc")),

        #[cfg(feature = "spice")]
        Target::Spice(spice) => {
            use crate::config::SpiceSecurityKind;
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
                            "security = \"plain\" to {}: SPICE's ticket \
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
                    // The operator configured QEMU's `image-compression=`;
                    // a preference from here would silently replace it.
                    preferred_compression: None,
                    video_streams: spice.video_streams,
                },
            )))
        }
        #[cfg(not(feature = "spice"))]
        Target::Spice(_) => Err(FactoryError::NotCompiledIn("spice")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BackendKind, Config};
    use crate::endpoint::Spec;

    fn one(spec: Spec) -> Result<Arc<dyn Backend>, FactoryError> {
        build(&spec.resolve().unwrap(), &Config::default().limits)
    }

    #[test]
    fn the_test_pattern_backend_always_builds() {
        let backend = one(Spec::new("Bars", BackendKind::TestPattern)).unwrap();
        assert_eq!(backend.name(), "testpattern");
    }

    #[test]
    fn no_endpoints_build_to_an_empty_set() {
        let endpoints = build_all(&[], &Config::default().limits).unwrap();
        assert!(endpoints.is_empty());
        assert!(endpoints.apps().is_empty());
    }

    #[test]
    fn every_endpoint_is_built_under_its_own_app_id() {
        let config = Config::parse(
            r#"
[[endpoint]]
name = "One"
kind = "testpattern"

[[endpoint]]
name = "Two"
kind = "testpattern"
"#,
        )
        .unwrap();
        let endpoints = build_all(&config.endpoints(&[]).unwrap(), &config.limits).unwrap();
        let apps = endpoints.apps();
        assert_eq!(
            apps.iter().map(|a| a.title.as_str()).collect::<Vec<_>>(),
            ["One", "Two"]
        );
        assert_eq!(apps[1].id, crate::endpoint::app_id("Two"));
        assert_eq!(endpoints.get(apps[1].id).unwrap().name, "Two");
        assert!(endpoints.get(1).is_none(), "1 is the old [backend] only");
    }

    #[cfg(not(feature = "spice"))]
    #[test]
    fn spice_says_it_was_excluded_rather_than_failing_obscurely() {
        assert!(matches!(
            one(Spec::new("S", BackendKind::Spice)),
            Err(FactoryError::NotCompiledIn("spice"))
        ));
    }

    #[cfg(feature = "spice")]
    #[test]
    fn a_tls_spice_backend_builds() {
        assert_eq!(
            one(Spec::new("S", BackendKind::Spice)).unwrap().name(),
            "spice"
        );
    }

    /// The factory refuses on its own as well, for an endpoint that reached
    /// it without going through `Spec::resolve`.
    #[cfg(feature = "spice")]
    #[test]
    fn plaintext_spice_to_a_remote_host_is_refused() {
        let mut spice = crate::config::Spice {
            security: crate::config::SpiceSecurityKind::Plain,
            host: "192.168.1.10".into(),
            ..Default::default()
        };
        let endpoint = Endpoint {
            id: 2,
            name: "S".into(),
            target: Target::Spice(spice.clone()),
        };
        let limits = Config::default().limits;
        assert!(matches!(
            build(&endpoint, &limits),
            Err(FactoryError::Config(_))
        ));

        spice.host = "127.0.0.1".into();
        let endpoint = Endpoint {
            target: Target::Spice(spice),
            ..endpoint
        };
        assert!(
            build(&endpoint, &limits).is_ok(),
            "loopback is the exception"
        );
    }

    #[cfg(feature = "vnc")]
    #[test]
    fn vnc_auth_without_a_password_is_refused() {
        let vnc = crate::config::Vnc {
            security: crate::config::VncSecurityKind::VncAuth,
            ..Default::default()
        };
        let endpoint = Endpoint {
            id: 2,
            name: "V".into(),
            target: Target::Vnc(vnc),
        };
        assert!(matches!(
            build(&endpoint, &Config::default().limits),
            Err(FactoryError::Config(_))
        ));
    }

    #[cfg(feature = "vnc")]
    #[test]
    fn a_vencrypt_backend_builds() {
        assert_eq!(one(Spec::new("V", BackendKind::Vnc)).unwrap().name(), "vnc");
    }
}
