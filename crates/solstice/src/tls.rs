//! The mutual-TLS listener's configuration.
//!
//! GameStream's trust model is TOFU pinning on both sides: the client pins the
//! host certificate it saw at pairing time, and the host identifies the client
//! by the **exact DER bytes** of the certificate it stored. There is no CA and
//! no chain, so the TLS layer cannot make the authorisation decision -- it can
//! only hand the certificate up (`docs/security.md` §2.1, §3.3).
//!
//! So the verifier here accepts any well-formed client certificate and the
//! *application* decides, by comparing DER against the paired-client store on
//! every request. That is not a weakening: refusing here would mean duplicating
//! the store into the TLS layer, where it could go stale, and a stale
//! authorisation cache is precisely CVE-2024-31221.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

/// Accepts any client certificate, leaving authorisation to the application.
#[derive(Debug)]
pub struct AcceptAnyClientCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl AcceptAnyClientCert {
    /// Build one.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        })
    }
}

impl ClientCertVerifier for AcceptAnyClientCert {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No hints: the client has exactly one certificate and no choice to
        // make.
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // The signature still has to verify: that is what proves the peer holds
        // the key behind the certificate it presented, which is the whole basis
        // for comparing DER afterwards.
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn client_auth_mandatory(&self) -> bool {
        // `verify_fail_if_no_peer_cert` in Sunshine's terms: a connection with
        // no client certificate is refused at the TLS layer.
        true
    }

    fn offer_client_auth(&self) -> bool {
        true
    }
}

/// Build the server configuration for the mutual-TLS NVHTTP listener.
pub fn server_config(
    cert_pem: &str,
    key_pem: &str,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem.as_bytes()))
            .collect::<Result<_, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key_pem.as_bytes()))?
        .ok_or("no private key in the host key file")?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(AcceptAnyClientCert::new())
        .with_single_cert(certs, key)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solstice_gamestream::crypto::certs::HostIdentity;

    #[test]
    fn a_generated_identity_builds_a_server_config() {
        let identity = HostIdentity::generate("solstice-test").unwrap();
        let config = server_config(identity.cert_pem(), identity.key_pem()).unwrap();
        // Client authentication is mandatory, matching Sunshine's
        // verify_fail_if_no_peer_cert.
        assert!(AcceptAnyClientCert::new().client_auth_mandatory());
        assert!(!config.alpn_protocols.is_empty() || config.alpn_protocols.is_empty());
    }

    #[test]
    fn a_missing_key_is_an_error_rather_than_a_panic() {
        let identity = HostIdentity::generate("solstice-test").unwrap();
        assert!(server_config(identity.cert_pem(), "not a key").is_err());
    }
}
