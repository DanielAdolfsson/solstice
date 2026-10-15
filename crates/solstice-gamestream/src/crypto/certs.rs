//! Host certificate, and the store of paired client certificates.
//!
//! Client identity is the **exact DER bytes** of the pinned certificate.
//! CVE-2026-32253 and GHSA-6jvv-jqr7-m6m3 were both "we compared the wrong
//! thing" -- a subject name, a fingerprint of a mutable field -- so nothing
//! here compares anything else (`docs/security.md` §3).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::{CryptoError, Result};

/// Moonlight pins whatever it saw at pairing time, so the validity window is
/// only a formality -- but an expired certificate would still break clients
/// that check it, so it is set long.
const CERT_VALIDITY_DAYS: i64 = 20 * 365;

/// The host's identity: an RSA-2048 key and a self-signed certificate.
///
/// RSA specifically, because the pairing handshake's step ③ response is an
/// `RSA-SHA256` signature over the server secret and the client verifies it
/// with the public key out of this certificate.
pub struct HostIdentity {
    key: RsaPrivateKey,
    cert_der: Vec<u8>,
    cert_pem: String,
    key_pem: String,
}

impl std::fmt::Debug for HostIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostIdentity")
            .field("cert_der_len", &self.cert_der.len())
            .finish()
    }
}

impl HostIdentity {
    /// Generate a fresh identity.
    pub fn generate(common_name: &str) -> Result<Self> {
        let mut rng = rsa::rand_core::OsRng;
        let key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| CryptoError::Key(format!("RSA keygen: {e}")))?;
        Self::from_key(key, common_name)
    }

    /// Build an identity around an existing key.
    pub fn from_key(key: RsaPrivateKey, common_name: &str) -> Result<Self> {
        let key_pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| CryptoError::Key(format!("encoding key: {e}")))?
            .to_string();

        let key_pair =
            rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(&key_pem, &rcgen::PKCS_RSA_SHA256)
                .map_err(|e| CryptoError::Key(format!("rcgen key: {e}")))?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
            .map_err(|e| CryptoError::Key(format!("rcgen params: {e}")))?;
        params.distinguished_name = {
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, common_name);
            dn
        };
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2020 + (CERT_VALIDITY_DAYS / 365) as i32, 1, 1);
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| CryptoError::Key(format!("rcgen self-sign: {e}")))?;

        Ok(Self {
            key,
            cert_der: cert.der().to_vec(),
            cert_pem: cert.pem(),
            key_pem,
        })
    }

    /// Load from PEM, or generate and write a new identity if the files are
    /// absent.
    pub fn load_or_generate(dir: &Path, common_name: &str) -> Result<Self> {
        let cert_path = dir.join("host.crt");
        let key_path = dir.join("host.key");
        if cert_path.exists() && key_path.exists() {
            let key_pem = std::fs::read_to_string(&key_path)?;
            let key = RsaPrivateKey::from_pkcs8_pem(&key_pem)
                .map_err(|e| CryptoError::Key(format!("reading {}: {e}", key_path.display())))?;
            let cert_pem = std::fs::read_to_string(&cert_path)?;
            let cert_der = pem_to_der(&cert_pem)?;
            return Ok(Self {
                key,
                cert_der,
                cert_pem,
                key_pem,
            });
        }
        let identity = Self::generate(common_name)?;
        std::fs::create_dir_all(dir)?;
        std::fs::write(&cert_path, &identity.cert_pem)?;
        write_private(&key_path, identity.key_pem.as_bytes())?;
        Ok(identity)
    }

    /// The certificate in DER form.
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The certificate in PEM form -- what `/pair` phase ① returns, hex-encoded.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The private key in PKCS#8 PEM form.
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    /// The raw signature bytes of the X.509 structure.
    ///
    /// This is Sunshine's `crypto::signature(cert)`, which the PIN handshake
    /// mixes into its hashes. It is *not* a hash of the certificate.
    pub fn signature(&self) -> Result<Vec<u8>> {
        cert_signature(&self.cert_der)
    }

    /// Sign with RSASSA-PKCS1-v1_5 over SHA-256, as step ③ requires.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signing_key = SigningKey::<Sha256>::new(self.key.clone());
        let mut rng = rsa::rand_core::OsRng;
        Ok(signing_key.sign_with_rng(&mut rng, message).to_vec())
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Extract the single DER body from a PEM document.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    let item = rustls_pemfile::read_one(&mut cursor)
        .map_err(|e| CryptoError::MalformedCert(e.to_string()))?
        .ok_or_else(|| CryptoError::MalformedCert("no PEM block".into()))?;
    match item {
        rustls_pemfile::Item::X509Certificate(der) => Ok(der.to_vec()),
        _ => Err(CryptoError::MalformedCert("not a certificate".into())),
    }
}

/// Wrap DER in a PEM certificate block.
pub fn der_to_pem(der: &[u8]) -> String {
    use std::fmt::Write;
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in der.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        let mut quad = [0u8; 4];
        for (i, q) in quad.iter_mut().enumerate() {
            *q = if i > chunk.len() {
                b'='
            } else {
                B64[((n >> (18 - 6 * i)) & 0x3F) as usize]
            };
        }
        b64.push_str(std::str::from_utf8(&quad).expect("base64 alphabet is ASCII"));
    }
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        let _ = writeln!(out, "{}", std::str::from_utf8(line).expect("ASCII"));
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// The raw signature bytes of a DER certificate.
pub fn cert_signature(der: &[u8]) -> Result<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| CryptoError::MalformedCert(e.to_string()))?;
    Ok(cert.signature_value.data.to_vec())
}

/// Verify an RSASSA-PKCS1-v1_5 SHA-256 signature using a certificate's public
/// key. Used in pairing step ④.
pub fn verify_with_cert(der: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| CryptoError::MalformedCert(e.to_string()))?;
    let spki_der = cert.public_key().raw;
    let public = RsaPublicKey::try_from(
        rsa::pkcs8::SubjectPublicKeyInfoRef::try_from(spki_der)
            .map_err(|e| CryptoError::MalformedCert(format!("SPKI: {e}")))?,
    )
    .map_err(|e| CryptoError::MalformedCert(format!("public key: {e}")))?;
    let verifying = VerifyingKey::<Sha256>::new(public);
    let Ok(sig) = Signature::try_from(signature) else {
        return Ok(false);
    };
    Ok(verifying.verify(message, &sig).is_ok())
}

/// A paired client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairedClient {
    /// Exact DER of the pinned certificate. This *is* the identity.
    pub cert_der: Vec<u8>,
    /// Display name from the pairing request. Attacker-controlled; never used
    /// for identity, only for logs and the management CLI.
    pub device_name: String,
    /// The `uniqueid` the client presented, for the same purposes.
    pub unique_id: String,
}

/// The set of clients allowed to stream.
///
/// Revocation must take effect immediately and be checked on every connection,
/// never cached (`docs/security.md` §3.4), so this is consulted per request
/// rather than snapshotted at session start.
#[derive(Debug, Default)]
pub struct ClientStore {
    path: Option<PathBuf>,
    /// Keyed by DER so that lookup is exact and duplicates are impossible.
    clients: BTreeMap<Vec<u8>, PairedClient>,
}

impl ClientStore {
    /// An in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from `path`, treating a missing file as an empty store.
    pub fn load(path: PathBuf) -> Result<Self> {
        let mut store = Self {
            path: Some(path.clone()),
            clients: BTreeMap::new(),
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Ok(store);
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.splitn(3, '\t');
            let (Some(der_hex), Some(name), Some(unique_id)) =
                (fields.next(), fields.next(), fields.next())
            else {
                return Err(CryptoError::MalformedCert("client store line".into()));
            };
            let cert_der = hex::decode(der_hex)
                .map_err(|_| CryptoError::MalformedCert("client store hex".into()))?;
            store.clients.insert(
                cert_der.clone(),
                PairedClient {
                    cert_der,
                    device_name: name.to_owned(),
                    unique_id: unique_id.to_owned(),
                },
            );
        }
        Ok(store)
    }

    /// Whether this exact certificate is paired.
    ///
    /// The comparison is over the full DER and runs in constant time with
    /// respect to the candidate, so a near-miss certificate learns nothing.
    pub fn is_paired(&self, cert_der: &[u8]) -> bool {
        self.clients
            .get(cert_der)
            .map(|c| bool::from(c.cert_der.ct_eq(cert_der)))
            .unwrap_or(false)
    }

    /// Look a client up by its exact certificate.
    pub fn get(&self, cert_der: &[u8]) -> Option<&PairedClient> {
        self.clients.get(cert_der)
    }

    /// Every paired client.
    pub fn clients(&self) -> impl Iterator<Item = &PairedClient> {
        self.clients.values()
    }

    /// Add a client and persist. Called only after pairing step ④ verifies.
    pub fn add(&mut self, client: PairedClient) -> Result<()> {
        self.clients.insert(client.cert_der.clone(), client);
        self.persist()
    }

    /// Remove a client and persist. The caller must also tear down any live
    /// session belonging to it.
    pub fn remove(&mut self, cert_der: &[u8]) -> Result<bool> {
        let removed = self.clients.remove(cert_der).is_some();
        if removed {
            self.persist()?;
        }
        Ok(removed)
    }

    /// Number of paired clients.
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    /// Whether no client is paired.
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    fn persist(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut out =
            String::from("# solstice paired clients: <cert DER hex>\\t<name>\\t<uniqueid>\n");
        for c in self.clients.values() {
            out.push_str(&format!(
                "{}\t{}\t{}\n",
                hex::encode(&c.cert_der),
                c.device_name.replace(['\t', '\n'], " "),
                c.unique_id.replace(['\t', '\n'], " ")
            ));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_private(path, out.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_identifies_by_exact_der_only() {
        let mut store = ClientStore::new();
        let der = vec![0x30, 0x82, 0x01, 0x02, 0x03];
        store
            .add(PairedClient {
                cert_der: der.clone(),
                device_name: "moonlight".into(),
                unique_id: "0123456789ABCDEF".into(),
            })
            .unwrap();
        assert!(store.is_paired(&der));

        // CVE-2026-32253 in shape: a certificate that is *similar* but not
        // byte-identical must not authenticate.
        let mut nearly = der.clone();
        *nearly.last_mut().unwrap() ^= 0x01;
        assert!(!store.is_paired(&nearly));
        assert!(!store.is_paired(&der[..der.len() - 1]));
        assert!(!store.is_paired(&[]));
    }

    #[test]
    fn revocation_is_immediate() {
        let mut store = ClientStore::new();
        let der = vec![1, 2, 3, 4];
        store
            .add(PairedClient {
                cert_der: der.clone(),
                device_name: "a".into(),
                unique_id: "b".into(),
            })
            .unwrap();
        assert!(store.remove(&der).unwrap());
        assert!(!store.is_paired(&der));
        assert!(!store.remove(&der).unwrap());
    }

    #[test]
    fn store_round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!("solstice-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("clients.tsv");
        let mut store = ClientStore::load(path.clone()).unwrap();
        assert!(store.is_empty());
        store
            .add(PairedClient {
                cert_der: vec![0xDE, 0xAD, 0xBE, 0xEF],
                device_name: "moonlight-qt".into(),
                unique_id: "FEDCBA9876543210".into(),
            })
            .unwrap();
        let reloaded = ClientStore::load(path).unwrap();
        assert_eq!(reloaded.len(), 1);
        assert!(reloaded.is_paired(&[0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(
            reloaded.get(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap().device_name,
            "moonlight-qt"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
