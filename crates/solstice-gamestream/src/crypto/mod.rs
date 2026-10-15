//! Key material, the PIN handshake, and the three symmetric constructions the
//! protocol uses.

pub mod certs;
pub mod gcm;
pub mod pairing;

/// Anything that can go wrong with keys, certificates or the PIN handshake.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The certificate store or key file could not be read or written.
    #[error("certificate I/O: {0}")]
    Io(#[from] std::io::Error),
    /// A PEM or DER structure did not parse.
    #[error("malformed certificate: {0}")]
    MalformedCert(String),
    /// Key generation or signing failed.
    #[error("key operation failed: {0}")]
    Key(String),
    /// A ciphertext was not a whole number of AES blocks, or was empty.
    #[error("bad ciphertext length {0}")]
    BadCiphertextLength(usize),
    /// A GCM tag did not verify.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// The handshake was driven out of order, or a value did not verify.
    #[error("pairing: {0}")]
    Pairing(&'static str),
}

/// Shorthand.
pub type Result<T> = std::result::Result<T, CryptoError>;
