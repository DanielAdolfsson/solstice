//! The three symmetric constructions, each with its own IV discipline.
//!
//! | Where | Cipher | IV |
//! |---|---|---|
//! | Pairing | AES-128-**ECB**, no padding | none -- see below |
//! | Control, RTSP, video | AES-128-GCM | deterministic, NIST SP 800-38D §8.2.1 |
//! | Audio | AES-128-CBC, PKCS#7 | `BE32(rikeyid + seq)` in bytes 0..4 |
//!
//! ECB is the wrong mode for the pairing handshake -- identical plaintext
//! blocks give identical ciphertext, which leaks structure in the fixed-layout
//! `hash || challenge` messages (`docs/security.md` §1.1). It is used anyway
//! because the protocol specifies it and the client will not accept anything
//! else.
//!
//! The deterministic GCM constructions are **only safe while the key is unique
//! per session**. `rikey` is fresh per `/launch`; a counter must never wrap and
//! a key must never be reused across sessions.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Tag};
use zeroize::Zeroizing;

use super::{CryptoError, Result};

/// AES block size, and the length of every key and IV constant here.
pub const BLOCK_LEN: usize = 16;
/// GCM tag length.
pub const TAG_LEN: usize = 16;

/// AES-128 in ECB mode with padding disabled, as the PIN handshake uses it.
#[derive(Clone)]
pub struct Ecb {
    cipher: Aes128,
}

impl std::fmt::Debug for Ecb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ecb(<aes-128>)")
    }
}

impl Ecb {
    /// Build from a 16-byte key.
    pub fn new(key: &[u8; BLOCK_LEN]) -> Self {
        Self {
            cipher: Aes128::new(key.into()),
        }
    }

    /// Encrypt a whole number of blocks.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() || plaintext.len() % BLOCK_LEN != 0 {
            return Err(CryptoError::BadCiphertextLength(plaintext.len()));
        }
        let mut out = plaintext.to_vec();
        for block in out.chunks_exact_mut(BLOCK_LEN) {
            self.cipher.encrypt_block(block.into());
        }
        Ok(out)
    }

    /// Decrypt a whole number of blocks.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.is_empty() || ciphertext.len() % BLOCK_LEN != 0 {
            return Err(CryptoError::BadCiphertextLength(ciphertext.len()));
        }
        let mut out = ciphertext.to_vec();
        for block in out.chunks_exact_mut(BLOCK_LEN) {
            self.cipher.decrypt_block(block.into());
        }
        Ok(out)
    }
}

/// AES-128-GCM under a session key, with caller-supplied deterministic IVs.
#[derive(Clone)]
pub struct SessionCrypto {
    cipher: Aes128Gcm,
}

impl std::fmt::Debug for SessionCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionCrypto(<aes-128-gcm>)")
    }
}

impl SessionCrypto {
    /// Build from the 16-byte `rikey` out of `/launch`.
    pub fn new(key: &[u8; BLOCK_LEN]) -> Self {
        Self {
            cipher: Aes128Gcm::new(key.into()),
        }
    }

    /// Encrypt in place, returning the tag separately -- which is the shape
    /// both the control envelope and the video prefix want, since each stores
    /// the tag in a header rather than appending it.
    pub fn encrypt_detached(&self, iv: &[u8; 12], buf: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        let tag = self
            .cipher
            .encrypt_in_place_detached(iv.into(), &[], buf)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        Ok(tag.into())
    }

    /// Decrypt in place against a detached tag.
    pub fn decrypt_detached(
        &self,
        iv: &[u8; 12],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<()> {
        self.cipher
            .decrypt_in_place_detached(iv.into(), &[], buf, Tag::from_slice(tag))
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    /// Encrypt, returning ciphertext and tag.
    pub fn encrypt(&self, iv: &[u8; 12], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; TAG_LEN])> {
        let mut buf = plaintext.to_vec();
        let tag = self.encrypt_detached(iv, &mut buf)?;
        Ok((buf, tag))
    }

    /// Decrypt, returning plaintext.
    pub fn decrypt(
        &self,
        iv: &[u8; 12],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<Vec<u8>> {
        let mut buf = ciphertext.to_vec();
        self.decrypt_detached(iv, &mut buf, tag)?;
        Ok(buf)
    }
}

/// AES-128-CBC with PKCS#7, as the audio stream uses it.
pub fn cbc_encrypt(key: &[u8; BLOCK_LEN], iv: &[u8; BLOCK_LEN], plaintext: &[u8]) -> Vec<u8> {
    use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    type Enc = cbc::Encryptor<Aes128>;
    Enc::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

/// The inverse of [`cbc_encrypt`], for the test client.
pub fn cbc_decrypt(
    key: &[u8; BLOCK_LEN],
    iv: &[u8; BLOCK_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    type Dec = cbc::Decryptor<Aes128>;
    Dec::new(key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| CryptoError::BadCiphertextLength(ciphertext.len()))
}

/// Derive the pairing key: `K = SHA256(salt || pin_ascii)[0..16]`
/// (`crypto.cpp:325-339`).
///
/// The result is wrapped in [`Zeroizing`] because it is the only thing standing
/// between an eavesdropper and a 10,000-entry keyspace.
pub fn pairing_key(salt: &[u8; BLOCK_LEN], pin: &str) -> Zeroizing<[u8; BLOCK_LEN]> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(pin.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; BLOCK_LEN];
    key.copy_from_slice(&digest[..BLOCK_LEN]);
    Zeroizing::new(key)
}

/// SHA-256 of the concatenation of `parts`.
pub fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::control::{control_iv, Origin};
    use crate::wire::video::EncPrefix;

    #[test]
    fn ecb_round_trips_whole_blocks() {
        let ecb = Ecb::new(&[0x42; 16]);
        let plaintext = [0xAB; 48];
        let ct = ecb.encrypt(&plaintext).unwrap();
        assert_eq!(ct.len(), 48);
        assert_eq!(ecb.decrypt(&ct).unwrap(), plaintext);
    }

    /// The documented weakness, asserted so it stays a known property rather
    /// than a surprise: ECB leaks block structure.
    #[test]
    fn ecb_leaks_repeated_blocks() {
        let ecb = Ecb::new(&[1; 16]);
        let ct = ecb.encrypt(&[7u8; 32]).unwrap();
        assert_eq!(ct[..16], ct[16..]);
    }

    #[test]
    fn ecb_refuses_partial_blocks() {
        let ecb = Ecb::new(&[1; 16]);
        assert!(ecb.encrypt(&[0; 17]).is_err());
        assert!(ecb.decrypt(&[0; 3]).is_err());
        assert!(ecb.encrypt(&[]).is_err());
    }

    #[test]
    fn pairing_key_matches_the_documented_derivation() {
        let salt = [0u8; 16];
        let k = pairing_key(&salt, "1234");
        let expect = sha256_concat(&[&salt, b"1234"]);
        assert_eq!(&k[..], &expect[..16]);
        // A different PIN gives a different key; that is the whole handshake.
        assert_ne!(*pairing_key(&salt, "1234"), *pairing_key(&salt, "1235"));
    }

    #[test]
    fn gcm_round_trips_and_detects_tampering() {
        let c = SessionCrypto::new(&[9; 16]);
        let iv = EncPrefix::iv_for(1);
        let (mut ct, tag) = c.encrypt(&iv, b"hello video shard").unwrap();
        assert_eq!(c.decrypt(&iv, &ct, &tag).unwrap(), b"hello video shard");

        ct[0] ^= 1;
        assert!(c.decrypt(&iv, &ct, &tag).is_err());
    }

    #[test]
    fn gcm_rejects_the_wrong_iv() {
        let c = SessionCrypto::new(&[9; 16]);
        let (ct, tag) = c.encrypt(&EncPrefix::iv_for(1), b"payload").unwrap();
        assert!(c.decrypt(&EncPrefix::iv_for(2), &ct, &tag).is_err());
    }

    /// Control messages in the two directions share a key, so their IVs must
    /// never collide even at the same sequence number.
    #[test]
    fn control_directions_do_not_share_an_iv() {
        let c = SessionCrypto::new(&[3; 16]);
        let (ct, tag) = c
            .encrypt(&control_iv(5, Origin::Client), b"input batch")
            .unwrap();
        assert!(c.decrypt(&control_iv(5, Origin::Host), &ct, &tag).is_err());
    }

    #[test]
    fn cbc_round_trips_with_pkcs7() {
        let key = [4u8; 16];
        let iv = crate::wire::audio::audio_iv(100, 3);
        let ct = cbc_encrypt(&key, &iv, b"opus packet");
        assert_eq!(ct.len() % 16, 0);
        assert_eq!(cbc_decrypt(&key, &iv, &ct).unwrap(), b"opus packet");
    }
}
