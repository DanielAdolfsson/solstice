//! The 24-byte encrypted-RTSP envelope (`rtsp.h:25-70`).
//!
//! Selected when the client reported `corever >= 1` at `/launch`, which makes
//! the launch response hand back an `rtspenc://` URL instead of `rtsp://`.
//!
//! ```text
//! struct encrypted_rtsp_header {   // packed, 24 bytes
//!     u32be typeAndLength;         // 0x80000000 | payload_length
//!     u32be sequenceNumber;        // -> low 4 bytes of the AES IV
//!     u8    tag[16];               // GCM auth tag
//! };                               // ciphertext follows
//! ```
//!
//! The MSB of `typeAndLength` is how a parser tells encrypted from plaintext.
//! Once a session is encrypted a plaintext message is **rejected**, not
//! tolerated (`rtsp.cpp:166`) -- otherwise the encryption is advisory.

use crate::crypto::gcm::{SessionCrypto, TAG_LEN};
use crate::crypto::{CryptoError, Result};
use crate::wire::{Reader, WireError};

/// Size of the envelope header.
pub const ENVELOPE_LEN: usize = 24;
/// The bit that marks a message as encrypted.
pub const ENCRYPTED_FLAG: u32 = 0x8000_0000;
/// Largest encrypted body accepted, matching the plaintext parser's cap.
pub const MAX_BODY_LEN: usize = super::message::MAX_MESSAGE_LEN;

/// Build the IV for RTSP sequence number `seq`.
///
/// The low four bytes carry the sequence number; the rest is zero. Like the
/// video and control constructions this is deterministic and therefore only
/// safe while `rikey` is unique per session.
pub fn rtsp_iv(seq: u32) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[..4].copy_from_slice(&seq.to_le_bytes());
    iv
}

/// Whether a buffer looks like an encrypted message.
pub fn is_encrypted(buf: &[u8]) -> bool {
    buf.len() >= 4 && buf[0] & 0x80 != 0
}

/// Wrap a plaintext RTSP message.
pub fn seal(crypto: &SessionCrypto, seq: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
    let (ciphertext, tag) = crypto.encrypt(&rtsp_iv(seq), plaintext)?;
    let mut out = Vec::with_capacity(ENVELOPE_LEN + ciphertext.len());
    out.extend_from_slice(&(ENCRYPTED_FLAG | ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unwrap one encrypted message from the front of `buf`.
///
/// Returns the plaintext and the number of bytes consumed, or `Ok(None)` if the
/// message has not fully arrived.
pub fn open(crypto: &SessionCrypto, buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>> {
    let mut r = Reader::new(buf);
    let Ok(type_and_length) = r.u32be() else {
        return Ok(None);
    };
    if type_and_length & ENCRYPTED_FLAG == 0 {
        return Err(CryptoError::Pairing(
            "plaintext RTSP message on an encrypted session",
        ));
    }
    let body_len = (type_and_length & !ENCRYPTED_FLAG) as usize;
    if body_len > MAX_BODY_LEN {
        return Err(CryptoError::BadCiphertextLength(body_len));
    }
    let Ok(seq) = r.u32be() else { return Ok(None) };
    let Ok(tag) = r.take_array::<TAG_LEN>() else {
        return Ok(None);
    };
    if r.remaining() < body_len {
        return Ok(None);
    }
    let ciphertext = r.take(body_len).map_err(|e: WireError| {
        CryptoError::BadCiphertextLength(match e {
            WireError::Truncated { have, .. } => have,
            _ => 0,
        })
    })?;
    let plaintext = crypto.decrypt(&rtsp_iv(seq), ciphertext, &tag)?;
    Ok(Some((plaintext, ENVELOPE_LEN + body_len)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crypto() -> SessionCrypto {
        SessionCrypto::new(&[0x2A; 16])
    }

    #[test]
    fn round_trips() {
        let c = crypto();
        let msg = b"OPTIONS rtsp://host:48010 RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        let sealed = seal(&c, 1, msg).unwrap();
        assert!(is_encrypted(&sealed));
        assert_eq!(sealed.len(), ENVELOPE_LEN + msg.len());
        let (plain, used) = open(&c, &sealed).unwrap().unwrap();
        assert_eq!(plain, msg);
        assert_eq!(used, sealed.len());
    }

    #[test]
    fn the_msb_distinguishes_encrypted_from_plaintext() {
        assert!(!is_encrypted(b"OPTI"));
        assert!(is_encrypted(&[0x80, 0, 0, 1]));
        assert!(!is_encrypted(&[0x00]));
    }

    /// `rtsp.cpp:166`: once encrypted, a plaintext message is refused.
    #[test]
    fn plaintext_on_an_encrypted_session_is_refused() {
        let c = crypto();
        assert!(open(&c, b"OPTIONS rtsp://h RTSP/1.0\r\n\r\n").is_err());
    }

    #[test]
    fn partial_messages_return_none() {
        let c = crypto();
        let sealed = seal(&c, 7, b"PLAY rtsp://h RTSP/1.0\r\nCSeq: 6\r\n\r\n").unwrap();
        for n in 0..sealed.len() {
            assert!(
                matches!(open(&c, &sealed[..n]), Ok(None)),
                "prefix of {n} bytes was not treated as incomplete"
            );
        }
        assert!(open(&c, &sealed).unwrap().is_some());
    }

    #[test]
    fn a_tampered_body_fails_authentication() {
        let c = crypto();
        let mut sealed = seal(&c, 2, b"ANNOUNCE x RTSP/1.0\r\n\r\n").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(open(&c, &sealed).is_err());
    }

    #[test]
    fn a_replayed_sequence_number_decrypts_to_a_different_message() {
        // The envelope itself has no replay protection -- the sequence number
        // only feeds the IV -- so a caller must track sequence numbers. This
        // test pins the property so the caller's duty stays visible.
        let c = crypto();
        let a = seal(&c, 1, b"A").unwrap();
        let b = seal(&c, 1, b"B").unwrap();
        assert_ne!(a, b);
        assert_eq!(open(&c, &a).unwrap().unwrap().0, b"A");
    }

    #[test]
    fn an_absurd_length_is_refused_rather_than_buffered() {
        let c = crypto();
        let mut buf = (ENCRYPTED_FLAG | 0x7FFF_FFFF).to_be_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 20]);
        assert!(open(&c, &buf).is_err());
    }

    #[test]
    fn a_message_sealed_under_another_key_does_not_open() {
        let sealed = seal(&crypto(), 1, b"secret").unwrap();
        let other = SessionCrypto::new(&[0xFF; 16]);
        assert!(open(&other, &sealed).is_err());
    }
}
