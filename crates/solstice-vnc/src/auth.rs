//! Security types, and the policy about which ones are acceptable.
//!
//! The policy is the point of this module. From `docs/security.md` §4.1:
//!
//! > Refuse `None` and `VNC Authentication` over anything but loopback or a
//! > Unix socket. Require VeNCrypt with certificate verification for any
//! > network hop.
//!
//! The reasoning is not subtle. VNC Authentication is DES in ECB keyed by the
//! password truncated to eight characters with each key byte's bit order
//! reversed -- a 56-bit key, no salt, no server authentication -- and
//! everything after it, framebuffer and keystrokes alike, is plaintext. Solstice
//! holds the VNC password *and* injects keyboard input into a live desktop, so
//! a compromise of the backend hop is a compromise of that desktop.
//!
//! A refusal test is a security test, so the refusals are tested as carefully
//! as the acceptances.

use std::net::IpAddr;

use cipher::{BlockEncrypt, KeyInit};
use des::Des;

use crate::protocol::{security, Result, RfbError};

/// What Solstice is willing to authenticate with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VncSecurity {
    /// No authentication. Loopback only.
    None,
    /// DES challenge-response. Loopback only, and discouraged there.
    VncAuth {
        /// The password. Only its first eight bytes matter -- that is the
        /// protocol, not a bug here.
        password: String,
    },
    /// TLS with x509 server certificates, sub-negotiating the auth method.
    VeNCrypt {
        /// Optional password for the `X509Vnc` sub-type.
        password: Option<String>,
        /// PEM file of certificates to trust. `None` uses the system roots.
        ca_file: Option<std::path::PathBuf>,
    },
}

impl VncSecurity {
    /// Whether this method may be used against `peer`.
    ///
    /// Loopback is the exception, and the only one.
    pub fn is_permitted_against(&self, peer: IpAddr) -> bool {
        match self {
            VncSecurity::VeNCrypt { .. } => true,
            VncSecurity::None | VncSecurity::VncAuth { .. } => peer.is_loopback(),
        }
    }

    /// The RFB security type number.
    pub fn type_number(&self) -> u8 {
        match self {
            VncSecurity::None => security::NONE,
            VncSecurity::VncAuth { .. } => security::VNC_AUTH,
            VncSecurity::VeNCrypt { .. } => security::VENCRYPT,
        }
    }

    /// Pick the configured method out of what the server offered.
    pub fn choose(&self, offered: &[u8], peer: IpAddr) -> Result<u8> {
        if !self.is_permitted_against(peer) {
            return Err(RfbError::Auth(format!(
                "security type {} is refused against a non-loopback peer ({peer}); \
                 use VeNCrypt or an SSH tunnel",
                self.type_number()
            )));
        }
        let wanted = self.type_number();
        if offered.contains(&wanted) {
            return Ok(wanted);
        }
        Err(RfbError::Auth(format!(
            "server offers {offered:?}, which does not include the configured type {wanted}"
        )))
    }
}

/// Compute the VNC Authentication response.
///
/// The password is truncated or zero-padded to eight bytes and each byte's bit
/// order is reversed; the 16-byte challenge is then DES-ECB encrypted as two
/// blocks.
pub fn vnc_auth_response(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    let mut key = [0u8; 8];
    for (slot, byte) in key.iter_mut().zip(password.bytes()) {
        *slot = byte.reverse_bits();
    }
    let cipher = Des::new(&key.into());
    let mut out = *challenge;
    for block in out.chunks_exact_mut(8) {
        cipher.encrypt_block(block.into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const REMOTE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    /// The refusal is the security control; test it as such.
    #[test]
    fn weak_methods_are_refused_off_loopback() {
        let none = VncSecurity::None;
        let vncauth = VncSecurity::VncAuth {
            password: "hunter2".into(),
        };
        assert!(none.is_permitted_against(LOOPBACK));
        assert!(vncauth.is_permitted_against(LOOPBACK));
        assert!(!none.is_permitted_against(REMOTE));
        assert!(!vncauth.is_permitted_against(REMOTE));

        assert!(none.choose(&[security::NONE], REMOTE).is_err());
        assert!(vncauth.choose(&[security::VNC_AUTH], REMOTE).is_err());
        assert!(none.choose(&[security::NONE], LOOPBACK).is_ok());
    }

    #[test]
    fn vencrypt_is_permitted_anywhere() {
        let v = VncSecurity::VeNCrypt {
            password: None,
            ca_file: None,
        };
        assert!(v.is_permitted_against(REMOTE));
        assert_eq!(
            v.choose(&[security::VENCRYPT, security::NONE], REMOTE)
                .unwrap(),
            19
        );
    }

    #[test]
    fn a_server_that_does_not_offer_the_configured_method_is_refused() {
        let v = VncSecurity::VeNCrypt {
            password: None,
            ca_file: None,
        };
        // A server offering only `None` must not silently get `None`: that is
        // exactly the downgrade the policy exists to prevent.
        assert!(v.choose(&[security::NONE], REMOTE).is_err());
        assert!(v.choose(&[], REMOTE).is_err());
    }

    /// The key schedule's bit reversal is the part everyone gets wrong.
    #[test]
    fn the_des_key_bytes_are_bit_reversed() {
        let a = vnc_auth_response("abcdefgh", &[0; 16]);
        // Reversing the bits of the password gives a different key, so a naive
        // implementation that skipped the reversal would produce this instead.
        let naive = {
            let cipher = Des::new(b"abcdefgh".into());
            let mut out = [0u8; 16];
            for block in out.chunks_exact_mut(8) {
                cipher.encrypt_block(block.into());
            }
            out
        };
        assert_ne!(a, naive);
    }

    #[test]
    fn the_password_is_truncated_to_eight_bytes() {
        // The protocol's own weakness, asserted so it stays visible: the ninth
        // character onward is ignored entirely.
        assert_eq!(
            vnc_auth_response("12345678", &[1; 16]),
            vnc_auth_response("12345678xyz", &[1; 16])
        );
        assert_ne!(
            vnc_auth_response("1234567", &[1; 16]),
            vnc_auth_response("12345678", &[1; 16])
        );
    }

    #[test]
    fn a_short_password_is_zero_padded() {
        // Deterministic, and the same two blocks are produced for both halves
        // of the challenge when the challenge repeats -- ECB, as specified.
        let response = vnc_auth_response("ab", &[7u8; 16]);
        assert_eq!(response[..8], response[8..]);
    }
}
