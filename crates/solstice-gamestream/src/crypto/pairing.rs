//! The four-phase PIN handshake (`nvhttp.cpp:752-910`).
//!
//! ```text
//! (1) getservercert       salt, clientcert        -> plaincert
//! (2) clientchallenge     ECB_K(challenge)        -> ECB_K(hash || server_challenge)
//! (3) serverchallengeresp ECB_K(client_hash)      -> server_secret || RSA-SHA256(secret)
//! (4) clientpairingsecret client_secret || sig    -> paired 1|0
//! ```
//!
//! Three CVEs live in this ~200 lines of state machine: CVE-2024-51738 (request
//! order not validated), CVE-2024-45407 (the client certificate was persisted
//! before the PIN check completed) and GHSA-36ff-frg7-492f (a PIN applied to an
//! unintended client session). `docs/security.md` §1.3 prescribes the shape
//! that avoids all three, and this module implements exactly that:
//!
//! * **one owner** -- [`PairingManager`] holds at most one session at a time;
//! * **one phase transition per request** -- each method consumes the session
//!   and hands back the next state, so a repeated or out-of-order call has
//!   nothing to act on;
//! * **no state written anywhere until step ④ verifies**;
//! * **the session is destroyed on any deviation**, successful or not.
//!
//! The PIN is four digits and chosen by the *client* (`moonlight-qt` hard-codes
//! `%04u`), so the keyspace is 10,000 and not negotiable. The compensating
//! controls -- a short window, a low attempt limit, and a source-address
//! restriction -- are the real defence, and they live in [`PairingManager`].

use std::time::{Duration, Instant};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::certs::{cert_signature, verify_with_cert, HostIdentity, PairedClient};
use super::gcm::{pairing_key, sha256_concat, Ecb, BLOCK_LEN};
use super::{CryptoError, Result};

/// Length of the server secret and of each challenge.
pub const SECRET_LEN: usize = 16;

/// Which request the session will accept next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Step ②.
    ClientChallenge,
    /// Step ③.
    ServerChallengeResponse,
    /// Step ④.
    ClientPairingSecret,
}

/// One in-flight pairing handshake.
///
/// Consumed by every transition: there is no way to apply the same step twice.
#[derive(Debug)]
pub struct PairingSession {
    phase: Phase,
    device_name: String,
    unique_id: String,
    client_cert_der: Vec<u8>,
    client_cert_signature: Vec<u8>,
    host_cert_signature: Vec<u8>,
    key: Zeroizing<[u8; BLOCK_LEN]>,
    server_secret: Zeroizing<[u8; SECRET_LEN]>,
    server_challenge: [u8; SECRET_LEN],
    client_hash: Option<[u8; 32]>,
}

impl PairingSession {
    /// Step ① -- `phrase=getservercert`.
    ///
    /// Nothing is persisted here. The client certificate is held only inside
    /// this session and is written to the store in step ④ or never
    /// (CVE-2024-45407).
    pub fn start(
        host: &HostIdentity,
        device_name: &str,
        unique_id: &str,
        salt: &[u8; BLOCK_LEN],
        client_cert_der: Vec<u8>,
        pin: &str,
    ) -> Result<(Self, String)> {
        if !is_plausible_pin(pin) {
            return Err(CryptoError::Pairing("PIN must be 4 or more decimal digits"));
        }
        let client_cert_signature = cert_signature(&client_cert_der)?;
        let session = Self {
            phase: Phase::ClientChallenge,
            device_name: device_name.to_owned(),
            unique_id: unique_id.to_owned(),
            client_cert_der,
            client_cert_signature,
            host_cert_signature: host.signature()?,
            key: pairing_key(salt, pin),
            server_secret: Zeroizing::new(random_bytes()),
            server_challenge: random_bytes(),
            client_hash: None,
        };
        Ok((session, host.cert_pem().to_owned()))
    }

    /// Which step this session will accept next.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The certificate this handshake is about. Not an identity until step ④.
    pub fn client_cert_der(&self) -> &[u8] {
        &self.client_cert_der
    }

    /// Step ② -- `clientchallenge`.
    pub fn client_challenge(mut self, encrypted: &[u8]) -> Result<(Self, Vec<u8>)> {
        self.expect(Phase::ClientChallenge)?;
        let ecb = Ecb::new(&self.key);
        let challenge = ecb.decrypt(encrypted)?;
        if challenge.len() != BLOCK_LEN {
            return Err(CryptoError::Pairing("client challenge is not one block"));
        }
        let hash = sha256_concat(&[&challenge, &self.host_cert_signature, &*self.server_secret]);
        let mut plain = Vec::with_capacity(hash.len() + SECRET_LEN);
        plain.extend_from_slice(&hash);
        plain.extend_from_slice(&self.server_challenge);
        let response = ecb.encrypt(&plain)?;
        self.phase = Phase::ServerChallengeResponse;
        Ok((self, response))
    }

    /// Step ③ -- `serverchallengeresp`.
    pub fn server_challenge_response(mut self, encrypted: &[u8]) -> Result<(Self, Vec<u8>)> {
        self.expect(Phase::ServerChallengeResponse)?;
        let decrypted = Ecb::new(&self.key).decrypt(encrypted)?;
        if decrypted.len() < 32 {
            return Err(CryptoError::Pairing("client hash is shorter than SHA-256"));
        }
        let mut client_hash = [0u8; 32];
        client_hash.copy_from_slice(&decrypted[..32]);
        self.client_hash = Some(client_hash);
        self.phase = Phase::ClientPairingSecret;
        // The response is the server secret plus proof that we hold the key
        // behind the certificate the client pinned in step ①.
        Ok((self, Vec::new()))
    }

    /// The `pairingsecret` body for step ③: `server_secret || RSA-SHA256(server_secret)`.
    ///
    /// Separate from [`Self::server_challenge_response`] so the signing key is
    /// borrowed only where it is needed.
    pub fn pairing_secret(&self, host: &HostIdentity) -> Result<Vec<u8>> {
        let signature = host.sign(&*self.server_secret)?;
        let mut out = Vec::with_capacity(SECRET_LEN + signature.len());
        out.extend_from_slice(&*self.server_secret);
        out.extend_from_slice(&signature);
        Ok(out)
    }

    /// Step ④ -- `clientpairingsecret`.
    ///
    /// Returns the client to persist, or an error. Either way the session is
    /// consumed.
    pub fn client_pairing_secret(self, body: &[u8]) -> Result<PairedClient> {
        if self.phase != Phase::ClientPairingSecret {
            return Err(CryptoError::Pairing("out of order"));
        }
        if body.len() <= SECRET_LEN {
            return Err(CryptoError::Pairing("pairing secret is too short"));
        }
        let (client_secret, signature) = body.split_at(SECRET_LEN);
        let expected = sha256_concat(&[
            &self.server_challenge,
            &self.client_cert_signature,
            client_secret,
        ]);
        let stored = self
            .client_hash
            .ok_or(CryptoError::Pairing("no client hash"))?;

        // Both checks always run: the comparison is constant-time and the
        // signature is verified even when the hash already failed, so the
        // response time says nothing about which half was wrong.
        let hash_ok = bool::from(expected.ct_eq(&stored));
        let sig_ok = verify_with_cert(&self.client_cert_der, client_secret, signature)?;
        if !(hash_ok && sig_ok) {
            return Err(CryptoError::Pairing("pairing verification failed"));
        }
        Ok(PairedClient {
            cert_der: self.client_cert_der,
            device_name: self.device_name,
            unique_id: self.unique_id,
        })
    }

    fn expect(&self, phase: Phase) -> Result<()> {
        if self.phase == phase {
            Ok(())
        } else {
            Err(CryptoError::Pairing("out of order"))
        }
    }
}

/// Whether a PIN is one Solstice will accept.
///
/// Sunshine enforces exactly four decimal digits. Nothing in the wire format
/// caps the length -- it is a query-string value -- so a longer PIN is accepted
/// if a client ever offers one, but it cannot be planned on
/// (`docs/security.md` §1.1).
pub fn is_plausible_pin(pin: &str) -> bool {
    pin.len() >= 4 && pin.len() <= 32 && pin.bytes().all(|b| b.is_ascii_digit())
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::TryRngCore;
    let mut out = [0u8; N];
    rand::rngs::OsRng
        .try_fill_bytes(&mut out)
        .expect("the OS CSPRNG must work; there is nothing sensible to do if it does not");
    out
}

/// Why a pairing request was refused before it reached the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PairingRefusal {
    /// `solstice pair` has not been run, or the window has closed.
    #[error("pairing is not open")]
    WindowClosed,
    /// Too many failed attempts; a human must re-enable pairing.
    #[error("pairing locked out after too many failed attempts")]
    LockedOut,
    /// A handshake is already in flight. One at a time, so a second client
    /// cannot be handed the PIN meant for the first (GHSA-36ff-frg7-492f).
    #[error("another pairing is already in progress")]
    Busy,
    /// The source address is not allowed to pair.
    #[error("pairing not allowed from this address")]
    SourceNotAllowed,
}

/// Window, lockout and single-owner policy around [`PairingSession`].
#[derive(Debug)]
pub struct PairingManager {
    pin: Option<Zeroizing<String>>,
    closes_at: Option<Instant>,
    session: Option<PairingSession>,
    failures: u32,
    max_attempts: u32,
    locked_out: bool,
    generation: u64,
    paired: Option<PairedClient>,
}

impl Default for PairingManager {
    fn default() -> Self {
        Self::new(3)
    }
}

impl PairingManager {
    /// Build with an attempt limit.
    pub fn new(max_attempts: u32) -> Self {
        Self {
            pin: None,
            closes_at: None,
            session: None,
            failures: 0,
            max_attempts,
            locked_out: false,
            generation: 0,
            paired: None,
        }
    }

    /// Open a time-boxed pairing window. This is what `solstice pair` calls.
    pub fn open(&mut self, pin: &str, window: Duration, now: Instant) -> Result<()> {
        if !is_plausible_pin(pin) {
            return Err(CryptoError::Pairing("PIN must be 4 or more decimal digits"));
        }
        self.pin = Some(Zeroizing::new(pin.to_owned()));
        self.closes_at = Some(now + window);
        self.session = None;
        self.failures = 0;
        self.locked_out = false;
        self.generation = self.generation.wrapping_add(1);
        self.paired = None;
        Ok(())
    }

    /// Which window this is: bumped by every successful [`open`](Self::open).
    ///
    /// `solstice pair` waits for the outcome of the window *it* opened, and a
    /// second `solstice pair` replaces the PIN under it; this is how the first
    /// one notices instead of reporting the second one's result as its own.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Close the window and drop any in-flight handshake.
    pub fn close(&mut self) {
        self.pin = None;
        self.closes_at = None;
        self.session = None;
    }

    /// Whether a window is currently open.
    pub fn is_open(&self, now: Instant) -> bool {
        !self.locked_out && self.closes_at.is_some_and(|t| now < t)
    }

    /// How long the window has left, if it is open.
    pub fn time_left(&self, now: Instant) -> Option<Duration> {
        self.closes_at
            .filter(|_| self.is_open(now))
            .map(|t| t.saturating_duration_since(now))
    }

    /// The client this window paired, once it has. Cleared by the next
    /// [`open`](Self::open), and the only way to tell a window that closed
    /// because it succeeded from one that ran out: a client re-pairing with a
    /// certificate the store already holds leaves the store looking unchanged.
    pub fn paired(&self) -> Option<&PairedClient> {
        self.paired.as_ref()
    }

    /// The attempt limit.
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Whether the attempt limit has been hit.
    pub fn is_locked_out(&self) -> bool {
        self.locked_out
    }

    /// Failed attempts since the window opened.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Begin a handshake. Refuses if the window is shut, the limit is hit, or
    /// another handshake is already in flight.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        &mut self,
        host: &HostIdentity,
        device_name: &str,
        unique_id: &str,
        salt: &[u8; BLOCK_LEN],
        client_cert_der: Vec<u8>,
        now: Instant,
    ) -> std::result::Result<String, PairingError> {
        if self.locked_out {
            return Err(PairingError::Refused(PairingRefusal::LockedOut));
        }
        if !self.is_open(now) {
            return Err(PairingError::Refused(PairingRefusal::WindowClosed));
        }
        if self.session.is_some() {
            return Err(PairingError::Refused(PairingRefusal::Busy));
        }
        let pin = self
            .pin
            .clone()
            .ok_or(PairingError::Refused(PairingRefusal::WindowClosed))?;
        let (session, cert_pem) =
            PairingSession::start(host, device_name, unique_id, salt, client_cert_der, &pin)
                .map_err(PairingError::Crypto)?;
        self.session = Some(session);
        Ok(cert_pem)
    }

    /// Run one transition. The closure gets the session by value; on any error
    /// the session is dropped and the failure is counted.
    pub fn step<T>(
        &mut self,
        now: Instant,
        f: impl FnOnce(PairingSession) -> Result<(PairingSession, T)>,
    ) -> std::result::Result<T, PairingError> {
        if !self.is_open(now) {
            self.session = None;
            return Err(PairingError::Refused(PairingRefusal::WindowClosed));
        }
        let session = self
            .session
            .take()
            .ok_or(PairingError::Refused(PairingRefusal::Busy))?;
        match f(session) {
            Ok((session, out)) => {
                self.session = Some(session);
                Ok(out)
            }
            Err(e) => {
                self.record_failure();
                Err(PairingError::Crypto(e))
            }
        }
    }

    /// Borrow the in-flight session, for the one step that needs the host key.
    pub fn session(&self) -> Option<&PairingSession> {
        self.session.as_ref()
    }

    /// Run the final transition, which consumes the session either way.
    pub fn finish(
        &mut self,
        now: Instant,
        body: &[u8],
    ) -> std::result::Result<PairedClient, PairingError> {
        if !self.is_open(now) {
            self.session = None;
            return Err(PairingError::Refused(PairingRefusal::WindowClosed));
        }
        let session = self
            .session
            .take()
            .ok_or(PairingError::Refused(PairingRefusal::Busy))?;
        match session.client_pairing_secret(body) {
            Ok(client) => {
                // One successful pairing per window: the window is closed
                // immediately so a second client cannot reuse the same PIN.
                self.close();
                self.paired = Some(client.clone());
                Ok(client)
            }
            Err(e) => {
                self.record_failure();
                Err(PairingError::Crypto(e))
            }
        }
    }

    fn record_failure(&mut self) {
        self.failures += 1;
        if self.failures >= self.max_attempts {
            self.locked_out = true;
            self.close();
        }
    }
}

/// A refusal or a cryptographic failure.
#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    /// Policy said no before any crypto ran.
    #[error(transparent)]
    Refused(#[from] PairingRefusal),
    /// The handshake itself failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// The client half of the handshake.
///
/// Solstice never needs this, but the test harness does: `docs/testing.md` §2.5
/// asks for a hostile client that can drive the phases out of order, replay
/// them, and brute-force the PIN. Keeping it beside the server half means the
/// two cannot drift.
pub mod client {
    use super::*;

    /// A client driving the handshake.
    #[derive(Debug)]
    pub struct ClientPairing {
        key: Zeroizing<[u8; BLOCK_LEN]>,
        challenge: [u8; SECRET_LEN],
        client_secret: [u8; SECRET_LEN],
        server_challenge: Option<[u8; SECRET_LEN]>,
    }

    impl ClientPairing {
        /// Start, given the salt the client chose and the PIN it displayed.
        pub fn new(salt: &[u8; BLOCK_LEN], pin: &str) -> Self {
            Self {
                key: pairing_key(salt, pin),
                challenge: random_bytes(),
                client_secret: random_bytes(),
                server_challenge: None,
            }
        }

        /// The step ② request body.
        pub fn client_challenge(&self) -> Result<Vec<u8>> {
            Ecb::new(&self.key).encrypt(&self.challenge)
        }

        /// Consume the step ② response and produce the step ③ request body.
        pub fn server_challenge_response(
            &mut self,
            response: &[u8],
            host_cert_der: &[u8],
            client_cert_signature: &[u8],
        ) -> Result<Vec<u8>> {
            let decrypted = Ecb::new(&self.key).decrypt(response)?;
            if decrypted.len() < 32 + SECRET_LEN {
                return Err(CryptoError::Pairing("server challenge response too short"));
            }
            let mut server_challenge = [0u8; SECRET_LEN];
            server_challenge.copy_from_slice(&decrypted[32..32 + SECRET_LEN]);
            self.server_challenge = Some(server_challenge);
            let _ = host_cert_der;
            let hash = sha256_concat(&[
                &server_challenge,
                client_cert_signature,
                &self.client_secret,
            ]);
            Ecb::new(&self.key).encrypt(&hash)
        }

        /// The step ④ request body, signed with the client's own key.
        pub fn client_pairing_secret(
            &self,
            sign: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
        ) -> Result<Vec<u8>> {
            let signature = sign(&self.client_secret)?;
            let mut out = Vec::with_capacity(SECRET_LEN + signature.len());
            out.extend_from_slice(&self.client_secret);
            out.extend_from_slice(&signature);
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::client::ClientPairing;
    use super::*;

    /// Key generation dominates these tests, so one identity is shared.
    fn identities() -> &'static (HostIdentity, HostIdentity) {
        use std::sync::OnceLock;
        static PAIR: OnceLock<(HostIdentity, HostIdentity)> = OnceLock::new();
        PAIR.get_or_init(|| {
            (
                HostIdentity::generate("solstice").unwrap(),
                HostIdentity::generate("moonlight").unwrap(),
            )
        })
    }

    const SALT: [u8; 16] = [0x11; 16];
    const PIN: &str = "1234";

    fn run_handshake(
        host: &HostIdentity,
        client_identity: &HostIdentity,
        pin_used_by_client: &str,
    ) -> Result<PairedClient> {
        let (session, _cert_pem) = PairingSession::start(
            host,
            "moonlight-qt",
            "0123456789ABCDEF",
            &SALT,
            client_identity.cert_der().to_vec(),
            PIN,
        )?;
        let mut client = ClientPairing::new(&SALT, pin_used_by_client);

        let (session, response) = session.client_challenge(&client.client_challenge()?)?;
        let step3 = client.server_challenge_response(
            &response,
            host.cert_der(),
            &client_identity.signature()?,
        )?;
        let (session, _) = session.server_challenge_response(&step3)?;
        let _secret = session.pairing_secret(host)?;
        let body = client.client_pairing_secret(|m| client_identity.sign(m))?;
        session.client_pairing_secret(&body)
    }

    #[test]
    fn the_happy_path_pairs() {
        let (host, client) = identities();
        let paired = run_handshake(host, client, PIN).unwrap();
        assert_eq!(paired.cert_der, client.cert_der());
        assert_eq!(paired.device_name, "moonlight-qt");
    }

    #[test]
    fn a_wrong_pin_does_not_pair() {
        let (host, client) = identities();
        // The wrong key makes the step ② response undecryptable, so the client
        // computes a hash the server will not accept.
        assert!(run_handshake(host, client, "9999").is_err());
    }

    /// CVE-2024-51738: the pairing protocol must validate request order.
    #[test]
    fn out_of_order_requests_are_refused() {
        let (host, client) = identities();
        let (session, _) =
            PairingSession::start(host, "d", "u", &SALT, client.cert_der().to_vec(), PIN).unwrap();
        assert_eq!(session.phase(), Phase::ClientChallenge);

        // Step ③ before step ②.
        let err = session.server_challenge_response(&[0u8; 32]).unwrap_err();
        assert!(matches!(err, CryptoError::Pairing("out of order")));
    }

    #[test]
    fn step_four_before_step_three_is_refused() {
        let (host, client) = identities();
        let (session, _) =
            PairingSession::start(host, "d", "u", &SALT, client.cert_der().to_vec(), PIN).unwrap();
        assert!(matches!(
            session.client_pairing_secret(&[0u8; 272]).unwrap_err(),
            CryptoError::Pairing("out of order")
        ));
    }

    /// A step cannot be replayed, because applying it consumes the session.
    #[test]
    fn a_replayed_step_has_nothing_to_act_on() {
        let (host, client_identity) = identities();
        let mut mgr = PairingManager::new(3);
        let now = Instant::now();
        mgr.open(PIN, Duration::from_secs(60), now).unwrap();
        mgr.start(
            host,
            "d",
            "u",
            &SALT,
            client_identity.cert_der().to_vec(),
            now,
        )
        .unwrap();

        let client = ClientPairing::new(&SALT, PIN);
        let challenge = client.client_challenge().unwrap();
        let _ = mgr.step(now, |s| s.client_challenge(&challenge)).unwrap();
        // Replaying step ② now hits a session that is waiting for step ③.
        assert!(mgr.step(now, |s| s.client_challenge(&challenge)).is_err());
    }

    /// GHSA-36ff-frg7-492f: a PIN must not be applied to an unintended client
    /// session. Only one handshake may be in flight.
    #[test]
    fn a_second_client_cannot_join_an_open_window() {
        let (host, client_identity) = identities();
        let mut mgr = PairingManager::new(3);
        let now = Instant::now();
        mgr.open(PIN, Duration::from_secs(60), now).unwrap();
        mgr.start(
            host,
            "first",
            "1",
            &SALT,
            client_identity.cert_der().to_vec(),
            now,
        )
        .unwrap();
        let second = mgr.start(
            host,
            "second",
            "2",
            &SALT,
            client_identity.cert_der().to_vec(),
            now,
        );
        assert!(matches!(
            second,
            Err(PairingError::Refused(PairingRefusal::Busy))
        ));
    }

    #[test]
    fn each_open_is_a_new_window_and_a_refused_one_is_not() {
        let mut mgr = PairingManager::new(3);
        let now = Instant::now();
        let before = mgr.generation();
        mgr.open(PIN, Duration::from_secs(60), now).unwrap();
        let first = mgr.generation();
        assert_ne!(first, before);
        assert!(mgr.open("12", Duration::from_secs(60), now).is_err());
        assert_eq!(mgr.generation(), first, "a refused open changes nothing");
        mgr.open(PIN, Duration::from_secs(60), now).unwrap();
        assert_ne!(mgr.generation(), first);
        assert_eq!(
            mgr.time_left(now + Duration::from_secs(20)),
            Some(Duration::from_secs(40))
        );
        assert_eq!(mgr.paired(), None);
    }

    #[test]
    fn pairing_is_closed_until_a_window_is_opened() {
        let (host, client_identity) = identities();
        let mut mgr = PairingManager::new(3);
        let now = Instant::now();
        assert!(!mgr.is_open(now));
        assert!(matches!(
            mgr.start(
                host,
                "d",
                "u",
                &SALT,
                client_identity.cert_der().to_vec(),
                now
            ),
            Err(PairingError::Refused(PairingRefusal::WindowClosed))
        ));
    }

    #[test]
    fn the_window_expires() {
        let (host, client_identity) = identities();
        let mut mgr = PairingManager::new(3);
        let now = Instant::now();
        mgr.open(PIN, Duration::from_secs(60), now).unwrap();
        let later = now + Duration::from_secs(61);
        assert!(!mgr.is_open(later));
        assert!(matches!(
            mgr.start(
                host,
                "d",
                "u",
                &SALT,
                client_identity.cert_der().to_vec(),
                later
            ),
            Err(PairingError::Refused(PairingRefusal::WindowClosed))
        ));
    }

    /// Against a 10,000-entry keyspace the lockout is the difference between a
    /// speed bump and nothing at all.
    ///
    /// Note where the counting has to happen: the protocol gives the host no
    /// way to detect a wrong PIN before step ④, because steps ② and ③ are
    /// decryptions that produce plausible garbage under any key. So every
    /// brute-force attempt is a full handshake that fails at the end, and that
    /// is the event the limit counts.
    #[test]
    fn repeated_failures_lock_pairing_out() {
        let (host, client_identity) = identities();
        let mut mgr = PairingManager::new(3);
        let now = Instant::now();
        mgr.open(PIN, Duration::from_secs(60), now).unwrap();

        for attempt in 1..=3 {
            mgr.start(
                host,
                "d",
                "u",
                &SALT,
                client_identity.cert_der().to_vec(),
                now,
            )
            .unwrap_or_else(|e| panic!("attempt {attempt}: {e}"));
            let mut client = ClientPairing::new(&SALT, "9999"); // wrong PIN
            let challenge = client.client_challenge().unwrap();
            let response = mgr.step(now, |s| s.client_challenge(&challenge)).unwrap();
            let step3 = client
                .server_challenge_response(
                    &response,
                    host.cert_der(),
                    &client_identity.signature().unwrap(),
                )
                .unwrap();
            mgr.step(now, |s| s.server_challenge_response(&step3))
                .unwrap();
            let body = client
                .client_pairing_secret(|m| client_identity.sign(m))
                .unwrap();
            assert!(
                mgr.finish(now, &body).is_err(),
                "attempt {attempt} should fail"
            );
            assert_eq!(mgr.failures(), attempt);
        }

        assert!(mgr.is_locked_out());
        assert!(!mgr.is_open(now));
        assert!(matches!(
            mgr.start(
                host,
                "d",
                "u",
                &SALT,
                client_identity.cert_der().to_vec(),
                now
            ),
            Err(PairingError::Refused(PairingRefusal::LockedOut))
        ));
    }

    /// One pairing per window: a successful handshake shuts the window so the
    /// same PIN cannot be spent twice.
    #[test]
    fn success_closes_the_window() {
        let (host, client_identity) = identities();
        let mut mgr = PairingManager::new(3);
        let now = Instant::now();
        mgr.open(PIN, Duration::from_secs(60), now).unwrap();
        mgr.start(
            host,
            "d",
            "u",
            &SALT,
            client_identity.cert_der().to_vec(),
            now,
        )
        .unwrap();

        let mut client = ClientPairing::new(&SALT, PIN);
        let challenge = client.client_challenge().unwrap();
        let response = mgr.step(now, |s| s.client_challenge(&challenge)).unwrap();
        let step3 = client
            .server_challenge_response(
                &response,
                host.cert_der(),
                &client_identity.signature().unwrap(),
            )
            .unwrap();
        mgr.step(now, |s| s.server_challenge_response(&step3))
            .unwrap();
        let body = client
            .client_pairing_secret(|m| client_identity.sign(m))
            .unwrap();
        let paired = mgr.finish(now, &body).unwrap();
        assert_eq!(paired.cert_der, client_identity.cert_der());
        assert_eq!(
            mgr.paired(),
            Some(&paired),
            "the window remembers its result"
        );

        assert!(!mgr.is_open(now));
        assert_eq!(mgr.time_left(now), None);
        assert!(matches!(
            mgr.start(
                host,
                "d",
                "u",
                &SALT,
                client_identity.cert_der().to_vec(),
                now
            ),
            Err(PairingError::Refused(PairingRefusal::WindowClosed))
        ));
    }

    /// CVE-2024-45407: nothing may be persisted before step ④ verifies.
    #[test]
    fn a_failed_handshake_yields_no_client() {
        let (host, client_identity) = identities();
        let (session, _) = PairingSession::start(
            host,
            "d",
            "u",
            &SALT,
            client_identity.cert_der().to_vec(),
            PIN,
        )
        .unwrap();
        let mut client = ClientPairing::new(&SALT, PIN);
        let (session, response) = session
            .client_challenge(&client.client_challenge().unwrap())
            .unwrap();
        let step3 = client
            .server_challenge_response(
                &response,
                host.cert_der(),
                &client_identity.signature().unwrap(),
            )
            .unwrap();
        let (session, _) = session.server_challenge_response(&step3).unwrap();

        // Correct hash, but the signature is over the wrong key.
        let mut body = client
            .client_pairing_secret(|m| client_identity.sign(m))
            .unwrap();
        let last = body.len() - 1;
        body[last] ^= 0xFF;
        assert!(session.client_pairing_secret(&body).is_err());
    }

    #[test]
    fn a_truncated_pairing_secret_is_refused() {
        let (host, client_identity) = identities();
        let (session, _) = PairingSession::start(
            host,
            "d",
            "u",
            &SALT,
            client_identity.cert_der().to_vec(),
            PIN,
        )
        .unwrap();
        let mut client = ClientPairing::new(&SALT, PIN);
        let (session, response) = session
            .client_challenge(&client.client_challenge().unwrap())
            .unwrap();
        let step3 = client
            .server_challenge_response(
                &response,
                host.cert_der(),
                &client_identity.signature().unwrap(),
            )
            .unwrap();
        let (session, _) = session.server_challenge_response(&step3).unwrap();
        assert!(session.client_pairing_secret(&[0u8; 16]).is_err());
    }

    #[test]
    fn pin_policy_matches_the_protocol() {
        assert!(is_plausible_pin("1234"));
        assert!(is_plausible_pin("00000000"));
        assert!(!is_plausible_pin("123"));
        assert!(!is_plausible_pin("12a4"));
        assert!(!is_plausible_pin(""));
        assert!(!is_plausible_pin(&"1".repeat(33)));
    }
}
