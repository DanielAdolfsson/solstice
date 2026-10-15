//! The per-channel link handshake.
//!
//! SPICE is not one connection: every channel is its own socket and every
//! socket repeats this exchange (`docs/spice-protocol.md` §2). The main
//! channel links with `connection_id` zero; the server allocates an id and
//! returns it in `MAIN_INIT`, and every later channel must present it.
//!
//! ```text
//! client -> SpiceLinkHeader { "REDQ", 2, 2, size }
//!           SpiceLinkMess   { connection_id, channel_type, channel_id,
//!                             num_common_caps, num_channel_caps, caps_offset }
//!           capability words: common, then channel
//!
//! server -> SpiceLinkHeader
//!           SpiceLinkReply  { error, pub_key[162], ...caps }
//!
//! client -> [ SpiceLinkAuthMechanism ]   iff the server has AUTH_SELECTION
//!           128 bytes of RSA-encrypted ticket
//!
//! server -> u32 SpiceLinkErr
//! ```
//!
//! Two details are easy to get wrong and both come from `spice-gtk`'s
//! `spice-channel.c`:
//!
//! * **The auth-mechanism word is conditional.** `:2025-2050` sends it only
//!   when the server advertised `PROTOCOL_AUTH_SELECTION`; sending it
//!   unconditionally desynchronises a server that did not.
//! * **The password is encrypted with its NUL terminator.** `:1265` passes
//!   `strlen(password) + 1` to the encrypt call, so an empty password is one
//!   zero byte, not zero bytes. A server with ticketing disabled still wants
//!   the block.

use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Result, SpiceError};
use crate::protocol::{self, common_cap, link_size, Caps};
use crate::wire::{Reader, Writer};

/// Anything that can carry a SPICE channel, with or without TLS under it.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}

/// `SPICE_LINK_ERR_NEED_SECURED` (`enums.h:42`): link again over TLS.
pub const LINK_ERR_NEED_SECURED: u32 = 5;

/// What to link as.
#[derive(Clone, Debug)]
pub struct LinkRequest {
    /// Zero on the main channel, the server's id on every other.
    pub connection_id: u32,
    /// `SPICE_CHANNEL_*`.
    pub channel_type: u8,
    /// Which instance of that channel type.
    pub channel_id: u8,
    /// Capabilities common to every channel.
    pub common_caps: Caps,
    /// Capabilities specific to this channel type.
    pub channel_caps: Caps,
}

impl LinkRequest {
    /// A request carrying the common capabilities every Solstice channel
    /// wants.
    ///
    /// `MINI_HEADER` is asked for because the full header's 64-bit serial and
    /// sub-message offset buy nothing here: Solstice never sends a
    /// `WAIT_FOR_CHANNELS` that would need the serial, and sub-message lists
    /// are handled the same either way.
    pub fn new(connection_id: u32, channel_type: u8, channel_id: u8) -> Self {
        LinkRequest {
            connection_id,
            channel_type,
            channel_id,
            common_caps: Caps::from_bits(&[
                common_cap::PROTOCOL_AUTH_SELECTION,
                common_cap::AUTH_SPICE,
                common_cap::MINI_HEADER,
            ]),
            channel_caps: Caps::new(),
        }
    }

    /// Replace the channel-specific capabilities.
    pub fn with_channel_caps(mut self, caps: Caps) -> Self {
        self.channel_caps = caps;
        self
    }

    /// Serialise the header, the message and the capability words.
    pub fn encode(&self) -> Vec<u8> {
        let common = self.common_caps.words();
        let channel = self.channel_caps.words();
        let caps_bytes = (common.len() + channel.len()) * 4;

        let mut out = Writer::with_capacity(link_size::HEADER + link_size::MESS + caps_bytes);
        out.u32(protocol::MAGIC)
            .u32(protocol::VERSION_MAJOR)
            .u32(protocol::VERSION_MINOR)
            .u32((link_size::MESS + caps_bytes) as u32);

        out.u32(self.connection_id)
            .u8(self.channel_type)
            .u8(self.channel_id)
            .u32(common.len() as u32)
            .u32(channel.len() as u32)
            // The caps follow the message immediately, so the offset is the
            // message's own length. It is an offset from the start of
            // `SpiceLinkMess`, not from the start of the header.
            .u32(link_size::MESS as u32);
        for word in common.iter().chain(channel.iter()) {
            out.u32(*word);
        }
        out.finish()
    }
}

/// What the server answered.
#[derive(Clone, Debug)]
pub struct LinkReply {
    /// `SpiceLinkErr`.
    pub error: u32,
    /// DER `SubjectPublicKeyInfo` for the per-connection RSA key.
    pub pub_key: Vec<u8>,
    /// The server's common capabilities.
    pub common_caps: Caps,
    /// The server's channel capabilities.
    pub channel_caps: Caps,
}

impl LinkReply {
    /// Whether both ends agreed on the short message header.
    pub fn mini_header(&self) -> bool {
        self.common_caps.has(common_cap::MINI_HEADER)
    }

    fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let error = r.u32()?;
        let pub_key = r.bytes(protocol::TICKET_PUBKEY_BYTES)?.to_vec();
        let num_common = r.u32()?;
        let num_channel = r.u32()?;
        let caps_offset = r.u32()? as usize;

        // A server is free to put the caps anywhere inside the reply, and
        // `spice-channel.c:2008-2022` bounds-checks exactly this before
        // walking them.
        let mut caps = r.at(caps_offset)?;
        let mut read = |n: u32| -> Result<Caps> {
            let n = caps.count(n, 4)?;
            let mut words = Vec::with_capacity(n);
            for _ in 0..n {
                words.push(caps.u32()?);
            }
            Ok(Caps::from_words(words))
        };
        let common_caps = read(num_common)?;
        let channel_caps = read(num_channel)?;

        Ok(LinkReply {
            error,
            pub_key,
            common_caps,
            channel_caps,
        })
    }
}

/// The largest `SpiceLinkReply` body accepted.
///
/// The reply's `size` is a `u32` arriving before anything has been
/// authenticated, so it needs a ceiling. A real reply is 174 bytes plus a
/// handful of capability words.
const MAX_REPLY_BODY: u32 = 64 * 1024;

/// Send the link message and read the reply, without authenticating.
///
/// Split out from [`link`] because `NEED_SECURED` has to be noticed *here*:
/// the answer to it is to drop this connection and dial the TLS port, which
/// the caller does rather than this function.
pub async fn exchange<S: Transport>(stream: &mut S, request: &LinkRequest) -> Result<LinkReply> {
    stream.write_all(&request.encode()).await?;
    stream.flush().await?;

    let mut header = [0u8; link_size::HEADER];
    stream.read_exact(&mut header).await?;
    let mut r = Reader::new(&header);
    let magic = r.u32()?;
    if magic != protocol::MAGIC {
        return Err(SpiceError::protocol(format!(
            "link reply magic {magic:#010x}, expected {:#010x}",
            protocol::MAGIC
        )));
    }
    let major = r.u32()?;
    let minor = r.u32()?;
    let size = r.u32()?;
    if major != protocol::VERSION_MAJOR {
        return Err(SpiceError::protocol(format!(
            "server speaks SPICE {major}.{minor}, this client speaks {}.{}",
            protocol::VERSION_MAJOR,
            protocol::VERSION_MINOR
        )));
    }
    if (size as usize) < link_size::REPLY || size > MAX_REPLY_BODY {
        return Err(SpiceError::protocol(format!(
            "link reply of {size} bytes is outside {}..={MAX_REPLY_BODY}",
            link_size::REPLY
        )));
    }

    let mut body = vec![0u8; size as usize];
    stream.read_exact(&mut body).await?;
    LinkReply::parse(&body)
}

/// Encrypt the ticket and read the link result.
///
/// Separate from [`exchange`] so a test can drive the two halves apart, and
/// because the TLS retry happens between them.
pub async fn authenticate<S: Transport>(
    stream: &mut S,
    reply: &LinkReply,
    password: &str,
) -> Result<()> {
    if password.len() > protocol::MAX_PASSWORD_LENGTH {
        return Err(SpiceError::Auth(format!(
            "password of {} bytes exceeds the protocol's {} byte limit",
            password.len(),
            protocol::MAX_PASSWORD_LENGTH
        )));
    }

    if reply.common_caps.has(common_cap::PROTOCOL_AUTH_SELECTION) {
        if !reply.common_caps.has(common_cap::AUTH_SPICE) {
            // SASL is the only other mechanism and it is not implemented;
            // saying so is better than sending a ticket the server will not
            // read.
            return Err(SpiceError::Auth(
                "server offers no mechanism this client implements (SASL only)".into(),
            ));
        }
        let mut selection = Writer::new();
        selection.u32(common_cap::AUTH_SPICE);
        stream.write_all(&selection.finish()).await?;
    }

    let ticket = encrypt_ticket(&reply.pub_key, password)?;
    stream.write_all(&ticket).await?;
    stream.flush().await?;

    let mut result = [0u8; 4];
    stream.read_exact(&mut result).await?;
    let result = u32::from_le_bytes(result);
    if result != 0 {
        return Err(SpiceError::Auth(format!(
            "ticket refused: {} ({result})",
            protocol::link_err_name(result)
        )));
    }
    Ok(())
}

/// Encrypt a password against the server's per-connection public key.
///
/// RSA-OAEP with MGF1-SHA-1 and an empty label -- OpenSSL's
/// `RSA_PKCS1_OAEP_PADDING` defaults, which is what `spice-gtk` relies on at
/// `spice-channel.c:1262-1276` without naming them. The plaintext includes
/// the terminating NUL.
pub fn encrypt_ticket(pub_key_der: &[u8], password: &str) -> Result<Vec<u8>> {
    let key = RsaPublicKey::from_public_key_der(pub_key_der)
        .map_err(|e| SpiceError::Auth(format!("server public key is not valid DER: {e}")))?;

    let mut plaintext = password.as_bytes().to_vec();
    plaintext.push(0);

    // `rsa` carries its own `rand_core`, a major version behind the one the
    // rest of the workspace uses; taking the OS RNG from `rsa` keeps the two
    // from having to agree.
    let mut rng = rsa::rand_core::OsRng;
    key.encrypt(&mut rng, Oaep::new::<sha1::Sha1>(), &plaintext)
        .map_err(|e| SpiceError::Auth(format!("encrypting the ticket: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::channel;

    #[test]
    fn the_link_message_puts_the_caps_where_the_offset_says() {
        let request = LinkRequest::new(0x11223344, channel::MAIN, 0);
        let bytes = request.encode();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.u32().unwrap(), protocol::MAGIC);
        assert_eq!(r.u32().unwrap(), 2);
        assert_eq!(r.u32().unwrap(), 2);
        let size = r.u32().unwrap() as usize;
        assert_eq!(bytes.len(), link_size::HEADER + size);

        let mess = &bytes[link_size::HEADER..];
        let mut m = Reader::new(mess);
        assert_eq!(m.u32().unwrap(), 0x11223344);
        assert_eq!(m.u8().unwrap(), channel::MAIN);
        assert_eq!(m.u8().unwrap(), 0);
        let num_common = m.u32().unwrap();
        let num_channel = m.u32().unwrap();
        let caps_offset = m.u32().unwrap() as usize;
        assert_eq!(num_common, 1);
        assert_eq!(num_channel, 0);
        assert_eq!(caps_offset, link_size::MESS);

        // The offset is from the start of SpiceLinkMess, not of the header.
        let word = u32::from_le_bytes(mess[caps_offset..caps_offset + 4].try_into().unwrap());
        let caps = Caps::from_words(vec![word]);
        assert!(caps.has(common_cap::MINI_HEADER));
        assert!(caps.has(common_cap::AUTH_SPICE));
        assert!(caps.has(common_cap::PROTOCOL_AUTH_SELECTION));
    }

    fn reply_bytes(error: u32, common: &[u32], channel: &[u32], caps_offset: usize) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(error).zeros(protocol::TICKET_PUBKEY_BYTES);
        w.u32(common.len() as u32)
            .u32(channel.len() as u32)
            .u32(caps_offset as u32);
        let mut body = w.finish();
        body.resize(caps_offset, 0);
        for word in common.iter().chain(channel.iter()) {
            body.extend_from_slice(&word.to_le_bytes());
        }
        body
    }

    #[test]
    fn a_reply_parses_its_capability_words() {
        let body = reply_bytes(
            0,
            &[1 << common_cap::MINI_HEADER],
            &[0b101],
            link_size::REPLY,
        );
        let reply = LinkReply::parse(&body).unwrap();
        assert_eq!(reply.error, 0);
        assert!(reply.mini_header());
        assert!(reply.channel_caps.has(0));
        assert!(reply.channel_caps.has(2));
        assert!(!reply.channel_caps.has(1));
    }

    #[test]
    fn a_caps_offset_past_the_reply_is_refused() {
        let mut body = reply_bytes(0, &[1], &[], link_size::REPLY);
        // Point the caps offset past the end.
        let offset_at = 4 + protocol::TICKET_PUBKEY_BYTES + 8;
        body[offset_at..offset_at + 4].copy_from_slice(&9999u32.to_le_bytes());
        assert!(LinkReply::parse(&body).is_err());
    }

    #[test]
    fn a_cap_count_larger_than_the_reply_is_refused_before_allocating() {
        let mut body = reply_bytes(0, &[1], &[], link_size::REPLY);
        let count_at = 4 + protocol::TICKET_PUBKEY_BYTES;
        body[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(LinkReply::parse(&body).is_err());
    }

    #[test]
    fn a_truncated_reply_is_an_error() {
        let body = reply_bytes(0, &[1], &[], link_size::REPLY);
        assert!(LinkReply::parse(&body[..body.len() - 8]).is_err());
        assert!(LinkReply::parse(&[]).is_err());
    }

    #[tokio::test]
    async fn exchange_refuses_a_reply_whose_magic_is_wrong() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let request = LinkRequest::new(0, channel::MAIN, 0);
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut scratch = vec![0u8; request.encode().len()];
            let _ = server.read_exact(&mut scratch).await;
            let mut header = Writer::new();
            header
                .u32(0xDEADBEEF)
                .u32(2)
                .u32(2)
                .u32(link_size::REPLY as u32);
            let _ = server.write_all(&header.finish()).await;
        });
        let request = LinkRequest::new(0, channel::MAIN, 0);
        let err = exchange(&mut client, &request).await.unwrap_err();
        assert!(matches!(err, SpiceError::Protocol(_)), "{err}");
    }

    #[tokio::test]
    async fn exchange_refuses_a_reply_body_too_short_to_be_one() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut scratch = vec![0u8; 64];
            let _ = server.read(&mut scratch).await;
            let mut header = Writer::new();
            header.u32(protocol::MAGIC).u32(2).u32(2).u32(4);
            let _ = server.write_all(&header.finish()).await;
        });
        let request = LinkRequest::new(0, channel::MAIN, 0);
        let err = exchange(&mut client, &request).await.unwrap_err();
        assert!(matches!(err, SpiceError::Protocol(_)), "{err}");
    }

    #[tokio::test]
    async fn a_password_past_the_protocol_limit_is_refused_before_any_crypto() {
        let reply = LinkReply {
            error: 0,
            pub_key: Vec::new(),
            common_caps: Caps::new(),
            channel_caps: Caps::new(),
        };
        let long = "x".repeat(protocol::MAX_PASSWORD_LENGTH + 1);
        let (mut client, _server) = tokio::io::duplex(64);
        let err = authenticate(&mut client, &reply, &long).await;
        assert!(matches!(err, Err(SpiceError::Auth(_))));
    }

    #[test]
    fn a_public_key_that_is_not_der_fails_rather_than_panicking() {
        assert!(encrypt_ticket(&[0u8; 162], "hunter2").is_err());
    }
}
