//! A deliberately minimal, deliberately pedantic SPICE server.
//!
//! `docs/testing.md` §4.1 asks for this for the same reason §3.2 asks for a
//! mock RFB server: the only SPICE server in the world is `spice-server`, and
//! a client tested solely against it codes to its habits. A mock is also the
//! only way to produce the things a real server never sends -- a truncated
//! `SpiceLinkMess`, the wrong `connection_id` on a secondary channel, a
//! `SpiceDataHeader` whose `size` overruns the payload, a server that stops
//! honouring its own ack window.
//!
//! It is a real link peer: it mints an RSA key, hands over the DER public
//! key, and decrypts the ticket the client sends back, so the OAEP path is
//! exercised rather than stubbed.
//!
//! What it deliberately does **not** do:
//!
//! * no full header -- mini only, unless [`MockConfig::mini_header`] says
//!   otherwise, so both framings get used;
//! * no image compression at all: every bitmap is raw, which is the
//!   `--image-compression off` baseline M3 is built against;
//! * no video streams unless a test pushes one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rsa::pkcs8::EncodePublicKey;
use rsa::{Oaep, RsaPrivateKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::channel::{frame, OutMessage};
use crate::error::{Result, SpiceError};
use crate::protocol::{
    self, channel as channel_type, common_cap, display_msg, link_size, main_msg, msg, Caps,
};
use crate::wire::{Reader, Writer};

/// A message the mock saw from the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recorded {
    /// Which channel it arrived on.
    pub channel: u8,
    /// The type number.
    pub kind: u16,
    /// The body.
    pub body: Vec<u8>,
}

/// How the mock should misbehave, or not.
#[derive(Clone, Debug)]
pub struct MockConfig {
    /// The ticket password the mock will accept. `None` accepts any.
    pub password: Option<String>,
    /// Whether to agree to the mini header.
    pub mini_header: bool,
    /// Whether to advertise `PROTOCOL_AUTH_SELECTION`.
    pub auth_selection: bool,
    /// The `connection_id` the mock hands out in `MAIN_INIT`.
    pub connection_id: u32,
    /// The channels `CHANNELS_LIST` names.
    pub channels: Vec<(u8, u8)>,
    /// The primary surface's size.
    pub width: u32,
    /// The primary surface's size.
    pub height: u32,
    /// The ack window to set, or zero for none.
    pub ack_window: u32,
    /// Whether to claim a guest agent.
    pub agent: bool,
    /// Mouse modes to advertise.
    pub mouse_modes: u32,
    /// The mouse mode in force at `MAIN_INIT`.
    pub mouse_mode: u32,
    /// Send a link reply with this error instead of success.
    pub link_error: Option<u32>,
    /// Claim a message body longer than the bytes that follow it.
    pub overrun_message: bool,
}

impl Default for MockConfig {
    fn default() -> Self {
        MockConfig {
            password: None,
            mini_header: true,
            auth_selection: true,
            connection_id: 0x5EED,
            channels: vec![
                (channel_type::MAIN, 0),
                (channel_type::DISPLAY, 0),
                (channel_type::INPUTS, 0),
                (channel_type::CURSOR, 0),
            ],
            width: 64,
            height: 48,
            ack_window: 0,
            agent: false,
            mouse_modes: protocol::mouse_mode::SERVER | protocol::mouse_mode::CLIENT,
            mouse_mode: protocol::mouse_mode::SERVER,
            link_error: None,
            overrun_message: false,
        }
    }
}

/// Something for the mock to send on a channel, pushed by a test.
#[derive(Clone, Debug)]
pub struct MockPush {
    /// Which channel type to send it on.
    pub channel: u8,
    /// The message.
    pub message: OutMessage,
}

/// The mock server.
pub struct MockServer {
    config: MockConfig,
    key: RsaPrivateKey,
    recorded: Arc<Mutex<Vec<Recorded>>>,
    pushes: Arc<Mutex<HashMap<u8, mpsc::UnboundedSender<OutMessage>>>>,
}

impl MockServer {
    /// Build one, minting the per-session RSA key.
    ///
    /// 1024 bits, which is what the protocol specifies
    /// (`protocol.h:45`) and is also why the workspace optimises `rsa` even
    /// in debug builds: unoptimised key generation takes seconds.
    pub fn new(config: MockConfig) -> Self {
        let mut rng = rsa::rand_core::OsRng;
        let key = RsaPrivateKey::new(&mut rng, protocol::TICKET_KEY_BITS)
            .expect("generating a 1024-bit RSA key");
        MockServer {
            config,
            key,
            recorded: Arc::new(Mutex::new(Vec::new())),
            pushes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Everything the client has sent, in order.
    pub fn recorded(&self) -> Arc<Mutex<Vec<Recorded>>> {
        self.recorded.clone()
    }

    /// Messages the client sent on one channel.
    pub fn messages_on(&self, channel: u8) -> Vec<Recorded> {
        self.recorded
            .lock()
            .expect("recorder lock")
            .iter()
            .filter(|r| r.channel == channel)
            .cloned()
            .collect()
    }

    /// Push a message onto a channel the client has already linked.
    ///
    /// Returns false when that channel is not connected yet.
    pub fn push(&self, push: MockPush) -> bool {
        let pushes = self.pushes.lock().expect("push lock");
        match pushes.get(&push.channel) {
            Some(sender) => sender.send(push.message).is_ok(),
            None => false,
        }
    }

    /// Serve one connection.
    pub async fn serve<S>(&self, stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let link = self.link(&mut reader, &mut writer).await?;
        if self.config.link_error.is_some() {
            return Ok(());
        }

        let (push_tx, mut push_rx) = mpsc::unbounded_channel::<OutMessage>();
        self.pushes
            .lock()
            .expect("push lock")
            .insert(link.channel_type, push_tx);

        let mini = link.mini;
        let mut serial = 1u64;
        for message in self.opening_messages(link.channel_type) {
            writer
                .write_all(&frame(mini, serial, message.kind, &message.body))
                .await?;
            serial += 1;
        }
        if self.config.overrun_message {
            // A header claiming more than follows it. The client should
            // notice at the read rather than running on into the next
            // message.
            writer
                .write_all(&frame(mini, serial, display_msg::MARK, &[]).as_slice()[..2])
                .await?;
            writer.write_all(&u32::MAX.to_le_bytes()).await?;
            writer.flush().await?;
            return Ok(());
        }
        writer.flush().await?;

        let channel = link.channel_type;
        let recorded = self.recorded.clone();
        let config = self.config.clone();

        // Reading the client and pushing to it run concurrently: a test that
        // queues a frame should not have to wait for the client to speak.
        let read = async {
            loop {
                let Some((kind, body)) = read_message(&mut reader, mini).await? else {
                    return Ok::<(), SpiceError>(());
                };
                recorded.lock().expect("recorder lock").push(Recorded {
                    channel,
                    kind,
                    body: body.clone(),
                });
                for reply in answer(&config, channel, kind, &body) {
                    let _ = push_tx_clone(&self.pushes, channel, reply);
                }
            }
        };
        let write = async {
            while let Some(message) = push_rx.recv().await {
                writer
                    .write_all(&frame(mini, serial, message.kind, &message.body))
                    .await?;
                serial += 1;
                writer.flush().await?;
            }
            Ok::<(), SpiceError>(())
        };

        tokio::select! {
            result = read => result,
            result = write => result,
        }
    }

    fn opening_messages(&self, channel: u8) -> Vec<OutMessage> {
        let mut out = Vec::new();
        if self.config.ack_window > 0 {
            let mut w = Writer::new();
            w.u32(0xA11CE).u32(self.config.ack_window);
            out.push(OutMessage::new(msg::SET_ACK, w.finish()));
        }
        match channel {
            channel_type::MAIN => {
                let mut init = Writer::new();
                init.u32(self.config.connection_id)
                    .u32(1)
                    .u32(self.config.mouse_modes)
                    .u32(self.config.mouse_mode)
                    .u32(u32::from(self.config.agent))
                    .u32(10)
                    .u32(0)
                    .u32(0);
                out.push(OutMessage::new(main_msg::INIT, init.finish()));

                let mut list = Writer::new();
                list.u32(self.config.channels.len() as u32);
                for (kind, id) in &self.config.channels {
                    list.u8(*kind).u8(*id);
                }
                out.push(OutMessage::new(main_msg::CHANNELS_LIST, list.finish()));
            }
            channel_type::DISPLAY => {
                let mut create = Writer::new();
                create
                    .u32(0)
                    .u32(self.config.width)
                    .u32(self.config.height)
                    .u32(protocol::surface_fmt::RGB32_XRGB)
                    .u32(protocol::surface_flags::PRIMARY);
                out.push(OutMessage::new(
                    display_msg::SURFACE_CREATE,
                    create.finish(),
                ));
                out.push(OutMessage::empty(display_msg::MARK));
            }
            channel_type::INPUTS => {
                let mut init = Writer::new();
                init.u16(0);
                out.push(OutMessage::new(protocol::inputs_msg::INIT, init.finish()));
            }
            _ => {}
        }
        out
    }

    async fn link<R, W>(&self, reader: &mut R, writer: &mut W) -> Result<LinkedAs>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut header = [0u8; link_size::HEADER];
        reader.read_exact(&mut header).await?;
        let mut r = Reader::new(&header);
        let magic = r.u32()?;
        if magic != protocol::MAGIC {
            return Err(SpiceError::protocol("client sent the wrong magic"));
        }
        let _major = r.u32()?;
        let _minor = r.u32()?;
        let size = r.u32()? as usize;
        if size < link_size::MESS {
            return Err(SpiceError::protocol(
                "client sent a truncated SpiceLinkMess",
            ));
        }

        let mut body = vec![0u8; size];
        reader.read_exact(&mut body).await?;
        let mut m = Reader::new(&body);
        let connection_id = m.u32()?;
        let channel_type = m.u8()?;
        let _channel_id = m.u8()?;
        let num_common = m.u32()?;
        let _num_channel = m.u32()?;
        let caps_offset = m.u32()? as usize;

        let mut caps = m.at(caps_offset)?;
        let mut words = Vec::new();
        for _ in 0..caps.count(num_common, 4)? {
            words.push(caps.u32()?);
        }
        let client_common = Caps::from_words(words);

        // Every channel but the first must present the id the main channel
        // was given. This is one of the negative cases `docs/testing.md`
        // §4.1 names.
        if channel_type != channel_type::MAIN && connection_id != self.config.connection_id {
            self.write_reply(writer, 8).await?;
            return Err(SpiceError::protocol(format!(
                "channel {channel_type} linked with connection id {connection_id:#x}, \
                 expected {:#x}",
                self.config.connection_id
            )));
        }

        if let Some(error) = self.config.link_error {
            self.write_reply(writer, error).await?;
            return Ok(LinkedAs {
                channel_type,
                mini: false,
            });
        }

        self.write_reply(writer, 0).await?;

        if self.config.auth_selection {
            let mut mechanism = [0u8; 4];
            reader.read_exact(&mut mechanism).await?;
            let mechanism = u32::from_le_bytes(mechanism);
            if mechanism != common_cap::AUTH_SPICE {
                return Err(SpiceError::Auth(format!(
                    "client chose auth mechanism {mechanism}"
                )));
            }
        }

        let mut ticket = vec![0u8; protocol::TICKET_BYTES];
        reader.read_exact(&mut ticket).await?;
        let plaintext = self
            .key
            .decrypt(Oaep::new::<sha1::Sha1>(), &ticket)
            .map_err(|e| SpiceError::Auth(format!("the ticket did not decrypt: {e}")))?;
        // The client encrypts the password with its NUL terminator.
        let password = String::from_utf8_lossy(&plaintext)
            .trim_end_matches('\0')
            .to_string();
        let accepted = match &self.config.password {
            None => true,
            Some(expected) => &password == expected,
        };
        let result: u32 = if accepted { 0 } else { 7 };
        writer.write_all(&result.to_le_bytes()).await?;
        writer.flush().await?;
        if !accepted {
            return Err(SpiceError::Auth("wrong password".into()));
        }

        Ok(LinkedAs {
            channel_type,
            mini: self.config.mini_header && client_common.has(common_cap::MINI_HEADER),
        })
    }

    async fn write_reply<W: AsyncWrite + Unpin>(&self, writer: &mut W, error: u32) -> Result<()> {
        let der = self
            .key
            .to_public_key()
            .to_public_key_der()
            .expect("encoding the public key");
        let der = der.as_bytes();

        let mut caps = Caps::new();
        if self.config.auth_selection {
            caps.set(common_cap::PROTOCOL_AUTH_SELECTION);
            caps.set(common_cap::AUTH_SPICE);
        }
        if self.config.mini_header {
            caps.set(common_cap::MINI_HEADER);
        }
        let words = caps.words();

        let mut reply = Writer::new();
        reply.u32(error);
        // The DER encoding of a 1024-bit key is 162 bytes, which is what the
        // protocol's fixed-size field expects.
        let mut key_field = der.to_vec();
        key_field.resize(protocol::TICKET_PUBKEY_BYTES, 0);
        reply.bytes(&key_field);
        reply
            .u32(words.len() as u32)
            .u32(0)
            .u32(link_size::REPLY as u32);
        let mut body = reply.finish();
        body.resize(link_size::REPLY, 0);
        for word in words {
            body.extend_from_slice(&word.to_le_bytes());
        }

        let mut header = Writer::new();
        header
            .u32(protocol::MAGIC)
            .u32(protocol::VERSION_MAJOR)
            .u32(protocol::VERSION_MINOR)
            .u32(body.len() as u32);
        writer.write_all(&header.finish()).await?;
        writer.write_all(&body).await?;
        writer.flush().await?;
        Ok(())
    }
}

struct LinkedAs {
    channel_type: u8,
    mini: bool,
}

fn push_tx_clone(
    pushes: &Arc<Mutex<HashMap<u8, mpsc::UnboundedSender<OutMessage>>>>,
    channel: u8,
    message: OutMessage,
) -> bool {
    pushes
        .lock()
        .expect("push lock")
        .get(&channel)
        .is_some_and(|sender| sender.send(message).is_ok())
}

/// What the mock answers a client message with.
fn answer(config: &MockConfig, channel: u8, kind: u16, _body: &[u8]) -> Vec<OutMessage> {
    match (channel, kind) {
        (channel_type::MAIN, crate::protocol::main_msgc::MOUSE_MODE_REQUEST) => {
            // Granting client mode is how a test gets absolute positions.
            if config.mouse_modes & protocol::mouse_mode::CLIENT != 0 {
                let mut w = Writer::new();
                w.u16(config.mouse_modes as u16)
                    .u16(protocol::mouse_mode::CLIENT as u16);
                vec![OutMessage::new(main_msg::MOUSE_MODE, w.finish())]
            } else {
                Vec::new()
            }
        }
        (channel_type::MAIN, crate::protocol::main_msgc::AGENT_START) if config.agent => {
            // Announce the guest agent's capabilities so a resize can be
            // tested.
            let caps = crate::agent::announce_capabilities(false);
            let mut w = Writer::new();
            w.u32(crate::agent::PROTOCOL)
                .u32(crate::agent::msg::ANNOUNCE_CAPABILITIES)
                .u64(0)
                .u32(caps.len() as u32)
                .bytes(&caps);
            vec![OutMessage::new(main_msg::AGENT_DATA, w.finish())]
        }
        _ => Vec::new(),
    }
}

async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    mini: bool,
) -> Result<Option<(u16, Vec<u8>)>> {
    let header_len = if mini {
        crate::channel::MINI_HEADER
    } else {
        crate::channel::FULL_HEADER
    };
    let mut header = vec![0u8; header_len];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let mut r = Reader::new(&header);
    let (kind, size) = if mini {
        (r.u16()?, r.u32()?)
    } else {
        let _serial = r.u64()?;
        let kind = r.u16()?;
        let size = r.u32()?;
        let _sub_list = r.u32()?;
        (kind, size)
    };
    if size > 64 * 1024 * 1024 {
        return Err(SpiceError::limit("client message too large"));
    }
    let mut body = vec![0u8; size as usize];
    reader.read_exact(&mut body).await?;
    Ok(Some((kind, body)))
}

/// Build a `DRAW_FILL` the mock can push, filling a rectangle with a colour.
pub fn draw_fill(
    surface_id: u32,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    colour: u32,
) -> OutMessage {
    let mut w = Writer::new();
    w.u32(surface_id);
    w.i32(top).i32(left).i32(bottom).i32(right);
    w.u8(protocol::clip_type::NONE);
    w.u8(protocol::brush_type::SOLID).u32(colour);
    w.u16(protocol::ropd::OP_PUT);
    w.u8(0).i32(0).i32(0).u32(0);
    OutMessage::new(display_msg::DRAW_FILL, w.finish())
}

/// Build a `MOUSE_MOTION_ACK`, which is how a test releases the input
/// channel's flow-control window.
pub fn motion_ack() -> OutMessage {
    OutMessage::empty(protocol::inputs_msg::MOUSE_MOTION_ACK)
}

/// Build a `CURSOR_SET` carrying a solid alpha cursor.
pub fn cursor_set(x: i16, y: i16, width: u16, height: u16, colour: [u8; 4]) -> OutMessage {
    let mut w = Writer::new();
    w.u16(x as u16).u16(y as u16).u8(1);
    w.u16(0); // flags: not cached, not none
    w.u64(1)
        .u8(protocol::cursor_type::ALPHA)
        .u16(width)
        .u16(height)
        .u16(0)
        .u16(0);
    for _ in 0..(width as usize * height as usize) {
        w.bytes(&colour);
    }
    OutMessage::new(protocol::cursor_msg::SET, w.finish())
}
