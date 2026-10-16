//! The guest agent, tunnelled through the main channel.
//!
//! `spice-vdagent` runs inside the guest and is reached by wrapping its
//! messages in `MAIN_AGENT_DATA` (`docs/spice-protocol.md` §4.2). It is what
//! makes the SPICE backend better than the RFB one rather than merely
//! different: **`MONITORS_CONFIG` resizes the guest**, so Moonlight's
//! requested mode is matched exactly instead of letterboxed, and client-mode
//! absolute mouse needs it too.
//!
//! All three of those degrade when the agent is absent, which is a supported
//! state rather than a failure: `--vdagent` is a flag on `Xspice` and plenty
//! of guests do not run one.
//!
//! # Framing
//!
//! A `VDAgentMessage` -- `protocol`, `type`, `opaque`, `size`, then the body
//! -- is written straight into the `AGENT_DATA` body and split at
//! `VD_AGENT_MAX_DATA_SIZE` (2048) boundaries, **header included in the
//! first chunk's budget** (`channel-main.c:1001`). There is no `VDIChunkHeader`
//! on this hop; that one belongs to the server-to-guest virtio link.
//!
//! Each outgoing chunk spends one token. Tokens arrive with `MAIN_INIT` and
//! are replenished by `MAIN_AGENT_TOKEN`, and sending without them is how a
//! client wedges the agent.

use std::collections::VecDeque;

use crate::channel::OutMessage;
use crate::error::{Result, SpiceError};
use crate::protocol::main_msgc;
use crate::wire::{Reader, Writer};

/// `VD_AGENT_PROTOCOL` (`vd_agent.h:61`).
pub const PROTOCOL: u32 = 1;
/// `VD_AGENT_MAX_DATA_SIZE` (`vd_agent.h:62`): the chunk size.
pub const MAX_DATA_SIZE: usize = 2048;
/// Bytes of `VDAgentMessage` before its payload.
pub const MESSAGE_HEADER: usize = 4 + 4 + 8 + 4;

/// Agent message types (`vd_agent.h:67-121`).
pub mod msg {
    #![allow(missing_docs)]
    pub const MOUSE_STATE: u32 = 1;
    pub const MONITORS_CONFIG: u32 = 2;
    pub const REPLY: u32 = 3;
    pub const CLIPBOARD: u32 = 4;
    pub const DISPLAY_CONFIG: u32 = 5;
    pub const ANNOUNCE_CAPABILITIES: u32 = 6;
    pub const CLIPBOARD_GRAB: u32 = 7;
    pub const CLIPBOARD_REQUEST: u32 = 8;
    pub const CLIPBOARD_RELEASE: u32 = 9;
    pub const FILE_XFER_START: u32 = 10;
    pub const FILE_XFER_STATUS: u32 = 11;
    pub const FILE_XFER_DATA: u32 = 12;
    pub const CLIENT_DISCONNECTED: u32 = 13;
    pub const MAX_CLIPBOARD: u32 = 14;
    pub const AUDIO_VOLUME_SYNC: u32 = 15;
    pub const GRAPHICS_DEVICE_INFO: u32 = 16;
}

/// Agent capability bits (`vd_agent.h:367-396`).
pub mod cap {
    #![allow(missing_docs)]
    pub const MOUSE_STATE: u32 = 0;
    pub const MONITORS_CONFIG: u32 = 1;
    pub const REPLY: u32 = 2;
    pub const CLIPBOARD: u32 = 3;
    pub const DISPLAY_CONFIG: u32 = 4;
    pub const CLIPBOARD_BY_DEMAND: u32 = 5;
    pub const CLIPBOARD_SELECTION: u32 = 6;
    pub const SPARSE_MONITORS_CONFIG: u32 = 7;
    pub const GUEST_LINEEND_LF: u32 = 8;
    pub const GUEST_LINEEND_CRLF: u32 = 9;
    pub const MAX_CLIPBOARD: u32 = 10;
    pub const AUDIO_VOLUME_SYNC: u32 = 11;
    pub const MONITORS_CONFIG_POSITION: u32 = 12;
    pub const FILE_XFER_DISABLED: u32 = 13;
    pub const FILE_XFER_DETAILED_ERRORS: u32 = 14;
    pub const GRAPHICS_DEVICE_INFO: u32 = 15;
}

/// Clipboard payload types (`vd_agent.h:285-296`).
pub mod clipboard_type {
    #![allow(missing_docs)]
    pub const NONE: u32 = 0;
    pub const UTF8_TEXT: u32 = 1;
    pub const IMAGE_PNG: u32 = 2;
    pub const IMAGE_BMP: u32 = 3;
    pub const IMAGE_TIFF: u32 = 4;
    pub const IMAGE_JPG: u32 = 5;
    pub const FILE_LIST: u32 = 6;
}

/// A clipboard payload type this client is willing to name.
///
/// `FILE_LIST` is deliberately absent. It names files the guest then expects
/// to pull across with `FILE_XFER_START`, and file transfer is not
/// implemented -- so claiming to understand the type would strand the guest
/// waiting for a transfer that never begins. `NONE` is absent for a
/// different reason: it is not a type but the answer "there is nothing", and
/// it is carried by [`crate::backend::ClipboardEvent::Unavailable`] instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ClipboardType {
    /// `VD_AGENT_CLIPBOARD_UTF8_TEXT`.
    Utf8Text,
    /// `VD_AGENT_CLIPBOARD_IMAGE_PNG`.
    Png,
    /// `VD_AGENT_CLIPBOARD_IMAGE_BMP`.
    Bmp,
    /// `VD_AGENT_CLIPBOARD_IMAGE_TIFF`.
    Tiff,
    /// `VD_AGENT_CLIPBOARD_IMAGE_JPG`.
    Jpeg,
}

impl ClipboardType {
    /// Read one off the wire, or `None` for a type this client will not
    /// claim to handle.
    pub fn from_wire(raw: u32) -> Option<Self> {
        Some(match raw {
            clipboard_type::UTF8_TEXT => ClipboardType::Utf8Text,
            clipboard_type::IMAGE_PNG => ClipboardType::Png,
            clipboard_type::IMAGE_BMP => ClipboardType::Bmp,
            clipboard_type::IMAGE_TIFF => ClipboardType::Tiff,
            clipboard_type::IMAGE_JPG => ClipboardType::Jpeg,
            _ => return None,
        })
    }

    /// The `VD_AGENT_CLIPBOARD_*` number.
    pub fn to_wire(self) -> u32 {
        match self {
            ClipboardType::Utf8Text => clipboard_type::UTF8_TEXT,
            ClipboardType::Png => clipboard_type::IMAGE_PNG,
            ClipboardType::Bmp => clipboard_type::IMAGE_BMP,
            ClipboardType::Tiff => clipboard_type::IMAGE_TIFF,
            ClipboardType::Jpeg => clipboard_type::IMAGE_JPG,
        }
    }
}

/// `VD_AGENT_SUCCESS` (`vd_agent.h:265-268`).
pub const REPLY_SUCCESS: u32 = 1;

/// The largest reassembled agent message this client will hold.
///
/// `VDAgentMessage.size` is a `u32` and the chunks that fill it arrive one
/// token at a time, so without a ceiling a server can make the client buffer
/// without bound. Clipboard contents are the only thing that legitimately
/// gets large, and a megabyte of it is already generous.
pub const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

/// The largest clipboard payload this client will send or accept.
///
/// [`MAX_MESSAGE_SIZE`] minus the four bytes `VDAgentClipboard` spends on
/// the type, because `VD_AGENT_MAX_CLIPBOARD` counts the payload and not the
/// word in front of it.
pub const MAX_CLIPBOARD_PAYLOAD: u32 = MAX_MESSAGE_SIZE - 4;

/// A reassembled agent message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentMessage {
    /// `VD_AGENT_*`.
    pub kind: u32,
    /// The payload.
    pub body: Vec<u8>,
}

/// The client's half of the agent link.
pub struct Agent {
    connected: bool,
    tokens: u32,
    queue: VecDeque<OutMessage>,
    /// Partially reassembled inbound message.
    partial: Option<(u32, u32, Vec<u8>)>,
    /// What the guest's agent said it supports.
    guest_caps: crate::protocol::Caps,
    /// Whether the guest has announced at all.
    announced: bool,
}

impl Default for Agent {
    fn default() -> Self {
        Agent::new()
    }
}

impl Agent {
    /// A disconnected agent.
    pub fn new() -> Self {
        Agent {
            connected: false,
            tokens: 0,
            queue: VecDeque::new(),
            partial: None,
            guest_caps: crate::protocol::Caps::new(),
            announced: false,
        }
    }

    /// Whether the guest has an agent running.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Whether the guest announced a capability.
    pub fn guest_has(&self, bit: u32) -> bool {
        self.announced && self.guest_caps.has(bit)
    }

    /// Whether a resize request can be honoured.
    pub fn can_resize(&self) -> bool {
        self.is_connected() && self.guest_has(cap::MONITORS_CONFIG)
    }

    /// Whether clipboard messages can be exchanged.
    ///
    /// `CLIPBOARD_BY_DEMAND` alone, and deliberately **not** `CLIPBOARD` as
    /// well. The bare bit means the superseded flow where a grab carries the
    /// payload with it; the grab/request/data exchange implemented here is
    /// the by-demand one. A real `spice-vdagent` announces only the latter
    /// -- `vdagentd.c`'s `send_capabilities` never sets `CLIPBOARD` -- so a
    /// gate that wanted both would refuse every guest in existence. That is
    /// not a deduction: requiring both is what the first draft of this did,
    /// and the real agent in `a_real_agent_hands_over_the_guests_clipboard`
    /// is what caught it. `spice-gtk` gates on the same single bit.
    pub fn can_clipboard(&self) -> bool {
        self.is_connected() && self.guest_has(cap::CLIPBOARD_BY_DEMAND)
    }

    /// Tokens currently held.
    pub fn tokens(&self) -> u32 {
        self.tokens
    }

    /// The agent came up. Returns the messages to send: `AGENT_START` and
    /// this client's capability announcement.
    pub fn connect(&mut self, tokens: u32) -> Vec<OutMessage> {
        self.connected = true;
        self.tokens = tokens;
        self.partial = None;
        self.announced = false;
        self.guest_caps = crate::protocol::Caps::new();

        let mut out = Vec::new();
        let mut start = Writer::new();
        // `channel-main.c:1605` asks for all of them.
        start.u32(u32::MAX);
        out.push(OutMessage::new(main_msgc::AGENT_START, start.finish()));
        self.queue_message(msg::ANNOUNCE_CAPABILITIES, &announce_capabilities(true));
        out.extend(self.drain());
        out
    }

    /// The agent went away.
    pub fn disconnect(&mut self) {
        self.connected = false;
        self.tokens = 0;
        self.queue.clear();
        self.partial = None;
        self.announced = false;
    }

    /// `MAIN_AGENT_TOKEN`: more budget.
    pub fn add_tokens(&mut self, tokens: u32) -> Vec<OutMessage> {
        self.tokens = self.tokens.saturating_add(tokens);
        self.drain()
    }

    /// Queue a message and return whatever that made sendable.
    pub fn send(&mut self, kind: u32, body: &[u8]) -> Vec<OutMessage> {
        if !self.connected {
            return Vec::new();
        }
        self.queue_message(kind, body);
        self.drain()
    }

    /// Ask the guest to change resolution.
    ///
    /// One head at the origin, 32 bits deep. `VD_AGENT_CONFIG_MONITORS_FLAG_USE_POS`
    /// is not set: with a single monitor the position is implied, and setting
    /// it would need the guest to have announced
    /// `MONITORS_CONFIG_POSITION`.
    pub fn request_resize(&mut self, width: u32, height: u32) -> Vec<OutMessage> {
        if !self.can_resize() {
            return Vec::new();
        }
        let mut w = Writer::new();
        w.u32(1) // num_of_monitors
            .u32(0); // flags
        w.u32(height).u32(width).u32(32).i32(0).i32(0);
        self.send(msg::MONITORS_CONFIG, &w.finish())
    }

    /// Tell the guest the largest clipboard payload this client will accept.
    ///
    /// Worth sending rather than relying on [`MAX_MESSAGE_SIZE`] alone. That
    /// ceiling is enforced on arrival, and arriving past it ends the channel
    /// -- the reassembler has no way to walk past a message it refused to
    /// buffer. `VD_AGENT_MAX_CLIPBOARD` moves the enforcement into the
    /// guest, where an oversized selection is simply never sent. Without it
    /// a large copy inside the guest would cost the session.
    pub fn max_clipboard(&mut self) -> Vec<OutMessage> {
        if !self.is_connected() || !self.guest_has(cap::MAX_CLIPBOARD) {
            return Vec::new();
        }
        let mut w = Writer::new();
        w.i32(MAX_CLIPBOARD_PAYLOAD as i32);
        self.send(msg::MAX_CLIPBOARD, &w.finish())
    }

    /// Offer the guest this client's clipboard in these types.
    pub fn clipboard_grab(&mut self, types: &[u32]) -> Vec<OutMessage> {
        if !self.can_clipboard() {
            return Vec::new();
        }
        let mut w = Writer::new();
        for kind in types {
            w.u32(*kind);
        }
        self.send(msg::CLIPBOARD_GRAB, &w.finish())
    }

    /// Ask the guest for the clipboard in a type it offered.
    pub fn clipboard_request(&mut self, kind: u32) -> Vec<OutMessage> {
        if !self.can_clipboard() {
            return Vec::new();
        }
        let mut w = Writer::new();
        w.u32(kind);
        self.send(msg::CLIPBOARD_REQUEST, &w.finish())
    }

    /// Send the clipboard to the guest, in answer to a request.
    ///
    /// `kind` may be [`clipboard_type::NONE`] with an empty payload, which
    /// is how the protocol says "the offer cannot be honoured after all" --
    /// and saying it matters, because the guest's paste blocks until
    /// something answers.
    pub fn clipboard_data(&mut self, kind: u32, data: &[u8]) -> Result<Vec<OutMessage>> {
        if data.len() > MAX_CLIPBOARD_PAYLOAD as usize {
            return Err(SpiceError::limit(format!(
                "a clipboard payload of {} bytes exceeds the {MAX_CLIPBOARD_PAYLOAD} byte ceiling",
                data.len()
            )));
        }
        if !self.can_clipboard() {
            return Ok(Vec::new());
        }
        let mut w = Writer::new();
        w.u32(kind).bytes(data);
        Ok(self.send(msg::CLIPBOARD, &w.finish()))
    }

    /// Take back a clipboard offer.
    pub fn clipboard_release(&mut self) -> Vec<OutMessage> {
        if !self.can_clipboard() {
            return Vec::new();
        }
        self.send(msg::CLIPBOARD_RELEASE, &[])
    }

    fn queue_message(&mut self, kind: u32, body: &[u8]) {
        let mut header = Writer::with_capacity(MESSAGE_HEADER);
        header
            .u32(PROTOCOL)
            .u32(kind)
            .u64(0) // opaque
            .u32(body.len() as u32);
        let mut whole = header.finish();
        whole.extend_from_slice(body);

        for chunk in whole.chunks(MAX_DATA_SIZE) {
            self.queue
                .push_back(OutMessage::new(main_msgc::AGENT_DATA, chunk.to_vec()));
        }
    }

    /// Spend tokens on whatever is queued.
    fn drain(&mut self) -> Vec<OutMessage> {
        let mut out = Vec::new();
        while self.tokens > 0 {
            let Some(message) = self.queue.pop_front() else {
                break;
            };
            self.tokens -= 1;
            out.push(message);
        }
        out
    }

    /// Feed one `MAIN_AGENT_DATA` body in, and get back a whole agent
    /// message if this chunk completed one.
    pub fn receive(&mut self, data: &[u8]) -> Result<Option<AgentMessage>> {
        if let Some((kind, size, mut body)) = self.partial.take() {
            let want = size as usize - body.len();
            body.extend_from_slice(&data[..data.len().min(want)]);
            if body.len() as u32 == size {
                return Ok(Some(AgentMessage { kind, body }));
            }
            self.partial = Some((kind, size, body));
            return Ok(None);
        }

        if data.is_empty() {
            return Ok(None);
        }
        let mut r = Reader::new(data);
        let protocol = r.u32()?;
        let kind = r.u32()?;
        let _opaque = r.u64()?;
        let size = r.u32()?;
        if protocol != PROTOCOL {
            return Err(SpiceError::protocol(format!(
                "agent message with protocol {protocol}, expected {PROTOCOL}"
            )));
        }
        if size > MAX_MESSAGE_SIZE {
            return Err(SpiceError::limit(format!(
                "agent message of {size} bytes exceeds the {MAX_MESSAGE_SIZE} byte ceiling"
            )));
        }
        let rest = &data[MESSAGE_HEADER..];
        let take = rest.len().min(size as usize);
        let mut body = Vec::with_capacity(take);
        body.extend_from_slice(&rest[..take]);
        if body.len() as u32 == size {
            if rest.len() > take {
                // More than one message in a chunk is legal, and
                // `spice-server` does not do it. Saying so beats losing the
                // second one silently.
                tracing::debug!(
                    trailing = rest.len() - take,
                    "more than one agent message in a chunk"
                );
            }
            return Ok(Some(AgentMessage { kind, body }));
        }
        self.partial = Some((kind, size, body));
        Ok(None)
    }

    /// Record a guest capability announcement.
    pub fn note_capabilities(&mut self, body: &[u8]) -> Result<bool> {
        let mut r = Reader::new(body);
        let request = r.u32()?;
        let mut words = Vec::new();
        while r.remaining() >= 4 {
            words.push(r.u32()?);
        }
        self.guest_caps = crate::protocol::Caps::from_words(words);
        self.announced = true;
        Ok(request != 0)
    }
}

/// Build a `VDAgentAnnounceCapabilities` body.
///
/// `request` asks the other end to announce back. The capability set is the
/// honest one: monitors config and the clipboard, which this client
/// implements, and nothing else -- announcing a capability a client does not
/// have is how a guest ends up waiting for a reply that never comes.
///
/// `CLIPBOARD` is absent for that reason and not by oversight: it names the
/// superseded flow in which a grab carries the payload with it, which this
/// client neither sends nor would know what to do with. `CLIPBOARD_BY_DEMAND`
/// is the grab/request/data exchange, and it is the only clipboard bit a real
/// `spice-vdagent` or `spice-gtk` sets either.
///
/// `CLIPBOARD_SELECTION` is the notable absentee, and its absence is load
/// bearing rather than incidental. With it, every clipboard message gains a
/// four-byte `VDAgentClipboardSelection` prefix naming X11's `CLIPBOARD` or
/// `PRIMARY`, and `spice-vdagent` decides whether to write that prefix from
/// *this* announcement (`vdagentd.c` reads the client's capabilities, not
/// its own). Leaving it out therefore keeps the unprefixed framing on both
/// directions, and the selection defaults to `CLIPBOARD` -- the one a paste
/// uses. `PRIMARY` is X11's middle-click selection, which no GameStream
/// client has a way to ask for.
pub fn announce_capabilities(request: bool) -> Vec<u8> {
    let caps = crate::protocol::Caps::from_bits(&[
        cap::MONITORS_CONFIG,
        cap::CLIPBOARD_BY_DEMAND,
        cap::MAX_CLIPBOARD,
        cap::REPLY,
    ]);
    let mut w = Writer::new();
    w.u32(u32::from(request));
    // `VD_AGENT_CAPS_SIZE`: one word for every 32 capability bits the
    // protocol defines, whether or not this client sets any of them.
    const END_CAP: usize = 19;
    for index in 0..END_CAP.div_ceil(32) {
        w.u32(caps.words().get(index).copied().unwrap_or(0));
    }
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connected_agent(tokens: u32) -> Agent {
        let mut agent = Agent::new();
        agent.connect(tokens);
        agent
    }

    #[test]
    fn connecting_asks_to_start_and_announces_this_clients_capabilities() {
        let mut agent = Agent::new();
        let messages = agent.connect(10);
        assert_eq!(messages[0].kind, main_msgc::AGENT_START);
        assert_eq!(messages[0].body, u32::MAX.to_le_bytes());
        assert_eq!(messages[1].kind, main_msgc::AGENT_DATA);

        let mut r = Reader::new(&messages[1].body);
        assert_eq!(r.u32().unwrap(), PROTOCOL);
        assert_eq!(r.u32().unwrap(), msg::ANNOUNCE_CAPABILITIES);
        assert_eq!(r.u64().unwrap(), 0);
        let size = r.u32().unwrap();
        assert_eq!(size as usize, messages[1].body.len() - MESSAGE_HEADER);
        assert!(agent.is_connected());
    }

    #[test]
    fn a_message_is_held_until_there_are_tokens_to_send_it_with() {
        let mut agent = Agent::new();
        // Connecting with no tokens queues the announcement rather than
        // sending it.
        let messages = agent.connect(0);
        assert_eq!(messages.len(), 1, "only AGENT_START, which is not tokened");
        assert_eq!(agent.tokens(), 0);

        let released = agent.add_tokens(1);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].kind, main_msgc::AGENT_DATA);
    }

    #[test]
    fn a_large_message_is_split_at_the_chunk_size_and_each_chunk_costs_a_token() {
        let mut agent = connected_agent(0);
        agent.queue.clear();
        agent.add_tokens(100);
        let body = vec![0x5Au8; MAX_DATA_SIZE * 2];
        let messages = agent.send(msg::CLIPBOARD, &body);
        let total = MESSAGE_HEADER + body.len();
        assert_eq!(messages.len(), total.div_ceil(MAX_DATA_SIZE));
        for message in &messages[..messages.len() - 1] {
            assert_eq!(message.body.len(), MAX_DATA_SIZE);
        }
        assert_eq!(agent.tokens(), 100 - messages.len() as u32);
    }

    #[test]
    fn sending_without_an_agent_produces_nothing() {
        let mut agent = Agent::new();
        assert!(agent.send(msg::CLIPBOARD, b"hello").is_empty());
    }

    #[test]
    fn a_resize_needs_the_guest_to_have_said_it_can() {
        let mut agent = connected_agent(10);
        assert!(!agent.can_resize());
        assert!(agent.request_resize(1920, 1080).is_empty());

        let announcement = announce_capabilities(false);
        agent.note_capabilities(&announcement).unwrap();
        assert!(agent.can_resize());

        let messages = agent.request_resize(1920, 1080);
        assert_eq!(messages.len(), 1);
        let mut r = Reader::new(&messages[0].body);
        r.skip(MESSAGE_HEADER).unwrap();
        assert_eq!(r.u32().unwrap(), 1, "one monitor");
        assert_eq!(r.u32().unwrap(), 0, "no flags");
        // VDAgentMonConfig is height *before* width.
        assert_eq!(r.u32().unwrap(), 1080);
        assert_eq!(r.u32().unwrap(), 1920);
        assert_eq!(r.u32().unwrap(), 32);
    }

    #[test]
    fn an_inbound_message_in_one_chunk_comes_straight_back() {
        let mut agent = connected_agent(0);
        let mut w = Writer::new();
        w.u32(PROTOCOL).u32(msg::REPLY).u64(0).u32(8);
        w.u32(msg::MONITORS_CONFIG).u32(1);
        let got = agent.receive(&w.finish()).unwrap().unwrap();
        assert_eq!(got.kind, msg::REPLY);
        assert_eq!(got.body.len(), 8);
    }

    #[test]
    fn an_inbound_message_split_across_chunks_is_reassembled() {
        let mut agent = connected_agent(0);
        let payload = vec![7u8; MAX_DATA_SIZE * 2];
        let mut w = Writer::new();
        w.u32(PROTOCOL)
            .u32(msg::CLIPBOARD)
            .u64(0)
            .u32(payload.len() as u32);
        let mut whole = w.finish();
        whole.extend_from_slice(&payload);

        let mut result = None;
        for chunk in whole.chunks(MAX_DATA_SIZE) {
            if let Some(message) = agent.receive(chunk).unwrap() {
                result = Some(message);
            }
        }
        let message = result.expect("the last chunk should complete it");
        assert_eq!(message.kind, msg::CLIPBOARD);
        assert_eq!(message.body, payload);
    }

    #[test]
    fn an_agent_message_past_the_ceiling_is_refused_before_buffering() {
        let mut agent = connected_agent(0);
        let mut w = Writer::new();
        w.u32(PROTOCOL).u32(msg::CLIPBOARD).u64(0).u32(u32::MAX);
        let err = agent.receive(&w.finish()).unwrap_err();
        assert!(matches!(err, SpiceError::Limit(_)), "{err}");
    }

    #[test]
    fn an_agent_message_with_the_wrong_protocol_is_refused() {
        let mut agent = connected_agent(0);
        let mut w = Writer::new();
        w.u32(99).u32(msg::CLIPBOARD).u64(0).u32(0);
        assert!(agent.receive(&w.finish()).is_err());
    }

    #[test]
    fn a_truncated_agent_header_is_an_error_rather_than_a_panic() {
        let mut agent = connected_agent(0);
        assert!(agent.receive(&[1, 2, 3]).is_err());
        assert!(agent.receive(&[]).unwrap().is_none());
    }

    #[test]
    fn disconnecting_drops_everything_that_was_queued() {
        let mut agent = connected_agent(0);
        agent.send(msg::CLIPBOARD, b"x");
        agent.disconnect();
        assert!(!agent.is_connected());
        assert!(agent.add_tokens(10).is_empty());
    }

    #[test]
    fn the_capability_announcement_is_only_what_this_client_implements() {
        let body = announce_capabilities(true);
        let mut r = Reader::new(&body);
        assert_eq!(r.u32().unwrap(), 1, "requests one back");
        let caps = crate::protocol::Caps::from_words(vec![r.u32().unwrap()]);
        assert!(caps.has(cap::MONITORS_CONFIG));
        assert!(caps.has(cap::CLIPBOARD_BY_DEMAND));
        assert!(!caps.has(cap::FILE_XFER_DETAILED_ERRORS));
        assert!(!caps.has(cap::DISPLAY_CONFIG));
    }

    /// The prefix question, asserted rather than left to a comment: with
    /// `CLIPBOARD_SELECTION` announced every clipboard message grows a
    /// four-byte `VDAgentClipboardSelection` in front of its type, and
    /// `spice-vdagent` decides to write it from *this* word. Every encoder
    /// below writes the type first, so the two have to agree.
    #[test]
    fn the_clipboard_capabilities_announced_are_the_ones_the_encoding_assumes() {
        let body = announce_capabilities(false);
        let mut r = Reader::new(&body);
        r.u32().unwrap();
        let caps = crate::protocol::Caps::from_words(vec![r.u32().unwrap()]);
        assert!(
            caps.has(cap::CLIPBOARD_BY_DEMAND),
            "the flow implemented here"
        );
        assert!(
            caps.has(cap::MAX_CLIPBOARD),
            "so the ceiling can be declared"
        );
        assert!(
            !caps.has(cap::CLIPBOARD),
            "the superseded flow, which a grab here never carries a payload for"
        );
        assert!(
            !caps.has(cap::CLIPBOARD_SELECTION),
            "announcing it would add a selection word in front of every type"
        );
    }

    /// Enough of a guest to exchange a clipboard with.
    fn clipboard_agent() -> Agent {
        let mut agent = connected_agent(100);
        agent
            .note_capabilities(&announce_capabilities(false))
            .unwrap();
        agent.queue.clear();
        agent
    }

    /// Strip the `VDAgentMessage` header off a queued chunk.
    fn agent_body(message: &OutMessage) -> (u32, Vec<u8>) {
        let mut r = Reader::new(&message.body);
        assert_eq!(r.u32().unwrap(), PROTOCOL);
        let kind = r.u32().unwrap();
        r.u64().unwrap();
        let size = r.u32().unwrap() as usize;
        (
            kind,
            message.body[MESSAGE_HEADER..MESSAGE_HEADER + size].to_vec(),
        )
    }

    #[test]
    fn every_clipboard_message_needs_the_guest_to_have_said_it_can() {
        let mut agent = connected_agent(100);
        assert!(!agent.can_clipboard(), "nothing announced yet");
        assert!(agent
            .clipboard_grab(&[clipboard_type::UTF8_TEXT])
            .is_empty());
        assert!(agent
            .clipboard_request(clipboard_type::UTF8_TEXT)
            .is_empty());
        assert!(agent
            .clipboard_data(clipboard_type::UTF8_TEXT, b"x")
            .unwrap()
            .is_empty());
        assert!(agent.clipboard_release().is_empty());
        assert!(agent.max_clipboard().is_empty());

        agent
            .note_capabilities(&announce_capabilities(false))
            .unwrap();
        assert!(agent.can_clipboard());
        assert!(!agent
            .clipboard_grab(&[clipboard_type::UTF8_TEXT])
            .is_empty());
    }

    /// The gate is `CLIPBOARD_BY_DEMAND` and nothing else. `CLIPBOARD`
    /// alone is the superseded flow in which a grab carries the payload, and
    /// a guest announcing only that cannot answer a request -- but, more to
    /// the point, no guest announces it at all: `vdagentd`'s
    /// `send_capabilities` sets `BY_DEMAND` and never the bare bit. A gate
    /// wanting both refuses every real agent, which is exactly what the
    /// first version of this did until a real one was pointed at it.
    #[test]
    fn the_clipboard_gate_is_by_demand_and_does_not_also_want_the_superseded_bit() {
        let announce = |bits: &[u32]| {
            let mut w = Writer::new();
            w.u32(0)
                .u32(crate::protocol::Caps::from_bits(bits).words()[0]);
            w.finish()
        };

        let mut agent = connected_agent(100);
        agent
            .note_capabilities(&announce(&[cap::CLIPBOARD]))
            .unwrap();
        assert!(agent.guest_has(cap::CLIPBOARD));
        assert!(
            !agent.can_clipboard(),
            "the superseded flow is not implemented"
        );

        // What `spice-vdagent` actually announces: by-demand, no bare bit.
        let mut agent = connected_agent(100);
        agent
            .note_capabilities(&announce(&[cap::CLIPBOARD_BY_DEMAND]))
            .unwrap();
        assert!(!agent.guest_has(cap::CLIPBOARD));
        assert!(agent.can_clipboard());
    }

    #[test]
    fn a_grab_names_every_type_offered_in_order() {
        let mut agent = clipboard_agent();
        let messages =
            agent.clipboard_grab(&[clipboard_type::UTF8_TEXT, clipboard_type::IMAGE_PNG]);
        let (kind, body) = agent_body(&messages[0]);
        assert_eq!(kind, msg::CLIPBOARD_GRAB);
        let mut r = Reader::new(&body);
        assert_eq!(r.u32().unwrap(), clipboard_type::UTF8_TEXT);
        assert_eq!(r.u32().unwrap(), clipboard_type::IMAGE_PNG);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn a_payload_goes_out_as_its_type_followed_by_the_bytes() {
        let mut agent = clipboard_agent();
        let messages = agent
            .clipboard_data(clipboard_type::UTF8_TEXT, b"hello")
            .unwrap();
        let (kind, body) = agent_body(&messages[0]);
        assert_eq!(kind, msg::CLIPBOARD);
        assert_eq!(&body[..4], clipboard_type::UTF8_TEXT.to_le_bytes());
        assert_eq!(&body[4..], b"hello");
    }

    /// The ceiling is checked before the queue, so an oversized payload
    /// costs an error rather than a megabyte of tokens.
    #[test]
    fn a_payload_past_the_ceiling_is_refused_before_it_is_queued() {
        let mut agent = clipboard_agent();
        let before = agent.tokens();
        let huge = vec![0u8; MAX_CLIPBOARD_PAYLOAD as usize + 1];
        let err = agent
            .clipboard_data(clipboard_type::UTF8_TEXT, &huge)
            .unwrap_err();
        assert!(matches!(err, SpiceError::Limit(_)), "{err}");
        assert!(agent.queue.is_empty());
        assert_eq!(agent.tokens(), before, "nothing was spent");

        // And the largest allowed one still fits inside the ceiling the
        // receiving half enforces.
        let biggest = vec![0u8; MAX_CLIPBOARD_PAYLOAD as usize];
        let sent = agent
            .clipboard_data(clipboard_type::UTF8_TEXT, &biggest)
            .unwrap();
        let declared: u32 = {
            let mut r = Reader::new(&sent[0].body);
            r.skip(12).unwrap();
            r.u32().unwrap()
        };
        assert!(declared <= MAX_MESSAGE_SIZE);
    }

    #[test]
    fn the_ceiling_is_declared_to_a_guest_that_can_hear_it() {
        let mut agent = clipboard_agent();
        let messages = agent.max_clipboard();
        let (kind, body) = agent_body(&messages[0]);
        assert_eq!(kind, msg::MAX_CLIPBOARD);
        assert_eq!(body, (MAX_CLIPBOARD_PAYLOAD as i32).to_le_bytes());

        // A guest that never announced the capability is not told, because
        // it would read the message as one it does not know.
        let mut agent = connected_agent(100);
        let mut w = Writer::new();
        w.u32(0).u32(
            crate::protocol::Caps::from_bits(&[cap::CLIPBOARD, cap::CLIPBOARD_BY_DEMAND]).words()
                [0],
        );
        agent.note_capabilities(&w.finish()).unwrap();
        assert!(agent.can_clipboard());
        assert!(agent.max_clipboard().is_empty());
    }

    #[test]
    fn clipboard_types_round_trip_and_the_ones_this_client_will_not_claim_do_not() {
        for kind in [
            ClipboardType::Utf8Text,
            ClipboardType::Png,
            ClipboardType::Bmp,
            ClipboardType::Tiff,
            ClipboardType::Jpeg,
        ] {
            assert_eq!(ClipboardType::from_wire(kind.to_wire()), Some(kind));
        }
        assert_eq!(
            ClipboardType::from_wire(clipboard_type::UTF8_TEXT),
            Some(ClipboardType::Utf8Text)
        );
        // `NONE` is an answer, not a type; `FILE_LIST` would promise a file
        // transfer this client does not implement.
        assert_eq!(ClipboardType::from_wire(clipboard_type::NONE), None);
        assert_eq!(ClipboardType::from_wire(clipboard_type::FILE_LIST), None);
        assert_eq!(ClipboardType::from_wire(9999), None);
    }
}
