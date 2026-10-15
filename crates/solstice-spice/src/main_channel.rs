//! The main channel: session setup, mouse mode, and the agent tunnel.
//!
//! The main channel is the one that must come up first, because the server
//! allocates the session's `connection_id` and returns it in `MAIN_INIT`;
//! every other channel has to present that id when it links
//! (`docs/spice-protocol.md` §2). `CHANNELS_LIST` then says which channels
//! exist, which is what turns a single socket into a session.
//!
//! It is also where the guest agent lives: `MAIN_AGENT_DATA` tunnels
//! `spice-vdagent` traffic in both directions, flow-controlled by tokens.
//! See [`crate::agent`].

use crate::agent::{self, Agent};
use crate::channel::OutMessage;
use crate::error::{Result, SpiceError};
use crate::inputs::MouseMode;
use crate::protocol::{main_msg, main_msgc, mouse_mode};
use crate::wire::{Reader, Writer};

/// Something the session needs to act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MainOutcome {
    /// `MAIN_INIT` arrived; the session is identified.
    Init {
        /// The id every other channel must link with.
        connection_id: u32,
    },
    /// `CHANNELS_LIST` arrived: `(channel_type, channel_id)` pairs.
    Channels(Vec<(u8, u8)>),
    /// The pointer representation changed.
    MouseMode(MouseMode),
    /// The guest agent came up or went away.
    AgentConnected(bool),
    /// The guest offered the clipboard in these types.
    ClipboardOffered(Vec<u32>),
}

/// The most channels a `CHANNELS_LIST` may name.
///
/// The count is a `u32` and each entry becomes a TCP connection, so a
/// server that asks for four billion of them should be refused rather than
/// obeyed. A real session has five or six.
const MAX_CHANNELS: u32 = 64;

/// The client's half of the main channel.
pub struct MainChannel {
    /// The guest agent tunnel.
    pub agent: Agent,
    connection_id: u32,
    supported_modes: u32,
    mouse_mode: MouseMode,
    multi_media_time: u32,
    name: Option<String>,
}

impl Default for MainChannel {
    fn default() -> Self {
        MainChannel::new()
    }
}

impl MainChannel {
    /// A channel that has not linked yet.
    pub fn new() -> Self {
        MainChannel {
            agent: Agent::new(),
            connection_id: 0,
            supported_modes: 0,
            mouse_mode: MouseMode::Server,
            multi_media_time: 0,
            name: None,
        }
    }

    /// The session id, once `MAIN_INIT` has arrived.
    pub fn connection_id(&self) -> u32 {
        self.connection_id
    }

    /// The pointer representation in force.
    pub fn mouse_mode(&self) -> MouseMode {
        self.mouse_mode
    }

    /// The server's media clock, as last reported.
    pub fn multi_media_time(&self) -> u32 {
        self.multi_media_time
    }

    /// The server's name for itself, if it sent one.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Handle one main-channel message.
    pub fn handle(
        &mut self,
        kind: u16,
        body: &[u8],
    ) -> Result<(Vec<OutMessage>, Vec<MainOutcome>)> {
        let mut send = Vec::new();
        let mut outcomes = Vec::new();
        let mut r = Reader::new(body);

        match kind {
            main_msg::INIT => {
                let session_id = r.u32()?;
                let _display_channels_hint = r.u32()?;
                let supported_mouse_modes = r.u32()?;
                let current_mouse_mode = r.u32()?;
                let agent_connected = r.u32()?;
                let agent_tokens = r.u32()?;
                let multi_media_time = r.u32()?;
                let _ram_hint = r.u32()?;

                self.connection_id = session_id;
                self.supported_modes = supported_mouse_modes;
                self.multi_media_time = multi_media_time;
                self.set_mouse_mode(current_mouse_mode, &mut outcomes);

                if agent_connected != 0 {
                    send.extend(self.agent.connect(agent_tokens));
                    outcomes.push(MainOutcome::AgentConnected(true));
                }

                // Ask for absolute positions. Moonlight's natural input is
                // absolute, and the server can only grant this when the
                // guest agent is running -- so it is a request, and the
                // relative fallback stays in place until `MAIN_MOUSE_MODE`
                // says it was granted.
                if supported_mouse_modes & mouse_mode::CLIENT != 0 {
                    send.push(mouse_mode_request(mouse_mode::CLIENT));
                }

                send.push(OutMessage::empty(main_msgc::ATTACH_CHANNELS));
                outcomes.push(MainOutcome::Init {
                    connection_id: session_id,
                });
            }

            main_msg::CHANNELS_LIST => {
                let count = r.u32()?;
                if count > MAX_CHANNELS {
                    return Err(SpiceError::limit(format!(
                        "server named {count} channels, past the {MAX_CHANNELS} ceiling"
                    )));
                }
                let count = r.count(count, 2)?;
                let mut channels = Vec::with_capacity(count);
                for _ in 0..count {
                    channels.push((r.u8()?, r.u8()?));
                }
                outcomes.push(MainOutcome::Channels(channels));
            }

            main_msg::MOUSE_MODE => {
                let supported = r.u16()? as u32;
                let current = r.u16()? as u32;
                self.supported_modes = supported;
                self.set_mouse_mode(current, &mut outcomes);
            }

            main_msg::MULTI_MEDIA_TIME => {
                self.multi_media_time = r.u32()?;
            }

            main_msg::AGENT_CONNECTED => {
                // The pre-`AGENT_CONNECTED_TOKENS` form carries no token
                // count; `channel-main.c:1814` starts with none and waits
                // for `AGENT_TOKEN`.
                send.extend(self.agent.connect(0));
                outcomes.push(MainOutcome::AgentConnected(true));
            }

            main_msg::AGENT_CONNECTED_TOKENS => {
                let tokens = r.u32()?;
                send.extend(self.agent.connect(tokens));
                outcomes.push(MainOutcome::AgentConnected(true));
            }

            main_msg::AGENT_DISCONNECTED => {
                let reason = r.u32().unwrap_or(0);
                tracing::info!(
                    reason = crate::protocol::link_err_name(reason),
                    "spice guest agent disconnected"
                );
                self.agent.disconnect();
                outcomes.push(MainOutcome::AgentConnected(false));
            }

            main_msg::AGENT_TOKEN => {
                let tokens = r.u32()?;
                send.extend(self.agent.add_tokens(tokens));
            }

            main_msg::AGENT_DATA => {
                // No token goes back. `AGENT_START` already granted the
                // server `~0` for its direction -- `reds.cpp:1007-1041`
                // takes that number as the server's own send budget, and
                // `spice-gtk` consequently never sends
                // `MSGC_MAIN_AGENT_TOKEN` at all. Sending one anyway would
                // add to a budget that is already saturated.
                if let Some(message) = self.agent.receive(body)? {
                    self.agent_message(&message, &mut send, &mut outcomes)?;
                }
            }

            main_msg::NAME => {
                let len = r.u32()?;
                let len = r.count(len, 1)?;
                let bytes = r.bytes(len)?;
                let name = String::from_utf8_lossy(bytes)
                    .trim_end_matches('\0')
                    .to_string();
                tracing::info!(%name, "spice server name");
                self.name = Some(name);
            }

            main_msg::UUID => {
                let uuid = r.bytes(16)?;
                tracing::debug!(uuid = ?uuid, "spice server uuid");
            }

            // Migration is out of scope: there is nowhere to migrate a
            // Moonlight session to.
            main_msg::MIGRATE_BEGIN
            | main_msg::MIGRATE_BEGIN_SEAMLESS
            | main_msg::MIGRATE_CANCEL
            | main_msg::MIGRATE_SWITCH_HOST
            | main_msg::MIGRATE_END => {
                tracing::debug!(kind, "ignoring a spice migration message");
            }

            other => {
                tracing::debug!(kind = other, "ignoring main-channel message");
            }
        }

        Ok((send, outcomes))
    }

    fn agent_message(
        &mut self,
        message: &agent::AgentMessage,
        send: &mut Vec<OutMessage>,
        outcomes: &mut Vec<MainOutcome>,
    ) -> Result<()> {
        match message.kind {
            agent::msg::ANNOUNCE_CAPABILITIES => {
                let wants_reply = self.agent.note_capabilities(&message.body)?;
                if wants_reply {
                    send.extend(self.agent.send(
                        agent::msg::ANNOUNCE_CAPABILITIES,
                        &agent::announce_capabilities(false),
                    ));
                }
                tracing::info!(
                    can_resize = self.agent.can_resize(),
                    "spice guest agent announced its capabilities"
                );
            }
            agent::msg::CLIPBOARD_GRAB => {
                let mut r = Reader::new(&message.body);
                let mut types = Vec::new();
                while r.remaining() >= 4 {
                    types.push(r.u32()?);
                }
                outcomes.push(MainOutcome::ClipboardOffered(types));
            }
            agent::msg::REPLY => {
                let mut r = Reader::new(&message.body);
                let kind = r.u32()?;
                let error = r.u32()?;
                if error != crate::agent::REPLY_SUCCESS {
                    tracing::warn!(kind, error, "the guest agent refused a request");
                }
            }
            other => {
                tracing::debug!(
                    kind = other,
                    len = message.body.len(),
                    "ignoring agent message"
                );
            }
        }
        Ok(())
    }

    fn set_mouse_mode(&mut self, raw: u32, outcomes: &mut Vec<MainOutcome>) {
        let mode = if raw & mouse_mode::CLIENT != 0 {
            MouseMode::Client
        } else {
            MouseMode::Server
        };
        if mode != self.mouse_mode {
            tracing::info!(?mode, "spice mouse mode");
        }
        self.mouse_mode = mode;
        outcomes.push(MainOutcome::MouseMode(mode));
    }

    /// Ask the guest to change resolution, if the agent can.
    pub fn request_resize(&mut self, width: u32, height: u32) -> Vec<OutMessage> {
        self.agent.request_resize(width, height)
    }

    /// Whether a resize request would be honoured.
    pub fn can_resize(&self) -> bool {
        self.agent.can_resize()
    }
}

/// Build `MAIN_MOUSE_MODE_REQUEST`.
pub fn mouse_mode_request(mode: u32) -> OutMessage {
    let mut w = Writer::new();
    w.u16(mode as u16);
    OutMessage::new(main_msgc::MOUSE_MODE_REQUEST, w.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_body(agent_connected: u32, modes: u32, current: u32) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(0xABCD_1234) // session_id
            .u32(1) // display channels hint
            .u32(modes)
            .u32(current)
            .u32(agent_connected)
            .u32(10) // agent tokens
            .u32(0) // multi media time
            .u32(0); // ram hint
        w.finish()
    }

    #[test]
    fn init_hands_back_the_connection_id_every_other_channel_needs() {
        let mut main = MainChannel::new();
        let (send, outcomes) = main
            .handle(
                main_msg::INIT,
                &init_body(0, mouse_mode::SERVER, mouse_mode::SERVER),
            )
            .unwrap();
        assert_eq!(main.connection_id(), 0xABCD_1234);
        assert!(outcomes.contains(&MainOutcome::Init {
            connection_id: 0xABCD_1234
        }));
        assert!(send.iter().any(|m| m.kind == main_msgc::ATTACH_CHANNELS));
    }

    #[test]
    fn client_mouse_mode_is_asked_for_when_the_server_says_it_is_available() {
        let mut main = MainChannel::new();
        let (send, _) = main
            .handle(
                main_msg::INIT,
                &init_body(
                    0,
                    mouse_mode::SERVER | mouse_mode::CLIENT,
                    mouse_mode::SERVER,
                ),
            )
            .unwrap();
        let request = send
            .iter()
            .find(|m| m.kind == main_msgc::MOUSE_MODE_REQUEST)
            .expect("should have asked");
        assert_eq!(request.body, (mouse_mode::CLIENT as u16).to_le_bytes());
        // ...but the mode in force is still the one the server reported.
        assert_eq!(main.mouse_mode(), MouseMode::Server);
    }

    #[test]
    fn client_mouse_mode_is_not_asked_for_when_the_server_cannot_do_it() {
        let mut main = MainChannel::new();
        let (send, _) = main
            .handle(
                main_msg::INIT,
                &init_body(0, mouse_mode::SERVER, mouse_mode::SERVER),
            )
            .unwrap();
        assert!(!send.iter().any(|m| m.kind == main_msgc::MOUSE_MODE_REQUEST));
    }

    #[test]
    fn a_mouse_mode_message_switches_the_pointer_representation() {
        let mut main = MainChannel::new();
        let mut w = Writer::new();
        w.u16((mouse_mode::SERVER | mouse_mode::CLIENT) as u16)
            .u16(mouse_mode::CLIENT as u16);
        let (_, outcomes) = main.handle(main_msg::MOUSE_MODE, &w.finish()).unwrap();
        assert_eq!(main.mouse_mode(), MouseMode::Client);
        assert!(outcomes.contains(&MainOutcome::MouseMode(MouseMode::Client)));
    }

    #[test]
    fn an_init_with_an_agent_starts_it() {
        let mut main = MainChannel::new();
        let (send, outcomes) = main
            .handle(
                main_msg::INIT,
                &init_body(1, mouse_mode::CLIENT, mouse_mode::CLIENT),
            )
            .unwrap();
        assert!(main.agent.is_connected());
        assert!(send.iter().any(|m| m.kind == main_msgc::AGENT_START));
        assert!(outcomes.contains(&MainOutcome::AgentConnected(true)));
    }

    #[test]
    fn the_channel_list_comes_back_as_type_and_id_pairs() {
        let mut main = MainChannel::new();
        let mut w = Writer::new();
        w.u32(3);
        w.u8(crate::protocol::channel::MAIN).u8(0);
        w.u8(crate::protocol::channel::DISPLAY).u8(0);
        w.u8(crate::protocol::channel::INPUTS).u8(0);
        let (_, outcomes) = main.handle(main_msg::CHANNELS_LIST, &w.finish()).unwrap();
        assert_eq!(
            outcomes[0],
            MainOutcome::Channels(vec![(1, 0), (2, 0), (3, 0)])
        );
    }

    #[test]
    fn a_channel_count_past_the_ceiling_is_refused_before_connecting_to_any() {
        let mut main = MainChannel::new();
        let mut w = Writer::new();
        w.u32(u32::MAX);
        let err = main
            .handle(main_msg::CHANNELS_LIST, &w.finish())
            .unwrap_err();
        assert!(matches!(err, SpiceError::Limit(_)), "{err}");
    }

    #[test]
    fn agent_data_does_not_hand_tokens_back() {
        // `AGENT_START` granted the server `~0` for its own direction, so a
        // token per chunk would add to a saturated budget. The reference
        // client never sends one either.
        let mut main = MainChannel::new();
        main.handle(main_msg::INIT, &init_body(1, 0, 0)).unwrap();
        let start = main
            .handle(main_msg::INIT, &init_body(1, 0, 0))
            .unwrap()
            .0
            .into_iter()
            .find(|m| m.kind == main_msgc::AGENT_START)
            .expect("AGENT_START should go out");
        assert_eq!(start.body, u32::MAX.to_le_bytes());

        let mut w = Writer::new();
        w.u32(agent::PROTOCOL).u32(agent::msg::REPLY).u64(0).u32(8);
        w.u32(agent::msg::MONITORS_CONFIG).u32(1);
        let (send, _) = main.handle(main_msg::AGENT_DATA, &w.finish()).unwrap();
        assert!(!send.iter().any(|m| m.kind == main_msgc::AGENT_TOKEN));
    }

    #[test]
    fn a_guest_capability_announcement_is_answered_and_enables_resize() {
        let mut main = MainChannel::new();
        main.handle(main_msg::INIT, &init_body(1, 0, 0)).unwrap();
        assert!(!main.can_resize());

        let caps = agent::announce_capabilities(true);
        let mut w = Writer::new();
        w.u32(agent::PROTOCOL)
            .u32(agent::msg::ANNOUNCE_CAPABILITIES)
            .u64(0)
            .u32(caps.len() as u32)
            .bytes(&caps);
        let (send, _) = main.handle(main_msg::AGENT_DATA, &w.finish()).unwrap();
        assert!(main.can_resize());
        assert!(send.iter().any(|m| m.kind == main_msgc::AGENT_DATA));
    }

    #[test]
    fn a_clipboard_offer_from_the_guest_is_surfaced() {
        let mut main = MainChannel::new();
        main.handle(main_msg::INIT, &init_body(1, 0, 0)).unwrap();
        let mut body = Writer::new();
        body.u32(agent::clipboard_type::UTF8_TEXT);
        let body = body.finish();
        let mut w = Writer::new();
        w.u32(agent::PROTOCOL)
            .u32(agent::msg::CLIPBOARD_GRAB)
            .u64(0)
            .u32(body.len() as u32)
            .bytes(&body);
        let (_, outcomes) = main.handle(main_msg::AGENT_DATA, &w.finish()).unwrap();
        assert!(outcomes.contains(&MainOutcome::ClipboardOffered(vec![
            agent::clipboard_type::UTF8_TEXT
        ])));
    }

    #[test]
    fn an_agent_disconnect_stops_the_tunnel() {
        let mut main = MainChannel::new();
        main.handle(main_msg::INIT, &init_body(1, 0, 0)).unwrap();
        let mut w = Writer::new();
        w.u32(0);
        let (_, outcomes) = main
            .handle(main_msg::AGENT_DISCONNECTED, &w.finish())
            .unwrap();
        assert!(!main.agent.is_connected());
        assert!(outcomes.contains(&MainOutcome::AgentConnected(false)));
    }

    #[test]
    fn the_server_name_is_read_without_its_terminator() {
        let mut main = MainChannel::new();
        let mut w = Writer::new();
        w.u32(7).bytes(b"spicy\0\0");
        main.handle(main_msg::NAME, &w.finish()).unwrap();
        assert_eq!(main.name(), Some("spicy"));
    }

    #[test]
    fn a_truncated_init_is_an_error_rather_than_a_panic() {
        let mut main = MainChannel::new();
        let body = init_body(0, 0, 0);
        for cut in 0..body.len() {
            let mut main = MainChannel::new();
            assert!(main.handle(main_msg::INIT, &body[..cut]).is_err());
        }
        assert!(main.handle(main_msg::INIT, &body).is_ok());
    }
}
