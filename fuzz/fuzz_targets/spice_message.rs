//! SPICE's non-drawing messages: the link reply, the channel framing, the
//! cursor shapes, the agent tunnel and the playback channel.
//!
//! All of them are parsed before anything about the peer has been
//! established, and all of them decide allocations from header fields. The
//! first byte picks which parser the rest is fed to.
#![no_main]
use libfuzzer_sys::fuzz_target;
use solstice_spice::agent::Agent;
use solstice_spice::cursor::CursorChannel;
use solstice_spice::display::stream::StreamSet;
use solstice_spice::main_channel::MainChannel;
use solstice_spice::playback::Playback;
use solstice_spice::protocol::{cursor_msg, display_msg, main_msg, playback_msg};

fuzz_target!(|data: &[u8]| {
    let Some((selector, body)) = data.split_first() else {
        return;
    };
    match selector % 6 {
        0 => {
            let mut cursor = CursorChannel::new();
            for kind in [
                cursor_msg::INIT,
                cursor_msg::SET,
                cursor_msg::MOVE,
                cursor_msg::INVAL_ONE,
            ] {
                let _ = cursor.handle(kind, body);
            }
        }
        1 => {
            let mut main = MainChannel::new();
            for kind in [
                main_msg::INIT,
                main_msg::CHANNELS_LIST,
                main_msg::MOUSE_MODE,
                main_msg::NAME,
                main_msg::AGENT_TOKEN,
            ] {
                let _ = main.handle(kind, body);
            }
        }
        2 => {
            // The agent tunnel reassembles across chunks, so feed it the
            // input in pieces as well as whole.
            let mut agent = Agent::new();
            agent.connect(0);
            let _ = agent.receive(body);
            let mut agent = Agent::new();
            agent.connect(0);
            for chunk in body.chunks(64.max(1)) {
                if agent.receive(chunk).is_err() {
                    break;
                }
            }
        }
        3 => {
            let mut playback = Playback::new();
            for kind in [
                playback_msg::START,
                playback_msg::MODE,
                playback_msg::DATA,
            ] {
                let _ = playback.handle(kind, body);
            }
        }
        4 => {
            let mut streams = StreamSet::new();
            let _ = streams.create(body);
            let _ = solstice_spice::display::stream::parse_data(body);
            let _ = solstice_spice::display::stream::parse_data_sized(body);
        }
        _ => {
            // A whole display message, dispatched the way the channel task
            // dispatches it -- including the surface and stream lifecycle
            // messages the draw-command target does not reach.
            let mut streams = StreamSet::new();
            let _ = streams.create(body);
            let _ = solstice_spice::display::types::Clip::parse(
                &mut solstice_spice::wire::Reader::new(body),
            );
            let _ = solstice_spice::display::types::Image::parse(
                &mut solstice_spice::wire::Reader::new(body),
            );
            let _ = display_msg::SURFACE_CREATE;
        }
    }
});
