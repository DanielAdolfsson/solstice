//! Message framing, and the base messages every channel shares.
//!
//! Once a channel is linked it carries a stream of typed messages behind one
//! of two headers, chosen by the `MINI_HEADER` capability
//! (`protocol.h:93-103`):
//!
//! ```text
//! SpiceDataHeader     { u64 serial; u16 type; u32 size; u32 sub_list; }  // 18 bytes
//! SpiceMiniDataHeader { u16 type; u32 size; }                            //  6 bytes
//! ```
//!
//! Types 1..=99 are the common base set and are handled here rather than by
//! the channel: `PING` must be ponged, `SET_ACK` must be answered and then
//! obeyed, and `LIST` is a container holding other messages. Everything from
//! 101 up is the channel's own namespace and is handed out by
//! [`ChannelReader::next`].
//!
//! # The ack window is not optional
//!
//! `SET_ACK` gives a generation and a window; the client answers `ACK_SYNC`
//! with that generation and then sends one `ACK` per `window` messages
//! received. A client that does not will see the server go quiet, with no
//! error anywhere -- `spice-gtk` does it at `channel-base.c:26-39` and
//! `spice-channel.c:2141-2149`, and the counting is per *message*, not per
//! sub-message or per byte.

use std::collections::VecDeque;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::error::{Result, SpiceError};
use crate::protocol::{msg, msgc};
use crate::wire::{Reader, Writer};

/// Bytes of the full `SpiceDataHeader`.
pub const FULL_HEADER: usize = 8 + 2 + 4 + 4;
/// Bytes of `SpiceMiniDataHeader`.
pub const MINI_HEADER: usize = 2 + 4;

/// The largest message body this client will read.
///
/// `size` is a `u32` written by the peer, and the allocation happens before a
/// single byte of the body has been seen. Real messages are small; the
/// largest by far is a full-screen raw bitmap, which at 8K and four bytes a
/// pixel is 132 MB -- so the ceiling is set from that rather than from
/// anything in the protocol, which has none.
pub const DEFAULT_MAX_MESSAGE: u32 = 192 * 1024 * 1024;

/// One channel message, after the header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The channel-specific type number.
    pub kind: u16,
    /// The body, exactly `size` bytes.
    pub body: Vec<u8>,
}

/// A message to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutMessage {
    /// The client-side type number.
    pub kind: u16,
    /// The body.
    pub body: Vec<u8>,
}

impl OutMessage {
    /// A message with a body.
    pub fn new(kind: u16, body: Vec<u8>) -> Self {
        OutMessage { kind, body }
    }

    /// A message with no body. Several of SPICE's are `Empty`.
    pub fn empty(kind: u16) -> Self {
        OutMessage {
            kind,
            body: Vec::new(),
        }
    }
}

/// The ack window, as `SET_ACK` set it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AckWindow {
    window: u32,
    countdown: u32,
}

impl AckWindow {
    /// Count one message. Returns true when an `ACK` is owed.
    fn message(&mut self) -> bool {
        if self.countdown == 0 {
            // No window has been set: the server has not asked to be acked.
            return false;
        }
        self.countdown -= 1;
        if self.countdown == 0 {
            self.countdown = self.window;
            true
        } else {
            false
        }
    }
}

/// What a base message turned into.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Handled {
    /// Hand this to the channel.
    Channel(Message),
    /// Dealt with here; read another.
    Consumed,
    /// The server said goodbye.
    Disconnect,
}

/// Reads one channel's messages, answering the base ones itself.
pub struct ChannelReader<R> {
    reader: R,
    mini: bool,
    max_message: u32,
    ack: AckWindow,
    outgoing: mpsc::Sender<OutMessage>,
    /// Messages unpacked from a `LIST` or a sub-message list, waiting to be
    /// handed out one at a time.
    pending: VecDeque<Message>,
    name: &'static str,
}

impl<R: AsyncRead + Unpin> ChannelReader<R> {
    /// Build one over an already-linked transport.
    pub fn new(
        reader: R,
        mini: bool,
        outgoing: mpsc::Sender<OutMessage>,
        name: &'static str,
    ) -> Self {
        ChannelReader {
            reader,
            mini,
            max_message: DEFAULT_MAX_MESSAGE,
            ack: AckWindow::default(),
            outgoing,
            pending: VecDeque::new(),
            name,
        }
    }

    /// Lower the ceiling on one message body.
    pub fn with_max_message(mut self, max: u32) -> Self {
        self.max_message = max;
        self
    }

    /// The next channel-specific message, or `None` when the peer
    /// disconnected cleanly.
    pub async fn next(&mut self) -> Result<Option<Message>> {
        loop {
            if let Some(message) = self.pending.pop_front() {
                return Ok(Some(message));
            }
            match self.read_one().await? {
                Handled::Channel(message) => return Ok(Some(message)),
                Handled::Consumed => continue,
                Handled::Disconnect => return Ok(None),
            }
        }
    }

    async fn read_one(&mut self) -> Result<Handled> {
        let (kind, size, sub_list) = self.read_header().await?;
        if size > self.max_message {
            return Err(SpiceError::limit(format!(
                "{} message {kind} claims {size} bytes, past the {} byte ceiling",
                self.name, self.max_message
            )));
        }
        let mut body = vec![0u8; size as usize];
        self.reader.read_exact(&mut body).await?;

        // A full header may point at a list of sub-messages trailing the
        // body. Each is a complete message in its own right.
        if sub_list != 0 {
            self.queue_sub_messages(&body, sub_list)?;
        }

        // The ack is owed for the message that arrived, whatever it was and
        // however many sub-messages it carried.
        if self.ack.message() {
            let _ = self.outgoing.try_send(OutMessage::empty(msgc::ACK));
        }

        self.dispatch(kind, body)
    }

    fn dispatch(&mut self, kind: u16, body: Vec<u8>) -> Result<Handled> {
        match kind {
            msg::SET_ACK => {
                let mut r = Reader::new(&body);
                let generation = r.u32()?;
                let window = r.u32()?;
                self.ack = AckWindow {
                    window,
                    countdown: window,
                };
                let mut out = Writer::new();
                out.u32(generation);
                let _ = self
                    .outgoing
                    .try_send(OutMessage::new(msgc::ACK_SYNC, out.finish()));
                tracing::debug!(channel = self.name, generation, window, "spice ack window");
                Ok(Handled::Consumed)
            }
            msg::PING => {
                // Echo the id and timestamp; the trailing padding the server
                // uses to size the ping is not echoed back.
                let mut r = Reader::new(&body);
                let id = r.u32()?;
                let timestamp = r.u64()?;
                let mut out = Writer::new();
                out.u32(id).u64(timestamp);
                let _ = self
                    .outgoing
                    .try_send(OutMessage::new(msgc::PONG, out.finish()));
                Ok(Handled::Consumed)
            }
            msg::NOTIFY => {
                let mut r = Reader::new(&body);
                let _time_stamp = r.u64()?;
                let severity = r.u32()?;
                let _visibility = r.u32()?;
                let what = r.u32()?;
                let len = r.u32()?;
                let len = r.count(len, 1)?;
                let text = r.bytes(len).unwrap_or_default();
                let text = String::from_utf8_lossy(text);
                let text = text.trim_end_matches('\0');
                match severity {
                    2 => tracing::warn!(channel = self.name, what, "spice server: {text}"),
                    1 => tracing::info!(channel = self.name, what, "spice server: {text}"),
                    _ => tracing::debug!(channel = self.name, what, "spice server: {text}"),
                }
                Ok(Handled::Consumed)
            }
            msg::DISCONNECTING => {
                let mut r = Reader::new(&body);
                let _time_stamp = r.u64()?;
                let reason = r.u32().unwrap_or(0);
                tracing::info!(
                    channel = self.name,
                    reason = crate::protocol::link_err_name(reason),
                    "spice server disconnecting"
                );
                Ok(Handled::Disconnect)
            }
            msg::LIST => {
                // The body *is* a SpiceSubMessageList.
                self.queue_sub_messages(&body, 0)?;
                Ok(Handled::Consumed)
            }
            msg::MIGRATE | msg::MIGRATE_DATA | msg::WAIT_FOR_CHANNELS => {
                // Migration is out of scope for a bridge: there is nothing to
                // migrate a Moonlight session to. WAIT_FOR_CHANNELS only
                // matters when several display channels share a GLZ window,
                // which this client does not do (`docs/roadmap.md` §2.2).
                tracing::debug!(channel = self.name, kind, "ignoring base message");
                Ok(Handled::Consumed)
            }
            _ => Ok(Handled::Channel(Message { kind, body })),
        }
    }

    /// Unpack a `SpiceSubMessageList` at `offset` into [`ChannelReader::pending`].
    fn queue_sub_messages(&mut self, body: &[u8], offset: u32) -> Result<()> {
        let list = Reader::new(body);
        let mut list = list.at(offset as usize)?;
        let count = list.u16()?;
        let count = list.count(count as u32, 4)?;
        let mut offsets = Vec::with_capacity(count);
        for _ in 0..count {
            offsets.push(list.u32()? as usize);
        }
        for offset in offsets {
            let mut sub = Reader::new(body).at(offset)?;
            let kind = sub.u16()?;
            let size = sub.u32()?;
            let size = sub.count(size, 1)?;
            let payload = sub.bytes(size)?.to_vec();
            self.pending.push_back(Message {
                kind,
                body: payload,
            });
        }
        Ok(())
    }

    async fn read_header(&mut self) -> Result<(u16, u32, u32)> {
        if self.mini {
            let mut header = [0u8; MINI_HEADER];
            self.reader.read_exact(&mut header).await?;
            let mut r = Reader::new(&header);
            Ok((r.u16()?, r.u32()?, 0))
        } else {
            let mut header = [0u8; FULL_HEADER];
            self.reader.read_exact(&mut header).await?;
            let mut r = Reader::new(&header);
            let _serial = r.u64()?;
            let kind = r.u16()?;
            let size = r.u32()?;
            let sub_list = r.u32()?;
            if sub_list != 0 && sub_list >= size {
                return Err(SpiceError::protocol(format!(
                    "{} sub-message list at {sub_list} is outside a {size} byte message",
                    self.name
                )));
            }
            Ok((kind, size, sub_list))
        }
    }
}

/// Frame and write outgoing messages until the sender is dropped.
///
/// The serial is the client's own counter and starts at one
/// (`spice-channel.c:116`); it is ignored by the server but is part of the
/// full header, and a mini-header channel does not carry it at all.
pub async fn writer_task<W: AsyncWrite + Unpin>(
    mut writer: W,
    mini: bool,
    mut outgoing: mpsc::Receiver<OutMessage>,
) {
    let mut serial: u64 = 1;
    while let Some(message) = outgoing.recv().await {
        let mut frame = Writer::with_capacity(FULL_HEADER + message.body.len());
        if mini {
            frame.u16(message.kind).u32(message.body.len() as u32);
        } else {
            frame
                .u64(serial)
                .u16(message.kind)
                .u32(message.body.len() as u32)
                .u32(0);
            serial += 1;
        }
        frame.bytes(&message.body);
        if writer.write_all(&frame.finish()).await.is_err() {
            break;
        }
        if writer.flush().await.is_err() {
            break;
        }
    }
}

/// Frame one message the way [`writer_task`] would, for tests and mocks.
pub fn frame(mini: bool, serial: u64, kind: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Writer::with_capacity(FULL_HEADER + body.len());
    if mini {
        out.u16(kind).u32(body.len() as u32);
    } else {
        out.u64(serial).u16(kind).u32(body.len() as u32).u32(0);
    }
    out.bytes(body);
    out.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader(
        mini: bool,
        bytes: Vec<u8>,
    ) -> (
        ChannelReader<std::io::Cursor<Vec<u8>>>,
        mpsc::Receiver<OutMessage>,
    ) {
        let (tx, rx) = mpsc::channel(32);
        (
            ChannelReader::new(std::io::Cursor::new(bytes), mini, tx, "test"),
            rx,
        )
    }

    #[tokio::test]
    async fn a_mini_header_message_comes_back_whole() {
        let bytes = frame(true, 0, 304, &[1, 2, 3, 4]);
        let (mut r, _rx) = reader(true, bytes);
        assert_eq!(
            r.next().await.unwrap(),
            Some(Message {
                kind: 304,
                body: vec![1, 2, 3, 4]
            })
        );
    }

    #[tokio::test]
    async fn a_full_header_message_comes_back_whole() {
        let bytes = frame(false, 7, 304, &[9]);
        let (mut r, _rx) = reader(false, bytes);
        assert_eq!(
            r.next().await.unwrap(),
            Some(Message {
                kind: 304,
                body: vec![9]
            })
        );
    }

    #[tokio::test]
    async fn set_ack_is_answered_with_ack_sync_and_then_obeyed() {
        let mut bytes = Vec::new();
        let mut set_ack = Writer::new();
        set_ack.u32(0x11223344).u32(2);
        bytes.extend(frame(true, 0, msg::SET_ACK, &set_ack.finish()));
        // Two channel messages: the second completes the window.
        bytes.extend(frame(true, 0, 200, b"a"));
        bytes.extend(frame(true, 0, 201, b"b"));

        let (mut r, mut rx) = reader(true, bytes);
        assert_eq!(r.next().await.unwrap().unwrap().kind, 200);
        assert_eq!(r.next().await.unwrap().unwrap().kind, 201);

        let sync = rx.try_recv().unwrap();
        assert_eq!(sync.kind, msgc::ACK_SYNC);
        assert_eq!(sync.body, 0x11223344u32.to_le_bytes());
        let ack = rx.try_recv().unwrap();
        assert_eq!(ack.kind, msgc::ACK);
        assert!(rx.try_recv().is_err(), "only one ack is owed per window");
    }

    #[tokio::test]
    async fn no_acks_are_sent_before_a_window_has_been_set() {
        let bytes = frame(true, 0, 200, b"a");
        let (mut r, mut rx) = reader(true, bytes);
        let _ = r.next().await.unwrap();
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_ping_is_ponged_with_the_id_and_timestamp_it_carried() {
        let mut ping = Writer::new();
        ping.u32(42).u64(0xDEADBEEFCAFEBABE).zeros(64);
        let mut bytes = frame(true, 0, msg::PING, &ping.finish());
        bytes.extend(frame(true, 0, 200, b"after"));
        let (mut r, mut rx) = reader(true, bytes);
        // The ping is consumed here, not handed out; the next message is.
        assert_eq!(r.next().await.unwrap().unwrap().kind, 200);
        let pong = rx.try_recv().unwrap();
        assert_eq!(pong.kind, msgc::PONG);
        let mut body = Reader::new(&pong.body);
        assert_eq!(body.u32().unwrap(), 42);
        assert_eq!(body.u64().unwrap(), 0xDEADBEEFCAFEBABE);
    }

    #[tokio::test]
    async fn disconnecting_ends_the_stream_rather_than_erroring() {
        let mut bye = Writer::new();
        bye.u64(0).u32(0);
        let bytes = frame(true, 0, msg::DISCONNECTING, &bye.finish());
        let (mut r, _rx) = reader(true, bytes);
        assert_eq!(r.next().await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_message_claiming_more_than_the_ceiling_is_refused_before_allocating() {
        let mut bytes = Writer::new();
        bytes.u16(304).u32(u32::MAX);
        let (mut r, _rx) = reader(true, bytes.finish());
        let err = r.next().await.unwrap_err();
        assert!(matches!(err, SpiceError::Limit(_)), "{err}");
    }

    #[tokio::test]
    async fn a_sub_list_pointing_outside_the_message_is_refused() {
        let mut out = Writer::new();
        out.u64(1).u16(304).u32(4).u32(9999);
        out.bytes(&[0, 0, 0, 0]);
        let (mut r, _rx) = reader(false, out.finish());
        assert!(r.next().await.is_err());
    }

    #[tokio::test]
    async fn a_message_list_is_unpacked_into_its_sub_messages() {
        // SpiceSubMessageList: u16 count, then count u32 offsets, each to a
        // SpiceSubMessage { u16 type; u32 size; } followed by its payload.
        let mut body = Writer::new();
        body.u16(2);
        let first = 2 + 4 + 4;
        let second = first + 6 + 1;
        body.u32(first as u32).u32(second as u32);
        body.u16(200).u32(1).u8(0xAA);
        body.u16(201).u32(2).u8(0xBB).u8(0xCC);
        let body = body.finish();

        let bytes = frame(true, 0, msg::LIST, &body);
        let (mut r, _rx) = reader(true, bytes);
        assert_eq!(
            r.next().await.unwrap(),
            Some(Message {
                kind: 200,
                body: vec![0xAA]
            })
        );
        assert_eq!(
            r.next().await.unwrap(),
            Some(Message {
                kind: 201,
                body: vec![0xBB, 0xCC]
            })
        );
    }

    #[tokio::test]
    async fn the_writer_frames_what_the_reader_expects() {
        let (tx, rx) = mpsc::channel(4);
        let (client, server) = tokio::io::duplex(4096);
        tokio::spawn(writer_task(client, true, rx));
        tx.send(OutMessage::new(111, vec![7, 7])).await.unwrap();
        drop(tx);

        let (reader_half, _writer_half) = tokio::io::split(server);
        let (sink, _sink_rx) = mpsc::channel(4);
        let mut r = ChannelReader::new(reader_half, true, sink, "test");
        assert_eq!(
            r.next().await.unwrap(),
            Some(Message {
                kind: 111,
                body: vec![7, 7]
            })
        );
    }
}
