//! The control channel's message layer (`ControlStream.c`, `stream.cpp:245-305`).
//!
//! Input events, IDR requests, loss statistics, rumble, HDR state and
//! termination all ride here. Whenever the client negotiated
//! `useReliableUdp == 13` every message is wrapped in AES-128-GCM, and an
//! unencrypted message on an encrypted stream is **dropped**
//! (`stream.cpp:746-750`) -- otherwise the encryption is advisory.
//!
//! The envelope has no replay protection of its own; the sequence number only
//! feeds the IV. [`ControlCodec`] therefore keeps a sliding window of sequence
//! numbers it has already accepted, so a captured message cannot be replayed
//! into the input path.

use crate::crypto::gcm::SessionCrypto;
use crate::crypto::{CryptoError, Result};
use crate::wire::control::{
    control_iv, msg, EncryptedHeader, EncryptedPacket, Origin, V2Header, ENCRYPTED_HEADER_LEN,
    ENCRYPTED_HEADER_TYPE, TAG_LEN, V2_HEADER_LEN,
};
use crate::wire::input::{decode_batch, InputRecord};

/// How far back the replay window reaches.
const REPLAY_WINDOW: u32 = 1024;

/// A decoded control message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlMessage {
    /// The client wants a keyframe, now. The encoder must be able to honour
    /// this immediately (`docs/bridging-design.md` §2.3).
    RequestIdr,
    /// Reference-frame invalidation. v1 answers every one of these with an IDR.
    InvalidateReferenceFrames,
    /// Periodic loss statistics.
    LossStats {
        /// The raw body, which varies by generation.
        payload: Vec<u8>,
    },
    /// A batch of input records.
    Input(Vec<InputRecord>),
    /// The client is leaving.
    Termination,
    /// HDR state change. Solstice does not offer HDR, so this is recorded only.
    HdrMode(bool),
    /// Something we know the framing of but do not act on.
    Unknown {
        /// Message type.
        msg_type: u16,
        /// Payload length.
        len: usize,
    },
}

/// Encodes and decodes control messages for one session.
pub struct ControlCodec {
    crypto: Option<SessionCrypto>,
    tx_sequence: u32,
    highest_rx: Option<u32>,
    seen: std::collections::VecDeque<u32>,
}

impl std::fmt::Debug for ControlCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlCodec")
            .field("encrypted", &self.crypto.is_some())
            .field("tx_sequence", &self.tx_sequence)
            .finish()
    }
}

impl ControlCodec {
    /// Build one. `key` is the `rikey`; pass `None` for a legacy plaintext
    /// stream.
    pub fn new(key: Option<&[u8; 16]>) -> Self {
        Self {
            crypto: key.map(SessionCrypto::new),
            tx_sequence: 0,
            highest_rx: None,
            seen: std::collections::VecDeque::new(),
        }
    }

    /// Whether this codec wraps messages in GCM.
    pub fn is_encrypted(&self) -> bool {
        self.crypto.is_some()
    }

    /// Decode one packet from the client.
    pub fn decode(&mut self, packet: &[u8]) -> Result<ControlMessage> {
        let plaintext = if self.crypto.is_some() {
            let parsed = EncryptedPacket::parse(packet)
                .map_err(|_| CryptoError::Pairing("malformed control envelope"))?;
            self.check_replay(parsed.header.sequence)?;
            let crypto = self.crypto.as_ref().expect("checked above");
            crypto.decrypt(
                &control_iv(parsed.header.sequence, Origin::Client),
                parsed.ciphertext,
                parsed.tag,
            )?
        } else {
            packet.to_vec()
        };

        let (header, payload) = V2Header::parse(&plaintext)
            .map_err(|_| CryptoError::Pairing("malformed control header"))?;
        Ok(match header.msg_type {
            msg::REQUEST_IDR_FRAME => ControlMessage::RequestIdr,
            msg::INVALIDATE_REF_FRAMES => ControlMessage::InvalidateReferenceFrames,
            msg::LOSS_STATS => ControlMessage::LossStats {
                payload: payload.to_vec(),
            },
            msg::INPUT_DATA => ControlMessage::Input(
                decode_batch(payload).map_err(|_| CryptoError::Pairing("malformed input batch"))?,
            ),
            msg::TERMINATION => ControlMessage::Termination,
            msg::HDR_MODE => ControlMessage::HdrMode(payload.first().copied().unwrap_or(0) != 0),
            other => ControlMessage::Unknown {
                msg_type: other,
                len: payload.len(),
            },
        })
    }

    /// Encode a host-originated message.
    pub fn encode(&mut self, msg_type: u16, payload: &[u8]) -> Result<Vec<u8>> {
        let mut plaintext = V2Header {
            msg_type,
            payload_length: payload.len() as u16,
        }
        .to_bytes()
        .to_vec();
        plaintext.extend_from_slice(payload);

        let Some(crypto) = &self.crypto else {
            return Ok(plaintext);
        };
        let sequence = self.tx_sequence;
        self.tx_sequence = self.tx_sequence.wrapping_add(1);
        let (ciphertext, tag) = crypto.encrypt(&control_iv(sequence, Origin::Host), &plaintext)?;

        let header = EncryptedHeader {
            header_type: ENCRYPTED_HEADER_TYPE,
            length: (4 + TAG_LEN + ciphertext.len()) as u16,
            sequence,
        };
        let mut out = Vec::with_capacity(ENCRYPTED_HEADER_LEN + TAG_LEN + ciphertext.len());
        out.extend_from_slice(&header.to_bytes());
        out.extend_from_slice(&tag);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn check_replay(&mut self, sequence: u32) -> Result<()> {
        if self.seen.contains(&sequence) {
            return Err(CryptoError::Pairing("replayed control sequence number"));
        }
        if let Some(highest) = self.highest_rx {
            if sequence.wrapping_add(REPLAY_WINDOW) < highest {
                return Err(CryptoError::Pairing("control sequence number too old"));
            }
        }
        self.seen.push_back(sequence);
        if self.seen.len() > REPLAY_WINDOW as usize {
            self.seen.pop_front();
        }
        self.highest_rx = Some(self.highest_rx.map_or(sequence, |h| h.max(sequence)));
        Ok(())
    }
}

/// The smallest well-formed plaintext body, for building host messages.
pub fn empty_payload() -> &'static [u8] {
    &[]
}

/// Size of the V2 header, re-exported for callers sizing buffers.
pub const HEADER_LEN: usize = V2_HEADER_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::input::encode_batch;

    const KEY: [u8; 16] = [0x33; 16];

    /// A client-side encoder, so the tests drive the real envelope rather than
    /// a hand-rolled approximation.
    fn client_encode(sequence: u32, msg_type: u16, payload: &[u8]) -> Vec<u8> {
        let crypto = SessionCrypto::new(&KEY);
        let mut plaintext = V2Header {
            msg_type,
            payload_length: payload.len() as u16,
        }
        .to_bytes()
        .to_vec();
        plaintext.extend_from_slice(payload);
        let (ciphertext, tag) = crypto
            .encrypt(&control_iv(sequence, Origin::Client), &plaintext)
            .unwrap();
        let header = EncryptedHeader {
            header_type: ENCRYPTED_HEADER_TYPE,
            length: (4 + TAG_LEN + ciphertext.len()) as u16,
            sequence,
        };
        let mut out = header.to_bytes().to_vec();
        out.extend_from_slice(&tag);
        out.extend_from_slice(&ciphertext);
        out
    }

    #[test]
    fn decodes_an_encrypted_idr_request() {
        let mut codec = ControlCodec::new(Some(&KEY));
        let packet = client_encode(0, msg::REQUEST_IDR_FRAME, &[]);
        assert_eq!(codec.decode(&packet).unwrap(), ControlMessage::RequestIdr);
    }

    #[test]
    fn decodes_an_input_batch() {
        let mut codec = ControlCodec::new(Some(&KEY));
        let records = vec![
            InputRecord::Key {
                down: true,
                flags: 0,
                key_code: 0x41,
                modifiers: 0,
            },
            InputRecord::MouseMoveAbs {
                x: 10,
                y: 20,
                width: 1920,
                height: 1080,
            },
        ];
        let packet = client_encode(1, msg::INPUT_DATA, &encode_batch(&records));
        assert_eq!(
            codec.decode(&packet).unwrap(),
            ControlMessage::Input(records)
        );
    }

    /// `stream.cpp:746-750`: an unencrypted message on an encrypted stream is
    /// not tolerated.
    #[test]
    fn plaintext_on_an_encrypted_stream_is_dropped() {
        let mut codec = ControlCodec::new(Some(&KEY));
        let plaintext = V2Header {
            msg_type: msg::REQUEST_IDR_FRAME,
            payload_length: 0,
        }
        .to_bytes();
        assert!(codec.decode(&plaintext).is_err());
    }

    #[test]
    fn a_replayed_message_is_refused() {
        let mut codec = ControlCodec::new(Some(&KEY));
        let packet = client_encode(5, msg::REQUEST_IDR_FRAME, &[]);
        assert!(codec.decode(&packet).is_ok());
        assert!(codec.decode(&packet).is_err());
    }

    #[test]
    fn a_very_old_sequence_number_is_refused() {
        let mut codec = ControlCodec::new(Some(&KEY));
        assert!(codec
            .decode(&client_encode(100_000, msg::REQUEST_IDR_FRAME, &[]))
            .is_ok());
        assert!(codec
            .decode(&client_encode(1, msg::REQUEST_IDR_FRAME, &[]))
            .is_err());
    }

    #[test]
    fn out_of_order_but_recent_messages_are_accepted() {
        let mut codec = ControlCodec::new(Some(&KEY));
        for seq in [10u32, 12, 11, 13] {
            assert!(
                codec
                    .decode(&client_encode(seq, msg::REQUEST_IDR_FRAME, &[]))
                    .is_ok(),
                "{seq}"
            );
        }
    }

    #[test]
    fn a_tampered_packet_fails_authentication() {
        let mut codec = ControlCodec::new(Some(&KEY));
        let mut packet = client_encode(0, msg::INPUT_DATA, &[0; 16]);
        let last = packet.len() - 1;
        packet[last] ^= 0xFF;
        assert!(codec.decode(&packet).is_err());
    }

    #[test]
    fn host_messages_round_trip_under_the_host_iv() {
        let mut codec = ControlCodec::new(Some(&KEY));
        let encoded = codec.encode(msg::RUMBLE, &[1, 2, 3, 4]).unwrap();
        let parsed = EncryptedPacket::parse(&encoded).unwrap();
        let crypto = SessionCrypto::new(&KEY);
        let plain = crypto
            .decrypt(
                &control_iv(parsed.header.sequence, Origin::Host),
                parsed.ciphertext,
                parsed.tag,
            )
            .unwrap();
        let (header, payload) = V2Header::parse(&plain).unwrap();
        assert_eq!(header.msg_type, msg::RUMBLE);
        assert_eq!(payload, &[1, 2, 3, 4]);

        // Host and client IVs must not collide at the same sequence number.
        assert!(crypto
            .decrypt(
                &control_iv(parsed.header.sequence, Origin::Client),
                parsed.ciphertext,
                parsed.tag
            )
            .is_err());
    }

    #[test]
    fn host_sequence_numbers_advance() {
        let mut codec = ControlCodec::new(Some(&KEY));
        let a = EncryptedPacket::parse(&codec.encode(msg::RUMBLE, &[]).unwrap())
            .unwrap()
            .header
            .sequence;
        let b = EncryptedPacket::parse(&codec.encode(msg::RUMBLE, &[]).unwrap())
            .unwrap()
            .header
            .sequence;
        assert_eq!(a + 1, b);
    }

    #[test]
    fn a_malformed_input_batch_does_not_become_a_message() {
        let mut codec = ControlCodec::new(Some(&KEY));
        // A record whose size field overruns the payload.
        let mut body = 999u32.to_be_bytes().to_vec();
        body.extend_from_slice(&3u32.to_le_bytes());
        let packet = client_encode(0, msg::INPUT_DATA, &body);
        assert!(codec.decode(&packet).is_err());
    }

    #[test]
    fn unknown_message_types_are_reported_not_guessed() {
        let mut codec = ControlCodec::new(Some(&KEY));
        let packet = client_encode(0, 0x5503, &[1, 2, 3]);
        assert_eq!(
            codec.decode(&packet).unwrap(),
            ControlMessage::Unknown {
                msg_type: 0x5503,
                len: 3
            }
        );
    }

    #[test]
    fn a_legacy_plaintext_codec_still_works() {
        let mut codec = ControlCodec::new(None);
        let mut plaintext = V2Header {
            msg_type: msg::TERMINATION,
            payload_length: 0,
        }
        .to_bytes()
        .to_vec();
        plaintext.truncate(V2_HEADER_LEN);
        assert_eq!(
            codec.decode(&plaintext).unwrap(),
            ControlMessage::Termination
        );
    }
}
