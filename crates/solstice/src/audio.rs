//! The audio sender: backend frames, or silence, to UDP 48000.
//!
//! One packet per negotiated packet duration, always. With the `audio`
//! feature the packets come out of [`solstice_audio::AudioBridge`], which
//! passes SPICE's Opus through where it lines up with what the client asked
//! for and re-encodes it where it does not, and which encodes silence in the
//! client's own layout when there is nothing to play. Without the feature
//! there is no codec, so the sender falls back to a canned stereo silence
//! packet, and backend audio is dropped.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use solstice_backend::AudioFrame;
use solstice_gamestream::rtsp::sdp::StreamConfig;
use solstice_gamestream::stream::audio_tx::{AudioConfig, AudioPacketizer};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Send audio to `peer` until the socket fails or the task is aborted.
pub async fn run(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    stream_config: StreamConfig,
    packetizer_config: AudioConfig,
    key: Option<[u8; 16]>,
    backend: Option<mpsc::Receiver<AudioFrame>>,
) {
    let mut packetizer = AudioPacketizer::new(packetizer_config, key.as_ref());
    let mut source = Source::new(&stream_config, backend);
    let mut ticker = tokio::time::interval(Duration::from_millis(
        packetizer_config.packet_duration_ms.max(1) as u64,
    ));
    // Burst, not Delay: a tick more than a few milliseconds late under Delay
    // pushes every later tick back, so a busy runtime sends fewer packets
    // than the client plays. The backend keeps its own pace, the queue grows
    // until the bridge trims it, and every trim is a jump in the sound. With
    // Burst a late tick is made up straight away, and the client's jitter
    // buffer absorbs the clump.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    loop {
        tokio::select! {
            // A frame that lands with a tick goes in first, so the tick can
            // send it rather than silence.
            biased;
            frame = source.next_frame() => match frame {
                Some(frame) => source.push(&frame),
                None => source.backend_ended(),
            },
            _ = ticker.tick() => {
                let packet = source.tick();
                for datagram in packetizer.packetize(&packet) {
                    if socket.send_to(&datagram, peer).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// Where the packets come from.
struct Source {
    backend: Option<mpsc::Receiver<AudioFrame>>,
    #[cfg(feature = "audio")]
    bridge: Option<LoggedBridge>,
    /// What is sent when there is no bridge.
    canned_silence: Vec<u8>,
}

impl Source {
    fn new(stream_config: &StreamConfig, backend: Option<mpsc::Receiver<AudioFrame>>) -> Self {
        let canned_silence = solstice_gamestream::stream::audio_tx::opus_silence_packet(
            stream_config.audio_channels as u8,
            stream_config.audio_packet_duration,
        );
        #[cfg(feature = "audio")]
        {
            let bridge = LoggedBridge::new(stream_config);
            Source {
                backend,
                bridge,
                canned_silence,
            }
        }
        #[cfg(not(feature = "audio"))]
        {
            if backend.is_some() {
                tracing::warn!(
                    "the backend has audio, but this build has no Opus codec \
                     (the `audio` feature); sending silence"
                );
            }
            Source {
                backend: None,
                canned_silence,
            }
        }
    }

    /// The next backend frame. Pends forever once there is no backend audio,
    /// so the ticker alone drives the loop.
    async fn next_frame(&mut self) -> Option<AudioFrame> {
        match &mut self.backend {
            Some(rx) => rx.recv().await,
            None => std::future::pending().await,
        }
    }

    fn backend_ended(&mut self) {
        tracing::debug!("the backend's audio ended; sending silence");
        self.backend = None;
    }

    fn push(&mut self, _frame: &AudioFrame) {
        #[cfg(feature = "audio")]
        if let Some(bridge) = &mut self.bridge {
            bridge.push(_frame);
        }
    }

    fn tick(&mut self) -> Vec<u8> {
        #[cfg(feature = "audio")]
        if let Some(bridge) = &mut self.bridge {
            return bridge.tick();
        }
        self.canned_silence.clone()
    }
}

/// The bridge, and a log line when the session ends. The sender is aborted
/// rather than returning, so the end of the session is a drop.
#[cfg(feature = "audio")]
struct LoggedBridge {
    bridge: solstice_audio::AudioBridge,
    started: bool,
}

#[cfg(feature = "audio")]
impl LoggedBridge {
    fn new(stream_config: &StreamConfig) -> Option<Self> {
        let config = output_config(stream_config);
        match solstice_audio::AudioBridge::new(config) {
            Ok(bridge) => {
                tracing::info!(
                    channels = config.layout.channels,
                    streams = config.layout.streams,
                    coupled = config.layout.coupled_streams,
                    bitrate = config.bitrate,
                    packet_ms = config.packet_ms,
                    "audio stream"
                );
                Some(LoggedBridge {
                    bridge,
                    started: false,
                })
            }
            Err(e) => {
                // Moonlight asks for 5 or 10 ms, both of which build; this is
                // some other client, which gets the old canned silence.
                tracing::warn!(error = %e, "no audio encoder for this stream; sending silence");
                None
            }
        }
    }

    fn push(&mut self, frame: &AudioFrame) {
        self.bridge.push(frame);
        if !self.started && self.bridge.queued() > 0 {
            self.started = true;
            let stats = self.bridge.stats();
            tracing::info!(
                pass_through = stats.passed_through > 0,
                format = ?frame.format,
                "backend audio is playing"
            );
        }
    }

    fn tick(&mut self) -> Vec<u8> {
        self.bridge.tick()
    }
}

#[cfg(feature = "audio")]
impl Drop for LoggedBridge {
    fn drop(&mut self) {
        let s = self.bridge.stats();
        tracing::info!(
            passed_through = s.passed_through,
            encoded = s.encoded,
            silent_ticks = s.silent_ticks,
            underruns = s.underruns,
            dropped = s.dropped,
            rejected = s.rejected,
            "audio stream ended"
        );
    }
}

/// What the client will decode, in the bridge's terms.
#[cfg(feature = "audio")]
pub fn output_config(stream_config: &StreamConfig) -> solstice_audio::OutputConfig {
    use solstice_gamestream::stream::opus_layout::OpusLayout;
    let layout = OpusLayout::negotiated(stream_config);
    solstice_audio::OutputConfig {
        layout: solstice_audio::codec::Layout {
            channels: layout.channels,
            streams: layout.streams,
            coupled_streams: layout.coupled_streams,
            mapping: layout.mapping,
        },
        bitrate: layout.bitrate,
        packet_ms: stream_config.audio_packet_duration,
    }
}
