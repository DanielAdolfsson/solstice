//! Session lifecycle: what starts, in what order, and what tears it down.
//!
//! One session at a time by default. A session owns a backend connection, three
//! UDP channels and an encoder, and it is the unit that resource ceilings apply
//! to -- an authenticated client is otherwise a lever on the host's CPU
//! (`docs/security.md` §5.3).

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use solstice_backend::{Backend, InputEvent, Session};
use solstice_gamestream::input::translate;
use solstice_gamestream::nvhttp::{Host, HostConfig};
use solstice_gamestream::rtsp::sdp::{encryption, Limits, StreamConfig};
use solstice_gamestream::rtsp::StreamPorts;
use solstice_gamestream::stream::audio_tx::{opus_silence_packet, AudioConfig, AudioPacketizer};
use solstice_gamestream::stream::control::ControlMessage;
use solstice_gamestream::stream::video_tx::VideoConfig;
use solstice_video::encoder::EncoderConfig;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::net::{control, media, rtsp};
use crate::pipeline::{self, PipelineConfig};

/// Everything a running daemon owns.
pub struct Supervisor {
    config: Config,
    host: Arc<Host>,
    backend: Arc<dyn Backend>,
}

impl Supervisor {
    /// Build one.
    pub fn new(config: Config, host: Arc<Host>, backend: Arc<dyn Backend>) -> Self {
        Self {
            config,
            host,
            backend,
        }
    }

    /// The host state, for the CLI subcommands.
    pub fn host(&self) -> Arc<Host> {
        self.host.clone()
    }

    /// Ports derived from the configured base.
    pub fn ports(&self) -> StreamPorts {
        StreamPorts {
            video: self.config.server.video_port(),
            audio: self.config.server.audio_port(),
            control: self.config.server.control_port(),
        }
    }

    /// The ANNOUNCE ceilings.
    pub fn limits(&self) -> Limits {
        Limits {
            max_width: self.config.limits.max_width,
            max_height: self.config.limits.max_height,
            max_fps: self.config.limits.max_fps,
            max_bitrate_kbps: self.config.limits.max_bitrate_kbps,
            max_packet_size: 1392,
        }
    }

    /// What the host insists the client negotiate.
    pub fn required_encryption(&self) -> u32 {
        if self.config.security.require_encryption {
            encryption::ALL
        } else {
            // Control is always encrypted even in the permissive mode: that is
            // the one thing Sunshine also always requires.
            encryption::CONTROL_V2
        }
    }

    /// Run until the process is told to stop.
    pub async fn run(self) -> std::io::Result<()> {
        let bind = self.config.server.bind;

        // First, so that a second daemon on the same state directory fails
        // here rather than after binding half its ports.
        let management = crate::management::bind(&self.config.server.control_socket())?;
        tokio::spawn(management.serve(Arc::new(crate::management::Context {
            host: self.host.clone(),
            pairing_window: self.config.security.pairing_window,
            backend: self.backend.name(),
        })));
        let (negotiated_tx, mut negotiated_rx) = mpsc::channel(4);

        let identity_cert = self.host.identity.cert_pem().to_owned();
        let identity_key = self.host.identity.key_pem().to_owned();
        let tls_config = crate::tls::server_config(&identity_cert, &identity_key)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        tokio::spawn(crate::net::nvhttp::serve_plaintext(
            self.host.clone(),
            SocketAddr::new(bind, self.config.server.port),
        ));
        tokio::spawn(crate::net::nvhttp::serve_tls(
            self.host.clone(),
            SocketAddr::new(bind, self.config.server.https_port()),
            Arc::new(tls_config),
        ));
        tokio::spawn(rtsp::serve(
            SocketAddr::new(bind, self.config.server.rtsp_port()),
            self.host.clone(),
            self.ports(),
            self.limits(),
            encryption::ALL,
            self.required_encryption(),
            negotiated_tx,
        ));

        tracing::info!(
            name = %self.config.server.name,
            %bind,
            port = self.config.server.port,
            backend = self.backend.name(),
            "solstice is up"
        );

        while let Some(negotiated) = negotiated_rx.recv().await {
            let session_key = {
                let sessions = self.host.sessions.lock().expect("session lock");
                sessions
                    .iter()
                    .find(|s| s.id == negotiated.session_id)
                    .map(|s| {
                        (
                            *s.rikey,
                            s.rikey_id,
                            s.av_ping_payload,
                            s.control_connect_data,
                        )
                    })
            };
            let Some((key, rikey_id, ping_payload, connect_data)) = session_key else {
                tracing::warn!(session = %negotiated.session_id, "no launch session for this PLAY");
                continue;
            };

            let config = self.config.clone();
            let backend = self.backend.clone();
            let host = self.host.clone();
            tokio::spawn(async move {
                let result = run_stream(
                    config,
                    backend,
                    *negotiated.config,
                    key,
                    rikey_id,
                    ping_payload,
                    connect_data,
                    bind,
                )
                .await;
                if let Err(e) = result {
                    tracing::warn!(error = %e, "stream session ended with an error");
                }
                // Whatever happened, the session is over.
                host.sessions.lock().expect("session lock").clear();
            });
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_stream(
    config: Config,
    backend: Arc<dyn Backend>,
    stream_config: StreamConfig,
    key: [u8; 16],
    rikey_id: i32,
    ping_payload: [u8; 16],
    connect_data: u32,
    bind: IpAddr,
) -> std::io::Result<()> {
    // 1. The backend first: if the desktop is unreachable there is no point
    //    binding sockets.
    let session = backend
        .connect()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let (backend_w, backend_h) = session.dimensions();

    // 2. Ask it to match the client's geometry. Declining is normal, and the
    //    pipeline letterboxes instead.
    let resized = session
        .request_resize(stream_config.width, stream_config.height)
        .await
        .unwrap_or(false);
    if resized {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    tracing::info!(
        backend = ?(backend_w, backend_h),
        requested = ?(stream_config.width, stream_config.height),
        resized,
        "backend geometry"
    );

    // 3. Bind the media sockets. Binding only: the pings that say where the
    //    client is cannot be waited for yet, see below.
    let video_socket =
        Arc::new(UdpSocket::bind(SocketAddr::new(bind, config.server.video_port())).await?);
    let audio_socket =
        Arc::new(UdpSocket::bind(SocketAddr::new(bind, config.server.audio_port())).await?);

    // 4. The control channel, on its own thread because ENet is a poll loop.
    //
    //    This must come *before* waiting for the video ping. Moonlight
    //    establishes the ENet control stream at `STAGE_CONTROL_STREAM_START`
    //    and only then starts the video stream, which is what begins the ping
    //    thread (`Connection.c:483-497`, `VideoStream.c:382-384`). A host that
    //    waits for the ping first and binds ENet afterwards deadlocks against
    //    a real client: each side is waiting for the other to go first. Our
    //    own test client pings immediately and so never showed it
    //    (`docs/roadmap.md` §3).
    let (control_tx, mut control_rx) = mpsc::channel(256);
    let running = Arc::new(AtomicBool::new(true));
    {
        let socket = control::bind(SocketAddr::new(bind, config.server.control_port()))?;
        let key = stream_config.control_encrypted().then_some(key);
        let running = running.clone();
        std::thread::Builder::new()
            .name("solstice-control".into())
            .spawn(move || {
                if let Err(e) = control::run(socket, key, connect_data, control_tx, running) {
                    tracing::warn!(error = %e, "control thread ended");
                }
            })?;
    }

    // 4b. Now the pings can be waited for.
    let video_peer = media::await_peer(&video_socket, &ping_payload).await?;
    let audio_peer = match media::await_peer(&audio_socket, &ping_payload).await {
        Ok(peer) => Some(peer),
        Err(e) => {
            tracing::warn!(error = %e, "no audio ping; continuing without audio");
            None
        }
    };

    // 5. The pipeline.
    let frame_interval = Duration::from_nanos(1_000_000_000 / stream_config.fps.max(1) as u64);
    let (packets_tx, packets_rx) = mpsc::channel(8);
    tokio::spawn(media::sender_task(
        video_socket.clone(),
        video_peer,
        packets_rx,
        frame_interval,
    ));

    let encoder = pipeline::build_encoder(
        config.video.encoder,
        EncoderConfig {
            width: stream_config.width,
            height: stream_config.height,
            fps: stream_config.fps,
            bitrate_kbps: stream_config.bitrate_kbps,
            slices_per_frame: stream_config.slices_per_frame,
        },
    )
    .map_err(|e| std::io::Error::other(e.to_string()))?;

    let (idr_tx, idr_rx) = mpsc::channel(8);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();

    // 6. Audio: Opus silence at the negotiated packet duration. The RFB backend
    //    has nothing else to send, and a client that gets no audio stream at
    //    all takes paths nobody tests.
    if config.audio.enabled {
        if let Some(peer) = audio_peer {
            let socket = audio_socket.clone();
            let audio_config = AudioConfig {
                packet_duration_ms: stream_config.audio_packet_duration,
                encrypt: stream_config.audio_encrypted(),
                rikey_id,
            };
            let channels = stream_config.audio_channels as u8;
            let key = stream_config.audio_encrypted().then_some(key);
            tokio::spawn(async move {
                let mut packetizer = AudioPacketizer::new(audio_config, key.as_ref());
                let mut ticker = tokio::time::interval(Duration::from_millis(
                    audio_config.packet_duration_ms.max(1) as u64,
                ));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let silence = opus_silence_packet(channels);
                loop {
                    ticker.tick().await;
                    for datagram in packetizer.packetize(&silence) {
                        if socket.send_to(&datagram, peer).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    }

    // 7. Input and IDR requests, from the control channel to the backend.
    let pipeline_config = PipelineConfig {
        width: stream_config.width,
        height: stream_config.height,
        fps: stream_config.fps,
        idle_fps: config.video.idle_fps,
        bitrate_kbps: stream_config.bitrate_kbps,
        slices_per_frame: stream_config.slices_per_frame,
        video: VideoConfig {
            packet_size: stream_config.packet_size as usize,
            fec_percentage: config.video.fec_percentage,
            min_required_fec_packets: stream_config.min_required_fec_packets,
            encrypt: stream_config.video_encrypted(),
        },
    };
    let video_key = stream_config.video_encrypted().then_some(key);

    let pipeline = {
        let session_ref: &dyn Session = &*session;
        pipeline::run(
            session_ref,
            pipeline_config,
            encoder,
            video_key,
            packets_tx,
            idr_rx,
            stop_rx,
        )
    };
    tokio::pin!(pipeline);

    loop {
        tokio::select! {
            exit = &mut pipeline => {
                tracing::info!(?exit, "pipeline ended");
                break;
            }
            Some(event) = control_rx.recv() => {
                match event {
                    control::ControlEvent::Message(ControlMessage::RequestIdr)
                    | control::ControlEvent::Message(
                        ControlMessage::InvalidateReferenceFrames
                    ) => {
                        // Reference-frame invalidation is answered with an IDR
                        // in v1 rather than tracked properly
                        // (`docs/bridging-design.md` §2.3).
                        let _ = idr_tx.try_send(());
                    }
                    control::ControlEvent::Message(ControlMessage::Input(records)) => {
                        let translation = translate(&records);
                        if !translation.dropped.is_empty() {
                            tracing::debug!(dropped = ?translation.dropped, "input dropped");
                        }
                        for event in translation.events {
                            forward_input(&*session, event).await;
                        }
                    }
                    control::ControlEvent::Message(ControlMessage::Termination) => {
                        tracing::info!("client terminated the session");
                        break;
                    }
                    control::ControlEvent::Disconnected => {
                        tracing::info!("control peer went away");
                        break;
                    }
                    other => tracing::debug!(?other, "control event"),
                }
            }
            else => break,
        }
    }

    let _ = stop_tx.send(());
    running.store(false, std::sync::atomic::Ordering::Relaxed);
    session.close().await;
    Ok(())
}

async fn forward_input(session: &dyn Session, event: InputEvent) {
    if let Err(e) = session.send_input(event).await {
        tracing::warn!(error = %e, "forwarding input failed");
    }
}

/// Build the host state from configuration.
pub fn build_host(
    config: &Config,
    identity: solstice_gamestream::crypto::certs::HostIdentity,
    clients: solstice_gamestream::crypto::certs::ClientStore,
) -> Host {
    let host_config = HostConfig {
        name: config.server.name.clone(),
        uuid: stable_uuid(&config.server.name),
        app_title: config.server.app_title.clone(),
        port: config.server.port,
        https_port: config.server.https_port(),
        rtsp_port: config.server.rtsp_port(),
        local_ip: config.server.bind.to_string(),
        mac: "00:00:00:00:00:00".into(),
        max_sessions: config.limits.max_sessions,
        allow_pairing_from: config.security.allow_pairing_from.clone(),
    };
    let mut host = Host::new(host_config, identity, clients);
    host.pairing =
        std::sync::Mutex::new(solstice_gamestream::crypto::pairing::PairingManager::new(
            config.security.max_pair_attempts,
        ));
    host
}

/// A UUID derived from the host name, so it survives restarts without needing
/// to be stored.
fn stable_uuid(name: &str) -> String {
    let digest =
        solstice_gamestream::crypto::gcm::sha256_concat(&[b"solstice-uuid", name.as_bytes()]);
    hex::encode(&digest[..16]).to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_uuid_is_stable_and_differs_per_host() {
        assert_eq!(stable_uuid("a"), stable_uuid("a"));
        assert_ne!(stable_uuid("a"), stable_uuid("b"));
        assert_eq!(stable_uuid("a").len(), 32);
    }

    #[test]
    fn required_encryption_follows_the_policy() {
        let identity = solstice_gamestream::crypto::certs::HostIdentity::generate("t").unwrap();
        let mut config = Config::default();
        let host = Arc::new(build_host(
            &config,
            identity,
            solstice_gamestream::crypto::certs::ClientStore::new(),
        ));
        let backend: Arc<dyn Backend> =
            Arc::new(crate::testpattern::TestPatternBackend::new(320, 240, 60));
        let s = Supervisor::new(config.clone(), host.clone(), backend.clone());
        assert_eq!(s.required_encryption(), encryption::ALL);

        config.security.require_encryption = false;
        let s = Supervisor::new(config, host, backend);
        assert_eq!(s.required_encryption(), encryption::CONTROL_V2);
    }

    #[test]
    fn ports_follow_the_configured_base() {
        let identity = solstice_gamestream::crypto::certs::HostIdentity::generate("t").unwrap();
        let mut config = Config::default();
        config.server.port = 50000;
        let host = Arc::new(build_host(
            &config,
            identity,
            solstice_gamestream::crypto::certs::ClientStore::new(),
        ));
        let backend: Arc<dyn Backend> =
            Arc::new(crate::testpattern::TestPatternBackend::new(320, 240, 60));
        let s = Supervisor::new(config, host, backend);
        assert_eq!(
            s.ports(),
            StreamPorts {
                video: 50009,
                audio: 50011,
                control: 50010
            }
        );
    }
}
