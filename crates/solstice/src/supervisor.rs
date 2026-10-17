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
use solstice_gamestream::stream::audio_tx::AudioConfig;
use solstice_gamestream::stream::control::ControlMessage;
use solstice_gamestream::stream::video_tx::VideoConfig;
use solstice_video::encoder::EncoderConfig;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::endpoint::Endpoints;
use crate::net::{control, media, rtsp};
use crate::pipeline::{self, PipelineConfig};

/// Everything a running daemon owns.
pub struct Supervisor {
    config: Config,
    host: Arc<Host>,
    endpoints: Arc<Endpoints>,
}

impl Supervisor {
    /// Build one, and offer its endpoints as the host's apps.
    pub fn new(config: Config, host: Arc<Host>, endpoints: Endpoints) -> Self {
        endpoints.publish(&host);
        Self {
            config,
            host,
            endpoints: Arc::new(endpoints),
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
            endpoints: self.endpoints.clone(),
            limits: self.config.limits,
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
            "solstice is up"
        );
        for entry in self.endpoints.list() {
            tracing::info!(endpoint = %entry.name, app = entry.id, "{}", entry.detail);
        }
        if self.endpoints.is_empty() {
            // Legitimate -- pair first, add desktops later -- but a daemon that
            // was meant to have one and does not would otherwise look healthy.
            tracing::warn!(
                "no endpoints configured; Moonlight will see a \"No desktops\" placeholder"
            );
        }

        // Every stream binds the same fixed ports, so one must have let go of
        // them before the next binds. A client that relaunches straight after
        // a `TERMINATION` arrives while the old stream is still lingering for
        // its acknowledgement; without this it got `EADDRINUSE`. With it, the
        // new stream waits a moment, and the client retries its `CONNECT`
        // meanwhile.
        let ports_free = Arc::new(tokio::sync::Mutex::new(()));

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
                            s.app_id,
                        )
                    })
            };
            let Some((key, rikey_id, ping_payload, connect_data, app_id)) = session_key else {
                tracing::warn!(session = %negotiated.session_id, "no launch session for this PLAY");
                continue;
            };
            // `/launch` accepted only an app on offer, so this misses only if
            // the endpoint went away in between.
            let Some(entry) = self.endpoints.get(app_id) else {
                tracing::warn!(session = %negotiated.session_id, app = app_id, "no endpoint for this app");
                self.host.remove_session(&negotiated.session_id);
                continue;
            };
            tracing::info!(session = %negotiated.session_id, endpoint = %entry.name, "streaming");

            let config = self.config.clone();
            let backend = entry.backend.clone();
            let host = self.host.clone();
            let ports_free = ports_free.clone();
            tokio::spawn(async move {
                let session_id = negotiated.session_id;
                let _ports = ports_free.lock().await;
                let result = run_stream(
                    config,
                    backend,
                    &host,
                    &session_id,
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
                // Whatever happened, this session is over. Only this one: with
                // `max_sessions` above one, another client's is still running.
                host.remove_session(&session_id);
            });
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_stream(
    config: Config,
    backend: Arc<dyn Backend>,
    host: &Host,
    session_id: &str,
    stream_config: StreamConfig,
    key: [u8; 16],
    rikey_id: i32,
    ping_payload: [u8; 16],
    connect_data: u32,
    bind: IpAddr,
) -> std::io::Result<()> {
    // 0. Watch for the launch record going away -- revocation, or `/cancel`.
    //    Subscribed before anything else, so an end that lands while the
    //    stream is still being set up is seen when the loop below starts.
    let mut ended = host.watch_ended();

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
    let (outgoing_tx, outgoing_rx) = std::sync::mpsc::channel();
    let running = Arc::new(AtomicBool::new(true));
    // Every return from here on stops the thread, the early ones included: a
    // client that never sends its video ping must not leave the control port
    // held by a thread nobody will stop.
    let _stop_control = StopOnDrop(running.clone());
    let control_thread = {
        let socket = control::bind(SocketAddr::new(bind, config.server.control_port()))?;
        let key = stream_config.control_encrypted().then_some(key);
        let running = running.clone();
        std::thread::Builder::new()
            .name("solstice-control".into())
            .spawn(move || {
                if let Err(e) =
                    control::run(socket, key, connect_data, control_tx, outgoing_rx, running)
                {
                    tracing::warn!(error = %e, "control thread ended");
                }
            })?
    };

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
    //
    //    The media tasks belong to this session and hold its sockets, so they
    //    are spawned into a set the session owns: dropping it aborts them,
    //    whichever way this function returns. Left detached, the audio task
    //    outlived every stream and kept the audio port bound, so a daemon
    //    could serve exactly one stream in its lifetime (`docs/roadmap.md` §5).
    let mut media_tasks = tokio::task::JoinSet::new();
    let frame_interval = Duration::from_nanos(1_000_000_000 / stream_config.fps.max(1) as u64);
    let (packets_tx, packets_rx) = mpsc::channel(8);
    media_tasks.spawn(media::sender_task(
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

    // 6. Audio: the backend's, where it has any, and silence otherwise, one
    //    packet per negotiated duration either way. The RFB backend has
    //    nothing to send, and a client that gets no audio stream at all takes
    //    paths nobody tests.
    if config.audio.enabled {
        if let Some(peer) = audio_peer {
            let audio_config = AudioConfig {
                packet_duration_ms: stream_config.audio_packet_duration,
                encrypt: stream_config.audio_encrypted(),
                rikey_id,
            };
            media_tasks.spawn(crate::audio::run(
                audio_socket.clone(),
                peer,
                stream_config.clone(),
                audio_config,
                stream_config.audio_encrypted().then_some(key),
                session.take_audio(),
            ));
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

    // An end that landed during setup has already changed the value.
    ended.mark_changed();
    loop {
        tokio::select! {
            Ok(()) = ended.changed() => {
                if !host.has_session(session_id) {
                    // `docs/security.md` §3.4: a revoked client's session is
                    // torn down, not left to run out. Told, so that it stops
                    // rather than reconnecting into a host that refuses it.
                    tracing::info!(session = %session_id, "the session was ended by the host");
                    let _ = outgoing_tx.send(control::Outgoing::Terminate(
                        control::TERMINATED_CLOSED,
                    ));
                    break;
                }
            }
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
    // Their sockets are the next session's ports.
    media_tasks.shutdown().await;
    // The thread may linger to see a `TERMINATION` acknowledged. Waited for,
    // so that the control port is free again before the next session binds it.
    let _ = tokio::task::spawn_blocking(move || control_thread.join()).await;
    Ok(())
}

/// Clears the flag the control thread polls, however the stream ends.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Relaxed);
    }
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

    fn test_pattern() -> Endpoints {
        let backend: Arc<dyn Backend> =
            Arc::new(crate::testpattern::TestPatternBackend::new(320, 240, 60));
        Endpoints::single("Desktop", backend)
    }

    #[test]
    fn the_endpoints_are_what_the_host_offers() {
        let identity = solstice_gamestream::crypto::certs::HostIdentity::generate("t").unwrap();
        let config = Config::default();
        let host = Arc::new(build_host(
            &config,
            identity,
            solstice_gamestream::crypto::certs::ClientStore::new(),
        ));
        assert!(host.apps().is_empty(), "nothing until the supervisor says");
        let _s = Supervisor::new(config, host.clone(), test_pattern());
        assert_eq!(host.apps().len(), 1);
        assert!(host.has_app(crate::endpoint::LEGACY_APP_ID));
    }

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
        let s = Supervisor::new(config.clone(), host.clone(), test_pattern());
        assert_eq!(s.required_encryption(), encryption::ALL);

        config.security.require_encryption = false;
        let s = Supervisor::new(config, host, test_pattern());
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
        let s = Supervisor::new(config, host, test_pattern());
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
