//! The frame loop: backend framebuffer in, UDP datagrams out.
//!
//! ```text
//! damage -> [convert] -> encode -> frame header -> shards -> FEC -> GCM -> UDP
//!    ^                     ^
//!    |                     '-- force IDR, from the control stream
//!    '-- synthetic frame clock
//! ```
//!
//! The clock is the part with no analogue on either side: RFB and SPICE have no
//! frame rate, and Moonlight expects a stream that does not go quiet. So a
//! frame goes out on every tick whether or not anything changed, and a repeat
//! costs a handful of bytes because it predicts perfectly from its predecessor
//! -- but not a handful of CPU, which is why the clock slows to `idle_fps` once
//! the screen has been still a while (`solstice_video::clock`).

use std::time::{Duration, Instant};

use solstice_backend::{BackendEvent, Session};
use solstice_gamestream::stream::video_tx::{VideoConfig, VideoPacketizer};
use solstice_gamestream::wire::video::FrameType;
use solstice_video::convert::{convert_full, convert_rect, convert_scaled};
use solstice_video::encoder::{EncoderConfig, VideoEncoder};
use solstice_video::{FrameClock, I420Frame};
use tokio::sync::mpsc;

/// Settings for one session's video pipeline.
#[derive(Clone, Copy, Debug)]
pub struct PipelineConfig {
    /// Stream width, as negotiated.
    pub width: u32,
    /// Stream height, as negotiated.
    pub height: u32,
    /// Stream framerate.
    pub fps: u32,
    /// Keep-alive framerate while the screen is still.
    pub idle_fps: u32,
    /// Target bitrate.
    pub bitrate_kbps: u32,
    /// Slices per frame.
    pub slices_per_frame: u32,
    /// Video packetiser settings.
    pub video: VideoConfig,
}

/// Why the pipeline stopped.
#[derive(Debug, PartialEq, Eq)]
pub enum PipelineExit {
    /// The backend went away.
    BackendDisconnected,
    /// The network side closed.
    ClientGone,
    /// The caller asked it to stop.
    Stopped,
}

/// Run the pipeline until something ends it.
pub async fn run(
    session: &dyn Session,
    config: PipelineConfig,
    mut encoder: Box<dyn VideoEncoder>,
    key: Option<[u8; 16]>,
    packets: mpsc::Sender<Vec<Vec<u8>>>,
    mut idr_requests: mpsc::Receiver<()>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) -> PipelineExit {
    let mut packetizer = VideoPacketizer::new(config.video, key.as_ref());
    let mut clock = FrameClock::new(config.fps, Instant::now()).with_idle_rate(config.idle_fps);
    let mut events = session.subscribe();
    let framebuffer = session.framebuffer();

    let (enc_w, enc_h) = encoder.dimensions();
    let mut frame = I420Frame::new(enc_w, enc_h);
    // Scaling is only needed when the backend declined to resize; when the
    // geometries agree the per-rectangle path runs instead, which is the whole
    // point of tracking damage.
    let mut scaling = {
        let fb = framebuffer.read();
        (fb.width(), fb.height()) != (enc_w, enc_h)
    };
    if scaling {
        tracing::info!(
            backend = ?{ let fb = framebuffer.read(); (fb.width(), fb.height()) },
            stream = ?(enc_w, enc_h),
            "backend declined to resize; letterboxing"
        );
    }
    {
        // Seed the first frame from whatever is on screen now.
        let fb = framebuffer.read();
        if scaling {
            convert_scaled(&fb, &mut frame);
        } else {
            convert_full(&fb, &mut frame);
        }
    }

    loop {
        let now = Instant::now();
        if let Some(tick) = clock.poll(now) {
            // The latency the client is told covers conversion as well as the
            // encode: both are host time spent on this frame, and a scaled
            // conversion can cost as much as the encode.
            let started = Instant::now();
            // Convert only what changed, unless the geometries disagree -- a
            // scaled frame has no one-to-one rectangle mapping.
            if let Some(rect) = tick.damage {
                let fb = framebuffer.read();
                if scaling {
                    convert_scaled(&fb, &mut frame);
                } else if !convert_rect(&fb, rect, &mut frame) {
                    // The damage rectangle no longer fits -- a resize raced us.
                    convert_full(&fb, &mut frame);
                }
            }

            let frame_type = if tick.force_idr {
                FrameType::Idr
            } else {
                FrameType::P
            };
            let encoded = match encoder.encode(&frame, tick.force_idr) {
                Ok(encoded) => encoded,
                Err(e) => {
                    tracing::error!(error = %e, "encode failed");
                    return PipelineExit::BackendDisconnected;
                }
            };
            let latency_tenths = (started.elapsed().as_micros() / 100).min(u16::MAX as u128) as u16;
            let frame_type = if encoded.is_idr {
                FrameType::Idr
            } else {
                frame_type
            };

            match packetizer.packetize(&encoded.data, frame_type, tick.timestamp, latency_tenths) {
                Ok(built) => {
                    if packets.send(built.packets).await.is_err() {
                        return PipelineExit::ClientGone;
                    }
                }
                Err(e) => tracing::error!(error = %e, "packetising failed"),
            }
        }

        let sleep = clock
            .time_until_next(Instant::now())
            .max(Duration::from_micros(200));
        tokio::select! {
            biased;
            _ = &mut stop => return PipelineExit::Stopped,
            Some(()) = idr_requests.recv() => {
                tracing::debug!("client requested an IDR");
                clock.request_idr();
            }
            event = events.recv() => match event {
                Ok(BackendEvent::Damage(rect)) => clock.damage(rect),
                Ok(BackendEvent::Resize { width, height }) => {
                    tracing::info!(width, height, "backend resized");
                    scaling = (width, height) != (enc_w, enc_h);
                    clock.damage(solstice_backend::Rect::whole(enc_w, enc_h));
                    // A resize invalidates every reference frame.
                    clock.request_idr();
                }
                Ok(BackendEvent::Disconnected) => return PipelineExit::BackendDisconnected,
                // `BackendEvent` is non-exhaustive, so a future variant must
                // not stop the clock.
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    // Falling behind on damage is survivable: the next frame is
                    // simply treated as fully damaged.
                    tracing::warn!(missed = n, "damage events lagged");
                    clock.damage(solstice_backend::Rect::whole(enc_w, enc_h));
                }
                Err(_) => return PipelineExit::BackendDisconnected,
            },
            _ = tokio::time::sleep(sleep) => {}
        }
    }
}

/// Build the encoder the configuration asks for.
pub fn build_encoder(
    kind: crate::config::Encoder,
    config: EncoderConfig,
) -> Result<Box<dyn VideoEncoder>, solstice_video::VideoError> {
    match kind {
        #[cfg(feature = "openh264")]
        crate::config::Encoder::OpenH264 => Ok(Box::new(
            solstice_video::openh264::OpenH264Encoder::new(config)?,
        )),
        #[cfg(not(feature = "openh264"))]
        crate::config::Encoder::OpenH264 => Err(solstice_video::VideoError::NoEncoder),
        crate::config::Encoder::Null => Ok(Box::new(solstice_video::null::NullEncoder::new(
            config, 2048,
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testpattern::TestPatternSession;
    use solstice_gamestream::wire::video::{flags, VideoPacketHeader};

    fn pipeline_config() -> PipelineConfig {
        PipelineConfig {
            width: 320,
            height: 240,
            fps: 60,
            idle_fps: 60,
            bitrate_kbps: 4000,
            slices_per_frame: 1,
            video: VideoConfig {
                packet_size: 1024,
                fec_percentage: 20,
                min_required_fec_packets: 2,
                encrypt: false,
            },
        }
    }

    #[tokio::test]
    async fn the_pipeline_produces_packets_for_a_live_backend() {
        let session = TestPatternSession::start(320, 240, 60);
        let config = pipeline_config();
        let encoder = build_encoder(
            crate::config::Encoder::Null,
            EncoderConfig {
                width: 320,
                height: 240,
                fps: 60,
                bitrate_kbps: 4000,
                slices_per_frame: 1,
            },
        )
        .unwrap();

        let (tx, mut rx) = mpsc::channel(64);
        let (_idr_tx, idr_rx) = mpsc::channel(4);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();

        let handle = tokio::spawn(async move {
            let session = session;
            run(&session, config, encoder, None, tx, idr_rx, stop_rx).await
        });

        // The first frame must be a keyframe and must be marked as one.
        let first = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .expect("no packets");
        assert!(!first.is_empty());
        let (header, payload) = VideoPacketHeader::parse(&first[0]).unwrap();
        assert!(header.nv.flags & flags::SOF != 0);
        assert_eq!(
            header.nv.frame_index,
            solstice_gamestream::stream::video_tx::FIRST_FRAME_INDEX
        );
        let fh = solstice_gamestream::wire::video::FrameHeader::parse(
            &mut solstice_gamestream::wire::Reader::new(payload),
        )
        .unwrap();
        assert_eq!(fh.frame_type, FrameType::Idr);

        // And frames keep coming.
        for _ in 0..3 {
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap();
        }

        let _ = stop_tx.send(());
        assert_eq!(handle.await.unwrap(), PipelineExit::Stopped);
    }

    /// A still screen must still produce frames: the client's watchdog fires
    /// otherwise.
    #[tokio::test]
    async fn a_backend_with_no_damage_still_produces_frames() {
        // A session that renders once and then goes quiet.
        let session = TestPatternSession::start(320, 240, 1);
        let config = PipelineConfig {
            fps: 30,
            ..pipeline_config()
        };
        let encoder = build_encoder(
            crate::config::Encoder::Null,
            EncoderConfig {
                width: 320,
                height: 240,
                fps: 30,
                bitrate_kbps: 4000,
                slices_per_frame: 1,
            },
        )
        .unwrap();
        let (tx, mut rx) = mpsc::channel(256);
        let (_idr_tx, idr_rx) = mpsc::channel(4);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let session = session;
            run(&session, config, encoder, None, tx, idr_rx, stop_rx).await
        });

        let mut frames = 0;
        let deadline = Instant::now() + Duration::from_millis(400);
        while Instant::now() < deadline {
            if tokio::time::timeout(Duration::from_millis(100), rx.recv())
                .await
                .is_ok()
            {
                frames += 1;
            }
        }
        let _ = stop_tx.send(());
        // At 30 fps over 400 ms, roughly a dozen; anything above a couple
        // proves the clock is free-running rather than damage-driven.
        assert!(frames >= 4, "only {frames} frames in 400 ms");
    }

    /// The control stream's 0x0302 must reach the encoder.
    #[tokio::test]
    async fn an_idr_request_produces_a_keyframe() {
        let session = TestPatternSession::start(320, 240, 60);
        let config = pipeline_config();
        let encoder = build_encoder(
            crate::config::Encoder::Null,
            EncoderConfig {
                width: 320,
                height: 240,
                fps: 60,
                bitrate_kbps: 4000,
                slices_per_frame: 1,
            },
        )
        .unwrap();
        let (tx, mut rx) = mpsc::channel(256);
        let (idr_tx, idr_rx) = mpsc::channel(4);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let session = session;
            run(&session, config, encoder, None, tx, idr_rx, stop_rx).await
        });

        // Drain the first few frames, then ask for a keyframe.
        for _ in 0..3 {
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap();
        }
        idr_tx.send(()).await.unwrap();

        let mut saw_idr = false;
        for _ in 0..10 {
            let packets = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap();
            let (_, payload) = VideoPacketHeader::parse(&packets[0]).unwrap();
            let fh = solstice_gamestream::wire::video::FrameHeader::parse(
                &mut solstice_gamestream::wire::Reader::new(payload),
            )
            .unwrap();
            if fh.frame_type == FrameType::Idr {
                saw_idr = true;
                break;
            }
        }
        let _ = stop_tx.send(());
        assert!(saw_idr, "the IDR request never reached the encoder");
    }

    /// A session that never changes unless the test says so.
    struct StillSession {
        fb: solstice_backend::FramebufferHandle,
        events: tokio::sync::broadcast::Sender<BackendEvent>,
    }

    #[async_trait::async_trait]
    impl Session for StillSession {
        fn dimensions(&self) -> (u32, u32) {
            (320, 240)
        }
        async fn request_resize(&self, _: u32, _: u32) -> solstice_backend::Result<bool> {
            Ok(false)
        }
        fn subscribe(&self) -> tokio::sync::broadcast::Receiver<BackendEvent> {
            self.events.subscribe()
        }
        fn framebuffer(&self) -> solstice_backend::FramebufferHandle {
            self.fb.clone()
        }
        async fn send_input(
            &self,
            _: solstice_backend::InputEvent,
        ) -> solstice_backend::Result<()> {
            Ok(())
        }
        async fn close(&self) {}
    }

    /// Frames that arrive within `window`.
    async fn count_frames(rx: &mut mpsc::Receiver<Vec<Vec<u8>>>, window: Duration) -> usize {
        let deadline = tokio::time::Instant::now() + window;
        let mut frames = 0;
        while let Ok(Some(_)) = tokio::time::timeout_at(deadline, rx.recv()).await {
            frames += 1;
        }
        frames
    }

    /// Roadmap §6: a still screen must stop costing a full-rate encode, keep
    /// sending at the keep-alive rate, and still get a change out promptly.
    #[tokio::test]
    async fn a_still_screen_backs_off_and_a_change_cuts_the_wait_short() {
        let (events, _) = tokio::sync::broadcast::channel(16);
        let session = StillSession {
            fb: solstice_backend::FramebufferHandle::with_size(320, 240),
            events: events.clone(),
        };
        let config = PipelineConfig {
            fps: 60,
            idle_fps: 2,
            ..pipeline_config()
        };
        let encoder = build_encoder(
            crate::config::Encoder::Null,
            EncoderConfig {
                width: 320,
                height: 240,
                fps: 60,
                bitrate_kbps: 4000,
                slices_per_frame: 1,
            },
        )
        .unwrap();
        let (tx, mut rx) = mpsc::channel(256);
        let (_idr_tx, idr_rx) = mpsc::channel(4);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let session = session;
            run(&session, config, encoder, None, tx, idr_rx, stop_rx).await
        });

        // The half-second tail at full rate, then the keep-alive rate. Loose
        // bounds: a loaded CI runner stretches the tail, but cannot turn 60 fps
        // into 2.
        let tail = count_frames(&mut rx, solstice_video::clock::IDLE_AFTER).await;
        assert!(tail >= 10, "only {tail} frames in the full-rate tail");
        let idle = count_frames(&mut rx, Duration::from_secs(2)).await;
        assert!(
            (2..=8).contains(&idle),
            "{idle} frames in 2 s of a still screen at idle_fps = 2"
        );

        // A change mid-wait: the keep-alive is up to 500 ms away, the change
        // must not wait for it.
        let sent = tokio::time::Instant::now();
        events
            .send(BackendEvent::Damage(solstice_backend::Rect::whole(
                320, 240,
            )))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let waited = sent.elapsed();
        assert!(
            waited < Duration::from_millis(150),
            "a change waited {waited:?} behind the keep-alive"
        );
        // And full rate resumes behind it.
        let after = count_frames(&mut rx, Duration::from_millis(300)).await;
        assert!(after >= 6, "only {after} frames in the tail after a change");

        let _ = stop_tx.send(());
        assert_eq!(handle.await.unwrap(), PipelineExit::Stopped);
    }
}
