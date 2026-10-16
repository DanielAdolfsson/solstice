//! The built-in colour-bar backend.
//!
//! The first milestone is to serve a hard-coded generator through the full
//! GameStream host stack until Moonlight displays it. That exercises pairing,
//! TLS, RTSP, the SDP negotiation and the video packetiser -- the half of the
//! system that fails silently -- before any backend exists to confuse the
//! picture (`docs/bridging-design.md` §7).
//!
//! It is also what the end-to-end tests run against, since the barcode in the
//! pattern makes every frame individually identifiable.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use solstice_backend::{
    Backend, BackendEvent, FramebufferHandle, InputEvent, Rect, Result, Session,
};
use solstice_video::testsrc::TestPattern;
use tokio::sync::broadcast;

/// Backend that renders colour bars.
#[derive(Debug)]
pub struct TestPatternBackend {
    width: u32,
    height: u32,
    fps: u32,
    /// Shared with every session this backend opens, so a caller holding the
    /// backend can read back what the client sent. The daemon only ever sees
    /// an `Arc<dyn Backend>` and the session is created inside the stream
    /// task, so this is the only handle a test can keep.
    received: Arc<Mutex<Vec<InputEvent>>>,
    /// Shared the same way, so a test can hold the picture still.
    frozen: Arc<AtomicBool>,
}

impl TestPatternBackend {
    /// Build one.
    pub fn new(width: u32, height: u32, fps: u32) -> Self {
        Self {
            width,
            height,
            fps: fps.clamp(1, 240),
            received: Arc::new(Mutex::new(Vec::new())),
            frozen: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Stop or restart the picture in every session of this backend. A frozen
    /// pattern renders nothing and raises no damage: a desktop nobody touches.
    pub fn set_frozen(&self, frozen: bool) {
        self.frozen.store(frozen, Ordering::Relaxed);
    }

    /// Every input event any session of this backend has been handed.
    pub fn received_input(&self) -> Vec<InputEvent> {
        self.received.lock().expect("input lock").clone()
    }
}

#[async_trait]
impl Backend for TestPatternBackend {
    fn name(&self) -> &'static str {
        "testpattern"
    }

    async fn connect(&self) -> Result<Box<dyn Session>> {
        Ok(Box::new(TestPatternSession::start_with(
            self.width,
            self.height,
            self.fps,
            self.received.clone(),
            self.frozen.clone(),
        )))
    }
}

/// A running colour-bar generator.
pub struct TestPatternSession {
    fb: FramebufferHandle,
    events: broadcast::Sender<BackendEvent>,
    width: u32,
    height: u32,
    running: Arc<AtomicBool>,
    /// Input is recorded rather than forwarded: there is nowhere to send it,
    /// and dropping it silently would make input bugs invisible in exactly the
    /// configuration used to debug everything else.
    received: Arc<Mutex<Vec<InputEvent>>>,
}

impl std::fmt::Debug for TestPatternSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestPatternSession")
            .field("width", &self.width)
            .field("height", &self.height)
            .finish_non_exhaustive()
    }
}

impl TestPatternSession {
    /// Start generating.
    pub fn start(width: u32, height: u32, fps: u32) -> Self {
        Self::start_recording_into(width, height, fps, Arc::new(Mutex::new(Vec::new())))
    }

    /// Start generating, recording input into a log the caller owns.
    pub fn start_recording_into(
        width: u32,
        height: u32,
        fps: u32,
        received: Arc<Mutex<Vec<InputEvent>>>,
    ) -> Self {
        Self::start_with(
            width,
            height,
            fps,
            received,
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn start_with(
        width: u32,
        height: u32,
        fps: u32,
        received: Arc<Mutex<Vec<InputEvent>>>,
        frozen: Arc<AtomicBool>,
    ) -> Self {
        let fb = FramebufferHandle::with_size(width, height);
        let (events, _) = broadcast::channel(64);
        let running = Arc::new(AtomicBool::new(true));

        {
            let fb = fb.clone();
            let events = events.clone();
            let running = running.clone();
            let interval = Duration::from_nanos(1_000_000_000 / fps.max(1) as u64);
            tokio::spawn(async move {
                let mut pattern = TestPattern::new();
                let mut ticker = tokio::time::interval(interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                while running.load(Ordering::Relaxed) {
                    ticker.tick().await;
                    if frozen.load(Ordering::Relaxed) {
                        continue;
                    }
                    pattern.render(&mut fb.write());
                    // An error here only means nobody is subscribed yet; keep
                    // rendering so the framebuffer is current when one arrives.
                    let _ = events.send(BackendEvent::Damage(Rect::whole(width, height)));
                }
                let _ = events.send(BackendEvent::Disconnected);
            });
        }

        Self {
            fb,
            events,
            width,
            height,
            running,
            received,
        }
    }

    /// Everything that has been injected so far.
    pub fn received_input(&self) -> Vec<InputEvent> {
        self.received.lock().expect("input lock").clone()
    }
}

#[async_trait]
impl Session for TestPatternSession {
    fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    async fn request_resize(&self, _width: u32, _height: u32) -> Result<bool> {
        // The generator could resize, but declining exercises the scaling path
        // that real backends will usually force.
        Ok(false)
    }

    fn subscribe(&self) -> broadcast::Receiver<BackendEvent> {
        self.events.subscribe()
    }

    fn framebuffer(&self) -> FramebufferHandle {
        self.fb.clone()
    }

    async fn send_input(&self, event: InputEvent) -> Result<()> {
        tracing::debug!(?event, "test pattern received input");
        self.received.lock().expect("input lock").push(event);
        Ok(())
    }

    async fn close(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solstice_video::testsrc::decode_barcode;

    #[tokio::test]
    async fn the_pattern_advances_and_raises_damage() {
        let backend = TestPatternBackend::new(320, 240, 60);
        let session = backend.connect().await.unwrap();
        let mut events = session.subscribe();

        let first = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(first, BackendEvent::Damage(_)));

        let fb = session.framebuffer();
        let a = decode_barcode(&fb.read()).expect("the pattern carries a barcode");
        tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .unwrap()
            .unwrap();
        let b = decode_barcode(&fb.read()).unwrap();
        assert!(b > a, "the frame counter must advance: {a} then {b}");
        session.close().await;
    }

    #[tokio::test]
    async fn a_frozen_pattern_raises_no_damage_until_thawed() {
        let backend = TestPatternBackend::new(320, 240, 60);
        let session = backend.connect().await.unwrap();
        let mut events = session.subscribe();
        events.recv().await.unwrap();

        backend.set_frozen(true);
        // Drain anything rendered before the switch was seen.
        tokio::time::sleep(Duration::from_millis(50)).await;
        while events.try_recv().is_ok() {}
        let fb = session.framebuffer();
        let held = decode_barcode(&fb.read()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), events.recv())
                .await
                .is_err(),
            "a frozen pattern raised damage"
        );
        assert_eq!(decode_barcode(&fb.read()), Some(held));

        backend.set_frozen(false);
        tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .expect("a thawed pattern raises damage again")
            .unwrap();
        assert!(decode_barcode(&fb.read()).unwrap() > held);
        session.close().await;
    }

    #[tokio::test]
    async fn input_is_recorded_rather_than_dropped_silently() {
        let session = TestPatternSession::start(64, 64, 60);
        session
            .send_input(InputEvent::Button {
                button: solstice_backend::MouseButton::Left,
                down: true,
            })
            .await
            .unwrap();
        assert_eq!(session.received_input().len(), 1);
        session.close().await;
    }
}
