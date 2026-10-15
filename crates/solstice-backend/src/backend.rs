//! The backend traits.

use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc};

use crate::{AudioFrame, BackendEvent, FramebufferHandle, InputEvent};

/// Anything that can go wrong talking to a remote desktop.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// Transport failure.
    #[error("backend I/O: {0}")]
    Io(#[from] std::io::Error),
    /// The peer sent something that is not valid for the protocol.
    #[error("backend protocol error: {0}")]
    Protocol(String),
    /// Authentication failed, or the only offered method is one policy refuses.
    #[error("backend authentication: {0}")]
    Auth(String),
    /// The peer asked for something outside a configured ceiling.
    #[error("backend limit exceeded: {0}")]
    Limit(String),
    /// The session is gone.
    #[error("backend disconnected")]
    Disconnected,
}

/// Shorthand.
pub type Result<T> = std::result::Result<T, BackendError>;

/// Dials a remote desktop.
#[async_trait]
pub trait Backend: Send + Sync {
    /// A name for logs.
    fn name(&self) -> &'static str;

    /// Connect, handshake, and return a live session.
    async fn connect(&self) -> Result<Box<dyn Session>>;
}

/// A live remote desktop connection.
#[async_trait]
pub trait Session: Send + Sync {
    /// Current framebuffer geometry.
    fn dimensions(&self) -> (u32, u32);

    /// Ask the remote desktop to change size. Best-effort: a server that cannot
    /// or will not resize returns `Ok(false)`, and the caller falls back to
    /// scaling (`docs/bridging-design.md` §2.2).
    async fn request_resize(&self, width: u32, height: u32) -> Result<bool>;

    /// Subscribe to damage and lifecycle events.
    fn subscribe(&self) -> broadcast::Receiver<BackendEvent>;

    /// The framebuffer these events describe.
    fn framebuffer(&self) -> FramebufferHandle;

    /// Inject input.
    async fn send_input(&self, event: InputEvent) -> Result<()>;

    /// Take the audio stream, if this backend has one. Returns `None` on the
    /// second call and for backends with no audio (RFB, in practice).
    fn take_audio(&self) -> Option<mpsc::Receiver<AudioFrame>> {
        None
    }

    /// Tear the session down.
    async fn close(&self);
}
