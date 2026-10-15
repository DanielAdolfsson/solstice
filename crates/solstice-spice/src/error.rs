//! What can go wrong on a SPICE connection.

use solstice_backend::BackendError;

/// Shorthand.
pub type Result<T> = std::result::Result<T, SpiceError>;

/// A SPICE client failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SpiceError {
    /// Transport failure.
    #[error("spice I/O: {0}")]
    Io(#[from] std::io::Error),

    /// TLS refused to come up. Separate from [`SpiceError::Auth`] because the
    /// remedy is different: a certificate problem is the operator's, a
    /// password problem is the user's.
    #[error("spice TLS: {0}")]
    Tls(String),

    /// The ticket was refused, or the server offered no mechanism policy
    /// accepts.
    #[error("spice authentication: {0}")]
    Auth(String),

    /// The link handshake failed with one of `SpiceLinkErr`
    /// (`enums.h:37-50`).
    #[error("spice link refused: {reason} ({code})")]
    Link {
        /// The raw `SpiceLinkErr` value.
        code: u32,
        /// Its name.
        reason: &'static str,
    },

    /// A message ended before the structure it claimed to hold did.
    #[error("truncated {what}: wanted {wanted} bytes, {available} left")]
    Truncated {
        /// What was being read.
        what: &'static str,
        /// How many bytes it needed.
        wanted: usize,
        /// How many were left.
        available: usize,
    },

    /// A field held a value the protocol does not define.
    #[error("spice protocol error: {0}")]
    Protocol(String),

    /// The peer asked for something past a configured ceiling.
    #[error("spice limit exceeded: {0}")]
    Limit(String),

    /// An image failed to decode.
    ///
    /// Not fatal on its own: the remedy is to drop the image and carry on.
    /// The exception is [`solstice_spice_codec::Error::GlzWindowMiss`], which
    /// means the GLZ history is inconsistent and the display channel has to
    /// reset (`docs/spice-protocol.md` §5.1).
    #[error("spice image: {0}")]
    Image(#[from] solstice_spice_codec::Error),

    /// The session ended.
    #[error("spice disconnected")]
    Disconnected,
}

impl SpiceError {
    /// A protocol error from anything that formats.
    pub fn protocol(message: impl Into<String>) -> Self {
        SpiceError::Protocol(message.into())
    }

    /// A limit error from anything that formats.
    pub fn limit(message: impl Into<String>) -> Self {
        SpiceError::Limit(message.into())
    }

    /// Whether this error leaves the session usable.
    ///
    /// A bad image is survivable -- drop the draw command and keep the
    /// channel. A truncated header or a window miss is not, because the next
    /// byte read would be interpreted in the wrong place.
    pub fn is_recoverable(&self) -> bool {
        match self {
            SpiceError::Image(e) => !matches!(e, solstice_spice_codec::Error::GlzWindowMiss { .. }),
            _ => false,
        }
    }
}

impl From<SpiceError> for BackendError {
    fn from(e: SpiceError) -> Self {
        match e {
            SpiceError::Io(e) => BackendError::Io(e),
            SpiceError::Auth(m) => BackendError::Auth(m),
            SpiceError::Tls(m) => BackendError::Auth(m),
            SpiceError::Limit(m) => BackendError::Limit(m),
            SpiceError::Disconnected => BackendError::Disconnected,
            other => BackendError::Protocol(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bad_image_is_recoverable_but_a_glz_window_miss_is_not() {
        let bad = SpiceError::Image(solstice_spice_codec::Error::Truncated);
        assert!(bad.is_recoverable());
        let miss =
            SpiceError::Image(solstice_spice_codec::Error::GlzWindowMiss { id: 1, wanted: 0 });
        assert!(!miss.is_recoverable());
    }

    #[test]
    fn errors_map_onto_the_backend_vocabulary() {
        assert!(matches!(
            BackendError::from(SpiceError::Auth("no".into())),
            BackendError::Auth(_)
        ));
        assert!(matches!(
            BackendError::from(SpiceError::Tls("no".into())),
            BackendError::Auth(_)
        ));
        assert!(matches!(
            BackendError::from(SpiceError::Disconnected),
            BackendError::Disconnected
        ));
    }
}
