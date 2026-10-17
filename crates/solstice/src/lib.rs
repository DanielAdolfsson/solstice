//! The Solstice daemon.
//!
//! Wiring only: CLI, configuration, logging, signal handling and session
//! supervision. No protocol logic lives here, which is what keeps every piece
//! below testable without starting a daemon (`PROJECT-LAYOUT.md` §2).

#![forbid(unsafe_code)]

pub mod audio;
pub mod backend_factory;
pub mod cli;
pub mod config;
pub mod endpoint;
pub mod management;
pub mod net;
pub mod pipeline;
pub mod supervisor;
pub mod testpattern;
pub mod tls;
