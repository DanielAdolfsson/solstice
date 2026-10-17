//! One line of JSON out, one line of JSON back.
//!
//! QMP and the guest agent share an encoding and differ in two details: QMP
//! opens with a greeting and requires a capabilities handshake, and the agent
//! does not. Both are wrapped by the same type.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::{Error, Result};

/// A JSON-line control channel to the running QEMU.
pub(crate) struct Channel {
    name: &'static str,
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Channel {
    /// Connect, retrying until QEMU has created the socket.
    pub(crate) fn connect(path: &Path, name: &'static str, timeout: Duration) -> Result<Self> {
        let deadline = Instant::now() + timeout;
        let stream = loop {
            match UnixStream::connect(path) {
                Ok(s) => break s,
                Err(e) if Instant::now() >= deadline => {
                    return Err(Error::Timeout(format!(
                        "connecting to the {name} socket at {}: {e}",
                        path.display()
                    )))
                }
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        Ok(Self {
            name,
            reader: BufReader::new(stream.try_clone()?),
            writer: stream,
        })
    }

    /// Read and discard the QMP greeting, then negotiate capabilities.
    pub(crate) fn qmp_handshake(&mut self) -> Result<()> {
        let mut greeting = String::new();
        self.reader.read_line(&mut greeting)?;
        self.cmd("qmp_capabilities", json!({}))?;
        Ok(())
    }

    /// Issue one command and return its `return` value.
    ///
    /// Asynchronous events are interleaved with replies on QMP and are
    /// skipped here; no test has yet needed to observe one, and a test that
    /// does should watch for it deliberately rather than race this loop.
    pub(crate) fn cmd(&mut self, command: &str, args: Value) -> Result<Value> {
        let mut request = json!({ "execute": command });
        if !args.is_null() && args != json!({}) {
            request["arguments"] = args;
        }
        writeln!(self.writer, "{request}")?;
        self.writer.flush()?;

        loop {
            let mut line = String::new();
            if self.reader.read_line(&mut line)? == 0 {
                return Err(Error::Timeout(format!(
                    "the {} channel closed while waiting for {command}",
                    self.name
                )));
            }
            let reply: Value = serde_json::from_str(&line)?;
            if reply.get("event").is_some() {
                continue;
            }
            if let Some(error) = reply.get("error") {
                return Err(Error::Rejected {
                    channel: self.name,
                    command: command.to_owned(),
                    message: error
                        .get("desc")
                        .and_then(Value::as_str)
                        .unwrap_or("no description")
                        .to_owned(),
                });
            }
            return Ok(reply.get("return").cloned().unwrap_or(Value::Null));
        }
    }
}
