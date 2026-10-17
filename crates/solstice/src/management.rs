//! The management socket: how `solstice pair`, `status`, `list-clients` and
//! `revoke` reach the running daemon.
//!
//! The CLI runs in a different process from the daemon, so before this existed
//! `solstice pair` could only have opened a window against its own throwaway
//! state, and `revoke` edited `clients.tsv` behind the back of a daemon that
//! went on trusting the client it had in memory.
//!
//! A Unix socket at `$state_dir/control.sock`, mode 0600, and deliberately
//! nothing more: not HTTP and not a web UI. Sunshine's worst CVEs -- CSRF to
//! command injection, clickjacking -- are in its config UI rather than its
//! protocol (`docs/security.md` §3.5). Filesystem permissions are the
//! authentication here, and every connection's peer credentials are checked as
//! well, so the 0600 is not the only thing between another local user and the
//! pairing window.
//!
//! The protocol is one line in and lines out, one request per connection:
//!
//! ```text
//! -> pair 4242 60000      PIN, then the window in milliseconds (optional)
//! -> status
//! -> list-clients
//! -> revoke 3fa9c2d1      a prefix of the fingerprint `list-clients` prints
//! <- out <text>           zero or more, shown as they arrive
//! <- ok [<text>]          exactly one of these two, last
//! <- err <text>
//! ```
//!
//! `pair` holds the connection until the window it opened has an outcome -- a
//! client paired, the window ran out, the attempt limit was hit -- so the
//! command's exit status says whether pairing happened, which is what a script
//! driving `moonlight pair -pin` needs (`docs/testing.md` §2.1). Closing the
//! connection early, Ctrl-C on `solstice pair`, closes the window.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use solstice_gamestream::crypto::certs::{ClientStore, PairedClient};
use solstice_gamestream::crypto::gcm::sha256_concat;
use solstice_gamestream::nvhttp::Host;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};

use crate::endpoint::Endpoints;

/// The longest request line accepted, newline included.
const MAX_REQUEST: u64 = 256;
/// How long a peer has to send its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// How often a waiting `pair` looks at the window.
const POLL: Duration = Duration::from_millis(100);
/// The longest window `pair` will open. `docs/security.md` recommends a minute;
/// this is a ceiling for a slow human, not a target. The window and the
/// lockout are the real control on a four-digit PIN, so an unbounded one would
/// give that away.
pub const MAX_WINDOW: Duration = Duration::from_secs(600);
/// The fewest fingerprint digits `revoke` acts on.
pub const MIN_PREFIX: usize = 4;
/// How many fingerprint digits `list-clients` prints.
const SHOWN_PREFIX: usize = 16;

// --------------------------------------------------------------- protocol --

/// One request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Open a pairing window and wait for its outcome.
    Pair {
        /// The PIN the client is showing.
        pin: String,
        /// How long to hold the window; the daemon's `security.pairing_window`
        /// when absent.
        window: Option<Duration>,
    },
    /// What the daemon is doing.
    Status,
    /// Every paired client.
    ListClients,
    /// Unpair one client, effective immediately.
    Revoke {
        /// A prefix of its certificate fingerprint.
        prefix: String,
    },
}

impl Request {
    /// Parse a request line, without its newline.
    pub fn parse(line: &str) -> Result<Self, String> {
        let mut words = line.split(' ');
        let request = match (words.next(), words.next(), words.next()) {
            (Some("pair"), Some(pin), window) => Request::Pair {
                pin: pin.to_owned(),
                window: window
                    .map(|w| {
                        w.parse()
                            .map(Duration::from_millis)
                            .map_err(|_| format!("not a window in milliseconds: {w}"))
                    })
                    .transpose()?,
            },
            (Some("status"), None, None) => Request::Status,
            (Some("list-clients"), None, None) => Request::ListClients,
            (Some("revoke"), Some(prefix), None) => Request::Revoke {
                prefix: prefix.to_owned(),
            },
            _ => return Err(format!("unrecognised request: {}", printable(line))),
        };
        if words.next().is_some() {
            return Err(format!("unrecognised request: {}", printable(line)));
        }
        Ok(request)
    }

    /// The request line, without its newline.
    pub fn to_line(&self) -> String {
        match self {
            Request::Pair { pin, window: None } => format!("pair {pin}"),
            Request::Pair {
                pin,
                window: Some(w),
            } => format!("pair {pin} {}", w.as_millis()),
            Request::Status => "status".into(),
            Request::ListClients => "list-clients".into(),
            Request::Revoke { prefix } => format!("revoke {prefix}"),
        }
    }
}

/// A client's certificate fingerprint: SHA-256 over the DER, in hex.
///
/// Not a prefix of the DER itself, which is what `list-clients` printed before:
/// every certificate starts with the same few bytes of ASN.1 framing, so the
/// first sixteen hex digits of two different clients' DER are usually equal.
pub fn fingerprint(cert_der: &[u8]) -> String {
    hex::encode(sha256_concat(&[cert_der]))
}

/// A device name or unique id, safe to put on a terminal and on one line.
///
/// Both come from the client's pairing request and are attacker-controlled
/// (`PairedClient`), so control characters -- escape sequences, newlines --
/// do not reach the operator's terminal or this protocol's framing.
pub fn printable(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// One line per paired client: fingerprint prefix, name, unique id.
pub fn client_lines(store: &ClientStore) -> Vec<String> {
    store
        .clients()
        .map(|c| {
            format!(
                "{}  {}  {}",
                &fingerprint(&c.cert_der)[..SHOWN_PREFIX],
                printable(&c.device_name),
                printable(&c.unique_id)
            )
        })
        .collect()
}

/// The one client whose fingerprint starts with `prefix`.
///
/// Refuses a prefix that matches more than one rather than picking, since the
/// action is irreversible short of pairing again.
pub fn find_client<'a>(store: &'a ClientStore, prefix: &str) -> Result<&'a PairedClient, String> {
    let prefix = prefix.to_ascii_lowercase();
    if prefix.len() < MIN_PREFIX || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "give at least {MIN_PREFIX} hex digits of the fingerprint `list-clients` prints"
        ));
    }
    let mut matching = store
        .clients()
        .filter(|c| fingerprint(&c.cert_der).starts_with(&prefix));
    match (matching.next(), matching.next()) {
        (Some(client), None) => Ok(client),
        (None, _) => Err(format!("no paired client matches {prefix}")),
        (Some(_), Some(_)) => Err(format!(
            "{prefix} matches more than one client; give more of the fingerprint"
        )),
    }
}

fn describe(client: &PairedClient) -> String {
    format!(
        "{} ({})",
        printable(&client.device_name),
        &fingerprint(&client.cert_der)[..SHOWN_PREFIX]
    )
}

// ----------------------------------------------------------------- server --

/// What the socket serves from.
pub struct Context {
    /// The daemon's shared state.
    pub host: Arc<Host>,
    /// The window `pair` opens when it is not given one.
    pub pairing_window: Duration,
    /// What the daemon offers, for `status`.
    pub endpoints: Arc<Endpoints>,
}

/// A bound management socket, not yet serving.
pub struct Listener {
    listener: UnixListener,
    owner: u32,
    file: SocketFile,
}

/// Removes the socket file when the daemon stops -- but only if it is still
/// the one this daemon bound, not one a successor has since put there.
struct SocketFile {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        if let Ok(meta) = std::fs::symlink_metadata(&self.path) {
            if meta.dev() == self.dev && meta.ino() == self.ino {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

/// Bind the socket at `path`, mode 0600.
///
/// A socket left behind by a daemon that did not exit cleanly is replaced. One
/// that still answers means another daemon is using this state directory, and
/// is an error, as is anything at `path` that is not a socket at all.
pub fn bind(path: &Path) -> std::io::Result<Listener> {
    let context =
        |e: std::io::Error| std::io::Error::new(e.kind(), format!("{}: {e}", path.display()));
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        format!(
                            "{} answers; is another solstice running with this state_dir?",
                            path.display()
                        ),
                    ))
                }
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    tracing::info!(path = %path.display(), "replacing a stale management socket");
                    std::fs::remove_file(path).map_err(context)?;
                }
                Err(e) => return Err(context(e)),
            }
        }
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{} exists and is not a socket; not replacing it",
                    path.display()
                ),
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(context(e)),
    }

    let listener = UnixListener::bind(path).map_err(context)?;
    let file = {
        let meta = std::fs::symlink_metadata(path).map_err(context)?;
        SocketFile {
            path: path.to_owned(),
            dev: meta.dev(),
            ino: meta.ino(),
        }
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(context)?;
    let owner = std::fs::symlink_metadata(path).map_err(context)?.uid();
    Ok(Listener {
        listener,
        owner,
        file,
    })
}

impl Listener {
    /// Serve until dropped. The socket file goes with it.
    pub async fn serve(self, context: Arc<Context>) {
        let Listener {
            listener,
            owner,
            file: _file,
        } = self;
        loop {
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(e) => {
                    // EMFILE and friends: back off rather than spin.
                    tracing::warn!(error = %e, "management socket accept failed");
                    tokio::time::sleep(POLL).await;
                    continue;
                }
            };
            // The file mode already keeps other users out. This is the check
            // that does not depend on the mode having been right from the
            // instant of bind(), or on nobody having loosened it since.
            match stream.peer_cred() {
                Ok(cred) if cred.uid() == owner || cred.uid() == 0 => {}
                Ok(cred) => {
                    tracing::warn!(
                        uid = cred.uid(),
                        "management connection from another user refused"
                    );
                    continue;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "management connection without credentials refused");
                    continue;
                }
            }
            let context = context.clone();
            tokio::spawn(async move {
                if let Err(e) = handle(stream, &context).await {
                    tracing::debug!(error = %e, "management connection ended");
                }
            });
        }
    }
}

async fn send(w: &mut OwnedWriteHalf, tag: &str, text: &str) -> std::io::Result<()> {
    let line = if text.is_empty() {
        format!("{tag}\n")
    } else {
        format!("{tag} {}\n", printable(text))
    };
    w.write_all(line.as_bytes()).await
}

async fn handle(stream: UnixStream, context: &Context) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(read);
    let mut line = String::new();
    let read = tokio::time::timeout(
        REQUEST_TIMEOUT,
        (&mut reader).take(MAX_REQUEST).read_line(&mut line),
    )
    .await;
    let request = match read {
        Ok(Ok(_)) if line.ends_with('\n') => Request::parse(line.trim_end_matches('\n')),
        Ok(Ok(_)) => Err("the request is too long or was not terminated".into()),
        Ok(Err(e)) => Err(format!("unreadable request: {e}")),
        Err(_) => Err("no request".into()),
    };
    let request = match request {
        Ok(request) => request,
        Err(e) => return send(&mut write, "err", &e).await,
    };

    let host = &context.host;
    match request {
        Request::Pair { pin, window } => {
            let window = window.unwrap_or(context.pairing_window);
            pair(host, &pin, window, reader, &mut write).await
        }
        Request::Status => {
            for line in status_lines(context) {
                send(&mut write, "out", &line).await?;
            }
            send(&mut write, "ok", "").await
        }
        Request::ListClients => {
            let lines = client_lines(&host.clients.read().expect("client store lock"));
            if lines.is_empty() {
                return send(&mut write, "ok", "no paired clients").await;
            }
            for line in lines {
                send(&mut write, "out", &line).await?;
            }
            send(&mut write, "ok", "").await
        }
        Request::Revoke { prefix } => {
            let found = find_client(&host.clients.read().expect("client store lock"), &prefix)
                .map(|c| (c.cert_der.clone(), describe(c)));
            match found {
                // Through `Host`, not the store: that is what drops the
                // client's launch sessions as well.
                Ok((der, name)) if host.revoke(&der) => {
                    tracing::info!(client = %name, "revoked over the management socket");
                    send(&mut write, "ok", &format!("revoked {name}")).await
                }
                Ok((_, name)) => send(&mut write, "err", &format!("could not revoke {name}")).await,
                Err(e) => send(&mut write, "err", &e).await,
            }
        }
    }
}

fn status_lines(context: &Context) -> Vec<String> {
    let host = &context.host;
    let pairing = {
        let mgr = host.pairing.lock().expect("pairing lock");
        if mgr.is_locked_out() {
            format!(
                "locked out after {} failed attempts; `solstice pair` re-enables it",
                mgr.failures()
            )
        } else if let Some(left) = mgr.time_left(Instant::now()) {
            format!(
                "open, {}s left, {} of {} attempts failed",
                left.as_secs(),
                mgr.failures(),
                mgr.max_attempts()
            )
        } else {
            "closed".into()
        }
    };
    let mut lines = vec![format!("name: {}", host.config.name)];
    if context.endpoints.is_empty() {
        lines.push("endpoints: none; Moonlight shows an empty app list".into());
    }
    for entry in context.endpoints.iter() {
        lines.push(format!(
            "endpoint: {} (app {}): {}",
            entry.name, entry.id, entry.detail
        ));
    }
    lines.extend([
        format!("pairing: {pairing}"),
        format!(
            "paired clients: {}",
            host.clients.read().expect("client store lock").len()
        ),
        format!(
            "sessions: {}",
            host.sessions.lock().expect("session lock").len()
        ),
    ]);
    lines
}

/// What became of the window a `pair` request opened.
#[derive(Debug)]
enum Outcome {
    Waiting { failures: u32 },
    Paired(String),
    Superseded,
    LockedOut(u32),
    Closed { ran_out: bool },
    ClientGaveUp,
}

fn outcome(host: &Host, generation: u64, closes_at: Instant) -> Outcome {
    let mut mgr = host.pairing.lock().expect("pairing lock");
    if mgr.generation() != generation {
        return Outcome::Superseded;
    }
    if let Some(client) = mgr.paired() {
        return Outcome::Paired(describe(client));
    }
    if mgr.is_locked_out() {
        return Outcome::LockedOut(mgr.failures());
    }
    let now = Instant::now();
    if mgr.is_open(now) {
        return Outcome::Waiting {
            failures: mgr.failures(),
        };
    }
    if mgr.did_client_give_up() {
        return Outcome::ClientGaveUp;
    }
    // Run out, or abandoned early by a malformed request. Either way the PIN
    // has no further use.
    mgr.close();
    Outcome::Closed {
        ran_out: now >= closes_at,
    }
}

async fn pair(
    host: &Host,
    pin: &str,
    window: Duration,
    mut reader: tokio::io::BufReader<OwnedReadHalf>,
    w: &mut OwnedWriteHalf,
) -> std::io::Result<()> {
    if window.is_zero() || window > MAX_WINDOW {
        let e = format!(
            "the window must be more than zero and at most {}",
            humantime::format_duration(MAX_WINDOW)
        );
        return send(w, "err", &e).await;
    }
    let opened_at = Instant::now();
    let opened = {
        let mut mgr = host.pairing.lock().expect("pairing lock");
        mgr.open(pin, window, opened_at)
            .map(|()| (mgr.generation(), mgr.max_attempts()))
    };
    let (generation, max_attempts) = match opened {
        Ok(opened) => opened,
        Err(e) => return send(w, "err", &e.to_string()).await,
    };
    let shown = humantime::format_duration(Duration::from_secs(window.as_secs().max(1)));
    tracing::info!(window = %shown, "pairing window opened over the management socket");
    send(
        w,
        "out",
        &format!("pairing is open for {shown}; finish pairing on the client"),
    )
    .await?;

    let mut reported_failures = 0;
    let mut scratch = [0u8; 64];
    loop {
        tokio::select! {
            _ = tokio::time::sleep(POLL) => {}
            read = reader.read(&mut scratch) => {
                if matches!(read, Ok(0) | Err(_)) {
                    let mut mgr = host.pairing.lock().expect("pairing lock");
                    if mgr.generation() == generation && mgr.paired().is_none() {
                        mgr.close();
                        tracing::info!("pairing window closed: `solstice pair` went away");
                    }
                    return Ok(());
                }
                // Anything else the peer sends is ignored.
                continue;
            }
        }
        match outcome(host, generation, opened_at + window) {
            Outcome::Waiting { failures } => {
                if failures > reported_failures {
                    reported_failures = failures;
                    send(
                        w,
                        "out",
                        &format!(
                            "a pairing attempt failed ({failures} of {max_attempts}); wrong PIN?"
                        ),
                    )
                    .await?;
                }
            }
            Outcome::Paired(name) => return send(w, "ok", &format!("paired {name}")).await,
            Outcome::Superseded => {
                return send(w, "err", "another `solstice pair` replaced this window").await
            }
            Outcome::LockedOut(failures) => {
                let e = format!(
                    "pairing locked out after {failures} failed attempts; \
                     run `solstice pair` again to re-enable it"
                );
                return send(w, "err", &e).await;
            }
            Outcome::Closed { ran_out: true } => {
                return send(w, "err", "the window closed before a client paired").await
            }
            Outcome::ClientGaveUp => {
                let e = "the client gave up partway through -- most likely the PIN did \
                         not match the one it shows; run `solstice pair` again with the \
                         new PIN";
                return send(w, "err", e).await;
            }
            Outcome::Closed { ran_out: false } => {
                let e = "the window was abandoned after a malformed or out-of-order pairing \
                         request; run `solstice pair` again";
                return send(w, "err", e).await;
            }
        }
    }
}

// ----------------------------------------------------------------- client --

/// Why a request did not succeed.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Nothing is listening: no daemon, or one with another `state_dir`.
    #[error("solstice is not running ({} does not answer)", .0.display())]
    NotRunning(PathBuf),
    /// The daemon said no.
    #[error("{0}")]
    Refused(String),
    /// Anything else.
    #[error("{0}")]
    Io(String),
}

/// Send one request to the daemon at `path`, copying what it says to `out`.
///
/// Blocking, and deliberately so: the CLI has nothing else to do meanwhile and
/// needs no runtime for it.
pub fn call(path: &Path, request: &Request, out: &mut dyn Write) -> Result<(), ClientError> {
    use std::io::ErrorKind;
    let io = |e: std::io::Error| ClientError::Io(format!("{}: {e}", path.display()));
    let stream = std::os::unix::net::UnixStream::connect(path).map_err(|e| match e.kind() {
        ErrorKind::NotFound | ErrorKind::ConnectionRefused => {
            ClientError::NotRunning(path.to_owned())
        }
        ErrorKind::PermissionDenied => ClientError::Io(format!(
            "{}: permission denied; run this as the user solstice runs as",
            path.display()
        )),
        _ => io(e),
    })?;
    (&stream)
        .write_all(format!("{}\n", request.to_line()).as_bytes())
        .map_err(io)?;
    for line in BufReader::new(&stream).lines() {
        let line = line.map_err(io)?;
        let (tag, text) = line.split_once(' ').unwrap_or((&line, ""));
        match tag {
            "out" => writeln!(out, "{text}").map_err(io)?,
            "ok" => {
                if !text.is_empty() {
                    writeln!(out, "{text}").map_err(io)?;
                }
                return Ok(());
            }
            "err" => return Err(ClientError::Refused(text.to_owned())),
            _ => {
                return Err(ClientError::Io(format!(
                    "unexpected reply from the daemon: {}",
                    printable(&line)
                )))
            }
        }
    }
    Err(ClientError::Io(
        "the daemon closed the connection without replying".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use solstice_gamestream::crypto::certs::HostIdentity;

    fn client(name: &str, der: &[u8]) -> PairedClient {
        PairedClient {
            cert_der: der.to_vec(),
            device_name: name.into(),
            unique_id: "0123".into(),
        }
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("solstice-mgmt-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn the_socket_is_private_and_goes_when_the_daemon_does() {
        let dir = scratch_dir("mode");
        let path = dir.join("control.sock");
        let listener = bind(&path).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        drop(listener);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_second_daemon_on_the_same_state_dir_is_refused() {
        let dir = scratch_dir("twice");
        let path = dir.join("control.sock");
        let first = bind(&path).unwrap();
        let second = bind(&path).err().expect("a second bind succeeded");
        assert_eq!(second.kind(), std::io::ErrorKind::AddrInUse);
        // The refused one must not have removed the first one's socket.
        assert!(path.exists());
        drop(first);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_stale_socket_is_replaced_and_anything_else_is_not() {
        let dir = scratch_dir("stale");
        let path = dir.join("control.sock");
        // A daemon that died without cleaning up: the file stays, nobody
        // listens.
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        assert!(path.exists());
        drop(bind(&path).unwrap());

        std::fs::write(&path, "not a socket").unwrap();
        let refused = bind(&path).err().expect("replaced a regular file");
        assert_eq!(refused.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not a socket");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn requests_round_trip() {
        for request in [
            Request::Pair {
                pin: "4242".into(),
                window: None,
            },
            Request::Pair {
                pin: "4242".into(),
                window: Some(Duration::from_millis(1500)),
            },
            Request::Status,
            Request::ListClients,
            Request::Revoke {
                prefix: "abcd".into(),
            },
        ] {
            assert_eq!(Request::parse(&request.to_line()), Ok(request));
        }
    }

    #[test]
    fn malformed_requests_are_refused() {
        for line in [
            "",
            "pair",
            "pair 4242 soon",
            "pair 4242 100 extra",
            "status now",
            "revoke",
            "revoke a b",
            "reboot",
            "STATUS",
        ] {
            assert!(Request::parse(line).is_err(), "{line:?} parsed");
        }
    }

    #[test]
    fn device_names_cannot_reach_the_terminal_raw() {
        assert_eq!(printable("tv\x1b[2J\nroot"), "tv?[2J?root");
        assert_eq!(printable("Living room ☀"), "Living room ☀");
    }

    /// The bug this replaced: two certificates share their DER framing, so a
    /// DER prefix could not tell them apart.
    #[test]
    fn fingerprints_tell_apart_certificates_whose_der_starts_alike() {
        let a = HostIdentity::generate("a").unwrap();
        let b = HostIdentity::generate("b").unwrap();
        // SEQUENCE, long-form length: every certificate opens this way.
        assert_eq!(a.cert_der()[..2], b.cert_der()[..2]);
        assert_ne!(
            &fingerprint(a.cert_der())[..SHOWN_PREFIX],
            &fingerprint(b.cert_der())[..SHOWN_PREFIX]
        );
    }

    #[test]
    fn revoke_needs_one_unambiguous_match() {
        let mut store = ClientStore::new();
        store.add(client("one", b"first")).unwrap();
        store.add(client("two", b"second")).unwrap();
        let one = fingerprint(b"first");

        assert_eq!(find_client(&store, &one[..8]).unwrap().device_name, "one");
        assert_eq!(
            find_client(&store, &one[..8].to_uppercase())
                .unwrap()
                .device_name,
            "one"
        );
        assert!(find_client(&store, &one[..3]).is_err(), "too short");
        assert!(find_client(&store, "zzzz").is_err(), "not hex");
        assert!(find_client(&store, "").is_err());

        let two = fingerprint(b"second");
        let unmatched = ["0000", "ffff", "1234"]
            .into_iter()
            .find(|p| !one.starts_with(p) && !two.starts_with(p))
            .unwrap();
        assert!(find_client(&store, unmatched)
            .unwrap_err()
            .contains("no paired client"));
    }

    #[test]
    fn an_ambiguous_prefix_is_refused_rather_than_guessed() {
        // Find two DERs whose fingerprints share four digits.
        let mut seen = std::collections::HashMap::new();
        let (a, b) = (0u32..)
            .find_map(|i| {
                let der = i.to_be_bytes().to_vec();
                let key = fingerprint(&der)[..MIN_PREFIX].to_owned();
                seen.insert(key, der.clone()).map(|other| (other, der))
            })
            .unwrap();
        let mut store = ClientStore::new();
        store.add(client("a", &a)).unwrap();
        store.add(client("b", &b)).unwrap();
        let prefix = &fingerprint(&a)[..MIN_PREFIX];
        assert!(find_client(&store, prefix)
            .unwrap_err()
            .contains("more than one"));
    }
}
