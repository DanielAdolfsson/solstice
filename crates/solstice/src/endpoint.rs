//! Endpoints: the remote desktops Solstice offers, one Moonlight app each.
//!
//! An endpoint is declared three ways, and all three are the same [`Spec`]:
//! an `[[endpoint]]` table in the configuration, a `--endpoint` flag on
//! `solstice run`, and `solstice endpoint add` on a running daemon. One spec,
//! one resolution, one set of refusals, so that no entry point is a way around
//! another's checks (`docs/roadmap.md` §9).
//!
//! ```text
//! --endpoint 'name=Build box,kind=vnc,host=10.0.0.5,password_file=/etc/solstice/build.pw'
//! ```
//!
//! The keys are the TOML keys. Everything but `name` and `kind` has the
//! default the old single `[backend]` section had. A password is never
//! accepted on the command line, where every user on the machine can read
//! it; `password_file` is.
//!
//! Zero endpoints is a legitimate state -- pair first, add desktops later --
//! and Moonlight then sees one placeholder saying so: an empty list it would
//! ignore, and go on showing what it had cached.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::Deserialize;
use solstice_backend::Backend;
use solstice_gamestream::nvhttp::applist::App;
use solstice_gamestream::nvhttp::Host;

use crate::config::{
    is_loopback_host, BackendKind, Spice, SpiceSecurityKind, Vnc, VncSecurityKind,
};

/// The app id of the old single `[backend]` section, kept so that a client
/// which knew the one app before still finds it under the same id.
pub const LEGACY_APP_ID: u32 = 1;

/// The longest name accepted. Moonlight shows it under a tile.
pub const MAX_NAME: usize = 64;

/// One endpoint as declared, before anything is checked or read.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    /// What Moonlight shows, and what the app id is derived from.
    pub name: String,
    /// `vnc`, `spice` or `testpattern`.
    pub kind: BackendKind,
    /// Host to dial.
    pub host: Option<String>,
    /// Port to dial.
    pub port: Option<u16>,
    /// `none`, `vncauth` or `vencrypt` for RFB; `tls` or `plain` for SPICE.
    pub security: Option<String>,
    /// The password, inline. Configuration file only.
    pub password: Option<String>,
    /// A file holding the password, read when the endpoint is resolved.
    pub password_file: Option<PathBuf>,
    /// PEM file of certificates to trust.
    pub ca_file: Option<PathBuf>,
    /// SPICE only: open the playback channel.
    pub audio: Option<bool>,
}

impl Spec {
    /// An endpoint with nothing but a name and a kind.
    pub fn new(name: &str, kind: BackendKind) -> Self {
        Self {
            name: name.to_owned(),
            kind,
            host: None,
            port: None,
            security: None,
            password: None,
            password_file: None,
            ca_file: None,
            audio: None,
        }
    }

    /// Parse the `key=value,key=value` form `--endpoint` takes.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut seen: Vec<&str> = Vec::new();
        let (mut name, mut kind) = (None, None);
        let mut out = Spec::new("", BackendKind::TestPattern);
        for field in spec.split(',') {
            let Some((key, value)) = field.split_once('=') else {
                return Err(format!("`{field}` is not key=value"));
            };
            let (key, value) = (key.trim(), value.trim());
            if seen.contains(&key) {
                return Err(format!("`{key}` is given twice"));
            }
            seen.push(key);
            match key {
                "name" => name = Some(value.to_owned()),
                "kind" => kind = Some(value.parse()?),
                "host" => out.host = Some(value.to_owned()),
                "port" => {
                    out.port = Some(
                        value
                            .parse()
                            .map_err(|_| format!("port = {value} is not a port"))?,
                    )
                }
                "security" => out.security = Some(value.to_owned()),
                "password" => {
                    return Err("a password on the command line is readable by every user \
                                on the machine; use password_file"
                        .into())
                }
                "password_file" => out.password_file = Some(value.into()),
                "ca_file" => out.ca_file = Some(value.into()),
                "audio" => {
                    out.audio = Some(match value {
                        "true" => true,
                        "false" => false,
                        _ => return Err(format!("audio = {value} is not true or false")),
                    })
                }
                _ => {
                    return Err(format!(
                        "unknown key `{key}`; expected name, kind, host, port, security, \
                         password_file, ca_file or audio"
                    ))
                }
            }
        }
        out.name = name.ok_or("`name` is required")?;
        out.kind = kind.ok_or("`kind` is required")?;
        Ok(out)
    }

    /// Check it, read its password file, and settle every default.
    pub fn resolve(&self) -> Result<Endpoint, String> {
        check_name(&self.name)?;
        let kind = self.kind;
        let refuse = |key: &str| {
            Err(format!(
                "`{key}` does not apply to kind = \"{}\"",
                kind.as_str()
            ))
        };
        let target = match kind {
            BackendKind::TestPattern => {
                for (key, given) in [
                    ("host", self.host.is_some()),
                    ("port", self.port.is_some()),
                    ("security", self.security.is_some()),
                    ("password", self.password.is_some()),
                    ("password_file", self.password_file.is_some()),
                    ("ca_file", self.ca_file.is_some()),
                    ("audio", self.audio.is_some()),
                ] {
                    if given {
                        return refuse(key);
                    }
                }
                Target::TestPattern
            }
            BackendKind::Vnc => {
                if self.audio.is_some() {
                    return refuse("audio");
                }
                let mut vnc = Vnc::default();
                if let Some(host) = &self.host {
                    vnc.host = host.clone();
                }
                vnc.port = self.port.unwrap_or(vnc.port);
                if let Some(security) = &self.security {
                    vnc.security = security.parse()?;
                }
                vnc.password = self.password()?;
                vnc.ca_file = self.ca_file.clone();
                Target::Vnc(vnc)
            }
            BackendKind::Spice => {
                let mut spice = Spice::default();
                if let Some(host) = &self.host {
                    spice.host = host.clone();
                }
                spice.port = self.port.unwrap_or(spice.port);
                if let Some(security) = &self.security {
                    spice.security = security.parse()?;
                }
                spice.password = self.password()?;
                spice.ca_file = self.ca_file.clone();
                spice.audio = self.audio.unwrap_or(spice.audio);
                Target::Spice(spice)
            }
        };
        target.check()?;
        Ok(Endpoint {
            id: app_id(&self.name),
            name: self.name.clone(),
            target,
        })
    }

    /// Refuse relative paths. For an endpoint added to a running daemon:
    /// the daemon opens the files, from its own working directory, which is
    /// not the one the path was typed in.
    pub fn require_absolute_paths(&self) -> Result<(), String> {
        for (key, path) in [
            ("password_file", &self.password_file),
            ("ca_file", &self.ca_file),
        ] {
            if let Some(path) = path.as_deref().filter(|p| !p.is_absolute()) {
                return Err(format!(
                    "{key} = {} is relative; the daemon would read it from its own \
                     working directory, so give an absolute path",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    fn password(&self) -> Result<Option<String>, String> {
        match (&self.password, &self.password_file) {
            (Some(_), Some(_)) => Err("give password or password_file, not both".into()),
            (password, None) => Ok(password.clone()),
            (None, Some(path)) => read_password(path).map(Some),
        }
    }
}

/// The first line of `path`, without its line ending.
fn read_password(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("password_file {}: {e}", path.display()))?;
    let line = text.lines().next().unwrap_or("");
    if line.is_empty() {
        return Err(format!("password_file {} is empty", path.display()));
    }
    Ok(line.to_owned())
}

/// Refuse a name that would not survive a tile, a terminal, or the
/// `key=value,` form.
pub fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("the name is empty".into());
    }
    if name.chars().count() > MAX_NAME {
        return Err(format!("the name is longer than {MAX_NAME} characters"));
    }
    if name.trim() != name {
        return Err(format!("the name `{name}` starts or ends with whitespace"));
    }
    if name.chars().any(|c| c.is_control() || c == ',') {
        return Err(format!(
            "the name `{}` has a comma or a control character in it",
            name.escape_debug()
        ));
    }
    Ok(())
}

/// The app id for a name: stable across restarts, without storing anything.
///
/// Moonlight keys box art, favourites and hidden apps by id, so the id must
/// follow the name and not the endpoint's position in a list, or removing one
/// endpoint would shift the next onto its predecessor's favourites. In
/// `2..=i32::MAX`: 0 means "nothing running", 1 is [`LEGACY_APP_ID`], and
/// clients parse the id into a signed int.
pub fn app_id(name: &str) -> u32 {
    let digest =
        solstice_gamestream::crypto::gcm::sha256_concat(&[b"solstice-app", name.as_bytes()]);
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    2 + n % (i32::MAX as u32 - 1)
}

/// One endpoint, checked and with every default settled.
#[derive(Clone, Debug)]
pub struct Endpoint {
    /// Its app id.
    pub id: u32,
    /// Its name.
    pub name: String,
    /// What it dials.
    pub target: Target,
}

/// What an endpoint dials.
#[derive(Clone, Debug)]
pub enum Target {
    /// RFB.
    Vnc(Vnc),
    /// SPICE.
    Spice(Spice),
    /// The built-in colour bars.
    TestPattern,
}

impl Target {
    /// Refuse what is dangerous enough to be worth refusing rather than
    /// warning about.
    pub fn check(&self) -> Result<(), String> {
        match self {
            // The weak RFB security types are refused off-loopback by the
            // backend itself, but catching it here turns a runtime failure
            // into a startup one (`docs/security.md` §4.1).
            Target::Vnc(vnc) => {
                if matches!(
                    vnc.security,
                    VncSecurityKind::None | VncSecurityKind::VncAuth
                ) && !is_loopback_host(&vnc.host)
                {
                    return Err(format!(
                        "security = \"{}\" is refused against {}; use vencrypt or an SSH \
                         tunnel to loopback",
                        vnc.security.as_str(),
                        vnc.host
                    ));
                }
                if vnc.security == VncSecurityKind::VncAuth && vnc.password.is_none() {
                    return Err("security = \"vncauth\" needs a password".into());
                }
            }
            // Same rule, same reason, for SPICE: its ticket is a password
            // check and not a key exchange, so a plaintext channel carries the
            // display and every keystroke in the clear (`docs/security.md`
            // §4.2).
            Target::Spice(spice) => {
                if spice.security == SpiceSecurityKind::Plain && !is_loopback_host(&spice.host) {
                    return Err(format!(
                        "security = \"plain\" is refused against {}; use tls or a tunnel \
                         to loopback",
                        spice.host
                    ));
                }
            }
            Target::TestPattern => {}
        }
        Ok(())
    }

    /// One line for `status`, without secrets.
    pub fn describe(&self) -> String {
        let address = |host: &str, port: u16| {
            if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            }
        };
        match self {
            Target::Vnc(vnc) => format!(
                "vnc {}, {}",
                address(&vnc.host, vnc.port),
                vnc.security.as_str()
            ),
            Target::Spice(spice) => format!(
                "spice {}, {}",
                address(&spice.host, spice.port),
                spice.security.as_str()
            ),
            Target::TestPattern => "testpattern".into(),
        }
    }
}

/// Refuse two endpoints that would be the same app.
pub fn check_unique<'a>(mut endpoints: impl Iterator<Item = (u32, &'a str)>) -> Result<(), String> {
    let mut seen: Vec<(u32, &str)> = Vec::new();
    endpoints.try_for_each(|(id, name)| {
        if let Some((_, other)) = seen.iter().find(|(i, n)| *n == name || *i == id) {
            return Err(if *other == name {
                format!("two endpoints are named `{name}`")
            } else {
                // Odds of one in a billion per pair, but the result -- one
                // tile launching the other's desktop -- is not one to leave to
                // chance.
                format!("`{name}` and `{other}` hash to the same app id; rename one")
            });
        }
        seen.push((id, name));
        Ok(())
    })
}

/// A built endpoint: its app, and the backend that dials it.
#[derive(Clone)]
pub struct Entry {
    /// Its app id.
    pub id: u32,
    /// Its name.
    pub name: String,
    /// What `status` says it dials.
    pub detail: String,
    /// The dialer.
    pub backend: Arc<dyn Backend>,
}

/// Every endpoint the daemon offers. Shared by the supervisor, which dials
/// them, and the management socket, which adds and removes them.
pub struct Endpoints {
    entries: RwLock<Vec<Entry>>,
}

impl Endpoints {
    /// Build the set, refusing duplicates.
    pub fn new(entries: Vec<Entry>) -> Result<Self, String> {
        check_unique(entries.iter().map(|e| (e.id, e.name.as_str())))?;
        Ok(Self {
            entries: RwLock::new(entries),
        })
    }

    /// One backend, offered as the old single app was: [`LEGACY_APP_ID`],
    /// titled `title`.
    pub fn single(title: &str, backend: Arc<dyn Backend>) -> Self {
        Self {
            entries: RwLock::new(vec![Entry {
                id: LEGACY_APP_ID,
                name: title.to_owned(),
                detail: backend.name().to_owned(),
                backend,
            }]),
        }
    }

    /// What `/applist` should offer.
    pub fn apps(&self) -> Vec<App> {
        apps_of(&self.entries.read().expect("endpoint lock"))
    }

    /// Offer them as `host`'s apps.
    pub fn publish(&self, host: &Host) {
        // Under the lock, so that it cannot land between a change and that
        // change's own publish and undo it.
        let entries = self.entries.read().expect("endpoint lock");
        host.set_apps(apps_of(&entries));
    }

    /// Add one, and offer it from `host` at once.
    pub fn add(&self, entry: Entry, host: &Host) -> Result<(), String> {
        let mut entries = self.entries.write().expect("endpoint lock");
        check_unique(
            entries
                .iter()
                .chain(std::iter::once(&entry))
                .map(|e| (e.id, e.name.as_str())),
        )?;
        entries.push(entry);
        host.set_apps(apps_of(&entries));
        Ok(())
    }

    /// Remove the one named `name`, stop offering it, and end its sessions.
    /// Returns it, and how many sessions ended; `None` if there is no such
    /// endpoint.
    pub fn remove(&self, name: &str, host: &Host) -> Option<(Entry, usize)> {
        let entry = {
            let mut entries = self.entries.write().expect("endpoint lock");
            let at = entries.iter().position(|e| e.name == name)?;
            let entry = entries.remove(at);
            host.set_apps(apps_of(&entries));
            entry
        };
        // After the app list, so that no new launch can name it meanwhile.
        // Its running stream sees its launch record go, as a revoked client's
        // does, and tells the client before it stops.
        let ended = host.end_sessions_of_app(entry.id);
        Some((entry, ended))
    }

    /// The endpoint behind an app id.
    pub fn get(&self, id: u32) -> Option<Entry> {
        self.entries
            .read()
            .expect("endpoint lock")
            .iter()
            .find(|e| e.id == id)
            .cloned()
    }

    /// Every endpoint, in order.
    pub fn list(&self) -> Vec<Entry> {
        self.entries.read().expect("endpoint lock").clone()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.entries.read().expect("endpoint lock").is_empty()
    }
}

fn apps_of(entries: &[Entry]) -> Vec<App> {
    entries
        .iter()
        .map(|e| App {
            id: e.id,
            title: e.name.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_spec_parses_with_defaults_for_what_it_leaves_out() {
        let spec = Spec::parse("name=My Spice X,kind=spice,host=127.0.0.1,port=7878").unwrap();
        assert_eq!(spec.name, "My Spice X");
        assert_eq!(spec.kind, BackendKind::Spice);
        let endpoint = spec.resolve().unwrap();
        let Target::Spice(spice) = &endpoint.target else {
            panic!("expected spice")
        };
        assert_eq!((spice.host.as_str(), spice.port), ("127.0.0.1", 7878));
        assert_eq!(spice.security, SpiceSecurityKind::Tls, "the sound default");
        assert!(spice.audio);
        assert_eq!(endpoint.id, app_id("My Spice X"));
    }

    #[test]
    fn spaces_around_fields_and_ipv6_hosts_are_fine() {
        let spec = Spec::parse("name=Six, kind=vnc, host=::1, security=none").unwrap();
        let endpoint = spec.resolve().unwrap();
        let Target::Vnc(vnc) = &endpoint.target else {
            panic!("expected vnc")
        };
        assert_eq!(vnc.host, "::1");
        assert_eq!(endpoint.target.describe(), "vnc [::1]:5900, none");
    }

    #[test]
    fn malformed_specs_are_refused_with_the_reason() {
        for (spec, why) in [
            ("kind=vnc", "`name` is required"),
            ("name=A", "`kind` is required"),
            ("name=A,kind=rdp", "rdp"),
            ("name=A,kind=vnc,port=99999", "not a port"),
            ("name=A,kind=vnc,colour=blue", "unknown key `colour`"),
            ("name=A,name=B,kind=vnc", "given twice"),
            ("name=A,kind=vnc,host", "not key=value"),
            ("name=A,kind=spice,audio=yes", "not true or false"),
        ] {
            let err = Spec::parse(spec).unwrap_err();
            assert!(err.contains(why), "{spec}: {err}");
        }
    }

    #[test]
    fn a_password_on_the_command_line_is_refused() {
        let err = Spec::parse("name=A,kind=vnc,password=hunter2").unwrap_err();
        assert!(err.contains("password_file"), "{err}");
    }

    #[test]
    fn a_password_file_is_read_to_its_first_line() {
        let dir = std::env::temp_dir().join(format!("solstice-pw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pw");
        std::fs::write(&path, "s3cret\r\nignored\n").unwrap();
        let spec = Spec::parse(&format!(
            "name=A,kind=vnc,security=vncauth,password_file={}",
            path.display()
        ))
        .unwrap();
        let Target::Vnc(vnc) = spec.resolve().unwrap().target else {
            panic!("expected vnc")
        };
        assert_eq!(vnc.password.as_deref(), Some("s3cret"));

        std::fs::write(&path, "\n").unwrap();
        assert!(spec.resolve().unwrap_err().contains("is empty"));
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(spec.resolve().unwrap_err().contains("password_file"));
    }

    #[test]
    fn fields_that_do_not_apply_to_the_kind_are_refused() {
        for spec in [
            "name=A,kind=testpattern,host=10.0.0.1",
            "name=A,kind=vnc,audio=false",
            "name=A,kind=vnc,security=tls",
            "name=A,kind=spice,security=vencrypt",
        ] {
            assert!(
                Spec::parse(spec).unwrap().resolve().is_err(),
                "{spec} was accepted"
            );
        }
    }

    /// The same refusals as the old `[backend]` section, whichever way the
    /// endpoint arrives.
    #[test]
    fn weak_security_off_loopback_is_refused() {
        for spec in [
            "name=A,kind=spice,host=192.168.1.10,security=plain",
            "name=A,kind=vnc,host=192.168.1.10,security=none",
            "name=A,kind=vnc,security=vncauth",
        ] {
            assert!(
                Spec::parse(spec).unwrap().resolve().is_err(),
                "{spec} was accepted"
            );
        }
        assert!(
            Spec::parse("name=A,kind=spice,host=localhost,security=plain")
                .unwrap()
                .resolve()
                .is_ok()
        );
    }

    #[test]
    fn names_that_would_not_survive_are_refused() {
        for name in ["", " lead", "trail ", "a\nb", "a\u{1b}[2J"] {
            assert!(check_name(name).is_err(), "{name:?} was accepted");
        }
        assert!(check_name(&"x".repeat(MAX_NAME + 1)).is_err());
        assert!(check_name(&"x".repeat(MAX_NAME)).is_ok());
        assert!(check_name("Büro-PC (2)").is_ok());
    }

    #[test]
    fn app_ids_follow_the_name_and_stay_clear_of_the_reserved_ones() {
        assert_eq!(app_id("Desktop"), app_id("Desktop"));
        assert_ne!(app_id("Desktop"), app_id("Desktop 2"));
        for i in 0..10_000 {
            let id = app_id(&format!("endpoint {i}"));
            assert!((2..=i32::MAX as u32).contains(&id), "{id}");
        }
    }

    #[test]
    fn relative_paths_are_found() {
        for spec in [
            "name=A,kind=vnc,password_file=pw",
            "name=A,kind=vnc,ca_file=./ca.pem",
        ] {
            let err = Spec::parse(spec)
                .unwrap()
                .require_absolute_paths()
                .unwrap_err();
            assert!(err.contains("absolute"), "{spec}: {err}");
        }
        assert!(
            Spec::parse("name=A,kind=vnc,password_file=/etc/pw,ca_file=/etc/ca.pem")
                .unwrap()
                .require_absolute_paths()
                .is_ok()
        );
    }

    fn host() -> Host {
        Host::new(
            Default::default(),
            solstice_gamestream::crypto::certs::HostIdentity::generate("t").unwrap(),
            solstice_gamestream::crypto::certs::ClientStore::new(),
        )
    }

    fn entry(name: &str) -> Entry {
        Entry {
            id: app_id(name),
            name: name.into(),
            detail: "testpattern".into(),
            backend: Arc::new(crate::testpattern::TestPatternBackend::new(64, 64, 30)),
        }
    }

    #[test]
    fn adding_and_removing_changes_what_the_host_offers() {
        let host = host();
        let endpoints = Endpoints::new(vec![entry("A")]).unwrap();
        endpoints.publish(&host);
        assert_eq!(host.apps().len(), 1);

        endpoints.add(entry("B"), &host).unwrap();
        let titles: Vec<_> = host.apps().into_iter().map(|a| a.title).collect();
        assert_eq!(titles, ["A", "B"]);
        assert!(host.has_app(app_id("B")));

        let err = endpoints.add(entry("B"), &host).unwrap_err();
        assert!(err.contains("named `B`"), "{err}");
        assert_eq!(host.apps().len(), 2, "a refused add changes nothing");

        let (removed, ended) = endpoints.remove("A", &host).unwrap();
        assert_eq!((removed.name.as_str(), ended), ("A", 0));
        assert!(!host.has_app(app_id("A")));
        assert!(endpoints.get(app_id("A")).is_none());
        assert!(endpoints.remove("A", &host).is_none());

        endpoints.remove("B", &host).unwrap();
        assert!(endpoints.is_empty());
        assert!(host.apps().is_empty());
    }

    #[test]
    fn duplicate_names_are_refused() {
        let err = check_unique([(5, "A"), (6, "B"), (7, "A")].into_iter()).unwrap_err();
        assert!(err.contains("named `A`"), "{err}");
        let err = check_unique([(5, "A"), (5, "B")].into_iter()).unwrap_err();
        assert!(err.contains("same app id"), "{err}");
        assert!(check_unique([(5, "A"), (6, "B")].into_iter()).is_ok());
    }
}
