//! `/applist` and `/appasset`.
//!
//! Solstice bridges remote desktops, and offers one app per desktop it has
//! been told about -- none, one, or several. There is no app launcher and
//! nothing here starts a process, which is deliberate: Sunshine's
//! command-injection CVEs are all downstream of a host that can launch
//! arbitrary commands (`docs/security.md` §3.5). An app is a name and an id;
//! what it dials is the daemon's business, not this crate's.

use super::xml::{escape, Root};
use super::Host;

/// One entry in `/applist`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct App {
    /// What `/launch?appid=` names. Never 0, which `currentgame` uses for
    /// "nothing running", and at most `i32::MAX`, because clients parse it
    /// into a signed int.
    pub id: u32,
    /// What Moonlight shows under the tile.
    pub title: String,
}

/// Build the `/applist` response.
///
/// With no apps this is an empty, successful list rather than an error: a
/// client treats a failed fetch as a problem with the host, and an empty one
/// as a host with nothing to offer yet.
pub fn applist(host: &Host) -> String {
    let markup: String = host
        .apps()
        .iter()
        .map(|app| {
            format!(
                "<App><IsHdrSupported>0</IsHdrSupported><AppTitle>{}</AppTitle><ID>{}</ID></App>",
                escape(&app.title),
                app.id
            )
        })
        .collect();
    Root::ok().raw(&markup).render()
}
