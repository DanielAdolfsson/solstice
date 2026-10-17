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

/// The id of the one entry `/applist` shows when there are no apps.
///
/// Inside the range real ids are hashed into, but never alongside one: it is
/// only ever listed when nothing else is.
pub const PLACEHOLDER_APP_ID: u32 = i32::MAX as u32;

/// Its title.
pub const PLACEHOLDER_TITLE: &str = "No desktops on this host";

/// What a launch is refused with while there are no apps -- the placeholder's,
/// or a tile the client still holds from before.
pub const NO_APPS_REFUSAL: &str = "This host has no desktops to offer yet. \
     Add one with `solstice endpoint add`, or in its configuration";

/// Build the `/applist` response.
///
/// With no apps, this is one placeholder entry rather than an empty list.
/// moonlight-qt treats an empty list as a failed fetch and goes on showing
/// whatever it had cached (`PcMonitorThread::updateAppList`), so a host whose
/// last desktop went away would still show it, and launching it would fail.
/// The placeholder replaces that cache, and launching it explains.
pub fn applist(host: &Host) -> String {
    let mut apps = host.apps();
    if apps.is_empty() {
        apps.push(App {
            id: PLACEHOLDER_APP_ID,
            title: PLACEHOLDER_TITLE.into(),
        });
    }
    let markup: String = apps
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
