//! `/applist` and `/appasset`.
//!
//! Solstice bridges one thing -- a remote desktop -- so it offers exactly one
//! app. There is no app launcher and nothing here starts a process, which is
//! deliberate: Sunshine's command-injection CVEs are all downstream of a host
//! that can launch arbitrary commands (`docs/security.md` §3.5).

use super::xml::{escape, Root};
use super::Host;

/// The id of the one app.
pub const DESKTOP_APP_ID: u32 = 1;

/// Build the `/applist` response.
pub fn applist(host: &Host) -> String {
    let markup = format!(
        "<App><IsHdrSupported>0</IsHdrSupported><AppTitle>{}</AppTitle><ID>{}</ID></App>",
        escape(&host.config.app_title),
        DESKTOP_APP_ID
    );
    Root::ok().raw(&markup).render()
}

/// Whether an app id is one Solstice will launch.
pub fn is_known_app(app_id: u32) -> bool {
    // 0 means "resume whatever is running", which the launch handler treats
    // separately.
    app_id == DESKTOP_APP_ID
}
