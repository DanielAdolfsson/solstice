//! `/launch`, `/resume` and `/cancel` (`nvhttp.cpp:487-543`, `:1395-1401`).

use std::time::Instant;

use zeroize::Zeroizing;

use super::applist::is_known_app;
use super::session::{LaunchSession, PING_PAYLOAD_LEN};
use super::xml::Root;
use super::{Host, RequestContext};

/// Handle `/launch`.
pub fn launch(host: &Host, ctx: &RequestContext) -> (u16, String) {
    // The four parameters Sunshine insists on (`nvhttp.cpp:1395-1401`).
    let (Some(rikey_hex), Some(rikey_id), Some(_local_audio), Some(app_id)) = (
        ctx.request.param("rikey"),
        ctx.request.param_num::<i64>("rikeyid"),
        ctx.request.param("localAudioPlayMode"),
        ctx.request.param_num::<u32>("appid"),
    ) else {
        return (400, Root::error(400, "Missing launch parameters").render());
    };

    let Ok(rikey_bytes) = hex::decode(rikey_hex) else {
        return (400, Root::error(400, "rikey is not hex").render());
    };
    let Ok(rikey) = <[u8; 16]>::try_from(rikey_bytes.as_slice()) else {
        return (400, Root::error(400, "rikey is not 16 bytes").render());
    };
    if !is_known_app(app_id) {
        return (404, Root::error(404, "No such app").render());
    }
    let Some(client_cert) = ctx.client_cert else {
        return (
            401,
            Root::error(401, "Client certificate required").render(),
        );
    };
    // Revocation is checked here, on this request, rather than cached from
    // session start (`docs/security.md` §3.4).
    if !host.is_paired(client_cert) {
        return (401, Root::error(401, "Not paired").render());
    }

    let mut sessions = host.sessions.lock().expect("session lock");
    if sessions.len() >= host.config.max_sessions {
        return (503, Root::error(503, "Host is busy").render());
    }

    let session = LaunchSession {
        id: hex::encode(random_bytes::<8>()).to_uppercase(),
        client_cert_der: client_cert.to_vec(),
        rikey: Zeroizing::new(rikey),
        // `rikeyid` is a signed int in the query string and may legitimately be
        // negative; wrapping is what the audio IV construction expects.
        rikey_id: rikey_id as i32,
        av_ping_payload: ping_payload(),
        control_connect_data: u32::from_be_bytes(random_bytes::<4>()),
        app_id,
        requested_mode: ctx
            .request
            .param("mode")
            .and_then(LaunchSession::parse_mode),
        // `corever >= 1` means the client speaks encrypted RTSP.
        encrypted_rtsp: ctx.request.param_num::<u32>("corever").unwrap_or(0) >= 1,
        started: Instant::now(),
    };

    let scheme = if session.encrypted_rtsp {
        "rtspenc"
    } else {
        "rtsp"
    };
    let body = Root::ok()
        .child(
            "sessionUrl0",
            format!(
                "{scheme}://{}:{}",
                host.config.local_ip, host.config.rtsp_port
            ),
        )
        .child("gamesession", 1)
        .render();
    tracing::info!(session = %session.id, app = app_id, encrypted_rtsp = session.encrypted_rtsp, "launched");
    sessions.push(session);
    (200, body)
}

/// Handle `/resume`.
///
/// Re-attaching needs the same proof of identity as launching, and the session
/// being resumed must belong to the *same* certificate.
pub fn resume(host: &Host, ctx: &RequestContext) -> (u16, String) {
    let Some(client_cert) = ctx.client_cert else {
        return (
            401,
            Root::error(401, "Client certificate required").render(),
        );
    };
    if !host.is_paired(client_cert) {
        return (401, Root::error(401, "Not paired").render());
    }
    let sessions = host.sessions.lock().expect("session lock");
    let Some(session) = sessions.iter().find(|s| s.client_cert_der == client_cert) else {
        return (404, Root::error(404, "No session to resume").render());
    };
    let scheme = if session.encrypted_rtsp {
        "rtspenc"
    } else {
        "rtsp"
    };
    (
        200,
        Root::ok()
            .child(
                "sessionUrl0",
                format!(
                    "{scheme}://{}:{}",
                    host.config.local_ip, host.config.rtsp_port
                ),
            )
            .child("resume", 1)
            .render(),
    )
}

/// Handle `/cancel`.
pub fn cancel(host: &Host, ctx: &RequestContext) -> (u16, String) {
    let Some(client_cert) = ctx.client_cert else {
        return (
            401,
            Root::error(401, "Client certificate required").render(),
        );
    };
    if !host.is_paired(client_cert) {
        return (401, Root::error(401, "Not paired").render());
    }
    let closed = host.end_sessions_of(client_cert);
    tracing::info!(closed, "cancel");
    (200, Root::ok().child("cancel", 1).render())
}

/// Eight random bytes, hex-encoded to the 16 ASCII characters the client
/// echoes back on the video and audio ports.
fn ping_payload() -> [u8; PING_PAYLOAD_LEN] {
    let hex = hex::encode(random_bytes::<8>());
    let mut out = [0u8; PING_PAYLOAD_LEN];
    out.copy_from_slice(hex.as_bytes());
    out
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::TryRngCore;
    let mut out = [0u8; N];
    rand::rngs::OsRng
        .try_fill_bytes(&mut out)
        .expect("OS CSPRNG");
    out
}
