//! `/serverinfo` -- capability and state advertisement (`nvhttp.cpp:1265-1310`).

use super::xml::Root;
use super::{Host, RequestContext};

/// `ServerCodecModeSupport` bits (`Limelight.h:506-522`).
pub mod codec {
    #![allow(missing_docs)]
    pub const SCM_H264: u32 = 0x0000_0001;
    pub const SCM_HEVC: u32 = 0x0000_0100;
    pub const SCM_HEVC_MAIN10: u32 = 0x0000_0200;
    pub const SCM_AV1_MAIN8: u32 = 0x0001_0000;
}

/// The version Solstice advertises.
///
/// `appversion` is load-bearing: `moonlight-common-c` parses it into an
/// `AppVersionQuad` and picks packet-type tables and RTSP stream-id strings
/// from it (`ControlStream.c:300-340`, `RtspConnection.c:953`). Anything below
/// 7.1.431 selects a legacy generation, and every legacy branch is an untested
/// branch (`docs/security.md` §6.5).
pub const APP_VERSION: &str = "7.1.431.-1";
/// The GFE version string clients expect alongside it.
pub const GFE_VERSION: &str = "3.23.0.74";

/// Build the `/serverinfo` response.
pub fn serverinfo(host: &Host, ctx: &RequestContext) -> String {
    let paired = ctx
        .client_cert
        .map(|der| host.is_paired(der))
        .unwrap_or(false);
    let current_game = host.current_app_id();

    Root::ok()
        .child("hostname", &host.config.name)
        .child("appversion", APP_VERSION)
        .child("GfeVersion", GFE_VERSION)
        .child("uniqueid", &host.config.uuid)
        .child("HttpsPort", host.config.https_port)
        .child("ExternalPort", host.config.port)
        .child("MaxLumaPixelsHEVC", 0) // H.264 only, so no HEVC claim
        // The real MAC is only disclosed over mutual TLS; the plaintext
        // listener is reachable by anyone (`nvhttp.cpp:1286`).
        .child(
            "mac",
            if ctx.over_tls {
                &host.config.mac
            } else {
                "00:00:00:00:00:00"
            },
        )
        .child("LocalIP", &host.config.local_ip)
        .child("ServerCodecModeSupport", codec::SCM_H264)
        .child("PairStatus", u8::from(paired))
        .child("currentgame", current_game)
        .child(
            "state",
            if current_game == 0 {
                "SUNSHINE_SERVER_FREE"
            } else {
                "SUNSHINE_SERVER_BUSY"
            },
        )
        .render()
}
