//! `/pair` -- the four-phase PIN handshake over plaintext HTTP.
//!
//! The crypto and the ordering rules live in [`crate::crypto::pairing`]; this
//! module is only the HTTP shape of them. Each phase is recognised by the
//! parameter present, exactly as Sunshine dispatches it, and anything that does
//! not match a phase ends the handshake rather than being ignored.

use std::time::Instant;

use super::xml::Root;
use super::{Host, RequestContext};
use crate::crypto::pairing::{PairingError, PairingRefusal};

/// Handle one `/pair` request, returning the XML body.
pub fn pair(host: &Host, ctx: &RequestContext) -> (u16, String) {
    let now = Instant::now();

    // The HTTPS probe that ends the flow: the client presents its certificate
    // and asks whether it is trusted.
    if ctx.request.param("phrase") == Some("pairchallenge") {
        return if ctx
            .client_cert
            .map(|der| host.is_paired(der))
            .unwrap_or(false)
        {
            (200, Root::ok().child("paired", 1).render())
        } else {
            (
                200,
                Root::error(400, "Not paired").child("paired", 0).render(),
            )
        };
    }

    if !host.pairing_allowed_from(ctx.peer_ip) {
        tracing::warn!(peer = %ctx.peer_ip, "pairing attempt from a disallowed address");
        return refuse(PairingRefusal::SourceNotAllowed);
    }

    // Check the window before parsing anything the client sent. When pairing
    // is shut there is no reason to run an attacker's bytes through a
    // certificate parser.
    {
        let mgr = host.pairing.lock().expect("pairing lock");
        if mgr.is_locked_out() {
            return refuse(PairingRefusal::LockedOut);
        }
        if !mgr.is_open(now) {
            return refuse(PairingRefusal::WindowClosed);
        }
    }

    if ctx.request.param("phrase") == Some("getservercert") {
        return getservercert(host, ctx, now);
    }
    if let Some(hex) = ctx.request.param_hex("clientchallenge") {
        return step(
            host,
            now,
            |mgr| mgr.step(now, |s| s.client_challenge(&hex)),
            |response| {
                Root::ok()
                    .child("paired", 1)
                    .child("challengeresponse", hex::encode(response))
                    .render()
            },
        );
    }
    if let Some(hex) = ctx.request.param_hex("serverchallengeresp") {
        return server_challenge_response(host, ctx, now, &hex);
    }
    if let Some(hex) = ctx.request.param_hex("clientpairingsecret") {
        return client_pairing_secret(host, now, &hex);
    }

    host.abandon_pairing();
    (
        400,
        Root::error(400, "Unrecognised pairing phase")
            .child("paired", 0)
            .render(),
    )
}

fn getservercert(host: &Host, ctx: &RequestContext, now: Instant) -> (u16, String) {
    let Some(salt_bytes) = ctx.request.param_hex("salt") else {
        return bad_request(host, "salt is not hex");
    };
    let Ok(salt) = <[u8; 16]>::try_from(salt_bytes.as_slice()) else {
        return bad_request(host, "salt is not 16 bytes");
    };
    let Some(cert_hex) = ctx.request.param("clientcert") else {
        return bad_request(host, "clientcert missing");
    };
    let Ok(cert_pem) = hex::decode(cert_hex) else {
        return bad_request(host, "clientcert is not hex");
    };
    let Ok(cert_pem) = String::from_utf8(cert_pem) else {
        return bad_request(host, "clientcert is not UTF-8 PEM");
    };
    let Ok(cert_der) = crate::crypto::certs::pem_to_der(&cert_pem) else {
        return bad_request(host, "clientcert is not a certificate");
    };

    let device_name = ctx.request.param("devicename").unwrap_or("unknown");
    let unique_id = ctx.request.param("uniqueid").unwrap_or("");
    let mut mgr = host.pairing.lock().expect("pairing lock");
    match mgr.start(&host.identity, device_name, unique_id, &salt, cert_der, now) {
        Ok(server_cert_pem) => (
            200,
            Root::ok()
                .child("paired", 1)
                .child("plaincert", hex::encode(server_cert_pem.as_bytes()))
                .render(),
        ),
        Err(PairingError::Refused(r)) => refuse(r),
        Err(PairingError::Crypto(e)) => {
            tracing::warn!(error = %e, "pairing start failed");
            (
                200,
                Root::error(400, "Pairing failed")
                    .child("paired", 0)
                    .render(),
            )
        }
    }
}

fn server_challenge_response(
    host: &Host,
    _ctx: &RequestContext,
    now: Instant,
    hex_body: &[u8],
) -> (u16, String) {
    let mut mgr = host.pairing.lock().expect("pairing lock");
    if let Err(e) = mgr.step(now, |s| s.server_challenge_response(hex_body)) {
        return pairing_error(e);
    }
    // The signing key is borrowed only here, after the transition succeeded.
    let Some(session) = mgr.session() else {
        return (
            200,
            Root::error(400, "Pairing failed")
                .child("paired", 0)
                .render(),
        );
    };
    match session.pairing_secret(&host.identity) {
        Ok(secret) => (
            200,
            Root::ok()
                .child("paired", 1)
                .child("pairingsecret", hex::encode(secret))
                .render(),
        ),
        Err(e) => {
            tracing::error!(error = %e, "signing the pairing secret failed");
            (
                200,
                Root::error(400, "Pairing failed")
                    .child("paired", 0)
                    .render(),
            )
        }
    }
}

fn client_pairing_secret(host: &Host, now: Instant, body: &[u8]) -> (u16, String) {
    let result = {
        let mut mgr = host.pairing.lock().expect("pairing lock");
        mgr.finish(now, body)
    };
    match result {
        Ok(client) => {
            let name = client.device_name.clone();
            match host.clients.write().expect("client store lock").add(client) {
                Ok(()) => {
                    tracing::info!(device = %name, "paired a new client");
                    (200, Root::ok().child("paired", 1).render())
                }
                Err(e) => {
                    tracing::error!(error = %e, "could not persist the paired client");
                    (
                        200,
                        Root::error(500, "Could not persist")
                            .child("paired", 0)
                            .render(),
                    )
                }
            }
        }
        Err(e) => pairing_error(e),
    }
}

fn step<T>(
    host: &Host,
    _now: Instant,
    run: impl FnOnce(
        &mut crate::crypto::pairing::PairingManager,
    ) -> std::result::Result<T, PairingError>,
    render: impl FnOnce(T) -> String,
) -> (u16, String) {
    let mut mgr = host.pairing.lock().expect("pairing lock");
    match run(&mut mgr) {
        Ok(value) => (200, render(value)),
        Err(e) => pairing_error(e),
    }
}

fn pairing_error(e: PairingError) -> (u16, String) {
    match e {
        PairingError::Refused(r) => refuse(r),
        PairingError::Crypto(e) => {
            tracing::warn!(error = %e, "pairing step failed");
            (
                200,
                Root::error(400, "Pairing failed")
                    .child("paired", 0)
                    .render(),
            )
        }
    }
}

fn refuse(reason: PairingRefusal) -> (u16, String) {
    tracing::warn!(%reason, "pairing refused");
    // The status code distinguishes the policy refusals, but the XML body says
    // only "not paired": a prober learns nothing about which control fired.
    let status = match reason {
        PairingRefusal::LockedOut => 429,
        PairingRefusal::SourceNotAllowed => 403,
        _ => 503,
    };
    (
        status,
        Root::error(503, "Pairing is not open")
            .child("paired", 0)
            .render(),
    )
}

fn bad_request(host: &Host, why: &'static str) -> (u16, String) {
    tracing::warn!(reason = why, "malformed pairing request");
    host.abandon_pairing();
    (
        400,
        Root::error(400, "Bad pairing request")
            .child("paired", 0)
            .render(),
    )
}
