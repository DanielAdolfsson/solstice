//! The two UDP media channels.
//!
//! A session starts when the client sends an `SS_PING` whose payload matches
//! the one minted at `/launch`; that is how the host learns where to send video
//! and audio. The payload is a 64-bit secret delivered over HTTPS, and the
//! legacy form -- a literal `"PING"` matched by source address alone -- is not
//! implemented at all, because it is trivially spoofable
//! (`docs/security.md` §2.3).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use solstice_gamestream::wire::ping::Ping;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// How long to wait for the client's first ping before giving up.
pub const PING_TIMEOUT: Duration = Duration::from_secs(30);

/// Wait for a ping carrying `expected`, and return where it came from.
pub async fn await_peer(socket: &UdpSocket, expected: &[u8; 16]) -> std::io::Result<SocketAddr> {
    let mut buf = [0u8; 256];
    let deadline = tokio::time::Instant::now() + PING_TIMEOUT;
    loop {
        let (len, from) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "no matching ping arrived")
            })??;
        match Ping::parse(&buf[..len]) {
            Ok(ping) if constant_time_eq(&ping.payload, expected) => {
                tracing::info!(%from, "media peer bound");
                return Ok(from);
            }
            Ok(_) => tracing::debug!(%from, "ping payload did not match"),
            Err(e) => tracing::debug!(%from, error = %e, "malformed ping"),
        }
    }
}

fn constant_time_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Send datagrams to a bound peer, pacing them within each frame.
///
/// Sunshine spreads a frame's packets over time rather than bursting
/// (`stream.cpp:1680-1690`); a burst causes loss on a real link, and the loss
/// then costs an IDR, which costs far more than the pacing did.
pub async fn sender_task(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    mut rx: mpsc::Receiver<Vec<Vec<u8>>>,
    frame_interval: Duration,
) {
    while let Some(packets) = rx.recv().await {
        if packets.is_empty() {
            continue;
        }
        // Spread over at most half the frame interval, so a late frame is never
        // delayed by its predecessor's pacing.
        let budget = frame_interval / 2;
        let gap = budget.checked_div(packets.len() as u32).unwrap_or_default();
        for packet in packets {
            if let Err(e) = socket.send_to(&packet, peer).await {
                tracing::warn!(error = %e, "media send failed");
                return;
            }
            if !gap.is_zero() {
                tokio::time::sleep(gap).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_matching_ping_binds_the_peer() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let payload = *b"0123456789abcdef";

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        tokio::spawn(async move {
            // A wrong payload first, then the right one.
            let wrong = Ping {
                payload: *b"ffffffffffffffff",
                sequence_number: 0,
            };
            client.send_to(&wrong.to_bytes(), addr).await.unwrap();
            let right = Ping {
                payload,
                sequence_number: 1,
            };
            client.send_to(&right.to_bytes(), addr).await.unwrap();
        });

        let bound = await_peer(&server, &payload).await.unwrap();
        assert_eq!(bound, client_addr);
    }

    #[tokio::test]
    async fn the_legacy_ping_does_not_bind_anything() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"PING", addr).await.unwrap();

        let result = tokio::time::timeout(
            Duration::from_millis(200),
            await_peer(&server, b"0123456789abcdef"),
        )
        .await;
        assert!(result.is_err(), "the legacy PING must not bind a peer");
    }
}
