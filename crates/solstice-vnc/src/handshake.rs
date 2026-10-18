//! Version, security type, authentication, `ClientInit`, `ServerInit`.
//!
//! Strictly ordered, and the order is where a sloppy client goes wrong: every
//! step's reply is read before the next is sent.

use std::net::IpAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::auth::{vnc_auth_response, VncSecurity};
use crate::pixel::PixelFormat;
use crate::protocol::{security, vencrypt, Result, RfbError};

/// Anything that can carry an RFB connection, with or without TLS under it.
pub trait RfbTransport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> RfbTransport for T {}

/// Longest desktop name accepted.
const MAX_DESKTOP_NAME: u32 = 4096;

/// What `ServerInit` said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerInit {
    /// Framebuffer width.
    pub width: u16,
    /// Framebuffer height.
    pub height: u16,
    /// The server's preferred pixel format.
    pub format: PixelFormat,
    /// Desktop name.
    pub name: String,
}

/// The RFB protocol version in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// Major, always 3 in practice.
    pub major: u8,
    /// Minor: 3, 7 or 8.
    pub minor: u8,
}

impl Version {
    /// Whether the server sends a security *list* rather than a single u32.
    pub fn has_security_list(&self) -> bool {
        self.minor >= 7
    }

    /// Whether `SecurityResult` carries a reason string on failure.
    pub fn has_failure_reason(&self) -> bool {
        self.minor >= 8
    }
}

/// Read and answer the version handshake.
pub async fn negotiate_version<S: RfbTransport>(stream: &mut S) -> Result<Version> {
    let mut banner = [0u8; 12];
    stream.read_exact(&mut banner).await?;
    let text = std::str::from_utf8(&banner)
        .map_err(|_| RfbError::UnsupportedVersion("<not ASCII>".into()))?;
    if !text.starts_with("RFB ") || !text.ends_with('\n') {
        return Err(RfbError::UnsupportedVersion(text.trim_end().to_owned()));
    }
    let major: u32 = text[4..7]
        .parse()
        .map_err(|_| RfbError::UnsupportedVersion(text.into()))?;
    // Not a u8: Apple announces 003.889 and means 003.008, so the field has to
    // be read before it can be clamped.
    let minor: u32 = text[8..11]
        .parse()
        .map_err(|_| RfbError::UnsupportedVersion(text.into()))?;
    if major != 3 {
        return Err(RfbError::UnsupportedVersion(text.trim_end().to_owned()));
    }

    // Answer with the highest version both sides know. Apple announces 003.889
    // and means 003.008; clamping rather than echoing is what makes that work.
    let chosen = Version {
        major: 3,
        minor: if minor >= 8 {
            8
        } else {
            minor.clamp(3, 7) as u8
        },
    };
    let reply = format!("RFB {:03}.{:03}\n", chosen.major, chosen.minor);
    stream.write_all(reply.as_bytes()).await?;
    stream.flush().await?;
    Ok(chosen)
}

/// Read the offered security types.
pub async fn read_security_types<S: RfbTransport>(
    stream: &mut S,
    version: Version,
) -> Result<Vec<u8>> {
    if !version.has_security_list() {
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await?;
        let kind = u32::from_be_bytes(buf);
        if kind == security::INVALID as u32 {
            return Err(RfbError::Auth(read_reason(stream).await?));
        }
        return Ok(vec![kind as u8]);
    }
    let mut count = [0u8; 1];
    stream.read_exact(&mut count).await?;
    if count[0] == 0 {
        return Err(RfbError::Auth(read_reason(stream).await?));
    }
    let mut types = vec![0u8; count[0] as usize];
    stream.read_exact(&mut types).await?;
    Ok(types)
}

async fn read_reason<S: RfbTransport>(stream: &mut S) -> Result<String> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len).min(MAX_DESKTOP_NAME) as usize;
    let mut reason = vec![0u8; len];
    stream.read_exact(&mut reason).await?;
    Ok(String::from_utf8_lossy(&reason).into_owned())
}

/// Run authentication for the chosen security type.
///
/// VeNCrypt's TLS upgrade is not handled here: it changes the transport type,
/// so the caller performs it and calls back in for the sub-type.
pub async fn authenticate<S: RfbTransport>(
    stream: &mut S,
    version: Version,
    config: &VncSecurity,
) -> Result<()> {
    match config {
        VncSecurity::None => {}
        VncSecurity::VncAuth { password } => {
            let mut challenge = [0u8; 16];
            stream.read_exact(&mut challenge).await?;
            stream
                .write_all(&vnc_auth_response(password, &challenge))
                .await?;
            stream.flush().await?;
        }
        VncSecurity::VeNCrypt { .. } => {
            return Err(RfbError::Auth("VeNCrypt is handled by the caller".into()))
        }
    }
    read_security_result(stream, version).await
}

/// Read `SecurityResult`.
pub async fn read_security_result<S: RfbTransport>(stream: &mut S, version: Version) -> Result<()> {
    let mut result = [0u8; 4];
    stream.read_exact(&mut result).await?;
    if u32::from_be_bytes(result) == 0 {
        return Ok(());
    }
    let reason = if version.has_failure_reason() {
        read_reason(stream)
            .await
            .unwrap_or_else(|_| "authentication failed".into())
    } else {
        "authentication failed".into()
    };
    Err(RfbError::Auth(reason))
}

/// Negotiate the VeNCrypt version and pick a sub-type.
///
/// Returns the chosen sub-type. The caller then wraps the transport in TLS and
/// continues.
pub async fn negotiate_vencrypt<S: RfbTransport>(
    stream: &mut S,
    want_password: bool,
) -> Result<u32> {
    let mut version = [0u8; 2];
    stream.read_exact(&mut version).await?;
    if version[0] != 0 {
        return Err(RfbError::Auth(format!(
            "VeNCrypt version {}.{}",
            version[0], version[1]
        )));
    }
    // Ask for 0.2, the only version with sub-types.
    stream.write_all(&[0, 2]).await?;
    stream.flush().await?;

    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).await?;
    if ack[0] != 0 {
        return Err(RfbError::Auth("server rejected VeNCrypt 0.2".into()));
    }

    let mut count = [0u8; 1];
    stream.read_exact(&mut count).await?;
    if count[0] == 0 {
        return Err(RfbError::Auth("server offers no VeNCrypt sub-types".into()));
    }
    let mut raw = vec![0u8; count[0] as usize * 4];
    stream.read_exact(&mut raw).await?;
    let offered: Vec<u32> = raw
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        .collect();

    // X509 first: it is the only sub-type that authenticates the server.
    // Anonymous TLS encrypts and authenticates nothing, so it is MITM-able and
    // is not offered as a fallback.
    let preference: &[u32] = if want_password {
        &[vencrypt::X509_VNC, vencrypt::X509_PLAIN]
    } else {
        &[vencrypt::X509_NONE]
    };
    let chosen = preference
        .iter()
        .copied()
        .find(|t| offered.contains(t))
        .ok_or_else(|| {
            RfbError::Auth(format!(
                "server offers VeNCrypt sub-types {offered:?}, none of which authenticate it; \
             anonymous TLS is refused"
            ))
        })?;
    stream.write_all(&chosen.to_be_bytes()).await?;
    stream.flush().await?;
    Ok(chosen)
}

/// Send `ClientInit` and read `ServerInit`.
pub async fn initialise<S: RfbTransport>(stream: &mut S, shared: bool) -> Result<ServerInit> {
    stream.write_all(&[u8::from(shared)]).await?;
    stream.flush().await?;

    let mut head = [0u8; 20];
    stream.read_exact(&mut head).await?;
    let width = u16::from_be_bytes([head[0], head[1]]);
    let height = u16::from_be_bytes([head[2], head[3]]);
    let format = PixelFormat::parse(head[4..20].try_into().expect("20 - 4 == 16"))?;

    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len);
    if len > MAX_DESKTOP_NAME {
        return Err(RfbError::Limit(format!("desktop name of {len} bytes")));
    }
    let mut name = vec![0u8; len as usize];
    stream.read_exact(&mut name).await?;

    if width == 0 || height == 0 {
        return Err(RfbError::Protocol(format!(
            "server announced a {width}x{height} framebuffer"
        )));
    }
    Ok(ServerInit {
        width,
        height,
        format,
        name: String::from_utf8_lossy(&name).into_owned(),
    })
}

/// Pick the security type to use, applying the policy.
pub fn choose_security(
    config: &VncSecurity,
    offered: &[u8],
    peer: IpAddr,
    allow_insecure: bool,
) -> Result<u8> {
    config.choose_allowing(offered, peer, allow_insecure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    async fn with_server<F, Fut, T>(script: Vec<u8>, client: F) -> (T, Vec<u8>)
    where
        F: FnOnce(tokio::io::DuplexStream) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let (mut server, client_end) = duplex(64 * 1024);
        let handle = tokio::spawn(async move {
            server.write_all(&script).await.unwrap();
            let mut received = Vec::new();
            // Read whatever the client sends until it closes.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                server.read_to_end(&mut received),
            )
            .await;
            received
        });
        let out = client(client_end).await;
        let received = handle.await.unwrap();
        (out, received)
    }

    #[tokio::test]
    async fn version_handshake_answers_with_the_lower_version() {
        let (version, sent) = with_server(b"RFB 003.008\n".to_vec(), |mut s| async move {
            negotiate_version(&mut s).await.unwrap()
        })
        .await;
        assert_eq!(version, Version { major: 3, minor: 8 });
        assert_eq!(&sent, b"RFB 003.008\n");

        let (version, sent) = with_server(b"RFB 003.003\n".to_vec(), |mut s| async move {
            negotiate_version(&mut s).await.unwrap()
        })
        .await;
        assert_eq!(version, Version { major: 3, minor: 3 });
        assert_eq!(&sent, b"RFB 003.003\n");
    }

    /// Apple announces 003.889 and means 003.008.
    #[tokio::test]
    async fn an_absurd_minor_version_is_clamped() {
        let (version, sent) = with_server(b"RFB 003.889\n".to_vec(), |mut s| async move {
            negotiate_version(&mut s).await.unwrap()
        })
        .await;
        assert_eq!(version.minor, 8);
        assert_eq!(&sent, b"RFB 003.008\n");
    }

    #[tokio::test]
    async fn a_foreign_banner_is_refused() {
        for banner in [
            &b"HTTP/1.1 200\n"[..],
            b"RFB 004.000\n",
            b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        ] {
            let (result, _) = with_server(banner.to_vec(), |mut s| async move {
                negotiate_version(&mut s).await
            })
            .await;
            assert!(result.is_err(), "{banner:?} was accepted");
        }
    }

    #[tokio::test]
    async fn security_types_are_read_as_a_list_above_3_7() {
        let (types, _) = with_server(
            vec![2, security::VENCRYPT, security::NONE],
            |mut s| async move {
                read_security_types(&mut s, Version { major: 3, minor: 8 })
                    .await
                    .unwrap()
            },
        )
        .await;
        assert_eq!(types, vec![security::VENCRYPT, security::NONE]);
    }

    #[tokio::test]
    async fn security_type_is_a_single_u32_at_3_3() {
        let (types, _) = with_server(2u32.to_be_bytes().to_vec(), |mut s| async move {
            read_security_types(&mut s, Version { major: 3, minor: 3 })
                .await
                .unwrap()
        })
        .await;
        assert_eq!(types, vec![security::VNC_AUTH]);
    }

    #[tokio::test]
    async fn an_empty_security_list_carries_a_reason() {
        let mut script = vec![0u8];
        script.extend_from_slice(&6u32.to_be_bytes());
        script.extend_from_slice(b"no way");
        let (result, _) = with_server(script, |mut s| async move {
            read_security_types(&mut s, Version { major: 3, minor: 8 }).await
        })
        .await;
        assert!(matches!(result, Err(RfbError::Auth(r)) if r == "no way"));
    }

    #[tokio::test]
    async fn vnc_auth_answers_the_challenge() {
        let mut script = [0u8; 16].to_vec();
        script.extend_from_slice(&0u32.to_be_bytes()); // SecurityResult OK
        let config = VncSecurity::VncAuth {
            password: "secret".into(),
        };
        let (result, sent) = with_server(script, |mut s| async move {
            authenticate(&mut s, Version { major: 3, minor: 8 }, &config).await
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(&sent[..16], &vnc_auth_response("secret", &[0u8; 16]));
    }

    #[tokio::test]
    async fn a_failed_security_result_carries_its_reason_at_3_8() {
        let mut script = 1u32.to_be_bytes().to_vec();
        script.extend_from_slice(&11u32.to_be_bytes());
        script.extend_from_slice(b"bad password");
        let (result, _) = with_server(script, |mut s| async move {
            read_security_result(&mut s, Version { major: 3, minor: 8 }).await
        })
        .await;
        assert!(matches!(result, Err(RfbError::Auth(r)) if r == "bad passwor"));
    }

    #[tokio::test]
    async fn server_init_is_parsed() {
        let mut script = 1280u16.to_be_bytes().to_vec();
        script.extend_from_slice(&720u16.to_be_bytes());
        script.extend_from_slice(&PixelFormat::BGRA.to_bytes());
        script.extend_from_slice(&7u32.to_be_bytes());
        script.extend_from_slice(b"desktop");
        let (init, sent) = with_server(script, |mut s| async move {
            initialise(&mut s, true).await.unwrap()
        })
        .await;
        assert_eq!(init.width, 1280);
        assert_eq!(init.height, 720);
        assert_eq!(init.name, "desktop");
        assert_eq!(sent, vec![1]); // shared flag
    }

    #[tokio::test]
    async fn a_zero_sized_framebuffer_is_refused() {
        let mut script = 0u16.to_be_bytes().to_vec();
        script.extend_from_slice(&0u16.to_be_bytes());
        script.extend_from_slice(&PixelFormat::BGRA.to_bytes());
        script.extend_from_slice(&0u32.to_be_bytes());
        let (result, _) = with_server(
            script,
            |mut s| async move { initialise(&mut s, true).await },
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn an_absurd_desktop_name_length_is_refused() {
        let mut script = 16u16.to_be_bytes().to_vec();
        script.extend_from_slice(&16u16.to_be_bytes());
        script.extend_from_slice(&PixelFormat::BGRA.to_bytes());
        script.extend_from_slice(&u32::MAX.to_be_bytes());
        let (result, _) = with_server(
            script,
            |mut s| async move { initialise(&mut s, true).await },
        )
        .await;
        assert!(matches!(result, Err(RfbError::Limit(_))));
    }

    /// Anonymous TLS encrypts but authenticates nothing, so it is MITM-able.
    #[tokio::test]
    async fn anonymous_tls_sub_types_are_refused() {
        let mut script = vec![0, 2, 0, 2];
        script.extend_from_slice(&vencrypt::TLS_NONE.to_be_bytes());
        script.extend_from_slice(&vencrypt::TLS_VNC.to_be_bytes());
        let (result, _) = with_server(script, |mut s| async move {
            negotiate_vencrypt(&mut s, false).await
        })
        .await;
        assert!(matches!(result, Err(RfbError::Auth(_))));
    }

    #[tokio::test]
    async fn x509_sub_types_are_chosen() {
        let mut script = vec![0, 2, 0, 2];
        script.extend_from_slice(&vencrypt::TLS_NONE.to_be_bytes());
        script.extend_from_slice(&vencrypt::X509_NONE.to_be_bytes());
        let (chosen, sent) = with_server(script, |mut s| async move {
            negotiate_vencrypt(&mut s, false).await.unwrap()
        })
        .await;
        assert_eq!(chosen, vencrypt::X509_NONE);
        assert_eq!(&sent[..2], &[0, 2]); // asked for VeNCrypt 0.2
        assert_eq!(&sent[2..6], &vencrypt::X509_NONE.to_be_bytes());
    }
}
