//! A deliberately minimal, deliberately pedantic RFB server, and a recorder.
//!
//! `docs/testing.md` §3.2 argues for two poles rather than a matrix of real
//! servers: TigerVNC at one end, with everything present, and a mock at the
//! other with nothing optional present at all. Testing only against TigerVNC
//! risks coding to that server's quirks and shipping a client that only works
//! with TigerVNC.
//!
//! So this server offers:
//!
//! * Raw encoding only -- no Tight, no ZRLE, no CopyRect;
//! * no ContinuousUpdates and no Fence, forcing the request/response fallback;
//! * no QEMU Extended Key Event, forcing the VK to keysym path;
//! * RFB 3.3 and 3.8, `None` and `VNC Authentication`;
//! * strict message ordering.
//!
//! And it **records every client message**, which is what makes input testable
//! precisely: inject a Moonlight key event at one end and assert on the exact
//! RFB message that came out the other, rather than observing a live desktop.

use std::sync::{Arc, Mutex};

use solstice_backend::Rect;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::auth::vnc_auth_response;
use crate::pixel::PixelFormat;
use crate::protocol::{client_msg, encoding, security, server_msg, RectHeader, Result, RfbError};

/// A client message the mock saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientMessage {
    /// `SetPixelFormat`.
    SetPixelFormat(PixelFormat),
    /// `SetEncodings`, in the order requested.
    SetEncodings(Vec<i32>),
    /// `FramebufferUpdateRequest`.
    UpdateRequest {
        /// Whether the client asked for an incremental update.
        incremental: bool,
        /// The region requested.
        rect: Rect,
    },
    /// `KeyEvent` -- the keysym path.
    KeyEvent {
        /// True for a press.
        down: bool,
        /// X11 keysym.
        keysym: u32,
    },
    /// QEMU Extended Key Event -- the scancode path.
    QemuKeyEvent {
        /// True for a press.
        down: bool,
        /// X11 keysym, possibly zero.
        keysym: u32,
        /// XT make scancode.
        keycode: u32,
    },
    /// `PointerEvent`.
    PointerEvent {
        /// Button mask.
        mask: u8,
        /// X.
        x: u16,
        /// Y.
        y: u16,
    },
    /// `ClientCutText`.
    CutText(String),
    /// `EnableContinuousUpdates`.
    EnableContinuousUpdates(bool),
    /// `ClientFence`.
    ClientFence,
    /// `SetDesktopSize`.
    SetDesktopSize {
        /// Requested width.
        width: u16,
        /// Requested height.
        height: u16,
    },
}

/// How the mock should behave.
#[derive(Clone, Debug)]
pub struct MockConfig {
    /// Minor version to announce: 3 or 8.
    pub minor_version: u8,
    /// Security types to offer.
    pub security_types: Vec<u8>,
    /// Password, when `VNC Authentication` is offered.
    pub password: Option<String>,
    /// Framebuffer width.
    pub width: u16,
    /// Framebuffer height.
    pub height: u16,
    /// Pixel format to announce in `ServerInit`.
    pub format: PixelFormat,
    /// Whether to acknowledge pseudo-encoding -258.
    pub offer_qemu_extended_key: bool,
    /// Whether to acknowledge pseudo-encodings -312 and -313.
    pub offer_flow_control: bool,
    /// Whether to acknowledge pseudo-encoding -308.
    pub offer_extended_desktop_size: bool,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            minor_version: 8,
            security_types: vec![security::NONE],
            password: None,
            width: 64,
            height: 64,
            format: PixelFormat::BGRA,
            offer_qemu_extended_key: false,
            offer_flow_control: false,
            offer_extended_desktop_size: false,
        }
    }
}

/// An update for the mock to push.
#[derive(Clone, Debug)]
pub enum MockUpdate {
    /// A solid-colour Raw rectangle.
    Fill {
        /// Where.
        rect: Rect,
        /// BGRA colour.
        colour: [u8; 4],
    },
    /// A DesktopSize pseudo-rectangle.
    Resize {
        /// New width.
        width: u16,
        /// New height.
        height: u16,
    },
}

/// The recording mock.
pub struct MockServer {
    config: MockConfig,
    recorded: Arc<Mutex<Vec<ClientMessage>>>,
}

impl MockServer {
    /// Build one.
    pub fn new(config: MockConfig) -> Self {
        Self {
            config,
            recorded: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// A handle to everything the client has sent so far.
    pub fn recorded(&self) -> Arc<Mutex<Vec<ClientMessage>>> {
        self.recorded.clone()
    }

    /// Serve one connection until the client disconnects.
    pub async fn serve<S>(&self, stream: S, mut updates: mpsc::Receiver<MockUpdate>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        self.handshake(&mut reader, &mut writer).await?;

        // Strict ordering: the first two messages must be SetPixelFormat and
        // SetEncodings, in that order. A client that pipelines them the other
        // way round is wrong, and a lenient mock would hide that.
        let first = read_client_message(&mut reader).await?;
        if !matches!(first, ClientMessage::SetPixelFormat(_)) {
            return Err(RfbError::Protocol(format!(
                "expected SetPixelFormat, got {first:?}"
            )));
        }
        self.record(first);
        let second = read_client_message(&mut reader).await?;
        let ClientMessage::SetEncodings(encodings) = &second else {
            return Err(RfbError::Protocol(format!(
                "expected SetEncodings, got {second:?}"
            )));
        };
        let pseudo_reply = self.pseudo_encodings(encodings);
        self.record(second);

        // Answer the first update request with the acknowledged
        // pseudo-encodings, which is how a real server reports its features.
        let recorded = self.recorded.clone();
        let reader_task = tokio::spawn(async move {
            while let Ok(message) = read_client_message(&mut reader).await {
                recorded.lock().expect("record lock").push(message);
            }
        });

        if !pseudo_reply.is_empty() {
            let mut frame = vec![server_msg::FRAMEBUFFER_UPDATE, 0];
            frame.extend_from_slice(&(pseudo_reply.len() as u16).to_be_bytes());
            for e in &pseudo_reply {
                frame.extend_from_slice(
                    &RectHeader {
                        x: 0,
                        y: 0,
                        width: 0,
                        height: 0,
                        encoding: *e,
                    }
                    .to_bytes(),
                );
            }
            writer.write_all(&frame).await?;
            writer.flush().await?;
        }

        while let Some(update) = updates.recv().await {
            let frame = match update {
                MockUpdate::Fill { rect, colour } => {
                    let mut frame = vec![server_msg::FRAMEBUFFER_UPDATE, 0];
                    frame.extend_from_slice(&1u16.to_be_bytes());
                    frame.extend_from_slice(
                        &RectHeader {
                            x: rect.x as u16,
                            y: rect.y as u16,
                            width: rect.width as u16,
                            height: rect.height as u16,
                            encoding: encoding::RAW,
                        }
                        .to_bytes(),
                    );
                    let pixel = self.encode_pixel(colour);
                    for _ in 0..rect.width as usize * rect.height as usize {
                        frame.extend_from_slice(&pixel);
                    }
                    frame
                }
                MockUpdate::Resize { width, height } => {
                    let mut frame = vec![server_msg::FRAMEBUFFER_UPDATE, 0];
                    frame.extend_from_slice(&1u16.to_be_bytes());
                    frame.extend_from_slice(
                        &RectHeader {
                            x: 0,
                            y: 0,
                            width,
                            height,
                            encoding: encoding::PSEUDO_DESKTOP_SIZE,
                        }
                        .to_bytes(),
                    );
                    frame
                }
            };
            writer.write_all(&frame).await?;
            writer.flush().await?;
        }

        drop(writer);
        let _ = reader_task.await;
        Ok(())
    }

    fn encode_pixel(&self, bgra: [u8; 4]) -> Vec<u8> {
        if self.config.format.is_native_bgra() {
            return bgra.to_vec();
        }
        // Only the handful of formats the tests use need re-encoding.
        let f = &self.config.format;
        let value = ((bgra[2] as u32) << f.red_shift)
            | ((bgra[1] as u32) << f.green_shift)
            | ((bgra[0] as u32) << f.blue_shift);
        let bytes = if f.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        bytes[..f.bytes_per_pixel()].to_vec()
    }

    fn pseudo_encodings(&self, requested: &[i32]) -> Vec<i32> {
        let mut out = Vec::new();
        let mut offer = |e: i32, enabled: bool| {
            if enabled && requested.contains(&e) {
                out.push(e);
            }
        };
        offer(
            encoding::PSEUDO_QEMU_EXTENDED_KEY,
            self.config.offer_qemu_extended_key,
        );
        offer(
            encoding::PSEUDO_CONTINUOUS_UPDATES,
            self.config.offer_flow_control,
        );
        offer(encoding::PSEUDO_FENCE, self.config.offer_flow_control);
        out
    }

    fn record(&self, message: ClientMessage) {
        self.recorded.lock().expect("record lock").push(message);
    }

    async fn handshake<R, W>(&self, reader: &mut R, writer: &mut W) -> Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        writer
            .write_all(format!("RFB 003.{:03}\n", self.config.minor_version).as_bytes())
            .await?;
        writer.flush().await?;
        let mut client_version = [0u8; 12];
        reader.read_exact(&mut client_version).await?;

        let chosen = if self.config.minor_version >= 7 {
            let mut list = vec![self.config.security_types.len() as u8];
            list.extend_from_slice(&self.config.security_types);
            writer.write_all(&list).await?;
            writer.flush().await?;
            let mut chosen = [0u8; 1];
            reader.read_exact(&mut chosen).await?;
            if !self.config.security_types.contains(&chosen[0]) {
                return Err(RfbError::Auth(format!(
                    "client chose unoffered type {}",
                    chosen[0]
                )));
            }
            chosen[0]
        } else {
            let kind = self.config.security_types[0];
            writer.write_all(&(kind as u32).to_be_bytes()).await?;
            writer.flush().await?;
            kind
        };

        if chosen == security::VNC_AUTH {
            let challenge = [0x5Au8; 16];
            writer.write_all(&challenge).await?;
            writer.flush().await?;
            let mut response = [0u8; 16];
            reader.read_exact(&mut response).await?;
            let password = self.config.password.clone().unwrap_or_default();
            if response != vnc_auth_response(&password, &challenge) {
                writer.write_all(&1u32.to_be_bytes()).await?;
                if self.config.minor_version >= 8 {
                    writer.write_all(&13u32.to_be_bytes()).await?;
                    writer.write_all(b"bad password!").await?;
                }
                writer.flush().await?;
                return Err(RfbError::Auth("client failed VNC authentication".into()));
            }
        }
        writer.write_all(&0u32.to_be_bytes()).await?;
        writer.flush().await?;

        let mut shared = [0u8; 1];
        reader.read_exact(&mut shared).await?;

        let mut init = self.config.width.to_be_bytes().to_vec();
        init.extend_from_slice(&self.config.height.to_be_bytes());
        init.extend_from_slice(&self.config.format.to_bytes());
        let name = b"mock";
        init.extend_from_slice(&(name.len() as u32).to_be_bytes());
        init.extend_from_slice(name);
        writer.write_all(&init).await?;
        writer.flush().await?;
        Ok(())
    }
}

/// Read one client message.
pub async fn read_client_message<R: AsyncRead + Unpin>(reader: &mut R) -> Result<ClientMessage> {
    let mut kind = [0u8; 1];
    reader.read_exact(&mut kind).await?;
    Ok(match kind[0] {
        client_msg::SET_PIXEL_FORMAT => {
            let mut body = [0u8; 19];
            reader.read_exact(&mut body).await?;
            ClientMessage::SetPixelFormat(PixelFormat::parse(
                body[3..19].try_into().expect("19 - 3 == 16"),
            )?)
        }
        client_msg::SET_ENCODINGS => {
            let mut head = [0u8; 3];
            reader.read_exact(&mut head).await?;
            let count = u16::from_be_bytes([head[1], head[2]]) as usize;
            let mut body = vec![0u8; count * 4];
            reader.read_exact(&mut body).await?;
            ClientMessage::SetEncodings(
                body.chunks_exact(4)
                    .map(|c| i32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                    .collect(),
            )
        }
        client_msg::FRAMEBUFFER_UPDATE_REQUEST => {
            let mut body = [0u8; 9];
            reader.read_exact(&mut body).await?;
            ClientMessage::UpdateRequest {
                incremental: body[0] != 0,
                rect: Rect {
                    x: u16::from_be_bytes([body[1], body[2]]) as u32,
                    y: u16::from_be_bytes([body[3], body[4]]) as u32,
                    width: u16::from_be_bytes([body[5], body[6]]) as u32,
                    height: u16::from_be_bytes([body[7], body[8]]) as u32,
                },
            }
        }
        client_msg::KEY_EVENT => {
            let mut body = [0u8; 7];
            reader.read_exact(&mut body).await?;
            ClientMessage::KeyEvent {
                down: body[0] != 0,
                keysym: u32::from_be_bytes([body[3], body[4], body[5], body[6]]),
            }
        }
        client_msg::POINTER_EVENT => {
            let mut body = [0u8; 5];
            reader.read_exact(&mut body).await?;
            ClientMessage::PointerEvent {
                mask: body[0],
                x: u16::from_be_bytes([body[1], body[2]]),
                y: u16::from_be_bytes([body[3], body[4]]),
            }
        }
        client_msg::CLIENT_CUT_TEXT => {
            let mut head = [0u8; 7];
            reader.read_exact(&mut head).await?;
            let len = u32::from_be_bytes([head[3], head[4], head[5], head[6]]).min(1 << 20);
            let mut body = vec![0u8; len as usize];
            reader.read_exact(&mut body).await?;
            ClientMessage::CutText(String::from_utf8_lossy(&body).into_owned())
        }
        client_msg::ENABLE_CONTINUOUS_UPDATES => {
            let mut body = [0u8; 9];
            reader.read_exact(&mut body).await?;
            ClientMessage::EnableContinuousUpdates(body[0] != 0)
        }
        client_msg::CLIENT_FENCE => {
            let mut head = [0u8; 8];
            reader.read_exact(&mut head).await?;
            let mut payload = vec![0u8; head[7] as usize];
            reader.read_exact(&mut payload).await?;
            ClientMessage::ClientFence
        }
        251 => {
            let mut head = [0u8; 7];
            reader.read_exact(&mut head).await?;
            let width = u16::from_be_bytes([head[1], head[2]]);
            let height = u16::from_be_bytes([head[3], head[4]]);
            let mut screens = vec![0u8; head[5] as usize * 16];
            reader.read_exact(&mut screens).await?;
            ClientMessage::SetDesktopSize { width, height }
        }
        client_msg::QEMU => {
            let mut body = [0u8; 11];
            reader.read_exact(&mut body).await?;
            ClientMessage::QemuKeyEvent {
                down: u16::from_be_bytes([body[1], body[2]]) != 0,
                keysym: u32::from_be_bytes([body[3], body[4], body[5], body[6]]),
                keycode: u32::from_be_bytes([body[7], body[8], body[9], body[10]]),
            }
        }
        other => {
            return Err(RfbError::Protocol(format!(
                "mock: unknown client message {other}"
            )))
        }
    })
}
