//! The RTSP exchange as a pure state machine: requests in, responses out.
//!
//! No I/O, so the recorded-transcript tests in `docs/testing.md` §7 can replay
//! a real Moonlight session against it without a socket.

use super::message::{Request, Response};
use super::sdp::{self, Limits, StreamConfig};

/// The UDP ports advertised in `SETUP` responses.
///
/// The client parses `server_port=` out of the `Transport` header
/// (`RtspConnection.c:717-745`), so a host may relocate its ports per session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamPorts {
    /// Video.
    pub video: u16,
    /// Audio.
    pub audio: u16,
    /// Control (ENet).
    pub control: u16,
}

impl Default for StreamPorts {
    fn default() -> Self {
        Self {
            video: 47998,
            audio: 48000,
            control: 47999,
        }
    }
}

/// The per-launch values the negotiation has to hand back to the client.
///
/// All three are minted at `/launch` and all three reach the client only
/// through RTSP, which is why they travel together.
#[derive(Clone, Debug)]
pub struct SessionParams {
    /// Echoed as the RTSP `Session:` attribute on the audio `SETUP`.
    pub session_id: String,
    /// `X-SS-Connect-Data` on the control `SETUP`: the client sends it back
    /// as ENet connect data, binding its peer to this session.
    pub control_connect_data: u32,
    /// `X-SS-Ping-Payload` on the audio and video `SETUP`s: the client puts
    /// it in its UDP pings, which is how the host learns where to send.
    pub ping_payload: [u8; 16],
}

/// What the caller should do after handling a request.
#[derive(Debug)]
pub enum RtspOutcome {
    /// Send this response and keep going.
    Reply(Response),
    /// Send this response and start streaming with this configuration.
    Play(Response, Box<StreamConfig>),
    /// Send this response, then close the connection.
    Close(Response),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    Start,
    Described,
    SetUp,
    Announced,
    Playing,
}

/// The session negotiation.
#[derive(Debug)]
pub struct RtspServer {
    ports: StreamPorts,
    limits: Limits,
    supported_encryption: u32,
    required_encryption: u32,
    session: SessionParams,
    stage: Stage,
    streams_set_up: u8,
    config: Option<StreamConfig>,
}

impl RtspServer {
    /// Build one for a launch session.
    pub fn new(
        ports: StreamPorts,
        limits: Limits,
        supported_encryption: u32,
        required_encryption: u32,
        session: SessionParams,
    ) -> Self {
        Self {
            ports,
            limits,
            supported_encryption,
            required_encryption,
            session,
            stage: Stage::Start,
            streams_set_up: 0,
            config: None,
        }
    }

    /// The negotiated configuration, once ANNOUNCE has been accepted.
    pub fn config(&self) -> Option<&StreamConfig> {
        self.config.as_ref()
    }

    /// Whether PLAY has been handled.
    pub fn is_playing(&self) -> bool {
        self.stage == Stage::Playing
    }

    /// Handle one request.
    pub fn handle(&mut self, request: &Request) -> RtspOutcome {
        let cseq = request.cseq().unwrap_or(0);
        match request.method.as_str() {
            "OPTIONS" => RtspOutcome::Reply(Response::ok(cseq).header(
                "Public",
                "OPTIONS, DESCRIBE, SETUP, PLAY, ANNOUNCE, TEARDOWN",
            )),
            "DESCRIBE" => {
                self.stage = self.stage.max(Stage::Described);
                let body = sdp::describe_body(self.supported_encryption, self.required_encryption);
                RtspOutcome::Reply(
                    Response::ok(cseq)
                        .header("Content-Type", "application/sdp")
                        .body(body.into_bytes()),
                )
            }
            "SETUP" => self.setup(request, cseq),
            "ANNOUNCE" => self.announce(request, cseq),
            "PLAY" => {
                if self.stage < Stage::Announced {
                    return RtspOutcome::Close(Response::error(
                        cseq,
                        455,
                        "Method Not Valid In This State",
                    ));
                }
                self.stage = Stage::Playing;
                let config = self.config.clone().expect("announced implies a config");
                RtspOutcome::Play(Response::ok(cseq), Box::new(config))
            }
            "TEARDOWN" => RtspOutcome::Close(Response::ok(cseq)),
            _ => RtspOutcome::Reply(Response::error(cseq, 501, "Not Implemented")),
        }
    }

    fn setup(&mut self, request: &Request, cseq: u32) -> RtspOutcome {
        if self.stage < Stage::Described {
            return RtspOutcome::Close(Response::error(
                cseq,
                455,
                "Method Not Valid In This State",
            ));
        }
        let Some(stream) = request.stream_id() else {
            return RtspOutcome::Close(Response::error(cseq, 400, "Bad Request"));
        };
        let port = match stream {
            "video" => self.ports.video,
            "audio" => self.ports.audio,
            "control" => self.ports.control,
            _ => return RtspOutcome::Close(Response::error(cseq, 404, "Stream Not Found")),
        };
        self.streams_set_up += 1;
        if self.streams_set_up >= 3 {
            self.stage = self.stage.max(Stage::SetUp);
        }
        let mut response = Response::ok(cseq).header("Transport", format!("server_port={port}"));
        // The client requires a Session attribute on the audio SETUP.
        if stream == "audio" {
            response = response.header(
                "Session",
                format!("{};timeout = 90", self.session.session_id),
            );
        }
        // Sunshine's `X-SS-Ping-Payload` extension
        // (`RtspConnection.c:1202-1207`, `:1267-1272`). Without it the client
        // falls back to the four-byte legacy `"PING"`, which this host refuses
        // on purpose as unauthenticated (`docs/security.md` §2.3) -- so the
        // host would never learn the client's address and would send nothing
        // at all. That is exactly what a real Moonlight saw here.
        if stream == "audio" || stream == "video" {
            response = response.header(
                "X-SS-Ping-Payload",
                String::from_utf8_lossy(&self.session.ping_payload).into_owned(),
            );
        }
        // Sunshine's `X-SS-Connect-Data` extension, read at
        // `RtspConnection.c:1309-1316` with `strtoul(.., 0)` and defaulted to
        // zero when the header is absent. Without it the client connects with
        // connect data 0, the host refuses the peer as belonging to no
        // session, and the stream dies at "control stream establishment" --
        // which is what a real Moonlight did here before this line existed.
        if stream == "control" {
            response = response.header(
                "X-SS-Connect-Data",
                self.session.control_connect_data.to_string(),
            );
        }
        RtspOutcome::Reply(response)
    }

    fn announce(&mut self, request: &Request, cseq: u32) -> RtspOutcome {
        if self.stage < Stage::SetUp {
            return RtspOutcome::Close(Response::error(
                cseq,
                455,
                "Method Not Valid In This State",
            ));
        }
        match sdp::parse_announce(
            &request.body,
            request.header("Host"),
            &self.limits,
            self.required_encryption,
        ) {
            Ok(config) => {
                self.config = Some(config);
                self.stage = Stage::Announced;
                RtspOutcome::Reply(Response::ok(cseq))
            }
            Err(e) => {
                tracing::warn!(error = %e, "rejecting ANNOUNCE");
                // A bad ANNOUNCE ends the negotiation: there is no partially
                // configured session worth keeping.
                RtspOutcome::Close(Response::error(cseq, 400, "Bad Request"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::message::parse_request;
    use super::super::sdp::encryption;
    use super::*;

    fn server() -> RtspServer {
        RtspServer::new(
            StreamPorts::default(),
            Limits::default(),
            encryption::ALL,
            encryption::ALL,
            SessionParams {
                session_id: "DEADBEEFCAFE".into(),
                control_connect_data: 0xC0FF_EE42,
                ping_payload: *b"0123456789abcdef",
            },
        )
    }

    fn req(text: &str) -> Request {
        parse_request(text.as_bytes()).unwrap().unwrap().0
    }

    fn announce_body() -> String {
        "v=0\r\n\
         s=NVIDIA Streaming Client\r\n\
         a=x-nv-video[0].clientViewportWd:1280\r\n\
         a=x-nv-video[0].clientViewportHt:720\r\n\
         a=x-nv-video[0].maxFPS:60\r\n\
         a=x-nv-video[0].packetSize:1392\r\n\
         a=x-nv-general.useReliableUdp:13\r\n\
         a=x-ss-general.encryptionEnabled:7\r\n"
            .to_owned()
    }

    fn announce_request() -> Request {
        let body = announce_body();
        req(&format!(
            "ANNOUNCE streamid=control/13/0 RTSP/1.0\r\nCSeq: 5\r\nHost: 10.0.0.5\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        ))
    }

    /// The full sequence `RtspConnection.c:944-1410` performs.
    #[test]
    fn the_documented_sequence_negotiates_a_session() {
        let mut s = server();

        let RtspOutcome::Reply(r) =
            s.handle(&req("OPTIONS rtsp://h:48010 RTSP/1.0\r\nCSeq: 1\r\n\r\n"))
        else {
            panic!("OPTIONS should reply")
        };
        assert_eq!(r.status, 200);

        let RtspOutcome::Reply(r) =
            s.handle(&req("DESCRIBE rtsp://h:48010 RTSP/1.0\r\nCSeq: 2\r\n\r\n"))
        else {
            panic!("DESCRIBE should reply")
        };
        let sdp = String::from_utf8(r.body).unwrap();
        assert!(sdp.contains("encryptionSupported:7"));

        for (cseq, stream, port) in [
            (3, "audio/0/0", 48000),
            (4, "video/0/0", 47998),
            (5, "control/13/0", 47999),
        ] {
            let RtspOutcome::Reply(r) = s.handle(&req(&format!(
                "SETUP streamid={stream} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
            ))) else {
                panic!("SETUP should reply")
            };
            let transport = r.headers.iter().find(|(k, _)| k == "Transport").unwrap();
            assert_eq!(transport.1, format!("server_port={port}"));
            // Only the audio SETUP carries the Session attribute the client
            // requires.
            let has_session = r.headers.iter().any(|(k, _)| k == "Session");
            assert_eq!(has_session, stream.starts_with("audio"), "{stream}");
        }

        let RtspOutcome::Reply(r) = s.handle(&announce_request()) else {
            panic!("ANNOUNCE should reply")
        };
        assert_eq!(r.status, 200);
        assert_eq!(s.config().unwrap().width, 1280);

        let RtspOutcome::Play(r, config) =
            s.handle(&req("PLAY rtsp://h RTSP/1.0\r\nCSeq: 6\r\n\r\n"))
        else {
            panic!("PLAY should start the stream")
        };
        assert_eq!(r.status, 200);
        assert_eq!(config.fps, 60);
        assert!(s.is_playing());
    }

    #[test]
    fn play_before_announce_is_refused() {
        let mut s = server();
        let RtspOutcome::Close(r) = s.handle(&req("PLAY rtsp://h RTSP/1.0\r\nCSeq: 1\r\n\r\n"))
        else {
            panic!("PLAY out of order should close")
        };
        assert_eq!(r.status, 455);
    }

    #[test]
    fn setup_before_describe_is_refused() {
        let mut s = server();
        let RtspOutcome::Close(r) =
            s.handle(&req("SETUP streamid=video/0/0 RTSP/1.0\r\nCSeq: 1\r\n\r\n"))
        else {
            panic!("SETUP out of order should close")
        };
        assert_eq!(r.status, 455);
    }

    #[test]
    fn announce_before_setup_is_refused() {
        let mut s = server();
        s.handle(&req("DESCRIBE rtsp://h RTSP/1.0\r\nCSeq: 1\r\n\r\n"));
        let RtspOutcome::Close(r) = s.handle(&announce_request()) else {
            panic!("ANNOUNCE out of order should close")
        };
        assert_eq!(r.status, 455);
    }

    #[test]
    fn an_unknown_stream_id_is_refused() {
        let mut s = server();
        s.handle(&req("DESCRIBE rtsp://h RTSP/1.0\r\nCSeq: 1\r\n\r\n"));
        let RtspOutcome::Close(r) = s.handle(&req(
            "SETUP streamid=telemetry/9/0 RTSP/1.0\r\nCSeq: 2\r\n\r\n",
        )) else {
            panic!("unknown stream should close")
        };
        assert_eq!(r.status, 404);
    }

    #[test]
    fn a_bad_announce_ends_the_negotiation() {
        let mut s = server();
        s.handle(&req("DESCRIBE rtsp://h RTSP/1.0\r\nCSeq: 1\r\n\r\n"));
        for (i, stream) in ["audio/0/0", "video/0/0", "control/13/0"]
            .iter()
            .enumerate()
        {
            s.handle(&req(&format!(
                "SETUP streamid={stream} RTSP/1.0\r\nCSeq: {}\r\n\r\n",
                i + 2
            )));
        }
        // encryptionEnabled omitted entirely: the client refuses what the host
        // requires.
        let body = "v=0\r\ns=c\r\na=x-nv-video[0].maxFPS:60\r\n";
        let r = s.handle(&req(&format!(
            "ANNOUNCE streamid=control/13/0 RTSP/1.0\r\nCSeq: 5\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )));
        let RtspOutcome::Close(r) = r else {
            panic!("bad ANNOUNCE should close")
        };
        assert_eq!(r.status, 400);
        assert!(s.config().is_none());
    }

    #[test]
    fn unknown_methods_get_501_without_ending_the_session() {
        let mut s = server();
        let RtspOutcome::Reply(r) =
            s.handle(&req("GET_PARAMETER rtsp://h RTSP/1.0\r\nCSeq: 1\r\n\r\n"))
        else {
            panic!("unknown method should reply")
        };
        assert_eq!(r.status, 501);
    }
}
