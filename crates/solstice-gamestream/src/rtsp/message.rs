//! The RTSP message parser.
//!
//! This dialect is RTSP-*shaped* but not RFC 2326. `moonlight-common-c` ships
//! its own parser and carries a comment about a *"Hacked CSeq attribute due to
//! RTSP parser bug"* (`RtspConnection.c:77`), so this is written against the
//! observed bytes rather than the RFC:
//!
//! * header names are matched case-insensitively, because the client is not
//!   consistent about `Content-Length` vs `Content-length`;
//! * a message with no `Content-Length` has no body, rather than a body that
//!   runs to end-of-connection;
//! * an unparseable request is an error that closes the connection, never a
//!   best-effort guess.
//!
//! It is a fuzz target (`fuzz/fuzz_targets/rtsp_message.rs`).

use crate::wire::WireError;

/// Largest message this parser will assemble, headers and body together.
///
/// A cap matters because the socket is reachable by any paired client and the
/// parser buffers until a message is complete (`docs/security.md` §5.3).
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;

/// A parsed request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// `OPTIONS`, `DESCRIBE`, `SETUP`, `ANNOUNCE`, `PLAY`, `TEARDOWN`.
    pub method: String,
    /// The request target, e.g. `rtsp://host:48010` or `streamid=video/0/0`.
    pub uri: String,
    /// Header name/value pairs, in order, names as received.
    pub headers: Vec<(String, String)>,
    /// The body, empty when there is no `Content-Length`.
    pub body: Vec<u8>,
}

impl Request {
    /// Look a header up case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The `CSeq`, which every response must echo.
    pub fn cseq(&self) -> Option<u32> {
        self.header("CSeq").and_then(|v| v.trim().parse().ok())
    }

    /// The `streamid=` part of a SETUP target, e.g. `video/0/0`.
    pub fn stream_id(&self) -> Option<&str> {
        self.uri
            .split("streamid=")
            .nth(1)
            .map(|s| s.split('/').next().unwrap_or(s))
    }

    /// The full `streamid=` value including its indices.
    pub fn stream_id_full(&self) -> Option<&str> {
        self.uri.split("streamid=").nth(1)
    }
}

/// Parse one request from the front of `buf`.
///
/// Returns the request and how many bytes it consumed, or `Ok(None)` if the
/// buffer does not yet hold a complete message.
pub fn parse_request(buf: &[u8]) -> Result<Option<(Request, usize)>, WireError> {
    if buf.len() > MAX_MESSAGE_LEN {
        return Err(WireError::LengthOverrun {
            claimed: buf.len(),
            available: MAX_MESSAGE_LEN,
        });
    }
    let Some(header_end) = find_header_end(buf) else {
        return Ok(None);
    };
    let head = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| WireError::InvalidUtf8("RTSP headers"))?;

    let mut lines = head.split("\r\n").filter(|l| !l.is_empty());
    let request_line = lines
        .next()
        .ok_or(WireError::InvalidUtf8("RTSP request line"))?;
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(uri), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(WireError::InvalidField {
            field: "RTSP request line",
            value: 0,
        });
    };
    if !version.starts_with("RTSP/") {
        return Err(WireError::InvalidField {
            field: "RTSP version",
            value: 0,
        });
    }

    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(WireError::InvalidField {
                field: "RTSP header",
                value: 0,
            });
        };
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }

    let content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
        .map(|(_, v)| v.trim().parse::<usize>())
        .transpose()
        .map_err(|_| WireError::InvalidField {
            field: "Content-Length",
            value: 0,
        })?
        .unwrap_or(0);
    if content_length > MAX_MESSAGE_LEN {
        return Err(WireError::LengthOverrun {
            claimed: content_length,
            available: MAX_MESSAGE_LEN,
        });
    }
    let total = header_end + content_length;
    if buf.len() < total {
        return Ok(None);
    }

    Ok(Some((
        Request {
            method: method.to_owned(),
            uri: uri.to_owned(),
            headers,
            body: buf[header_end..total].to_vec(),
        },
        total,
    )))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// A response under construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Reason phrase.
    pub reason: String,
    /// Headers, emitted in order after `CSeq`.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
    /// The sequence number to echo.
    pub cseq: u32,
}

impl Response {
    /// A `200 OK` echoing `cseq`.
    pub fn ok(cseq: u32) -> Self {
        Self {
            status: 200,
            reason: "OK".into(),
            headers: Vec::new(),
            body: Vec::new(),
            cseq,
        }
    }

    /// An error response.
    pub fn error(cseq: u32, status: u16, reason: &str) -> Self {
        Self {
            status,
            reason: reason.into(),
            headers: Vec::new(),
            body: Vec::new(),
            cseq,
        }
    }

    /// Add a header.
    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_owned(), value.into()));
        self
    }

    /// Set the body. `Content-Length` is emitted automatically.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Serialise.
    ///
    /// `CSeq` goes first: `moonlight-common-c`'s parser is sensitive to where
    /// it appears, which is the "hacked CSeq" comment's subject.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = format!(
            "RTSP/1.0 {} {}\r\nCSeq: {}\r\n",
            self.status, self.reason, self.cseq
        );
        for (name, value) in &self.headers {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
        if !self.body.is_empty() {
            out.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPTIONS: &[u8] =
        b"OPTIONS rtsp://10.0.0.1:48010 RTSP/1.0\r\nCSeq: 1\r\nX-GS-ClientVersion: 14\r\n\r\n";

    #[test]
    fn parses_a_request_with_no_body() {
        let (req, used) = parse_request(OPTIONS).unwrap().unwrap();
        assert_eq!(used, OPTIONS.len());
        assert_eq!(req.method, "OPTIONS");
        assert_eq!(req.uri, "rtsp://10.0.0.1:48010");
        assert_eq!(req.cseq(), Some(1));
        assert_eq!(req.header("x-gs-clientversion"), Some("14"));
        assert!(req.body.is_empty());
    }

    #[test]
    fn parses_a_request_with_a_body() {
        let msg = b"ANNOUNCE streamid=control/13/0 RTSP/1.0\r\nCSeq: 5\r\nContent-length: 10\r\n\r\nv=0\r\na=b\r\n";
        let (req, used) = parse_request(msg).unwrap().unwrap();
        assert_eq!(used, msg.len());
        assert_eq!(req.body, b"v=0\r\na=b\r\n".to_vec());
        // Case-insensitive, because the client is not consistent.
        assert_eq!(req.header("Content-Length"), Some("10"));
    }

    #[test]
    fn returns_none_until_the_message_is_complete() {
        for n in 0..OPTIONS.len() {
            assert_eq!(parse_request(&OPTIONS[..n]).unwrap(), None, "prefix {n}");
        }
        assert!(parse_request(OPTIONS).unwrap().is_some());
    }

    #[test]
    fn waits_for_a_body_that_has_not_arrived() {
        let msg = b"ANNOUNCE x RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 20\r\n\r\nshort";
        assert_eq!(parse_request(msg).unwrap(), None);
    }

    #[test]
    fn pipelined_requests_are_consumed_one_at_a_time() {
        let mut buf = OPTIONS.to_vec();
        buf.extend_from_slice(b"PLAY rtsp://h RTSP/1.0\r\nCSeq: 2\r\n\r\n");
        let (first, used) = parse_request(&buf).unwrap().unwrap();
        assert_eq!(first.method, "OPTIONS");
        let (second, _) = parse_request(&buf[used..]).unwrap().unwrap();
        assert_eq!(second.method, "PLAY");
        assert_eq!(second.cseq(), Some(2));
    }

    #[test]
    fn stream_ids_are_extracted() {
        let msg = b"SETUP streamid=video/0/0 RTSP/1.0\r\nCSeq: 3\r\n\r\n";
        let (req, _) = parse_request(msg).unwrap().unwrap();
        assert_eq!(req.stream_id(), Some("video"));
        assert_eq!(req.stream_id_full(), Some("video/0/0"));

        let msg = b"SETUP streamid=control/13/0 RTSP/1.0\r\nCSeq: 4\r\n\r\n";
        let (req, _) = parse_request(msg).unwrap().unwrap();
        assert_eq!(req.stream_id(), Some("control"));
    }

    #[test]
    fn malformed_requests_are_errors() {
        assert!(parse_request(b"GARBAGE\r\n\r\n").is_err());
        assert!(parse_request(b"OPTIONS rtsp://h HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_request(b"OPTIONS rtsp://h RTSP/1.0\r\nnocolon\r\n\r\n").is_err());
        assert!(
            parse_request(b"OPTIONS rtsp://h RTSP/1.0\r\nContent-Length: abc\r\n\r\n").is_err()
        );
    }

    #[test]
    fn an_absurd_content_length_is_refused_rather_than_buffered() {
        let msg = b"ANNOUNCE x RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 999999999\r\n\r\n";
        assert!(parse_request(msg).is_err());
    }

    #[test]
    fn response_puts_cseq_first() {
        let bytes = Response::ok(7)
            .header("Session", "DEADBEEF;timeout=90")
            .header("Transport", "server_port=47998")
            .body(b"sdp".to_vec())
            .to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("RTSP/1.0 200 OK\r\nCSeq: 7\r\n"), "{text}");
        assert!(text.contains("Content-Length: 3\r\n"));
        assert!(text.ends_with("\r\n\r\nsdp"));
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0xDEADBEEFu32;
        for _ in 0..2000 {
            let len = (state % 128) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                buf.push((state >> 16) as u8);
            }
            let _ = parse_request(&buf);
        }
    }
}
