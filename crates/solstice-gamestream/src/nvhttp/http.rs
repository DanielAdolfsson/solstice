//! A minimal HTTP/1.1 server surface, deliberately not a web framework.
//!
//! NVHTTP is a handful of `GET`s returning XML. Sunshine's worst CVEs are in
//! its *config UI* rather than its protocol -- CSRF to command injection,
//! clickjacking -- so `docs/security.md` §3.5 says not to build one. This
//! module exists so that Solstice's HTTP surface is only what the protocol
//! needs: no cookies, no sessions, no POST bodies, no file serving.

use std::collections::BTreeMap;

/// Largest request head accepted.
pub const MAX_REQUEST_LEN: usize = 16 * 1024;

/// A parsed request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    /// Method, uppercased as received.
    pub method: String,
    /// Path with the query removed.
    pub path: String,
    /// Decoded query parameters. Later duplicates win, matching a naive
    /// server's behaviour so the two cannot disagree about which value applies.
    pub query: BTreeMap<String, String>,
    /// Headers, names lowercased.
    pub headers: BTreeMap<String, String>,
}

impl HttpRequest {
    /// A query parameter.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(|s| s.as_str())
    }

    /// A query parameter parsed as a number.
    pub fn param_num<T: std::str::FromStr>(&self, name: &str) -> Option<T> {
        self.param(name).and_then(|v| v.parse().ok())
    }

    /// A query parameter decoded from hex.
    pub fn param_hex(&self, name: &str) -> Option<Vec<u8>> {
        self.param(name).and_then(|v| hex::decode(v).ok())
    }
}

/// Parse a request head.
///
/// Returns `Ok(None)` while the head is incomplete. A request with a body is
/// rejected: nothing in NVHTTP has one.
pub fn parse_request(buf: &[u8]) -> Result<Option<(HttpRequest, usize)>, &'static str> {
    if buf.len() > MAX_REQUEST_LEN {
        return Err("request too long");
    }
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) else {
        return Ok(None);
    };
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| "request is not UTF-8")?;
    let mut lines = head.split("\r\n").filter(|l| !l.is_empty());
    let request_line = lines.next().ok_or("empty request")?;
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err("malformed request line");
    };
    if !version.starts_with("HTTP/1.") {
        return Err("unsupported HTTP version");
    }

    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("malformed header")?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    if headers.contains_key("content-length") || headers.contains_key("transfer-encoding") {
        return Err("request bodies are not accepted");
    }

    let (path, query_string) = target.split_once('?').unwrap_or((target, ""));
    Ok(Some((
        HttpRequest {
            method: method.to_ascii_uppercase(),
            path: percent_decode(path),
            query: parse_query(query_string),
            headers,
        },
        end,
    )))
}

/// Split and percent-decode a query string.
pub fn parse_query(query: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(percent_decode(k), percent_decode(v));
    }
    out
}

/// Percent-decode, leaving invalid escapes as literal text rather than
/// guessing.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(byte) => {
                    out.push(byte);
                    i += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A response to write back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    /// The HTTP status. 200 for anything a handler answered, whatever the
    /// outcome, as Sunshine does: moonlight-qt's HTTP layer turns any other
    /// status into a bare Qt error number before the XML is read, so the
    /// client would show "203" where the host said "No such app".
    pub status: u16,
    /// The outcome: the body's `status_code`, which is what a client acts on.
    /// The same as `status` for a response with no XML.
    pub outcome: u16,
    /// Content type.
    pub content_type: &'static str,
    /// Body.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// An XML body with status 200.
    pub fn xml(body: String) -> Self {
        Self {
            status: 200,
            outcome: 200,
            content_type: "application/xml",
            body: body.into_bytes(),
        }
    }

    /// A bare status response.
    pub fn status(status: u16) -> Self {
        Self {
            status,
            outcome: status,
            content_type: "text/plain",
            body: Vec::new(),
        }
    }

    /// Serialise.
    pub fn to_bytes(&self) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            429 => "Too Many Requests",
            503 => "Service Unavailable",
            _ => "Error",
        };
        let mut head = format!(
            "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\n",
            self.status,
            self.content_type,
            self.body.len()
        );
        // The listener is reachable from the network; say nothing extra.
        head.push_str("Connection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n");
        let mut out = head.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_serverinfo_request() {
        let raw = b"GET /serverinfo?uniqueid=0123456789ABCDEF&uuid=abc HTTP/1.1\r\nHost: 10.0.0.1:47989\r\n\r\n";
        let (req, used) = parse_request(raw).unwrap().unwrap();
        assert_eq!(used, raw.len());
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/serverinfo");
        assert_eq!(req.param("uniqueid"), Some("0123456789ABCDEF"));
        assert_eq!(req.headers.get("host").unwrap(), "10.0.0.1:47989");
    }

    #[test]
    fn decodes_percent_escapes_and_plus() {
        let raw = b"GET /pair?devicename=My%20Phone&extra=a+b HTTP/1.1\r\n\r\n";
        let (req, _) = parse_request(raw).unwrap().unwrap();
        assert_eq!(req.param("devicename"), Some("My Phone"));
        assert_eq!(req.param("extra"), Some("a b"));
    }

    #[test]
    fn a_malformed_escape_is_left_alone_rather_than_guessed() {
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn hex_parameters_decode() {
        let raw = b"GET /pair?salt=0011ff HTTP/1.1\r\n\r\n";
        let (req, _) = parse_request(raw).unwrap().unwrap();
        assert_eq!(req.param_hex("salt"), Some(vec![0x00, 0x11, 0xFF]));
        let raw = b"GET /pair?salt=nothex HTTP/1.1\r\n\r\n";
        let (req, _) = parse_request(raw).unwrap().unwrap();
        assert_eq!(req.param_hex("salt"), None);
    }

    #[test]
    fn incomplete_requests_wait() {
        let raw = b"GET /serverinfo HTTP/1.1\r\nHost: x\r\n";
        assert_eq!(parse_request(raw).unwrap(), None);
    }

    #[test]
    fn request_bodies_are_refused() {
        assert!(parse_request(b"POST /x HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc").is_err());
        assert!(parse_request(b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").is_err());
    }

    #[test]
    fn malformed_requests_are_errors() {
        assert!(parse_request(b"nonsense\r\n\r\n").is_err());
        assert!(parse_request(b"GET /x HTTP/2.0\r\n\r\n").is_err());
        assert!(parse_request(b"GET /x HTTP/1.1\r\nnocolon\r\n\r\n").is_err());
        assert!(parse_request(&[0xFF, 0xFE, b'\r', b'\n', b'\r', b'\n']).is_err());
    }

    #[test]
    fn an_oversized_request_is_refused() {
        let raw = vec![b'A'; MAX_REQUEST_LEN + 1];
        assert!(parse_request(&raw).is_err());
    }

    #[test]
    fn responses_carry_a_length_and_close() {
        let bytes = HttpResponse::xml("<root/>".into()).to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 7\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.ends_with("\r\n\r\n<root/>"));
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0x1234_5678u32;
        for _ in 0..2000 {
            let len = (state % 96) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                buf.push((state >> 16) as u8);
            }
            let _ = parse_request(&buf);
        }
    }
}
