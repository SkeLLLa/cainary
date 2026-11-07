//! Pure HTTP/1.1 parsing and response bytes (design §8.2). Reads from `impl BufRead`; no sockets,
//! no clocks (the server's reader enforces the deadlines).

use std::io::{self, BufRead, Read};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_request_line: usize,
    pub max_header_bytes: usize,
    pub max_headers: usize,
    pub max_body: usize,
    pub max_chunk_line: usize,
    pub max_trailer_bytes: usize,
    pub max_trailers: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_request_line: 8 * 1024,
            max_header_bytes: 16 * 1024,
            max_headers: 64,
            max_body: 16 * 1024 * 1024,
            max_chunk_line: 1024,
            max_trailer_bytes: 8 * 1024,
            max_trailers: 32,
        }
    }
}

#[derive(Debug)]
pub enum HttpError {
    /// The peer closed before a request began.
    Eof,
    Io(io::Error),
    /// Answer with this status and close.
    Bad {
        status: u16,
        message: String,
    },
}

fn bad<T>(status: u16, message: impl Into<String>) -> Result<T, HttpError> {
    Err(HttpError::Bad {
        status,
        message: message.into(),
    })
}

impl From<io::Error> for HttpError {
    fn from(e: io::Error) -> HttpError {
        HttpError::Io(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub method: String,
    /// The request target as sent: path plus optional query.
    pub target: String,
    /// 0 for HTTP/1.0, 1 for HTTP/1.1.
    pub minor: u8,
    /// Lower-cased names, trimmed values, in arrival order.
    pub headers: Vec<(String, String)>,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
    pub fn path(&self) -> &str {
        self.target.split(['?', '#']).next().unwrap_or("")
    }
    /// Whether the connection may carry another request.
    pub fn keep_alive(&self) -> bool {
        if self.minor == 0 {
            return false;
        }
        !self
            .headers
            .iter()
            .filter(|(k, _)| k == "connection")
            .any(|(_, v)| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")))
    }
    pub fn expects_continue(&self) -> bool {
        self.header("expect")
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
    }
}

/// One line without its CRLF, at most `max` bytes before the terminator.
/// `Ok(None)` is EOF before any byte.
fn read_line(r: &mut impl BufRead, max: usize) -> Result<Option<Vec<u8>>, HttpError> {
    let mut line = Vec::new();
    loop {
        let buf = r.fill_buf()?;
        if buf.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::from(io::ErrorKind::UnexpectedEof).into())
            };
        }
        let (take, found) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (buf.len(), false),
        };
        // Bound before copying, so a line without a newline can't grow memory.
        if line.len() + take > max + 2 {
            return Err(HttpError::Bad {
                status: 0,
                message: String::new(),
            });
        }
        line.extend_from_slice(&buf[..take]);
        r.consume(take);
        if found {
            line.pop();
            // RFC 9112: lines end in CRLF; a bare LF or a stray CR is a framing attack surface.
            if line.pop() != Some(b'\r') || line.contains(&b'\r') {
                return bad(400, "lines must end in CRLF");
            }
            if line.len() > max {
                return Err(HttpError::Bad {
                    status: 0,
                    message: String::new(),
                });
            }
            return Ok(Some(line));
        }
    }
}

/// `read_line` with the over-long case mapped to `status`.
fn line_or(
    r: &mut impl BufRead,
    max: usize,
    status: u16,
    what: &str,
) -> Result<Option<Vec<u8>>, HttpError> {
    match read_line(r, max) {
        Err(HttpError::Bad { status: 0, .. }) => bad(status, format!("{what} too long")),
        other => other,
    }
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

pub fn read_head(r: &mut impl BufRead, lim: &Limits) -> Result<Head, HttpError> {
    let Some(line) = line_or(r, lim.max_request_line, 414, "request line")? else {
        return Err(HttpError::Eof);
    };
    let line = String::from_utf8(line).or_else(|_| bad(400, "request line isn't text"))?;
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return bad(400, "malformed request line");
    };
    if !is_token(method) || method.len() > 16 {
        return bad(400, "malformed request line");
    }
    let minor = match version {
        "HTTP/1.1" => 1,
        "HTTP/1.0" => 0,
        v if v.starts_with("HTTP/") => return bad(400, "unsupported HTTP version"),
        _ => return bad(400, "malformed request line"),
    };
    if !target.starts_with('/') || target.bytes().any(|b| b < 0x21 || b == 0x7f) {
        return bad(400, "malformed request target");
    }

    let mut headers = Vec::new();
    let mut total = 0usize;
    loop {
        let remaining = lim.max_header_bytes.saturating_sub(total);
        let Some(line) = line_or(r, remaining, 431, "headers")? else {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        };
        total += line.len() + 2;
        if line.is_empty() {
            break;
        }
        if headers.len() >= lim.max_headers {
            return bad(431, "too many headers");
        }
        if line[0] == b' ' || line[0] == b'\t' {
            return bad(400, "folded headers aren't supported");
        }
        if line.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return bad(400, "control character in a header");
        }
        let line = String::from_utf8(line).or_else(|_| bad(400, "header isn't text"))?;
        let Some((name, value)) = line.split_once(':') else {
            return bad(400, "malformed header");
        };
        if !is_token(name) {
            return bad(400, "malformed header name");
        }
        headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
    }
    let head = Head {
        method: method.to_string(),
        target: target.to_string(),
        minor,
        headers,
    };
    if head.header("expect").is_some() && !head.expects_continue() {
        return bad(400, "unsupported Expect");
    }
    Ok(head)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    None,
    Length(usize),
    Chunked,
}

/// How the body is delimited; rejects conflicts, and a Content-Length over the cap (413)
/// before any body byte is read.
pub fn framing(head: &Head, lim: &Limits) -> Result<Framing, HttpError> {
    let te: Vec<&str> = head
        .headers
        .iter()
        .filter(|(k, _)| k == "transfer-encoding")
        .map(|(_, v)| v.as_str())
        .collect();
    let cl: Vec<&str> = head
        .headers
        .iter()
        .filter(|(k, _)| k == "content-length")
        .map(|(_, v)| v.as_str())
        .collect();
    if !te.is_empty() {
        if !cl.is_empty() {
            return bad(400, "both Content-Length and Transfer-Encoding");
        }
        if te.len() != 1 || !te[0].eq_ignore_ascii_case("chunked") {
            return bad(400, "unsupported Transfer-Encoding");
        }
        return Ok(Framing::Chunked);
    }
    if cl.len() > 1 {
        // Even equal duplicates: some intermediaries merge them, some pick one.
        return bad(400, "duplicate Content-Length");
    }
    let Some(v) = cl.first() else {
        return if head.method == "POST" {
            bad(400, "POST needs Content-Length or chunked framing")
        } else {
            Ok(Framing::None)
        };
    };
    if v.is_empty() || v.len() > 18 || !v.bytes().all(|b| b.is_ascii_digit()) {
        // 18 digits fit a u64; longer is over the cap anyway but never worth parsing.
        return if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
            bad(413, "body too large")
        } else {
            bad(400, "invalid Content-Length")
        };
    }
    match v.parse::<usize>() {
        Ok(0) => Ok(Framing::Length(0)),
        Ok(n) if n <= lim.max_body => Ok(Framing::Length(n)),
        _ => bad(413, "body too large"),
    }
}

pub fn read_body(r: &mut impl BufRead, f: Framing, lim: &Limits) -> Result<Vec<u8>, HttpError> {
    match f {
        Framing::None => Ok(Vec::new()),
        Framing::Length(n) => {
            // Grows as bytes arrive: a client can't make us reserve the cap up front.
            let mut body = Vec::new();
            r.take(n as u64).read_to_end(&mut body)?;
            if body.len() != n {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
            Ok(body)
        }
        Framing::Chunked => read_chunked(r, lim),
    }
}

fn read_chunked(r: &mut impl BufRead, lim: &Limits) -> Result<Vec<u8>, HttpError> {
    let eof = || HttpError::Io(io::Error::from(io::ErrorKind::UnexpectedEof));
    let mut body = Vec::new();
    loop {
        let line = line_or(r, lim.max_chunk_line, 400, "chunk size line")?.ok_or_else(eof)?;
        let line = String::from_utf8(line).or_else(|_| bad(400, "invalid chunk size"))?;
        // Chunk extensions are rejected: nothing legitimate sends them to an OTLP receiver.
        let size = line.as_str();
        if size.is_empty() || size.len() > 16 || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
            return bad(400, "invalid chunk size");
        }
        let size = usize::from_str_radix(size, 16).or_else(|_| bad(400, "invalid chunk size"))?;
        if size == 0 {
            break;
        }
        if size > lim.max_body || body.len() + size > lim.max_body {
            return bad(413, "body too large");
        }
        let before = body.len();
        r.take(size as u64).read_to_end(&mut body)?;
        if body.len() - before != size {
            return Err(eof());
        }
        let end = line_or(r, 2, 400, "chunk terminator")?.ok_or_else(eof)?;
        if !end.is_empty() {
            return bad(400, "missing chunk terminator");
        }
    }
    // Trailers: read and ignore, bounded.
    let mut bytes = 0usize;
    for _ in 0..=lim.max_trailers {
        let line = line_or(r, lim.max_chunk_line, 431, "trailer")?.ok_or_else(eof)?;
        if line.is_empty() {
            return Ok(body);
        }
        bytes += line.len() + 2;
        if bytes > lim.max_trailer_bytes {
            return bad(431, "trailers too large");
        }
    }
    bad(431, "too many trailers")
}

pub const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
    pub close: bool,
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        403 => "Forbidden",
        421 => "Misdirected Request",
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

impl Response {
    pub fn json(status: u16, body: String, keep_alive: bool) -> Response {
        Response {
            status,
            headers: vec![("Content-Type", "application/json".to_string())],
            body: body.into_bytes(),
            // Every non-200 closes (design §8.2).
            close: status != 200 || !keep_alive,
        }
    }

    /// `{"code":3,"message":"…"}`, the OTLP error body.
    pub fn error(status: u16, message: &str) -> Response {
        let body = serde_json::json!({"code": 3, "message": message}).to_string();
        Response::json(status, body, false)
    }

    /// The OTLP/HTTP protobuf answer: an empty `ExportServiceResponse` in the request's media type.
    pub fn protobuf_ok(media: &str, keep_alive: bool) -> Response {
        Response {
            status: 200,
            headers: vec![("Content-Type", media.to_string())],
            body: Vec::new(),
            close: !keep_alive,
        }
    }

    /// A `google.rpc.Status` (1: code = 3 INVALID_ARGUMENT, 2: message), the OTLP error body for
    /// a protobuf request. The HTTP status is the JSON answer's.
    pub fn protobuf_error(status: u16, media: &str, message: &str) -> Response {
        let mut body = vec![0x08, 0x03, 0x12];
        let mut len = message.len();
        while len >= 0x80 {
            body.push((len & 0x7f) as u8 | 0x80);
            len >>= 7;
        }
        body.push(len as u8);
        body.extend_from_slice(message.as_bytes());
        Response {
            status,
            headers: vec![("Content-Type", media.to_string())],
            body,
            close: true,
        }
    }

    pub fn with_header(mut self, name: &'static str, value: &str) -> Response {
        self.headers.push((name, value.to_string()));
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut s = format!("HTTP/1.1 {} {}\r\n", self.status, reason(self.status));
        for (k, v) in &self.headers {
            s.push_str(&format!("{k}: {v}\r\n"));
        }
        s.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        s.push_str(if self.close {
            "Connection: close\r\n"
        } else {
            "Connection: keep-alive\r\n"
        });
        s.push_str("\r\n");
        let mut out = s.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn head(text: &str) -> Result<Head, HttpError> {
        read_head(
            &mut Cursor::new(text.as_bytes().to_vec()),
            &Limits::default(),
        )
    }
    fn status(r: Result<impl std::fmt::Debug, HttpError>) -> u16 {
        match r {
            Err(HttpError::Bad { status, .. }) => status,
            other => panic!("expected Bad, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_request_head() {
        let h = head(
            "POST /v1/logs?x=1 HTTP/1.1\r\nHost: a\r\nContent-Type:  application/json \r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            (h.method.as_str(), h.path(), h.minor),
            ("POST", "/v1/logs", 1)
        );
        assert_eq!(h.header("content-type"), Some("application/json"));
        assert!(h.keep_alive());
    }

    #[test]
    fn bare_lf_and_stray_cr_are_rejected() {
        assert_eq!(status(head("GET / HTTP/1.1\nHost: a\n\n")), 400);
        assert_eq!(status(head("GET / HTTP/1.1\r\nHost: a\n\r\n")), 400);
        assert_eq!(status(head("GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n")), 400);
    }

    #[test]
    fn clean_eof_and_truncation() {
        assert!(matches!(head(""), Err(HttpError::Eof)));
        assert!(matches!(
            head("GET / HTTP/1.1\r\nHost"),
            Err(HttpError::Io(_))
        ));
        assert!(matches!(head("GET / HTTP/1.1\r\n"), Err(HttpError::Io(_))));
    }

    #[test]
    fn malformed_request_lines() {
        for l in [
            "GET /",
            "GET / HTTP/1.1 x",
            "get\u{1} / HTTP/1.1",
            "GET x HTTP/1.1",
            "GET / HTTP/2.0",
            "GET / FTP/1.1",
            "PRI * HTTP/2.0",
            "GET /a b HTTP/1.1",
        ] {
            assert_eq!(status(head(&format!("{l}\r\n\r\n"))), 400, "{l}");
        }
    }

    #[test]
    fn grpc_preface_is_a_400() {
        assert_eq!(status(head("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")), 400);
    }

    #[test]
    fn request_line_cap() {
        let ok = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(8 * 1024 - 15));
        assert!(head(&ok).is_ok(), "exactly at the cap");
        let long = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(8 * 1024));
        assert_eq!(status(head(&long)), 414);
        // No newline at all: still bounded.
        let endless = "a".repeat(100_000);
        assert_eq!(status(head(&endless)), 414);
    }

    #[test]
    fn header_caps() {
        let big = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(20 * 1024));
        assert_eq!(status(head(&big)), 431);
        let many: String = (0..65).map(|i| format!("H{i}: v\r\n")).collect();
        assert_eq!(status(head(&format!("GET / HTTP/1.1\r\n{many}\r\n"))), 431);
        let sixty_four: String = (0..64).map(|i| format!("H{i}: v\r\n")).collect();
        assert!(head(&format!("GET / HTTP/1.1\r\n{sixty_four}\r\n")).is_ok());
        // Many small headers that together pass 16 KiB.
        let lots: String = (0..64)
            .map(|i| format!("H{i}: {}\r\n", "a".repeat(300)))
            .collect();
        assert_eq!(status(head(&format!("GET / HTTP/1.1\r\n{lots}\r\n"))), 431);
    }

    #[test]
    fn bad_headers() {
        for h in ["NoColon", " folded: x", "Bad Name: x", ": x", "X: a\u{1}b"] {
            assert_eq!(
                status(head(&format!("GET / HTTP/1.1\r\n{h}\r\n\r\n"))),
                400,
                "{h:?}"
            );
        }
    }

    fn framed(headers: &str) -> Result<Framing, HttpError> {
        let h = head(&format!("POST / HTTP/1.1\r\n{headers}\r\n")).unwrap();
        framing(&h, &Limits::default())
    }

    #[test]
    fn framing_rules() {
        assert_eq!(status(framed("")), 400, "POST needs explicit framing");
        let get = head("GET / HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(framing(&get, &Limits::default()).unwrap(), Framing::None);
        assert_eq!(framed("Content-Length: 0\r\n").unwrap(), Framing::Length(0));
        assert_eq!(
            framed("Content-Length: 12\r\n").unwrap(),
            Framing::Length(12)
        );
        assert_eq!(
            framed("Transfer-Encoding: Chunked\r\n").unwrap(),
            Framing::Chunked
        );
        for bad in [
            "Content-Length: 1\r\nContent-Length: 2\r\n",
            "Content-Length: 12\r\nContent-Length: 12\r\n",
            "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
            "Transfer-Encoding: gzip, chunked\r\n",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
            "Content-Length: -1\r\n",
            "Content-Length: +1\r\n",
            "Content-Length: 1x\r\n",
            "Content-Length:\r\n",
        ] {
            assert_eq!(status(framed(bad)), 400, "{bad:?}");
        }
    }

    #[test]
    fn content_length_cap() {
        assert_eq!(
            framed("Content-Length: 16777216\r\n").unwrap(),
            Framing::Length(16 * 1024 * 1024)
        );
        assert_eq!(status(framed("Content-Length: 16777217\r\n")), 413);
        assert_eq!(
            status(framed("Content-Length: 99999999999999999999999\r\n")),
            413
        );
    }

    #[test]
    fn expect() {
        let h = head("POST / HTTP/1.1\r\nExpect: 100-Continue\r\n\r\n").unwrap();
        assert!(h.expects_continue());
        assert_eq!(status(head("POST / HTTP/1.1\r\nExpect: nope\r\n\r\n")), 400);
        assert_eq!(CONTINUE, b"HTTP/1.1 100 Continue\r\n\r\n");
    }

    #[test]
    fn keep_alive_rules() {
        assert!(!head("GET / HTTP/1.0\r\n\r\n").unwrap().keep_alive());
        assert!(
            !head("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
                .unwrap()
                .keep_alive()
        );
        assert!(
            !head("GET / HTTP/1.1\r\nConnection: Close\r\n\r\n")
                .unwrap()
                .keep_alive()
        );
        assert!(
            !head("GET / HTTP/1.1\r\nConnection: keep-alive, close\r\n\r\n")
                .unwrap()
                .keep_alive()
        );
        assert!(
            head("GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n")
                .unwrap()
                .keep_alive()
        );
    }

    fn body(f: Framing, data: &[u8]) -> Result<Vec<u8>, HttpError> {
        read_body(&mut Cursor::new(data.to_vec()), f, &Limits::default())
    }

    #[test]
    fn bodies() {
        assert_eq!(body(Framing::Length(3), b"abcdef").unwrap(), b"abc");
        assert!(matches!(
            body(Framing::Length(9), b"abc"),
            Err(HttpError::Io(_))
        ));
        assert_eq!(body(Framing::None, b"abc").unwrap(), b"");
    }

    #[test]
    fn chunked_bodies() {
        let ok = b"3\r\nabc\r\n4\r\ndefg\r\n0\r\nTrailer: x\r\n\r\n";
        assert_eq!(body(Framing::Chunked, ok).unwrap(), b"abcdefg");
        assert_eq!(body(Framing::Chunked, b"0\r\n\r\n").unwrap(), b"");
        assert_eq!(status(body(Framing::Chunked, b"zz\r\n")), 400);
        assert_eq!(
            status(body(Framing::Chunked, b"3;ext=1\r\nabc\r\n0\r\n\r\n")),
            400,
            "extensions"
        );
        assert_eq!(
            status(body(Framing::Chunked, b"3\nabc\r\n0\r\n\r\n")),
            400,
            "bare LF"
        );
        let many = format!("0\r\n{}\r\n", "T: x\r\n".repeat(33));
        assert_eq!(status(body(Framing::Chunked, many.as_bytes())), 431);
        let big = format!(
            "0\r\n{}\r\n",
            format!("T: {}\r\n", "x".repeat(900)).repeat(10)
        );
        assert_eq!(status(body(Framing::Chunked, big.as_bytes())), 431);
        assert_eq!(status(body(Framing::Chunked, b"\r\n")), 400);
        assert_eq!(status(body(Framing::Chunked, b"3\r\nabcXX0\r\n\r\n")), 400);
        assert!(matches!(
            body(Framing::Chunked, b"3\r\nab"),
            Err(HttpError::Io(_))
        ));
        assert!(matches!(
            body(Framing::Chunked, b"3\r\nabc\r\n"),
            Err(HttpError::Io(_))
        ));
        let long_line = format!("3;{}\r\nabc\r\n0\r\n\r\n", "x".repeat(2000));
        assert_eq!(status(body(Framing::Chunked, long_line.as_bytes())), 400);
    }

    #[test]
    fn chunked_over_the_cap_is_counted_as_it_arrives() {
        let lim = Limits {
            max_body: 8,
            ..Limits::default()
        };
        let mut r = Cursor::new(b"5\r\naaaaa\r\n5\r\nbbbbb\r\n0\r\n\r\n".to_vec());
        assert_eq!(status(read_body(&mut r, Framing::Chunked, &lim)), 413);
        let mut r = Cursor::new(b"ffffffff\r\n".to_vec());
        assert_eq!(status(read_body(&mut r, Framing::Chunked, &lim)), 413);
        let mut r = Cursor::new(b"fffffffffffffffff\r\n".to_vec());
        assert_eq!(status(read_body(&mut r, Framing::Chunked, &lim)), 400);
    }

    #[test]
    fn response_bytes() {
        let r = Response::json(200, "{}".into(), true);
        assert_eq!(
            String::from_utf8(r.to_bytes()).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n{}"
        );
        assert!(Response::json(200, "{}".into(), false).close);
        let e = Response::error(405, "no").with_header("Allow", "POST");
        let s = String::from_utf8(e.to_bytes()).unwrap();
        assert!(s.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert!(s.contains("Allow: POST\r\n"));
        assert!(s.contains("Connection: close\r\n"));
        assert!(s.ends_with("{\"code\":3,\"message\":\"no\"}"));
        assert!(s.contains("Content-Length: 25\r\n"));
        for st in [400, 404, 413, 414, 415, 431, 503] {
            assert!(Response::error(st, "x").close);
            assert_ne!(reason(st), "Error");
        }
    }

    #[test]
    fn protobuf_responses() {
        let ok = Response::protobuf_ok("application/x-protobuf", true);
        assert_eq!(
            String::from_utf8(ok.to_bytes()).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
        );
        assert!(Response::protobuf_ok("application/protobuf", false).close);
        // google.rpc.Status: code 3, then the message.
        let e = Response::protobuf_error(415, "application/protobuf", "no");
        assert_eq!((e.status, e.close), (415, true));
        assert_eq!(e.body, [0x08, 0x03, 0x12, 0x02, b'n', b'o']);
        let bytes = e.to_bytes();
        assert!(bytes.starts_with(
            b"HTTP/1.1 415 Unsupported Media Type\r\nContent-Type: application/protobuf\r\n"
        ));
        assert!(bytes.ends_with(b"Connection: close\r\n\r\n\x08\x03\x12\x02no"));
        // A message over 127 bytes needs a two-byte length.
        let long = "x".repeat(300);
        let e = Response::protobuf_error(400, "application/x-protobuf", &long);
        assert_eq!(e.body[..5], [0x08, 0x03, 0x12, 0xac, 0x02]);
        assert_eq!(e.body.len(), 5 + 300);
    }
}
