//! Plain-HTTP requests to revocation endpoints.
//!
//! OCSP responders (RFC 6960 Appendix A) and CRL distribution points
//! (RFC 5280 §4.2.1.13) are published as `http://` URLs. This module sends one
//! `GET` or `POST` request to such a URL and returns the reply body, capped
//! at a caller-chosen size. Redirects are not followed.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::ProbeError;
use crate::http::{HttpResponse, complete_head, parse_head};

/// Settings for requests to revocation endpoints.
#[derive(Debug, Clone)]
pub struct Fetcher {
    /// TCP connect timeout, applied to each resolved address.
    pub connect_timeout: Duration,
    /// Timeout for sending the request and reading the whole reply.
    pub read_timeout: Duration,
    /// Largest accepted reply body in bytes.
    pub max_body: usize,
    /// Local address to connect from; the OS picks one when `None`.
    /// Resolved addresses of the other family are skipped.
    pub source: Option<IpAddr>,
    /// HTTP proxy to tunnel through with `CONNECT` to a validated IP.
    /// Direct when `None`.
    pub proxy: Option<SocketAddr>,
    /// Explicitly permitted additional destinations, including private IPs or
    /// nonstandard ports. Otherwise only public addresses on port 80 are used.
    pub allowed_endpoints: Vec<SocketAddr>,
}

/// Reply to a [`Fetcher`] request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpBody {
    /// Status code of the final response.
    pub status: u16,
    /// `Content-Type` header, if present.
    pub content_type: Option<String>,
    /// Reply body with any chunked transfer coding removed.
    pub body: Vec<u8>,
}

/// Parts of an `http://` URL needed to send a request.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpUrl {
    /// Host name or IP literal, without IPv6 brackets.
    host: String,
    /// TCP port, 80 unless given.
    port: u16,
    /// Path and query, at least `/`.
    target: String,
    /// Value of the `Host` header (RFC 9110 §7.2).
    authority: String,
}

impl Fetcher {
    /// Sends `GET url` and returns the reply.
    ///
    /// # Errors
    /// Returns a [`ProbeError`] for URLs that are not `http://`, resolution
    /// or connect failures, timeouts, malformed replies, and bodies larger
    /// than [`Fetcher::max_body`].
    pub async fn get(&self, url: &str) -> Result<HttpBody, ProbeError> {
        self.request(url, None).await
    }

    /// Sends `POST url` with `body` of type `content_type` and returns the
    /// reply.
    ///
    /// # Errors
    /// As for [`Fetcher::get`].
    pub async fn post(
        &self,
        url: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<HttpBody, ProbeError> {
        if content_type.bytes().any(|b| b.is_ascii_control()) {
            return Err(ProbeError::Unexpected("invalid Content-Type"));
        }
        self.request(url, Some((content_type, body))).await
    }

    /// Sends one request and reads the reply until it is complete.
    async fn request(
        &self,
        url: &str,
        post: Option<(&str, &[u8])>,
    ) -> Result<HttpBody, ProbeError> {
        let url = HttpUrl::parse(url)?;
        let mut stream = self.connect(&url).await?;
        let request = encode_request(&url, post);
        timeout(self.read_timeout, async {
            stream.write_all(&request).await.map_err(ProbeError::Io)?;
            self.read_reply(&mut stream).await
        })
        .await
        .map_err(|_| ProbeError::Timeout)?
    }

    /// Connects to the first reachable address of the URL's host, or opens
    /// a tunnel to it through the proxy.
    async fn connect(&self, url: &HttpUrl) -> Result<TcpStream, ProbeError> {
        let addrs = timeout(
            self.connect_timeout,
            tokio::net::lookup_host((url.host.as_str(), url.port)),
        )
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map_err(ProbeError::Connect)?;
        let mut last = None;
        let mut skipped = false;
        for addr in addrs {
            if !self.allowed_endpoints.contains(&addr)
                && (addr.port() != 80 || !public_address(addr.ip()))
            {
                last = Some(ProbeError::Unexpected(
                    "revocation destination blocked; use an explicit endpoint allowance",
                ));
                continue;
            }
            if self.source.is_some_and(|ip| ip.is_ipv4() != addr.is_ipv4()) {
                skipped = true;
                continue;
            }
            let result = if let Some(proxy) = self.proxy {
                crate::tunnel(proxy, self.source, self.connect_timeout, &addr.to_string()).await
            } else {
                crate::connect(addr, self.source, self.connect_timeout).await
            };
            match result {
                Ok(stream) => return Ok(stream),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or(ProbeError::Unexpected(if skipped {
            "no address in the source address family"
        } else {
            "host name did not resolve"
        })))
    }

    /// Reads the final response head and its body (RFC 9112 §6.3).
    async fn read_reply(&self, stream: &mut TcpStream) -> Result<HttpBody, ProbeError> {
        let mut data = Vec::new();
        let mut buf = vec![0; 16 * 1024];
        let mut closed = false;
        let head = loop {
            if let Some(end) = complete_head(&data)? {
                let head = parse_head(&data[..end])?;
                data.drain(..end);
                if (100..200).contains(&head.status) {
                    continue;
                }
                break head;
            }
            if closed {
                return Err(ProbeError::Unexpected(
                    "connection closed before the HTTP headers ended",
                ));
            }
            closed = read_more(stream, &mut buf, &mut data).await?;
        };
        let reply = |body| HttpBody {
            status: head.status,
            content_type: head.header("content-type").map(str::to_owned),
            body,
        };
        if matches!(head.status, 204 | 304) {
            return Ok(reply(Vec::new()));
        }
        let codings: Vec<&str> = head
            .header_values("transfer-encoding")
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .collect();
        let chunked = match codings.as_slice() {
            [] => false,
            [coding] if coding.eq_ignore_ascii_case("chunked") => true,
            _ => return Err(ProbeError::Unexpected("unsupported Transfer-Encoding")),
        };
        let length = if chunked {
            None
        } else {
            content_length(&head)?
        };
        if length.is_some_and(|l| l > self.max_body) {
            return Err(too_large());
        }
        let mut decoder = Dechunker::default();
        loop {
            if chunked {
                if decoder.feed(&data, self.max_body)? {
                    return Ok(reply(decoder.body));
                }
            } else if let Some(length) = length {
                if data.len() >= length {
                    data.truncate(length);
                    return Ok(reply(data));
                }
            } else if data.len() > self.max_body {
                return Err(too_large());
            } else if closed {
                return Ok(reply(data));
            }
            if closed {
                return Err(truncated());
            }
            // A one-byte chunk ("1\r\nX\r\n") takes six bytes on the wire;
            // this bound only stops a server that streams forever.
            if data.len() > self.max_body.saturating_mul(6).saturating_add(64 * 1024) {
                return Err(too_large());
            }
            closed = read_more(stream, &mut buf, &mut data).await?;
        }
    }
}

/// Conservative public-unicast policy based on the IANA special-purpose
/// registries. IPv6 transition mechanisms are excluded to avoid embedded
/// private IPv4 destinations. Explicit endpoint allowances bypass this policy.
fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(matches!(a, 0 | 10 | 127 | 224..=255)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || b == 0 || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let [a, b, ..] = ip.segments();
            (0x2000..=0x3fff).contains(&a)
                && !(a == 0x2001 && (b < 0x0200 || b == 0x0db8))
                && a != 0x2002
                && !(a == 0x3fff && b < 0x1000)
        }
    }
}

impl HttpUrl {
    /// Parses `http://host[:port][/path][?query][#fragment]`. User info is
    /// rejected and the fragment is dropped (RFC 3986 §3, RFC 9110 §4.2.1).
    fn parse(url: &str) -> Result<Self, ProbeError> {
        let invalid = |msg| Err(ProbeError::Unexpected(msg));
        let Some(rest) = url
            .get(..7)
            .filter(|s| s.eq_ignore_ascii_case("http://"))
            .map(|_| &url[7..])
        else {
            return invalid("only http:// URLs are supported");
        };
        let rest = rest.split('#').next().unwrap_or_default();
        let split = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, target) = rest.split_at(split);
        if authority.contains('@') {
            return invalid("URLs with user info are not supported");
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let Some((host, tail)) = v6.split_once(']') else {
                return invalid("malformed URL host");
            };
            (host, tail.strip_prefix(':'))
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            }
        };
        let port = match port {
            None | Some("") => 80,
            Some(p) if p.bytes().all(|b| b.is_ascii_digit()) => match p.parse() {
                Ok(p) if p > 0 => p,
                _ => return invalid("malformed URL port"),
            },
            Some(_) => return invalid("malformed URL port"),
        };
        if host.is_empty() || !host.bytes().all(|b| b.is_ascii_graphic()) {
            return invalid("malformed URL host");
        }
        if !target.bytes().all(|b| b.is_ascii_graphic()) {
            return invalid("malformed URL path");
        }
        let target = match target {
            "" => "/".to_owned(),
            t if t.starts_with('?') => format!("/{t}"),
            t => t.to_owned(),
        };
        let host_part = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        let authority = match port {
            80 => host_part,
            p => format!("{host_part}:{p}"),
        };
        Ok(Self {
            host: host.to_owned(),
            port,
            target,
            authority,
        })
    }
}

/// Returns the body length announced by every `Content-Length` field, or
/// `None` without one. Malformed or conflicting values are an error
/// (RFC 9112 §6.3).
fn content_length(head: &HttpResponse) -> Result<Option<usize>, ProbeError> {
    let mut length = None;
    for value in head
        .header_values("content-length")
        .flat_map(|v| v.split(','))
    {
        let value = value.trim();
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ProbeError::Unexpected("malformed Content-Length"));
        }
        let parsed = value
            .parse::<usize>()
            .map_err(|_| ProbeError::Unexpected("malformed Content-Length"))?;
        if length.is_some_and(|l| l != parsed) {
            return Err(ProbeError::Unexpected("conflicting Content-Length values"));
        }
        length = Some(parsed);
    }
    Ok(length)
}

/// Encodes an HTTP/1.1 request (RFC 9112 §3) that asks the server to close
/// the connection after replying.
fn encode_request(url: &HttpUrl, post: Option<(&str, &[u8])>) -> Vec<u8> {
    let method = if post.is_some() { "POST" } else { "GET" };
    let mut head = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: testls/{}\r\nAccept: */*\r\nConnection: close\r\n",
        url.target,
        url.authority,
        env!("CARGO_PKG_VERSION"),
    );
    if let Some((content_type, body)) = post {
        let _ = write!(
            head,
            "Content-Type: {content_type}\r\nContent-Length: {}\r\n",
            body.len()
        );
    }
    head.push_str("\r\n");
    let mut request = head.into_bytes();
    if let Some((_, body)) = post {
        request.extend_from_slice(body);
    }
    request
}

/// Longest chunk-size or trailer line accepted, so a missing CRLF cannot
/// make every read rescan an ever-growing line.
const MAX_CHUNK_LINE: usize = 8 * 1024;

/// Incremental decoder for the chunked transfer coding (RFC 9112 §7.1).
/// It remembers how much of the raw body it has consumed, so each read
/// only parses the new bytes.
#[derive(Debug, Default)]
struct Dechunker {
    /// Decoded body so far.
    body: Vec<u8>,
    /// Raw bytes already decoded.
    consumed: usize,
    /// Whether the last chunk has arrived and trailer lines are being skipped.
    trailer: bool,
}

impl Dechunker {
    /// Decodes the complete units in `raw[self.consumed..]`. `raw` is the
    /// whole body received so far. Returns `true` once the last chunk and
    /// the trailer section have arrived.
    fn feed(&mut self, raw: &[u8], max_body: usize) -> Result<bool, ProbeError> {
        let malformed = || ProbeError::Unexpected("malformed chunked body");
        loop {
            let rest = &raw[self.consumed..];
            let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") else {
                return if rest.len() > MAX_CHUNK_LINE {
                    Err(malformed())
                } else {
                    Ok(false)
                };
            };
            if eol > MAX_CHUNK_LINE {
                return Err(malformed());
            }
            if self.trailer {
                // Trailer section: field lines up to an empty line.
                self.consumed += eol + 2;
                if eol == 0 {
                    return Ok(true);
                }
                continue;
            }
            let line = std::str::from_utf8(&rest[..eol]).map_err(|_| malformed())?;
            let size = line.split(';').next().unwrap_or_default().trim_end();
            if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(malformed());
            }
            let size = usize::from_str_radix(size, 16).map_err(|_| too_large())?;
            if size == 0 {
                self.consumed += eol + 2;
                self.trailer = true;
                continue;
            }
            if size > max_body.saturating_sub(self.body.len()) {
                return Err(too_large());
            }
            let Some(end) = size.checked_add(eol + 4) else {
                return Err(too_large());
            };
            let Some(chunk) = rest.get(eol + 2..end) else {
                return Ok(false);
            };
            if &chunk[size..] != b"\r\n" {
                return Err(malformed());
            }
            self.body.extend_from_slice(&chunk[..size]);
            self.consumed += end;
        }
    }
}

/// Removes the chunked transfer coding from a complete raw body. Returns
/// `None` while the last chunk has not arrived.
#[cfg(test)]
fn dechunk(raw: &[u8], max_body: usize) -> Result<Option<Vec<u8>>, ProbeError> {
    let mut decoder = Dechunker::default();
    Ok(decoder.feed(raw, max_body)?.then_some(decoder.body))
}

/// Appends the next read from `stream` to `data`. Returns `true` when the
/// peer has closed the connection.
async fn read_more(
    stream: &mut TcpStream,
    buf: &mut [u8],
    data: &mut Vec<u8>,
) -> Result<bool, ProbeError> {
    let n = stream.read(buf).await.map_err(ProbeError::Io)?;
    data.extend_from_slice(&buf[..n]);
    Ok(n == 0)
}

/// Error for replies whose body exceeds the size limit.
fn too_large() -> ProbeError {
    ProbeError::Unexpected("HTTP reply body too large")
}

/// Error for replies that end before the announced body.
fn truncated() -> ProbeError {
    ProbeError::Unexpected("connection closed before the HTTP body ended")
}

#[cfg(test)]
mod tests {
    //! Unit tests for URL parsing, body framing and the request itself.

    use super::*;
    use tokio::net::TcpListener;

    /// Fetcher with short timeouts and a 1 KiB body limit.
    fn fetcher() -> Fetcher {
        Fetcher {
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            max_body: 1024,
            source: None,
            proxy: None,
            allowed_endpoints: vec![],
        }
    }

    /// Special-purpose destinations are blocked, including IPv6 tunnels.
    #[test]
    fn public_destinations_only() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "2002:7f00:1::",
            "2001:db8::1",
            "64:ff9b::7f00:1",
        ] {
            assert!(!public_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(public_address(ip.parse().unwrap()), "{ip}");
        }
    }

    /// Disallowed addresses never open either a direct or proxy connection.
    #[tokio::test]
    async fn blocked_before_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        for proxy in [None, Some(addr)] {
            let fetcher = Fetcher { proxy, ..fetcher() };
            let error = fetcher.get(&format!("http://{addr}/")).await.unwrap_err();
            assert!(error.to_string().contains("destination blocked"));
            assert!(
                timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err()
            );
        }
        assert!(
            fetcher()
                .get("http://8.8.8.8:25/")
                .await
                .unwrap_err()
                .to_string()
                .contains("destination blocked")
        );
    }

    /// Starts a one-shot HTTP server that records the request and answers
    /// with `reply`, then closes the connection.
    async fn serve(reply: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 1024];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                request.extend_from_slice(&buf[..n]);
                if let Ok(Some(end)) = complete_head(&request) {
                    let length = parse_head(&request[..end])
                        .ok()
                        .and_then(|h| h.header("content-length").map(str::to_owned))
                        .map_or(0, |v| v.parse::<usize>().unwrap());
                    if request.len() >= end + length {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            s.write_all(&reply).await.unwrap();
            let _ = s.shutdown().await;
            request
        });
        (addr, task)
    }

    /// A `GET` request names the path and host; the sized body comes back.
    #[tokio::test]
    async fn get_with_content_length() {
        let (addr, task) = serve(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: 3\r\n\r\nabcEXTRA"
                .to_vec(),
        )
        .await;
        let r = Fetcher {
            allowed_endpoints: vec![addr],
            ..fetcher()
        }
        .get(&format!("http://{addr}/ca.crl"))
        .await
        .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.content_type.as_deref(), Some("application/pkix-crl"));
        assert_eq!(r.body, b"abc");
        let request = String::from_utf8(task.await.unwrap()).unwrap();
        assert!(request.starts_with("GET /ca.crl HTTP/1.1\r\n"), "{request}");
        assert!(
            request.contains(&format!("\r\nHost: {addr}\r\n")),
            "{request}"
        );
    }

    /// A `POST` request carries its body, type and length.
    #[tokio::test]
    async fn post_sends_body() {
        let (addr, task) = serve(b"HTTP/1.0 200 OK\r\n\r\nreply".to_vec()).await;
        let r = Fetcher {
            allowed_endpoints: vec![addr],
            ..fetcher()
        }
        .post(
            &format!("http://{addr}"),
            "application/ocsp-request",
            b"\x30\x00",
        )
        .await
        .unwrap();
        assert_eq!(r.body, b"reply");
        let request = task.await.unwrap();
        let text = String::from_utf8_lossy(&request);
        assert!(text.starts_with("POST / HTTP/1.1\r\n"), "{text}");
        assert!(text.contains("\r\nContent-Type: application/ocsp-request\r\n"));
        assert!(text.contains("\r\nContent-Length: 2\r\n"));
        assert!(request.ends_with(b"\r\n\r\n\x30\x00"));
    }

    /// Chunked bodies are decoded, including extensions and trailers.
    #[tokio::test]
    async fn chunked_body() {
        let (addr, _task) = serve(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
              3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: t\r\n\r\n"
                .to_vec(),
        )
        .await;
        let r = Fetcher {
            allowed_endpoints: vec![addr],
            ..fetcher()
        }
        .get(&format!("http://{addr}/"))
        .await
        .unwrap();
        assert_eq!(r.body, b"abcde");
    }

    /// A body of one-byte chunks up to the size limit is accepted despite
    /// the framing overhead.
    #[tokio::test]
    async fn one_byte_chunks() {
        // 64 KiB of one-byte chunks is 384 KiB on the wire, well past
        // twice the body limit plus the 64 KiB allowance.
        let fetcher = Fetcher {
            max_body: 64 * 1024,
            ..fetcher()
        };
        let mut reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for _ in 0..fetcher.max_body {
            reply.extend_from_slice(b"1\r\nx\r\n");
        }
        reply.extend_from_slice(b"0\r\n\r\n");
        let (addr, _task) = serve(reply).await;
        let r = Fetcher {
            allowed_endpoints: vec![addr],
            ..fetcher
        }
        .get(&format!("http://{addr}/"))
        .await
        .unwrap();
        assert_eq!(r.body.len(), fetcher.max_body);
    }

    /// Chunk-size lines without an end are rejected instead of buffered.
    #[test]
    fn overlong_chunk_line() {
        let raw = vec![b'1'; MAX_CHUNK_LINE + 1];
        assert!(dechunk(&raw, 1024).is_err());
        let mut raw = vec![b'0'; MAX_CHUNK_LINE + 1];
        raw.extend_from_slice(b"\r\n");
        assert!(dechunk(&raw, 1024).is_err());
    }

    /// Feeding a chunked body piecewise gives the same result as feeding
    /// it whole.
    #[test]
    fn incremental_dechunk() {
        let raw = b"3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: t\r\n\r\n";
        let mut decoder = Dechunker::default();
        for end in 0..raw.len() {
            assert!(!decoder.feed(&raw[..end], 1024).unwrap(), "{end}");
        }
        assert!(decoder.feed(raw, 1024).unwrap());
        assert_eq!(decoder.body, b"abcde");
    }

    /// A huge chunk size with an unlimited body is an error, not an
    /// arithmetic overflow.
    #[test]
    fn huge_chunk_size_without_limit() {
        let raw = format!("{:x}\r\nabc\r\n", usize::MAX);
        assert!(dechunk(raw.as_bytes(), usize::MAX).is_err());
    }

    /// Error statuses are returned for the caller to judge.
    #[tokio::test]
    async fn error_status_is_returned() {
        let (addr, _task) =
            serve(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
        let r = Fetcher {
            allowed_endpoints: vec![addr],
            ..fetcher()
        }
        .get(&format!("http://{addr}/"))
        .await
        .unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(r.body, b"");
    }

    /// With a source address, requests connect from it and resolved
    /// addresses of the other family are skipped.
    #[tokio::test]
    async fn source_address() {
        let (addr, _task) = serve(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()).await;
        let from_v4 = Fetcher {
            allowed_endpoints: vec![addr],
            source: Some("127.0.0.1".parse().unwrap()),
            ..fetcher()
        };
        let r = from_v4.get(&format!("http://{addr}/")).await.unwrap();
        assert_eq!(r.status, 204);
        let from_v6 = Fetcher {
            allowed_endpoints: vec![addr],
            source: Some("::1".parse().unwrap()),
            ..fetcher()
        };
        let r = from_v6.get(&format!("http://{addr}/")).await;
        assert!(
            matches!(r, Err(ProbeError::Unexpected(m)) if m.contains("address family")),
            "{r:?}"
        );
    }

    /// With a proxy, a validated IP is sent in `CONNECT` and the
    /// request goes through the tunnel.
    #[tokio::test]
    async fn through_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut data = Vec::new();
            let mut buf = [0; 1024];
            while !data.ends_with(b"\r\n\r\n") {
                let n = s.read(&mut buf).await.unwrap();
                data.extend_from_slice(&buf[..n]);
            }
            s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            let connect_len = data.len();
            while !data[connect_len..].ends_with(b"\r\n\r\n") {
                let n = s.read(&mut buf).await.unwrap();
                data.extend_from_slice(&buf[..n]);
            }
            s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                .await
                .unwrap();
            String::from_utf8(data).unwrap()
        });
        let via_proxy = Fetcher {
            proxy: Some(proxy),
            allowed_endpoints: vec!["127.0.0.1:8080".parse().unwrap()],
            ..fetcher()
        };
        let r = via_proxy.get("http://localhost:8080/x").await.unwrap();
        assert_eq!(r.status, 204);
        let seen = task.await.unwrap();
        assert!(
            seen.starts_with("CONNECT 127.0.0.1:8080 HTTP/1.1\r\n"),
            "{seen}"
        );
        assert!(
            seen.contains("GET /x HTTP/1.1\r\nHost: localhost:8080\r\n"),
            "{seen}"
        );
    }

    /// Repeated identical `Content-Length` values are accepted.
    #[tokio::test]
    async fn repeated_content_length() {
        let (addr, _task) = serve(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3, 3\r\n\r\nabcd".to_vec(),
        )
        .await;
        let r = Fetcher {
            allowed_endpoints: vec![addr],
            ..fetcher()
        }
        .get(&format!("http://{addr}/"))
        .await
        .unwrap();
        assert_eq!(r.body, b"abc");
    }

    /// 204 and 304 replies end after their headers even when the server
    /// keeps the connection open.
    #[tokio::test]
    async fn bodyless_statuses() {
        for reply in [
            &b"HTTP/1.1 204 No Content\r\n\r\n"[..],
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\n\r\n",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0; 1024];
                let _ = s.read(&mut buf).await;
                s.write_all(reply).await.unwrap();
                std::future::pending::<()>().await;
            });
            let r = Fetcher {
                allowed_endpoints: vec![addr],
                ..fetcher()
            }
            .get(&format!("http://{addr}/"))
            .await
            .unwrap();
            assert!(matches!(r.status, 204 | 304));
            assert_eq!(r.body, b"");
            server.abort();
        }
    }

    /// Content types with control characters cannot inject header lines.
    #[tokio::test]
    async fn content_type_injection_is_rejected() {
        let r = fetcher()
            .post("http://127.0.0.1:1/", "a\r\nX-Injected: 1", b"")
            .await;
        assert!(matches!(r, Err(ProbeError::Unexpected(_))), "{r:?}");
    }

    /// Oversized and truncated bodies are errors.
    #[tokio::test]
    async fn size_limit_and_truncation() {
        let mut big = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        big.resize(big.len() + 1025, b'a');
        for reply in [
            big,
            b"HTTP/1.1 200 OK\r\nContent-Length: 1025\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n401\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3, 4\r\n\r\nabcd".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: +3\r\n\r\nabc".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nabc".to_vec(),
            b"HTTP/1.1 200 OK\r\n".to_vec(),
        ] {
            let (addr, _task) = serve(reply.clone()).await;
            let r = Fetcher {
                allowed_endpoints: vec![addr],
                ..fetcher()
            }
            .get(&format!("http://{addr}/"))
            .await;
            assert!(
                matches!(r, Err(ProbeError::Unexpected(_))),
                "{:?}: {r:?}",
                String::from_utf8_lossy(&reply)
            );
        }
    }

    /// Chunk framing errors are rejected.
    #[test]
    fn malformed_chunks() {
        assert!(dechunk(b"z\r\n", 10).is_err());
        assert!(dechunk(b"\r\n", 10).is_err());
        assert!(dechunk(b"2\r\nabc\r\n", 10).is_err());
        assert_eq!(dechunk(b"2\r\nab\r\n", 10).unwrap(), None);
        assert_eq!(dechunk(b"0\r\n\r\n", 10).unwrap(), Some(vec![]));
    }

    /// URLs are split into host, port, target and `Host` header.
    #[test]
    fn parses_urls() {
        let url = |s: &str| HttpUrl::parse(s).unwrap();
        let u = url("http://ocsp.example.com");
        assert_eq!(
            (u.host.as_str(), u.port, u.target.as_str()),
            ("ocsp.example.com", 80, "/")
        );
        assert_eq!(u.authority, "ocsp.example.com");
        let u = url("HTTP://crl.example.com:8080/a/b.crl?x=1#frag");
        assert_eq!((u.port, u.target.as_str()), (8080, "/a/b.crl?x=1"));
        assert_eq!(u.authority, "crl.example.com:8080");
        let u = url("http://[2001:db8::1]:81?q");
        assert_eq!((u.host.as_str(), u.target.as_str()), ("2001:db8::1", "/?q"));
        assert_eq!(u.authority, "[2001:db8::1]:81");
        assert_eq!(url("http://192.0.2.1:/").port, 80);
    }

    /// Unsupported schemes and malformed URLs are rejected.
    #[test]
    fn rejects_urls() {
        for bad in [
            "https://example.com/",
            "ldap://example.com/",
            "http:/example.com",
            "http://",
            "http://user@example.com/",
            "http://example.com:0/",
            "http://example.com:99999/",
            "http://example.com:x/",
            "http://[2001:db8::1/",
            "http://exa mple.com/",
            "http://example.com/a b",
        ] {
            assert!(HttpUrl::parse(bad).is_err(), "{bad}");
        }
    }
}
