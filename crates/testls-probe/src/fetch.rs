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
#[derive(Debug, Clone, Copy)]
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
    /// HTTP proxy to tunnel through with `CONNECT`; the proxy then
    /// resolves the host name. Direct when `None`.
    pub proxy: Option<SocketAddr>,
    /// Whether endpoints on loopback, private, link-local and other
    /// non-public addresses may be contacted. The scanned server's
    /// certificate chooses the URLs, so they are refused by default.
    pub allow_private: bool,
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
    ///
    /// Unless [`Fetcher::allow_private`] is set, non-public addresses are
    /// skipped. Through a proxy, which resolves names itself, only IP
    /// literals and `localhost` names can be checked.
    async fn connect(&self, url: &HttpUrl) -> Result<TcpStream, ProbeError> {
        if !self.allow_private && local_host(&url.host) {
            return Err(blocked());
        }
        if let Some(proxy) = self.proxy {
            let host = if url.host.contains(':') {
                format!("[{}]", url.host)
            } else {
                url.host.clone()
            };
            let authority = format!("{host}:{}", url.port);
            return crate::tunnel(proxy, self.source, self.connect_timeout, &authority).await;
        }
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
            if !self.allow_private && !public_address(addr.ip()) {
                last.get_or_insert_with(blocked);
                continue;
            }
            if self.source.is_some_and(|ip| ip.is_ipv4() != addr.is_ipv4()) {
                skipped = true;
                continue;
            }
            match crate::connect(addr, self.source, self.connect_timeout).await {
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

/// Error for an endpoint refused by the non-public address guard.
fn blocked() -> ProbeError {
    ProbeError::Unexpected("non-public address refused")
}

/// Reports whether `host` is visibly local without resolving it: a
/// non-public IP literal, a `localhost` name (RFC 6761 §6.3), a scoped
/// address (`%`) or a non-canonical numeric form such as `127.1`, which
/// `inet_aton`-style resolvers read as an IPv4 address.
fn local_host(host: &str) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return !public_address(ip);
    }
    let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    name == "localhost"
        || name.ends_with(".localhost")
        || name.contains('%')
        || ends_in_number(&name)
}

/// Reports whether the last label is numeric (decimal, octal or `0x` hex),
/// so the host parses as an IPv4 address rather than a domain name (WHATWG
/// URL Standard, "ends in a number"). No top-level domain is numeric.
fn ends_in_number(name: &str) -> bool {
    let last = name.rsplit('.').next().unwrap_or(name);
    !last.is_empty()
        && (last.bytes().all(|b| b.is_ascii_digit())
            || last
                .strip_prefix("0x")
                .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit())))
}

/// Reports whether `ip` is a public unicast address.
///
/// Blocks the IANA IPv4 and IPv6 Special-Purpose Address Registries
/// (RFC 6890 and updates), multicast and reserved space, and IPv6 outside
/// global unicast `2000::/3`. IPv4-mapped (RFC 4291 §2.5.5.2) and NAT64
/// well-known-prefix (RFC 6052 §2.1) addresses are judged by their embedded
/// IPv4 address; 6to4 and Teredo prefixes are blocked.
#[must_use]
pub fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(matches!(a, 0 | 10 | 127 | 224..=255)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 0 && (c == 0 || c == 2))
                || (a == 192 && b == 88 && c == 99)
                || (a == 192 && b == 168)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return public_address(IpAddr::V4(v4));
            }
            if let [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, a, b, c, d] = ip.octets() {
                return public_address(IpAddr::V4([a, b, c, d].into()));
            }
            let [first, second, ..] = ip.segments();
            (0x2000..=0x3fff).contains(&first)
                && !(first == 0x2001 && (second < 0x0200 || second == 0x0db8))
                && first != 0x2002
                && !(first == 0x3fff && second < 0x1000)
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
            allow_private: true,
        }
    }

    /// Special-purpose addresses are not public; embedded IPv4 addresses
    /// are judged on their own.
    #[test]
    fn public_addresses() {
        for ip in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:10.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001::1",
            "2001:db8::1",
            "2002:7f00:1::",
            "3fff::1",
        ] {
            assert!(!public_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "172.32.0.1",
            "192.0.1.1",
            "192.0.3.1",
            "192.1.0.1",
            "198.20.0.1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
        ] {
            assert!(public_address(ip.parse().unwrap()), "{ip}");
        }
    }

    /// Local names and non-public literals are recognised without a lookup.
    #[test]
    fn local_hosts() {
        for host in [
            "localhost",
            "LOCALHOST.",
            "ocsp.localhost",
            "127.0.0.2",
            "fd00::1",
            "127.1",
            "2130706433",
            "0x7f000001",
            "0177.0.0.1",
            "fe80::1%1",
            "134744072",
        ] {
            assert!(local_host(host), "{host}");
        }
        for host in [
            "ocsp.example",
            "localhost.example",
            "8.8.8.8",
            "0x.example",
            "ocsp1.example",
        ] {
            assert!(!local_host(host), "{host}");
        }
    }

    /// Without `allow_private`, non-public endpoints are refused before any
    /// connection, directly and through a proxy.
    #[tokio::test]
    async fn private_endpoints_are_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        for proxy in [None, Some(addr)] {
            let guarded = Fetcher {
                proxy,
                allow_private: false,
                ..fetcher()
            };
            for url in [
                format!("http://{addr}/"),
                format!("http://localhost:{}/", addr.port()),
            ] {
                let e = guarded.get(&url).await.unwrap_err();
                assert!(
                    e.to_string().contains("non-public address refused"),
                    "{url}: {e}"
                );
            }
        }
        let accepted = timeout(Duration::from_millis(50), listener.accept()).await;
        assert!(accepted.is_err(), "a connection was opened");
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
        let r = fetcher()
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
        let r = fetcher()
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
        let r = fetcher().get(&format!("http://{addr}/")).await.unwrap();
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
        let r = fetcher.get(&format!("http://{addr}/")).await.unwrap();
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
        let r = fetcher().get(&format!("http://{addr}/")).await.unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(r.body, b"");
    }

    /// With a source address, requests connect from it and resolved
    /// addresses of the other family are skipped.
    #[tokio::test]
    async fn source_address() {
        let (addr, _task) = serve(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()).await;
        let from_v4 = Fetcher {
            source: Some("127.0.0.1".parse().unwrap()),
            ..fetcher()
        };
        let r = from_v4.get(&format!("http://{addr}/")).await.unwrap();
        assert_eq!(r.status, 204);
        let from_v6 = Fetcher {
            source: Some("::1".parse().unwrap()),
            ..fetcher()
        };
        let r = from_v6.get(&format!("http://{addr}/")).await;
        assert!(
            matches!(r, Err(ProbeError::Unexpected(m)) if m.contains("address family")),
            "{r:?}"
        );
    }

    /// With a proxy, the host name is sent unresolved in `CONNECT` and the
    /// request goes through the tunnel. The proxy itself may be local even
    /// when non-public endpoints are refused.
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
            allow_private: false,
            ..fetcher()
        };
        let r = via_proxy.get("http://ocsp.invalid:8080/x").await.unwrap();
        assert_eq!(r.status, 204);
        let seen = task.await.unwrap();
        assert!(
            seen.starts_with("CONNECT ocsp.invalid:8080 HTTP/1.1\r\n"),
            "{seen}"
        );
        assert!(
            seen.contains("GET /x HTTP/1.1\r\nHost: ocsp.invalid:8080\r\n"),
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
        let r = fetcher().get(&format!("http://{addr}/")).await.unwrap();
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
            let r = fetcher().get(&format!("http://{addr}/")).await.unwrap();
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
            let r = fetcher().get(&format!("http://{addr}/")).await;
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
