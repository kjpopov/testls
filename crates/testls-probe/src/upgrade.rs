//! In-band TLS upgrades over plaintext HTTP (RFC 2817).
//!
//! A server that answers `Upgrade: TLS/1.0` with `101 Switching Protocols`
//! lets a network attacker splice plaintext HTTP into what the client
//! believes is an HTTPS session (the Opossum attack, Dahlke et al.,
//! USENIX Security 2024). One `OPTIONS *` request with the upgrade headers
//! (RFC 2817 §3.2) is sent in plaintext to the scanned port and to port 80
//! of the same address; the reply head is read and the connection closed.

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::http::{complete_head, parse_head};
use crate::{ProbeError, Transport};

/// Plaintext HTTP port probed besides the scanned one.
const HTTP_PORT: u16 = 80;

/// Whether one port accepted an RFC 2817 upgrade to TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsUpgrade {
    /// Port the plaintext request went to.
    pub port: u16,
    /// `Some(true)` when the server answered `101 Switching Protocols` to
    /// TLS, `Some(false)` when it answered otherwise, closed the connection
    /// without a reply or refused a direct connection, `None` when the
    /// connect or reply timed out, the proxy could not reach it, or the
    /// connection failed after it was opened or mid-reply.
    pub accepted: Option<bool>,
}

/// Offers an RFC 2817 upgrade to TLS on the scanned port and on port 80.
///
/// `sni` names the `Host`; the IP address is used without it. Costs at most
/// two connections, made sequentially.
pub async fn probe_tls_upgrade(transport: &Transport, sni: Option<&str>) -> Vec<TlsUpgrade> {
    if transport.addr.port() == HTTP_PORT {
        return vec![upgrade_on(transport, sni).await];
    }
    let mut plain = transport.clone();
    plain.addr.set_port(HTTP_PORT);
    vec![
        upgrade_on(transport, sni).await,
        upgrade_on(&plain, sni).await,
    ]
}

/// Sends the upgrade request to [`Transport::addr`] and classifies the
/// reply.
async fn upgrade_on(transport: &Transport, sni: Option<&str>) -> TlsUpgrade {
    let port = transport.addr.port();
    let result = request_upgrade(transport, sni).await;
    TlsUpgrade {
        port,
        accepted: classify(result, transport.proxy.is_some()),
    }
}

/// Maps the outcome of [`request_upgrade`] to [`TlsUpgrade::accepted`].
fn classify(result: Result<bool, ProbeError>, proxied: bool) -> Option<bool> {
    match result {
        Ok(accepted) => Some(accepted),
        // Nothing listens there; through a proxy the proxy may be to blame,
        // and a timeout may be a firewall hiding a listener.
        Err(ProbeError::Connect(e)) if !proxied && e.kind() == io::ErrorKind::ConnectionRefused => {
            Some(false)
        }
        Err(_) => None,
    }
}

/// Whether the server switches to TLS after `OPTIONS *` with
/// `Upgrade: TLS/1.0` and `Connection: Upgrade` (RFC 2817 §3.2, §3.3).
/// A reply that is not HTTP, such as a TLS alert, or a connection closed
/// without a reply counts as a refusal.
///
/// # Errors
/// Returns a [`ProbeError`] on connect or I/O failure, on timeout and when
/// an HTTP reply head is cut short or too large.
async fn request_upgrade(transport: &Transport, sni: Option<&str>) -> Result<bool, ProbeError> {
    let mut stream = transport.connect().await?;
    let request = format!(
        "OPTIONS * HTTP/1.1\r\nHost: {}\r\nUser-Agent: testls/{}\r\nUpgrade: TLS/1.0\r\nConnection: Upgrade\r\n\r\n",
        host(transport, sni),
        env!("CARGO_PKG_VERSION"),
    );
    timeout(transport.read_timeout, async {
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(ProbeError::Io)?;
        let mut head = Vec::new();
        let mut buf = [0; 4096];
        loop {
            match complete_head(&head) {
                Ok(Some(end)) => return Ok(switches_to_tls(&head[..end])),
                Ok(None) => {}
                Err(e) if is_http_prefix(&head) => return Err(e),
                Err(_) => return Ok(false),
            }
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => 0,
                Err(e) => return Err(ProbeError::Io(e)),
            };
            if n == 0 {
                return if is_http_prefix(&head) {
                    Err(ProbeError::Unexpected(
                        "connection closed inside the reply head",
                    ))
                } else {
                    Ok(false)
                };
            }
            head.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .map_err(|_| ProbeError::Timeout)?
}

/// Whether `head` is a non-empty start of an HTTP reply, so a close here
/// cuts the reply short.
fn is_http_prefix(head: &[u8]) -> bool {
    const HTTP: &[u8] = b"HTTP/";
    !head.is_empty() && (head.starts_with(HTTP) || HTTP.starts_with(head))
}

/// Whether `head` is `101 Switching Protocols` naming a `TLS/` protocol in
/// `Upgrade` (RFC 9110 §7.8).
fn switches_to_tls(head: &[u8]) -> bool {
    let Ok(response) = parse_head(head) else {
        return false;
    };
    response.status == 101
        && response
            .header_values("upgrade")
            .flat_map(|v| v.split(','))
            .any(|p| {
                p.trim_matches([' ', '\t'])
                    .get(..4)
                    .is_some_and(|t| t.eq_ignore_ascii_case("tls/"))
            })
}

/// Value of the `Host` header: the SNI name or the IP, with IPv6 in
/// brackets, plus the port when it is not 80.
fn host(transport: &Transport, sni: Option<&str>) -> String {
    let host = match (sni, transport.addr.ip()) {
        (Some(name), _) => name.to_owned(),
        (None, std::net::IpAddr::V4(ip)) => ip.to_string(),
        (None, std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
    };
    match transport.addr.port() {
        HTTP_PORT => host,
        port => format!("{host}:{port}"),
    }
}

#[cfg(test)]
mod tests {
    //! Upgrade probes against in-process plaintext servers.

    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::net::TcpListener;

    /// Starts a one-shot server that reads the request head, answers with
    /// `reply` and returns the request.
    async fn serve(reply: &'static [u8]) -> (SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut buf).await.unwrap();
                request.extend_from_slice(&buf[..n]);
            }
            s.write_all(reply).await.unwrap();
            String::from_utf8(request).unwrap()
        });
        (addr, task)
    }

    /// A 101 reply to TLS is an accepted upgrade; the request carries the
    /// RFC 2817 headers and the `Host` with port.
    #[tokio::test]
    async fn accepted_upgrade() {
        let (addr, task) = serve(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: TLS/1.0, HTTP/1.1\r\nConnection: Upgrade\r\n\r\n",
        )
        .await;
        let r = upgrade_on(&Transport::new(addr), Some("example.com")).await;
        assert_eq!(
            r,
            TlsUpgrade {
                port: addr.port(),
                accepted: Some(true)
            }
        );
        let request = task.await.unwrap();
        assert!(request.starts_with("OPTIONS * HTTP/1.1\r\n"), "{request}");
        assert!(
            request.contains(&format!("\r\nHost: example.com:{}\r\n", addr.port())),
            "{request}"
        );
        assert!(request.contains("\r\nUpgrade: TLS/1.0\r\n"), "{request}");
        assert!(request.contains("\r\nConnection: Upgrade\r\n"), "{request}");
    }

    /// Other statuses, upgrades to other protocols, non-HTTP replies and
    /// closed connections are refusals.
    #[tokio::test]
    async fn refused_upgrade() {
        for reply in [
            &b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"[..],
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n",
            b"\x15\x03\x01\x00\x02\x02\x46",
            b"",
        ] {
            let (addr, _task) = serve(reply).await;
            let r = upgrade_on(&Transport::new(addr), None).await;
            assert_eq!(r.accepted, Some(false), "{reply:?}");
        }
    }

    /// A port that refuses the connection is a refusal; a silent server and
    /// a reply head cut short are failed probes.
    #[tokio::test]
    async fn unreachable_and_silent() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed = listener.local_addr().unwrap();
        drop(listener);
        let r = upgrade_on(&Transport::new(closed), None).await;
        assert_eq!(r.accepted, Some(false));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut transport = Transport::new(listener.local_addr().unwrap());
        transport.read_timeout = Duration::from_millis(100);
        let _hold = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // Read until the probe gives up and closes.
            while s.read(&mut [0; 1024]).await.is_ok_and(|n| n > 0) {}
        });
        let r = tokio::time::timeout(Duration::from_secs(5), upgrade_on(&transport, None))
            .await
            .expect("probe must enforce read_timeout");
        assert_eq!(r.accepted, None);

        for reply in [&b"HTTP/1.1 101 Switching"[..], b"HTT"] {
            let (addr, _task) = serve(reply).await;
            let r = upgrade_on(&Transport::new(addr), None).await;
            assert_eq!(r.accepted, None, "{reply:?}");
        }
    }

    /// Only a refused direct connect is a refusal; connect timeouts and
    /// proxy failures leave the port untested.
    #[test]
    fn connect_errors() {
        let refused = || ProbeError::Connect(io::ErrorKind::ConnectionRefused.into());
        let timed_out = || ProbeError::Connect(io::ErrorKind::TimedOut.into());
        assert_eq!(classify(Err(refused()), false), Some(false));
        assert_eq!(classify(Err(refused()), true), None);
        assert_eq!(classify(Err(timed_out()), false), None);
        assert_eq!(classify(Err(ProbeError::Timeout), false), None);
        assert_eq!(classify(Ok(true), true), Some(true));
    }

    /// An HTTP reply head beyond the size limit leaves the port untested;
    /// oversized non-HTTP data is a refusal.
    #[tokio::test]
    async fn oversized_reply() {
        let http: &'static [u8] = format!("HTTP/1.1 101 Switching\r\nX: {}", "a".repeat(70_000))
            .into_bytes()
            .leak();
        let binary: &'static [u8] = vec![0x16; 70_000].leak();
        for (reply, expected) in [(http, None), (binary, Some(false))] {
            let (addr, _task) = serve(reply).await;
            let r = upgrade_on(&Transport::new(addr), None).await;
            assert_eq!(r.accepted, expected);
        }
    }

    /// Only non-empty starts of `HTTP/` count as a reply head.
    #[test]
    fn http_prefix() {
        assert!(is_http_prefix(b"H"));
        assert!(is_http_prefix(b"HTTP/1.1 200"));
        assert!(!is_http_prefix(b""));
        assert!(!is_http_prefix(b"\x15\x03\x01"));
    }

    /// The scanned port and port 80 are both probed, once each.
    #[tokio::test]
    async fn probes_scanned_port_and_port_80() {
        let (addr, _task) =
            serve(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: TLS/1.2\r\n\r\n").await;
        let mut transport = Transport::new(addr);
        transport.connect_timeout = Duration::from_millis(500);
        transport.read_timeout = Duration::from_millis(500);
        let list = probe_tls_upgrade(&transport, None).await;
        assert_eq!(list.len(), 2);
        assert_eq!(
            list[0],
            TlsUpgrade {
                port: addr.port(),
                accepted: Some(true)
            }
        );
        assert_eq!(list[1].port, 80);
    }

    /// A reset without a reply and an unparsable HTTP head are refusals.
    #[tokio::test]
    async fn reset_and_garbled_head() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut first = [0; 1];
            s.read_exact(&mut first).await.unwrap();
            // Closing with unread data makes the kernel send a reset.
            drop(s);
        });
        let r = upgrade_on(&Transport::new(addr), None).await;
        assert_eq!(r.accepted, Some(false));

        let (addr, _task) = serve(b"HTTP/1.1 abc Weird\r\n\r\n").await;
        let r = upgrade_on(&Transport::new(addr), None).await;
        assert_eq!(r.accepted, Some(false));
    }

    /// Scanning port 80 itself probes it only once.
    #[tokio::test]
    async fn port_80_probed_once() {
        let mut transport = Transport::new("127.0.0.1:80".parse().unwrap());
        transport.connect_timeout = Duration::from_millis(200);
        transport.read_timeout = Duration::from_millis(200);
        let list = probe_tls_upgrade(&transport, None).await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].port, 80);
    }

    /// `Host` omits port 80 and brackets IPv6 addresses.
    #[test]
    fn host_header() {
        let t = Transport::new("[::1]:80".parse().unwrap());
        assert_eq!(host(&t, None), "[::1]");
        let t = Transport::new("192.0.2.1:8080".parse().unwrap());
        assert_eq!(host(&t, None), "192.0.2.1:8080");
        assert_eq!(host(&t, Some("a.example")), "a.example:8080");
    }
}
