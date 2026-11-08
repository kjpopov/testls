//! Async TLS probes over TCP built on testls-wire.

mod certificates;
mod ciphers;
mod details;
mod features;
mod fetch;
mod groups;
pub mod hello;
mod http;
mod intolerance;
mod mx;
mod protocols;
mod response;
mod starttls;
mod upgrade;

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

pub use certificates::{CertificateChain, fetch_certificates};
pub use ciphers::{CipherOrder, CipherResult, enumerate_ciphers};
pub use details::{HandshakeDetails, probe_details};
pub use features::{HandshakeFeatures, probe_features};
pub use fetch::{Fetcher, HttpBody, public_address};
pub use groups::{KeyExchangeResult, probe_key_exchange};
pub use http::{HttpResponse, fetch_http_headers};
pub use intolerance::{Intolerance, probe_intolerance};
pub use mx::{MxError, MxResolver};
pub use protocols::{ProtocolResult, ProtocolSupport, classify, detect_protocols, probe_protocol};
pub use response::HelloResponse;
use response::ResponseParser;
pub use starttls::Starttls;
use testls_wire::{DecodeError, EncodeError};
pub use upgrade::{TlsUpgrade, probe_tls_upgrade};

/// Error from a single probe.
#[derive(Debug)]
pub enum ProbeError {
    /// TCP connect failed.
    Connect(io::Error),
    /// Reading or writing the socket failed.
    Io(io::Error),
    /// The operation did not complete within the configured timeout.
    Timeout,
    /// The hello could not be encoded.
    Encode(EncodeError),
    /// The server sent bytes that are not a valid TLS/SSL reply.
    Decode(DecodeError),
    /// The server behaved inconsistently across probes.
    Unexpected(&'static str),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "connect failed: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Timeout => f.write_str("timed out"),
            Self::Encode(e) => write!(f, "cannot encode hello: {e}"),
            Self::Decode(e) => write!(f, "malformed server reply: {e}"),
            Self::Unexpected(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ProbeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(e) | Self::Io(e) => Some(e),
            Self::Timeout | Self::Unexpected(_) => None,
            Self::Encode(e) => Some(e),
            Self::Decode(e) => Some(e),
        }
    }
}

/// Connection settings shared by all probes against one target.
#[derive(Debug, Clone)]
pub struct Transport {
    /// Address to connect to.
    pub addr: SocketAddr,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Timeout for the server to finish answering after the hello is sent.
    pub read_timeout: Duration,
    /// Local address to connect from; the OS picks one when `None`.
    pub source: Option<IpAddr>,
    /// HTTP proxy to tunnel through with `CONNECT`; direct when `None`.
    pub proxy: Option<SocketAddr>,
    /// Plain-text protocol to upgrade with STARTTLS before each hello;
    /// TLS from the first byte when `None`.
    pub starttls: Option<Starttls>,
    /// Server name for STARTTLS dialogues that need one (the XMPP `to`
    /// address); the IP address of [`Transport::addr`] when `None`.
    pub host: Option<String>,
}

impl Transport {
    /// Transport with 5 s connect and 10 s read timeouts, no fixed source
    /// address and no proxy.
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(10),
            source: None,
            proxy: None,
            starttls: None,
            host: None,
        }
    }

    /// Opens a TCP connection to [`Transport::addr`] from
    /// [`Transport::source`], through [`Transport::proxy`] when set, within
    /// the connect timeout, then runs the [`Transport::starttls`] dialogue
    /// within the read timeout.
    ///
    /// # Errors
    /// As for [`connect`] and [`tunnel`]; a failed or timed-out STARTTLS
    /// dialogue is also a [`ProbeError::Connect`].
    pub(crate) async fn connect(&self) -> Result<TcpStream, ProbeError> {
        let (mut stream, early) = self.open().await?;
        match (self.starttls, self.proxy) {
            (Some(starttls), _) => {
                let ip = self.addr.ip().to_string();
                let host = self.host.as_deref().unwrap_or(&ip);
                timeout(
                    self.read_timeout,
                    starttls.upgrade(&mut stream, early, host),
                )
                .await
                .map_err(|_| ProbeError::Connect(io::ErrorKind::TimedOut.into()))??;
            }
            (None, Some(proxy)) => reject_early(proxy, &early)?,
            (None, None) => {}
        }
        Ok(stream)
    }

    /// Opens the TCP connection, directly or through the proxy. Also
    /// returns any tunnel data the proxy relayed after its `CONNECT` reply.
    async fn open(&self) -> Result<(TcpStream, Vec<u8>), ProbeError> {
        match self.proxy {
            Some(proxy) => {
                tunnel_open(
                    proxy,
                    self.source,
                    self.connect_timeout,
                    &self.addr.to_string(),
                )
                .await
            }
            None => Ok((
                connect(self.addr, self.source, self.connect_timeout).await?,
                Vec::new(),
            )),
        }
    }

    /// Open a fresh connection, send an already encoded hello, and
    /// classify the server's answer.
    ///
    /// # Errors
    /// Returns a [`ProbeError`] on connect/I/O failure, timeout, or a reply
    /// that is not TLS/SSL. A connect timeout is a [`ProbeError::Connect`]
    /// with [`io::ErrorKind::TimedOut`], so callers can tell that no hello
    /// was sent.
    pub async fn exchange(&self, hello: &[u8]) -> Result<HelloResponse, ProbeError> {
        let mut stream = self.connect().await?;
        stream.set_nodelay(true).map_err(ProbeError::Io)?;
        timeout(self.read_timeout, async {
            stream.write_all(hello).await.map_err(ProbeError::Io)?;
            read_response(&mut stream).await
        })
        .await
        .map_err(|_| ProbeError::Timeout)?
    }
}

/// Connects to `addr`, binding the socket to `source` first when given.
///
/// # Errors
/// Returns [`ProbeError::Connect`] when binding or connecting fails, when
/// `source` and `addr` are from different address families, or with
/// [`io::ErrorKind::TimedOut`] when `connect_timeout` expires.
pub(crate) async fn connect(
    addr: SocketAddr,
    source: Option<IpAddr>,
    connect_timeout: Duration,
) -> Result<TcpStream, ProbeError> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(ProbeError::Connect)?;
    if let Some(ip) = source {
        if ip.is_ipv4() != addr.is_ipv4() {
            return Err(ProbeError::Connect(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("source address {ip} cannot reach {addr} (different address family)"),
            )));
        }
        socket
            .bind(SocketAddr::new(ip, 0))
            .map_err(ProbeError::Connect)?;
    }
    timeout(connect_timeout, socket.connect(addr))
        .await
        .map_err(|_| ProbeError::Connect(io::ErrorKind::TimedOut.into()))?
        .map_err(ProbeError::Connect)
}

/// Opens a tunnel to `authority` (`host:port`) through the HTTP proxy at
/// `proxy` with a `CONNECT` request (RFC 9110 §9.3.6), all within
/// `connect_timeout`.
///
/// # Errors
/// Returns [`ProbeError::Connect`] when the proxy cannot be reached, its
/// reply is malformed or not 2xx, it sends bytes after the reply head, or
/// with [`io::ErrorKind::TimedOut`] when `connect_timeout` expires.
pub(crate) async fn tunnel(
    proxy: SocketAddr,
    source: Option<IpAddr>,
    connect_timeout: Duration,
    authority: &str,
) -> Result<TcpStream, ProbeError> {
    let (stream, early) = tunnel_open(proxy, source, connect_timeout, authority).await?;
    // A client-first tunnel carries nothing before our first write.
    reject_early(proxy, &early)?;
    Ok(stream)
}

/// Fails when the proxy relayed `early` bytes before our first write.
fn reject_early(proxy: SocketAddr, early: &[u8]) -> Result<(), ProbeError> {
    if early.is_empty() {
        Ok(())
    } else {
        Err(ProbeError::Connect(io::Error::other(format!(
            "proxy {proxy} sent data after its CONNECT reply"
        ))))
    }
}

/// Like [`tunnel`], but returns the bytes that arrived after the reply head
/// instead of rejecting them (RFC 9110 §9.3.6: they are tunnel data, such
/// as a server-first protocol's greeting).
///
/// # Errors
/// As for [`tunnel`], except for early tunnel data.
async fn tunnel_open(
    proxy: SocketAddr,
    source: Option<IpAddr>,
    connect_timeout: Duration,
    authority: &str,
) -> Result<(TcpStream, Vec<u8>), ProbeError> {
    let proxy_error = |msg: String| ProbeError::Connect(io::Error::other(msg));
    timeout(connect_timeout, async {
        let mut stream = connect(proxy, source, connect_timeout).await?;
        let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(ProbeError::Connect)?;
        let mut data = Vec::new();
        let mut buf = [0; 1024];
        let end = loop {
            let n = stream.read(&mut buf).await.map_err(ProbeError::Connect)?;
            if n == 0 {
                return Err(proxy_error(format!(
                    "proxy {proxy} closed the connection during CONNECT"
                )));
            }
            data.extend_from_slice(&buf[..n]);
            match http::complete_head(&data) {
                Ok(Some(end)) => break end,
                Ok(None) => {}
                Err(e) => return Err(proxy_error(format!("proxy {proxy}: {e}"))),
            }
        };
        let head = http::parse_head(&data[..end])
            .map_err(|e| proxy_error(format!("proxy {proxy}: {e}")))?;
        if !(200..300).contains(&head.status) {
            return Err(proxy_error(format!(
                "proxy {proxy} refused CONNECT {authority} with status {}",
                head.status
            )));
        }
        data.drain(..end);
        Ok((stream, data))
    })
    .await
    .map_err(|_| ProbeError::Connect(io::ErrorKind::TimedOut.into()))?
}

async fn read_response(stream: &mut TcpStream) -> Result<HelloResponse, ProbeError> {
    let mut parser = ResponseParser::new();
    let mut buf = vec![0; 16 * 1024];
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(n) => n,
            // A reset right after our hello is how many servers say "no".
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => 0,
            Err(e) => return Err(ProbeError::Io(e)),
        };
        if n == 0 {
            return Ok(parser.finish());
        }
        if let Some(r) = parser.push(&buf[..n]).map_err(ProbeError::Decode)? {
            return Ok(r);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn serve(reply: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0; 512];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(reply).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn alert_reply() {
        let addr = serve(&[21, 3, 3, 0, 2, 2, 70]).await;
        let r = Transport::new(addr).exchange(b"hello").await.unwrap();
        assert!(matches!(r, HelloResponse::Alert(a) if a.description == 70));
    }

    #[tokio::test]
    async fn silent_close() {
        let addr = serve(&[]).await;
        let r = Transport::new(addr).exchange(b"hello").await.unwrap();
        assert_eq!(r, HelloResponse::Closed);
    }

    #[tokio::test]
    async fn timeout_when_server_stalls() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let mut t = Transport::new(addr);
        t.read_timeout = Duration::from_millis(100);
        assert!(matches!(t.exchange(b"x").await, Err(ProbeError::Timeout)));
    }

    /// A source address is bound before connecting; one of the other
    /// address family is rejected without connecting.
    #[tokio::test]
    async fn source_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move { listener.accept().await.unwrap().1 });
        let mut t = Transport::new(addr);
        t.source = Some("127.0.0.1".parse().unwrap());
        let stream = t.connect().await.unwrap();
        assert_eq!(peer.await.unwrap(), stream.local_addr().unwrap());
        assert_eq!(stream.local_addr().unwrap().ip(), t.source.unwrap());

        t.source = Some("::1".parse().unwrap());
        let Err(ProbeError::Connect(e)) = t.connect().await else {
            panic!("connected across address families");
        };
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("different address family"), "{e}");
    }

    /// Fake HTTP proxy that answers the `CONNECT` head with `reply`, then
    /// plays the TLS server by answering the hello with `server_reply`.
    /// Returns its address and the received `CONNECT` head.
    async fn proxy(
        reply: &'static [u8],
        server_reply: &'static [u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0; 512];
            while !head.ends_with(b"\r\n\r\n") {
                let n = s.read(&mut buf).await.unwrap();
                assert_ne!(n, 0, "client closed before finishing CONNECT");
                head.extend_from_slice(&buf[..n]);
            }
            s.write_all(reply).await.unwrap();
            if !server_reply.is_empty() {
                let _ = s.read(&mut buf).await.unwrap();
                s.write_all(server_reply).await.unwrap();
            }
            String::from_utf8(head).unwrap()
        });
        (addr, task)
    }

    /// Probes go through the proxy's tunnel to the target address.
    #[tokio::test]
    async fn proxy_tunnel() {
        let (proxy, head) = proxy(
            b"HTTP/1.1 200 Connection established\r\n\r\n",
            &[21, 3, 3, 0, 2, 2, 70],
        )
        .await;
        let mut t = Transport::new("[2001:db8::1]:8443".parse().unwrap());
        t.proxy = Some(proxy);
        let r = t.exchange(b"hello").await.unwrap();
        assert!(matches!(r, HelloResponse::Alert(a) if a.description == 70));
        assert_eq!(
            head.await.unwrap(),
            "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n\r\n"
        );
    }

    /// With STARTTLS the hello follows the upgrade dialogue on the same
    /// connection.
    #[tokio::test]
    async fn starttls_exchange() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0; 512];
            s.write_all(b"220 hi\r\n").await.unwrap();
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(b"250-mx\r\n250 STARTTLS\r\n").await.unwrap();
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(b"220 go\r\n").await.unwrap();
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(&[21, 3, 3, 0, 2, 2, 70]).await.unwrap();
            buf[..n].to_vec()
        });
        let mut t = Transport::new(addr);
        t.starttls = Some(Starttls::Smtp);
        let r = t.exchange(b"hello").await.unwrap();
        assert!(matches!(r, HelloResponse::Alert(a) if a.description == 70));
        assert_eq!(task.await.unwrap(), b"hello");
    }

    /// XMPP addresses the stream to [`Transport::host`], or to the IP
    /// address without one.
    #[tokio::test]
    async fn starttls_xmpp_host() {
        for (host, expected) in [
            (Some("example.org"), "to='example.org'"),
            (None, "to='127.0.0.1'"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0; 512];
                let n = s.read(&mut buf).await.unwrap();
                s.write_all(b"<stream:error><host-unknown/></stream:error>")
                    .await
                    .unwrap();
                String::from_utf8_lossy(&buf[..n]).into_owned()
            });
            let mut t = Transport::new(addr);
            t.starttls = Some(Starttls::Xmpp);
            t.host = host.map(str::to_owned);
            let Err(ProbeError::Connect(e)) = t.exchange(b"hello").await else {
                panic!("unknown host accepted");
            };
            assert!(e.to_string().contains("host-unknown"), "{e}");
            let sent = task.await.unwrap();
            assert!(sent.contains(expected), "{sent}");
        }
    }

    /// Through a proxy, a greeting that arrives with the `CONNECT` reply
    /// feeds the STARTTLS dialogue instead of failing the tunnel.
    #[tokio::test]
    async fn starttls_proxy_greeting() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0; 512];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\n\r\n220 hi\r\n")
                .await
                .unwrap();
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(b"250-mx\r\n250 STARTTLS\r\n").await.unwrap();
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(b"220 go\r\n").await.unwrap();
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(&[21, 3, 3, 0, 2, 2, 70]).await.unwrap();
            buf[..n].to_vec()
        });
        let mut t = Transport::new("192.0.2.1:25".parse().unwrap());
        t.proxy = Some(addr);
        t.starttls = Some(Starttls::Smtp);
        let r = t.exchange(b"hello").await.unwrap();
        assert!(matches!(r, HelloResponse::Alert(a) if a.description == 70));
        assert_eq!(task.await.unwrap(), b"hello");
    }

    /// A server that stalls during STARTTLS gives a connect timeout, so
    /// callers know no hello was sent.
    #[tokio::test]
    async fn starttls_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let mut t = Transport::new(addr);
        t.read_timeout = Duration::from_millis(100);
        t.starttls = Some(Starttls::Smtp);
        let Err(ProbeError::Connect(e)) = t.exchange(b"x").await else {
            panic!("stalled STARTTLS did not time out");
        };
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    }

    /// A refused or garbled `CONNECT` is a connect error.
    #[tokio::test]
    async fn proxy_errors() {
        for (reply, expected) in [
            (&b"HTTP/1.1 403 Forbidden\r\n\r\n"[..], "status 403"),
            (b"SSH-2.0-nope\r\n\r\n", "not an HTTP/1.x response"),
            (
                b"HTTP/1.1 200 OK\r\n\r\nextra",
                "data after its CONNECT reply",
            ),
            (b"HTTP/1.1 200 OK\r\n", "closed the connection"),
        ] {
            let (proxy, _head) = proxy(reply, &[]).await;
            let mut t = Transport::new("192.0.2.1:443".parse().unwrap());
            t.proxy = Some(proxy);
            let Err(ProbeError::Connect(e)) = t.exchange(b"hello").await else {
                panic!("tunnel accepted {reply:?}");
            };
            assert!(e.to_string().contains(expected), "{e}");
        }
    }
}
