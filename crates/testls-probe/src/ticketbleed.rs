//! Opt-in Ticketbleed probe (CVE-2016-9244, RFC 5077 §3.4).
//!
//! See the original disclosure: <https://ticketbleed.com/>.
//! A TLS 1.2 ticket is obtained with a complete handshake. A subsequent
//! resumption offers a 31-byte session ID, limiting excess output to one byte.

use std::io::Cursor;
use std::sync::Arc;

use rustls::ClientConnection;
use rustls::pki_types::ServerName;
use testls_wire::{
    AnyRecord, ContentType, Extension, ProtocolVersion, ServerHello, parse_handshake, parse_record,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::{ProbeError, Transport, certificates::tls12_client_config, hello::client_hello};

/// Bound data retained while reading either handshake.
const LIMIT: usize = 1024 * 1024;

/// Outcome of a completed Ticketbleed resumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketbleedVerdict {
    /// The server extended the 31-byte session ID: possible memory exposure.
    ExtendedId,
    /// The server echoed the session ID unchanged, as RFC 5077 §3.4 requires.
    EchoedId,
}

/// Tests for an extended session ID during TLS 1.2 ticket resumption.
///
/// [`TicketbleedVerdict::ExtendedId`] indicates a possible disclosure, not
/// proof of the origin of the extra byte. No returned data contains the byte
/// or ticket.
///
/// # Errors
/// Returns an error for unsupported handshakes, refusal, malformed or
/// mismatched responses, and timeouts; these do not establish that the server
/// is safe.
pub async fn probe_ticketbleed(
    transport: &Transport,
    sni: Option<&str>,
) -> Result<TicketbleedVerdict, ProbeError> {
    let (ticket, initial) = obtain_ticket(transport, sni).await?;
    let mut marker = [0_u8; 31];
    getrandom::fill(&mut marker).map_err(|_| ProbeError::Unexpected("session ID RNG failed"))?;
    let mut hello = client_hello(ProtocolVersion::TLS12, vec![initial.cipher_suite], sni);
    hello.session_id = marker.to_vec();
    hello.extensions.push(Extension::Raw {
        typ: 35,
        data: ticket,
    });
    if initial.extension(23).is_some() {
        hello.extensions.push(Extension::Raw {
            typ: 23,
            data: vec![],
        });
    }
    let bytes = hello.encode().map_err(ProbeError::Encode)?;
    let mut stream = transport.connect().await?;
    timeout(transport.read_timeout, async {
        stream.write_all(&bytes).await.map_err(ProbeError::Io)?;
        let mut input = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let n = stream.read(&mut buf).await.map_err(ProbeError::Io)?;
            if n == 0 {
                return Err(ProbeError::Unexpected("peer closed before resumption"));
            }
            input.extend_from_slice(&buf[..n]);
            if input.len() > LIMIT {
                return Err(ProbeError::Unexpected("resumption exceeds probe limit"));
            }
            if let Some(verdict) = resumed(&input, &marker, initial.cipher_suite)? {
                return Ok(verdict);
            }
        }
    })
    .await
    .map_err(|_| ProbeError::Timeout)?
}

/// Complete a TLS 1.2 handshake and capture its plaintext session ticket.
async fn obtain_ticket(
    transport: &Transport,
    sni: Option<&str>,
) -> Result<(Vec<u8>, ServerHello), ProbeError> {
    let name = match sni {
        Some(name) => ServerName::try_from(name.to_owned())
            .map_err(|_| ProbeError::Unexpected("invalid SNI"))?,
        None => ServerName::from(transport.addr.ip()),
    };
    let mut conn = ClientConnection::new(Arc::new(tls12_client_config()), name)
        .map_err(|_| ProbeError::Unexpected("could not initialize TLS"))?;
    let mut stream = transport.connect().await?;
    timeout(transport.read_timeout, async {
        let mut captured = Vec::new();
        let mut buf = [0; 4096];
        while conn.is_handshaking() {
            while conn.wants_write() {
                let mut out = Vec::new();
                conn.write_tls(&mut out).map_err(ProbeError::Io)?;
                stream.write_all(&out).await.map_err(ProbeError::Io)?;
            }
            if !conn.is_handshaking() {
                break;
            }
            let n = stream.read(&mut buf).await.map_err(ProbeError::Io)?;
            if n == 0 {
                return Err(ProbeError::Unexpected(
                    "peer closed during ticket handshake",
                ));
            }
            captured.extend_from_slice(&buf[..n]);
            if captured.len() > LIMIT {
                return Err(ProbeError::Unexpected(
                    "ticket handshake exceeds probe limit",
                ));
            }
            conn.read_tls(&mut Cursor::new(&buf[..n]))
                .map_err(ProbeError::Io)?;
            conn.process_new_packets()
                .map_err(|_| ProbeError::Unexpected("ticket handshake failed"))?;
        }
        extract_ticket(&captured)
    })
    .await
    .map_err(|_| ProbeError::Timeout)?
}

/// Extracts the initial hello and ticket from plaintext records before CCS.
fn extract_ticket(bytes: &[u8]) -> Result<(Vec<u8>, ServerHello), ProbeError> {
    let mut records = bytes;
    let mut handshake = Vec::new();
    while let Some((record, used)) = parse_record(records).map_err(ProbeError::Decode)? {
        records = &records[used..];
        match record {
            AnyRecord::Tls(r) if r.content_type == ContentType::Handshake => {
                handshake.extend_from_slice(r.fragment);
            }
            AnyRecord::Tls(r) if r.content_type == ContentType::ChangeCipherSpec => break,
            _ => return Err(ProbeError::Unexpected("unexpected ticket handshake record")),
        }
    }
    let mut messages = handshake.as_slice();
    let mut hello = None;
    let mut ticket = None;
    while let Some((msg, used)) = parse_handshake(messages).map_err(ProbeError::Decode)? {
        match msg.typ {
            2 if hello.is_none() => {
                hello = Some(ServerHello::parse(msg.body).map_err(ProbeError::Decode)?);
            }
            4 if msg.body.len() >= 6 => {
                let len = usize::from(u16::from_be_bytes([msg.body[4], msg.body[5]]));
                if len > 0 && msg.body.len() == 6 + len {
                    ticket = Some(msg.body[6..].to_vec());
                }
            }
            _ => {}
        }
        messages = &messages[used..];
    }
    let hello = hello.ok_or(ProbeError::Unexpected("missing initial server hello"))?;
    if hello.negotiated_version().map_err(ProbeError::Decode)? != ProtocolVersion::TLS12 {
        return Err(ProbeError::Unexpected("ticket handshake was not TLS 1.2"));
    }
    Ok((
        ticket.ok_or(ProbeError::Unexpected("server issued no session ticket"))?,
        hello,
    ))
}

/// Checks a resumed flight: hello, optional ticket renewal, then valid CCS.
/// Returns a verdict once the CCS arrives, `None` while more bytes are needed.
fn resumed(
    bytes: &[u8],
    marker: &[u8; 31],
    suite: u16,
) -> Result<Option<TicketbleedVerdict>, ProbeError> {
    let mut records = bytes;
    let mut handshake = Vec::new();
    let mut hello = None;
    while let Some((record, used)) = parse_record(records).map_err(ProbeError::Decode)? {
        records = &records[used..];
        let AnyRecord::Tls(record) = record else {
            return Err(ProbeError::Unexpected("non-TLS resumption"));
        };
        match record.content_type {
            ContentType::Handshake => {
                handshake.extend_from_slice(record.fragment);
                let mut offset = 0;
                while let Some((msg, used)) =
                    parse_handshake(&handshake[offset..]).map_err(ProbeError::Decode)?
                {
                    match (msg.typ, hello.is_some()) {
                        (2, false) => {
                            hello = Some(ServerHello::parse(msg.body).map_err(ProbeError::Decode)?);
                        }
                        (4, true) => {}
                        _ => return Err(ProbeError::Unexpected("peer did not resume ticket")),
                    }
                    offset += used;
                }
                handshake.drain(..offset);
            }
            ContentType::ChangeCipherSpec if record.fragment == [1] && handshake.is_empty() => {
                let h = hello.ok_or(ProbeError::Unexpected("missing resumed server hello"))?;
                let matches = h.negotiated_version().map_err(ProbeError::Decode)?
                    == ProtocolVersion::TLS12
                    && h.cipher_suite == suite
                    && h.compression_method == 0;
                return match h.session_id.len() {
                    32 if matches && h.session_id.starts_with(marker) => {
                        Ok(Some(TicketbleedVerdict::ExtendedId))
                    }
                    31 if matches && h.session_id == marker => {
                        Ok(Some(TicketbleedVerdict::EchoedId))
                    }
                    _ => Err(ProbeError::Unexpected(
                        "resumed hello did not echo the session ID",
                    )),
                };
            }
            _ => return Err(ProbeError::Unexpected("peer did not resume ticket")),
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    //! Test with a real ticket issuer and scripted resumption responses.
    use super::*;
    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    /// Builds a TLS record for scripted server responses.
    fn record(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![kind, 3, 3];
        out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// Builds a TLS 1.2 server hello with a chosen session ID.
    fn hello(id: &[u8], suite: u16) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[1; 32]);
        body.push(u8::try_from(id.len()).unwrap());
        body.extend_from_slice(id);
        body.extend_from_slice(&suite.to_be_bytes());
        body.push(0);
        let len = u32::try_from(body.len()).unwrap().to_be_bytes();
        let mut message = vec![2, len[1], len[2], len[3]];
        message.extend_from_slice(&body);
        message
    }

    /// TLS 1.2 acceptor that issues tickets, for scripted resumption tests.
    fn ticket_acceptor() -> TlsAcceptor {
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS12])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(
                        include_bytes!("testdata/localhost.cert.der").to_vec(),
                    )],
                    PrivateKeyDer::try_from(include_bytes!("testdata/localhost.key.der").to_vec())
                        .unwrap(),
                )
                .unwrap();
        config.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
        TlsAcceptor::from(Arc::new(config))
    }

    /// Runs the probe against a real first handshake and a scripted second
    /// connection that is handed to `second` once accepted.
    async fn probe_with_second<F, Fut>(second: F) -> Result<TicketbleedVerdict, ProbeError>
    where
        F: FnOnce(tokio::net::TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let acceptor = ticket_acceptor();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let transport = Transport::new(listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (first, _) = listener.accept().await.unwrap();
            let _tls = acceptor.accept(first).await.unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            second(stream).await;
        });
        let result = probe_ticketbleed(&transport, Some("localhost")).await;
        server.await.unwrap();
        result
    }

    /// A peer that closes instead of resuming is an error, not a verdict.
    #[tokio::test]
    async fn closed_before_resumption_is_error() {
        let result = probe_with_second(|mut stream| async move {
            // Consume the hello so closing does not reset the connection.
            let mut buf = [0; 4096];
            let _ = stream.read(&mut buf).await;
        })
        .await;
        assert!(matches!(
            result,
            Err(ProbeError::Unexpected("peer closed before resumption"))
        ));
    }

    /// Endless resumption handshake data hits the probe limit.
    #[tokio::test]
    async fn oversized_resumption_is_error() {
        let result = probe_with_second(|mut stream| async move {
            let mut header = [0; 5];
            stream.read_exact(&mut header).await.unwrap();
            let mut data = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
            stream.read_exact(&mut data).await.unwrap();
            let suite = u16::from_be_bytes([data[72], data[73]]);
            let mut out = record(22, &hello(&data[39..70], suite));
            // NewSessionTicket messages of 16000 bytes each, never a CCS.
            let mut ticket = vec![4, 0, 0x3e, 0x80];
            ticket.resize(16_004, 0);
            for _ in 0..70 {
                out.extend(record(22, &ticket));
            }
            let _ = stream.write_all(&out).await;
        })
        .await;
        assert!(matches!(
            result,
            Err(ProbeError::Unexpected("resumption exceeds probe limit"))
        ));
    }

    /// A server that hangs up mid ticket handshake is an error.
    #[tokio::test]
    async fn closed_during_ticket_handshake_is_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let transport = Transport::new(listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0; 4096];
            let _ = stream.read(&mut buf).await;
        });
        let result = probe_ticketbleed(&transport, Some("localhost")).await;
        server.await.unwrap();
        assert!(matches!(
            result,
            Err(ProbeError::Unexpected(
                "peer closed during ticket handshake"
            ))
        ));
    }

    /// Non-handshake records and non-TLS 1.2 hellos are rejected when
    /// extracting the ticket.
    #[test]
    fn ticket_extraction_rejects_unexpected_input() {
        assert!(matches!(
            extract_ticket(&record(21, &[2, 40])),
            Err(ProbeError::Unexpected("unexpected ticket handshake record"))
        ));
        let mut old = hello(&[], 0xc02f);
        old[4] = 3;
        old[5] = 2;
        assert!(matches!(
            extract_ticket(&record(22, &old)),
            Err(ProbeError::Unexpected("ticket handshake was not TLS 1.2"))
        ));
    }

    /// An SSLv2-style record in the resumed flight is rejected.
    #[test]
    fn resumed_rejects_ssl2_record() {
        assert!(matches!(
            resumed(&[0x80, 1, 0], &[0; 31], 0xc02f),
            Err(ProbeError::Unexpected("non-TLS resumption"))
        ));
    }

    /// An extended matching ID is positive, an exact echo negative; all else errors.
    #[test]
    fn evidence_requires_correlated_resumption() {
        let marker = [17; 31];
        let mut id = marker.to_vec();
        id.push(0);
        let hs = hello(&id, 0xc02f);
        let mut bytes = record(22, &hs[..12]);
        bytes.extend(record(22, &hs[12..]));
        let partial = bytes.len();
        bytes.extend(record(20, &[1]));
        for n in 0..bytes.len() {
            assert!(resumed(&bytes[..n], &marker, 0xc02f).unwrap().is_none());
        }
        assert_eq!(
            resumed(&bytes, &marker, 0xc02f).unwrap(),
            Some(TicketbleedVerdict::ExtendedId)
        );
        assert!(resumed(&bytes, &[18; 31], 0xc02f).is_err());
        assert!(resumed(&bytes, &marker, 0xc030).is_err());
        let mut full = bytes[..partial].to_vec();
        full.extend(record(22, &[14, 0, 0, 0]));
        assert!(resumed(&full, &marker, 0xc02f).is_err());
        let mut alert = bytes[..partial].to_vec();
        alert.extend(record(21, &[2, 40]));
        assert!(resumed(&alert, &marker, 0xc02f).is_err());
        let mut equal = record(22, &hello(&marker, 0xc02f));
        equal.extend(record(20, &[1]));
        assert_eq!(
            resumed(&equal, &marker, 0xc02f).unwrap(),
            Some(TicketbleedVerdict::EchoedId)
        );
        assert!(resumed(&equal, &marker, 0xc030).is_err());
        assert!(resumed(&equal, &[18; 31], 0xc02f).is_err());
    }

    /// A real TLS server accepts the acquired ticket and echoes the short ID.
    #[tokio::test]
    async fn real_server_resumes_ticket() {
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS12])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(
                        include_bytes!("testdata/localhost.cert.der").to_vec(),
                    )],
                    PrivateKeyDer::try_from(include_bytes!("testdata/localhost.key.der").to_vec())
                        .unwrap(),
                )
                .unwrap();
        config.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let transport = Transport::new(listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (first, _) = listener.accept().await.unwrap();
            let _first = acceptor.accept(first).await.unwrap();
            let (second, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(second).await;
        });
        let (ticket, initial) = obtain_ticket(&transport, Some("localhost")).await.unwrap();
        let marker = [19; 31];
        let mut client = client_hello(
            ProtocolVersion::TLS12,
            vec![initial.cipher_suite],
            Some("localhost"),
        );
        client.session_id = marker.to_vec();
        client.extensions.push(Extension::Raw {
            typ: 35,
            data: ticket,
        });
        if initial.extension(23).is_some() {
            client.extensions.push(Extension::Raw {
                typ: 23,
                data: vec![],
            });
        }
        let mut stream = transport.connect().await.unwrap();
        stream.write_all(&client.encode().unwrap()).await.unwrap();
        let mut input = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let n = timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_ne!(n, 0, "server closed before resumption");
            input.extend_from_slice(&buf[..n]);
            if let Some(verdict) = resumed(&input, &marker, initial.cipher_suite).unwrap() {
                assert_eq!(verdict, TicketbleedVerdict::EchoedId);
                break;
            }
        }
        drop(stream);
        server.await.unwrap();
    }

    /// A real ticket handshake followed by a scripted abbreviated flight.
    #[tokio::test]
    async fn ticket_handshake_and_resumption() {
        for leak in [true, false] {
            let mut config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(
                    include_bytes!("testdata/localhost.cert.der").to_vec(),
                )],
                PrivateKeyDer::try_from(include_bytes!("testdata/localhost.key.der").to_vec())
                    .unwrap(),
            )
            .unwrap();
            config.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let transport = Transport::new(listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (first, _) = listener.accept().await.unwrap();
                let _tls = acceptor.accept(first).await.unwrap();
                let (mut second, _) = listener.accept().await.unwrap();
                let mut header = [0; 5];
                second.read_exact(&mut header).await.unwrap();
                let mut data = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
                second.read_exact(&mut data).await.unwrap();
                assert_eq!(data[38], 31);
                let mut id = data[39..70].to_vec();
                let suite = u16::from_be_bytes([data[72], data[73]]);
                // An actual ticket must be carried by the second hello.
                assert!(
                    data.windows(4)
                        .any(|w| w[0..2] == [0, 35] && u16::from_be_bytes([w[2], w[3]]) > 0)
                );
                if leak {
                    id.push(42);
                }
                let mut response = record(22, &hello(&id, suite));
                response.extend(record(20, &[1]));
                for part in response.chunks(3) {
                    second.write_all(part).await.unwrap();
                }
            });
            let result = probe_ticketbleed(&transport, Some("localhost")).await;
            let expected = if leak {
                TicketbleedVerdict::ExtendedId
            } else {
                TicketbleedVerdict::EchoedId
            };
            assert_eq!(result.unwrap(), expected);
            server.await.unwrap();
        }
    }
}
