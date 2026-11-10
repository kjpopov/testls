//! Opt-in early `ChangeCipherSpec` probe for CVE-2014-0224.
//!
//! RFC 5246 §7.1 requires CCS after the key exchange. A bad record MAC
//! after an early CCS and a bogus encrypted record indicates that the peer
//! activated a cipher before the key exchange (OpenSSL advisory 2014-06-05).

use crate::{ProbeError, Transport, hello::client_hello};
use testls_wire::{ProtocolVersion, ServerHello, handshake_type, parse_handshake};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Maximum plaintext flight size and TLS ciphertext record size.
const MAX_FLIGHT: usize = 256 * 1024;
const MAX_RECORD: usize = (1 << 14) + 2048;

/// Tests for early cipher activation at one measured TLS version.
///
/// A fatal `bad_record_mac` alert after the premature CCS is evidence of early
/// cipher activation. All other responses, including rejection, are errors and
/// must be reported as inconclusive. No application data is sent.
///
/// # Errors
/// Returns an error for invalid inputs, refusal, malformed responses or I/O.
pub async fn probe_ccs(
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
    let hello = client_hello(version, suites.to_vec(), sni)
        .encode()
        .map_err(ProbeError::Encode)?;
    let mut stream = transport.connect().await?;
    timeout(transport.read_timeout, async {
        stream.write_all(&hello).await.map_err(ProbeError::Io)?;
        flight(&mut stream, version, suites).await?;
        let [major, minor] = version.0.to_be_bytes();
        // After CCS, a bogus ciphertext forces record authentication. A patched
        // server rejects the CCS before attempting to authenticate this record.
        let mut request = vec![20, major, minor, 0, 1, 1, 22, major, minor, 0, 64];
        request.extend_from_slice(&[0; 64]);
        stream.write_all(&request).await.map_err(ProbeError::Io)?;
        let (typ, record_version, body) = read_record(&mut stream).await?;
        if typ == 21 && record_version == version && body == [2, 20] {
            Ok(())
        } else {
            Err(ProbeError::Unexpected(
                "early CCS did not produce a bad_record_mac alert",
            ))
        }
    })
    .await
    .map_err(|_| ProbeError::Timeout)?
}

/// Reads a bounded TLS record without consuming bytes from the next record.
async fn read_record(stream: &mut TcpStream) -> Result<(u8, ProtocolVersion, Vec<u8>), ProbeError> {
    let mut header = [0; 5];
    stream
        .read_exact(&mut header)
        .await
        .map_err(ProbeError::Io)?;
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if len > MAX_RECORD {
        return Err(ProbeError::Unexpected("record exceeds probe limit"));
    }
    let mut body = vec![0; len];
    stream.read_exact(&mut body).await.map_err(ProbeError::Io)?;
    Ok((
        header[0],
        ProtocolVersion(u16::from_be_bytes([header[1], header[2]])),
        body,
    ))
}

/// Requires a complete server flight with exactly one hello at the measured version/suite.
async fn flight(
    stream: &mut TcpStream,
    version: ProtocolVersion,
    suites: &[u16],
) -> Result<(), ProbeError> {
    let mut handshake = Vec::new();
    let mut total = 0;
    let mut got_hello = false;
    loop {
        let (typ, _, body) = read_record(stream).await?;
        total += body.len() + 5;
        if total > MAX_FLIGHT || typ != 22 {
            return Err(ProbeError::Unexpected("invalid or oversized server flight"));
        }
        handshake.extend_from_slice(&body);
        let mut offset = 0;
        while let Some((message, used)) =
            parse_handshake(&handshake[offset..]).map_err(ProbeError::Decode)?
        {
            offset += used;
            match message.typ {
                handshake_type::SERVER_HELLO if got_hello => {
                    return Err(ProbeError::Unexpected("duplicate ServerHello"));
                }
                handshake_type::SERVER_HELLO if !got_hello => {
                    let hello = ServerHello::parse(message.body).map_err(ProbeError::Decode)?;
                    if hello.negotiated_version().map_err(ProbeError::Decode)? != version
                        || !suites.contains(&hello.cipher_suite)
                        || hello.compression_method != 0
                    {
                        return Err(ProbeError::Unexpected(
                            "server chose an unexpected version or cipher",
                        ));
                    }
                    got_hello = true;
                }
                handshake_type::SERVER_HELLO_DONE if got_hello && message.body.is_empty() => {
                    return Ok(());
                }
                _ if !got_hello => {
                    return Err(ProbeError::Unexpected("server flight missing ServerHello"));
                }
                _ => {}
            }
        }
        handshake.drain(..offset);
    }
}

#[cfg(test)]
mod tests {
    //! Scripted peers exercise framing, evidence and failure handling.
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    /// Frames a TLS record at the scripted peer's protocol version.
    fn record(typ: u8, version: ProtocolVersion, body: &[u8]) -> Vec<u8> {
        let [major, minor] = version.0.to_be_bytes();
        let mut out = vec![typ, major, minor];
        out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// Encodes a scripted `ServerHello` with explicit negotiation parameters.
    fn server_hello(version: ProtocolVersion, suite: u16, compression: u8) -> Vec<u8> {
        let mut hello = vec![2, 0, 0, 38];
        hello.extend_from_slice(&version.0.to_be_bytes());
        hello.extend_from_slice(&[1; 32]);
        hello.push(0);
        hello.extend_from_slice(&suite.to_be_bytes());
        hello.push(compression);
        hello
    }

    /// Checks outgoing probe framing after a fragmented flight and returns the verdict.
    async fn scripted_evidence(
        version: ProtocolVersion,
        alert_version: ProtocolVersion,
        response: &[u8],
    ) -> Result<(), ProbeError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut transport = Transport::new(listener.local_addr().unwrap());
        transport.read_timeout = Duration::from_secs(2);
        let response = response.to_vec();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_record(&mut stream).await.unwrap();
            let mut hello = server_hello(version, 0x2f, 0);
            hello.extend_from_slice(&[14, 0, 0, 0]);
            // Split the handshake across records and the records across writes.
            let mut flight = record(22, version, &hello[..19]);
            flight.extend_from_slice(&record(22, version, &hello[19..]));
            for chunk in flight.chunks(3) {
                stream.write_all(chunk).await.unwrap();
            }
            assert_eq!(
                read_record(&mut stream).await.unwrap(),
                (20, version, vec![1])
            );
            assert_eq!(
                read_record(&mut stream).await.unwrap(),
                (22, version, vec![0; 64])
            );
            stream
                .write_all(&record(21, alert_version, &response))
                .await
                .unwrap();
        });
        let result = probe_ccs(&transport, version, &[0x2f], None).await;
        peer.await.unwrap();
        result
    }

    /// Only the fatal alert at the measured TLS 1.0–1.2 version succeeds.
    #[tokio::test]
    async fn peers() {
        for version in [
            ProtocolVersion::TLS10,
            ProtocolVersion::TLS11,
            ProtocolVersion::TLS12,
        ] {
            for (response, success) in [
                (&[2, 20][..], true),
                (&[2, 10][..], false),
                (&[1, 20][..], false),
            ] {
                assert_eq!(
                    scripted_evidence(version, version, response).await.is_ok(),
                    success,
                    "{version}: {response:?}"
                );
            }
            let mismatched_version = if version == ProtocolVersion::TLS12 {
                ProtocolVersion::TLS10
            } else {
                ProtocolVersion::TLS12
            };
            assert!(matches!(
                scripted_evidence(version, mismatched_version, &[2, 20]).await,
                Err(ProbeError::Unexpected(
                    "early CCS did not produce a bad_record_mac alert"
                ))
            ));
        }
    }

    /// A premature alert after `ServerHello` is not a completed flight.
    #[tokio::test]
    async fn incomplete_flight() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut transport = Transport::new(listener.local_addr().unwrap());
        transport.read_timeout = Duration::from_secs(2);
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_record(&mut stream).await.unwrap();
            let hello = server_hello(ProtocolVersion::TLS12, 0x2f, 0);
            stream
                .write_all(&record(22, ProtocolVersion::TLS12, &hello))
                .await
                .unwrap();
            stream
                .write_all(&record(21, ProtocolVersion::TLS12, &[2, 20]))
                .await
                .unwrap();
        });
        assert!(
            probe_ccs(&transport, ProtocolVersion::TLS12, &[0x2f], None)
                .await
                .is_err()
        );
        peer.await.unwrap();
    }

    /// Returns a scripted flight and verifies rejection before any CCS is sent.
    async fn scripted_flight(flight_bytes: Vec<u8>) -> Result<(), ProbeError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut transport = Transport::new(listener.local_addr().unwrap());
        transport.read_timeout = Duration::from_secs(3);
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_record(&mut stream).await.unwrap();
            stream.write_all(&flight_bytes).await.unwrap();
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0, "unexpected CCS");
        });
        let result = probe_ccs(&transport, ProtocolVersion::TLS12, &[0x2f], None).await;
        peer.await.unwrap();
        result
    }

    /// Oversized record and handshake flights are rejected before unbounded reads.
    #[tokio::test]
    async fn flight_bounds() {
        let length = u16::try_from(MAX_RECORD + 1).unwrap().to_be_bytes();
        let result = scripted_flight(vec![22, 3, 3, length[0], length[1]]).await;
        assert!(matches!(
            result,
            Err(ProbeError::Unexpected("record exceeds probe limit"))
        ));

        let mut body = vec![0; 1 << 14];
        body[..4].copy_from_slice(&[11, 255, 255, 255]);
        let frame = record(22, ProtocolVersion::TLS12, &body);
        let result = scripted_flight(frame.repeat(16)).await;
        assert!(matches!(
            result,
            Err(ProbeError::Unexpected("invalid or oversized server flight"))
        ));
    }

    /// A server cannot select an unoffered version, cipher or compression.
    #[tokio::test]
    async fn invalid_server_hello() {
        for (version, suite, compression) in [
            (0x0302_u16, 0x2f_u16, 0_u8),
            (0x0303, 0x35, 0),
            (0x0303, 0x2f, 1),
        ] {
            let mut hello = server_hello(ProtocolVersion(version), suite, compression);
            hello.extend_from_slice(&[14, 0, 0, 0]);
            let result = scripted_flight(record(22, ProtocolVersion::TLS12, &hello)).await;
            assert!(matches!(
                result,
                Err(ProbeError::Unexpected(
                    "server chose an unexpected version or cipher"
                ))
            ));
        }
    }

    /// Duplicate hellos, including changed negotiation parameters, abort before CCS.
    #[tokio::test]
    async fn duplicate_server_hello() {
        for (version, suite) in [
            (ProtocolVersion::TLS12, 0x2f),
            (ProtocolVersion::TLS11, 0x2f),
            (ProtocolVersion::TLS12, 0x35),
        ] {
            let mut hello = server_hello(ProtocolVersion::TLS12, 0x2f, 0);
            hello.extend_from_slice(&server_hello(version, suite, 0));
            hello.extend_from_slice(&[14, 0, 0, 0]);
            let result = scripted_flight(record(22, ProtocolVersion::TLS12, &hello)).await;
            assert!(matches!(
                result,
                Err(ProbeError::Unexpected("duplicate ServerHello"))
            ));
        }
    }

    /// Unsupported versions and empty suite lists do not open a connection.
    #[tokio::test]
    async fn invalid_inputs_do_not_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let transport = Transport::new(listener.local_addr().unwrap());
        for (version, suites) in [
            (ProtocolVersion::TLS13, &[0x1301][..]),
            (ProtocolVersion::TLS12, &[][..]),
        ] {
            assert!(matches!(
                probe_ccs(&transport, version, suites, None).await,
                Err(ProbeError::Unexpected(
                    "no applicable TLS version or cipher suite"
                ))
            ));
        }
        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }
}
