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

/// Requires a complete server flight with the requested version and suite.
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

    /// Frames a TLS record for the scripted peer.
    fn record(typ: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![typ, 3, 3];
        out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// Checks that only a complete flight followed by the specific alert succeeds.
    #[tokio::test]
    async fn peers() {
        for (response, success) in [
            (&[2, 20][..], true),
            (&[2, 10][..], false),
            (&[1, 20][..], false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut transport = Transport::new(listener.local_addr().unwrap());
            transport.read_timeout = Duration::from_secs(2);
            let response = response.to_vec();
            let peer = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_record(&mut stream).await.unwrap();
                let mut hello = vec![2, 0, 0, 38, 3, 3];
                hello.extend_from_slice(&[1; 32]);
                hello.extend_from_slice(&[0, 0, 0x2f, 0]);
                hello.extend_from_slice(&[14, 0, 0, 0]);
                // Split the handshake across records and the records across writes.
                let mut flight = record(22, &hello[..19]);
                flight.extend_from_slice(&record(22, &hello[19..]));
                for chunk in flight.chunks(3) {
                    stream.write_all(chunk).await.unwrap();
                }
                assert_eq!(read_record(&mut stream).await.unwrap().2, [1]);
                assert_eq!(read_record(&mut stream).await.unwrap().2, [0; 64]);
                stream.write_all(&record(21, &response)).await.unwrap();
            });
            assert_eq!(
                probe_ccs(&transport, ProtocolVersion::TLS12, &[0x2f], None)
                    .await
                    .is_ok(),
                success
            );
            peer.await.unwrap();
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
            let mut hello = vec![2, 0, 0, 38, 3, 3];
            hello.extend_from_slice(&[1; 32]);
            hello.extend_from_slice(&[0, 0, 0x2f, 0]);
            stream.write_all(&record(22, &hello)).await.unwrap();
            stream.write_all(&record(21, &[2, 20])).await.unwrap();
        });
        assert!(
            probe_ccs(&transport, ProtocolVersion::TLS12, &[0x2f], None)
                .await
                .is_err()
        );
        peer.await.unwrap();
    }
}
