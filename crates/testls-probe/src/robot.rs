//! Opt-in RSA padding oracle probe (ROBOT; RFC 5246 §7.4.7.1 and RFC 8017 §7.2).
//!
//! Compares fatal alerts for a valid PKCS#1 v1.5 block and several malformed
//! blocks. A repeated difference against a bad-record-MAC control is evidence
//! of an oracle; identical or unobservable responses are inconclusive.

use num_bigint::BigUint;
use testls_wire::{
    ProtocolVersion, ServerHello, handshake_type, parse_certificate_list, parse_handshake,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use x509_parser::public_key::PublicKey;

use crate::{ProbeError, Transport, ccs::read_record, hello::client_hello};

/// Upper bound on the plaintext server flight.
const MAX_FLIGHT: usize = 256 * 1024;

/// Tests one measured static RSA suite for a repeated padding-dependent alert.
///
/// Only a fatal alert differing from the valid-padding control is positive.
/// Equal alerts, closes, timeouts and protocol errors are inconclusive.
///
/// # Errors
/// Returns an error when no reproducible alert difference is observed or a
/// handshake cannot be compared safely.
pub async fn probe_robot(
    transport: &Transport,
    version: ProtocolVersion,
    suite: u16,
    sni: Option<&str>,
) -> Result<(), ProbeError> {
    if !(ProtocolVersion::TLS10..=ProtocolVersion::TLS12).contains(&version)
        || !testls_data::cipher_suite(suite).is_some_and(|c| c.name.starts_with("TLS_RSA_WITH_"))
    {
        return Err(ProbeError::Unexpected("not a static RSA TLS suite"));
    }
    let mut cert = None;
    let mut responses = [[0_u8; 4]; 2];
    // Interleave controls and malformed blocks to reduce transient differences.
    for round in &mut responses {
        for (kind, response) in round.iter_mut().enumerate() {
            let (leaf, alert) = attempt(transport, version, suite, sni, kind).await?;
            if cert.as_ref().is_some_and(|c| c != &leaf) {
                return Err(ProbeError::Unexpected(
                    "server certificate changed during probe",
                ));
            }
            cert = Some(leaf);
            *response = alert;
        }
    }
    if responses[0] == responses[1]
        && responses[0][0] == 20
        && responses[0][1..].iter().any(|a| *a != 20)
    {
        Ok(())
    } else {
        Err(ProbeError::Unexpected(
            "no reproducible RSA padding alert difference",
        ))
    }
}

/// Performs one handshake through a bogus encrypted Finished record.
async fn attempt(
    transport: &Transport,
    version: ProtocolVersion,
    suite: u16,
    sni: Option<&str>,
    kind: usize,
) -> Result<(Vec<u8>, u8), ProbeError> {
    let hello = client_hello(version, vec![suite], sni)
        .encode()
        .map_err(ProbeError::Encode)?;
    let mut stream = transport.connect().await?;
    timeout(transport.read_timeout, async {
        stream.write_all(&hello).await.map_err(ProbeError::Io)?;
        let leaf = flight(&mut stream, version, suite).await?;
        let encrypted = ciphertext(&leaf, version, kind)?;
        let len = u16::try_from(encrypted.len())
            .map_err(|_| ProbeError::Unexpected("RSA key too large"))?;
        let mut body = Vec::with_capacity(encrypted.len() + 6);
        body.extend_from_slice(&[16, 0]);
        body.extend_from_slice(&(len + 2).to_be_bytes());
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(&encrypted);
        let [major, minor] = version.0.to_be_bytes();
        let mut request = vec![22, major, minor];
        request.extend_from_slice(
            &u16::try_from(body.len())
                .map_err(|_| ProbeError::Unexpected("RSA key too large"))?
                .to_be_bytes(),
        );
        request.extend_from_slice(&body);
        request.extend_from_slice(&[20, major, minor, 0, 1, 1, 22, major, minor, 0, 64]);
        request.extend_from_slice(&[0; 64]);
        stream.write_all(&request).await.map_err(ProbeError::Io)?;
        let (typ, received_version, alert) = read_record(&mut stream).await?;
        if typ != 21 || received_version != version || alert.len() != 2 || alert[0] != 2 {
            return Err(ProbeError::Unexpected("no comparable fatal alert"));
        }
        Ok((leaf, alert[1]))
    })
    .await
    .map_err(|_| ProbeError::Timeout)?
}

/// Requires exactly one hello and certificate before `ServerHelloDone`.
async fn flight(
    stream: &mut TcpStream,
    version: ProtocolVersion,
    suite: u16,
) -> Result<Vec<u8>, ProbeError> {
    let mut pending = Vec::new();
    let mut total = 0;
    let mut hello = false;
    let mut leaf = None;
    loop {
        let (typ, _, body) = read_record(stream).await?;
        total += body.len() + 5;
        if typ != 22 || total > MAX_FLIGHT {
            return Err(ProbeError::Unexpected(
                "invalid or oversized RSA server flight",
            ));
        }
        pending.extend_from_slice(&body);
        let mut offset = 0;
        while let Some((message, used)) =
            parse_handshake(&pending[offset..]).map_err(ProbeError::Decode)?
        {
            offset += used;
            match message.typ {
                handshake_type::SERVER_HELLO if !hello && leaf.is_none() => {
                    let h = ServerHello::parse(message.body).map_err(ProbeError::Decode)?;
                    if h.negotiated_version().map_err(ProbeError::Decode)? != version
                        || h.cipher_suite != suite
                        || h.compression_method != 0
                    {
                        return Err(ProbeError::Unexpected("unexpected RSA server hello"));
                    }
                    hello = true;
                }
                handshake_type::CERTIFICATE if hello && leaf.is_none() => {
                    leaf = parse_certificate_list(message.body)
                        .map_err(ProbeError::Decode)?
                        .into_iter()
                        .next();
                    if leaf.is_none() {
                        return Err(ProbeError::Unexpected("empty certificate chain"));
                    }
                }
                handshake_type::SERVER_HELLO_DONE
                    if hello
                        && leaf.is_some()
                        && message.body.is_empty()
                        && offset == pending.len() =>
                {
                    return Ok(leaf.unwrap());
                }
                _ => return Err(ProbeError::Unexpected("unexpected RSA server flight")),
            }
        }
        pending.drain(..offset);
    }
}

/// Encrypts one RFC 8017 encoded block with the certificate's RSA public key.
fn ciphertext(cert: &[u8], version: ProtocolVersion, kind: usize) -> Result<Vec<u8>, ProbeError> {
    let (rest, cert) = x509_parser::parse_x509_certificate(cert)
        .map_err(|_| ProbeError::Unexpected("invalid RSA certificate"))?;
    if !rest.is_empty() {
        return Err(ProbeError::Unexpected("invalid RSA certificate"));
    }
    let PublicKey::RSA(key) = cert
        .public_key()
        .parsed()
        .map_err(|_| ProbeError::Unexpected("invalid RSA public key"))?
    else {
        return Err(ProbeError::Unexpected("certificate has no RSA key"));
    };
    let modulus = BigUint::from_bytes_be(key.modulus);
    let exponent = BigUint::from_bytes_be(key.exponent);
    let len = modulus.to_bytes_be().len();
    if !(64..=1024).contains(&len) || exponent.bits() > 32 || exponent < BigUint::from(3_u8) {
        return Err(ProbeError::Unexpected("unsupported RSA key"));
    }
    let block = padding_block(len, version, kind)?;
    let number = BigUint::from_bytes_be(&block);
    if number >= modulus {
        return Err(ProbeError::Unexpected("RSA block exceeds modulus"));
    }
    let encoded = number.modpow(&exponent, &modulus).to_bytes_be();
    let mut result = vec![0; len];
    result[len - encoded.len()..].copy_from_slice(&encoded);
    Ok(result)
}

/// Builds a valid or deliberately malformed PKCS#1 v1.5 encoded block.
fn padding_block(len: usize, version: ProtocolVersion, kind: usize) -> Result<Vec<u8>, ProbeError> {
    if !(64..=1024).contains(&len) {
        return Err(ProbeError::Unexpected("unsupported RSA key"));
    }
    let mut block = vec![0_u8; len];
    getrandom::fill(&mut block[2..]).map_err(|_| ProbeError::Unexpected("RSA probe RNG failed"))?;
    block[0] = 0;
    block[1] = 2;
    for byte in &mut block[2..len - 49] {
        if *byte == 0 {
            *byte = 1;
        }
    }
    block[len - 49] = 0;
    block[len - 48..len - 46].copy_from_slice(&version.0.to_be_bytes());
    match kind {
        0 => {}
        1 => block[1] = 1,
        2 => block[2] = 0,
        3 => {
            block[len - 49] = 1;
            // No later zero may act as a replacement PKCS#1 separator.
            for byte in &mut block[len - 46..] {
                if *byte == 0 {
                    *byte = 1;
                }
            }
        }
        _ => return Err(ProbeError::Unexpected("invalid RSA probe vector")),
    }
    Ok(block)
}

#[cfg(test)]
mod tests {
    //! Scripted peers check framing and alert comparisons.
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    /// Wraps a body in a TLS 1.2 record.
    fn record(typ: u8, body: &[u8]) -> Vec<u8> {
        let mut r = vec![typ, 3, 3];
        r.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        r.extend_from_slice(body);
        r
    }

    /// Builds static RSA handshake messages with a known certificate.
    fn server_handshakes(cert: &[u8]) -> Vec<u8> {
        let mut h = vec![2, 0, 0, 38, 3, 3];
        h.extend_from_slice(&[1; 32]);
        h.extend_from_slice(&[0, 0, 0x2f, 0]);
        let cert_len = u32::try_from(cert.len()).unwrap().to_be_bytes();
        let list_len = u32::try_from(cert.len() + 3).unwrap().to_be_bytes();
        let msg_len = u32::try_from(cert.len() + 6).unwrap().to_be_bytes();
        h.extend_from_slice(&[
            11,
            msg_len[1],
            msg_len[2],
            msg_len[3],
            list_len[1],
            list_len[2],
            list_len[3],
            cert_len[1],
            cert_len[2],
            cert_len[3],
        ]);
        h.extend_from_slice(cert);
        h.extend_from_slice(&[14, 0, 0, 0]);
        h
    }

    /// Fragments a full static RSA server flight across two records.
    fn server_flight(cert: &[u8]) -> Vec<u8> {
        let h = server_handshakes(cert);
        let mut result = record(22, &h[..19]);
        result.extend(record(22, &h[19..]));
        result
    }

    /// Reads one scripted server flight without sending attack traffic.
    async fn scripted_flight(bytes: Vec<u8>) -> Result<Vec<u8>, ProbeError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let result = flight(&mut stream, ProtocolVersion::TLS12, 0x2f).await;
        peer.await.unwrap();
        result
    }

    /// Rejects non-handshake records, oversized flights and unexpected messages.
    #[tokio::test]
    async fn invalid_server_flights() {
        let cert = include_bytes!("testdata/rsa1024.cert.der");
        let valid = server_handshakes(cert);
        let mut cases = vec![
            (
                record(21, &[2, 40]),
                "invalid or oversized RSA server flight",
            ),
            (
                record(22, &[11, 0, 0, 3, 0, 0, 0]),
                "unexpected RSA server flight",
            ),
            (record(22, &[14, 0, 0, 0]), "unexpected RSA server flight"),
        ];
        for (offset, value) in [(5, 2), (40, 0x35), (41, 1)] {
            let mut h = valid.clone();
            h[offset] = value;
            cases.push((record(22, &h), "unexpected RSA server hello"));
        }
        let mut empty = valid[..42].to_vec();
        empty.extend_from_slice(&[11, 0, 0, 3, 0, 0, 0]);
        cases.push((record(22, &empty), "empty certificate chain"));
        let mut duplicate = valid[..42].to_vec();
        duplicate.extend_from_slice(&valid);
        cases.push((record(22, &duplicate), "unexpected RSA server flight"));
        let mut trailing = valid;
        trailing.extend_from_slice(&[14, 0, 0, 0]);
        cases.push((record(22, &trailing), "unexpected RSA server flight"));
        // An incomplete large handshake stays buffered until the flight cap.
        let mut oversized = record(22, &[11, 0xff, 0xff, 0xff]);
        for _ in 0..16 {
            oversized.extend(record(22, &[0xff; 16 * 1024]));
        }
        cases.push((oversized, "invalid or oversized RSA server flight"));
        for (bytes, expected) in cases {
            assert!(matches!(
                scripted_flight(bytes).await,
                Err(ProbeError::Unexpected(message)) if message == expected
            ));
        }
    }

    /// Only a fatal two-byte alert at the measured version is comparable.
    #[tokio::test]
    async fn noncomparable_responses() {
        let mut wrong_version = record(21, &[2, 20]);
        wrong_version[2] = 2;
        for response in [
            record(22, &[2, 20]),
            wrong_version,
            record(21, &[2]),
            record(21, &[1, 20]),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let transport = Transport::new(listener.local_addr().unwrap());
            let peer = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_record(&mut stream).await.unwrap();
                stream
                    .write_all(&server_flight(include_bytes!("testdata/rsa1024.cert.der")))
                    .await
                    .unwrap();
                for _ in 0..3 {
                    read_record(&mut stream).await.unwrap();
                }
                stream.write_all(&response).await.unwrap();
            });
            let result = probe_robot(&transport, ProtocolVersion::TLS12, 0x2f, None).await;
            peer.await.unwrap();
            assert!(matches!(
                result,
                Err(ProbeError::Unexpected("no comparable fatal alert"))
            ));
        }
    }

    /// Exercises all eight exchanges with a controllable sequence of alerts.
    async fn scripted(alerts: [u8; 8]) -> Result<(), ProbeError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut transport = Transport::new(listener.local_addr().unwrap());
        transport.read_timeout = Duration::from_secs(2);
        let peer = tokio::spawn(async move {
            for alert in alerts {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_record(&mut stream).await.unwrap();
                let flight = server_flight(include_bytes!("testdata/rsa1024.cert.der"));
                for part in flight.chunks(13) {
                    stream.write_all(part).await.unwrap();
                }
                let (typ, version, cke) = read_record(&mut stream).await.unwrap();
                assert_eq!((typ, version), (22, ProtocolVersion::TLS12));
                assert_eq!(cke[0..6], [16, 0, 0, 130, 0, 128]);
                assert_eq!(cke.len(), 134);
                assert_eq!(read_record(&mut stream).await.unwrap().2, [1]);
                assert_eq!(read_record(&mut stream).await.unwrap().2, [0; 64]);
                stream.write_all(&record(21, &[2, alert])).await.unwrap();
            }
        });
        let result = probe_robot(&transport, ProtocolVersion::TLS12, 0x2f, Some("localhost")).await;
        peer.await.unwrap();
        result
    }

    /// A reproducible alert difference requires the expected valid-block control.
    #[tokio::test]
    async fn repeated_comparable_alerts() {
        assert!(scripted([20, 40, 20, 20, 20, 40, 20, 20]).await.is_ok());
        assert!(scripted([20; 8]).await.is_err());
        assert!(scripted([20, 40, 20, 20, 20, 20, 20, 20]).await.is_err());
        assert!(scripted([40, 20, 20, 20, 40, 20, 20, 20]).await.is_err());
    }

    /// A certificate change between connections makes the comparison inconclusive.
    #[tokio::test]
    async fn changing_certificate_is_inconclusive() {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let other =
            CertificateDer::from_pem_slice(include_bytes!("testdata/robot.cert.pem")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let transport = Transport::new(listener.local_addr().unwrap());
        let peer = tokio::spawn(async move {
            for cert in [
                include_bytes!("testdata/rsa1024.cert.der").as_slice(),
                other.as_ref(),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_record(&mut stream).await.unwrap();
                stream.write_all(&server_flight(cert)).await.unwrap();
                for _ in 0..3 {
                    read_record(&mut stream).await.unwrap();
                }
                stream.write_all(&record(21, &[2, 20])).await.unwrap();
            }
        });
        let result = probe_robot(&transport, ProtocolVersion::TLS12, 0x2f, None).await;
        peer.await.unwrap();
        assert!(matches!(
            result,
            Err(ProbeError::Unexpected(
                "server certificate changed during probe"
            ))
        ));
    }

    /// Each test vector changes only its intended PKCS#1 padding condition.
    #[test]
    fn encoded_blocks() {
        for _ in 0..64 {
            for kind in 0..4 {
                let block = padding_block(128, ProtocolVersion::TLS12, kind).unwrap();
                assert_eq!(block[0], 0);
                assert_eq!(block[1], if kind == 1 { 1 } else { 2 });
                assert_eq!(block[2] == 0, kind == 2);
                assert!(block[3..79].iter().all(|b| *b != 0));
                assert_eq!(block[79] == 0, kind != 3);
                assert_eq!(&block[80..82], &[3, 3]);
                if kind == 3 {
                    assert!(block[82..].iter().all(|b| *b != 0));
                }
            }
        }
    }

    /// Decrypt each ciphertext with the public test server fixture key.
    #[test]
    fn ciphertext_round_trips_with_fixture_key() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
        use x509_parser::der_parser::der::parse_der;
        let cert =
            CertificateDer::from_pem_slice(include_bytes!("testdata/robot.cert.pem")).unwrap();
        let key = PrivateKeyDer::from_pem_slice(include_bytes!("testdata/robot.key.pem")).unwrap();
        let (_, pkcs8) = parse_der(key.secret_der()).unwrap();
        let pkcs8_fields = pkcs8.as_sequence().unwrap();
        let (_, rsa) = parse_der(pkcs8_fields[2].as_slice().unwrap()).unwrap();
        let fields = rsa.as_sequence().unwrap();
        let modulus = BigUint::from_bytes_be(fields[1].as_slice().unwrap());
        let private_exponent = BigUint::from_bytes_be(fields[3].as_slice().unwrap());
        for kind in 0..4 {
            let encrypted = ciphertext(cert.as_ref(), ProtocolVersion::TLS12, kind).unwrap();
            let decoded = BigUint::from_bytes_be(&encrypted)
                .modpow(&private_exponent, &modulus)
                .to_bytes_be();
            let mut block = vec![0; encrypted.len()];
            block[encrypted.len() - decoded.len()..].copy_from_slice(&decoded);
            assert_eq!(block[0], 0);
            assert_eq!(block[1], if kind == 1 { 1 } else { 2 });
            assert_eq!(block[2] == 0, kind == 2);
            assert!(block[3..block.len() - 49].iter().all(|b| *b != 0));
            assert_eq!(block[block.len() - 49] == 0, kind != 3);
            assert_eq!(&block[block.len() - 48..block.len() - 46], &[3, 3]);
            if kind == 3 {
                assert!(block[block.len() - 46..].iter().all(|b| *b != 0));
            }
        }
    }

    /// Invalid versions, suites, certificates and padding parameters are rejected.
    #[tokio::test]
    async fn invalid_inputs() {
        let t = Transport::new("127.0.0.1:1".parse().unwrap());
        assert!(
            probe_robot(&t, ProtocolVersion::TLS12, 0xc02f, None)
                .await
                .is_err()
        );
        for version in [ProtocolVersion::SSL3, ProtocolVersion::TLS13] {
            assert!(probe_robot(&t, version, 0x2f, None).await.is_err());
        }
        assert!(ciphertext(&[], ProtocolVersion::TLS12, 0).is_err());
        let mut trailing = include_bytes!("testdata/rsa1024.cert.der").to_vec();
        trailing.push(0);
        assert!(matches!(
            ciphertext(&trailing, ProtocolVersion::TLS12, 0),
            Err(ProbeError::Unexpected("invalid RSA certificate"))
        ));
        for len in [0, 63, 1025] {
            assert!(padding_block(len, ProtocolVersion::TLS12, 0).is_err());
        }
        assert!(padding_block(128, ProtocolVersion::TLS12, 4).is_err());
        assert!(
            ciphertext(
                include_bytes!("testdata/localhost.cert.der"),
                ProtocolVersion::TLS12,
                0
            )
            .is_err()
        );
    }

    /// Malformed or unsupported RSA public keys cannot produce ciphertext.
    #[test]
    fn invalid_public_keys() {
        let fixture = include_bytes!("testdata/rsa1024.cert.der");
        let (_, cert) = x509_parser::parse_x509_certificate(fixture).unwrap();
        let raw = cert.public_key().subject_public_key.data.as_ref();
        let offset = fixture.windows(raw.len()).position(|w| w == raw).unwrap();
        let mut malformed = fixture.to_vec();
        malformed[offset] = 0x31;
        assert!(matches!(
            ciphertext(&malformed, ProtocolVersion::TLS12, 0),
            Err(ProbeError::Unexpected("invalid RSA public key"))
        ));
        // Keep the DER and certificate lengths unchanged while moving bytes
        // from the modulus to an exponent wider than the supported 32 bits.
        let mut public_key = vec![0x30, 0x81, 137, 0x02, 127];
        public_key.extend_from_slice(&[0x7f; 127]);
        public_key.extend_from_slice(&[0x02, 6, 1, 0, 0, 0, 0, 1]);
        assert_eq!(public_key.len(), raw.len());
        let mut large_exponent = fixture.to_vec();
        large_exponent[offset..offset + raw.len()].copy_from_slice(&public_key);
        assert!(matches!(
            ciphertext(&large_exponent, ProtocolVersion::TLS12, 0),
            Err(ProbeError::Unexpected("unsupported RSA key"))
        ));
    }
}
