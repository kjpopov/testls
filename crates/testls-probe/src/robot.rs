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
use x509_parser::asn1_rs::{Any, Class, Oid, Tag};
use x509_parser::prelude::{FromDer, X509Name};
use x509_parser::public_key::PublicKey;

use crate::{ProbeError, Transport, ccs::read_record, hello::client_hello};

/// Upper bound on the plaintext server flight.
const MAX_FLIGHT: usize = 256 * 1024;

/// Empty client Certificate handshake message (RFC 2246/4346/5246 §7.4.6).
const EMPTY_CERTIFICATE_HANDSHAKE: [u8; 7] = [11, 0, 0, 3, 0, 0, 0];

/// Comparable static-RSA flight, including the optional client-authentication policy.
#[derive(Debug, PartialEq, Eq)]
struct RsaFlight {
    /// Server leaf certificate used to encrypt the probe vectors.
    leaf: Vec<u8>,
    /// Validated request body, retained to reject changes between attempts.
    certificate_request: Option<Vec<u8>>,
}

/// Tests one measured static RSA suite for a repeated padding-dependent alert.
///
/// Only a fatal alert differing from the valid-padding control is positive.
/// Equal alerts, closes, timeouts and protocol errors are inconclusive.
/// Changes in the certificate or client-authentication request stop the probe
/// without retrying; different handshake policies cannot be oracle evidence.
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
    let mut previous: Option<RsaFlight> = None;
    let mut responses = [[0_u8; 4]; 2];
    // Interleave controls and malformed blocks to reduce transient differences.
    for round in &mut responses {
        for (kind, response) in round.iter_mut().enumerate() {
            let (current, alert) = attempt(transport, version, suite, sni, kind).await?;
            if previous.as_ref().is_some_and(|p| p.leaf != current.leaf) {
                return Err(ProbeError::Unexpected(
                    "server certificate changed during probe",
                ));
            }
            if previous
                .as_ref()
                .is_some_and(|p| p.certificate_request != current.certificate_request)
            {
                return Err(ProbeError::Unexpected(
                    "server certificate request changed during probe",
                ));
            }
            previous = Some(current);
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
) -> Result<(RsaFlight, u8), ProbeError> {
    let hello = client_hello(version, vec![suite], sni)
        .encode()
        .map_err(ProbeError::Encode)?;
    let mut stream = transport.connect().await?;
    timeout(transport.read_timeout, async {
        stream.write_all(&hello).await.map_err(ProbeError::Io)?;
        let received = flight(&mut stream, version, suite).await?;
        let encrypted = ciphertext(&received.leaf, version, kind)?;
        let len = u16::try_from(encrypted.len())
            .map_err(|_| ProbeError::Unexpected("RSA key too large"))?;
        // Four handshake-header bytes and two ciphertext-length bytes for CKE.
        let mut body = Vec::with_capacity(encrypted.len() + 6 + EMPTY_CERTIFICATE_HANDSHAKE.len());
        if received.certificate_request.is_some() {
            // RFC 2246/4346/5246 §7.4.6–7: no credentials; empty Certificate
            // immediately precedes ClientKeyExchange, in the same record.
            body.extend_from_slice(&EMPTY_CERTIFICATE_HANDSHAKE);
        }
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
        Ok((received, alert[1]))
    })
    .await
    .map_err(|_| ProbeError::Timeout)?
}

/// Requires hello, certificate, at most one validated request, then `ServerHelloDone`.
async fn flight(
    stream: &mut TcpStream,
    version: ProtocolVersion,
    suite: u16,
) -> Result<RsaFlight, ProbeError> {
    let mut pending = Vec::new();
    let mut total = 0;
    let mut hello = false;
    let mut leaf = None;
    let mut certificate_request = None;
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
                handshake_type::CERTIFICATE_REQUEST
                    if leaf.is_some() && certificate_request.is_none() =>
                {
                    validate_certificate_request(version, message.body)?;
                    certificate_request = Some(message.body.to_vec());
                }
                handshake_type::SERVER_HELLO_DONE
                    if hello
                        && leaf.is_some()
                        && message.body.is_empty()
                        && offset == pending.len() =>
                {
                    return Ok(RsaFlight {
                        leaf: leaf.unwrap(),
                        certificate_request,
                    });
                }
                _ => return Err(ProbeError::Unexpected("unexpected RSA server flight")),
            }
        }
        pending.drain(..offset);
    }
}

/// Reads one bounded uint16-length TLS vector without allocating.
fn request_vector<'a>(body: &mut &'a [u8]) -> Result<&'a [u8], ProbeError> {
    let error = || ProbeError::Unexpected("invalid RSA certificate request");
    let (prefix, rest) = body.split_at_checked(2).ok_or_else(error)?;
    let len = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    let (value, rest) = rest.split_at_checked(len).ok_or_else(error)?;
    *body = rest;
    Ok(value)
}

/// Checks RFC 2246/4346/5246 §7.4.4 vector framing and DER authority names.
///
/// TLS 1.2 adds nonempty hash/signature pairs; TLS 1.0 requires a nonempty
/// authority list. Unknown algorithm/type values need no selection because
/// the probe always sends an empty certificate, never a client credential.
fn validate_certificate_request(
    version: ProtocolVersion,
    mut body: &[u8],
) -> Result<(), ProbeError> {
    let error = || ProbeError::Unexpected("invalid RSA certificate request");
    let (&types_len, rest) = body.split_first().ok_or_else(error)?;
    if types_len == 0 {
        return Err(error());
    }
    let (_, rest) = rest
        .split_at_checked(usize::from(types_len))
        .ok_or_else(error)?;
    body = rest;
    if version == ProtocolVersion::TLS12 {
        let algorithms = request_vector(&mut body)?;
        if algorithms.len() < 2 || algorithms.len() % 2 != 0 {
            return Err(error());
        }
    }
    let mut authorities = request_vector(&mut body)?;
    if !body.is_empty() || (version == ProtocolVersion::TLS10 && authorities.len() < 3) {
        return Err(error());
    }
    while !authorities.is_empty() {
        let name = request_vector(&mut authorities)?;
        validate_authority_name(name)?;
        let (rest, _) = X509Name::from_der(name).map_err(|_| error())?;
        if !rest.is_empty() {
            return Err(error());
        }
    }
    Ok(())
}

/// Consumes one definite-length DER container without discarding inner bytes.
fn name_container<'a>(body: &mut &'a [u8], tag: Tag) -> Result<&'a [u8], ProbeError> {
    let error = || ProbeError::Unexpected("invalid RSA certificate request");
    let (rest, value) = Any::from_der(body).map_err(|_| error())?;
    if value.header.class() != Class::Universal
        || value.header.tag() != tag
        || !value.header.is_constructed()
    {
        return Err(error());
    }
    *body = rest;
    Ok(value.data)
}

/// Requires complete Name/RDN/attribute content (RFC 5280 §4.1.2.4).
///
/// `X509Name`'s parser can discard unread container content; check each level
/// before using it for the existing semantic validation. No recursion needed.
fn validate_authority_name(mut name: &[u8]) -> Result<(), ProbeError> {
    let error = || ProbeError::Unexpected("invalid RSA certificate request");
    let mut rdns = name_container(&mut name, Tag::Sequence)?;
    if !name.is_empty() {
        return Err(error());
    }
    while !rdns.is_empty() {
        let mut attributes = name_container(&mut rdns, Tag::Set)?;
        if attributes.is_empty() {
            return Err(error());
        }
        while !attributes.is_empty() {
            let attribute = name_container(&mut attributes, Tag::Sequence)?;
            let (value, _) = Oid::from_der(attribute).map_err(|_| error())?;
            let (rest, _) = Any::from_der(value).map_err(|_| error())?;
            if !rest.is_empty() {
                return Err(error());
            }
        }
    }
    Ok(())
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
        record_at(typ, ProtocolVersion::TLS12, body)
    }

    /// Wraps a body in a record at the measured protocol version.
    fn record_at(typ: u8, version: ProtocolVersion, body: &[u8]) -> Vec<u8> {
        let [major, minor] = version.0.to_be_bytes();
        let mut r = vec![typ, major, minor];
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
    async fn scripted_flight(bytes: Vec<u8>) -> Result<RsaFlight, ProbeError> {
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

    /// Builds a minimal certificate request from RFC 2246/4346/5246 §7.4.4.
    fn certificate_request(version: ProtocolVersion) -> Vec<u8> {
        let mut body = vec![1, 1]; // One certificate type: rsa_sign.
        if version == ProtocolVersion::TLS12 {
            body.extend_from_slice(&[0, 2, 4, 1]); // One SHA-256/RSA pair.
        }
        if version == ProtocolVersion::TLS10 {
            body.extend_from_slice(&[0, 4, 0, 2, 0x30, 0]); // One DER Name.
        } else {
            body.extend_from_slice(&[0, 0]); // No preferred authorities.
        }
        let mut message = vec![13, 0, 0, u8::try_from(body.len()).unwrap()];
        message.extend(body);
        message
    }

    /// Exercises eight versioned exchanges, with optional client authentication.
    async fn scripted(
        alerts: [u8; 8],
        version: ProtocolVersion,
        requested: bool,
    ) -> Result<(), ProbeError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut transport = Transport::new(listener.local_addr().unwrap());
        transport.read_timeout = Duration::from_secs(2);
        let peer = tokio::spawn(async move {
            for alert in alerts {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_record(&mut stream).await.unwrap();
                let mut h = server_handshakes(include_bytes!("testdata/rsa1024.cert.der"));
                // ServerHello.version follows its four-byte handshake header.
                h[4..6].copy_from_slice(&version.0.to_be_bytes());
                if requested {
                    h.splice(h.len() - 4..h.len() - 4, certificate_request(version));
                }
                let mut flight = record_at(22, version, &h[..19]);
                flight.extend(record_at(22, version, &h[19..]));
                for part in flight.chunks(13) {
                    stream.write_all(part).await.unwrap();
                }
                let (typ, received_version, cke) = read_record(&mut stream).await.unwrap();
                assert_eq!((typ, received_version), (22, version));
                let cke = if requested {
                    // Independent RFC encoding, not the production constant.
                    assert_eq!(cke[..7], [11, 0, 0, 3, 0, 0, 0]);
                    &cke[7..]
                } else {
                    cke.as_slice()
                };
                assert_eq!(cke[0..6], [16, 0, 0, 130, 0, 128]);
                assert_eq!(cke.len(), 134);
                assert_eq!(
                    read_record(&mut stream).await.unwrap(),
                    (20, version, vec![1])
                );
                assert_eq!(
                    read_record(&mut stream).await.unwrap(),
                    (22, version, vec![0; 64])
                );
                stream
                    .write_all(&record_at(21, version, &[2, alert]))
                    .await
                    .unwrap();
            }
        });
        let result = probe_robot(&transport, version, 0x2f, Some("localhost")).await;
        peer.await.unwrap();
        result
    }

    /// A reproducible alert difference requires the expected valid-block control.
    #[tokio::test]
    async fn repeated_comparable_alerts() {
        for version in [
            ProtocolVersion::TLS10,
            ProtocolVersion::TLS11,
            ProtocolVersion::TLS12,
        ] {
            assert!(
                scripted([20, 40, 20, 20, 20, 40, 20, 20], version, false)
                    .await
                    .is_ok()
            );
        }
        assert!(
            scripted([20; 8], ProtocolVersion::TLS12, false)
                .await
                .is_err()
        );
        assert!(
            scripted(
                [20, 40, 20, 20, 20, 20, 20, 20],
                ProtocolVersion::TLS12,
                false
            )
            .await
            .is_err()
        );
        assert!(
            scripted(
                [40, 20, 20, 20, 40, 20, 20, 20],
                ProtocolVersion::TLS12,
                false
            )
            .await
            .is_err()
        );
    }

    /// Optional requests get an empty certificate without weakening oracle evidence.
    #[tokio::test]
    async fn requested_certificate_framing_and_evidence() {
        for version in [
            ProtocolVersion::TLS10,
            ProtocolVersion::TLS11,
            ProtocolVersion::TLS12,
        ] {
            assert!(
                scripted([20, 40, 20, 20, 20, 40, 20, 20], version, true)
                    .await
                    .is_ok()
            );
            assert!(matches!(
                scripted([20; 8], version, true).await,
                Err(ProbeError::Unexpected(
                    "no reproducible RSA padding alert difference"
                ))
            ));
            // Refusal of the empty client certificate cannot confirm an oracle.
            assert!(matches!(
                scripted([40; 8], version, true).await,
                Err(ProbeError::Unexpected(
                    "no reproducible RSA padding alert difference"
                ))
            ));
        }
    }

    /// Checks every truncated request and malformed nested vector at each version.
    #[test]
    fn certificate_request_validation() {
        for version in [
            ProtocolVersion::TLS10,
            ProtocolVersion::TLS11,
            ProtocolVersion::TLS12,
        ] {
            let request = certificate_request(version);
            let body = &request[4..];
            assert!(validate_certificate_request(version, body).is_ok());
            for len in 0..body.len() {
                assert!(validate_certificate_request(version, &body[..len]).is_err());
            }
            let mut trailing = body.to_vec();
            trailing.push(0);
            assert!(validate_certificate_request(version, &trailing).is_err());
            let mut empty_types = vec![0];
            empty_types.extend_from_slice(&body[2..]);
            assert!(validate_certificate_request(version, &empty_types).is_err());
            let mut prefix = body[..body.len()
                - if version == ProtocolVersion::TLS10 {
                    6
                } else {
                    2
                }]
                .to_vec();
            for authorities in [
                vec![0, 1, 0],                // Incomplete distinguished-name length.
                vec![0, 2, 0, 0],             // Empty distinguished name.
                vec![0, 3, 0, 2, 0x30],       // Truncated name vector.
                vec![0, 4, 0, 2, 0x31, 0],    // Not an X.501 Name sequence.
                vec![0, 5, 0, 3, 0x30, 0, 0], // Trailing data inside the name.
            ] {
                let mut invalid = prefix.clone();
                invalid.extend(authorities);
                assert!(validate_certificate_request(version, &invalid).is_err());
            }
            // Two valid names prove that each nested vector is consumed.
            prefix.extend_from_slice(&[0, 8, 0, 2, 0x30, 0, 0, 2, 0x30, 0]);
            assert!(validate_certificate_request(version, &prefix).is_ok());
        }
        for invalid in [
            vec![1, 1, 0, 0, 0, 0],             // Empty signature-algorithm list.
            vec![1, 1, 0, 1, 4, 0, 0],          // Odd-length list.
            vec![1, 1, 0xff, 0xff, 4, 1, 0, 0], // Truncated oversized list.
        ] {
            assert!(validate_certificate_request(ProtocolVersion::TLS12, &invalid).is_err());
        }
        let empty_authorities = [1, 1, 0, 0];
        assert!(validate_certificate_request(ProtocolVersion::TLS10, &empty_authorities).is_err());
        assert!(validate_certificate_request(ProtocolVersion::TLS11, &empty_authorities).is_ok());
        let mut oversized = vec![1, 1, 0xff, 0xff];
        oversized.extend_from_slice(&[0x30; 32]);
        assert!(validate_certificate_request(ProtocolVersion::TLS11, &oversized).is_err());
    }

    /// Reassembles certificate requests split anywhere across handshake records.
    #[tokio::test]
    async fn fragmented_certificate_request_flight() {
        let cert = include_bytes!("testdata/rsa1024.cert.der");
        let h = server_handshakes(cert);
        let request = certificate_request(ProtocolVersion::TLS12);
        let before_done = h.len() - 4;
        for split in 0..=request.len() {
            let mut first = h[..before_done].to_vec();
            first.extend_from_slice(&request[..split]);
            let mut second = request[split..].to_vec();
            second.extend_from_slice(&h[before_done..]);
            let mut bytes = record(22, &first);
            bytes.extend(record(22, &second));
            assert_eq!(
                scripted_flight(bytes).await.unwrap(),
                RsaFlight {
                    leaf: cert.to_vec(),
                    certificate_request: Some(request[4..].to_vec()),
                }
            );
        }
    }

    /// Rejects unread content inside DER Name, RDN and attribute containers.
    #[test]
    fn certificate_authority_container_consumption() {
        let valid = [0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, b'a'];
        for (name, accepted) in [
            (valid.to_vec(), true),
            ([&[0x30, 24][..], &valid[2..], &valid[2..]].concat(), true),
            (
                [&[0x30, 22, 0x31, 20][..], &valid[4..], &valid[4..]].concat(),
                true,
            ),
            (vec![0x30, 1, 0xff], false),
            (vec![0x10, 0], false),                   // Primitive SEQUENCE.
            (vec![0xb0, 0], false),                   // Non-universal SEQUENCE tag.
            (vec![0x30, 0, 0], false),                // Bytes after the Name.
            (vec![0x30, 2, 0x30, 0], false),          // RDN must be a SET.
            (vec![0x30, 4, 0x31, 2, 0x31, 0], false), // Attribute must be a SEQUENCE.
            (vec![0x30, 6, 0x31, 4, 0x30, 2, 5, 0], false), // Missing attribute OID.
            (vec![0x30, 7, 0x31, 5, 0x30, 3, 6, 1, 0x55], false), // Missing value.
            ([&[0x30, 13][..], &valid[2..], &[0xff]].concat(), false),
            (
                [&[0x30, 13, 0x31, 11][..], &valid[4..], &[0xff]].concat(),
                false,
            ),
            (
                [&[0x30, 13, 0x31, 11, 0x30, 9][..], &valid[6..], &[0xff]].concat(),
                false,
            ),
            (vec![0x30, 2, 0x31, 0], false),
        ] {
            let mut request = vec![1, 1, 0, 2, 4, 1];
            request.extend_from_slice(&u16::try_from(name.len() + 2).unwrap().to_be_bytes());
            request.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
            request.extend_from_slice(&name);
            assert_eq!(
                validate_certificate_request(ProtocolVersion::TLS12, &request).is_ok(),
                accepted,
                "{name:02x?}"
            );
        }
        let (_, cert) =
            x509_parser::parse_x509_certificate(include_bytes!("testdata/rsa1024.cert.der"))
                .unwrap();
        assert!(validate_authority_name(cert.subject().as_raw()).is_ok());
    }

    /// Rejects malformed, duplicated and out-of-order requests before RSA traffic.
    #[tokio::test]
    async fn invalid_certificate_request_flights() {
        let h = server_handshakes(include_bytes!("testdata/rsa1024.cert.der"));
        let request = certificate_request(ProtocolVersion::TLS12);
        let before_done = h.len() - 4;
        let mut duplicate = h.clone();
        duplicate.splice(
            before_done..before_done,
            request.iter().chain(&request).copied(),
        );
        let mut before_certificate = h.clone();
        before_certificate.splice(42..42, request.clone());
        let mut before_hello = request.clone();
        before_hello.extend_from_slice(&h);
        let mut after_done = h.clone();
        after_done.extend_from_slice(&request);
        for bytes in [duplicate, before_certificate, before_hello, after_done] {
            assert!(matches!(
                scripted_flight(record(22, &bytes)).await,
                Err(ProbeError::Unexpected("unexpected RSA server flight"))
            ));
        }
        let mut malformed = h.clone();
        malformed.splice(before_done..before_done, [13, 0, 0, 1, 0]);
        assert!(matches!(
            scripted_flight(record(22, &malformed)).await,
            Err(ProbeError::Unexpected("invalid RSA certificate request"))
        ));
        // A second Certificate cannot follow the request either.
        let mut repeated_certificate = h[..before_done].to_vec();
        repeated_certificate.extend_from_slice(&request);
        repeated_certificate.extend_from_slice(&h[42..]);
        assert!(matches!(
            scripted_flight(record(22, &repeated_certificate)).await,
            Err(ProbeError::Unexpected("unexpected RSA server flight"))
        ));
    }

    /// Presence/content changes, even between rounds, abort without retries or evidence.
    #[tokio::test]
    async fn changing_certificate_request_is_inconclusive() {
        let request = certificate_request(ProtocolVersion::TLS12);
        let mut changed = request.clone();
        changed[5] = 2; // A different, well-framed certificate-type list.
        let requested = Some(request);
        for (first, next, change_at) in [
            (requested.clone(), None, 1),
            (None, requested.clone(), 1),
            (requested.clone(), Some(changed), 1),
            (requested, None, 4),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut transport = Transport::new(listener.local_addr().unwrap());
            transport.read_timeout = Duration::from_secs(2);
            let peer = tokio::spawn(async move {
                for index in 0..=change_at {
                    let request = if index == change_at { &next } else { &first };
                    let alert = if index == 1 { 40 } else { 20 };
                    let (mut stream, _) = listener.accept().await.unwrap();
                    read_record(&mut stream).await.unwrap();
                    let mut h = server_handshakes(include_bytes!("testdata/rsa1024.cert.der"));
                    if let Some(request) = request {
                        h.splice(h.len() - 4..h.len() - 4, request.iter().copied());
                    }
                    stream.write_all(&record(22, &h)).await.unwrap();
                    for _ in 0..3 {
                        read_record(&mut stream).await.unwrap();
                    }
                    stream.write_all(&record(21, &[2, alert])).await.unwrap();
                }
                // A changed policy ends the probe; no retry may connect here.
                assert!(
                    timeout(Duration::from_millis(100), listener.accept())
                        .await
                        .is_err()
                );
            });
            let result = probe_robot(&transport, ProtocolVersion::TLS12, 0x2f, None).await;
            peer.await.unwrap();
            assert!(matches!(
                result,
                Err(ProbeError::Unexpected(
                    "server certificate request changed during probe"
                ))
            ));
        }
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
