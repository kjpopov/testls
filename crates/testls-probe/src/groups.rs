//! Key exchange probes: supported groups and finite-field DH parameter size.
//!
//! TLS 1.3 groups are enumerated with hellos that carry an empty `key_share`
//! list, so the server has to name its choice in a `HelloRetryRequest`
//! (RFC 8446, section 4.2.8). For TLS 1.2 and earlier the chosen curve is
//! read from the `ServerKeyExchange` of an ECDHE suite (RFC 8422,
//! section 5.4), and the DH prime size from that of a DHE suite
//! (RFC 5246, section 7.4.3).

use testls_data::{cipher_suite, groups};
use testls_wire::{DheParams, EcdheParams, ProtocolVersion};

use crate::hello::{client_hello, group_hello, tls13_suites};
use crate::{CipherOrder, HelloResponse, ProbeError, Transport};

/// Key exchange parameters accepted for one protocol version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyExchangeResult {
    /// Version the hellos were sent with.
    pub version: ProtocolVersion,
    /// Accepted named groups (IANA code points). In server preference order
    /// when `group_order` is [`CipherOrder::Server`]. Empty if the server
    /// accepted no ECDHE suite at this version (TLS 1.2 and earlier).
    pub groups: Vec<u16>,
    /// Whether the server enforces its own group order.
    pub group_order: CipherOrder,
    /// Smallest DH prime size seen across accepted suites.
    pub dh_bits: Option<usize>,
    /// Whether any suite reused its DH public value. False requires a
    /// comparable pair for every suite; otherwise the result is unknown.
    pub dh_key_reused: Option<bool>,
    /// Per-suite DH measurements, including unsuccessful or unsupported probes.
    pub dh_suites: Vec<DhSuiteResult>,
}

/// DH evidence for one accepted cipher suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhSuiteResult {
    /// IANA cipher suite code point.
    pub suite: u16,
    /// Prime size, or `None` when the measurement failed or is unsupported.
    pub bits: Option<usize>,
    /// Distinct primes seen in the two handshakes, big-endian, in the order
    /// received; may hold one prime even when `bits` is `None`.
    pub primes: Vec<Vec<u8>>,
    /// Reuse of the public value for comparable parameters in this suite.
    pub key_reused: Option<bool>,
}

/// Whether `suite` carries `ServerECDHParams` in its `ServerKeyExchange`.
///
/// PSK suites are excluded: their parameters follow a `psk_identity_hint`
/// (RFC 5489, section 2).
fn is_ecdhe_suite(suite: u16) -> bool {
    cipher_suite(suite).is_some_and(|c| {
        (c.name.starts_with("TLS_ECDHE_") || c.name.starts_with("TLS_ECDH_anon_"))
            && !c.name.contains("_PSK_")
    })
}

/// Whether `suite` carries `ServerDHParams` in its `ServerKeyExchange`.
///
/// PSK suites are excluded: their parameters follow a `psk_identity_hint`
/// (RFC 4279, section 3).
fn is_dhe_suite(suite: u16) -> bool {
    cipher_suite(suite).is_some_and(|c| {
        (c.name.starts_with("TLS_DHE_") || c.name.starts_with("TLS_DH_anon_"))
            && !c.name.contains("_PSK_")
    })
}

/// Named groups worth offering at `version`.
///
/// TLS 1.3 drops the curves below `secp256r1` (RFC 8446, section 4.2.7);
/// TLS 1.2 and earlier only negotiate elliptic curves here, since
/// finite-field groups are measured through [`dh_params`] and the
/// post-quantum groups are TLS 1.3 only. The explicit-curve markers
/// `0xff01`/`0xff02` are not real groups and are never offered.
fn candidate_groups(version: ProtocolVersion) -> Vec<u16> {
    groups()
        .iter()
        .map(|g| g.id)
        .filter(|&id| !matches!(id, 0xff01 | 0xff02))
        .filter(|&id| {
            if version >= ProtocolVersion::TLS13 {
                id >= 0x0017
            } else {
                id < 0x0100
            }
        })
        .collect()
}

/// The group a server chose in reply to a hello offering `groups`.
///
/// # Errors
/// Returns [`ProbeError::Decode`] if the relevant extension or
/// `ServerKeyExchange` is malformed.
fn selected_group(
    version: ProtocolVersion,
    suites: &[u16],
    groups: &[u16],
    response: &HelloResponse,
) -> Result<Option<u16>, ProbeError> {
    let HelloResponse::ServerHello {
        hello,
        server_key_exchange,
        ..
    } = response
    else {
        return Ok(None);
    };
    if !suites.contains(&hello.cipher_suite) {
        return Ok(None);
    }
    let group = if version >= ProtocolVersion::TLS13 {
        if hello.negotiated_version().map_err(ProbeError::Decode)? != version {
            return Ok(None);
        }
        hello.key_share_group().map_err(ProbeError::Decode)?
    } else {
        if hello.is_hello_retry_request()
            || hello.negotiated_version().map_err(ProbeError::Decode)? != version
        {
            return Ok(None);
        }
        match server_key_exchange {
            Some(body) => Some(EcdheParams::parse(body).map_err(ProbeError::Decode)?.group),
            None => None,
        }
    };
    Ok(group.filter(|g| groups.contains(g)))
}

/// Send one hello offering `groups` and return the group the server picked.
async fn offer_groups(
    transport: &Transport,
    version: ProtocolVersion,
    suites: &[u16],
    groups: &[u16],
    sni: Option<&str>,
) -> Result<Option<u16>, ProbeError> {
    let bytes = group_hello(version, suites.to_vec(), groups, sni)
        .encode()
        .map_err(ProbeError::Encode)?;
    match transport.exchange(&bytes).await {
        Ok(response) => selected_group(version, suites, groups, &response),
        // Many servers reset instead of sending handshake_failure.
        Err(ProbeError::Io(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Enumerate the groups the server accepts with `suites`, and its order.
async fn enumerate_groups(
    transport: &Transport,
    version: ProtocolVersion,
    suites: &[u16],
    sni: Option<&str>,
) -> Result<(Vec<u16>, CipherOrder), ProbeError> {
    let mut candidates = candidate_groups(version);
    let mut accepted = Vec::new();
    while !candidates.is_empty() {
        let Some(group) = offer_groups(transport, version, suites, &candidates, sni).await? else {
            break;
        };
        candidates.retain(|&g| g != group);
        accepted.push(group);
    }
    let order = match accepted.as_slice() {
        [] | [_] => CipherOrder::NotApplicable,
        [_, .., last] => {
            let mut reversed = accepted.clone();
            reversed.reverse();
            match offer_groups(transport, version, suites, &reversed, sni).await? {
                Some(g) if g == *last => CipherOrder::Client,
                // Any other choice means the server's own preference wins.
                Some(_) => CipherOrder::Server,
                None => {
                    return Err(ProbeError::Unexpected(
                        "server refused a list of groups it had accepted",
                    ));
                }
            }
        }
    };
    Ok((accepted, order))
}

/// The DH parameters the server sends with one of `suites`.
async fn dh_params(
    transport: &Transport,
    version: ProtocolVersion,
    suites: &[u16],
    sni: Option<&str>,
) -> Result<Option<DheParams>, ProbeError> {
    let bytes = client_hello(version, suites.to_vec(), sni)
        .encode()
        .map_err(ProbeError::Encode)?;
    let response = match transport.exchange(&bytes).await {
        Ok(r) => r,
        Err(ProbeError::Io(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    let HelloResponse::ServerHello {
        hello,
        server_key_exchange: Some(body),
        ..
    } = response
    else {
        return Ok(None);
    };
    if hello.is_hello_retry_request()
        || !suites.contains(&hello.cipher_suite)
        || hello.negotiated_version().map_err(ProbeError::Decode)? != version
    {
        return Ok(None);
    }
    DheParams::parse(&body)
        .map(Some)
        .map_err(ProbeError::Decode)
}

/// Probe the key exchange parameters the server accepts at `version`.
///
/// `accepted` are the cipher suites found by
/// [`enumerate_ciphers`](crate::enumerate_ciphers) for the same version.
/// Groups are enumerated over its ECDHE suites (all TLS 1.3 suites at
/// TLS 1.3), at a cost of one connection per accepted group plus two.
/// Each accepted DHE or anonymous DH suite gets up to two connections to
/// measure its parameters and check key reuse. DHE-PSK remains unmeasured.
/// SSLv2 and SSLv3 have no `supported_groups` extension, so only the DH
/// size is probed there.
///
/// # Errors
/// Returns a [`ProbeError`] if a probe fails for reasons other than the
/// server refusing the hello.
pub async fn probe_key_exchange(
    transport: &Transport,
    version: ProtocolVersion,
    accepted: &[u32],
    sni: Option<&str>,
) -> Result<KeyExchangeResult, ProbeError> {
    let accepted: Vec<u16> = accepted
        .iter()
        .filter_map(|&s| u16::try_from(s).ok())
        .collect();
    let mut result = KeyExchangeResult {
        version,
        groups: Vec::new(),
        group_order: CipherOrder::NotApplicable,
        dh_bits: None,
        dh_key_reused: None,
        dh_suites: Vec::new(),
    };
    if version <= ProtocolVersion::SSL2 {
        return Ok(result);
    }
    let ecdhe: Vec<u16> = if version >= ProtocolVersion::TLS13 {
        if accepted.is_empty() {
            tls13_suites()
        } else {
            accepted.clone()
        }
    } else if version > ProtocolVersion::SSL3 {
        accepted
            .iter()
            .copied()
            .filter(|&s| is_ecdhe_suite(s))
            .collect()
    } else {
        Vec::new()
    };
    if !ecdhe.is_empty() {
        (result.groups, result.group_order) =
            enumerate_groups(transport, version, &ecdhe, sni).await?;
    }
    if version < ProtocolVersion::TLS13 {
        for suite in accepted.into_iter().filter(|&s| {
            is_dhe_suite(s) || cipher_suite(s).is_some_and(|c| c.name.starts_with("TLS_DHE_PSK_"))
        }) {
            if result.dh_suites.iter().any(|d| d.suite == suite) {
                continue;
            }
            let mut sample = DhSuiteResult {
                suite,
                bits: None,
                primes: Vec::new(),
                key_reused: None,
            };
            // A server may rotate parameters between handshakes, so keep every
            // prime. Only two successful samples make the suite measured, but a
            // single weak prime is still evidence.
            if is_dhe_suite(suite)
                && let Ok(Some(first)) = dh_params(transport, version, &[suite], sni).await
            {
                let second = dh_params(transport, version, &[suite], sni)
                    .await
                    .ok()
                    .flatten();
                let mut bits = first.prime_bits();
                sample.primes.push(first.p.clone());
                if let Some(second) = second {
                    sample.key_reused = (second.p == first.p && second.g == first.g)
                        .then_some(second.public_key == first.public_key);
                    bits = bits.min(second.prime_bits());
                    sample.bits = Some(bits);
                    if second.p != first.p {
                        sample.primes.push(second.p);
                    }
                }
                result.dh_bits = Some(result.dh_bits.map_or(bits, |b| b.min(bits)));
            }
            result.dh_suites.push(sample);
        }
        if result.dh_suites.iter().any(|d| d.key_reused == Some(true)) {
            result.dh_key_reused = Some(true);
        } else if !result.dh_suites.is_empty()
            && result.dh_suites.iter().all(|d| d.key_reused == Some(false))
        {
            result.dh_key_reused = Some(false);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use testls_wire::{HRR_RANDOM, RawExtension, ServerHello, ext};

    /// A `ServerHello` response for `suite` with optional SKE body.
    fn sh(
        version: u16,
        random: [u8; 32],
        suite: u16,
        extensions: Vec<RawExtension>,
        ske: Option<Vec<u8>>,
    ) -> HelloResponse {
        HelloResponse::ServerHello {
            hello: ServerHello {
                legacy_version: ProtocolVersion(version),
                random,
                session_id: vec![],
                cipher_suite: suite,
                compression_method: 0,
                extensions,
            },
            certificates: vec![],
            server_key_exchange: ske,
        }
    }

    /// Suite names decide which key exchange parser applies.
    #[test]
    fn suite_classes() {
        assert!(is_ecdhe_suite(0xc02f));
        assert!(!is_ecdhe_suite(0x009e));
        assert!(is_dhe_suite(0x009e));
        assert!(!is_dhe_suite(0x009c));
        assert!(!is_dhe_suite(0xc02f));
        // TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
        assert!(!is_ecdhe_suite(0xc037));
        assert!(!is_dhe_suite(0x00aa));
    }

    /// TLS 1.3 candidates include hybrids but no legacy curves; TLS 1.2
    /// candidates are elliptic curves only.
    #[test]
    fn candidates() {
        let tls13 = candidate_groups(ProtocolVersion::TLS13);
        assert!(tls13.contains(&0x11ec));
        assert!(tls13.contains(&0x0100));
        assert!(!tls13.contains(&0x0001));
        assert!(!tls13.contains(&0xff01));
        let tls12 = candidate_groups(ProtocolVersion::TLS12);
        assert!(tls12.contains(&0x0001));
        assert!(tls12.contains(&0x001d));
        assert!(!tls12.contains(&0x0100));
        assert!(!tls12.contains(&0x11ec));
    }

    /// TLS 1.2: the curve comes from the `ServerKeyExchange`.
    #[test]
    fn selected_group_tls12() {
        let v = ProtocolVersion::TLS12;
        let r = sh(
            0x0303,
            [1; 32],
            0xc02f,
            vec![],
            Some(vec![3, 0, 0x17, 1, 4]),
        );
        assert_eq!(
            selected_group(v, &[0xc02f], &[0x17], &r).unwrap(),
            Some(0x17)
        );
        assert_eq!(selected_group(v, &[0xc02f], &[0x18], &r).unwrap(), None);
        assert_eq!(selected_group(v, &[0xc030], &[0x17], &r).unwrap(), None);
        let none = sh(0x0303, [1; 32], 0xc02f, vec![], None);
        assert_eq!(selected_group(v, &[0xc02f], &[0x17], &none).unwrap(), None);
        let bad = sh(0x0303, [1; 32], 0xc02f, vec![], Some(vec![1]));
        assert!(selected_group(v, &[0xc02f], &[0x17], &bad).is_err());
    }

    /// TLS 1.3: the group comes from the HRR `key_share`.
    #[test]
    fn selected_group_tls13() {
        let v = ProtocolVersion::TLS13;
        let exts = vec![
            RawExtension {
                typ: ext::SUPPORTED_VERSIONS,
                data: vec![3, 4],
            },
            RawExtension {
                typ: ext::KEY_SHARE,
                data: vec![0x11, 0xec],
            },
        ];
        let r = sh(0x0303, HRR_RANDOM, 0x1301, exts, None);
        assert_eq!(
            selected_group(v, &[0x1301], &[0x11ec, 0x1d], &r).unwrap(),
            Some(0x11ec)
        );
        assert_eq!(selected_group(v, &[0x1301], &[0x1d], &r).unwrap(), None);
        assert_eq!(
            selected_group(v, &[0x1301], &[0x1d], &HelloResponse::Closed).unwrap(),
            None
        );
    }
}

#[cfg(test)]
mod mock_server {
    use super::*;
    use std::net::SocketAddr;
    use testls_wire::{HRR_RANDOM, ext};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Cipher suites and extensions of a `ClientHello` record.
    fn parse_hello(record: &[u8]) -> (Vec<u16>, Vec<(u16, Vec<u8>)>) {
        let u16_at = |i: usize| u16::from_be_bytes([record[i], record[i + 1]]);
        // record header (5) + handshake header (4) + version (2) + random (32)
        let mut i = 5 + 4 + 2 + 32;
        i += 1 + usize::from(record[i]);
        let len = usize::from(u16_at(i));
        let suites = record[i + 2..i + 2 + len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_be_bytes(c))
            .collect();
        i += 2 + len;
        i += 1 + usize::from(record[i]);
        let end = i + 2 + usize::from(u16_at(i));
        i += 2;
        let mut exts = Vec::new();
        while i < end {
            let len = usize::from(u16_at(i + 2));
            exts.push((u16_at(i), record[i + 4..i + 4 + len].to_vec()));
            i += 4 + len;
        }
        (suites, exts)
    }

    /// Wrap handshake messages in one handshake record.
    fn record(messages: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut hs = Vec::new();
        for (typ, body) in messages {
            let len = u32::try_from(body.len()).unwrap().to_be_bytes();
            hs.extend([*typ, len[1], len[2], len[3]]);
            hs.extend(body);
        }
        let mut rec = vec![22, 3, 3];
        rec.extend(u16::try_from(hs.len()).unwrap().to_be_bytes());
        rec.extend(hs);
        rec
    }

    /// A `ServerHello` body with the given random, suite and extensions.
    fn server_hello(random: [u8; 32], suite: u16, exts: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend(random);
        body.push(0);
        body.extend(suite.to_be_bytes());
        body.push(0);
        body.extend(u16::try_from(exts.len()).unwrap().to_be_bytes());
        body.extend(exts);
        body
    }

    /// Reply to one hello: HRR for TLS 1.3, `ServerHello` +
    /// `ServerKeyExchange` + `ServerHelloDone` for TLS 1.2. `groups` are
    /// the supported groups in server preference order; `dh_prime_len` is
    /// the byte length of the prime sent with DHE suites. Unless `reuse` is set,
    /// the DH public value is taken from the client random, so it differs
    /// per handshake.
    fn reply(hello: &[u8], groups: &[u16], dh_prime_len: usize, reuse: bool) -> Vec<u8> {
        const ALERT: [u8; 7] = [21, 3, 3, 0, 2, 2, 40];
        let (suites, exts) = parse_hello(hello);
        let find = |typ| exts.iter().find(|(t, _)| *t == typ).map(|(_, d)| d.clone());
        let offered: Vec<u16> = find(ext::SUPPORTED_GROUPS)
            .map(|d| {
                d[2..]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&c| u16::from_be_bytes(c))
                    .collect()
            })
            .unwrap_or_default();
        let group = groups.iter().copied().find(|g| offered.contains(g));
        if find(ext::SUPPORTED_VERSIONS).is_some() {
            let Some(group) = group else {
                return ALERT.to_vec();
            };
            let mut e = vec![0, 43, 0, 2, 3, 4, 0, 51, 0, 2];
            e.extend(group.to_be_bytes());
            return record(&[(2, server_hello(HRR_RANDOM, 0x1301, &e))]);
        }
        if suites.contains(&0x009e) {
            let mut ske = u16::try_from(dh_prime_len).unwrap().to_be_bytes().to_vec();
            ske.push(0x80);
            ske.extend(vec![0xff; dh_prime_len - 1]);
            ske.extend([0, 1, 2, 0, 16]);
            ske.extend(if reuse { &[5; 16] } else { &hello[11..27] });
            return record(&[
                (2, server_hello([7; 32], 0x009e, &[])),
                (12, ske),
                (14, vec![]),
            ]);
        }
        let Some(group) = group else {
            return ALERT.to_vec();
        };
        let mut ske = vec![3];
        ske.extend(group.to_be_bytes());
        ske.extend([1, 4]);
        record(&[
            (2, server_hello([7; 32], 0xc02f, &[])),
            (12, ske),
            (14, vec![]),
        ])
    }

    /// Serve hellos forever, replying as described in [`reply`].
    async fn serve(groups: &'static [u16], dh_prime_len: usize, reuse: bool) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0; 1 << 16];
                let mut n = 0;
                while n < 5 || n < 5 + usize::from(u16::from_be_bytes([buf[3], buf[4]])) {
                    n += s.read(&mut buf[n..]).await.unwrap();
                }
                s.write_all(&reply(&buf[..n], groups, dh_prime_len, reuse))
                    .await
                    .unwrap();
            }
        });
        addr
    }

    /// TLS 1.2: curves come out in server order, DH size is measured.
    #[tokio::test]
    async fn tls12_groups_and_dh() {
        let addr = serve(&[0x0018, 0x001d, 0x0017], 128, false).await;
        let r = probe_key_exchange(
            &Transport::new(addr),
            ProtocolVersion::TLS12,
            &[0xc02f, 0x009e],
            None,
        )
        .await
        .unwrap();
        assert_eq!(r.groups, vec![0x0018, 0x001d, 0x0017]);
        assert_eq!(r.group_order, CipherOrder::Server);
        assert_eq!(r.dh_bits, Some(1024));
        assert_eq!(
            r.dh_suites[0]
                .primes
                .iter()
                .map(Vec::len)
                .collect::<Vec<_>>(),
            [128]
        );
        assert_eq!(r.dh_key_reused, Some(false));
    }

    /// Every accepted suite is sampled separately; failures do not erase
    /// other suites' measurements, rotated parameters keep both primes and
    /// the smaller size, and incomparable parameters cannot prove reuse.
    #[tokio::test]
    async fn mixed_dh_suites_and_failed_probes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut attempts = std::collections::HashMap::<u16, usize>::new();
            for _ in 0..6 {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0; 1 << 16];
                let mut n = 0;
                while n < 5 || n < 5 + usize::from(u16::from_be_bytes([buf[3], buf[4]])) {
                    n += s.read(&mut buf[n..]).await.unwrap();
                }
                let (suites, _) = parse_hello(&buf[..n]);
                assert_eq!(suites.len(), 1);
                let suite = suites[0];
                let count = attempts.entry(suite).or_default();
                *count += 1;
                let response = match suite {
                    0x0033 | 0x0034 => {
                        // The anonymous suite rotates to a smaller prime on the
                        // second attempt.
                        let len = if suite == 0x0034 && *count == 2 {
                            128
                        } else {
                            256
                        };
                        let mut ske = u16::try_from(len).unwrap().to_be_bytes().to_vec();
                        ske.extend(vec![0xff; len]);
                        ske.extend([0, 1, 2, 0, 1, 5]);
                        record(&[
                            (2, server_hello([7; 32], suite, &[])),
                            (12, ske),
                            (14, vec![]),
                        ])
                    }
                    // Malformed parameters must remain unmeasured.
                    0x003a => record(&[
                        (2, server_hello([7; 32], suite, &[])),
                        (12, vec![0, 4, 1]),
                        (14, vec![]),
                    ]),
                    // An answer using another protocol version is unmeasured too.
                    0x0032 => {
                        let mut h = server_hello([7; 32], suite, &[]);
                        h[1] = 2;
                        record(&[(2, h), (12, vec![0, 1, 7, 0, 1, 2, 0, 1, 5]), (14, vec![])])
                    }
                    _ => panic!("unexpected suite"),
                };
                s.write_all(&response).await.unwrap();
            }
        });
        let r = probe_key_exchange(
            &Transport::new(addr),
            ProtocolVersion::TLS12,
            &[0x003a, 0x0033, 0x0034, 0x0032, 0x00aa],
            None,
        )
        .await
        .unwrap();
        assert_eq!(r.dh_bits, Some(1024));
        assert_eq!(
            r.dh_suites
                .iter()
                .map(|d| (
                    d.suite,
                    d.bits,
                    d.key_reused,
                    d.primes.iter().map(Vec::len).collect::<Vec<_>>()
                ))
                .collect::<Vec<_>>(),
            vec![
                (0x003a, None, None, vec![]),
                (0x0033, Some(2048), Some(true), vec![256]),
                (0x0034, Some(1024), None, vec![256, 128]),
                (0x0032, None, None, vec![]),
                (0x00aa, None, None, vec![])
            ]
        );
        assert_eq!(r.dh_key_reused, Some(true));
    }

    /// TLS 1.3: groups, including the ML-KEM hybrid, are found via HRR.
    #[tokio::test]
    async fn tls13_groups() {
        let addr = serve(&[0x11ec, 0x001d], 0, false).await;
        let r = probe_key_exchange(
            &Transport::new(addr),
            ProtocolVersion::TLS13,
            &[0x1301],
            None,
        )
        .await
        .unwrap();
        assert_eq!(r.groups, vec![0x11ec, 0x001d]);
        assert_eq!(r.group_order, CipherOrder::Server);
        assert_eq!(r.dh_bits, None);
    }

    /// A DH size sent at another protocol version is not reported.
    #[tokio::test]
    async fn dh_bits_version_mismatch() {
        let addr = serve(&[], 128, true).await;
        let params = dh_params(
            &Transport::new(addr),
            ProtocolVersion::TLS11,
            &[0x009e],
            None,
        )
        .await
        .unwrap();
        assert_eq!(params, None);
    }

    /// A server sending the same DH public value twice is flagged.
    #[tokio::test]
    async fn dh_key_reuse() {
        let addr = serve(&[], 64, true).await;
        let r = probe_key_exchange(
            &Transport::new(addr),
            ProtocolVersion::TLS12,
            &[0x009e],
            None,
        )
        .await
        .unwrap();
        assert_eq!(r.dh_bits, Some(512));
        assert_eq!(r.dh_key_reused, Some(true));
    }

    /// If the second DHE handshake fails, the suite stays unmeasured (one
    /// sample cannot rule out a weaker rotated prime) but keeps its prime as
    /// evidence.
    #[tokio::test]
    async fn second_dh_handshake_fails() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0; 1 << 16];
            let mut n = 0;
            while n < 5 || n < 5 + usize::from(u16::from_be_bytes([buf[3], buf[4]])) {
                n += s.read(&mut buf[n..]).await.unwrap();
            }
            s.write_all(&reply(&buf[..n], &[], 64, false))
                .await
                .unwrap();
            // Dropping the listener refuses the second connection.
        });
        let r = probe_key_exchange(
            &Transport::new(addr),
            ProtocolVersion::TLS12,
            &[0x009e],
            None,
        )
        .await
        .unwrap();
        assert_eq!(r.dh_bits, Some(512));
        assert_eq!(r.dh_suites[0].bits, None);
        assert_eq!(r.dh_suites[0].primes.len(), 1);
        assert_eq!(r.dh_key_reused, None);
    }

    /// Without ECDHE or DHE suites nothing is probed.
    #[tokio::test]
    async fn rsa_only() {
        let r = probe_key_exchange(
            &Transport::new("127.0.0.1:9".parse().unwrap()),
            ProtocolVersion::TLS12,
            &[0x009c],
            None,
        )
        .await
        .unwrap();
        assert_eq!(r.groups, Vec::<u16>::new());
        assert_eq!(r.dh_bits, None);
    }
}
