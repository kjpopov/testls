//! Synthetic, offline capture fixtures assembled from protocol fields.

use super::{Hello, Observation, inspect};
use crate::{ClientHello, Extension, HRR_RANDOM, ProtocolVersion};

/// Encode a TLS 1.3 offer split across short TLS records.
fn client() -> Vec<u8> {
    ClientHello {
        record_version: ProtocolVersion::TLS10,
        version: ProtocolVersion::TLS12,
        random: [12; 32],
        session_id: vec![],
        cipher_suites: vec![0x1301, 0x1302],
        compression_methods: vec![0],
        extensions: vec![Extension::SupportedVersions(vec![
            ProtocolVersion::TLS13,
            ProtocolVersion::TLS12,
        ])],
    }
    .encode_fragmented(14)
    .unwrap()
}

/// Build an independent TLS 1.3 server selection (RFC 8446 §4.1.3).
fn server(random: [u8; 32]) -> Vec<u8> {
    let mut hello = vec![22, 3, 3, 0, 50, 2, 0, 0, 46, 3, 3];
    hello.extend(random);
    hello.extend([0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4]);
    hello
}

/// Build a little-endian pcap header, with the requested link-layer type.
fn file(link: u32) -> Vec<u8> {
    let mut file = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0,
    ];
    file.extend(link.to_le_bytes());
    file
}

/// Record one packet, optionally with a different original length (clipped capture).
fn record(file: &mut Vec<u8>, data: &[u8], original: Option<u32>) {
    let len = u32::try_from(data.len()).unwrap();
    file.extend(7u32.to_le_bytes());
    file.extend(42u32.to_le_bytes());
    file.extend(len.to_le_bytes());
    file.extend(original.unwrap_or(len).to_le_bytes());
    file.extend(data);
}

/// Build an IPv4/TCP packet or an Ethernet II IPv6/TCP frame, with TCP options.
fn packet(v6: bool, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let tcp_len = u16::try_from(24 + payload.len()).unwrap();
    let mut p = if v6 {
        let mut p = vec![0; 54];
        p[12..14].copy_from_slice(&[0x86, 0xdd]);
        p[14] = 0x60;
        p[18..20].copy_from_slice(&tcp_len.to_be_bytes());
        p[20] = 6;
        p[37] = 1;
        p[53] = 2;
        p
    } else {
        let mut p = vec![0; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(20 + tcp_len).to_be_bytes());
        p[9] = 6;
        p[12..20].copy_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
        p
    };
    let mut tcp = [0u8; 24];
    tcp[..4].copy_from_slice(&[4, 0, 1, 0xbb]);
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[12] = 6 << 4;
    tcp[13] = flags;
    p.extend(tcp);
    p.extend(payload);
    p
}

/// Collect owned observations as an offline caller would.
fn observations(file: &[u8]) -> Vec<Observation> {
    let mut hellos = Vec::new();
    inspect(file, |h| hellos.push(h)).unwrap();
    hellos
}

/// TCP wraparound and matching overlaps preserve one complete fragmented client offer.
#[test]
fn contiguous_client() {
    let mut f = file(101);
    let data = client();
    record(&mut f, &packet(false, u32::MAX - 3, 2, &[]), None);
    record(&mut f, &packet(false, u32::MAX - 2, 16, &data[..12]), None);
    record(&mut f, &packet(false, 4, 16, &data[7..]), None);
    let got = observations(&f);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].source.to_string(), "192.0.2.1:1024");
    assert_eq!(got[0].timestamp.as_micros(), 7_000_042);
    assert_eq!(
        got[0].hello,
        Hello::Client {
            legacy_version: ProtocolVersion::TLS12,
            offered_versions: vec![ProtocolVersion::TLS13, ProtocolVersion::TLS12],
            cipher_count: 2
        }
    );
}

/// IPv6 server selections distinguish HRR from a `ServerHello` and ignore Ethernet padding.
#[test]
fn ipv6_selection() {
    for (random, retry) in [([0; 32], false), (HRR_RANDOM, true)] {
        let mut f = file(1);
        record(&mut f, &packet(true, 4, 18, &[]), None);
        let mut frame = packet(true, 5, 16, &server(random));
        frame.extend([0xaa; 14]);
        record(&mut f, &frame, None);
        let got = observations(&f);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].source.to_string(), "[::1]:1024");
        assert_eq!(
            got[0].hello,
            Hello::Server {
                version: ProtocolVersion::TLS13,
                cipher_suite: 0x1301,
                retry
            }
        );
    }
}

/// Dropped bytes, overlap conflicts, fragments, or a missing SYN never become a hello.
#[test]
fn rejects_ambiguous_prefixes() {
    let data = client();
    let mut f = file(101);
    record(&mut f, &packet(false, 1, 16, &data), None);
    let mut fragment = packet(false, 0, 2, &data);
    fragment[6] = 0x20;
    record(&mut f, &fragment, None);
    assert_eq!(observations(&f), []);
    record(&mut f, &packet(false, 0, 2, &data[..10]), None);
    for (seq, first) in [(12, data[11]), (10, !data[9])] {
        let mut attempt = f.clone();
        let mut tail = data[usize::try_from(seq - 1).unwrap()..].to_vec();
        tail[0] = first;
        record(&mut attempt, &packet(false, seq, 16, &tail), None);
        record(&mut attempt, &packet(false, 1, 16, &data), None);
        assert_eq!(observations(&attempt), []);
    }
}

/// Bytes outside the IP packet and missing FCS bytes cannot be interpreted as TLS.
#[test]
fn declared_lengths() {
    let data = client();
    let mut f = file(0x2400_0065);
    let mut p = packet(false, 20, 2, &data);
    // The entire IP packet is present; the snapshot omitted only the FCS.
    record(&mut f, &p, Some(u32::try_from(p.len() + 4).unwrap()));
    assert_eq!(observations(&f).len(), 1);
    let mut f = file(101);
    p[2..4].copy_from_slice(&44u16.to_be_bytes());
    record(&mut f, &p, None);
    assert_eq!(observations(&f), []);
    assert!(inspect(&file(999), |_| {}).is_err());
}
