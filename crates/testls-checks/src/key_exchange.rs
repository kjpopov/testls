//! Key exchange checks: supported groups and DH parameter size.

use testls_probe::KeyExchangeResult;
use testls_wire::ProtocolVersion;

use crate::post_quantum::{GroupKind, group_kind};
use crate::{Finding, Severity};

/// Whether group `id` is post-quantum: a pure ML-KEM group
/// (draft-ietf-tls-mlkem) or an ML-KEM hybrid (draft-ietf-tls-ecdhe-mlkem),
/// as named in the IANA TLS Supported Groups registry.
fn is_post_quantum(id: u16) -> bool {
    group_kind(id) == GroupKind::PostQuantum
}

/// IANA name of group `id`, or `"unknown"`.
#[must_use]
pub fn group_name(id: u16) -> &'static str {
    testls_data::group(id).map_or("unknown", |g| g.name)
}

/// Severity of a server accepting group `id`, with a short reason.
///
/// RFC 8422 §5.1.1 deprecates every elliptic curve below `secp256r1`
/// (code points `0x0001` to `0x0016`) and the explicit curves. The draft
/// Kyber code points are obsolete in the IANA registry.
#[must_use]
pub fn group_severity(id: u16) -> (Severity, &'static str) {
    match id {
        0x0001..=0x0016 | 0xff01 | 0xff02 => {
            (Severity::Medium, "deprecated curve (RFC 8422 §5.1.1)")
        }
        _ if testls_data::group(id).is_none() => (Severity::Info, "unknown group"),
        _ if group_kind(id) == GroupKind::DraftKyber => {
            (Severity::Low, "obsolete draft Kyber code point")
        }
        _ => (Severity::Ok, "current"),
    }
}

/// Severity of an ephemeral DH prime of `bits` bits, with a short reason.
///
/// Primes below 1024 bits are within reach of precomputation attacks
/// (Logjam); RFC 7919 groups start at 2048 bits.
#[must_use]
pub fn dh_severity(bits: usize) -> (Severity, &'static str) {
    match bits {
        0..1024 => (Severity::High, "breakable with precomputation (Logjam)"),
        1024..2048 => (Severity::Medium, "below 2048 bits (RFC 7919)"),
        _ => (Severity::Ok, "strong"),
    }
}

/// Findings for the key exchange result of one protocol version.
///
/// Emits one finding per weak group, one for a weak DH prime, and a note
/// when TLSv1.3 offers no post-quantum group.
#[must_use]
pub fn key_exchange_findings(result: &KeyExchangeResult) -> Vec<Finding> {
    let v = result.version;
    let mut out: Vec<Finding> = result
        .groups
        .iter()
        .filter_map(|&id| {
            let (severity, reason) = group_severity(id);
            (severity > Severity::Ok).then(|| {
                Finding::new(
                    "group.weak",
                    severity,
                    format!("{v} {}: {reason}", group_name(id)),
                )
            })
        })
        .collect();
    if let Some(bits) = result.dh_bits {
        let (severity, reason) = dh_severity(bits);
        if severity > Severity::Ok {
            out.push(Finding::new(
                "dh.weak",
                severity,
                format!("{v} DH parameters are {bits} bits: {reason}"),
            ));
        }
    }
    if result.dh_suites.iter().any(|d| d.bits.is_none()) {
        out.push(Finding::new(
            "dh.incomplete",
            Severity::Info,
            format!("{v} DH parameters could not be measured for every accepted suite"),
        ));
    }
    if v == ProtocolVersion::TLS13
        && !result.groups.is_empty()
        && !result.groups.iter().any(|&g| is_post_quantum(g))
    {
        out.push(Finding::new(
            "group.no_post_quantum",
            Severity::Info,
            format!("{v}: no post-quantum group such as X25519MLKEM768"),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use testls_probe::CipherOrder;

    use super::*;

    /// Builds a key exchange result for `version`.
    fn result(
        version: ProtocolVersion,
        groups: &[u16],
        dh_bits: Option<usize>,
    ) -> KeyExchangeResult {
        KeyExchangeResult {
            version,
            groups: groups.to_vec(),
            group_order: CipherOrder::Server,
            dh_bits,
            dh_prime: None,
            dh_key_reused: None,
            dh_suites: Vec::new(),
        }
    }

    /// Groups are rated by their RFC 8422 status.
    #[test]
    fn group_ratings() {
        assert_eq!(group_severity(0x0017).0, Severity::Ok);
        assert_eq!(group_severity(0x001d).0, Severity::Ok);
        assert_eq!(group_severity(0x11ec).0, Severity::Ok);
        assert_eq!(group_severity(0x0100).0, Severity::Ok);
        assert_eq!(group_severity(0x0015).0, Severity::Medium);
        assert_eq!(group_severity(0x0001).0, Severity::Medium);
        assert_eq!(group_severity(0xfafa).0, Severity::Info);
        assert_eq!(group_severity(0x6399).0, Severity::Low);
        assert_eq!(group_name(0x11ec), "X25519MLKEM768");
    }

    /// DH primes are rated by size.
    #[test]
    fn dh_ratings() {
        assert_eq!(dh_severity(512).0, Severity::High);
        assert_eq!(dh_severity(1024).0, Severity::Medium);
        assert_eq!(dh_severity(2048).0, Severity::Ok);
    }

    /// A legacy TLSv1.2 server yields weak group and DH findings.
    #[test]
    fn tls12_findings() {
        let f = key_exchange_findings(&result(
            ProtocolVersion::TLS12,
            &[0x0017, 0x0015],
            Some(1024),
        ));
        let ids: Vec<_> = f.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["group.weak", "dh.weak"]);
        assert_eq!(
            f[0].message,
            "TLSv1.2 secp224r1: deprecated curve (RFC 8422 §5.1.1)"
        );
        assert_eq!(crate::max_severity(&f), Some(Severity::Medium));
    }

    /// A weak measurement and an unmeasured suite both produce findings.
    #[test]
    fn partial_dh_findings() {
        let mut r = result(ProtocolVersion::TLS12, &[], Some(1024));
        r.dh_suites.push(testls_probe::DhSuiteResult {
            suite: 0x003a,
            bits: None,
            prime: None,
            key_reused: None,
        });
        let findings = key_exchange_findings(&r);
        assert!(findings.iter().any(|f| f.id == "dh.weak"));
        assert!(findings.iter().any(|f| f.id == "dh.incomplete"));
    }

    /// Every registered ML-KEM group counts as post-quantum; draft Kyber
    /// code points and classical groups do not.
    #[test]
    fn post_quantum_groups() {
        for id in [
            0x0200, 0x0201, 0x0202, 0x11e9, 0x11ea, 0x11eb, 0x11ec, 0x11ed, 0x11ee,
        ] {
            assert!(is_post_quantum(id), "{id:#06x}");
        }
        for id in [0x001d, 0x0100, 0x6399, 0xfafa] {
            assert!(!is_post_quantum(id), "{id:#06x}");
        }
    }

    /// TLSv1.3 without a post-quantum group gets an informational note.
    #[test]
    fn tls13_post_quantum() {
        let f = key_exchange_findings(&result(ProtocolVersion::TLS13, &[0x001d, 0x0017], None));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "group.no_post_quantum");
        assert_eq!(f[0].severity, Severity::Info);

        let f = key_exchange_findings(&result(ProtocolVersion::TLS13, &[0x11ec, 0x001d], None));
        assert_eq!(f.len(), 0);
        let f = key_exchange_findings(&result(ProtocolVersion::TLS13, &[], None));
        assert_eq!(f.len(), 0);
    }
}
