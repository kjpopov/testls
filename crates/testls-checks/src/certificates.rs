//! Findings for the server's certificate chain: validity period, host name
//! match, public key strength, and signature algorithm.
//!
//! Trust (chain building against a root store) is checked by
//! [`trust_findings`](crate::trust_findings).

use std::net::IpAddr;

use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;
use x509_parser::public_key::PublicKey;
use x509_parser::signature_algorithm::SignatureAlgorithm;

use crate::{Finding, Severity};

/// Seconds in a day.
const DAY: i64 = 24 * 60 * 60;

/// Certificates expiring within this many days get a warning.
const EXPIRY_WARNING_DAYS: i64 = 30;

/// Checks a DER certificate chain (leaf first) as presented by a server.
///
/// `host` is the name the client connected to (SNI name or IP address); it
/// is matched against the leaf's subject alternative names. Internationalised
/// names must already be in A-label (punycode) form, as they are on the wire
/// in SNI (RFC 6066 §3). `now` is the current time as a Unix timestamp.
#[must_use]
pub fn certificate_findings(chain: &[Vec<u8>], host: Option<&str>, now: i64) -> Vec<Finding> {
    let Some(leaf_der) = chain.first() else {
        return vec![Finding::new(
            "cert.missing",
            Severity::High,
            "server sent no certificate",
        )];
    };
    let leaf = match parse_entry(leaf_der) {
        Ok(cert) => cert,
        Err(e) => {
            return vec![Finding::new(
                "cert.unparsable",
                Severity::High,
                format!("leaf certificate cannot be parsed: {e}"),
            )];
        }
    };

    let mut findings = validity_findings(&leaf, now);
    if let Some(host) = host {
        findings.extend(hostname_finding(&leaf, host));
    }
    findings.extend(key_finding(&leaf));
    findings.extend(signature_finding(&leaf, 0));
    let mut presented = vec![Some(leaf)];
    for (position, der) in chain.iter().enumerate().skip(1) {
        match parse_entry(der) {
            Ok(cert) => {
                findings.extend(signature_finding(&cert, position));
                presented.push(Some(cert));
            }
            Err(e) => {
                findings.push(Finding::new(
                    "cert.unparsable",
                    Severity::High,
                    format!("chain certificate #{position} cannot be parsed: {e}"),
                ));
                presented.push(None);
            }
        }
    }
    findings.extend(crate::chain_order::misplaced_issuer(&presented));
    findings
}

/// Human-readable details of one certificate, for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    /// Subject distinguished name, e.g. `CN=localhost`.
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Start of the validity period.
    pub not_before: String,
    /// End of the validity period.
    pub not_after: String,
    /// Start of the validity period as a Unix timestamp.
    pub not_before_unix: i64,
    /// End of the validity period as a Unix timestamp.
    pub not_after_unix: i64,
    /// DNS names and IP addresses from the subject alternative names.
    pub names: Vec<String>,
    /// Public key algorithm and size, e.g. `RSA 2048 bits`.
    pub key: String,
    /// Number of embedded Certificate Transparency timestamps, or `None`
    /// if the SCT list cannot be read.
    pub scts: Option<usize>,
}

/// Describes a DER certificate for display.
///
/// # Errors
///
/// Returns the parse error if `der` is not exactly one certificate.
pub fn describe_certificate(der: &[u8]) -> Result<CertificateInfo, String> {
    let cert = parse_entry(der)?;
    let validity = cert.validity();
    let names = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(san_label)
                .map(|name| printable(&name))
                .collect()
        })
        .unwrap_or_default();
    let key = match cert.public_key().parsed() {
        Ok(key) => {
            let label = match key {
                PublicKey::RSA(_) => "RSA",
                PublicKey::EC(_) => "EC",
                PublicKey::DSA(_) => "DSA",
                _ => "other",
            };
            format!("{label} {} bits", key.key_size())
        }
        Err(_) => "unknown".to_owned(),
    };
    Ok(CertificateInfo {
        subject: printable(&cert.subject().to_string()),
        issuer: printable(&cert.issuer().to_string()),
        not_before: validity.not_before.to_string(),
        not_after: validity.not_after.to_string(),
        not_before_unix: validity.not_before.timestamp(),
        not_after_unix: validity.not_after.timestamp(),
        names,
        key,
        scts: crate::embedded_scts(der).ok().map(|scts| scts.len()),
    })
}

/// Escapes control characters (e.g. terminal escape sequences) in
/// certificate-supplied text so it is safe to print.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Display form of a DNS or IP subject alternative name; other kinds are
/// skipped.
fn san_label(name: &GeneralName<'_>) -> Option<String> {
    match name {
        GeneralName::DNSName(dns) => Some((*dns).to_owned()),
        GeneralName::IPAddress(octets) => match octets.len() {
            4 => <[u8; 4]>::try_from(*octets)
                .ok()
                .map(|o| IpAddr::from(o).to_string()),
            16 => <[u8; 16]>::try_from(*octets)
                .ok()
                .map(|o| IpAddr::from(o).to_string()),
            _ => None,
        },
        _ => None,
    }
}

/// Parses one chain entry, which must be exactly one DER certificate
/// (RFC 8446 §4.4.2 `cert_data`); trailing bytes are an error.
fn parse_entry(der: &[u8]) -> Result<X509Certificate<'_>, String> {
    match parse_x509_certificate(der) {
        Ok(([], cert)) => Ok(cert),
        Ok((rest, _)) => Err(format!("{} trailing bytes", rest.len())),
        Err(e) => Err(e.to_string()),
    }
}

/// Expired, not yet valid, or soon-to-expire leaf certificate.
fn validity_findings(leaf: &X509Certificate<'_>, now: i64) -> Vec<Finding> {
    let validity = leaf.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    if now > not_after {
        let days = (now - not_after) / DAY;
        return vec![Finding::new(
            "cert.expired",
            Severity::Critical,
            format!(
                "certificate expired {days} days ago ({})",
                validity.not_after
            ),
        )];
    }
    if now < not_before {
        return vec![Finding::new(
            "cert.not_yet_valid",
            Severity::Critical,
            format!("certificate is not valid before {}", validity.not_before),
        )];
    }
    let days_left = (not_after - now) / DAY;
    if days_left < EXPIRY_WARNING_DAYS {
        return vec![Finding::new(
            "cert.expires_soon",
            Severity::Low,
            format!(
                "certificate expires in {days_left} days ({})",
                validity.not_after
            ),
        )];
    }
    Vec::new()
}

/// Leaf does not cover `host` in its subject alternative names.
///
/// Per RFC 9525 the subject common name is not consulted.
fn hostname_finding(leaf: &X509Certificate<'_>, host: &str) -> Option<Finding> {
    let names = leaf
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| ext.value.general_names.clone())
        .unwrap_or_default();
    let matched = match host.parse::<IpAddr>() {
        Ok(ip) => names
            .iter()
            .any(|n| matches!(n, GeneralName::IPAddress(b) if ip_matches(ip, b))),
        Err(_) => names
            .iter()
            .any(|n| matches!(n, GeneralName::DNSName(p) if dns_matches(p, host))),
    };
    (!matched).then(|| {
        Finding::new(
            "cert.hostname_mismatch",
            Severity::High,
            format!("certificate does not cover {host}"),
        )
    })
}

/// Compares an IP address with the raw octets of an `iPAddress` SAN entry.
fn ip_matches(ip: IpAddr, octets: &[u8]) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets() == octets,
        IpAddr::V6(v6) => v6.octets() == octets,
    }
}

/// Matches a `dNSName` pattern against a host name (RFC 9525 §6.3).
///
/// Comparison is case-insensitive and ignores a trailing dot. A wildcard is
/// only honoured as the complete left-most label and matches exactly one
/// label.
fn dns_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix),
        None => pattern == host,
    }
}

/// Weak leaf public key.
fn key_finding(leaf: &X509Certificate<'_>) -> Option<Finding> {
    let key = match leaf.public_key().parsed() {
        Ok(key) => key,
        Err(e) => {
            return Some(Finding::new(
                "cert.key_unparsable",
                Severity::Medium,
                format!("public key cannot be parsed: {e}"),
            ));
        }
    };
    let bits = key.key_size();
    // Thresholds follow NIST SP 800-57 Part 1 Rev. 5, table 2: 2048-bit RSA
    // and 224-bit EC are the minimum for 112-bit security.
    let (severity, label) = match key {
        PublicKey::RSA(_) if bits < 1024 => (Severity::Critical, "RSA"),
        PublicKey::RSA(_) if bits < 2048 => (Severity::High, "RSA"),
        PublicKey::EC(_) if bits < 224 => (Severity::High, "EC"),
        PublicKey::DSA(_) => (Severity::Medium, "DSA"),
        _ => return None,
    };
    Some(Finding::new(
        "cert.weak_key",
        severity,
        format!("{label} key of {bits} bits is too weak"),
    ))
}

/// Signature algorithms with broken or deprecated hashes, by OID.
///
/// OIDs from RFC 8017 appendix C (PKCS #1), RFC 3279 §2.2 (DSA, ECDSA) and
/// the OIW registry (1.3.14.3.2.x).
const WEAK_SIGNATURES: &[(&str, Severity, &str)] = &[
    ("1.2.840.113549.1.1.2", Severity::Critical, "MD2"),
    ("1.2.840.113549.1.1.3", Severity::Critical, "MD4"),
    ("1.2.840.113549.1.1.4", Severity::Critical, "MD5"),
    ("1.3.14.3.2.25", Severity::Critical, "MD5"),
    ("1.2.840.113549.1.1.5", Severity::High, "SHA-1"),
    ("1.3.14.3.2.29", Severity::High, "SHA-1"),
    ("1.2.840.10040.4.3", Severity::High, "SHA-1"),
    ("1.2.840.10045.4.1", Severity::High, "SHA-1"),
];

/// Hash algorithms that make an RSASSA-PSS signature weak, by OID.
///
/// OIDs from RFC 8017 appendix B.1 and RFC 3279 §2.2.
const WEAK_PSS_HASHES: &[(&str, Severity, &str)] = &[
    ("1.2.840.113549.2.2", Severity::Critical, "MD2"),
    ("1.2.840.113549.2.5", Severity::Critical, "MD5"),
    ("1.3.14.3.2.26", Severity::High, "SHA-1"),
];

/// Weak signature on a certificate. Self-signed certificates above the leaf
/// (roots) are skipped: clients never verify their signature.
fn signature_finding(cert: &X509Certificate<'_>, position: usize) -> Option<Finding> {
    if position > 0 && is_self_signed(cert) {
        return None;
    }
    let (severity, hash) = weak_signature(cert)?;
    let which = if position == 0 {
        "leaf certificate".to_owned()
    } else {
        format!("chain certificate #{position}")
    };
    Some(Finding::new(
        "cert.weak_signature",
        severity,
        format!("{which} is signed with {hash}"),
    ))
}

/// Whether the certificate is signed by its own key, not merely self-issued
/// (a key rollover certificate has subject == issuer but a different key).
fn is_self_signed(cert: &X509Certificate<'_>) -> bool {
    cert.subject() == cert.issuer() && cert.verify_signature(None).is_ok()
}

/// Severity and hash name of a weak signature algorithm, if it is one.
///
/// For RSASSA-PSS the hash comes from the parameters, defaulting to SHA-1
/// when absent (RFC 4055 §3.1).
fn weak_signature(cert: &X509Certificate<'_>) -> Option<(Severity, &'static str)> {
    let algorithm = &cert.signature_algorithm;
    let (table, oid) = match SignatureAlgorithm::try_from(algorithm) {
        Ok(SignatureAlgorithm::RSASSA_PSS(params)) => {
            (WEAK_PSS_HASHES, params.hash_algorithm_oid().to_id_string())
        }
        _ => (WEAK_SIGNATURES, algorithm.algorithm.to_id_string()),
    };
    table
        .iter()
        .find(|(o, ..)| *o == oid)
        .map(|&(_, severity, hash)| (severity, hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-signed P-256 leaf, SAN `localhost` + `127.0.0.1`, valid 2026-01-01..2027-01-01.
    const EC_LOCALHOST: &[u8] = include_bytes!("testdata/ec-localhost.der");
    /// Self-signed RSA-1024/SHA-1 leaf, SAN `*.example.com`, same validity.
    const RSA1024_SHA1: &[u8] = include_bytes!("testdata/rsa1024-sha1-wildcard.der");
    /// Self-signed RSA-2048 leaf without SAN (CN `nosan.example`), same validity.
    const RSA2048_NO_SAN: &[u8] = include_bytes!("testdata/rsa2048-no-san.der");

    /// 2026-07-01T00:00:00Z, inside every fixture's validity period.
    const MID_2026: i64 = 1_782_864_000;
    /// 2027-01-01T00:00:00Z, the fixtures' `notAfter`.
    const NOT_AFTER: i64 = 1_798_761_600;

    /// Expected id list when there are no findings.
    const NONE: [&str; 0] = [];

    /// Runs the checks on a single certificate and returns the finding ids.
    fn ids(der: &[u8], host: Option<&str>, now: i64) -> Vec<String> {
        certificate_findings(&[der.to_vec()], host, now)
            .into_iter()
            .map(|f| f.id)
            .collect()
    }

    /// A good certificate for the right host produces no findings.
    #[test]
    fn clean_certificate() {
        assert_eq!(ids(EC_LOCALHOST, Some("localhost"), MID_2026), NONE);
        assert_eq!(ids(EC_LOCALHOST, Some("127.0.0.1"), MID_2026), NONE);
        assert_eq!(ids(EC_LOCALHOST, None, MID_2026), NONE);
    }

    /// Validity window boundaries.
    #[test]
    fn validity() {
        assert_eq!(ids(EC_LOCALHOST, None, NOT_AFTER + DAY), ["cert.expired"]);
        assert_eq!(
            ids(EC_LOCALHOST, None, NOT_AFTER - 10 * DAY),
            ["cert.expires_soon"]
        );
        assert_eq!(ids(EC_LOCALHOST, None, 0), ["cert.not_yet_valid"]);
    }

    /// Host names and IPs not in the SAN list are reported.
    #[test]
    fn hostname_mismatch() {
        assert_eq!(
            ids(EC_LOCALHOST, Some("example.com"), MID_2026),
            ["cert.hostname_mismatch"]
        );
        assert_eq!(
            ids(EC_LOCALHOST, Some("::1"), MID_2026),
            ["cert.hostname_mismatch"]
        );
        // The CN is ignored when there is no SAN.
        assert_eq!(
            ids(RSA2048_NO_SAN, Some("nosan.example"), MID_2026),
            ["cert.hostname_mismatch"]
        );
    }

    /// Weak key and SHA-1 signature on the same leaf.
    #[test]
    fn weak_key_and_signature() {
        let findings =
            certificate_findings(&[RSA1024_SHA1.to_vec()], Some("www.example.com"), MID_2026);
        let summary: Vec<_> = findings
            .iter()
            .map(|f| (f.id.as_str(), f.severity))
            .collect();
        assert_eq!(
            summary,
            [
                ("cert.weak_key", Severity::High),
                ("cert.weak_signature", Severity::High),
            ]
        );
        assert_eq!(findings[0].message, "RSA key of 1024 bits is too weak");
        assert_eq!(findings[1].message, "leaf certificate is signed with SHA-1");
    }

    /// Self-signed roots further up the chain are not judged by signature.
    #[test]
    fn self_signed_root_signature_ignored() {
        let chain = [EC_LOCALHOST.to_vec(), RSA1024_SHA1.to_vec()];
        let ids: Vec<_> = certificate_findings(&chain, Some("localhost"), MID_2026)
            .into_iter()
            .map(|f| f.id)
            .collect();
        assert_eq!(ids, NONE);
    }

    /// Self-signed RSA-2048 leaf signed with RSASSA-PSS using the default
    /// (SHA-1) hash parameters, SAN `pss.example`, same validity.
    const RSA_PSS_SHA1: &[u8] = include_bytes!("testdata/rsa-pss-sha1.der");
    /// Self-issued `CN=Rollover` certificate whose SHA-1 signature was made
    /// by a different key (a key rollover certificate), same validity.
    const ROLLOVER_SHA1: &[u8] = include_bytes!("testdata/rollover-sha1.der");
    /// Self-signed `CN=Rollover` SHA-1 root, same validity.
    const ROOT_SHA1: &[u8] = include_bytes!("testdata/root-sha1.der");

    /// RSASSA-PSS with the default SHA-1 hash counts as a SHA-1 signature.
    #[test]
    fn pss_default_sha1_is_weak() {
        let findings =
            certificate_findings(&[RSA_PSS_SHA1.to_vec()], Some("pss.example"), MID_2026);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "cert.weak_signature");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].message, "leaf certificate is signed with SHA-1");
    }

    /// A self-issued certificate signed by another key is still judged;
    /// a truly self-signed root is not.
    #[test]
    fn rollover_signature_reported() {
        let chain = [
            EC_LOCALHOST.to_vec(),
            ROLLOVER_SHA1.to_vec(),
            ROOT_SHA1.to_vec(),
        ];
        let findings = certificate_findings(&chain, Some("localhost"), MID_2026);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "cert.weak_signature");
        assert_eq!(
            findings[0].message,
            "chain certificate #1 is signed with SHA-1"
        );
    }

    /// An unparsable certificate further up the chain is reported.
    #[test]
    fn unparsable_chain_certificate() {
        let chain = [EC_LOCALHOST.to_vec(), b"garbage".to_vec()];
        let findings = certificate_findings(&chain, Some("localhost"), MID_2026);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "cert.unparsable");
        assert!(findings[0].message.starts_with("chain certificate #1 "));
    }

    /// Trailing bytes after a certificate make it unparsable.
    #[test]
    fn trailing_bytes() {
        let mut leaf = EC_LOCALHOST.to_vec();
        leaf.push(0);
        assert_eq!(ids_of(&[leaf.clone()]), ["cert.unparsable"]);
        let findings = certificate_findings(&[EC_LOCALHOST.to_vec(), leaf], None, MID_2026);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].message,
            "chain certificate #1 cannot be parsed: 1 trailing bytes"
        );
    }

    /// Empty and garbage chains.
    #[test]
    fn missing_or_broken() {
        assert_eq!(ids_of(&[]), ["cert.missing"]);
        assert_eq!(
            ids_of(&[b"not a certificate".to_vec()]),
            ["cert.unparsable"]
        );
    }

    /// Finding ids for an arbitrary chain.
    fn ids_of(chain: &[Vec<u8>]) -> Vec<String> {
        certificate_findings(chain, None, MID_2026)
            .into_iter()
            .map(|f| f.id)
            .collect()
    }

    /// Subject, issuer, validity, SANs, and key are extracted for display.
    #[test]
    fn describe() {
        let info = describe_certificate(EC_LOCALHOST).unwrap();
        assert_eq!(info.scts, Some(0));
        assert_eq!(info.subject, info.issuer);
        assert!(info.subject.contains("localhost"), "{}", info.subject);
        assert!(info.not_before.contains("2026"), "{}", info.not_before);
        assert!(info.not_after.contains("2027"), "{}", info.not_after);
        assert_eq!(info.not_before_unix, NOT_AFTER - 365 * DAY);
        assert_eq!(info.not_after_unix, NOT_AFTER);
        assert_eq!(info.names, ["localhost", "127.0.0.1"]);
        assert_eq!(info.key, "EC 256 bits");

        let info = describe_certificate(RSA1024_SHA1).unwrap();
        assert_eq!(info.names, ["*.example.com"]);
        assert_eq!(info.key, "RSA 1024 bits");

        assert!(describe_certificate(b"junk").is_err());
    }

    /// Self-signed certificate whose subject and SAN contain ESC sequences.
    const CONTROL_CHARS: &[u8] = include_bytes!("testdata/control-chars.der");

    /// Control characters from the certificate are escaped, not passed
    /// through to the terminal.
    #[test]
    fn describe_escapes_control_characters() {
        let info = describe_certificate(CONTROL_CHARS).unwrap();
        let all = [&info.subject, &info.issuer]
            .into_iter()
            .chain(&info.names)
            .collect::<Vec<_>>();
        for text in &all {
            assert!(!text.chars().any(char::is_control), "{text:?}");
        }
        assert_eq!(info.names, [r"bad\u{1b}[2Jname"]);
    }

    /// RFC 9525 wildcard rules.
    #[test]
    fn dns_matching() {
        assert!(dns_matches("example.com", "EXAMPLE.com."));
        assert!(dns_matches("*.example.com", "www.example.com"));
        assert!(!dns_matches("*.example.com", "example.com"));
        assert!(!dns_matches("*.example.com", "a.b.example.com"));
        assert!(!dns_matches("w*.example.com", "www.example.com"));
    }
}
