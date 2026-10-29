//! Revocation checks against the issuer's own services: the OCSP responder
//! named in the leaf's Authority Information Access extension
//! (RFC 5280 §4.2.2.1, RFC 6960) and the CRLs from its CRL Distribution
//! Points (RFC 5280 §4.2.1.13, §5).
//!
//! Fetching is left to the caller; this module extracts the URLs, verifies
//! what was fetched and turns the attempts into findings.

use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
use x509_parser::oid_registry::{
    OID_PKIX_ACCESS_DESCRIPTOR_OCSP, OID_PKIX_AUTHORITY_INFO_ACCESS,
    OID_X509_EXT_CRL_DISTRIBUTION_POINTS, OID_X509_EXT_DELTA_CRL_INDICATOR,
    OID_X509_EXT_ISSUER_DISTRIBUTION_POINT,
};
use x509_parser::parse_x509_crl;
use x509_parser::revocation_list::CertificateRevocationList;

use crate::ocsp::{OcspStatus, certificate, display_time, stale};
use crate::{CertStatus, Finding, Severity, revocation_reason_name};

/// Where the leaf certificate's issuer publishes revocation data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevocationUrls {
    /// OCSP responder URLs from Authority Information Access.
    pub ocsp: Vec<String>,
    /// CRL URLs from the full names of CRL Distribution Points.
    pub crl: Vec<String>,
}

/// Lists the OCSP responder and CRL URLs in a certificate, in the order
/// they appear. Every URI is returned, whatever its scheme, except those
/// holding spaces or control characters, which no valid URI contains.
///
/// # Errors
///
/// Returns a description if the certificate or one of the two extensions
/// cannot be parsed.
pub fn revocation_urls(leaf: &[u8]) -> Result<RevocationUrls, String> {
    let leaf = certificate(leaf)?;
    let mut urls = RevocationUrls::default();
    for ext in leaf.extensions() {
        if ext.oid == OID_PKIX_AUTHORITY_INFO_ACCESS {
            let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() else {
                return Err("invalid Authority Information Access extension".into());
            };
            for desc in &aia.accessdescs {
                if desc.access_method == OID_PKIX_ACCESS_DESCRIPTOR_OCSP
                    && let GeneralName::URI(uri) = desc.access_location
                    && is_uri_text(uri)
                {
                    urls.ocsp.push(uri.to_owned());
                }
            }
        } else if ext.oid == OID_X509_EXT_CRL_DISTRIBUTION_POINTS {
            let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() else {
                return Err("invalid CRL Distribution Points extension".into());
            };
            for point in &points.points {
                // CRLs from another issuer (indirect CRLs) are not supported.
                if point.crl_issuer.is_some() {
                    continue;
                }
                if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
                    urls.crl.extend(names.iter().filter_map(|name| match name {
                        GeneralName::URI(uri) if is_uri_text(uri) => Some((*uri).to_owned()),
                        _ => None,
                    }));
                }
            }
        }
    }
    Ok(urls)
}

/// Reports whether `uri` contains only the visible ASCII characters a URI
/// may hold (RFC 3986 §2), so it is safe to print and to request.
fn is_uri_text(uri: &str) -> bool {
    !uri.is_empty() && uri.bytes().all(|b| b.is_ascii_graphic())
}

/// Revocation status of the leaf according to a verified OCSP response or
/// CRL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationStatus {
    /// Status of the leaf certificate; CRLs never report `Unknown`.
    pub status: CertStatus,
    /// Start of the validity interval (`thisUpdate`), as a Unix timestamp.
    pub this_update: i64,
    /// End of the validity interval (`nextUpdate`), as a Unix timestamp.
    pub next_update: Option<i64>,
}

impl From<OcspStatus> for RevocationStatus {
    /// Keeps the parts of an OCSP response that matter for revocation.
    fn from(status: OcspStatus) -> Self {
        Self {
            status: status.status,
            this_update: status.this_update,
            next_update: status.next_update,
        }
    }
}

/// Parses a DER CRL and looks up the leaf of `chain` in it.
///
/// The CRL must be a complete CRL (not a delta) issued and signed by the
/// leaf's issuer, the second entry of `chain`, whose key usage, if present,
/// must allow `cRLSign` (RFC 5280 §4.2.1.3, §6.3.3). CRLs limited to CA
/// certificates, attribute certificates, some reasons or other issuers are
/// rejected. Freshness is left to [`revocation_findings`].
///
/// # Errors
///
/// Returns a description if the CRL is malformed, unsupported, from a
/// different issuer, or its signature does not verify.
pub fn verify_crl(crl: &[u8], chain: &[Vec<u8>]) -> Result<RevocationStatus, String> {
    let [leaf, issuer, ..] = chain else {
        return Err("issuer certificate missing from chain".into());
    };
    let leaf = certificate(leaf)?;
    let issuer = certificate(issuer)?;
    if leaf.issuer().as_raw() != issuer.subject().as_raw() {
        return Err("leaf certificate is not issued by the certificate issuer".into());
    }
    let crl = match parse_x509_crl(crl) {
        Ok(([], crl)) => crl,
        Ok(_) => return Err("CRL has trailing bytes".into()),
        Err(e) => return Err(format!("CRL cannot be parsed: {e}")),
    };
    if crl.issuer().as_raw() != issuer.subject().as_raw() {
        return Err("CRL is not issued by the certificate issuer".into());
    }
    let may_sign = match issuer.key_usage() {
        Ok(None) => true,
        Ok(Some(usage)) => usage.value.crl_sign(),
        Err(_) => false,
    };
    if !may_sign {
        return Err("issuer key usage does not allow signing CRLs".into());
    }
    crl.verify_signature(issuer.public_key())
        .map_err(|e| format!("CRL signature does not verify: {e}"))?;
    check_scope(&crl)?;
    let status = crl
        .iter_revoked_certificates()
        .find(|entry| entry.raw_serial() == leaf.raw_serial())
        .map_or(CertStatus::Good, |entry| CertStatus::Revoked {
            time: entry.revocation_date.timestamp(),
            reason: entry.reason_code().map(|(_, code)| u32::from(code.0)),
        });
    Ok(RevocationStatus {
        status,
        this_update: crl.last_update().timestamp(),
        next_update: crl.next_update().map(|time| time.timestamp()),
    })
}

/// Rejects CRLs that do not cover every end-entity certificate of the
/// issuer for every reason (RFC 5280 §5.2.4, §5.2.5).
fn check_scope(crl: &CertificateRevocationList<'_>) -> Result<(), String> {
    for ext in crl.extensions() {
        if ext.oid == OID_X509_EXT_DELTA_CRL_INDICATOR {
            return Err("delta CRLs are not supported".into());
        }
        if ext.oid == OID_X509_EXT_ISSUER_DISTRIBUTION_POINT {
            let ParsedExtension::IssuingDistributionPoint(point) = ext.parsed_extension() else {
                return Err("invalid Issuing Distribution Point extension".into());
            };
            if point.distribution_point.is_some()
                || point.only_contains_ca_certs
                || point.only_contains_attribute_certs
                || point.only_some_reasons.is_some()
                || point.indirect_crl
            {
                return Err("CRL covers only part of the issuer's certificates".into());
            }
        } else if ext.critical
            && matches!(
                ext.parsed_extension(),
                ParsedExtension::UnsupportedExtension { .. }
            )
        {
            return Err(format!(
                "CRL has an unsupported critical extension {}",
                ext.oid
            ));
        }
    }
    Ok(())
}

/// How revocation data was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationMethod {
    /// Query to the OCSP responder.
    Ocsp,
    /// Download of a CRL.
    Crl,
}

impl RevocationMethod {
    /// Short name used in messages and reports: `OCSP` or `CRL`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ocsp => "OCSP",
            Self::Crl => "CRL",
        }
    }
}

/// One attempt to learn the leaf's revocation status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationCheck {
    /// Responder query or CRL download.
    pub method: RevocationMethod,
    /// The URL that was used.
    pub url: String,
    /// The verified status, or why fetching or verification failed.
    pub outcome: Result<RevocationStatus, String>,
}

/// Findings for revocation checks against the issuer's services.
///
/// `checks` are the attempts in the order they were made; the first one
/// that succeeded decides the result. `now` is the current time as a Unix
/// timestamp.
#[must_use]
pub fn revocation_findings(checks: &[RevocationCheck], now: i64) -> Vec<Finding> {
    let Some((check, status)) = checks
        .iter()
        .find_map(|check| check.outcome.as_ref().ok().map(|status| (check, status)))
    else {
        return vec![match checks.last() {
            None => Finding::new(
                "revocation.no_source",
                Severity::Info,
                "certificate names no HTTP OCSP responder or CRL",
            ),
            Some(last) => Finding::new(
                "revocation.error",
                Severity::Info,
                format!(
                    "revocation status could not be checked: {} {}: {}",
                    last.method.as_str(),
                    last.url,
                    last.outcome.as_ref().err().map_or("", String::as_str)
                ),
            ),
        }];
    };
    let source = format!("{} {}", check.method.as_str(), check.url);
    match status.status {
        CertStatus::Revoked { time, reason } => {
            return vec![Finding::new(
                "revocation.revoked",
                Severity::Critical,
                format!(
                    "certificate was revoked on {} ({}) according to {source}",
                    display_time(time),
                    reason.map_or("no reason given", revocation_reason_name)
                ),
            )];
        }
        CertStatus::Unknown => {
            return vec![Finding::new(
                "revocation.unknown",
                Severity::Medium,
                format!("{source} does not know the certificate"),
            )];
        }
        CertStatus::Good => {}
    }
    if let Some(stale) = stale(
        "revocation",
        &source,
        status.this_update,
        status.next_update,
        now,
    ) {
        return vec![stale];
    }
    vec![Finding::new(
        "revocation.good",
        Severity::Ok,
        format!("certificate is not revoked according to {source}"),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_ocsp_response;

    /// A signed CRL for a named partition cannot establish a good status.
    #[test]
    fn rejects_partitioned_crl() {
        let crl = include_bytes!("testdata/ocsp-crl-partition.der");
        let error = verify_crl(crl, &chain(LEAF)).unwrap_err();
        assert!(error.contains("only part"), "{error}");
    }

    /// Self-signed test CA.
    const CA: &[u8] = include_bytes!("testdata/ocsp-ca.der");
    /// Leaf that is not revoked.
    const LEAF: &[u8] = include_bytes!("testdata/ocsp-leaf.der");
    /// Leaf revoked for key compromise on 2026-10-01.
    const OTHER: &[u8] = include_bytes!("testdata/ocsp-other.der");
    /// Leaf with OCSP and CRL URLs.
    const URLS: &[u8] = include_bytes!("testdata/ocsp-urls.der");
    /// Leaf issued by an unrelated intermediate CA.
    const FOREIGN: &[u8] = include_bytes!("testdata/trust-leaf.der");
    /// CRL from the test CA listing `OTHER`.
    const CRL: &[u8] = include_bytes!("testdata/ocsp-crl.der");
    /// The same CRL content issued and signed by the OCSP responder.
    const CRL_RESPONDER: &[u8] = include_bytes!("testdata/ocsp-crl-responder.der");
    /// CA-signed OCSP response: `LEAF` is good.
    const GOOD: &[u8] = include_bytes!("testdata/ocsp-good.der");

    /// One day in seconds.
    const DAY: i64 = 86_400;

    /// Chain of `leaf` and the test CA.
    fn chain(leaf: &[u8]) -> Vec<Vec<u8>> {
        vec![leaf.to_vec(), CA.to_vec()]
    }

    /// `thisUpdate` of the generated CRL; test times are relative to it.
    fn issued() -> i64 {
        verify_crl(CRL, &chain(LEAF))
            .expect("run scripts/gen-ocsp-fixtures.sh")
            .this_update
    }

    /// A check with the given method, URL and outcome.
    fn check(
        method: RevocationMethod,
        url: &str,
        outcome: Result<RevocationStatus, String>,
    ) -> RevocationCheck {
        RevocationCheck {
            method,
            url: url.into(),
            outcome,
        }
    }

    /// Finding ids and severities.
    fn ids(findings: &[Finding]) -> Vec<(&str, Severity)> {
        findings
            .iter()
            .map(|f| (f.id.as_str(), f.severity))
            .collect()
    }

    /// URLs come from AIA (OCSP only) and full-name distribution points.
    #[test]
    fn extracts_urls() {
        let urls = revocation_urls(URLS).unwrap();
        assert_eq!(urls.ocsp, ["http://ocsp.example.test/"]);
        assert_eq!(
            urls.crl,
            [
                "http://crl.example.test/ca.crl",
                "ldap://crl.example.test/ca"
            ]
        );
        assert_eq!(revocation_urls(LEAF).unwrap(), RevocationUrls::default());
        assert!(revocation_urls(b"junk").is_err());
    }

    /// URIs with spaces, control or non-ASCII characters are dropped.
    #[test]
    fn uri_text() {
        assert!(is_uri_text("http://ocsp.example.test/?a=%20&b=\"c\""));
        for bad in [
            "",
            "http://a b/",
            "http://a/\x1b[2J",
            "http://a/\n",
            "http://ä/",
        ] {
            assert!(!is_uri_text(bad), "{bad:?}");
        }
    }

    /// The CRL lists the revoked leaf with its reason and not the good one.
    #[test]
    fn crl_lookup() {
        let good = verify_crl(CRL, &chain(LEAF)).unwrap();
        assert_eq!(good.status, CertStatus::Good);
        assert_eq!(good.next_update, Some(good.this_update + 7 * DAY));
        let revoked = verify_crl(CRL, &chain(OTHER)).unwrap();
        assert_eq!(
            revoked.status,
            CertStatus::Revoked {
                time: 1_790_812_800,
                reason: Some(1)
            }
        );
    }

    /// CRLs from another issuer, leaves from another CA, tampered or truncated CRLs and missing
    /// issuers are rejected.
    #[test]
    fn invalid_crls() {
        assert_eq!(
            verify_crl(CRL_RESPONDER, &chain(LEAF)).unwrap_err(),
            "CRL is not issued by the certificate issuer"
        );
        assert_eq!(
            verify_crl(CRL, &chain(FOREIGN)).unwrap_err(),
            "leaf certificate is not issued by the certificate issuer"
        );
        let mut tampered = CRL.to_vec();
        // Flip the last digit of thisUpdate (the first UTCTime, tag 0x17).
        let at = tampered.windows(2).position(|w| w == [0x17, 0x0d]).unwrap() + 13;
        tampered[at] ^= 1;
        let err = verify_crl(&tampered, &chain(LEAF)).unwrap_err();
        assert!(err.starts_with("CRL signature does not verify"), "{err}");
        assert!(verify_crl(&CRL[..CRL.len() - 1], &chain(LEAF)).is_err());
        let mut trailing = CRL.to_vec();
        trailing.push(0);
        assert_eq!(
            verify_crl(&trailing, &chain(LEAF)).unwrap_err(),
            "CRL has trailing bytes"
        );
        assert_eq!(
            verify_crl(CRL, &[LEAF.to_vec()]).unwrap_err(),
            "issuer certificate missing from chain"
        );
    }

    /// The first successful attempt decides; failures before it are
    /// ignored.
    #[test]
    fn findings_from_attempts() {
        let now = issued() + DAY;
        let good = verify_crl(CRL, &chain(LEAF)).unwrap();
        let revoked = verify_crl(CRL, &chain(OTHER)).unwrap();
        let ocsp: RevocationStatus = verify_ocsp_response(GOOD, &chain(LEAF), now)
            .unwrap()
            .into();
        let failed = check(RevocationMethod::Ocsp, "http://o/", Err("timed out".into()));
        let crl = |status| check(RevocationMethod::Crl, "http://c/", Ok(status));

        assert_eq!(
            ids(&revocation_findings(&[], now)),
            [("revocation.no_source", Severity::Info)]
        );
        let findings = revocation_findings(std::slice::from_ref(&failed), now);
        assert_eq!(ids(&findings), [("revocation.error", Severity::Info)]);
        assert_eq!(
            findings[0].message,
            "revocation status could not be checked: OCSP http://o/: timed out"
        );
        let findings = revocation_findings(&[failed.clone(), crl(good)], now);
        assert_eq!(ids(&findings), [("revocation.good", Severity::Ok)]);
        assert_eq!(
            findings[0].message,
            "certificate is not revoked according to CRL http://c/"
        );
        let findings = revocation_findings(&[failed, crl(revoked)], now);
        assert_eq!(ids(&findings), [("revocation.revoked", Severity::Critical)]);
        assert!(
            findings[0]
                .message
                .contains("(keyCompromise) according to CRL")
        );
        let ocsp_check = check(RevocationMethod::Ocsp, "http://o/", Ok(ocsp));
        assert_eq!(
            ids(&revocation_findings(&[ocsp_check], now)),
            [("revocation.good", Severity::Ok)]
        );
        let unknown = RevocationStatus {
            status: CertStatus::Unknown,
            ..good
        };
        let unknown = check(RevocationMethod::Ocsp, "http://o/", Ok(unknown));
        assert_eq!(
            ids(&revocation_findings(&[unknown], now)),
            [("revocation.unknown", Severity::Medium)]
        );
    }

    /// Data outside its validity interval is reported as stale.
    #[test]
    fn stale_data() {
        let good = verify_crl(CRL, &chain(LEAF)).unwrap();
        let checks = [check(RevocationMethod::Crl, "http://c/", Ok(good))];
        assert_eq!(
            ids(&revocation_findings(&checks, issued() - DAY)),
            [("revocation.not_yet_valid", Severity::Medium)]
        );
        let findings = revocation_findings(&checks, issued() + 8 * DAY);
        assert_eq!(ids(&findings), [("revocation.expired", Severity::Medium)]);
        assert!(findings[0].message.starts_with("CRL http://c/ expired "));
    }
}
