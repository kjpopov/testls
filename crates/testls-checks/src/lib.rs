//! Scan findings, severity model, and check implementations.

mod baseline;
mod certificates;
mod chain_order;
mod ciphers;
mod der;
mod details;
mod explain;
mod grade;
mod http;
mod http_extras;
mod intolerance;
mod key_exchange;
mod ocsp;
mod policy;
mod post_quantum;
mod protocols;
mod revocation;
mod trust;
mod vulnerabilities;

use std::fmt;

pub use baseline::{Sct, baseline_findings, embedded_scts, max_validity_days};
pub use certificates::{CertificateInfo, certificate_findings, describe_certificate};
pub use ciphers::{cipher_findings, cipher_name, cipher_severity};
pub use details::details_findings;
pub use explain::{Explanation, explain, explanations};
pub use grade::{Grade, Letter, grade};
pub use http::{Hsts, http_findings, parse_hsts};
pub use http_extras::{AltService, Cookie, alt_services, banners, cookies, http_extra_findings};
pub use intolerance::intolerance_findings;
pub use key_exchange::{dh_severity, group_name, group_severity, key_exchange_findings};
pub use ocsp::{
    CertStatus, OcspStatus, display_time, ocsp_findings, ocsp_request, revocation_reason_name,
    verify_ocsp_response,
};
pub use policy::{Policy, PolicyInput, policy_findings};
pub use post_quantum::{GroupKind, PostQuantum, PqStatus, group_kind, post_quantum_readiness};
pub use protocols::{protocol_findings, protocol_severity};
pub use revocation::{
    RevocationCheck, RevocationMethod, RevocationStatus, RevocationUrls, revocation_findings,
    revocation_urls, verify_crl,
};
pub use trust::{TrustStore, is_trusted, trust_findings};
pub use vulnerabilities::{
    VulnStatus, Vulnerability, assess_vulnerabilities, vulnerability_findings,
};

/// How serious a finding is. Ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Good configuration; reported for completeness.
    Ok,
    /// Neutral observation.
    Info,
    /// Minor weakness or outdated practice.
    Low,
    /// Weakness that should be fixed.
    Medium,
    /// Serious weakness, practically exploitable in some settings.
    High,
    /// Broken: no meaningful security.
    Critical,
}

impl Severity {
    /// All severities in ascending order.
    pub const ALL: [Self; 6] = [
        Self::Ok,
        Self::Info,
        Self::Low,
        Self::Medium,
        Self::High,
        Self::Critical,
    ];

    /// Lower-case name, as used on the command line and in JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when parsing an unknown severity name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseSeverityError(String);

impl fmt::Display for ParseSeverityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown severity {:?}", self.0)
    }
}

impl std::error::Error for ParseSeverityError {}

impl std::str::FromStr for Severity {
    type Err = ParseSeverityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|v| v.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| ParseSeverityError(s.to_owned()))
    }
}

/// One result of a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Stable machine-readable identifier, e.g. `protocol.tls10`.
    pub id: String,
    /// How serious the finding is.
    pub severity: Severity,
    /// Human-readable summary.
    pub message: String,
    /// Text that identifies the finding across runs, when it differs from
    /// `message` (see [`Finding::with_key`]).
    pub key: Option<String>,
}

impl Finding {
    /// Create a finding.
    #[must_use]
    pub fn new(id: impl Into<String>, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            severity,
            message: message.into(),
            key: None,
        }
    }

    /// Pin the text that identifies this finding across runs. Set it to the
    /// old message when a finding is reworded so tools that track findings
    /// (SARIF code scanning) keep their history.
    #[must_use]
    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    /// Text that identifies the finding: the pinned key, else the message.
    #[must_use]
    pub fn identity(&self) -> &str {
        self.key.as_deref().unwrap_or(&self.message)
    }
}

/// Highest severity among `findings`, or `None` if empty.
#[must_use]
pub fn max_severity<'a>(findings: impl IntoIterator<Item = &'a Finding>) -> Option<Severity> {
    findings.into_iter().map(|f| f.severity).max()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_order_and_parse() {
        assert!(Severity::Ok < Severity::Info);
        assert!(Severity::High < Severity::Critical);
        assert_eq!("HIGH".parse::<Severity>(), Ok(Severity::High));
        assert!("bogus".parse::<Severity>().is_err());
        for s in Severity::ALL {
            assert_eq!(s.to_string().parse::<Severity>(), Ok(s));
        }
    }

    #[test]
    fn max_of_findings() {
        let f = [
            Finding::new("a", Severity::Low, ""),
            Finding::new("b", Severity::High, ""),
        ];
        assert_eq!(max_severity(&f), Some(Severity::High));
        assert_eq!(max_severity(&[]), None);
    }
}
