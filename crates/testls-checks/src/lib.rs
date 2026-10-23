//! Scan findings, severity model, and check implementations.

mod certificates;
mod ciphers;
mod protocols;

use std::fmt;

pub use certificates::certificate_findings;
pub use ciphers::{cipher_findings, cipher_name, cipher_severity};
pub use protocols::{protocol_findings, protocol_severity};

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
}

impl Finding {
    /// Create a finding.
    #[must_use]
    pub fn new(id: impl Into<String>, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            severity,
            message: message.into(),
        }
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
