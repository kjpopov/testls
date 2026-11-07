//! Scan profiles chosen with `--profile`: how much of the scan runs.

use std::fmt;
use std::str::FromStr;

/// How thorough a scan is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanProfile {
    /// Protocols, cipher suites and the certificate only.
    Quick,
    /// Every probe of the target itself.
    #[default]
    Default,
    /// `default` plus revocation lookups and every address of a host.
    Full,
}

/// Reason recorded for sections the `quick` profile leaves out.
pub const SKIPPED: &str = "skipped by --profile quick";

impl ScanProfile {
    /// All profiles, in the order shown in `--help`.
    pub const ALL: [Self; 3] = [Self::Quick, Self::Default, Self::Full];

    /// Lower-case name, as used on the command line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Default => "default",
            Self::Full => "full",
        }
    }

    /// Whether key exchange, HTTP, handshake feature, tolerance and
    /// detail probes run.
    #[must_use]
    pub fn deep(self) -> bool {
        self != Self::Quick
    }

    /// Whether the profile turns on `--revocation` and `--all-addresses`.
    #[must_use]
    pub fn full(self) -> bool {
        self == Self::Full
    }
}

impl fmt::Display for ScanProfile {
    /// Writes the command-line name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ScanProfile {
    type Err = String;

    /// Parses `quick`, `default` or `full`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|p| p.as_str() == s)
            .ok_or_else(|| format!("unknown profile {s:?}"))
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for profile names and switches.

    use super::*;

    /// Names round-trip and each profile turns on the right parts.
    #[test]
    fn profiles() {
        for p in ScanProfile::ALL {
            assert_eq!(p.as_str().parse::<ScanProfile>(), Ok(p));
            assert_eq!(p.to_string(), p.as_str());
        }
        assert!("thorough".parse::<ScanProfile>().is_err());
        assert_eq!(ScanProfile::default(), ScanProfile::Default);
        assert!(!ScanProfile::Quick.deep() && !ScanProfile::Quick.full());
        assert!(ScanProfile::Default.deep() && !ScanProfile::Default.full());
        assert!(ScanProfile::Full.deep() && ScanProfile::Full.full());
    }
}
