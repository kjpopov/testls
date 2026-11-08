//! `.testls.toml`: project settings read before a scan.
//!
//! For now the file only lists suppressions, findings that are accepted
//! for a while and must not fail the scan:
//!
//! ```toml
//! [[suppress]]
//! id = "cookie.insecure"
//! target = "example.com"     # optional (CIDR allowed), defaults to every target
//! reason = "legacy app, replaced in Q1"
//! expires = 2026-12-31       # optional, last day the entry applies (UTC)
//! ```

use std::path::Path;

use serde::Deserialize;
use testls_checks::Finding;
use testls_report::json::Suppressed;

use testls_scan::target::{Target, TargetSpec};

/// File looked up in the working directory when `--config` is not given.
pub const DEFAULT_PATH: &str = ".testls.toml";

/// Parsed `.testls.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Accepted findings.
    #[serde(default)]
    pub suppress: Vec<Suppression>,
}

/// One accepted finding.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suppression {
    /// Finding id to suppress, as shown by `testls explain`.
    pub id: String,
    /// Target or CIDR range the entry is limited to; every target when
    /// absent.
    #[serde(default, deserialize_with = "target")]
    pub target: Option<TargetSpec>,
    /// Why the finding is accepted.
    pub reason: String,
    /// Last day (UTC) the entry applies; forever when absent.
    pub expires: Option<toml::value::Datetime>,
}

/// Deserializes an optional target string with the CLI target syntax,
/// including CIDR ranges.
fn target<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Option<TargetSpec>, D::Error> {
    let s = String::deserialize(de)?;
    s.parse().map(Some).map_err(serde::de::Error::custom)
}

impl Config {
    /// Reads `path`, or [`DEFAULT_PATH`] when it exists and no path is
    /// given.
    pub fn load(path: Option<&Path>) -> Result<Self, String> {
        let explicit = path.is_some();
        let path = path.unwrap_or(Path::new(DEFAULT_PATH));
        let text = match std::fs::read_to_string(path) {
            Err(e) if !explicit && e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            text => text,
        };
        let text = text.map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Parses the file contents and checks each entry. Expired entries are
    /// kept but reported by [`Config::expired`].
    pub fn parse(text: &str) -> Result<Self, String> {
        let config: Self = toml::from_str(text).map_err(|e| e.to_string())?;
        for s in &config.suppress {
            if s.reason.trim().is_empty() {
                return Err(format!("suppression of {} needs a reason", s.id));
            }
            if s.expires.is_some() && s.expiry().is_none() {
                return Err(format!(
                    "suppression of {}: `expires` must be a date such as 2026-12-31",
                    s.id
                ));
            }
        }
        Ok(config)
    }

    /// Suppressed ids that no check emits, likely typos.
    pub fn unknown_ids(&self) -> impl Iterator<Item = &str> {
        self.suppress
            .iter()
            .map(|s| s.id.as_str())
            .filter(|id| testls_checks::explain(id).is_none())
    }

    /// Entries whose expiry date lies before `today`.
    pub fn expired(&self, today: (u16, u8, u8)) -> impl Iterator<Item = &Suppression> {
        self.suppress.iter().filter(move |s| !s.active(today))
    }

    /// Splits `findings` of `target` into those still reported and those
    /// suppressed by an active entry, the latter with the entry's reason.
    pub fn apply(
        &self,
        target: &Target,
        findings: Vec<Finding>,
        today: (u16, u8, u8),
    ) -> (Vec<Finding>, Vec<Suppressed>) {
        let mut kept = Vec::new();
        let mut suppressed = Vec::new();
        for finding in findings {
            match self
                .suppress
                .iter()
                .find(|s| s.active(today) && s.matches(target, &finding))
            {
                Some(s) => suppressed.push(Suppressed {
                    finding,
                    reason: s.reason.clone(),
                }),
                None => kept.push(finding),
            }
        }
        (kept, suppressed)
    }
}

impl Suppression {
    /// The expiry as `(year, month, day)`, `None` when absent or not a
    /// plain date.
    fn expiry(&self) -> Option<(u16, u8, u8)> {
        let d = self.expires?;
        match (d.date, d.time, d.offset) {
            (Some(date), None, None) => Some((date.year, date.month, date.day)),
            _ => None,
        }
    }

    /// Whether the entry still applies on `today` (its expiry day included).
    fn active(&self, today: (u16, u8, u8)) -> bool {
        self.expires.is_none() || self.expiry().is_some_and(|e| e >= today)
    }

    /// Whether the entry covers `finding` on `target`.
    fn matches(&self, target: &Target, finding: &Finding) -> bool {
        self.id == finding.id
            && self
                .target
                .as_ref()
                .is_none_or(|spec| spec.0.contains(target))
    }

    /// The expiry date as written, for messages.
    pub fn expires_text(&self) -> String {
        self.expires.map(|d| d.to_string()).unwrap_or_default()
    }
}

/// Converts a Unix timestamp to a UTC civil date `(year, month, day)`.
///
/// Uses the days-to-civil algorithm from Howard Hinnant, "chrono-Compatible
/// Low-Level Date Algorithms" (public domain).
pub fn utc_date(unix: i64) -> (u16, u8, u8) {
    let z = unix.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        u16::try_from(year).unwrap_or(u16::MAX),
        u8::try_from(month).unwrap_or(12),
        u8::try_from(day).unwrap_or(31),
    )
}

#[cfg(test)]
mod tests {
    //! Unit tests for config parsing and suppression matching.

    use testls_checks::Severity;

    use super::*;

    /// A fixed "today" for the tests.
    const TODAY: (u16, u8, u8) = (2026, 10, 26);

    /// Builds a finding with `id`.
    fn finding(id: &str) -> Finding {
        Finding::new(id, Severity::Medium, "msg")
    }

    /// Parses `text`, panicking on errors.
    fn parse(text: &str) -> Config {
        Config::parse(text).expect("valid config")
    }

    /// Entries match by id and optional target, and stop at their expiry.
    #[test]
    fn suppressions() {
        let config = parse(
            r#"
            [[suppress]]
            id = "cookie.insecure"
            reason = "legacy"

            [[suppress]]
            id = "hsts.missing"
            target = "a.example"
            reason = "internal"
            expires = 2026-10-26

            [[suppress]]
            id = "protocol.tls10"
            reason = "old"
            expires = 2026-10-25
            "#,
        );
        let a: Target = "a.example".parse().expect("target");
        let b: Target = "b.example:443".parse().expect("target");
        let all = || {
            ["cookie.insecure", "hsts.missing", "protocol.tls10"]
                .map(finding)
                .to_vec()
        };
        let ids = |v: &[Finding]| v.iter().map(|f| f.id.clone()).collect::<Vec<_>>();

        let (kept, suppressed) = config.apply(&a, all(), TODAY);
        assert_eq!(ids(&kept), ["protocol.tls10"]);
        let reasons: Vec<_> = suppressed
            .iter()
            .map(|s| (s.finding.id.as_str(), s.reason.as_str()))
            .collect();
        assert_eq!(
            reasons,
            [("cookie.insecure", "legacy"), ("hsts.missing", "internal")]
        );
        let (kept, _) = config.apply(&b, all(), TODAY);
        assert_eq!(ids(&kept), ["hsts.missing", "protocol.tls10"]);
        let (kept, _) = config.apply(&a, all(), (2026, 10, 27));
        assert_eq!(ids(&kept), ["hsts.missing", "protocol.tls10"]);

        let expired: Vec<_> = config.expired(TODAY).map(|s| s.id.as_str()).collect();
        assert_eq!(expired, ["protocol.tls10"]);
        assert_eq!(config.suppress[2].expires_text(), "2026-10-25");
    }

    /// A CIDR target covers every address in its range and nothing else.
    #[test]
    fn cidr_target() {
        let config = parse(
            r#"
            [[suppress]]
            id = "cookie.insecure"
            target = "192.0.2.0/30"
            reason = "range"
            "#,
        );
        let target = |s: &str| s.parse::<Target>().expect("target");
        let kept = |t: &str| {
            config
                .apply(&target(t), vec![finding("cookie.insecure")], TODAY)
                .0
        };
        assert_eq!(kept("192.0.2.3").len(), 0);
        assert_eq!(kept("192.0.2.4").len(), 1);
        assert_eq!(kept("192.0.2.3:8443").len(), 1);
    }

    /// Bad entries are rejected with a message naming the problem.
    #[test]
    fn invalid() {
        let err = |text: &str| Config::parse(text).expect_err("invalid");
        assert!(err("[[suppress]]\nid = \"x\"\n").contains("reason"));
        assert!(err("[[suppress]]\nid = \"x\"\nreason = \" \"\n").contains("needs a reason"));
        assert!(
            err("[[suppress]]\nid = \"x\"\nreason = \"r\"\nexpires = 2026-01-01T00:00:00Z\n")
                .contains("must be a date")
        );
        assert!(
            err("[[suppress]]\nid = \"x\"\nreason = \"r\"\ntarget = \"a b\"\n").contains("target")
        );
        assert!(err("[[suppress]]\nid = \"x\"\nreason = \"r\"\nextra = 1\n").contains("extra"));
        assert!(err("unknown = 1\n").contains("unknown"));
        assert!(parse("").suppress.is_empty());
        let typo = parse("[[suppress]]\nid = \"hsts.mising\"\nreason = \"r\"\n");
        assert_eq!(typo.unknown_ids().collect::<Vec<_>>(), ["hsts.mising"]);
    }

    /// A missing explicit file is an error.
    #[test]
    fn loading() {
        assert!(Config::load(Some(Path::new("no/such/file.toml"))).is_err());
    }

    /// Unix timestamps map to the right UTC calendar day.
    #[test]
    fn dates() {
        assert_eq!(utc_date(0), (1970, 1, 1));
        assert_eq!(utc_date(951_782_400), (2000, 2, 29));
        assert_eq!(utc_date(1_798_761_599), (2026, 12, 31));
        assert_eq!(utc_date(1_798_761_600), (2027, 1, 1));
        assert_eq!(utc_date(-1), (1969, 12, 31));
    }
}
