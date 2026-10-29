//! `--baseline`: a previous JSON report whose findings are accepted.
//!
//! A finding is known when the baseline has a document for the same target
//! input (as given on the command line) with a finding of the same id and equal or greater severity. The
//! message is ignored because its wording may change. Findings that were
//! suppressed in the baseline are not known, so expiring a suppression is
//! not undone by the baseline.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use testls_checks::{Finding, Severity};
use testls_report::json::{SCHEMA_VERSION, Suppressed};

/// Reason attached to findings set aside because the baseline has them.
pub const REASON: &str = "in baseline";

/// Highest accepted severity for each `(target input, finding id)` pair.
#[derive(Debug, Default)]
pub struct Baseline {
    /// Accepted severities from every document in the file.
    known: HashMap<(String, String), Severity>,
}

/// The parts of a JSON report document the baseline needs.
#[derive(Debug, Deserialize)]
struct Document {
    /// Must equal [`SCHEMA_VERSION`].
    schema_version: u32,
    /// Producer; `name` must be `testls`.
    tool: DocumentTool,
    /// Scan start; required so that fragments are rejected.
    #[allow(dead_code)] // only checked for presence
    started_at: i64,
    /// The scanned target.
    target: DocumentTarget,
    /// Reported findings.
    findings: Vec<DocumentFinding>,
}

/// `tool` of a report document.
#[derive(Debug, Deserialize)]
struct DocumentTool {
    /// Tool name.
    name: String,
}

/// `target` of a report document.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // `address` is only checked for presence
struct DocumentTarget {
    /// Target as given on the command line.
    input: String,
    /// Scanned socket address.
    address: String,
}

/// One entry of `findings` in a report document.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // `message` is only checked for presence
struct DocumentFinding {
    /// Finding id.
    id: String,
    /// Severity name.
    severity: String,
    /// Finding message.
    message: String,
}

impl Baseline {
    /// Reads the report at `path`.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read baseline {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("baseline {}: {e}", path.display()))
    }

    /// Parses `--format json` output: one document or an array of them.
    pub fn parse(text: &str) -> Result<Self, String> {
        let value: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let documents: Vec<Document> = if value.is_array() {
            serde_json::from_value(value)
        } else {
            serde_json::from_value(value).map(|d| vec![d])
        }
        .map_err(|e| format!("not a testls JSON report: {e}"))?;
        let mut known = HashMap::new();
        for d in documents {
            if d.tool.name != "testls" {
                return Err(format!(
                    "not a testls JSON report: tool is {:?}",
                    d.tool.name
                ));
            }
            if d.schema_version != SCHEMA_VERSION {
                return Err(format!(
                    "schema_version {} is not supported (expected {SCHEMA_VERSION})",
                    d.schema_version
                ));
            }
            for f in d.findings {
                let severity: Severity = f
                    .severity
                    .parse()
                    .map_err(|e| format!("invalid baseline severity: {e}"))?;
                known
                    .entry((d.target.input.clone(), f.id))
                    .and_modify(|old| *old = std::cmp::max(*old, severity))
                    .or_insert(severity);
            }
        }
        Ok(Self { known })
    }

    /// Whether the baseline has `id` for `target`.
    fn contains(&self, target: &str, id: &str, severity: Severity) -> bool {
        !matches!(id.rsplit('.').next(), Some("error" | "incomplete"))
            && self
                .known
                .get(&(target.to_owned(), id.to_owned()))
                .is_some_and(|old| severity <= *old)
    }

    /// Splits `findings` of `target` into new ones and known ones, the
    /// latter with [`REASON`].
    pub fn apply(&self, target: &str, findings: Vec<Finding>) -> (Vec<Finding>, Vec<Suppressed>) {
        let (known, new): (Vec<_>, Vec<_>) = findings
            .into_iter()
            .partition(|f| self.contains(target, &f.id, f.severity));
        let known = known
            .into_iter()
            .map(|finding| Suppressed {
                finding,
                reason: REASON.to_owned(),
            })
            .collect();
        (new, known)
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for baseline parsing and matching.

    use testls_checks::Severity;

    use super::*;

    /// Builds a finding with `id`.
    fn finding(id: &str) -> Finding {
        Finding::new(id, Severity::Low, "msg")
    }

    /// A minimal report document for `input` with finding `ids`.
    fn document(input: &str, ids: &[&str]) -> String {
        let findings: Vec<String> = ids
            .iter()
            .map(|id| format!(r#"{{"id":"{id}","severity":"low","message":"m"}}"#))
            .collect();
        format!(
            r#"{{"schema_version":1,"tool":{{"name":"testls","version":"0"}},"started_at":0,"target":{{"input":"{input}","address":"192.0.2.1:443","sni":null}},"findings":[{}],"suppressed":[{{"id":"s.id","severity":"low","message":"m","reason":"r"}}]}}"#,
            findings.join(",")
        )
    }

    /// Known findings match by target input and id; the rest stay new.
    #[test]
    fn matching() {
        let one = Baseline::parse(&document("a.example", &["cookie.insecure"])).expect("valid");
        let (new, known) = one.apply(
            "a.example",
            vec![finding("cookie.insecure"), finding("hsts.missing")],
        );
        assert_eq!(new, vec![finding("hsts.missing")]);
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].finding.id, "cookie.insecure");
        assert_eq!(known[0].reason, REASON);
        let (new, known) = one.apply("b.example", vec![finding("cookie.insecure")]);
        assert_eq!((new.len(), known.len()), (1, 0));
        let (new, _) = one.apply("a.example", vec![finding("s.id")]);
        assert_eq!(new.len(), 1, "suppressed findings are not known");

        let many = Baseline::parse(&format!(
            "[{},{}]",
            document("a.example", &[]),
            document("b.example", &["hsts.missing"])
        ))
        .expect("valid");
        assert!(many.contains("b.example", "hsts.missing", Severity::Low));
        assert!(!many.contains("a.example", "hsts.missing", Severity::Low));
    }

    /// Baselines cannot hide worsening findings or accept unknown severities.
    #[test]
    fn severity_escalation() {
        for (id, severity) in [("protocol.ssl3", "info"), ("dh.weak", "medium")] {
            let baseline = Baseline::parse(&document("a", &[id]).replace("low", severity)).unwrap();
            let (new, known) =
                baseline.apply("a", vec![Finding::new(id, Severity::High, "worsened")]);
            assert_eq!(new.len(), 1);
            assert_eq!(known.len(), 0);
        }
        let baseline =
            Baseline::parse(&document("a", &["cert.error", "policy.incomplete"])).unwrap();
        let (new, known) = baseline.apply(
            "a",
            vec![finding("cert.error"), finding("policy.incomplete")],
        );
        assert_eq!(new.len(), 2);
        assert_eq!(known.len(), 0);
        assert!(Baseline::parse(&document("a", &["x"]).replace("low", "nonsense")).is_err());
    }

    /// Non-JSON, foreign JSON and other schema versions are rejected.
    #[test]
    fn invalid() {
        assert!(Baseline::parse("not json").is_err());
        let err = Baseline::parse(r#"{"runs":[]}"#).expect_err("not a report");
        assert!(err.contains("not a testls JSON report"), "{err}");
        let err = Baseline::parse(
            &document("a", &[]).replace(r#""schema_version":1"#, r#""schema_version":2"#),
        )
        .expect_err("version");
        assert!(err.contains("schema_version 2"), "{err}");
        let err = Baseline::parse(
            r#"{"schema_version":1,"target":{"input":"a"},"findings":[{"id":"cert.revoked"}]}"#,
        )
        .expect_err("fragment");
        assert!(err.contains("not a testls JSON report"), "{err}");
        let err =
            Baseline::parse(&document("a", &[]).replace(r#""name":"testls""#, r#""name":"x""#))
                .expect_err("tool");
        assert!(err.contains("tool is"), "{err}");
        let err = Baseline::load(Path::new("no/such/baseline.json")).expect_err("missing");
        assert!(err.starts_with("cannot read baseline"), "{err}");
    }
}
