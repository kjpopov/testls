//! SARIF 2.1.0 report for code scanning dashboards such as GitHub's.
//!
//! One run holds the findings of every scanned address. Each finding id is
//! a rule described by its `testls explain` entry; each finding is a result
//! located at `https://HOST:PORT/` of its target. The grade of each
//! address is in the run's `grades` property. Structure follows the OASIS
//! SARIF 2.1.0 standard and GitHub's list of supported properties.

use std::net::SocketAddr;

use serde_json::{Value, json};
use testls_checks::{Finding, Grade, Severity, explain};

/// Schema URI written to `$schema`.
const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// Findings of one scanned address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    /// Target as given on the command line, e.g. `example.com:443`.
    pub target: String,
    /// Address that was scanned.
    pub addr: SocketAddr,
    /// Overall grade.
    pub grade: Grade,
    /// Findings, most severe first.
    pub findings: Vec<Finding>,
}

/// SARIF result level for `severity`.
fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Low => "warning",
        Severity::Ok | Severity::Info => "note",
    }
}

/// GitHub `security-severity` score for `severity`, inside the band GitHub
/// maps back to the same name; `None` for informational findings.
fn security_severity(severity: Severity) -> Option<&'static str> {
    match severity {
        Severity::Critical => Some("9.5"),
        Severity::High => Some("8.0"),
        Severity::Medium => Some("5.5"),
        Severity::Low => Some("2.0"),
        Severity::Ok | Severity::Info => None,
    }
}

/// Stable 64-bit FNV-1a hash, hex encoded, so the fingerprint of a finding
/// does not change between runs or testls versions.
fn fingerprint(parts: &[&str]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in parts.join("\0").bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Describes finding `id` with its explanation and the highest severity it
/// was reported with.
fn rule(id: &str, severity: Severity) -> Value {
    let (title, rationale, reference) = explain(id).map_or(
        (id, "No explanation is available for this finding.", ""),
        |e| (e.title, e.rationale, e.reference),
    );
    let help = if reference.is_empty() {
        rationale.to_owned()
    } else {
        format!("{rationale} Reference: {reference}.")
    };
    let mut properties = json!({ "tags": ["security", "tls"] });
    if let Some(score) = security_severity(severity) {
        properties["security-severity"] = json!(score);
    }
    json!({
        "id": id,
        "name": id,
        "shortDescription": { "text": title },
        "fullDescription": { "text": rationale },
        "help": { "text": help },
        "defaultConfiguration": { "level": level(severity) },
        "properties": properties,
    })
}

/// Renders `scans` as one pretty-printed SARIF log followed by a newline.
/// `success` is false when a scan failed, which SARIF records on the
/// invocation.
///
/// # Panics
///
/// Never in practice: the log holds only strings, numbers, booleans,
/// objects and arrays, which `serde_json` always serializes.
#[must_use]
pub fn render(scans: &[Scan], success: bool) -> String {
    let mut rules: Vec<(&str, Severity)> = Vec::new();
    for f in scans.iter().flat_map(|s| &s.findings) {
        match rules.iter_mut().find(|(id, _)| *id == f.id) {
            Some((_, severity)) => *severity = (*severity).max(f.severity),
            None => rules.push((&f.id, f.severity)),
        }
    }
    rules.sort_by_key(|(id, _)| *id);
    let results: Vec<Value> = scans
        .iter()
        .flat_map(|scan| scan.findings.iter().map(move |f| (scan, f)))
        .map(|(scan, f)| {
            let index = rules
                .iter()
                .position(|(id, _)| *id == f.id)
                .expect("rule listed");
            json!({
                "ruleId": f.id,
                "ruleIndex": index,
                "level": level(f.severity),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": format!("https://{}/", scan.target) },
                    },
                }],
                "partialFingerprints": {
                    "primaryLocationLineHash": fingerprint(&[&f.id, &scan.target, f.identity()]),
                },
                "properties": {
                    "severity": f.severity.as_str(),
                    "address": scan.addr.to_string(),
                },
            })
        })
        .collect();
    let log = json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "testls",
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "informationUri": env!("CARGO_PKG_REPOSITORY"),
                    "rules": rules.iter().map(|(id, s)| rule(id, *s)).collect::<Vec<_>>(),
                },
            },
            "invocations": [{ "executionSuccessful": success }],
            "results": results,
            "properties": {
                "grades": scans.iter().map(|s| json!({
                    "target": s.target,
                    "address": s.addr.to_string(),
                    "letter": s.grade.letter.as_str(),
                    "untrusted": s.grade.untrusted,
                    "incomplete": s.grade.incomplete,
                    "reasons": s.grade.reasons,
                })).collect::<Vec<_>>(),
            },
        }],
    });
    let mut out = serde_json::to_string_pretty(&log).expect("SARIF log serializes");
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use testls_checks::Letter;

    use super::*;

    /// A scan of `target` with the given findings.
    fn scan(target: &str, findings: Vec<Finding>) -> Scan {
        Scan {
            target: target.to_owned(),
            addr: "192.0.2.1:443".parse().expect("address"),
            grade: Grade {
                letter: Letter::B,
                untrusted: false,
                incomplete: false,
                reasons: Vec::new(),
            },
            findings,
        }
    }

    /// Findings become results pointing at their rule and target; rules are
    /// listed once with their explanation and highest severity.
    #[test]
    fn log() {
        let scans = [
            scan(
                "a.example:443",
                vec![
                    Finding::new("protocol.tls10", Severity::Medium, "TLSv1.0 offered"),
                    Finding::new("hsts.missing", Severity::Low, "no HSTS"),
                ],
            ),
            scan(
                "b.example:8443",
                vec![Finding::new(
                    "protocol.tls10",
                    Severity::High,
                    "TLSv1.0 offered",
                )],
            ),
        ];
        let v: Value = serde_json::from_str(&render(&scans, true)).expect("valid JSON");
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["$schema"], SCHEMA);
        let run = &v["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "testls");
        assert_eq!(run["invocations"][0]["executionSuccessful"], true);
        assert_eq!(
            run["properties"]["grades"][0],
            json!({"target": "a.example:443", "address": "192.0.2.1:443", "letter": "B",
                "untrusted": false, "incomplete": false, "reasons": []})
        );

        let rules = run["tool"]["driver"]["rules"].as_array().expect("rules");
        let ids: Vec<&str> = rules.iter().filter_map(|r| r["id"].as_str()).collect();
        assert_eq!(ids, ["hsts.missing", "protocol.tls10"]);
        let tls10 = &rules[1];
        assert_eq!(tls10["defaultConfiguration"]["level"], "error");
        assert_eq!(tls10["properties"]["security-severity"], "8.0");
        assert_eq!(
            tls10["shortDescription"]["text"],
            explain("protocol.tls10").expect("explained").title
        );
        assert!(
            tls10["help"]["text"]
                .as_str()
                .expect("help")
                .contains("Reference: ")
        );

        let results = run["results"].as_array().expect("results");
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["ruleIndex"], 1);
        assert_eq!(results[0]["level"], "warning");
        assert_eq!(results[1]["ruleId"], "hsts.missing");
        assert_eq!(results[1]["ruleIndex"], 0);
        assert_eq!(
            results[2]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "https://b.example:8443/"
        );
        assert_eq!(results[2]["properties"]["address"], "192.0.2.1:443");
        let hash = |r: &Value| r["partialFingerprints"]["primaryLocationLineHash"].clone();
        assert_ne!(hash(&results[0]), hash(&results[2]));
    }

    /// A run without findings is still a complete log, and a failed scan
    /// marks the invocation unsuccessful.
    #[test]
    fn empty_and_failed() {
        let v: Value = serde_json::from_str(&render(&[], false)).expect("valid JSON");
        let run = &v["runs"][0];
        assert_eq!(run["results"], json!([]));
        assert_eq!(run["tool"]["driver"]["rules"], json!([]));
        assert_eq!(run["invocations"][0]["executionSuccessful"], false);
    }

    /// Severities map to SARIF levels and GitHub score bands; the
    /// fingerprint is stable and depends on every part.
    #[test]
    fn mappings() {
        assert_eq!(level(Severity::Critical), "error");
        assert_eq!(level(Severity::Low), "warning");
        assert_eq!(level(Severity::Info), "note");
        assert_eq!(security_severity(Severity::Critical), Some("9.5"));
        assert_eq!(security_severity(Severity::Info), None);
        assert_eq!(fingerprint(&["a", "b"]), fingerprint(&["a", "b"]));
        assert_ne!(fingerprint(&["a", "b"]), fingerprint(&["ab", ""]));
        assert_eq!(fingerprint(&[]), "cbf29ce484222325");
    }

    /// A pinned key keeps the fingerprint when the message is reworded, a
    /// finding without a key hashes its message, and a finding's fingerprint
    /// does not depend on its siblings (removal or reordering).
    #[test]
    fn fingerprint_uses_identity() {
        let hashes = |findings: Vec<Finding>| -> Vec<Value> {
            let v: Value = serde_json::from_str(&render(&[scan("a.example:443", findings)], true))
                .expect("valid JSON");
            v["runs"][0]["results"]
                .as_array()
                .expect("results")
                .iter()
                .map(|r| r["partialFingerprints"]["primaryLocationLineHash"].clone())
                .collect()
        };
        let rc4 = |m: &str| Finding::new("cipher.rc4", Severity::High, m);
        let old = hashes(vec![rc4("old text")]);
        let reworded = hashes(vec![rc4("new text").with_key("old text")]);
        assert_eq!(old, reworded);
        assert_ne!(old, hashes(vec![rc4("new text")]));

        let both = hashes(vec![rc4("suite a"), rc4("suite b")]);
        assert_ne!(both[0], both[1]);
        assert_eq!(hashes(vec![rc4("suite b")])[0], both[1]);
        assert_eq!(hashes(vec![rc4("suite b"), rc4("suite a")])[1], both[0]);
    }

    /// Ids without a catalogue entry still get a usable rule.
    #[test]
    fn unknown_rule() {
        let r = rule("x.unknown", Severity::Info);
        assert_eq!(r["shortDescription"]["text"], "x.unknown");
        assert!(r["properties"].get("security-severity").is_none());
        assert_eq!(r["defaultConfiguration"]["level"], "note");
    }
}
