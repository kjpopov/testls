//! JSON report, schema documented in `docs/json-schema.md`.
//!
//! The serialized structs here are the schema; they are kept separate from
//! the probe and check types so internal refactors cannot change the output.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::SocketAddr;

use serde::Serialize;
use testls_checks::{
    CertStatus, Finding, Grade, OcspStatus, PostQuantum, RevocationCheck, RevocationMethod,
    Vulnerability, alt_services, banners, cipher_name, cipher_severity, cookies, group_name,
    group_severity, parse_hsts, revocation_reason_name,
};
use testls_probe::{
    CipherOrder, HandshakeDetails, HttpResponse, Intolerance, ProtocolResult, ProtocolSupport,
};

use crate::text::{
    CertificateSection, CipherSection, INTOLERANCE_TESTS, KeyExchangeSection, SECURITY_HEADERS,
    suite_id,
};

/// Version of the JSON schema. Bumped on any change that is not a pure
/// addition of fields.
pub const SCHEMA_VERSION: u32 = 2;

/// Everything a scan produced, borrowed for rendering.
#[derive(Debug, Clone, Copy)]
pub struct Report<'a> {
    /// Target as given on the command line.
    pub target: &'a str,
    /// Address that was scanned.
    pub addr: SocketAddr,
    /// SNI name sent, if any.
    pub sni: Option<&'a str>,
    /// Unix time the scan started.
    pub started_at: i64,
    /// Protocol support results.
    pub protocols: &'a [ProtocolResult],
    /// Cipher enumeration per offered protocol.
    pub ciphers: &'a [CipherSection],
    /// Key exchange probe per offered protocol.
    pub key_exchange: &'a [KeyExchangeSection],
    /// Post-quantum readiness of the TLSv1.3 key exchange.
    pub post_quantum: &'a PostQuantum,
    /// Certificate chain, or why it could not be retrieved.
    pub certificate: &'a Result<CertificateSection, String>,
    /// Reply to `GET /`, or why it could not be fetched.
    pub http: &'a Result<HttpResponse, String>,
    /// Revocation checks against the issuer's services, or why they could
    /// not run; `None` when not requested.
    pub revocation: Option<&'a Result<Vec<RevocationCheck>, String>>,
    /// Named vulnerabilities derived from the scan data.
    pub vulnerabilities: &'a [Vulnerability],
    /// `ClientHello` tolerance tests, or why they could not run.
    pub intolerance: &'a Result<Intolerance, String>,
    /// Handshake details, or why they could not be probed.
    pub details: &'a Result<HandshakeDetails, String>,
    /// Overall grade, from the findings before suppressions.
    pub grade: &'a Grade,
    /// Findings, most severe first.
    pub findings: &'a [Finding],
    /// Findings hidden by a suppression, most severe first.
    pub suppressed: &'a [Suppressed],
}

/// A finding accepted by a suppression entry, kept out of the findings
/// and the exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppressed {
    /// The finding as the checks reported it.
    pub finding: Finding,
    /// Why the finding is accepted.
    pub reason: String,
}

/// Top-level JSON document.
#[derive(Debug, Serialize)]
struct Document<'a> {
    /// See [`SCHEMA_VERSION`].
    schema_version: u32,
    /// Producing tool and its version.
    tool: Tool,
    /// What was scanned.
    target: TargetJson<'a>,
    /// Unix time the scan started.
    started_at: i64,
    /// One entry per probed protocol version.
    protocols: Vec<ProtocolJson>,
    /// One entry per offered protocol version.
    ciphers: Vec<CiphersJson>,
    /// One entry per offered protocol version.
    key_exchange: Vec<KeyExchangeJson>,
    /// Post-quantum readiness summary.
    post_quantum: PostQuantumJson,
    /// Certificate chain result.
    certificate: CertificateJson<'a>,
    /// HTTP security headers result.
    http: HttpJson<'a>,
    /// Revocation check result, or `null` when not requested.
    revocation: Option<RevocationJson<'a>>,
    /// Named vulnerabilities.
    vulnerabilities: Vec<VulnerabilityJson<'a>>,
    /// `ClientHello` tolerance result.
    intolerance: IntoleranceJson<'a>,
    /// Handshake details result.
    details: DetailsJson<'a>,
    /// Overall grade.
    grade: GradeJson<'a>,
    /// Findings, most severe first.
    findings: Vec<FindingJson<'a>>,
    /// Suppressed findings, most severe first.
    suppressed: Vec<SuppressedJson<'a>>,
}

/// Name and version of the producing tool.
#[derive(Debug, Serialize)]
struct Tool {
    /// Always `testls`.
    name: &'static str,
    /// Crate version.
    version: &'static str,
}

/// Scanned target.
#[derive(Debug, Serialize)]
struct TargetJson<'a> {
    /// Target as given on the command line.
    input: &'a str,
    /// Resolved socket address.
    address: String,
    /// SNI name sent, or `null`.
    sni: Option<&'a str>,
}

/// Support status of one protocol version.
#[derive(Debug, Serialize)]
struct ProtocolJson {
    /// Version name, e.g. `TLSv1.2`.
    version: String,
    /// `offered`, `not_offered`, or `error`.
    status: &'static str,
    /// Error message when `status` is `error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Cipher suites of one protocol version.
#[derive(Debug, Serialize)]
struct CiphersJson {
    /// Version name, e.g. `TLSv1.2`.
    protocol: String,
    /// `server`, `client`, or `null` when not applicable or unknown.
    order: Option<&'static str>,
    /// Suites in the order the server chose them.
    suites: Vec<SuiteJson>,
    /// Error message when enumeration failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// One cipher suite.
#[derive(Debug, Serialize)]
struct SuiteJson {
    /// Hex code point, e.g. `0xc02f` (six digits for SSLv2 cipher specs).
    id: String,
    /// IANA name.
    name: &'static str,
    /// Severity of the suite.
    severity: &'static str,
}

/// Key exchange groups and DH parameter size of one protocol version.
#[derive(Debug, Serialize)]
struct KeyExchangeJson {
    /// Version name, e.g. `TLSv1.2`.
    protocol: String,
    /// `server`, `client`, or `null` when not applicable or unknown.
    group_order: Option<&'static str>,
    /// Supported groups in the order the server chose them.
    groups: Vec<GroupJson>,
    /// Smallest measured ephemeral DH prime in bits, or `null` if none.
    dh_bits: Option<usize>,
    /// Measurements for each accepted finite-field DH suite.
    dh_suites: Vec<DhSuiteJson>,
    /// Error message when the probe failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// DH evidence for one cipher suite; null values indicate missing measurements.
#[derive(Debug, Serialize)]
struct DhSuiteJson {
    /// IANA suite code point.
    suite: String,
    /// Prime size in bits.
    bits: Option<usize>,
    /// Distinct primes seen, as hexadecimal big-endian bytes.
    primes: Vec<String>,
    /// Whether comparable handshakes reused the public value.
    key_reused: Option<bool>,
}

/// One supported group.
#[derive(Debug, Serialize)]
struct GroupJson {
    /// Hex code point, e.g. `0x001d`.
    id: String,
    /// IANA name.
    name: &'static str,
    /// Severity of the group.
    severity: &'static str,
}

/// Certificate chain result.
#[derive(Debug, Serialize)]
struct CertificateJson<'a> {
    /// Version of the handshake that fetched the chain, or `null`.
    protocol: Option<String>,
    /// Certificates, leaf first.
    chain: Vec<CertJson<'a>>,
    /// Stapled OCSP response, or `null` when the chain could not be
    /// retrieved.
    ocsp: Option<OcspJson<'a>>,
    /// Error message when the chain could not be retrieved.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

/// Stapled OCSP response for the leaf certificate.
#[derive(Debug, Serialize)]
struct OcspJson<'a> {
    /// Whether the server stapled a response.
    stapled: bool,
    /// `good`, `revoked`, `unknown`, `invalid`, or `null` when not stapled.
    status: Option<&'static str>,
    /// When the response was signed, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    produced_at: Option<i64>,
    /// Start of the validity interval, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    this_update: Option<i64>,
    /// End of the validity interval, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_update: Option<i64>,
    /// Revocation time, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_time: Option<i64>,
    /// RFC 5280 `CRLReason` name, when revoked with a reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_reason: Option<&'static str>,
    /// Why the response is invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

/// One certificate of the chain.
#[derive(Debug, Serialize)]
struct CertJson<'a> {
    /// Subject distinguished name.
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<&'a str>,
    /// Issuer distinguished name.
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<&'a str>,
    /// Start of validity, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_before: Option<i64>,
    /// End of validity, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_after: Option<i64>,
    /// DNS names and IP addresses from the SAN extension.
    #[serde(skip_serializing_if = "Option::is_none")]
    names: Option<&'a [String]>,
    /// Key algorithm and size, e.g. `RSA 2048 bits`.
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<&'a str>,
    /// Number of embedded Certificate Transparency timestamps; absent when
    /// the SCT list cannot be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    scts: Option<usize>,
    /// Parse error when the certificate could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

/// Status and security headers of the reply to `GET /`.
#[derive(Debug, Serialize)]
struct HttpJson<'a> {
    /// HTTP status code, or `null` when the fetch failed.
    status: Option<u16>,
    /// Each security header by lowercase name, `null` when not set.
    headers: BTreeMap<String, Option<&'a str>>,
    /// Parsed `Strict-Transport-Security` policy, or `null` when the header
    /// is missing or invalid.
    hsts: Option<HstsJson>,
    /// Software banners (`server`, `x-powered-by`) by lowercase name, every
    /// field value in order.
    banners: BTreeMap<String, Vec<String>>,
    /// Alternative services from `Alt-Svc`, or `null` when the header is
    /// malformed.
    alt_svc: Option<Vec<AltSvcJson>>,
    /// Cookies set by the reply, one per `Set-Cookie` header.
    cookies: Vec<CookieJson>,
    /// Error message when the headers could not be fetched.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

/// One alternative service (RFC 7838).
#[derive(Debug, Serialize)]
struct AltSvcJson {
    /// ALPN protocol id, e.g. `h3`.
    protocol: String,
    /// Alternative authority, e.g. `:443`.
    authority: String,
    /// Freshness lifetime in seconds.
    max_age: u64,
}

/// Attributes of one cookie.
#[derive(Debug, Serialize)]
struct CookieJson {
    /// Cookie name.
    name: String,
    /// The `Secure` attribute is present.
    secure: bool,
    /// The `HttpOnly` attribute is present.
    http_only: bool,
    /// `SameSite` value, or `null` when absent.
    same_site: Option<String>,
}

/// Parsed `Strict-Transport-Security` policy.
#[derive(Debug, Serialize)]
struct HstsJson {
    /// `max-age` in seconds.
    max_age: u64,
    /// The `includeSubDomains` directive is present.
    include_subdomains: bool,
    /// The `preload` directive is present.
    preload: bool,
    /// The policy meets the preload list's header requirements.
    preload_eligible: bool,
}

/// Opt-in revocation check against the issuer's services.
#[derive(Debug, Serialize)]
struct RevocationJson<'a> {
    /// Each OCSP query or CRL download, in the order made.
    checks: Vec<RevocationCheckJson<'a>>,
    /// Why no check could be made, e.g. the chain could not be retrieved.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

/// One OCSP query or CRL download.
#[derive(Debug, Serialize)]
struct RevocationCheckJson<'a> {
    /// `ocsp` or `crl`.
    method: &'static str,
    /// URL that was used.
    url: &'a str,
    /// `good`, `revoked`, `unknown`, or `error`.
    status: &'static str,
    /// Start of the validity interval, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    this_update: Option<i64>,
    /// End of the validity interval, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_update: Option<i64>,
    /// Revocation time, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_time: Option<i64>,
    /// RFC 5280 `CRLReason` name, when revoked with a reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_reason: Option<&'static str>,
    /// Why fetching or verification failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

/// One named vulnerability and its verdict.
#[derive(Debug, Serialize)]
struct VulnerabilityJson<'a> {
    /// Stable short id, e.g. `poodle`.
    id: &'static str,
    /// Display name, e.g. `POODLE`.
    name: &'static str,
    /// `vulnerable`, `not vulnerable`, or `not tested`.
    status: &'static str,
    /// Short reason for the verdict.
    detail: &'a str,
    /// Finding id that reports the issue, when vulnerable.
    finding: Option<&'static str>,
}

/// `ClientHello` tolerance verdicts: `tolerated`, `rejected`, or `null` when
/// not tested.
#[derive(Debug, Serialize)]
struct IntoleranceJson<'a> {
    /// Protocol version the tests used, e.g. `TLSv1.3`.
    protocol: Option<String>,
    /// Verdict per test, keyed by test name.
    tests: BTreeMap<&'static str, Option<&'static str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

/// Handshake details; each field is `null` when not tested.
#[derive(Debug, Serialize)]
struct DetailsJson<'a> {
    /// TLSv1.2 or older version used for the extended master secret and
    /// downgrade sentinel probes.
    protocol: Option<String>,
    /// Server negotiates the extended master secret (RFC 7627).
    extended_master_secret: Option<bool>,
    /// TLSv1.3 server sets the downgrade sentinel (RFC 8446 §4.1.3).
    downgrade_sentinel: Option<bool>,
    /// Server issues TLSv1.3 session tickets.
    session_tickets: Option<bool>,
    /// Largest 0-RTT early data size offered in a ticket; 0 = none.
    max_early_data: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

/// Post-quantum readiness of the TLSv1.3 key exchange.
#[derive(Debug, Serialize)]
struct PostQuantumJson {
    /// `ready`, `draft only`, `not ready`, or `not tested`.
    status: &'static str,
    /// Accepted ML-KEM groups.
    groups: Vec<GroupJson>,
    /// Accepted draft Kyber code points.
    draft_groups: Vec<GroupJson>,
    /// Server picks an ML-KEM group first, or `null` when unknown.
    preferred: Option<bool>,
}

/// Overall grade of the scan.
#[derive(Debug, Serialize)]
struct GradeJson<'a> {
    /// `A+`, `A`, `A-`, `B`, `C`, or `F`.
    letter: &'static str,
    /// The certificate is untrusted or does not cover the host.
    untrusted: bool,
    /// A probe failed, so the grade may be too good.
    incomplete: bool,
    /// Why the grade is not better.
    reasons: &'a [String],
}

/// One finding.
#[derive(Debug, Serialize)]
struct FindingJson<'a> {
    /// Stable identifier, e.g. `protocol.tls10`.
    id: &'a str,
    /// `info`, `low`, `medium`, `high`, or `critical`.
    severity: &'static str,
    /// Human-readable description.
    message: &'a str,
}

/// One suppressed finding.
#[derive(Debug, Serialize)]
struct SuppressedJson<'a> {
    /// The finding itself.
    #[serde(flatten)]
    finding: FindingJson<'a>,
    /// Why it is accepted.
    reason: &'a str,
}

/// Converts a finding to its JSON form.
fn finding(f: &Finding) -> FindingJson<'_> {
    FindingJson {
        id: &f.id,
        severity: f.severity.as_str(),
        message: &f.message,
    }
}

/// Renders `report` as pretty-printed JSON followed by a newline.
///
/// # Panics
///
/// Never in practice: the document contains only strings, integers, and
/// sequences, which `serde_json` always serializes.
#[must_use]
pub fn render(report: &Report<'_>) -> String {
    let doc = Document {
        schema_version: SCHEMA_VERSION,
        tool: Tool {
            name: "testls",
            version: env!("CARGO_PKG_VERSION"),
        },
        target: TargetJson {
            input: report.target,
            address: report.addr.to_string(),
            sni: report.sni,
        },
        started_at: report.started_at,
        protocols: report.protocols.iter().map(protocol).collect(),
        ciphers: report.ciphers.iter().map(ciphers).collect(),
        key_exchange: report.key_exchange.iter().map(key_exchange).collect(),
        post_quantum: post_quantum(report.post_quantum),
        certificate: certificate(report.certificate),
        http: http(report.http),
        revocation: report.revocation.map(revocation),
        vulnerabilities: report.vulnerabilities.iter().map(vulnerability).collect(),
        intolerance: intolerance(report.intolerance),
        details: details(report.details),
        grade: GradeJson {
            letter: report.grade.letter.as_str(),
            untrusted: report.grade.untrusted,
            incomplete: report.grade.incomplete,
            reasons: &report.grade.reasons,
        },
        findings: report.findings.iter().map(finding).collect(),
        suppressed: report
            .suppressed
            .iter()
            .map(|s| SuppressedJson {
                finding: finding(&s.finding),
                reason: &s.reason,
            })
            .collect(),
    };
    let mut out = serde_json::to_string_pretty(&doc).expect("report serializes");
    out.push('\n');
    out
}

/// Joins documents from [`render`] into one pretty-printed JSON array,
/// indented the way `serde_json` would print it, followed by a newline.
#[must_use]
pub fn render_array(documents: &[String]) -> String {
    if documents.is_empty() {
        return "[]\n".to_owned();
    }
    let items: Vec<String> = documents
        .iter()
        .map(|doc| {
            doc.trim_end()
                .lines()
                .map(|line| format!("  {line}"))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .collect();
    format!("[\n{}\n]\n", items.join(",\n"))
}

/// Converts the tolerance tests; on error every verdict is `null`.
fn intolerance(section: &Result<Intolerance, String>) -> IntoleranceJson<'_> {
    let result = section.as_ref().ok();
    IntoleranceJson {
        protocol: result.and_then(|r| r.version).map(|v| v.to_string()),
        tests: INTOLERANCE_TESTS
            .iter()
            .map(|(key, _, get)| {
                let verdict = result
                    .and_then(get)
                    .map(|ok| if ok { "tolerated" } else { "rejected" });
                (*key, verdict)
            })
            .collect(),
        error: section.as_ref().err().map(String::as_str),
    }
}

/// Converts the handshake details; on error every field is `null`.
fn details(section: &Result<HandshakeDetails, String>) -> DetailsJson<'_> {
    let result = section.as_ref().ok();
    DetailsJson {
        protocol: result.and_then(|r| r.legacy_version).map(|v| v.to_string()),
        extended_master_secret: result.and_then(|r| r.extended_master_secret),
        downgrade_sentinel: result.and_then(|r| r.downgrade_sentinel),
        session_tickets: result.and_then(|r| r.session_tickets),
        max_early_data: result.and_then(|r| r.max_early_data),
        error: section.as_ref().err().map(String::as_str),
    }
}

/// Converts the post-quantum summary.
fn post_quantum(pq: &PostQuantum) -> PostQuantumJson {
    PostQuantumJson {
        status: pq.status.as_str(),
        groups: pq.groups.iter().map(|&id| group(id)).collect(),
        draft_groups: pq.draft_groups.iter().map(|&id| group(id)).collect(),
        preferred: pq.preferred,
    }
}

/// Converts one group code point.
fn group(id: u16) -> GroupJson {
    GroupJson {
        id: format!("0x{id:04x}"),
        name: group_name(id),
        severity: group_severity(id).0.as_str(),
    }
}

/// Converts one vulnerability verdict.
fn vulnerability(v: &Vulnerability) -> VulnerabilityJson<'_> {
    VulnerabilityJson {
        id: v.id,
        name: v.name,
        status: v.status.as_str(),
        detail: &v.detail,
        finding: v.finding,
    }
}

/// Converts one protocol result.
fn protocol(r: &ProtocolResult) -> ProtocolJson {
    let (status, error) = match &r.support {
        ProtocolSupport::Supported => ("offered", None),
        ProtocolSupport::NotSupported => ("not_offered", None),
        ProtocolSupport::Error(e) => ("error", Some(e.clone())),
    };
    ProtocolJson {
        version: r.version.to_string(),
        status,
        error,
    }
}

/// Converts one cipher section, labelling each suite with its severity.
fn ciphers(section: &CipherSection) -> CiphersJson {
    let version = section.version;
    match &section.outcome {
        Ok(c) => CiphersJson {
            protocol: version.to_string(),
            order: order(c.order),
            suites: c
                .suites
                .iter()
                .map(|&id| SuiteJson {
                    id: suite_id(version, id),
                    name: cipher_name(version, id),
                    severity: cipher_severity(version, id).0.as_str(),
                })
                .collect(),
            error: None,
        },
        Err(e) => CiphersJson {
            protocol: version.to_string(),
            order: None,
            suites: Vec::new(),
            error: Some(e.clone()),
        },
    }
}

/// Maps a preference order onto its JSON label.
fn order(order: CipherOrder) -> Option<&'static str> {
    match order {
        CipherOrder::Server => Some("server"),
        CipherOrder::Client => Some("client"),
        CipherOrder::NotApplicable => None,
    }
}

/// Converts one key exchange section, labelling each group with its
/// severity.
fn key_exchange(section: &KeyExchangeSection) -> KeyExchangeJson {
    let protocol = section.version.to_string();
    match &section.outcome {
        Ok(k) => KeyExchangeJson {
            protocol,
            group_order: order(k.group_order),
            groups: k.groups.iter().map(|&id| group(id)).collect(),
            dh_bits: k.dh_bits,
            dh_suites: k
                .dh_suites
                .iter()
                .map(|d| DhSuiteJson {
                    suite: format!("0x{:04x}", d.suite),
                    bits: d.bits,
                    primes: d
                        .primes
                        .iter()
                        .map(|p| {
                            p.iter().fold(String::new(), |mut out, b| {
                                write!(out, "{b:02x}").expect("writing to a string cannot fail");
                                out
                            })
                        })
                        .collect(),
                    key_reused: d.key_reused,
                })
                .collect(),
            error: None,
        },
        Err(e) => KeyExchangeJson {
            protocol,
            group_order: None,
            groups: Vec::new(),
            dh_bits: None,
            dh_suites: Vec::new(),
            error: Some(e.clone()),
        },
    }
}

/// Converts the certificate section.
fn certificate(section: &Result<CertificateSection, String>) -> CertificateJson<'_> {
    match section {
        Ok(chain) => CertificateJson {
            protocol: Some(chain.version.to_string()),
            chain: chain
                .certificates
                .iter()
                .map(|cert| match cert {
                    Ok(info) => CertJson {
                        subject: Some(&info.subject),
                        issuer: Some(&info.issuer),
                        not_before: Some(info.not_before_unix),
                        not_after: Some(info.not_after_unix),
                        names: Some(&info.names),
                        key: Some(&info.key),
                        scts: info.scts,
                        error: None,
                    },
                    Err(e) => CertJson {
                        subject: None,
                        issuer: None,
                        not_before: None,
                        not_after: None,
                        names: None,
                        key: None,
                        scts: None,
                        error: Some(e),
                    },
                })
                .collect(),
            ocsp: Some(ocsp(chain.ocsp.as_ref())),
            error: None,
        },
        Err(e) => CertificateJson {
            protocol: None,
            chain: Vec::new(),
            ocsp: None,
            error: Some(e),
        },
    }
}

/// Converts the stapled OCSP result.
fn ocsp(section: Option<&Result<OcspStatus, String>>) -> OcspJson<'_> {
    let mut json = OcspJson {
        stapled: section.is_some(),
        status: None,
        produced_at: None,
        this_update: None,
        next_update: None,
        revocation_time: None,
        revocation_reason: None,
        error: None,
    };
    match section {
        None => {}
        Some(Err(e)) => {
            json.status = Some("invalid");
            json.error = Some(e);
        }
        Some(Ok(status)) => {
            json.produced_at = Some(status.produced_at);
            json.this_update = Some(status.this_update);
            json.next_update = status.next_update;
            json.status = Some(match status.status {
                CertStatus::Good => "good",
                CertStatus::Revoked { time, reason } => {
                    json.revocation_time = Some(time);
                    json.revocation_reason = reason.map(revocation_reason_name);
                    "revoked"
                }
                CertStatus::Unknown => "unknown",
            });
        }
    }
    json
}

/// Converts the HTTP section; only the first HSTS header counts
/// (RFC 6797 §8.1).
fn http(section: &Result<HttpResponse, String>) -> HttpJson<'_> {
    match section {
        Ok(response) => HttpJson {
            status: Some(response.status),
            headers: SECURITY_HEADERS
                .iter()
                .map(|name| (name.to_ascii_lowercase(), response.header(name)))
                .collect(),
            hsts: response
                .header("strict-transport-security")
                .and_then(|v| parse_hsts(v).ok())
                .map(|h| HstsJson {
                    max_age: h.max_age,
                    include_subdomains: h.include_subdomains,
                    preload: h.preload,
                    preload_eligible: h.preload_eligible(),
                }),
            banners: banners(response).into_iter().fold(
                BTreeMap::new(),
                |mut map: BTreeMap<String, Vec<String>>, (name, value)| {
                    map.entry(name.to_ascii_lowercase())
                        .or_default()
                        .push(value);
                    map
                },
            ),
            alt_svc: alt_services(response).ok().map(|list| {
                list.into_iter()
                    .map(|a| AltSvcJson {
                        protocol: a.protocol,
                        authority: a.authority,
                        max_age: a.max_age,
                    })
                    .collect()
            }),
            cookies: cookies(response)
                .into_iter()
                .map(|c| CookieJson {
                    name: c.name,
                    secure: c.secure,
                    http_only: c.http_only,
                    same_site: c.same_site,
                })
                .collect(),
            error: None,
        },
        Err(e) => HttpJson {
            status: None,
            headers: BTreeMap::new(),
            hsts: None,
            banners: BTreeMap::new(),
            alt_svc: None,
            cookies: Vec::new(),
            error: Some(e),
        },
    }
}

/// Converts the revocation checks.
fn revocation(section: &Result<Vec<RevocationCheck>, String>) -> RevocationJson<'_> {
    match section {
        Ok(checks) => RevocationJson {
            checks: checks.iter().map(revocation_check).collect(),
            error: None,
        },
        Err(e) => RevocationJson {
            checks: Vec::new(),
            error: Some(e),
        },
    }
}

/// Converts one revocation attempt.
fn revocation_check(check: &RevocationCheck) -> RevocationCheckJson<'_> {
    let mut json = RevocationCheckJson {
        method: match check.method {
            RevocationMethod::Ocsp => "ocsp",
            RevocationMethod::Crl => "crl",
        },
        url: &check.url,
        status: "error",
        this_update: None,
        next_update: None,
        revocation_time: None,
        revocation_reason: None,
        error: None,
    };
    match &check.outcome {
        Err(e) => json.error = Some(e),
        Ok(status) => {
            json.this_update = Some(status.this_update);
            json.next_update = status.next_update;
            json.status = match status.status {
                CertStatus::Good => "good",
                CertStatus::Revoked { time, reason } => {
                    json.revocation_time = Some(time);
                    json.revocation_reason = reason.map(revocation_reason_name);
                    "revoked"
                }
                CertStatus::Unknown => "unknown",
            };
        }
    }
    json
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use testls_checks::{
        CertificateInfo, Letter, PqStatus, RevocationStatus, Severity, VulnStatus,
    };
    use testls_probe::{CipherResult, KeyExchangeResult};
    use testls_wire::ProtocolVersion;

    use super::*;

    /// Post-quantum summary of a scan without TLSv1.3 data.
    const UNTESTED: PostQuantum = PostQuantum {
        status: PqStatus::NotTested,
        groups: Vec::new(),
        draft_groups: Vec::new(),
        preferred: None,
    };

    /// Grade of a scan without counted findings.
    const GRADE_A: Grade = Grade {
        letter: Letter::A,
        untrusted: false,
        incomplete: false,
        reasons: Vec::new(),
    };

    /// Grade of an incomplete scan with an untrusted certificate.
    fn untrusted_grade() -> Grade {
        Grade {
            letter: Letter::C,
            untrusted: true,
            incomplete: true,
            reasons: vec!["high findings: cert.untrusted".into()],
        }
    }

    /// The post-quantum summary lists ML-KEM and draft groups separately.
    #[test]
    fn post_quantum_object() {
        let pq = PostQuantum {
            status: PqStatus::Ready,
            groups: vec![0x11ec],
            draft_groups: vec![0x6399],
            preferred: Some(false),
        };
        assert_eq!(
            serde_json::to_value(post_quantum(&pq)).unwrap(),
            json!({
                "status": "ready",
                "groups": [{"id": "0x11ec", "name": "X25519MLKEM768", "severity": "ok"}],
                "draft_groups": [
                    {"id": "0x6399", "name": "X25519Kyber768Draft00 (OBSOLETE)", "severity": "low"}
                ],
                "preferred": false,
            })
        );
    }

    /// Renders `report` and parses it back for comparison.
    fn value(report: &Report<'_>) -> Value {
        let out = render(report);
        assert!(out.ends_with("}\n"), "{out}");
        serde_json::from_str(&out).unwrap()
    }

    /// A full report maps every section onto the documented schema.
    #[test]
    fn full_report() {
        let protocols = [
            ProtocolResult {
                version: ProtocolVersion::TLS13,
                support: ProtocolSupport::Supported,
            },
            ProtocolResult {
                version: ProtocolVersion::TLS10,
                support: ProtocolSupport::NotSupported,
            },
            ProtocolResult {
                version: ProtocolVersion::SSL3,
                support: ProtocolSupport::Error("timed out".into()),
            },
        ];
        let ciphers = [
            CipherSection {
                version: ProtocolVersion::TLS13,
                outcome: Ok(CipherResult {
                    version: ProtocolVersion::TLS13,
                    suites: vec![0x1302],
                    order: CipherOrder::Server,
                }),
            },
            CipherSection {
                version: ProtocolVersion::TLS12,
                outcome: Err("reset".into()),
            },
        ];
        let certificate = Ok(CertificateSection {
            version: ProtocolVersion::TLS13,
            certificates: vec![
                Ok(CertificateInfo {
                    subject: "CN=localhost".into(),
                    issuer: "CN=test CA".into(),
                    not_before: String::new(),
                    not_after: String::new(),
                    not_before_unix: 1,
                    not_after_unix: 2,
                    names: vec!["localhost".into()],
                    key: "EC 256 bits".into(),
                    scts: Some(0),
                }),
                Err("bad".into()),
            ],
            ocsp: None,
        });
        let report = Report {
            target: "localhost:443",
            addr: "127.0.0.1:443".parse().unwrap(),
            sni: Some("localhost"),
            started_at: 1_700_000_000,
            protocols: &protocols,
            ciphers: &ciphers,
            key_exchange: &[],
            post_quantum: &UNTESTED,
            certificate: &certificate,
            http: &Err("reset".into()),
            revocation: None,
            vulnerabilities: &[],
            intolerance: &Err("skipped".into()),
            details: &Err("skipped".into()),
            grade: &untrusted_grade(),
            findings: &[Finding::new("cert.untrusted", Severity::High, "untrusted")],
            suppressed: &[],
        };
        assert_eq!(
            value(&report),
            json!({
                "schema_version": 2,
                "tool": {"name": "testls", "version": env!("CARGO_PKG_VERSION")},
                "target": {"input": "localhost:443", "address": "127.0.0.1:443", "sni": "localhost"},
                "started_at": 1_700_000_000,
                "protocols": [
                    {"version": "TLSv1.3", "status": "offered"}, {"version": "TLSv1.0", "status": "not_offered"},
                    {"version": "SSLv3", "status": "error", "error": "timed out"},
                ],
                "ciphers": [
                    {
                        "protocol": "TLSv1.3",
                        "order": "server",
                        "suites": [{"id": "0x1302", "name": "TLS_AES_256_GCM_SHA384", "severity": "ok"}],
                    },
                    {"protocol": "TLSv1.2", "order": null, "suites": [], "error": "reset"},
                ],
                "key_exchange": [], "post_quantum": {"status": "not tested", "groups": [], "draft_groups": [], "preferred": null},
                "certificate": {
                    "protocol": "TLSv1.3",
                    "chain": [{"subject": "CN=localhost", "issuer": "CN=test CA", "not_before": 1, "not_after": 2,
                        "names": ["localhost"], "key": "EC 256 bits", "scts": 0}, {"error": "bad"}],
                    "ocsp": {"stapled": false, "status": null},
                },
                "http": {"status": null, "headers": {}, "hsts": null, "banners": {}, "alt_svc": null, "cookies": [], "error": "reset"}, "revocation": null, "vulnerabilities": [],
                "intolerance": {"protocol": null, "error": "skipped", "tests": {
                    "fragmented": null, "grease": null, "oversized": null, "unknown_extension": null, "unknown_version": null}},
                "details": {"protocol": null, "extended_master_secret": null, "downgrade_sentinel": null,
                    "session_tickets": null, "max_early_data": null, "error": "skipped"},
                "findings": [{"id": "cert.untrusted", "severity": "high", "message": "untrusted"}],
                "suppressed": [], "grade": {"letter": "C", "untrusted": true, "incomplete": true, "reasons": ["high findings: cert.untrusted"]},
            })
        );
    }

    /// Key exchange sections list groups with severity, DH size, or the error.
    #[test]
    fn key_exchange_sections() {
        let sections = [
            KeyExchangeSection {
                version: ProtocolVersion::TLS13,
                outcome: Ok(KeyExchangeResult {
                    version: ProtocolVersion::TLS13,
                    groups: vec![0x11ec, 0x001d],
                    group_order: CipherOrder::Client,
                    dh_bits: None,
                    dh_key_reused: None,
                    dh_suites: Vec::new(),
                }),
            },
            KeyExchangeSection {
                version: ProtocolVersion::TLS12,
                outcome: Ok(KeyExchangeResult {
                    version: ProtocolVersion::TLS12,
                    groups: vec![0x0015],
                    group_order: CipherOrder::NotApplicable,
                    dh_bits: Some(1024),
                    dh_key_reused: None,
                    dh_suites: vec![
                        testls_probe::DhSuiteResult {
                            suite: 0x0034,
                            bits: Some(1024),
                            primes: vec![vec![0xab, 0xcd]],
                            key_reused: Some(false),
                        },
                        testls_probe::DhSuiteResult {
                            suite: 0x003a,
                            bits: None,
                            primes: Vec::new(),
                            key_reused: None,
                        },
                    ],
                }),
            },
            KeyExchangeSection {
                version: ProtocolVersion::TLS11,
                outcome: Err("reset".into()),
            },
        ];
        let certificate = Err("refused".into());
        let http = Err("reset".into());
        let report = Report {
            target: "127.0.0.1",
            addr: "127.0.0.1:443".parse().unwrap(),
            sni: None,
            started_at: 0,
            protocols: &[],
            ciphers: &[],
            key_exchange: &sections,
            post_quantum: &UNTESTED,
            certificate: &certificate,
            http: &http,
            revocation: None,
            vulnerabilities: &[],
            intolerance: &Err("skipped".into()),
            details: &Err("skipped".into()),
            grade: &GRADE_A,
            findings: &[],
            suppressed: &[],
        };
        assert_eq!(
            value(&report)["key_exchange"],
            json!([
                {
                    "protocol": "TLSv1.3",
                    "group_order": "client",
                    "groups": [
                        {"id": "0x11ec", "name": "X25519MLKEM768", "severity": "ok"},
                        {"id": "0x001d", "name": "x25519", "severity": "ok"},
                    ],
                    "dh_bits": null, "dh_suites": [],
                },
                {
                    "protocol": "TLSv1.2",
                    "group_order": null,
                    "groups": [{"id": "0x0015", "name": "secp224r1", "severity": "medium"}],
                    "dh_bits": 1024, "dh_suites": [{"suite": "0x0034", "bits": 1024, "primes": ["abcd"], "key_reused": false}, {"suite": "0x003a", "bits": null, "primes": [], "key_reused": null}],
                },
                {"protocol": "TLSv1.1", "group_order": null, "groups": [], "dh_bits": null, "dh_suites": [], "error": "reset"},
            ])
        );
    }

    /// Several documents join into an array that parses and keeps key order.
    #[test]
    fn document_array() {
        let a = "{\n  \"b\": 1,\n  \"a\": [\n    1,\n    2\n  ]\n}\n".to_owned();
        let b = "{\n  \"c\": \"x\\ny\"\n}\n".to_owned();
        let out = render_array(&[a, b]);
        assert_eq!(
            out,
            "[\n  {\n    \"b\": 1,\n    \"a\": [\n      1,\n      2\n    ]\n  },\n  {\n    \"c\": \"x\\ny\"\n  }\n]\n"
        );
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v[1]["c"], "x\ny");
        assert_eq!(render_array(&[]), "[]\n");
    }

    /// Missing SNI is `null`, a failed certificate fetch carries the error,
    /// and suppressed findings keep their reason.
    #[test]
    fn errors_and_nulls() {
        let certificate = Err("refused".into());
        let http = Err("reset".into());
        let report = Report {
            target: "127.0.0.1",
            addr: "127.0.0.1:443".parse().unwrap(),
            sni: None,
            started_at: 0,
            protocols: &[],
            ciphers: &[],
            key_exchange: &[],
            post_quantum: &UNTESTED,
            certificate: &certificate,
            http: &http,
            revocation: None,
            vulnerabilities: &[],
            intolerance: &Err("skipped".into()),
            details: &Err("skipped".into()),
            grade: &GRADE_A,
            findings: &[],
            suppressed: &[Suppressed {
                finding: Finding::new("hsts.missing", Severity::Medium, "no HSTS"),
                reason: "internal".to_owned(),
            }],
        };
        let v = value(&report);
        assert_eq!(v["target"]["sni"], Value::Null);
        assert_eq!(
            v["certificate"],
            json!({"protocol": null, "chain": [], "ocsp": null, "error": "refused"})
        );
        assert_eq!(v["findings"], json!([]));
        assert_eq!(
            v["suppressed"],
            json!([{"id": "hsts.missing", "severity": "medium", "message": "no HSTS",
                "reason": "internal"}])
        );
    }

    /// The HTTP section lists every security header and the parsed HSTS
    /// policy from the first header.
    #[test]
    fn http_section() {
        let certificate = Err("refused".into());
        let http = Ok(HttpResponse {
            status: 301,
            headers: vec![
                (
                    "strict-transport-security".into(),
                    "max-age=31536000; includeSubDomains; preload".into(),
                ),
                ("strict-transport-security".into(), "max-age=0".into()),
                ("x-frame-options".into(), "DENY".into()),
                ("x-powered-by".into(), "PHP/8".into()),
                ("x-powered-by".into(), "Express".into()),
                ("alt-svc".into(), "h3=\":443\"".into()),
                ("set-cookie".into(), "sid=1; Secure; SameSite=Lax".into()),
            ],
        });
        let report = Report {
            target: "127.0.0.1",
            addr: "127.0.0.1:443".parse().unwrap(),
            sni: None,
            started_at: 0,
            protocols: &[],
            ciphers: &[],
            key_exchange: &[],
            post_quantum: &UNTESTED,
            certificate: &certificate,
            http: &http,
            revocation: None,
            vulnerabilities: &[],
            intolerance: &Err("skipped".into()),
            details: &Err("skipped".into()),
            grade: &GRADE_A,
            findings: &[],
            suppressed: &[],
        };
        assert_eq!(
            value(&report)["http"],
            json!({
                "status": 301,
                "headers": {
                    "content-security-policy": null,
                    "referrer-policy": null,
                    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
                    "x-content-type-options": null,
                    "x-frame-options": "DENY",
                },
                "hsts": {
                    "max_age": 31_536_000,
                    "include_subdomains": true,
                    "preload": true,
                    "preload_eligible": true,
                },
                "banners": {"x-powered-by": ["PHP/8", "Express"]},
                "alt_svc": [{"protocol": "h3", "authority": ":443", "max_age": 86_400}],
                "cookies": [
                    {"name": "sid", "secure": true, "http_only": false, "same_site": "Lax"},
                ],
            })
        );
    }

    /// The OCSP object carries the status, validity interval, revocation
    /// details, or the reason the response is invalid.
    #[test]
    fn ocsp_object() {
        let revoked = Ok(OcspStatus {
            status: CertStatus::Revoked {
                time: 5,
                reason: Some(1),
            },
            produced_at: 2,
            this_update: 3,
            next_update: None,
        });
        assert_eq!(
            serde_json::to_value(ocsp(Some(&revoked))).unwrap(),
            json!({
                "stapled": true,
                "status": "revoked",
                "produced_at": 2,
                "this_update": 3,
                "revocation_time": 5,
                "revocation_reason": "keyCompromise",
            })
        );
        let good = Ok(OcspStatus {
            status: CertStatus::Good,
            produced_at: 2,
            this_update: 3,
            next_update: Some(4),
        });
        assert_eq!(
            serde_json::to_value(ocsp(Some(&good))).unwrap(),
            json!({"stapled": true, "status": "good", "produced_at": 2, "this_update": 3, "next_update": 4})
        );
        let invalid = Err("bad signature".into());
        assert_eq!(
            serde_json::to_value(ocsp(Some(&invalid))).unwrap(),
            json!({"stapled": true, "status": "invalid", "error": "bad signature"})
        );
    }

    /// Revocation checks list each attempt with its status, or the reason
    /// none could be made.
    #[test]
    fn revocation_object() {
        let checks = Ok(vec![
            RevocationCheck {
                method: RevocationMethod::Ocsp,
                url: "http://ocsp.test/".into(),
                outcome: Err("HTTP status 500".into()),
            },
            RevocationCheck {
                method: RevocationMethod::Crl,
                url: "http://crl.test/ca.crl".into(),
                outcome: Ok(RevocationStatus {
                    status: CertStatus::Revoked {
                        time: 5,
                        reason: Some(1),
                    },
                    this_update: 3,
                    next_update: None,
                }),
            },
        ]);
        assert_eq!(
            serde_json::to_value(revocation(&checks)).unwrap(),
            json!({"checks": [
                {"method": "ocsp", "url": "http://ocsp.test/", "status": "error", "error": "HTTP status 500"},
                {
                    "method": "crl",
                    "url": "http://crl.test/ca.crl",
                    "status": "revoked",
                    "this_update": 3,
                    "revocation_time": 5,
                    "revocation_reason": "keyCompromise",
                },
            ]})
        );
        assert_eq!(
            serde_json::to_value(revocation(&Err("refused".into()))).unwrap(),
            json!({"checks": [], "error": "refused"})
        );
    }

    /// Tolerance verdicts map to `tolerated`, `rejected`, or `null`.
    #[test]
    fn intolerance_object() {
        let result = Intolerance {
            version: Some(ProtocolVersion::TLS12),
            unknown_version: Some(true),
            unknown_extension: Some(false),
            grease: None,
            oversized: Some(true),
            fragmented: Some(false),
        };
        assert_eq!(
            serde_json::to_value(intolerance(&Ok(result))).unwrap(),
            json!({
                "protocol": "TLSv1.2",
                "tests": {
                    "unknown_version": "tolerated",
                    "unknown_extension": "rejected",
                    "grease": null,
                    "oversized": "tolerated",
                    "fragmented": "rejected",
                },
            })
        );
    }

    /// Handshake details keep every flag and the probed legacy version.
    #[test]
    fn details_object() {
        let result = HandshakeDetails {
            legacy_version: Some(ProtocolVersion::TLS12),
            extended_master_secret: Some(true),
            downgrade_sentinel: Some(false),
            session_tickets: None,
            max_early_data: Some(0),
        };
        assert_eq!(
            serde_json::to_value(details(&Ok(result))).unwrap(),
            json!({
                "protocol": "TLSv1.2",
                "extended_master_secret": true,
                "downgrade_sentinel": false,
                "session_tickets": null,
                "max_early_data": 0,
            })
        );
    }

    /// Vulnerabilities carry their verdict and the reporting finding id.
    #[test]
    fn vulnerability_object() {
        let v = Vulnerability {
            id: "crime",
            name: "CRIME",
            status: VulnStatus::Vulnerable,
            detail: "TLS compression enabled".into(),
            finding: Some("vuln.crime"),
        };
        assert_eq!(
            serde_json::to_value(vulnerability(&v)).unwrap(),
            json!({
                "id": "crime",
                "name": "CRIME",
                "status": "vulnerable",
                "detail": "TLS compression enabled",
                "finding": "vuln.crime",
            })
        );
        let v = Vulnerability {
            status: VulnStatus::NotTested,
            finding: None,
            ..v
        };
        assert_eq!(
            serde_json::to_value(vulnerability(&v)).unwrap()["finding"],
            Value::Null
        );
    }
}
