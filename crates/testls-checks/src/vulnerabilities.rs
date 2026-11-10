//! Named vulnerabilities derived from data the scan already collected.
//!
//! Nothing here sends attack traffic: each verdict comes from the offered
//! protocols, cipher suites, key exchange parameters, handshake features and
//! the HTTP response headers.
//! Findings are only emitted for issues no other check reports already; the
//! rest point to the existing finding id.

use testls_probe::{
    CipherResult, HandshakeFeatures, HttpResponse, KeyExchangeResult, ProtocolResult,
    ProtocolSupport, TlsUpgrade,
};
use testls_wire::ProtocolVersion;

use crate::ciphers::{cipher_name, finding_id, has_weakness};
use crate::{Finding, Severity};

/// Verdict for one vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnStatus {
    /// The server shows the weakness.
    Vulnerable,
    /// The server does not show the weakness.
    NotVulnerable,
    /// The data needed for a verdict is missing.
    NotTested,
}

impl VulnStatus {
    /// Stable lower-case name used in reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vulnerable => "vulnerable",
            Self::NotVulnerable => "not vulnerable",
            Self::NotTested => "not tested",
        }
    }
}

/// One named vulnerability and its verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vulnerability {
    /// Stable short id, e.g. `poodle`.
    pub id: &'static str,
    /// Display name, e.g. `POODLE`.
    pub name: &'static str,
    /// Verdict.
    pub status: VulnStatus,
    /// Short reason for the verdict.
    pub detail: String,
    /// Finding id that reports the issue when vulnerable.
    pub finding: Option<&'static str>,
}

/// Builds a [`Vulnerability`].
fn vuln(
    id: &'static str,
    name: &'static str,
    status: VulnStatus,
    detail: impl Into<String>,
    finding: &'static str,
) -> Vulnerability {
    Vulnerability {
        id,
        name,
        status,
        detail: detail.into(),
        finding: (status == VulnStatus::Vulnerable).then_some(finding),
    }
}

/// Severity of the findings this module owns.
fn severity(finding: &str) -> Option<Severity> {
    match finding {
        "vuln.heartbleed" => Some(Severity::Critical),
        "vuln.crime" | "vuln.ccs_injection" | "vuln.ticketbleed" => Some(Severity::High),
        "vuln.renegotiation" | "vuln.opossum" => Some(Severity::Medium),
        "vuln.beast" | "vuln.logjam" | "vuln.fallback_scsv" | "vuln.raccoon" | "vuln.breach"
        | "vuln.alpaca" => Some(Severity::Low),
        _ => None,
    }
}

/// Everything the assessment looks at.
struct Inputs<'a> {
    protocols: &'a [ProtocolResult],
    ciphers: &'a [CipherResult],
    key_exchange: &'a [KeyExchangeResult],
    features: Option<&'a HandshakeFeatures>,
    http: Option<&'a HttpResponse>,
    upgrade: Option<&'a [TlsUpgrade]>,
}

impl Inputs<'_> {
    /// Whether `version` was offered; `None` when the probe failed.
    fn offered(&self, version: ProtocolVersion) -> Option<bool> {
        match self
            .protocols
            .iter()
            .find(|p| p.version == version)?
            .support
        {
            ProtocolSupport::Supported => Some(true),
            ProtocolSupport::NotSupported => Some(false),
            ProtocolSupport::Error(_) => None,
        }
    }

    /// Accepted SSLv3+ suites that satisfy `pred`, deduplicated by name,
    /// with the finding id the cipher check emits for each.
    fn suites(
        &self,
        pred: impl Fn(ProtocolVersion, &str) -> bool,
    ) -> Vec<(&'static str, Option<&'static str>)> {
        let mut found: Vec<(&'static str, Option<&'static str>)> = self
            .ciphers
            .iter()
            .filter(|c| c.version >= ProtocolVersion::SSL3)
            .flat_map(|c| c.suites.iter().map(move |&id| (c.version, id)))
            .filter(|&(v, id)| pred(v, cipher_name(v, id)))
            .map(|(v, id)| (cipher_name(v, id), finding_id(v, id)))
            .collect();
        found.sort_unstable();
        found.dedup_by_key(|(name, _)| *name);
        found
    }

    /// Whether a version matching `relevant` is offered (or failed to probe)
    /// but has no (or an empty) cipher enumeration, so suite verdicts are
    /// incomplete.
    fn enumeration_missing(&self, relevant: impl Fn(ProtocolVersion) -> bool) -> bool {
        self.protocols.iter().any(|p| {
            p.version >= ProtocolVersion::SSL3
                && relevant(p.version)
                && p.support != ProtocolSupport::NotSupported
                && !self
                    .ciphers
                    .iter()
                    .any(|c| c.version == p.version && !c.suites.is_empty())
        })
    }

    /// Whether an offered SSLv3..TLSv1.2 version lacks a key exchange result,
    /// or accepted a DHE suite without a DH parameter measurement.
    fn dh_unmeasured(&self) -> bool {
        self.protocols.iter().any(|p| {
            let legacy = (ProtocolVersion::SSL3..ProtocolVersion::TLS13).contains(&p.version);
            if !legacy || p.support == ProtocolSupport::NotSupported {
                return false;
            }
            let Some(k) = self.key_exchange.iter().find(|k| k.version == p.version) else {
                return true;
            };
            // The probe never measures DHE-PSK, so its parameters stay unknown.
            let dhe_psk = self
                .suite_names(p.version)
                .any(|n| n.starts_with("TLS_DHE_PSK_"));
            dhe_psk || (self.accepts_dhe(p.version) && k.dh_bits.is_none())
        })
    }

    /// Names of the suites accepted with `version`.
    fn suite_names(&self, version: ProtocolVersion) -> impl Iterator<Item = &'static str> + '_ {
        self.ciphers
            .iter()
            .filter(move |c| c.version == version)
            .flat_map(|c| &c.suites)
            .map(move |&id| cipher_name(version, id))
    }

    /// Whether `version` accepted a finite-field DHE suite.
    fn accepts_dhe(&self, version: ProtocolVersion) -> bool {
        self.suite_names(version)
            .any(|n| n.starts_with("TLS_DHE_") || n.starts_with("TLS_DH_anon_"))
    }

    /// Key exchange results for versions before TLSv1.3.
    fn legacy_key_exchange(&self) -> impl Iterator<Item = &KeyExchangeResult> {
        self.key_exchange
            .iter()
            .filter(|k| k.version < ProtocolVersion::TLS13)
    }
}

/// Verdict from whether a protocol version is offered.
fn protocol_vuln(
    inputs: &Inputs,
    id: &'static str,
    name: &'static str,
    version: ProtocolVersion,
    finding: &'static str,
) -> Vulnerability {
    let (status, detail) = match inputs.offered(version) {
        Some(true) => (VulnStatus::Vulnerable, format!("{version} offered")),
        Some(false) => (VulnStatus::NotVulnerable, format!("{version} not offered")),
        None => (VulnStatus::NotTested, format!("{version} probe failed")),
    };
    vuln(id, name, status, detail, finding)
}

/// Finding that reports the affected suites: `preferred` when one of them
/// emits it, otherwise the id emitted for the first suite.
fn pointer(
    found: &[(&'static str, Option<&'static str>)],
    preferred: &'static str,
) -> &'static str {
    if found.iter().any(|&(_, f)| f == Some(preferred)) {
        return preferred;
    }
    found
        .iter()
        .find_map(|&(_, f)| f)
        .unwrap_or("cipher.unknown")
}

/// Verdict from the accepted suites matching `pred` with a version matching
/// `versions`; a vulnerable verdict points to a cipher finding that is
/// actually emitted, preferably `finding`.
fn suite_vuln(
    inputs: &Inputs,
    (id, name, finding): (&'static str, &'static str, &'static str),
    versions: impl Fn(ProtocolVersion) -> bool,
    pred: impl Fn(&str) -> bool,
) -> Vulnerability {
    let found = inputs.suites(|v, n| versions(v) && pred(n));
    let missing = inputs.enumeration_missing(&versions);
    match found.as_slice() {
        [] if inputs.ciphers.is_empty() || missing => vuln(
            id,
            name,
            VulnStatus::NotTested,
            "cipher suites not enumerated for every offered version",
            finding,
        ),
        [] => vuln(
            id,
            name,
            VulnStatus::NotVulnerable,
            "no affected suites",
            finding,
        ),
        [(one, _)] => vuln(
            id,
            name,
            VulnStatus::Vulnerable,
            *one,
            pointer(&found, finding),
        ),
        [(first, _), rest @ ..] => vuln(
            id,
            name,
            VulnStatus::Vulnerable,
            format!("{first} and {} more", rest.len()),
            pointer(&found, finding),
        ),
    }
}

/// BEAST: CBC suites with SSLv3 or TLSv1.0, whose record IVs are predictable.
fn beast(inputs: &Inputs) -> Vulnerability {
    let (id, name, finding) = ("beast", "BEAST", "vuln.beast");
    let old = [ProtocolVersion::SSL3, ProtocolVersion::TLS10];
    if old.iter().all(|&v| inputs.offered(v) == Some(false)) {
        return vuln(
            id,
            name,
            VulnStatus::NotVulnerable,
            "no SSLv3 or TLSv1.0",
            finding,
        );
    }
    let mut verdict = suite_vuln(
        inputs,
        (id, name, finding),
        |v| old.contains(&v),
        |n| has_weakness("cbc", n),
    );
    if verdict.status == VulnStatus::Vulnerable {
        verdict.finding = Some(finding);
    }
    verdict
}

/// Logjam: export DHE suites, small DH groups, or a widely shared 1024-bit
/// prime that is a precomputation target.
fn logjam(inputs: &Inputs) -> Vulnerability {
    let (id, name) = ("logjam", "Logjam");
    if !inputs.ciphers.is_empty() {
        let export = inputs.suites(|_, n| n.contains("DHE") && n.contains("EXPORT"));
        if let Some((suite, _)) = export.first() {
            let finding = pointer(&export, "cipher.export");
            return vuln(id, name, VulnStatus::Vulnerable, *suite, finding);
        }
    }
    let mut detail = None;
    for k in inputs.legacy_key_exchange() {
        let Some(bits) = k.dh_bits else { continue };
        if bits < 1024 {
            let text = format!("{} uses a {bits}-bit DH group", k.version);
            return vuln(id, name, VulnStatus::Vulnerable, text, "dh.weak");
        }
        let known = k.dh_prime.as_deref().and_then(testls_data::known_dh_prime);
        if let Some(p) = known.filter(|p| !p.ffdhe && bits <= 1024) {
            let text = format!(
                "{} uses the well-known {} ({})",
                k.version, p.name, p.source
            );
            return vuln(id, name, VulnStatus::Vulnerable, text, "vuln.logjam");
        }
        detail = Some(match known {
            Some(p) => format!("{bits}-bit {}", p.name),
            None => format!("{bits}-bit custom DH group"),
        });
    }
    if inputs.dh_unmeasured() {
        return vuln(
            id,
            name,
            VulnStatus::NotTested,
            "DH parameters not measured for every offered version",
            "",
        );
    }
    match detail {
        Some(text) => vuln(id, name, VulnStatus::NotVulnerable, text, ""),
        None if inputs.legacy_key_exchange().next().is_some() => vuln(
            id,
            name,
            VulnStatus::NotVulnerable,
            "no DHE key exchange",
            "",
        ),
        None => vuln(id, name, VulnStatus::NotTested, "no key exchange data", ""),
    }
}

/// Raccoon: a DHE server that reuses its public value across handshakes.
fn raccoon(inputs: &Inputs) -> Vulnerability {
    let (id, name, finding) = ("raccoon", "Raccoon", "vuln.raccoon");
    let mut measured = false;
    let mut unmeasured = false;
    let mut dhe = false;
    for k in inputs.legacy_key_exchange() {
        let uses_dhe = k.dh_bits.is_some() || inputs.accepts_dhe(k.version);
        dhe |= uses_dhe;
        match k.dh_key_reused {
            Some(true) => {
                let text = format!("{} reuses its DH public value", k.version);
                return vuln(id, name, VulnStatus::Vulnerable, text, finding);
            }
            Some(false) => measured = true,
            None if uses_dhe => unmeasured = true,
            None => {}
        }
    }
    let (status, detail) = if unmeasured || inputs.dh_unmeasured() {
        (
            VulnStatus::NotTested,
            "DH key reuse not measured for every DHE result",
        )
    } else if measured {
        (
            VulnStatus::NotVulnerable,
            "fresh DH public value per handshake",
        )
    } else if dhe {
        (VulnStatus::NotTested, "DH key reuse not measured")
    } else if inputs.legacy_key_exchange().next().is_some() {
        (VulnStatus::NotVulnerable, "no DHE key exchange")
    } else {
        (VulnStatus::NotTested, "no key exchange data")
    };
    vuln(id, name, status, detail, finding)
}

/// Verdict from a handshake feature probe flag.
///
/// `flag` reads the feature; `bad` is the value that means vulnerable.
/// The probe picks its versions from the cipher enumerations, so a missing
/// enumeration for a `relevant` version leaves the verdict untested.
fn feature_vuln(
    inputs: &Inputs,
    (id, name, finding): (&'static str, &'static str, &'static str),
    relevant: fn(ProtocolVersion) -> bool,
    flag: fn(&HandshakeFeatures) -> (bool, Option<bool>),
    bad: bool,
    texts: [&'static str; 3],
) -> Vulnerability {
    let [vulnerable, safe, not_applicable] = texts;
    let Some(features) = inputs.features else {
        return vuln(
            id,
            name,
            VulnStatus::NotTested,
            "handshake probe failed",
            finding,
        );
    };
    let (applicable, value) = flag(features);
    let (status, detail) = match value {
        _ if !applicable => (VulnStatus::NotVulnerable, not_applicable),
        Some(v) if v == bad => (VulnStatus::Vulnerable, vulnerable),
        Some(_) => (VulnStatus::NotVulnerable, safe),
        None => (VulnStatus::NotTested, "handshake probe failed"),
    };
    if status == VulnStatus::NotVulnerable && inputs.enumeration_missing(relevant) {
        return vuln(
            id,
            name,
            VulnStatus::NotTested,
            "cipher suites not enumerated for every offered version",
            finding,
        );
    }
    vuln(id, name, status, detail, finding)
}

/// BREACH: the reply to `GET /` uses an HTTP content coding, so secrets in
/// response bodies can leak through the compressed length (as CRIME does for
/// TLS compression). Whether a body mixes secrets with attacker-chosen input
/// cannot be seen from outside, so a compressed reply is reported as a
/// potential issue. RFC 7457 §2.6 covers compression side channels.
fn breach(inputs: &Inputs) -> Vulnerability {
    let (id, name, finding) = ("breach", "BREACH", "vuln.breach");
    let Some(http) = inputs.http else {
        return vuln(
            id,
            name,
            VulnStatus::NotTested,
            "HTTP response not retrieved",
            finding,
        );
    };
    let codings = content_codings(http);
    if codings.is_empty() {
        return vuln(
            id,
            name,
            VulnStatus::NotVulnerable,
            "no HTTP compression",
            finding,
        );
    }
    let detail = format!("HTTP compression: {}", codings.join(", "));
    vuln(id, name, VulnStatus::Vulnerable, detail, finding)
}

/// Content codings of the response (RFC 9110 §8.4), lowercased, in order,
/// without `identity` and empty list elements.
fn content_codings(http: &HttpResponse) -> Vec<String> {
    http.header_values("content-encoding")
        .flat_map(|v| v.split(','))
        .map(|c| c.trim_matches([' ', '\t']).to_ascii_lowercase())
        .filter(|c| !c.is_empty() && c != "identity")
        .collect()
}

/// Assesses the named vulnerabilities from the collected scan data.
///
/// `ciphers` holds the successful cipher enumerations only; `features` is
/// `None` when the handshake feature probe failed, and `http` when the HTTP
/// headers were not retrieved; `upgrade` is `None` when the RFC 2817
/// upgrade probe did not run.
#[must_use]
pub fn assess_vulnerabilities(
    protocols: &[ProtocolResult],
    ciphers: &[CipherResult],
    key_exchange: &[KeyExchangeResult],
    features: Option<&HandshakeFeatures>,
    http: Option<&HttpResponse>,
    upgrade: Option<&[TlsUpgrade]>,
) -> Vec<Vulnerability> {
    let inputs = Inputs {
        protocols,
        ciphers,
        key_exchange,
        features,
        http,
        upgrade,
    };
    let only_tls13 = "no TLSv1.2 or older protocol";
    let all = |_: ProtocolVersion| true;
    let legacy = |v: ProtocolVersion| v <= ProtocolVersion::TLS12;
    vec![
        protocol_vuln(
            &inputs,
            "poodle",
            "POODLE",
            ProtocolVersion::SSL3,
            "protocol.ssl3",
        ),
        beast(&inputs),
        suite_vuln(&inputs, ("sweet32", "SWEET32", "cipher.3des"), all, |n| {
            ["3des", "des", "rc2"].iter().any(|k| has_weakness(k, n)) || n.contains("_IDEA_")
        }),
        suite_vuln(&inputs, ("rc4", "RC4", "cipher.rc4"), all, |n| {
            has_weakness("rc4", n)
        }),
        suite_vuln(&inputs, ("freak", "FREAK", "cipher.export"), all, |n| {
            n.starts_with("TLS_RSA_EXPORT")
        }),
        logjam(&inputs),
        protocol_vuln(
            &inputs,
            "drown",
            "DROWN",
            ProtocolVersion::SSL2,
            "protocol.ssl2",
        ),
        feature_vuln(
            &inputs,
            ("crime", "CRIME", "vuln.crime"),
            legacy,
            |f| (f.legacy_version.is_some(), f.compression),
            true,
            ["TLS compression enabled", "no TLS compression", only_tls13],
        ),
        feature_vuln(
            &inputs,
            (
                "renegotiation",
                "Insecure renegotiation",
                "vuln.renegotiation",
            ),
            legacy,
            |f| (f.legacy_version.is_some(), f.secure_renegotiation),
            false,
            [
                "no secure renegotiation (RFC 5746)",
                "secure renegotiation supported",
                only_tls13,
            ],
        ),
        feature_vuln(
            &inputs,
            (
                "fallback_scsv",
                "Downgrade (TLS_FALLBACK_SCSV)",
                "vuln.fallback_scsv",
            ),
            all,
            |f| (f.fallback_version.is_some(), f.fallback_scsv),
            false,
            [
                "TLS_FALLBACK_SCSV ignored",
                "TLS_FALLBACK_SCSV honoured",
                "only one protocol version offered",
            ],
        ),
        suite_vuln(
            &inputs,
            ("no_forward_secrecy", "No forward secrecy", "cipher.no_pfs"),
            all,
            |n| has_weakness("no_pfs", n),
        ),
        raccoon(&inputs),
        breach(&inputs),
        alpaca(&inputs),
        opossum(&inputs),
    ]
}

/// ALPACA: strict ALPN is one of the countermeasures (Brinkmann et al.,
/// USENIX Security 2021; RFC 7301 section 3.2). The probe runs at the
/// highest enumerated version, so a higher offered version without an
/// enumeration leaves the verdict untested; lower versions don't matter.
fn alpaca(inputs: &Inputs) -> Vulnerability {
    let (id, name, finding) = ("alpaca", "ALPACA", "vuln.alpaca");
    let probed = inputs
        .ciphers
        .iter()
        .filter(|c| c.version > ProtocolVersion::SSL3 && !c.suites.is_empty())
        .map(|c| c.version)
        .max();
    let higher_missing = probed.is_some_and(|best| inputs.enumeration_missing(|v| v > best));
    let (status, detail) = match inputs.features.and_then(|f| f.strict_alpn) {
        None => (VulnStatus::NotTested, "handshake probe failed"),
        Some(_) if higher_missing => (
            VulnStatus::NotTested,
            "cipher suites not enumerated for the highest offered version",
        ),
        Some(false) => (VulnStatus::Vulnerable, "unknown ALPN protocol accepted"),
        Some(true) => (VulnStatus::NotVulnerable, "unknown ALPN protocol refused"),
    };
    vuln(id, name, status, detail, finding)
}

/// Opossum: a server that switches plaintext HTTP to TLS on request
/// (RFC 2817 §3) lets an attacker desynchronise request and response
/// streams (Dahlke et al., USENIX Security 2024). Any port that accepts is
/// vulnerable; otherwise one unanswered probe leaves it untested.
fn opossum(inputs: &Inputs) -> Vulnerability {
    let (id, name, finding) = ("opossum", "Opossum", "vuln.opossum");
    let ports = |want: Option<bool>| {
        let ports: Vec<String> = inputs
            .upgrade
            .unwrap_or_default()
            .iter()
            .filter(|u| u.accepted == want)
            .map(|u| u.port.to_string())
            .collect();
        ports.join(", ")
    };
    let (status, detail) = match inputs.upgrade {
        None | Some([]) => (VulnStatus::NotTested, "HTTP upgrade not probed".to_owned()),
        Some(list) if list.iter().any(|u| u.accepted == Some(true)) => (
            VulnStatus::Vulnerable,
            format!("TLS upgrade accepted on port {}", ports(Some(true))),
        ),
        Some(list) if list.iter().any(|u| u.accepted.is_none()) => (
            VulnStatus::NotTested,
            format!("no answer to the upgrade request on port {}", ports(None)),
        ),
        Some(_) => (
            VulnStatus::NotVulnerable,
            format!("TLS upgrade refused on port {}", ports(Some(false))),
        ),
    };
    vuln(id, name, status, detail, finding)
}

/// Findings for vulnerable entries not already reported by another check.
#[must_use]
pub fn vulnerability_findings(vulnerabilities: &[Vulnerability]) -> Vec<Finding> {
    vulnerabilities
        .iter()
        .filter_map(|v| {
            let id = v.finding?;
            let severity = severity(id)?;
            Some(Finding::new(
                id,
                severity,
                format!("{}: {}", v.name, v.detail),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    //! Unit tests for the vulnerability assessment.

    use testls_probe::CipherOrder;

    use super::*;

    /// Ticketbleed findings keep their severity and possible-exposure detail.
    #[test]
    fn ticketbleed_finding() {
        let item = Vulnerability {
            id: "ticketbleed",
            name: "Ticketbleed",
            status: VulnStatus::Vulnerable,
            detail: "possible memory exposure".to_owned(),
            finding: Some("vuln.ticketbleed"),
        };
        let findings = vulnerability_findings(&[item]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].message, "Ticketbleed: possible memory exposure");
    }

    /// `TLS_RSA_WITH_3DES_EDE_CBC_SHA`.
    const RSA_3DES: u32 = 0x000a;
    /// `TLS_RSA_WITH_AES_128_CBC_SHA`.
    const RSA_AES_CBC: u32 = 0x002f;
    /// `TLS_RSA_WITH_RC4_128_SHA`.
    const RSA_RC4: u32 = 0x0005;
    /// `TLS_RSA_EXPORT_WITH_RC4_40_MD5`.
    const RSA_EXPORT: u32 = 0x0003;
    /// `TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA`.
    const DHE_EXPORT: u32 = 0x0014;
    /// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
    const ECDHE_GCM: u32 = 0xc02f;
    /// `TLS_AES_128_GCM_SHA256`.
    const TLS13_AES: u32 = 0x1301;

    /// Protocol results with `offered` supported and every other version not.
    fn protocols(offered: &[ProtocolVersion]) -> Vec<ProtocolResult> {
        ProtocolVersion::ALL
            .iter()
            .map(|&version| ProtocolResult {
                version,
                support: if offered.contains(&version) {
                    ProtocolSupport::Supported
                } else {
                    ProtocolSupport::NotSupported
                },
            })
            .collect()
    }

    /// A cipher result accepting `suites` with `version`.
    fn ciphers(version: ProtocolVersion, suites: &[u32]) -> CipherResult {
        CipherResult {
            version,
            suites: suites.to_vec(),
            order: CipherOrder::Server,
        }
    }

    /// Key exchange data for `version` with optional DH parameters.
    fn kx(
        version: ProtocolVersion,
        prime: Option<Vec<u8>>,
        reused: Option<bool>,
    ) -> KeyExchangeResult {
        KeyExchangeResult {
            version,
            groups: vec![0x001d],
            group_order: CipherOrder::Server,
            dh_bits: prime.as_ref().map(|p| p.len() * 8),
            dh_prime: prime,
            dh_key_reused: reused,
        }
    }

    /// Handshake features of a well-configured TLSv1.2 + TLSv1.3 server.
    fn good_features() -> HandshakeFeatures {
        HandshakeFeatures {
            legacy_version: Some(ProtocolVersion::TLS12),
            compression: Some(false),
            secure_renegotiation: Some(true),
            fallback_version: Some(ProtocolVersion::TLS12),
            fallback_scsv: Some(true),
            strict_alpn: Some(true),
        }
    }

    /// Upgrade probe result for a port that refused the upgrade.
    fn refused(port: u16) -> TlsUpgrade {
        TlsUpgrade {
            port,
            accepted: Some(false),
        }
    }

    /// Decodes upper-case hex.
    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Status of vulnerability `id` in `list`.
    fn status(list: &[Vulnerability], id: &str) -> VulnStatus {
        list.iter().find(|v| v.id == id).unwrap().status
    }

    /// A modern server is vulnerable to nothing and yields no findings.
    #[test]
    fn modern_server() {
        let p = protocols(&[ProtocolVersion::TLS12, ProtocolVersion::TLS13]);
        let c = [
            ciphers(ProtocolVersion::TLS12, &[ECDHE_GCM]),
            ciphers(ProtocolVersion::TLS13, &[TLS13_AES]),
        ];
        let k = [
            kx(ProtocolVersion::TLS12, None, None),
            kx(ProtocolVersion::TLS13, None, None),
        ];
        let http = response(&[("Content-Type", "text/html")]);
        let upgrade = [refused(443), refused(80)];
        let list = assess_vulnerabilities(
            &p,
            &c,
            &k,
            Some(&good_features()),
            Some(&http),
            Some(&upgrade),
        );
        assert_eq!(list.len(), 15);
        for v in &list {
            assert_eq!(
                v.status,
                VulnStatus::NotVulnerable,
                "{}: {}",
                v.id,
                v.detail
            );
            assert_eq!(v.finding, None);
        }
        assert_eq!(vulnerability_findings(&list), []);
    }

    /// A legacy server trips most checks; only new issues become findings.
    #[test]
    fn legacy_server() {
        let all = [
            ProtocolVersion::SSL2,
            ProtocolVersion::SSL3,
            ProtocolVersion::TLS10,
            ProtocolVersion::TLS12,
        ];
        let p = protocols(&all);
        let c = [
            ciphers(ProtocolVersion::TLS10, &[RSA_AES_CBC, RSA_3DES, RSA_RC4]),
            ciphers(ProtocolVersion::TLS12, &[RSA_EXPORT, ECDHE_GCM]),
        ];
        let oakley2 = unhex(testls_data::known_dh_primes()[1].hex);
        let k = [kx(ProtocolVersion::TLS12, Some(oakley2), Some(true))];
        let features = HandshakeFeatures {
            legacy_version: Some(ProtocolVersion::TLS12),
            compression: Some(true),
            secure_renegotiation: Some(false),
            fallback_version: Some(ProtocolVersion::TLS10),
            fallback_scsv: Some(false),
            strict_alpn: Some(false),
        };
        let http = response(&[("Content-Encoding", "gzip")]);
        let upgrade = [
            refused(443),
            TlsUpgrade {
                port: 80,
                accepted: Some(true),
            },
        ];
        let list = assess_vulnerabilities(&p, &c, &k, Some(&features), Some(&http), Some(&upgrade));
        for v in &list {
            assert_eq!(v.status, VulnStatus::Vulnerable, "{}: {}", v.id, v.detail);
        }
        let by_id = |id: &str| list.iter().find(|v| v.id == id).unwrap();
        assert_eq!(by_id("poodle").finding, Some("protocol.ssl3"));
        assert_eq!(by_id("sweet32").detail, "TLS_RSA_WITH_3DES_EDE_CBC_SHA");
        assert_eq!(
            by_id("no_forward_secrecy").detail,
            "TLS_RSA_EXPORT_WITH_RC4_40_MD5 and 3 more"
        );
        assert_eq!(by_id("logjam").finding, Some("vuln.logjam"));
        assert!(by_id("logjam").detail.contains("Oakley group 2"));

        let findings = vulnerability_findings(&list);
        let ids: Vec<(&str, Severity)> = findings
            .iter()
            .map(|f| (f.id.as_str(), f.severity))
            .collect();
        assert_eq!(
            ids,
            [
                ("vuln.beast", Severity::Low),
                ("vuln.logjam", Severity::Low),
                ("vuln.crime", Severity::High),
                ("vuln.renegotiation", Severity::Medium),
                ("vuln.fallback_scsv", Severity::Low),
                ("vuln.raccoon", Severity::Low),
                ("vuln.breach", Severity::Low),
                ("vuln.alpaca", Severity::Low),
                ("vuln.opossum", Severity::Medium),
            ]
        );
        assert_eq!(findings[2].message, "CRIME: TLS compression enabled");
    }

    /// Logjam verdicts: export DHE, small groups, shared and safe primes.
    #[test]
    fn logjam_cases() {
        let p = protocols(&[ProtocolVersion::TLS12]);
        let assess = |c: &[CipherResult], k: &[KeyExchangeResult]| {
            let list = assess_vulnerabilities(&p, c, k, None, None, None);
            list.into_iter().find(|v| v.id == "logjam").unwrap()
        };
        let tls12 = ProtocolVersion::TLS12;

        let v = assess(&[ciphers(tls12, &[DHE_EXPORT])], &[]);
        assert_eq!(
            (v.status, v.finding),
            (VulnStatus::Vulnerable, Some("cipher.export"))
        );

        let v = assess(&[], &[kx(tls12, Some(vec![0xff; 64]), None)]);
        assert_eq!(
            (v.status, v.finding),
            (VulnStatus::Vulnerable, Some("dh.weak"))
        );
        assert_eq!(v.detail, "TLSv1.2 uses a 512-bit DH group");

        let ffdhe2048 = unhex(testls_data::known_dh_primes()[11].hex);
        let v = assess(&[], &[kx(tls12, Some(ffdhe2048), None)]);
        assert_eq!(v.status, VulnStatus::NotVulnerable);
        assert_eq!(v.detail, "2048-bit ffdhe2048");

        let v = assess(&[], &[kx(tls12, Some(vec![0xc5; 128]), None)]);
        assert_eq!(v.detail, "1024-bit custom DH group");

        let v = assess(&[], &[kx(tls12, None, None)]);
        assert_eq!(
            (v.status, v.detail.as_str()),
            (VulnStatus::NotVulnerable, "no DHE key exchange")
        );

        let v = assess(&[], &[]);
        assert_eq!(v.status, VulnStatus::NotTested);

        // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 accepted, DH size not measured.
        let v = assess(&[ciphers(tls12, &[0x009e])], &[kx(tls12, None, None)]);
        assert_eq!(v.status, VulnStatus::NotTested);

        // TLS_DHE_PSK_WITH_AES_128_GCM_SHA256: the probe does not measure it.
        let v = assess(&[ciphers(tls12, &[0x00aa])], &[kx(tls12, None, None)]);
        assert_eq!(v.status, VulnStatus::NotTested);
        // Mixed with a measured DHE suite, DHE-PSK still stays unmeasured.
        let k = [kx(tls12, Some(vec![0xc5; 256]), None)];
        let v = assess(&[ciphers(tls12, &[0x00aa, 0x009e])], &k);
        assert_eq!(v.status, VulnStatus::NotTested);

        // One offered version without key exchange data.
        let p = protocols(&[ProtocolVersion::TLS11, tls12]);
        let k = [kx(tls12, Some(vec![0xc5; 256]), None)];
        let list = assess_vulnerabilities(&p, &[], &k, None, None, None);
        assert_eq!(status(&list, "logjam"), VulnStatus::NotTested);
        // A measured weak group still wins.
        let k = [kx(tls12, Some(vec![0xff; 64]), None)];
        let list = assess_vulnerabilities(&p, &[], &k, None, None, None);
        assert_eq!(status(&list, "logjam"), VulnStatus::Vulnerable);
    }

    /// Missing data leads to "not tested" rather than a guess.
    #[test]
    fn missing_data() {
        let mut p = protocols(&[ProtocolVersion::TLS12]);
        p[1].support = ProtocolSupport::Error("timeout".into());
        let k = [kx(ProtocolVersion::TLS12, Some(vec![0xc5; 256]), None)];
        let list = assess_vulnerabilities(&p, &[], &k, None, None, None);
        for id in [
            "poodle",
            "beast",
            "sweet32",
            "rc4",
            "crime",
            "renegotiation",
            "fallback_scsv",
            "raccoon",
            "alpaca",
            "opossum",
        ] {
            assert_eq!(status(&list, id), VulnStatus::NotTested, "{id}");
        }
        assert_eq!(status(&list, "drown"), VulnStatus::NotVulnerable);
        assert_eq!(vulnerability_findings(&list), []);
    }

    /// A supported version without cipher enumeration makes a clean suite
    /// verdict "not tested", but found suites still count.
    #[test]
    fn incomplete_enumeration() {
        let p = protocols(&[ProtocolVersion::TLS10, ProtocolVersion::TLS12]);
        let c = [ciphers(ProtocolVersion::TLS12, &[ECDHE_GCM, RSA_RC4])];
        let list = assess_vulnerabilities(&p, &c, &[], None, None, None);
        for id in ["beast", "sweet32", "freak"] {
            assert_eq!(status(&list, id), VulnStatus::NotTested, "{id}");
        }
        assert_eq!(status(&list, "rc4"), VulnStatus::Vulnerable);
        // An empty enumeration counts as missing too.
        let c = [
            ciphers(ProtocolVersion::TLS10, &[]),
            ciphers(ProtocolVersion::TLS12, &[ECDHE_GCM]),
        ];
        let list = assess_vulnerabilities(&p, &c, &[], None, None, None);
        assert_eq!(status(&list, "beast"), VulnStatus::NotTested);
        // Feature probes pick versions from the enumerations, so a missing
        // one leaves clean feature verdicts untested; findings still count.
        let features = HandshakeFeatures {
            legacy_version: Some(ProtocolVersion::TLS12),
            compression: Some(true),
            secure_renegotiation: Some(true),
            fallback_version: None,
            fallback_scsv: None,
            strict_alpn: Some(true),
        };
        let c = [ciphers(ProtocolVersion::TLS12, &[ECDHE_GCM])];
        let list = assess_vulnerabilities(&p, &c, &[], Some(&features), None, None);
        assert_eq!(status(&list, "crime"), VulnStatus::Vulnerable);
        for id in ["renegotiation", "fallback_scsv"] {
            assert_eq!(status(&list, id), VulnStatus::NotTested, "{id}");
        }
        // ALPACA only needs the version it probed, not lower ones.
        assert_eq!(status(&list, "alpaca"), VulnStatus::NotVulnerable);
    }

    /// A higher offered version without an enumeration means the ALPN probe
    /// ran below the best version, so either outcome is untested.
    #[test]
    fn alpaca_higher_version_missing() {
        let p = protocols(&[ProtocolVersion::TLS12, ProtocolVersion::TLS13]);
        let c = [ciphers(ProtocolVersion::TLS12, &[ECDHE_GCM])];
        for strict in [true, false] {
            let features = HandshakeFeatures {
                strict_alpn: Some(strict),
                ..good_features()
            };
            let list = assess_vulnerabilities(&p, &c, &[], Some(&features), None, None);
            assert_eq!(status(&list, "alpaca"), VulnStatus::NotTested, "{strict}");
        }
    }

    /// Vulnerable verdicts point to the cipher finding that is emitted.
    #[test]
    fn finding_pointers() {
        let p = protocols(&[ProtocolVersion::TLS12]);
        let by_id = |suites: &[u32], id: &str| {
            let c = [ciphers(ProtocolVersion::TLS12, suites)];
            let list = assess_vulnerabilities(&p, &c, &[], None, None, None);
            list.into_iter().find(|v| v.id == id).unwrap().finding
        };
        // TLS_RSA_WITH_AES_128_CBC_SHA is reported as cipher.cbc.
        assert_eq!(
            by_id(&[RSA_AES_CBC], "no_forward_secrecy"),
            Some("cipher.cbc")
        );
        // The export RC4 suite is reported as cipher.export.
        assert_eq!(by_id(&[RSA_EXPORT], "rc4"), Some("cipher.export"));
        assert_eq!(by_id(&[RSA_EXPORT, RSA_RC4], "rc4"), Some("cipher.rc4"));
        // TLS_RSA_WITH_DES_CBC_SHA is reported as cipher.des.
        assert_eq!(by_id(&[0x0009], "sweet32"), Some("cipher.des"));
        // TLS_RSA_WITH_IDEA_CBC_SHA has no IDEA rule; it is reported as cipher.cbc.
        assert_eq!(by_id(&[0x0007], "sweet32"), Some("cipher.cbc"));
    }

    /// One DHE result without a reuse measurement makes Raccoon "not tested".
    #[test]
    fn raccoon_partially_measured() {
        let p = protocols(&[ProtocolVersion::TLS11, ProtocolVersion::TLS12]);
        let k = [
            kx(ProtocolVersion::TLS11, Some(vec![0xc5; 256]), None),
            kx(ProtocolVersion::TLS12, Some(vec![0xc5; 256]), Some(false)),
        ];
        let list = assess_vulnerabilities(&p, &[], &k, None, None, None);
        assert_eq!(status(&list, "raccoon"), VulnStatus::NotTested);
        // An accepted DHE suite (TLS_DHE_RSA_WITH_AES_128_GCM_SHA256) without
        // any DH measurement is not "no DHE key exchange".
        let p = protocols(&[ProtocolVersion::TLS12]);
        let c = [ciphers(ProtocolVersion::TLS12, &[0x009e])];
        let k = [kx(ProtocolVersion::TLS12, None, None)];
        let list = assess_vulnerabilities(&p, &c, &k, None, None, None);
        assert_eq!(status(&list, "raccoon"), VulnStatus::NotTested);
        // A fresh TLSv1.2 result says nothing about TLSv1.1 without a key
        // exchange result, nor about unmeasured DHE-PSK (0x00aa).
        let p = protocols(&[ProtocolVersion::TLS11, ProtocolVersion::TLS12]);
        let k = [kx(
            ProtocolVersion::TLS12,
            Some(vec![0xc5; 256]),
            Some(false),
        )];
        let list = assess_vulnerabilities(&p, &[], &k, None, None, None);
        assert_eq!(status(&list, "raccoon"), VulnStatus::NotTested);
        let p = protocols(&[ProtocolVersion::TLS12]);
        let c = [ciphers(ProtocolVersion::TLS12, &[0x009e, 0x00aa])];
        let list = assess_vulnerabilities(&p, &c, &k, None, None, None);
        assert_eq!(status(&list, "raccoon"), VulnStatus::NotTested);
    }

    /// Feature checks do not apply to TLSv1.3-only or single-version servers.
    #[test]
    fn features_not_applicable() {
        let p = protocols(&[ProtocolVersion::TLS13]);
        let c = [ciphers(ProtocolVersion::TLS13, &[TLS13_AES])];
        let features = HandshakeFeatures {
            legacy_version: None,
            compression: None,
            secure_renegotiation: None,
            fallback_version: None,
            fallback_scsv: None,
            strict_alpn: None,
        };
        let list = assess_vulnerabilities(&p, &c, &[], Some(&features), None, None);
        let crime = list.iter().find(|v| v.id == "crime").unwrap();
        assert_eq!(crime.status, VulnStatus::NotVulnerable);
        assert_eq!(crime.detail, "no TLSv1.2 or older protocol");
        let fallback = list.iter().find(|v| v.id == "fallback_scsv").unwrap();
        assert_eq!(fallback.detail, "only one protocol version offered");
        assert_eq!(status(&list, "beast"), VulnStatus::NotVulnerable);
        assert_eq!(VulnStatus::NotTested.as_str(), "not tested");
    }

    /// Response with status 200 and the given header fields.
    fn response(headers: &[(&str, &str)]) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_ascii_lowercase(), (*v).to_owned()))
                .collect(),
        }
    }

    /// BREACH: any content coding but `identity` counts; no HTTP response
    /// leaves it untested.
    #[test]
    fn breach_cases() {
        let p = protocols(&[ProtocolVersion::TLS13]);
        let c = [ciphers(ProtocolVersion::TLS13, &[TLS13_AES])];
        let breach = |http: Option<&HttpResponse>| {
            let list = assess_vulnerabilities(&p, &c, &[], None, http, None);
            list.into_iter().find(|v| v.id == "breach").unwrap()
        };
        let v = breach(None);
        assert_eq!(v.status, VulnStatus::NotTested);
        assert_eq!(v.detail, "HTTP response not retrieved");
        for plain in [
            &[][..],
            &[("Content-Encoding", "identity")],
            &[("Content-Encoding", " , ")],
        ] {
            let v = breach(Some(&response(plain)));
            assert_eq!(v.status, VulnStatus::NotVulnerable, "{plain:?}");
            assert_eq!(v.detail, "no HTTP compression");
        }
        let v = breach(Some(&response(&[
            ("Content-Encoding", "GZIP, identity"),
            ("Content-Encoding", "br"),
        ])));
        assert_eq!(v.status, VulnStatus::Vulnerable);
        assert_eq!(v.detail, "HTTP compression: gzip, br");
        assert_eq!(v.finding, Some("vuln.breach"));
        let findings = vulnerability_findings(&[v]);
        assert_eq!(findings[0].message, "BREACH: HTTP compression: gzip, br");
    }

    /// Opossum: one accepting port is enough; an unanswered probe leaves a
    /// clean result untested; no probe is untested.
    #[test]
    fn opossum_cases() {
        let p = protocols(&[ProtocolVersion::TLS13]);
        let c = [ciphers(ProtocolVersion::TLS13, &[TLS13_AES])];
        let opossum = |upgrade: Option<&[TlsUpgrade]>| {
            let list = assess_vulnerabilities(&p, &c, &[], None, None, upgrade);
            list.into_iter().find(|v| v.id == "opossum").unwrap()
        };
        let silent = |port| TlsUpgrade {
            port,
            accepted: None,
        };
        let accepted = |port| TlsUpgrade {
            port,
            accepted: Some(true),
        };
        let cases: [(Option<&[TlsUpgrade]>, VulnStatus, &str); 5] = [
            (None, VulnStatus::NotTested, "HTTP upgrade not probed"),
            (Some(&[]), VulnStatus::NotTested, "HTTP upgrade not probed"),
            (
                Some(&[refused(443), refused(80)]),
                VulnStatus::NotVulnerable,
                "TLS upgrade refused on port 443, 80",
            ),
            (
                Some(&[refused(443), silent(80)]),
                VulnStatus::NotTested,
                "no answer to the upgrade request on port 80",
            ),
            (
                Some(&[accepted(443), silent(80)]),
                VulnStatus::Vulnerable,
                "TLS upgrade accepted on port 443",
            ),
        ];
        for (upgrade, status, detail) in cases {
            let v = opossum(upgrade);
            assert_eq!(
                (v.status, v.detail.as_str()),
                (status, detail),
                "{upgrade:?}"
            );
        }
        let v = opossum(Some(&[accepted(80)]));
        assert_eq!(v.finding, Some("vuln.opossum"));
        let findings = vulnerability_findings(&[v]);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(
            findings[0].message,
            "Opossum: TLS upgrade accepted on port 80"
        );
    }
}
