//! The `testls` scan pipeline: probes one server address section by section,
//! reports each section as it finishes, and returns the collected results
//! with their findings and grade.
//!
//! The command-line tool renders the [`Event`]s as text; other front ends
//! can serialise them instead.

mod profile;
mod revocation;
mod sections;
pub mod target;

use std::fmt;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use testls_checks::{
    Finding, Grade, Policy, PostQuantum, RevocationCheck, TrustStore, Vulnerability,
    post_quantum_readiness, protocol_findings,
};
use testls_probe::{
    HandshakeDetails, HttpResponse, Intolerance, ProtocolResult, ProtocolSupport, Transport,
    detect_protocols,
};
use testls_report::Painter;
use testls_report::text::{self, CertificateSection, CipherSection, KeyExchangeSection};
use testls_wire::ProtocolVersion;

pub use profile::{SKIPPED, ScanProfile};

use sections::{
    certificate_section, later_sections, measured, policy_section, revocation_section,
    suite_sections,
};

/// What to scan beyond the address itself. Start from
/// [`Options::default`] and set the fields you need.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Options {
    /// Server name to send in SNI and check the certificate against; the
    /// target IP is checked when `None`.
    pub sni: Option<String>,
    /// How thorough the scan is.
    pub profile: ScanProfile,
    /// Check revocation even when the profile does not.
    pub revocation: bool,
    /// Enable intrusive Heartbleed, CCS, Ticketbleed and ROBOT probes; never implied by a profile.
    pub intrusive: bool,
    /// Let revocation lookups reach non-public addresses.
    pub revocation_allow_private: bool,
    /// Policies to check the server against.
    pub policies: Vec<Policy>,
}

/// A section of the scan that has just finished, in scan order.
#[derive(Debug, Clone, Copy)]
pub enum Event<'a> {
    /// Protocol version support.
    Protocols(&'a [ProtocolResult]),
    /// Cipher suites of one supported protocol version.
    Ciphers(&'a CipherSection),
    /// Key exchange groups of one supported protocol version.
    KeyExchange(&'a KeyExchangeSection),
    /// Post-quantum readiness, after every key exchange section.
    PostQuantum(&'a PostQuantum),
    /// Certificate chain, or why it could not be retrieved.
    Certificate(&'a Result<CertificateSection, String>),
    /// Revocation checks, or why they could not run.
    Revocation(&'a Result<Vec<RevocationCheck>, String>),
    /// Reply to `GET /`, or why it could not be fetched.
    Http(&'a Result<HttpResponse, String>),
    /// Why HTTP headers were not fetched at all, such as STARTTLS.
    HttpSkipped(&'a str),
    /// Named vulnerability verdicts.
    Vulnerabilities(&'a [Vulnerability]),
    /// `ClientHello` tolerance, or why it could not be tested.
    Intolerance(&'a Result<Intolerance, String>),
    /// Handshake details, or why they could not be probed.
    Details(&'a Result<HandshakeDetails, String>),
}

impl Event<'_> {
    /// Stable name of the section, such as `ciphers`.
    #[must_use]
    pub fn section(&self) -> &'static str {
        match self {
            Self::Protocols(_) => "protocols",
            Self::Ciphers(_) => "ciphers",
            Self::KeyExchange(_) => "key_exchange",
            Self::PostQuantum(_) => "post_quantum",
            Self::Certificate(_) => "certificate",
            Self::Revocation(_) => "revocation",
            Self::Http(_) | Self::HttpSkipped(_) => "http",
            Self::Vulnerabilities(_) => "vulnerabilities",
            Self::Intolerance(_) => "intolerance",
            Self::Details(_) => "details",
        }
    }

    /// Protocol version the section covers, for the per-version sections.
    #[must_use]
    pub fn version(&self) -> Option<ProtocolVersion> {
        match self {
            Self::Ciphers(s) => Some(s.version),
            Self::KeyExchange(s) => Some(s.version),
            _ => None,
        }
    }

    /// Text rendering of the section, as the CLI prints it.
    #[must_use]
    pub fn text(&self, paint: Painter) -> String {
        match *self {
            Self::Protocols(p) => text::protocols(p, paint),
            Self::Ciphers(s) => text::ciphers(s, paint),
            Self::KeyExchange(s) => text::key_exchange(s, paint),
            Self::PostQuantum(pq) => text::post_quantum(pq, paint),
            Self::Certificate(c) => text::certificate(c, paint),
            Self::Revocation(r) => text::revocation(r, paint),
            Self::Http(h) => text::http(h, paint),
            Self::HttpSkipped(reason) => format!("HTTP headers: {reason}"),
            Self::Vulnerabilities(v) => text::vulnerabilities(v, paint),
            Self::Intolerance(i) => text::intolerance(i, paint),
            Self::Details(d) => text::details(d, paint),
        }
    }
}

/// Receiver of the [`Event`]s of a running scan.
pub type OnEvent<'a> = dyn FnMut(Event<'_>) + Send + 'a;

/// Why a scan stopped before collecting any results.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScanError {
    /// Every protocol probe failed, so nothing else can be tested.
    NoProtocol,
}

impl fmt::Display for ScanError {
    /// Describes the error in the CLI's wording.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProtocol => f.write_str("no protocol could be tested"),
        }
    }
}

impl std::error::Error for ScanError {}

/// Everything one scan collected. Sections the profile skips hold
/// [`SKIPPED`] as their error.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Scan {
    /// Address that was scanned.
    pub addr: SocketAddr,
    /// SNI name sent, if any.
    pub sni: Option<String>,
    /// Unix time the scan started.
    pub started_at: i64,
    /// Protocol support results.
    pub protocols: Vec<ProtocolResult>,
    /// Cipher enumeration per supported protocol.
    pub ciphers: Vec<CipherSection>,
    /// Key exchange probe per supported protocol; empty for `quick`.
    pub key_exchange: Vec<KeyExchangeSection>,
    /// Post-quantum readiness of the TLSv1.3 key exchange.
    pub post_quantum: PostQuantum,
    /// Certificate chain description, or why it could not be retrieved.
    pub certificate: Result<CertificateSection, String>,
    /// DER certificate chain when it was retrieved.
    pub chain: Option<Vec<Vec<u8>>>,
    /// Revocation checks; `None` when not requested.
    pub revocation: Option<Result<Vec<RevocationCheck>, String>>,
    /// Reply to `GET /`, or why it was not fetched.
    pub http: Result<HttpResponse, String>,
    /// Named vulnerability verdicts.
    pub vulnerabilities: Vec<Vulnerability>,
    /// `ClientHello` tolerance, or why it was not tested.
    pub intolerance: Result<Intolerance, String>,
    /// Handshake details, or why they were not probed.
    pub details: Result<HandshakeDetails, String>,
    /// Grade derived from all findings.
    pub grade: Grade,
    /// All findings in scan order, `ok` ones included.
    pub findings: Vec<Finding>,
}

/// Scans the server at `transport` with `options`, checking certificates
/// against `store` and handing each finished section to `on_event`.
///
/// The SNI name also becomes [`Transport::host`] (used by STARTTLS) unless
/// the caller has set one.
///
/// # Errors
///
/// [`ScanError::NoProtocol`] when no protocol version could be tested.
pub async fn scan(
    mut transport: Transport,
    options: &Options,
    store: &TrustStore,
    on_event: &mut OnEvent<'_>,
) -> Result<Scan, ScanError> {
    let sni = options.sni.as_deref();
    default_host(&mut transport, sni);
    let addr = transport.addr;
    let started_at = unix_now();

    let protocols = detect_protocols(&transport, sni).await;
    on_event(Event::Protocols(&protocols));
    if protocols
        .iter()
        .all(|r| matches!(r.support, ProtocolSupport::Error(_)))
    {
        return Err(ScanError::NoProtocol);
    }
    let mut findings = protocol_findings(&protocols);

    let deep = options.profile.deep();
    let (ciphers, key_exchange) =
        suite_sections(&transport, &protocols, sni, deep, &mut findings, on_event).await;
    let post_quantum = post_quantum_readiness(&measured(&key_exchange));
    if deep {
        on_event(Event::PostQuantum(&post_quantum));
    }

    let host = sni.map_or_else(|| addr.ip().to_string(), str::to_owned);
    let (certificate, cert_findings, chain) =
        certificate_section(&transport, sni, &host, store).await;
    on_event(Event::Certificate(&certificate));
    findings.extend(cert_findings);

    let revocation = if options.revocation || options.profile.full() {
        let allow_private = options.revocation_allow_private;
        let (section, more) = revocation_section(&transport, chain.as_deref(), allow_private).await;
        on_event(Event::Revocation(&section));
        findings.extend(more);
        Some(section)
    } else {
        None
    };

    let (http, vulnerabilities, intolerance, details) = later_sections(
        &transport,
        (&protocols, &ciphers, &key_exchange),
        sni,
        (deep, options.intrusive),
        &mut findings,
        on_event,
    )
    .await;
    let measured_parts = (&protocols[..], &ciphers[..], &key_exchange[..]);
    findings.extend(policy_section(
        options,
        measured_parts,
        chain.as_deref(),
        &http,
    ));
    let grade = testls_checks::grade(&findings, &protocols, http.as_ref().ok());

    Ok(Scan {
        addr,
        sni: options.sni.clone(),
        started_at,
        protocols,
        ciphers,
        key_exchange,
        post_quantum,
        certificate,
        chain,
        revocation,
        http,
        vulnerabilities,
        intolerance,
        details,
        grade,
        findings,
    })
}

/// Sets `transport.host` to `sni` when the caller left it unset.
fn default_host(transport: &mut Transport, sni: Option<&str>) {
    if transport.host.is_none() {
        transport.host = sni.map(str::to_owned);
    }
}

/// Current time as a Unix timestamp.
#[must_use]
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    //! Unit tests for the scan entry point.

    use super::*;

    /// The scan future can run on a multi-threaded runtime, as a server
    /// needs.
    #[test]
    fn scan_is_send() {
        /// Compiles only for `Send` values.
        fn assert_send<T: Send>(_: &T) {}
        let transport = Transport::new(SocketAddr::from(([127, 0, 0, 1], 9)));
        let options = Options::default();
        let store = TrustStore::webpki();
        let mut on_event = |_: Event<'_>| {};
        let future = scan(transport, &options, &store, &mut on_event);
        assert_send(&future);
    }

    /// The no-protocol error keeps the CLI's wording.
    #[test]
    fn error_message() {
        assert_eq!(
            ScanError::NoProtocol.to_string(),
            "no protocol could be tested"
        );
    }

    /// An explicit transport host survives; otherwise the SNI name fills it.
    #[test]
    fn host_defaults_to_sni() {
        let mut transport = Transport::new(SocketAddr::from(([127, 0, 0, 1], 9)));
        default_host(&mut transport, Some("sni.example"));
        assert_eq!(transport.host.as_deref(), Some("sni.example"));
        transport.host = Some("xmpp.example".to_owned());
        default_host(&mut transport, None);
        assert_eq!(transport.host.as_deref(), Some("xmpp.example"));
        default_host(&mut transport, Some("sni.example"));
        assert_eq!(transport.host.as_deref(), Some("xmpp.example"));
    }

    /// A server that refuses every connection yields only the protocols
    /// event, then the no-protocol error.
    #[tokio::test]
    async fn refused_reports_protocols_only() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let mut events = Vec::new();
        let mut on_event = |event: Event<'_>| events.push(format!("{event:?}"));
        let result = scan(
            Transport::new(addr),
            &Options::default(),
            &TrustStore::webpki(),
            &mut on_event,
        )
        .await;
        assert_eq!(result.err(), Some(ScanError::NoProtocol));
        assert_eq!(events.len(), 1);
        assert!(events[0].starts_with("Protocols("), "{events:?}");
    }

    /// Events name their section, carry a version only for per-version
    /// sections, and render the CLI text.
    #[test]
    fn event_metadata() {
        let skipped = Event::HttpSkipped("not over STARTTLS");
        assert_eq!(skipped.section(), "http");
        assert_eq!(skipped.version(), None);
        assert_eq!(
            skipped.text(Painter::new(false)),
            "HTTP headers: not over STARTTLS"
        );

        let tls12 = ProtocolVersion(0x0303);
        let ciphers = CipherSection {
            version: tls12,
            outcome: Err("reset".into()),
        };
        let kx = KeyExchangeSection {
            version: tls12,
            outcome: Err("reset".into()),
        };
        let failed = "unreachable".to_owned();
        let certificate = Err(failed.clone());
        let revocation = Err(failed.clone());
        let http = Err(failed.clone());
        let intolerance = Err(failed.clone());
        let details = Err(failed);
        let pq = post_quantum_readiness(&[]);
        for (event, name, version) in [
            (Event::Protocols(&[]), "protocols", None),
            (Event::Ciphers(&ciphers), "ciphers", Some(tls12)),
            (Event::KeyExchange(&kx), "key_exchange", Some(tls12)),
            (Event::PostQuantum(&pq), "post_quantum", None),
            (Event::Certificate(&certificate), "certificate", None),
            (Event::Revocation(&revocation), "revocation", None),
            (Event::Http(&http), "http", None),
            (Event::Vulnerabilities(&[]), "vulnerabilities", None),
            (Event::Intolerance(&intolerance), "intolerance", None),
            (Event::Details(&details), "details", None),
        ] {
            assert_eq!(event.section(), name);
            assert_eq!(event.version(), version, "{name}");
            let _ = event.text(Painter::new(false));
        }
    }
}
