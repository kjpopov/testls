//! The scan sections: each probes one aspect of the server and turns the
//! result into findings.

use testls_checks::{
    Finding, PolicyInput, RevocationCheck, Severity, TrustStore, Vulnerability,
    assess_vulnerabilities, baseline_findings, certificate_findings, cipher_findings,
    describe_certificate, details_findings, http_extra_findings, http_findings,
    intolerance_findings, is_trusted, key_exchange_findings, ocsp_findings, policy_findings,
    revocation_findings, revocation_urls, trust_findings, verify_ocsp_response,
    vulnerability_findings,
};
use testls_probe::{
    CipherResult, Fetcher, HandshakeDetails, HttpResponse, Intolerance, KeyExchangeResult,
    ProtocolResult, ProtocolSupport, Transport, enumerate_ciphers, fetch_certificates,
    fetch_http_headers, probe_details, probe_features, probe_intolerance, probe_key_exchange,
    probe_tls_upgrade,
};
use testls_report::text::{CertificateSection, CipherSection, KeyExchangeSection};
use testls_wire::ProtocolVersion;

use crate::{Event, OnEvent, Options, unix_now};

/// `policy.*` findings for each `--policy`. Successful cipher suite and key
/// exchange probes are checked per version; failed probes of versions a
/// policy allows make it incomplete (the quick profile skips key exchange).
pub(crate) fn policy_section(
    options: &Options,
    (protocols, ciphers, key_exchange): (
        &[ProtocolResult],
        &[CipherSection],
        &[KeyExchangeSection],
    ),
    chain: Option<&[Vec<u8>]>,
    http: &Result<HttpResponse, String>,
) -> Vec<Finding> {
    let (ciphers, cipher_errors) = measured_versions(ciphers, |s| (s.version, &s.outcome));
    let (key_exchange, key_exchange_errors) =
        measured_versions(key_exchange, |s| (s.version, &s.outcome));
    let input = PolicyInput {
        protocols,
        ciphers: Some(&ciphers),
        cipher_errors: &cipher_errors,
        key_exchange: options.profile.deep().then_some(&key_exchange[..]),
        key_exchange_errors: &key_exchange_errors,
        chain,
        http: http.as_ref().ok(),
    };
    options
        .policies
        .iter()
        .flat_map(|&p| policy_findings(p, &input))
        .collect()
}

/// The results of the sections that succeeded, and the protocol versions of
/// those that failed.
pub(crate) fn measured_versions<S, T: Clone>(
    sections: &[S],
    outcome: impl Fn(&S) -> (ProtocolVersion, &Result<T, String>),
) -> (Vec<T>, Vec<ProtocolVersion>) {
    let mut results = Vec::new();
    let mut failed = Vec::new();
    for section in sections {
        match outcome(section) {
            (_, Ok(result)) => results.push(result.clone()),
            (version, Err(_)) => failed.push(version),
        }
    }
    (results, failed)
}

/// Enumerates the cipher suites of one protocol `version`.
pub(crate) async fn cipher_section(
    transport: &Transport,
    version: ProtocolVersion,
    sni: Option<&str>,
) -> CipherSection {
    CipherSection {
        version,
        outcome: enumerate_ciphers(transport, version, sni)
            .await
            .map_err(|e| e.to_string()),
    }
}

/// Findings for one cipher section; a failed enumeration is informational.
pub(crate) fn section_findings(section: &CipherSection) -> Vec<Finding> {
    match &section.outcome {
        Ok(c) => cipher_findings(c),
        Err(e) => vec![Finding::new(
            "cipher.error",
            Severity::Info,
            format!("{} ciphers could not be enumerated: {e}", section.version),
        )],
    }
}

/// Probes the supported groups and DH parameter size of one protocol
/// `version`, using the suites accepted in the cipher `section`.
///
/// When cipher enumeration failed the accepted suites are unknown, so the
/// key exchange section reports that instead of probing.
pub(crate) async fn key_exchange_section(
    transport: &Transport,
    section: &CipherSection,
    sni: Option<&str>,
) -> KeyExchangeSection {
    let outcome = match &section.outcome {
        Ok(c) => probe_key_exchange(transport, section.version, &c.suites, sni)
            .await
            .map_err(|e| e.to_string()),
        Err(_) => Err("cipher enumeration failed".to_owned()),
    };
    KeyExchangeSection {
        version: section.version,
        outcome,
    }
}

/// Enumerates the cipher suites of each supported protocol and, when
/// `deep` is set, probes its key exchange, adding their findings to
/// `findings` and reporting each section to `on_event` as it finishes.
pub(crate) async fn suite_sections(
    transport: &Transport,
    protocols: &[ProtocolResult],
    sni: Option<&str>,
    deep: bool,
    findings: &mut Vec<Finding>,
    on_event: &mut OnEvent<'_>,
) -> (Vec<CipherSection>, Vec<KeyExchangeSection>) {
    let mut ciphers = Vec::new();
    let mut key_exchange = Vec::new();
    for r in protocols {
        if r.support != ProtocolSupport::Supported {
            continue;
        }
        let section = cipher_section(transport, r.version, sni).await;
        on_event(Event::Ciphers(&section));
        findings.extend(section_findings(&section));
        if deep {
            let kx = key_exchange_section(transport, &section, sni).await;
            on_event(Event::KeyExchange(&kx));
            findings.extend(kx_findings(&kx));
            key_exchange.push(kx);
        }
        ciphers.push(section);
    }
    (ciphers, key_exchange)
}

/// Fetches HTTP headers, derives vulnerabilities and runs the tolerance
/// and detail probes; all but the vulnerability verdicts are skipped
/// unless `deep` is set. Adds their findings to `findings` and reports each
/// section to `on_event`.
pub(crate) async fn later_sections(
    transport: &Transport,
    (protocols, ciphers, key_exchange): (
        &[ProtocolResult],
        &[CipherSection],
        &[KeyExchangeSection],
    ),
    sni: Option<&str>,
    deep: bool,
    findings: &mut Vec<Finding>,
    on_event: &mut OnEvent<'_>,
) -> (
    Result<HttpResponse, String>,
    Vec<Vulnerability>,
    Result<Intolerance, String>,
    Result<HandshakeDetails, String>,
) {
    let http = if let Some(protocol) = transport.starttls {
        let reason = format!("not checked over --starttls {protocol}");
        on_event(Event::HttpSkipped(&reason));
        Err(reason)
    } else if deep {
        let (http, http_findings) = http_section(transport, sni).await;
        on_event(Event::Http(&http));
        findings.extend(http_findings);
        http
    } else {
        skipped()
    };

    let measured = (protocols, ciphers, key_exchange, http.as_ref().ok());
    let vulns = vulnerability_section(transport, measured, sni, deep).await;
    on_event(Event::Vulnerabilities(&vulns));
    findings.extend(vulnerability_findings(&vulns));

    if !deep {
        return (http, vulns, skipped(), skipped());
    }
    let (intolerance, intolerance_findings) = intolerance_section(transport, ciphers, sni).await;
    on_event(Event::Intolerance(&intolerance));
    findings.extend(intolerance_findings);
    let (details, details_findings) = details_section(transport, ciphers, sni).await;
    on_event(Event::Details(&details));
    findings.extend(details_findings);
    (http, vulns, intolerance, details)
}

/// Result of a section the `quick` profile leaves out: an error naming
/// the profile.
pub(crate) fn skipped<T>() -> Result<T, String> {
    Err(crate::profile::SKIPPED.to_owned())
}

/// Findings for one key exchange section; a failed probe is informational.
pub(crate) fn kx_findings(section: &KeyExchangeSection) -> Vec<Finding> {
    match &section.outcome {
        Ok(k) => key_exchange_findings(k),
        Err(e) => vec![Finding::new(
            "group.error",
            Severity::Info,
            format!("{} key exchange could not be probed: {e}", section.version),
        )],
    }
}

/// Certificate section, its findings, and the DER chain when it was
/// retrieved.
pub(crate) type CertificateOutcome = (
    Result<CertificateSection, String>,
    Vec<Finding>,
    Option<Vec<Vec<u8>>>,
);

/// Fetches and checks the certificate chain, returning its description,
/// findings, and the chain itself.
///
/// The leaf is checked against `host`, the SNI name or the target IP.
pub(crate) async fn certificate_section(
    transport: &Transport,
    sni: Option<&str>,
    host: &str,
    store: &TrustStore,
) -> CertificateOutcome {
    let chain = match fetch_certificates(transport, sni).await {
        Ok(chain) => chain,
        Err(e) => {
            let finding = Finding::new(
                "cert.error",
                Severity::Info,
                format!("certificate could not be retrieved: {e}"),
            );
            return (Err(e.to_string()), vec![finding], None);
        }
    };
    let now = unix_now();
    let mut findings = certificate_findings(&chain.certificates, Some(host), now);
    if !chain.signature_verified {
        findings.push(Finding::new(
            "cert.signature_unverified",
            Severity::Info,
            "handshake signature not verified: scheme or key not supported",
        ));
    }
    if store.is_public() && is_trusted(&chain.certificates, now, store) {
        findings.extend(baseline_findings(&chain.certificates));
    }
    findings.extend(trust_findings(&chain.certificates, now, store));
    let ocsp_response = chain.ocsp_response.as_deref();
    findings.extend(ocsp_findings(&chain.certificates, ocsp_response, now));
    let ocsp = ocsp_response.map(|der| verify_ocsp_response(der, &chain.certificates, now));
    let section = CertificateSection {
        version: chain.version,
        certificates: chain
            .certificates
            .iter()
            .map(|der| describe_certificate(der))
            .collect(),
        ocsp,
    };
    (Ok(section), findings, Some(chain.certificates))
}

/// Checks the leaf of `chain` against the issuer's OCSP responders and
/// CRLs. Without a chain or with unreadable URLs the check cannot run,
/// which is informational.
///
/// Requests use the connect and read timeouts of `transport`; non-public
/// endpoints are refused unless `allow_private` is set.
pub(crate) async fn revocation_section(
    transport: &Transport,
    chain: Option<&[Vec<u8>]>,
    allow_private: bool,
) -> (Result<Vec<RevocationCheck>, String>, Vec<Finding>) {
    let fetcher = Fetcher {
        connect_timeout: transport.connect_timeout,
        read_timeout: transport.read_timeout,
        max_body: 0,
        source: transport.source,
        proxy: transport.proxy,
        allow_private,
    };
    let urls = chain
        .ok_or_else(|| "certificate chain could not be retrieved".to_owned())
        .and_then(|chain| {
            let leaf = chain.first().ok_or("empty certificate chain")?;
            revocation_urls(leaf).map(|urls| (chain, urls))
        });
    match urls {
        Ok((chain, urls)) => {
            let now = unix_now();
            let checks = crate::revocation::check_revocation(fetcher, chain, &urls, now).await;
            let findings = revocation_findings(&checks, now);
            (Ok(checks), findings)
        }
        Err(e) => {
            let finding = Finding::new(
                "revocation.error",
                Severity::Info,
                format!("revocation status could not be checked: {e}"),
            );
            (Err(e), vec![finding])
        }
    }
}

/// Fetches the reply to `GET /` and checks HSTS, security headers, banners,
/// `Alt-Svc`, and cookies.
///
/// A server that does not speak HTTP is common for non-web TLS services,
/// so a failed fetch is informational.
pub(crate) async fn http_section(
    transport: &Transport,
    sni: Option<&str>,
) -> (Result<HttpResponse, String>, Vec<Finding>) {
    match fetch_http_headers(transport, sni).await {
        Ok(response) => {
            let mut findings = http_findings(&response);
            findings.extend(http_extra_findings(&response));
            (Ok(response), findings)
        }
        Err(e) => {
            let finding = Finding::new(
                "http.error",
                Severity::Info,
                format!("HTTP headers could not be retrieved: {e}"),
            );
            (Err(e.to_string()), vec![finding])
        }
    }
}

/// Probes compression, renegotiation, downgrade protection, ALPN and, unless
/// STARTTLS is used, the RFC 2817 HTTP upgrade when `probe` is set, then
/// derives the named vulnerabilities from everything the scan
/// collected: protocols, cipher and key exchange sections, and the HTTP
/// response when one was retrieved.
///
/// A failed or skipped feature probe or HTTP fetch leaves the affected
/// verdicts as not tested.
pub(crate) async fn vulnerability_section(
    transport: &Transport,
    (protocols, ciphers, key_exchange, http): (
        &[ProtocolResult],
        &[CipherSection],
        &[KeyExchangeSection],
        Option<&HttpResponse>,
    ),
    sni: Option<&str>,
    probe: bool,
) -> Vec<Vulnerability> {
    let ciphers: Vec<CipherResult> = ciphers
        .iter()
        .filter_map(|s| s.outcome.as_ref().ok().cloned())
        .collect();
    let key_exchange = measured(key_exchange);
    // The RFC 2817 upgrade probe speaks plaintext HTTP, which STARTTLS
    // protocols are not.
    let (features, upgrade) = if probe {
        let upgrade = async {
            match transport.starttls {
                Some(_) => None,
                None => Some(Box::pin(probe_tls_upgrade(transport, sni)).await),
            }
        };
        let (features, upgrade) =
            tokio::join!(Box::pin(probe_features(transport, &ciphers, sni)), upgrade);
        (features.ok(), upgrade)
    } else {
        (None, None)
    };
    assess_vulnerabilities(
        protocols,
        &ciphers,
        &key_exchange,
        features.as_ref(),
        http,
        upgrade.as_deref(),
    )
}

/// Sends unusual but valid `ClientHello`s at the best offered version.
///
/// A probe error becomes an informational `intolerance.error` finding.
pub(crate) async fn intolerance_section(
    transport: &Transport,
    ciphers: &[CipherSection],
    sni: Option<&str>,
) -> (Result<Intolerance, String>, Vec<Finding>) {
    let ciphers: Vec<CipherResult> = ciphers
        .iter()
        .filter_map(|s| s.outcome.as_ref().ok().cloned())
        .collect();
    match probe_intolerance(transport, &ciphers, sni).await {
        Ok(result) => {
            let findings = intolerance_findings(&result);
            (Ok(result), findings)
        }
        Err(e) => {
            let finding = Finding::new(
                "intolerance.error",
                Severity::Info,
                format!("ClientHello tolerance could not be tested: {e}"),
            );
            (Err(e.to_string()), vec![finding])
        }
    }
}

/// The key exchange results that were measured without error.
pub(crate) fn measured(sections: &[KeyExchangeSection]) -> Vec<KeyExchangeResult> {
    sections
        .iter()
        .filter_map(|s| s.outcome.as_ref().ok().cloned())
        .collect()
}

/// Probes extended master secret, the downgrade sentinel, session tickets
/// and 0-RTT.
///
/// A probe error becomes an informational `handshake.error` finding.
pub(crate) async fn details_section(
    transport: &Transport,
    ciphers: &[CipherSection],
    sni: Option<&str>,
) -> (Result<HandshakeDetails, String>, Vec<Finding>) {
    let ciphers: Vec<CipherResult> = ciphers
        .iter()
        .filter_map(|s| s.outcome.as_ref().ok().cloned())
        .collect();
    match probe_details(transport, &ciphers, sni).await {
        Ok(result) => {
            let findings = details_findings(&result);
            (Ok(result), findings)
        }
        Err(e) => {
            let finding = Finding::new(
                "handshake.error",
                Severity::Info,
                format!("handshake details could not be probed: {e}"),
            );
            (Err(e.to_string()), vec![finding])
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for section results when probes fail.

    use std::net::SocketAddr;

    use super::*;

    /// A failed cipher enumeration is reported in the key exchange section
    /// without probing the server.
    #[tokio::test]
    async fn key_exchange_after_cipher_error() {
        // Nothing listens on port 9 of the discard address; no probe is sent.
        let transport = Transport::new(SocketAddr::from(([127, 0, 0, 1], 9)));
        let ciphers = CipherSection {
            version: ProtocolVersion::TLS12,
            outcome: Err("timed out".to_owned()),
        };
        let kx = key_exchange_section(&transport, &ciphers, None).await;
        assert_eq!(kx.version, ProtocolVersion::TLS12);
        assert_eq!(
            kx.outcome.as_ref().unwrap_err(),
            "cipher enumeration failed"
        );
        assert_eq!(kx_findings(&kx)[0].id, "group.error");
    }

    /// Without a certificate chain the revocation check reports why.
    #[tokio::test]
    async fn revocation_without_chain() {
        let transport = Transport::new(SocketAddr::from(([127, 0, 0, 1], 9)));
        let (section, findings) = revocation_section(&transport, None, false).await;
        assert_eq!(
            section.unwrap_err(),
            "certificate chain could not be retrieved"
        );
        assert_eq!(findings[0].id, "revocation.error");
        let (section, findings) = revocation_section(&transport, Some(&[]), false).await;
        assert_eq!(section.unwrap_err(), "empty certificate chain");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    /// A failed HTTP fetch becomes an informational finding.
    #[tokio::test]
    async fn http_error_is_info() {
        // Nothing listens on port 9 of the discard address.
        let transport = Transport::new(SocketAddr::from(([127, 0, 0, 1], 9)));
        let (http, findings) = http_section(&transport, None).await;
        assert!(http.is_err());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "http.error");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    /// A failed handshake feature probe leaves its verdicts untested.
    #[tokio::test]
    async fn vulnerabilities_without_features() {
        let transport = Transport::new(SocketAddr::from(([127, 0, 0, 1], 9)));
        let protocols = [ProtocolResult {
            version: ProtocolVersion::TLS12,
            support: ProtocolSupport::Supported,
        }];
        let ciphers = [CipherSection {
            version: ProtocolVersion::TLS12,
            outcome: Ok(CipherResult {
                version: ProtocolVersion::TLS12,
                suites: vec![0xc02f],
                order: testls_probe::CipherOrder::Server,
            }),
        }];
        let measured = (&protocols[..], &ciphers[..], &[][..], None);
        let list = vulnerability_section(&transport, measured, None, true).await;
        let crime = list.iter().find(|v| v.id == "crime").expect("crime");
        assert_eq!(crime.status, testls_checks::VulnStatus::NotTested);
        assert_eq!(vulnerability_findings(&list), vec![]);
    }

    /// A failed tolerance probe is reported as an info finding.
    #[tokio::test]
    async fn intolerance_error_is_info() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let ciphers = [CipherSection {
            version: ProtocolVersion::TLS12,
            outcome: Ok(CipherResult {
                version: ProtocolVersion::TLS12,
                suites: vec![0xc02f],
                order: testls_probe::CipherOrder::Server,
            }),
        }];
        let (section, findings) = intolerance_section(&Transport::new(addr), &ciphers, None).await;
        assert!(section.is_err());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "intolerance.error");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    /// A failed handshake details probe is reported as an info finding.
    #[tokio::test]
    async fn details_error_is_info() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let ciphers = [CipherSection {
            version: ProtocolVersion::TLS12,
            outcome: Ok(CipherResult {
                version: ProtocolVersion::TLS12,
                suites: vec![0xc02f],
                order: testls_probe::CipherOrder::Server,
            }),
        }];
        let (section, findings) = details_section(&Transport::new(addr), &ciphers, None).await;
        assert!(section.is_err());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "handshake.error");
        assert_eq!(findings[0].severity, Severity::Info);
    }
}
