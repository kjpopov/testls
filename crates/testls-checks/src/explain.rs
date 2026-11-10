//! Catalogue of finding ids with a short rationale and a reference.
//!
//! Every id a check can emit has an entry here; `testls explain <id>` prints
//! it. Ids are part of the output contract and never change meaning.

/// Explanation of one finding id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Explanation {
    /// Stable dotted finding id, e.g. `hsts.missing`.
    pub id: &'static str,
    /// One-line summary of what the finding means.
    pub title: &'static str,
    /// Why it matters and what to do about it.
    pub rationale: &'static str,
    /// Standard or document the check is based on.
    pub reference: &'static str,
}

/// Shorthand constructor that keeps the table below compact.
const fn entry(
    id: &'static str,
    title: &'static str,
    rationale: &'static str,
    reference: &'static str,
) -> Explanation {
    Explanation {
        id,
        title,
        rationale,
        reference,
    }
}

/// All explanations, grouped by area and sorted by id within each area.
const EXPLANATIONS: &[Explanation] = &[
    // Protocol versions.
    entry(
        "protocol.ssl2",
        "SSLv2 is offered",
        "SSLv2 has fundamental design flaws: weak MAC construction, no handshake integrity and export ciphers. It also enables cross-protocol attacks such as DROWN against TLS on the same key. Disable it.",
        "RFC 6176",
    ),
    entry(
        "protocol.ssl3",
        "SSLv3 is offered",
        "SSLv3 CBC padding is not authenticated, which allows the POODLE padding oracle, and its RC4 suites are broken. Disable it.",
        "RFC 7568",
    ),
    entry(
        "protocol.tls10",
        "TLSv1.0 is offered",
        "TLSv1.0 relies on SHA-1 and MD5 in the handshake and lacks modern AEAD ciphers. It is formally deprecated; disable it unless very old clients must be served.",
        "RFC 8996",
    ),
    entry(
        "protocol.tls11",
        "TLSv1.1 is offered",
        "TLSv1.1 shares the weaknesses of TLSv1.0 apart from the CBC IV fix and is formally deprecated. Disable it.",
        "RFC 8996",
    ),
    entry(
        "protocol.tls12",
        "TLSv1.2 status",
        "Reported when TLSv1.2 is offered (fine) or could not be tested (informational).",
        "RFC 5246, RFC 9325",
    ),
    entry(
        "protocol.tls13",
        "TLSv1.3 status",
        "Reported when TLSv1.3 is offered (fine) or could not be tested (informational).",
        "RFC 8446",
    ),
    entry(
        "protocol.no_modern",
        "Neither TLSv1.2 nor TLSv1.3 is offered",
        "Current clients require TLSv1.2 or later. A server that offers only older versions is insecure and increasingly unreachable.",
        "RFC 8996, RFC 9325",
    ),
    entry(
        "protocol.no_tls13",
        "TLSv1.3 is not offered",
        "TLSv1.3 removes legacy algorithms, encrypts most of the handshake and always provides forward secrecy. Enabling it is recommended.",
        "RFC 8446, RFC 9325 §3.1.1",
    ),
    // Cipher suites.
    entry(
        "cipher.null",
        "Cipher suite without encryption",
        "NULL suites send application data in clear text. Never enable them on a public service.",
        "RFC 5246 appendix A.5, RFC 9325 §4.1",
    ),
    entry(
        "cipher.integrity_only",
        "Integrity-only TLSv1.3 suite",
        "TLS_SHA256_SHA256 and TLS_SHA384_SHA384 authenticate but do not encrypt data. They are meant for constrained industrial networks only.",
        "RFC 9150",
    ),
    entry(
        "cipher.anon",
        "Anonymous key exchange",
        "Anonymous suites skip server authentication, so any active attacker can intercept the connection.",
        "RFC 5246 appendix A.5, RFC 9325 §4.1",
    ),
    entry(
        "cipher.export",
        "Export-grade cipher suite",
        "Export suites use 40- or 56-bit keys and 512-bit key exchange that can be broken quickly; they enable attacks such as FREAK and Logjam.",
        "RFC 9325 §4.1",
    ),
    entry(
        "cipher.rc4",
        "RC4 cipher suite",
        "RC4 keystream biases allow plaintext recovery from repeated secrets such as cookies. RC4 is prohibited in TLS.",
        "RFC 7465",
    ),
    entry(
        "cipher.des",
        "Single-DES cipher suite",
        "DES has a 56-bit key that can be brute-forced with modest resources.",
        "RFC 5469, RFC 9325 §4.1",
    ),
    entry(
        "cipher.rc2",
        "RC2 cipher suite",
        "RC2 is an obsolete cipher only used with export-grade keys in SSL/TLS.",
        "RFC 9325 §4.1",
    ),
    entry(
        "cipher.md5",
        "Cipher suite with an MD5 MAC",
        "MD5 is cryptographically broken; suites that use it for the record MAC belong to the legacy SSL era.",
        "RFC 6151",
    ),
    entry(
        "cipher.3des",
        "Triple-DES cipher suite",
        "3DES has a 64-bit block size, so long connections leak plaintext through block collisions (Sweet32).",
        "RFC 9325 §4.1, NIST SP 800-131A Rev. 2",
    ),
    entry(
        "cipher.no_pfs",
        "Cipher suite without forward secrecy",
        "With static RSA or static (EC)DH key exchange, anyone who later obtains the server key can decrypt recorded traffic. Prefer ECDHE or DHE suites.",
        "RFC 9325 §4.1",
    ),
    entry(
        "cipher.cbc",
        "CBC-mode cipher suite",
        "CBC suites in TLS use MAC-then-encrypt and have a history of padding-oracle and timing attacks (Lucky Thirteen). Prefer AEAD suites such as AES-GCM or ChaCha20-Poly1305.",
        "RFC 9325 §4.2, RFC 7366",
    ),
    entry(
        "cipher.ssl2",
        "SSLv2 cipher spec",
        "Any cipher spec accepted over SSLv2 inherits the protocol's flaws.",
        "RFC 6176",
    ),
    entry(
        "cipher.unknown",
        "Unknown cipher suite",
        "The server accepted a suite that is not in the IANA registry, for example a private or draft code point.",
        "IANA TLS Cipher Suites registry",
    ),
    entry(
        "cipher.client_order",
        "Server follows the client's cipher order",
        "When the server does not enforce its own preference, a client that lists a weak suite first gets it even though a stronger common suite exists.",
        "RFC 9325 §4.2",
    ),
    entry(
        "cipher.error",
        "Cipher suites could not be enumerated",
        "A network or protocol error stopped cipher enumeration for this protocol version, so its suites were not rated.",
        "testls",
    ),
    // Key exchange.
    entry(
        "group.weak",
        "Deprecated key exchange group",
        "Binary curves, small prime curves and explicit curve parameters are deprecated, and the pre-standard Kyber code points are obsolete. Offer x25519, secp256r1, secp384r1 or X25519MLKEM768 instead.",
        "RFC 8422 §5.1.1, IANA TLS Supported Groups",
    ),
    entry(
        "group.no_post_quantum",
        "No post-quantum key exchange in TLSv1.3",
        "Hybrid ML-KEM groups such as X25519MLKEM768 protect recorded traffic against future quantum computers (harvest now, decrypt later).",
        "draft-ietf-tls-ecdhe-mlkem, FIPS 203",
    ),
    entry(
        "group.error",
        "Key exchange could not be probed",
        "A network or protocol error stopped group or DH parameter detection for this protocol version.",
        "testls",
    ),
    entry(
        "dh.weak",
        "Weak finite-field DH parameters",
        "DH primes below 1024 bits are within reach of well-funded attackers (Logjam); below 2048 bits they fall short of current guidance. Use 2048 bits or more, ideally the RFC 7919 groups, or prefer ECDHE.",
        "RFC 7919, NIST SP 800-57 Part 1",
    ),
    // Certificates.
    entry(
        "cert.missing",
        "No certificate sent",
        "The server completed the handshake without a certificate, so it cannot be authenticated.",
        "RFC 8446 §4.4.2",
    ),
    entry(
        "cert.unparsable",
        "Certificate cannot be parsed",
        "A certificate in the chain is not valid DER X.509; clients will reject it.",
        "RFC 5280",
    ),
    entry(
        "cert.expired",
        "Certificate has expired",
        "The current time is after notAfter, so clients reject the certificate. Renew it.",
        "RFC 5280 §4.1.2.5",
    ),
    entry(
        "cert.not_yet_valid",
        "Certificate is not yet valid",
        "The current time is before notBefore, so clients reject the certificate. Check the issuing process or the server clock.",
        "RFC 5280 §4.1.2.5",
    ),
    entry(
        "cert.expires_soon",
        "Certificate expires soon",
        "The leaf certificate expires within 30 days. Renew it before clients start failing.",
        "RFC 5280 §4.1.2.5",
    ),
    entry(
        "cert.hostname_mismatch",
        "Certificate does not cover the host name",
        "No subjectAltName entry matches the scanned name, so clients reject the certificate.",
        "RFC 6125, RFC 9525",
    ),
    entry(
        "cert.key_unparsable",
        "Certificate key cannot be parsed",
        "The leaf public key could not be decoded, so its strength was not checked.",
        "RFC 5280 §4.1.2.7",
    ),
    entry(
        "cert.weak_key",
        "Certificate key is too weak",
        "RSA keys below 2048 bits, EC keys below 224 bits and DSA keys do not reach 112-bit security. Issue a new certificate with a stronger key.",
        "NIST SP 800-57 Part 1 Rev. 5",
    ),
    entry(
        "cert.weak_signature",
        "Certificate signed with a weak hash",
        "MD2, MD4, MD5 and SHA-1 signatures can be forged with collision attacks. Reissue the certificate with SHA-256 or better.",
        "RFC 6151, RFC 9155",
    ),
    entry(
        "cert.untrusted",
        "Certificate chain is not trusted",
        "The chain does not lead to a root in the selected trust store, or a certificate in it is invalid. Clients will show an error.",
        "RFC 5280 §6",
    ),
    entry(
        "cert.too_long",
        "Certificate validity period too long",
        "Publicly trusted TLS certificates may be valid for at most 398 days, 200 days when issued from 15 March 2026, 100 days from 15 March 2027 and 47 days from 15 March 2029. Longer certificates break CA rules and may be rejected by browsers.",
        "CA/Browser Forum Baseline Requirements §6.3.2 (ballot SC-081v3)",
    ),
    entry(
        "cert.no_sct",
        "No embedded Certificate Transparency timestamps",
        "Browsers require proof that publicly trusted certificates were logged. Without embedded SCTs the server must deliver them in the TLS handshake or a stapled OCSP response, which this check does not see.",
        "RFC 6962 §3.3",
    ),
    entry(
        "cert.sct_invalid",
        "Embedded Certificate Transparency timestamps are unreadable",
        "The SCT list extension cannot be parsed, so clients cannot use it as proof of logging. Reissue the certificate.",
        "RFC 6962 §3.3",
    ),
    entry(
        "cert.error",
        "Certificate chain could not be retrieved",
        "The full handshake used to fetch the certificate chain failed. A handshake signature that does not match the leaf key also fails it: the peer does not hold the key of the certificate it presented.",
        "testls",
    ),
    entry(
        "cert.signature_unverified",
        "Handshake signature not verified",
        "The server signed the handshake with a scheme or key testls cannot check (ML-DSA, P-521, Ed448, or RSA keys under 2048 bits), so it cannot confirm the server holds the key of the certificate it presented. The certificate results still apply to the chain as sent.",
        "RFC 8446 §4.4.3",
    ),
    // Stapled OCSP.
    entry(
        "ocsp.stapled",
        "Valid OCSP response stapled",
        "The server staples a fresh, correctly signed OCSP response that reports the certificate as good.",
        "RFC 6066 §8, RFC 6960",
    ),
    entry(
        "ocsp.not_stapled",
        "No OCSP response stapled",
        "Without stapling, clients must ask the CA themselves or skip the revocation check. Enable OCSP stapling if the CA offers OCSP.",
        "RFC 6066 §8",
    ),
    entry(
        "ocsp.must_staple_missing",
        "Must-Staple certificate without a stapled response",
        "The certificate carries the TLS feature extension requiring an OCSP staple; clients that honour it will refuse the connection.",
        "RFC 7633",
    ),
    entry(
        "ocsp.invalid",
        "Stapled OCSP response is invalid",
        "The stapled response could not be parsed, does not cover the leaf, or is not signed by the issuer or an authorised responder.",
        "RFC 6960 §4.2.2.2",
    ),
    entry(
        "ocsp.revoked",
        "Stapled OCSP response reports revocation",
        "The CA has revoked the certificate. Replace it immediately.",
        "RFC 6960",
    ),
    entry(
        "ocsp.unknown",
        "Stapled OCSP response reports unknown",
        "The responder does not know the certificate, which usually means a misconfigured responder or a certificate it did not issue.",
        "RFC 6960 §2.2",
    ),
    entry(
        "ocsp.not_yet_valid",
        "Stapled OCSP response is not yet valid",
        "thisUpdate lies in the future, beyond the allowed clock skew. Check the server and responder clocks.",
        "RFC 6960 §4.2.2.1",
    ),
    entry(
        "ocsp.expired",
        "Stapled OCSP response has expired",
        "nextUpdate has passed (or a day has passed since thisUpdate when nextUpdate is absent). The server is not refreshing its staple.",
        "RFC 6960 §4.2.2.1",
    ),
    // Revocation lookups (--revocation).
    entry(
        "revocation.good",
        "Certificate is not revoked",
        "The issuer's OCSP responder or CRL reports the certificate as good.",
        "RFC 6960, RFC 5280 §5",
    ),
    entry(
        "revocation.revoked",
        "Certificate is revoked",
        "The issuer's OCSP responder or CRL lists the certificate as revoked. Replace it immediately.",
        "RFC 6960, RFC 5280 §5",
    ),
    entry(
        "revocation.unknown",
        "Responder does not know the certificate",
        "The issuer's OCSP responder answered unknown for the certificate.",
        "RFC 6960 §2.2",
    ),
    entry(
        "revocation.no_source",
        "No revocation source",
        "The certificate names no HTTP OCSP responder or CRL distribution point, so revocation cannot be checked.",
        "RFC 5280 §4.2.1.13, §4.2.2.1",
    ),
    entry(
        "revocation.error",
        "Revocation status could not be checked",
        "Every OCSP responder and CRL named by the certificate failed to answer with valid data.",
        "RFC 6960, RFC 5280 §5",
    ),
    entry(
        "revocation.not_yet_valid",
        "Revocation data is not yet valid",
        "The OCSP reply or CRL has a thisUpdate in the future, beyond the allowed clock skew.",
        "RFC 6960 §4.2.2.1, RFC 5280 §5.1.2.4",
    ),
    entry(
        "revocation.expired",
        "Revocation data has expired",
        "The OCSP reply or CRL is past its nextUpdate, so its answer can no longer be relied on.",
        "RFC 6960 §4.2.2.1, RFC 5280 §5.1.2.5",
    ),
    // HTTP headers.
    entry(
        "hsts",
        "HSTS is enabled",
        "The server sends a Strict-Transport-Security header with an adequate max-age.",
        "RFC 6797",
    ),
    entry(
        "hsts.missing",
        "No HSTS header",
        "Without Strict-Transport-Security, a network attacker can downgrade the first visit to plain HTTP (SSL stripping).",
        "RFC 6797",
    ),
    entry(
        "hsts.invalid",
        "Invalid HSTS header",
        "Browsers ignore a Strict-Transport-Security header that does not follow the grammar, so the policy has no effect.",
        "RFC 6797 §6.1",
    ),
    entry(
        "hsts.disabled",
        "HSTS max-age is zero",
        "max-age=0 tells browsers to forget the policy.",
        "RFC 6797 §6.1.1",
    ),
    entry(
        "hsts.short",
        "HSTS max-age is short",
        "A max-age below 180 days lets the policy lapse between visits. Use at least six months, ideally one year.",
        "RFC 6797 §11.2",
    ),
    entry(
        "hsts.preload_ineligible",
        "HSTS preload requested but not eligible",
        "Preload lists require max-age of at least one year and includeSubDomains alongside the preload directive.",
        "hstspreload.org",
    ),
    entry(
        "header.x_content_type_options",
        "No X-Content-Type-Options: nosniff",
        "Without nosniff, browsers may guess content types and execute uploaded files as scripts or styles.",
        "WHATWG Fetch Standard",
    ),
    entry(
        "header.framing",
        "No framing protection",
        "Without a restrictive X-Frame-Options or CSP frame-ancestors, other sites can embed the page for clickjacking.",
        "RFC 7034, CSP Level 3",
    ),
    entry(
        "header.content_security_policy",
        "No Content-Security-Policy",
        "A Content-Security-Policy limits where scripts and other resources load from and reduces the impact of cross-site scripting.",
        "W3C Content Security Policy Level 3",
    ),
    entry(
        "header.referrer_policy",
        "No Referrer-Policy",
        "Without a Referrer-Policy, full URLs may leak to other sites in the Referer header, depending on browser defaults.",
        "W3C Referrer Policy",
    ),
    entry(
        "header.banner",
        "Server software banner",
        "Server and X-Powered-By values that name software and versions help attackers pick known exploits; they add no value to clients.",
        "RFC 9110 §10.2.4",
    ),
    entry(
        "header.alt_svc_invalid",
        "Malformed Alt-Svc header",
        "Clients ignore an Alt-Svc header they cannot parse, so advertised alternatives such as HTTP/3 are never used.",
        "RFC 7838 §3",
    ),
    entry(
        "cookie.insecure",
        "Cookie without Secure",
        "Cookies without the Secure attribute are also sent over plain HTTP, where an attacker on the network can read them.",
        "RFC 6265 §4.1.2.5",
    ),
    entry(
        "cookie.no_httponly",
        "Cookie without HttpOnly",
        "Cookies without HttpOnly are readable by page scripts, so cross-site scripting can steal them. Session cookies should set it.",
        "RFC 6265 §4.1.2.6",
    ),
    entry(
        "cookie.no_samesite",
        "Cookie without SameSite",
        "Without an explicit SameSite attribute, cross-site request handling depends on browser defaults. Set Lax or Strict where possible.",
        "RFC 6265bis §4.1.2.7",
    ),
    entry(
        "cookie.samesite_none_insecure",
        "SameSite=None cookie without Secure",
        "Browsers reject SameSite=None cookies that lack Secure, so the cookie is dropped.",
        "RFC 6265bis §4.1.2.7",
    ),
    entry(
        "http.error",
        "HTTP headers could not be retrieved",
        "The HTTPS request used to read response headers failed, so HSTS and security headers were not checked.",
        "testls",
    ),
    entry(
        "intolerance.error",
        "ClientHello tolerance could not be tested",
        "The probe that sends unusual but valid ClientHellos failed, so tolerance was not checked.",
        "testls",
    ),
    entry(
        "handshake.error",
        "Handshake details could not be probed",
        "The probe for extended master secret, the downgrade sentinel, session tickets and 0-RTT failed, so they were not checked.",
        "testls",
    ),
    entry(
        "vuln.beast",
        "BEAST: CBC suites with SSLv3 or TLSv1.0",
        "SSLv3 and TLSv1.0 chain CBC record IVs, which lets an attacker who can inject chosen plaintext recover secrets; current clients mitigate it with record splitting.",
        "RFC 4346 §1.1, RFC 8996",
    ),
    entry(
        "vuln.crime",
        "CRIME: TLS compression enabled",
        "Compressing records before encryption leaks the length of secrets mixed with attacker-chosen data, such as session cookies.",
        "RFC 7457 §2.6",
    ),
    entry(
        "vuln.renegotiation",
        "No secure renegotiation",
        "Without the renegotiation_info extension an attacker can splice their own traffic in front of a client's session during renegotiation.",
        "RFC 5746",
    ),
    entry(
        "vuln.fallback_scsv",
        "TLS_FALLBACK_SCSV not honoured",
        "The server accepted a fallback handshake at a lower version, so clients that retry with older versions can be downgraded by an attacker.",
        "RFC 7507",
    ),
    entry(
        "vuln.logjam",
        "Logjam: widely shared 1024-bit DH prime",
        "A precomputation against a common 1024-bit prime breaks every handshake that uses it; use a 2048-bit or larger RFC 7919 group.",
        "RFC 7919, weakdh.org",
    ),
    entry(
        "vuln.raccoon",
        "Raccoon: reused DH public value",
        "A server that reuses its DHE secret across handshakes exposes a timing side channel on the shared secret; use fresh keys or ECDHE.",
        "RFC 7919 §8.3, raccoon-attack.com",
    ),
    entry(
        "vuln.breach",
        "BREACH: HTTP responses are compressed",
        "Compressing response bodies leaks the length of secrets, such as CSRF tokens, that appear next to attacker-reflected input. Only the front page is checked; disable compression for pages with secrets, or mask tokens per response.",
        "RFC 7457 §2.6, breachattack.com",
    ),
    entry(
        "vuln.alpaca",
        "ALPACA: unknown ALPN protocols are accepted",
        "A server that completes the handshake for an ALPN protocol it does not speak helps an attacker redirect traffic between services that share a certificate. Refuse unknown protocols with no_application_protocol and keep certificates specific to one service.",
        "RFC 7301 §3.2, alpaca-attack.com",
    ),
    entry(
        "vuln.robot",
        "ROBOT: RSA padding oracle",
        "The server gives different fatal alerts for correctly and incorrectly padded RSA key exchanges. An attacker may exploit a padding oracle to decrypt or sign data using the RSA key. Disable static RSA key exchange and update the TLS implementation.",
        "RFC 5246 §7.4.7.1; robotattack.org",
    ),
    entry(
        "vuln.ticketbleed",
        "Ticketbleed: possible memory exposure on ticket resumption",
        "The server extended a short session ID during ticket resumption. This can disclose uninitialized memory, although other implementations may exhibit a similar error without exposing memory. Check the server implementation and disable session tickets or apply its security updates.",
        "CVE-2016-9244; RFC 5077 §3.4",
    ),
    entry(
        "vuln.ccs_injection",
        "CCS injection: premature cipher activation",
        "The server appears to activate its cipher before the key exchange. CVE-2014-0224 allows a man-in-the-middle to weaken connections when both client and server are affected. Upgrade the TLS implementation.",
        "CVE-2014-0224; OpenSSL security advisory 2014-06-05; RFC 5246 §7.1",
    ),
    entry(
        "vuln.heartbleed",
        "Heartbleed: heartbeat discloses memory",
        "An opt-in malformed heartbeat received a correlated response containing more payload bytes than were supplied. Upgrade the affected TLS implementation and rotate potentially exposed secrets. Disclosed bytes are not reported.",
        "CVE-2014-0160; RFC 6520 §4",
    ),
    entry(
        "vuln.opossum",
        "Opossum: plaintext HTTP can be upgraded to TLS",
        "A server that switches a plaintext HTTP connection to TLS on request (RFC 2817) lets a man-in-the-middle splice responses from that connection into a browser's HTTPS session. Disable the HTTP Upgrade to TLS and serve HTTPS on its own port only.",
        "RFC 2817 §3, opossum-attack.com",
    ),
    entry(
        "intolerance.unknown_version",
        "Server rejects an unknown protocol version",
        "A server must negotiate the highest version both sides support; failing on a newer version offer breaks future clients and invites insecure fallback.",
        "RFC 8446 §4.1.2, §4.2.1",
    ),
    entry(
        "intolerance.unknown_extension",
        "Server rejects an unknown extension",
        "Servers must ignore extensions they do not recognise; rejecting them blocks clients from deploying new extensions.",
        "RFC 8446 §4.2, RFC 5246 §7.4.1.4",
    ),
    entry(
        "intolerance.grease",
        "Server rejects GREASE values",
        "Clients send reserved GREASE values to keep the ecosystem extensible; servers must ignore them like any unknown value.",
        "RFC 8701 §3",
    ),
    entry(
        "intolerance.oversized",
        "Server rejects a large ClientHello",
        "ClientHellos grow with post-quantum key shares and padding; a server must accept a hello that fills a whole record.",
        "RFC 8446 §5.1, RFC 7685",
    ),
    entry(
        "intolerance.fragmented",
        "Server rejects a fragmented ClientHello",
        "Handshake messages may span several records; a server that requires the ClientHello in one record breaks large hellos.",
        "RFC 8446 §5.1, RFC 5246 §6.2.1",
    ),
    entry(
        "handshake.no_ems",
        "No extended master secret",
        "Without the extended master secret a TLS 1.2 session key is not bound to the handshake transcript, enabling triple handshake attacks.",
        "RFC 7627 §1, §5",
    ),
    entry(
        "handshake.no_downgrade_sentinel",
        "TLSv1.3 server omits the downgrade sentinel",
        "A TLS 1.3 server answering an older handshake must mark its random so TLS 1.3 clients detect forced downgrades; without it the protection is lost.",
        "RFC 8446 §4.1.3",
    ),
    entry(
        "handshake.early_data",
        "Session tickets allow 0-RTT early data",
        "Early data is not protected against replay; only enable 0-RTT for idempotent requests and with application-level replay protection.",
        "RFC 8446 §8, §E.5",
    ),
    // Compliance policies (--policy).
    entry(
        "policy.cert_key",
        "Certificate key type or size outside the policy",
        "The chosen policy limits leaf keys, e.g. Mozilla modern allows only ECDSA on P-256 or P-384, Mozilla intermediate and NIST SP 800-52r2 also RSA of at least 2048 bits, BSI TR-02102-2 RSA of at least 3000 bits or ECDSA on NIST or brainpool curves, PCI DSS RSA of at least 2048 bits, ECDSA on NIST curves from P-224 up or brainpool curves, or EdDSA, CNSA 2.0 only ML-DSA-87. Reissue the certificate with an allowed key.",
        "Mozilla Server Side TLS 6.0; NIST SP 800-52r2 §3.2.1; BSI TR-02102-2 table 14, §3.6.2; PCI DSS v4.0.1 glossary 'Strong Cryptography'; draft-becker-cnsa2-tls-profile §8",
    ),
    entry(
        "policy.cert_lifespan",
        "Certificate validity period longer than the policy allows",
        "Shorter certificate lifetimes limit the damage of a compromised key; Mozilla modern allows 90 days and intermediate 366 days.",
        "Mozilla Server Side TLS 6.0",
    ),
    entry(
        "policy.cert_signature",
        "Certificate signature algorithm outside the policy",
        "The chosen policy lists the signature algorithms the leaf certificate may use, e.g. ECDSA with SHA-2 and, for Mozilla intermediate, sha256WithRSAEncryption; NIST SP 800-52r2 also allows RSA with SHA-384, SHA-512 and RSASSA-PSS; BSI TR-02102-2 only RSASSA-PSS with SHA-2 and ECDSA with SHA-2; PCI DSS the NIST list plus Ed25519 and Ed448; CNSA 2.0 allows only ML-DSA-87.",
        "Mozilla Server Side TLS 6.0; NIST SP 800-52r2 §3.2.1; BSI TR-02102-2 table 12; PCI DSS v4.0.1 glossary 'Strong Cryptography'; draft-becker-cnsa2-tls-profile §8",
    ),
    entry(
        "policy.cipher",
        "Cipher suite outside the policy",
        "The server accepts a cipher suite the chosen policy does not list. It may not be broken, but disabling it brings the configuration in line with the policy. PCI DSS lists no suites; it rejects broken suites and 64-bit block ciphers such as 3DES.",
        "Mozilla Server Side TLS 6.0; NIST SP 800-52r2 §3.3.1; BSI TR-02102-2 tables 3 and 13; PCI DSS v4.0.1 req. 4.2.1; draft-becker-cnsa2-tls-profile §4",
    ),
    entry(
        "policy.group",
        "Key exchange group outside the policy",
        "The server accepts a named group or TLSv1.2 DHE prime the chosen policy does not list; Mozilla allows X25519MLKEM768, x25519, secp256r1 and secp384r1, NIST SP 800-52r2 the NIST curves, ffdhe groups and MODP groups of 2048 bits or more, BSI TR-02102-2 the NIST and brainpool curves, ffdhe3072 and ffdhe4096, PCI DSS any group or DHE prime of at least 112-bit security, CNSA 2.0 only MLKEM1024.",
        "Mozilla Server Side TLS 6.0; NIST SP 800-52r2 §3.4.2.2; BSI TR-02102-2 tables 6 and 10; PCI DSS v4.0.1 glossary 'Strong Cryptography', NIST SP 800-57 part 1 table 2; draft-becker-cnsa2-tls-profile §7.2",
    ),
    entry(
        "policy.hsts",
        "HSTS missing or shorter than the policy requires",
        "Mozilla asks for Strict-Transport-Security with a max-age of at least two years (63072000 seconds).",
        "Mozilla Server Side TLS 6.0; RFC 6797",
    ),
    entry(
        "policy.incomplete",
        "Policy could not be fully checked",
        "Parts of the scan the policy depends on were skipped or failed, so compliance is unknown for them. Rerun without --profile quick or fix the reported errors.",
        "testls",
    ),
    entry(
        "policy.protocol",
        "Protocol version outside the policy or missing",
        "The server offers a protocol version the chosen policy does not allow; Mozilla modern and CNSA 2.0 allow only TLSv1.3, Mozilla intermediate, NIST SP 800-52r2, BSI TR-02102-2 and PCI DSS TLSv1.2 and TLSv1.3. NIST SP 800-52r2 also requires both TLSv1.2 and TLSv1.3 to be offered, CNSA 2.0 requires TLSv1.3.",
        "Mozilla Server Side TLS 6.0; NIST SP 800-52r2 §3.1; BSI TR-02102-2 §3.2; PCI DSS v4.0.1 req. 4.2.1; draft-becker-cnsa2-tls-profile §6",
    ),
];

/// All finding explanations, grouped by area.
#[must_use]
pub fn explanations() -> &'static [Explanation] {
    EXPLANATIONS
}

/// Explanation for finding `id`, if it is known.
#[must_use]
pub fn explain(id: &str) -> Option<&'static Explanation> {
    EXPLANATIONS.iter().find(|e| e.id == id)
}

#[cfg(test)]
mod tests {
    //! Keeps the catalogue in sync with the ids the checks emit.

    use std::collections::BTreeSet;

    use testls_wire::ProtocolVersion;

    use super::*;

    /// Area prefixes that finding ids start with.
    const AREAS: [&str; 15] = [
        "cert",
        "cipher",
        "cookie",
        "dh",
        "group",
        "handshake",
        "header",
        "hsts",
        "http",
        "intolerance",
        "ocsp",
        "policy",
        "protocol",
        "revocation",
        "vuln",
    ];

    /// Ids emitted by the CLI itself for scan errors.
    const CLI_IDS: [&str; 8] = [
        "cipher.error",
        "group.error",
        "cert.error",
        "cert.signature_unverified",
        "revocation.error",
        "http.error",
        "intolerance.error",
        "handshake.error",
    ];

    /// Whether a string literal looks like a finding id.
    fn is_id(literal: &str) -> bool {
        if literal == "hsts" {
            return true;
        }
        literal.split_once('.').is_some_and(|(area, rest)| {
            AREAS.contains(&area)
                && !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
    }

    /// Ids that appear as string literals in the check sources, plus the
    /// ones built at run time (cipher rule keys, protocol versions, stale
    /// revocation data) and by the CLI.
    fn emitted_ids() -> BTreeSet<String> {
        let sources = [
            include_str!("baseline.rs"),
            include_str!("certificates.rs"),
            include_str!("ciphers.rs"),
            include_str!("details.rs"),
            include_str!("http.rs"),
            include_str!("http_extras.rs"),
            include_str!("intolerance.rs"),
            include_str!("key_exchange.rs"),
            include_str!("ocsp.rs"),
            include_str!("policy.rs"),
            include_str!("post_quantum.rs"),
            include_str!("protocols.rs"),
            include_str!("revocation.rs"),
            include_str!("trust.rs"),
            include_str!("vulnerabilities.rs"),
        ];
        let mut ids: BTreeSet<String> = sources
            .iter()
            .flat_map(|s| s.lines())
            .flat_map(|line| line.split('"').skip(1).step_by(2))
            .filter(|l| is_id(l))
            .map(str::to_owned)
            .collect();
        ids.extend(crate::ciphers::rule_keys().map(|k| format!("cipher.{k}")));
        ids.extend(["cipher.ssl2", "cipher.unknown"].map(str::to_owned));
        ids.extend(ProtocolVersion::ALL.map(crate::protocols::id));
        for prefix in ["ocsp", "revocation"] {
            ids.insert(format!("{prefix}.not_yet_valid"));
            ids.insert(format!("{prefix}.expired"));
        }
        ids.extend(CLI_IDS.map(str::to_owned));
        ids
    }

    /// Every emitted id is explained and every explanation is emitted.
    #[test]
    fn catalogue_matches_checks() {
        let catalogue: BTreeSet<String> = EXPLANATIONS.iter().map(|e| e.id.to_owned()).collect();
        assert_eq!(catalogue, emitted_ids());
        assert_eq!(catalogue.len(), EXPLANATIONS.len(), "duplicate ids");
    }

    /// Entries are complete single paragraphs.
    #[test]
    fn entries_are_filled_in() {
        for e in explanations() {
            assert!(is_id(e.id), "{}", e.id);
            for text in [e.title, e.rationale, e.reference] {
                assert!(!text.is_empty() && !text.contains('\n'), "{}", e.id);
            }
            assert!(!e.title.ends_with('.'), "{}", e.id);
            assert!(e.rationale.ends_with('.'), "{}", e.id);
        }
    }

    /// Lookup by id.
    #[test]
    fn lookup() {
        assert_eq!(
            explain("hsts.missing").map(|e| e.reference),
            Some("RFC 6797")
        );
        assert!(explain("hsts.nope").is_none());
    }
}
