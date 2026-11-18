//! Compliance policies: findings for everything a server offers or presents
//! that a published configuration profile does not allow.
//!
//! The Mozilla profiles follow the Mozilla Server Side TLS guidelines,
//! version 6.0 (<https://ssl-config.mozilla.org/guidelines/6.0.json>).
//! The NIST profile follows NIST SP 800-52 revision 2
//! (<https://doi.org/10.6028/NIST.SP.800-52r2>). The BSI profile follows
//! BSI TR-02102-2, version 2025-01. The CNSA 2.0 profile
//! follows the NSA CNSA 2.0 TLS 1.3 profile,
//! draft-becker-cnsa2-tls-profile-05. The PCI DSS profile reads
//! requirement 4.2.1 of PCI DSS v4.0.1 and its glossary entry "Strong
//! Cryptography" (at least 112 bits of effective key strength).
//! Suite and group code points are from the IANA TLS parameter registries.

use std::fmt;

use testls_probe::{
    CipherResult, HttpResponse, KeyExchangeResult, ProtocolResult, ProtocolSupport,
};
use testls_wire::ProtocolVersion;
use x509_parser::asn1_rs::Oid;
use x509_parser::certificate::X509Certificate;
use x509_parser::parse_x509_certificate;
use x509_parser::public_key::PublicKey;
use x509_parser::signature_algorithm::SignatureAlgorithm;

use crate::{Finding, Severity, cipher_name, cipher_severity, group_name, parse_hsts};

/// Seconds in a day.
const DAY: i64 = 24 * 60 * 60;

/// Severity of every policy deviation: the configuration may be safe, but
/// it is not what the chosen policy requires.
const DEVIATION: Severity = Severity::Medium;

/// A configuration profile the server can be checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Mozilla "modern": TLSv1.3 only, ECDSA certificates.
    MozillaModern,
    /// Mozilla "intermediate": TLSv1.2 and TLSv1.3, AEAD suites with ECDHE.
    MozillaIntermediate,
    /// NIST SP 800-52r2 for servers used by government clients: TLSv1.2
    /// and TLSv1.3, NIST-approved suites, groups and certificates.
    Nist80052r2,
    /// BSI TR-02102-2: TLSv1.2 and TLSv1.3 with forward secrecy, RSA keys
    /// of at least 3000 bits, brainpool or NIST curves.
    BsiTr021022,
    /// PCI DSS v4.0.1: TLSv1.2 and TLSv1.3 with strong cryptography (at
    /// least 112-bit security), no RC4, DES, 3DES or other broken suites.
    PciDss4,
    /// NSA CNSA 2.0: TLSv1.3 with `TLS_AES_256_GCM_SHA384`, ML-KEM-1024 and
    /// ML-DSA-87 only.
    Cnsa2,
}

impl Policy {
    /// All policies, in the order they are listed on the command line.
    pub const ALL: [Self; 6] = [
        Self::MozillaModern,
        Self::MozillaIntermediate,
        Self::Nist80052r2,
        Self::BsiTr021022,
        Self::PciDss4,
        Self::Cnsa2,
    ];

    /// Name used on the command line and in finding messages.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MozillaModern => "mozilla-modern",
            Self::MozillaIntermediate => "mozilla-intermediate",
            Self::Nist80052r2 => "nist-800-52r2",
            Self::BsiTr021022 => "bsi-tr-02102-2",
            Self::PciDss4 => "pci-dss-4",
            Self::Cnsa2 => "cnsa-2.0",
        }
    }

    /// What the policy allows.
    fn rules(self) -> &'static Rules {
        match self {
            Self::MozillaModern => &MOZILLA_MODERN,
            Self::MozillaIntermediate => &MOZILLA_INTERMEDIATE,
            Self::Nist80052r2 => &NIST_800_52R2,
            Self::BsiTr021022 => &BSI_TR_02102_2,
            Self::PciDss4 => &PCI_DSS_4,
            Self::Cnsa2 => &CNSA_2,
        }
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Policy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|p| p.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| format!("unknown policy {s:?}"))
    }
}

/// What one policy allows.
#[derive(Debug)]
struct Rules {
    /// Protocol versions.
    versions: &'static [ProtocolVersion],
    /// Protocol versions the server must offer.
    required: &'static [ProtocolVersion],
    /// TLSv1.3 cipher suites.
    tls13_suites: &'static [u16],
    /// Cipher suites for TLSv1.2 and earlier.
    suites: &'static [u16],
    /// Whether every other TLSv1.2 suite of at least 112-bit strength is
    /// allowed too (see [`strong_suite`]).
    strong_suites: bool,
    /// Named groups for TLSv1.3 key exchange.
    tls13_groups: &'static [u16],
    /// Named groups for (EC)DHE key exchange in TLSv1.2 and earlier.
    groups: &'static [u16],
    /// Other TLSv1.2 DHE primes, by `testls_data::KnownPrime` name.
    dh_primes: &'static [&'static str],
    /// Size in bits from which any other TLSv1.2 DHE prime, known or
    /// custom, is allowed.
    dh_min_bits: Option<usize>,
    /// Minimum RSA key size in bits, or `None` if RSA keys are not allowed.
    rsa_bits: Option<usize>,
    /// Named curves (OIDs) for ECDSA keys.
    curves: &'static [(&'static str, &'static str)],
    /// Other leaf key algorithms (OIDs).
    keys: &'static [(&'static str, &'static str)],
    /// Leaf signature algorithms (OIDs).
    signatures: &'static [(&'static str, &'static str)],
    /// Longest allowed leaf validity period in days, if limited.
    lifespan_days: Option<i64>,
    /// Minimum HSTS `max-age` in seconds, if HSTS is required.
    hsts_max_age: Option<u64>,
}

/// TLSv1.3 suites of both Mozilla profiles: `TLS_AES_128_GCM_SHA256`,
/// `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`.
const MOZILLA_TLS13_SUITES: &[u16] = &[0x1301, 0x1302, 0x1303];

/// Groups of both Mozilla profiles: `X25519MLKEM768`, `x25519`,
/// `secp256r1`, `secp384r1`.
const MOZILLA_GROUPS: &[u16] = &[0x11ec, 0x001d, 0x0017, 0x0018];

/// ECDSA curves of both Mozilla profiles: P-256 (RFC 5480 §2.1.1.1) and
/// P-384.
const MOZILLA_CURVES: &[(&str, &str)] =
    &[("1.2.840.10045.3.1.7", "P-256"), ("1.3.132.0.34", "P-384")];

/// ECDSA signature algorithms (RFC 5758 §3.2).
const ECDSA_SIGNATURES: &[(&str, &str)] = &[
    ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
    ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
    ("1.2.840.10045.4.3.4", "ecdsa-with-SHA512"),
];

/// ECDSA plus `sha256WithRSAEncryption` (RFC 8017 appendix C).
const INTERMEDIATE_SIGNATURES: &[(&str, &str)] = &[
    ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
    ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
    ("1.2.840.10045.4.3.4", "ecdsa-with-SHA512"),
    ("1.2.840.113549.1.1.11", "sha256WithRSAEncryption"),
];

/// HSTS `max-age` both Mozilla profiles ask for: two years.
const MOZILLA_HSTS_MAX_AGE: u64 = 63_072_000;

/// Mozilla "modern".
static MOZILLA_MODERN: Rules = Rules {
    versions: &[ProtocolVersion::TLS13],
    required: &[],
    tls13_suites: MOZILLA_TLS13_SUITES,
    suites: &[],
    strong_suites: false,
    tls13_groups: MOZILLA_GROUPS,
    groups: MOZILLA_GROUPS,
    dh_primes: &[],
    dh_min_bits: None,
    rsa_bits: None,
    curves: MOZILLA_CURVES,
    keys: &[],
    signatures: ECDSA_SIGNATURES,
    lifespan_days: Some(90),
    hsts_max_age: Some(MOZILLA_HSTS_MAX_AGE),
};

/// Mozilla "intermediate". The TLSv1.2 suites are the ECDHE AEAD suites
/// `0xc02b`, `0xc02f`, `0xc02c`, `0xc030`, `0xcca9` and `0xcca8`.
static MOZILLA_INTERMEDIATE: Rules = Rules {
    versions: &[ProtocolVersion::TLS12, ProtocolVersion::TLS13],
    required: &[],
    tls13_suites: MOZILLA_TLS13_SUITES,
    suites: &[0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8],
    strong_suites: false,
    tls13_groups: MOZILLA_GROUPS,
    groups: MOZILLA_GROUPS,
    dh_primes: &[],
    dh_min_bits: None,
    rsa_bits: Some(2048),
    curves: MOZILLA_CURVES,
    keys: &[],
    signatures: INTERMEDIATE_SIGNATURES,
    lifespan_days: Some(366),
    hsts_max_age: Some(MOZILLA_HSTS_MAX_AGE),
};

/// TLSv1.3 suites of NIST SP 800-52r2 §3.3.1.2: `TLS_AES_128_GCM_SHA256`,
/// `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_CCM_SHA256`,
/// `TLS_AES_128_CCM_8_SHA256`.
const NIST_TLS13_SUITES: &[u16] = &[0x1301, 0x1302, 0x1304, 0x1305];

/// TLSv1.2 suites of NIST SP 800-52r2 §3.3.1.1, for ECDSA, RSA, DSA, DH and
/// ECDH certificates in the document's order. RSA key transport suites
/// (appendix D, transition only) and PSK suites (appendix C) are excluded.
const NIST_SUITES: &[u16] = &[
    // ECDHE-ECDSA.
    0xc02b, 0xc02c, 0xc0ac, 0xc0ad, 0xc0ae, 0xc0af, 0xc023, 0xc024, 0xc009, 0xc00a,
    // ECDHE-RSA.
    0xc02f, 0xc030, 0xc027, 0xc028, 0xc013, 0xc014, // DHE-RSA.
    0x009e, 0x009f, 0xc09e, 0xc09f, 0xc0a2, 0xc0a3, 0x0067, 0x006b, 0x0033, 0x0039,
    // DHE-DSS.
    0x00a2, 0x00a3, 0x0040, 0x006a, 0x0032, 0x0038, // DH-DSS.
    0x00a4, 0x00a5, 0x003e, 0x0068, 0x0030, 0x0036, // DH-RSA.
    0x00a0, 0x00a1, 0x003f, 0x0069, 0x0031, 0x0037, // ECDH-ECDSA.
    0xc02d, 0xc02e, 0xc025, 0xc026, 0xc004, 0xc005, // ECDH-RSA.
    0xc031, 0xc032, 0xc029, 0xc02a, 0xc00e, 0xc00f,
];

/// Groups of NIST SP 800-52r2 §3.4.2.2, which points to the SP 800-56A
/// appendix D groups: `secp256r1`, `secp384r1`, `secp521r1` and
/// `ffdhe2048` to `ffdhe8192`.
const NIST_GROUPS: &[u16] = &[
    0x0017, 0x0018, 0x0019, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104,
];

/// The RFC 3526 MODP groups that SP 800-56A rev. 3 appendix D also
/// approves for DHE (`MODP-2048` to `MODP-8192`).
const NIST_DH_PRIMES: &[&str] = &[
    "MODP group 14",
    "MODP group 15",
    "MODP group 16",
    "MODP group 17",
    "MODP group 18",
];

/// Leaf signature algorithms of NIST SP 800-52r2 §3.2.1 and SP 800-57
/// part 1 (at least 112-bit security, SHA-2): RSA PKCS #1 v1.5 and PSS
/// (RFC 8017 appendix C) and ECDSA.
const NIST_SIGNATURES: &[(&str, &str)] = &[
    ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
    ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
    ("1.2.840.10045.4.3.4", "ecdsa-with-SHA512"),
    ("1.2.840.113549.1.1.11", "sha256WithRSAEncryption"),
    ("1.2.840.113549.1.1.12", "sha384WithRSAEncryption"),
    ("1.2.840.113549.1.1.13", "sha512WithRSAEncryption"),
    ("1.2.840.113549.1.1.10", "RSASSA-PSS"),
];

/// NIST SP 800-52r2 for government-only servers: TLSv1.2 and TLSv1.3,
/// both required (§3.1; TLSv1.3 since 1 January 2024), RSA keys of at least 2048 bits and ECDSA on P-256 or P-384
/// (§3.2.1). DSA leaf keys are reported because FIPS 186-5 withdrew DSA
/// signature generation. No HSTS or lifetime limits.
static NIST_800_52R2: Rules = Rules {
    versions: &[ProtocolVersion::TLS12, ProtocolVersion::TLS13],
    required: &[ProtocolVersion::TLS12, ProtocolVersion::TLS13],
    tls13_suites: NIST_TLS13_SUITES,
    suites: NIST_SUITES,
    strong_suites: false,
    tls13_groups: NIST_GROUPS,
    groups: NIST_GROUPS,
    dh_primes: NIST_DH_PRIMES,
    dh_min_bits: None,
    rsa_bits: Some(2048),
    curves: MOZILLA_CURVES,
    keys: &[],
    signatures: NIST_SIGNATURES,
    lifespan_days: None,
    hsts_max_age: None,
};

/// TLSv1.2 suites of BSI TR-02102-2 table 3 (ECDHE and DHE with AES in
/// CBC, GCM or CCM mode). The non-forward-secret suites of table 4 (only
/// "if forward secrecy is not possible", until 2026) and the PSK suites of
/// table 5 are excluded.
const BSI_SUITES: &[u16] = &[
    // ECDHE-ECDSA.
    0xc023, 0xc024, 0xc02b, 0xc02c, 0xc0ac, 0xc0ad, // ECDHE-RSA.
    0xc027, 0xc028, 0xc02f, 0xc030, // DHE-DSS.
    0x0040, 0x006a, 0x00a2, 0x00a3, // DHE-RSA.
    0x0067, 0x006b, 0x009e, 0x009f, 0xc09e, 0xc09f,
];

/// TLSv1.2 groups of BSI TR-02102-2 table 6: `secp256r1`, `secp384r1`,
/// `secp521r1`, the brainpool curves `26`-`28` (RFC 7027), `ffdhe3072` and
/// `ffdhe4096`.
const BSI_TLS12_GROUPS: &[u16] = &[
    0x0017, 0x0018, 0x0019, 0x001a, 0x001b, 0x001c, 0x0101, 0x0102,
];

/// TLSv1.3 groups of BSI TR-02102-2 table 10: as table 6, but with the
/// brainpool code points `31`-`33` that RFC 8734 assigns for TLSv1.3.
const BSI_TLS13_GROUPS: &[u16] = &[
    0x0017, 0x0018, 0x0019, 0x001f, 0x0020, 0x0021, 0x0101, 0x0102,
];

/// ECDSA curves of BSI TR-02102-2 §3.6.2: brainpoolP256r1, brainpoolP384r1,
/// brainpoolP512r1 (RFC 5639 §4.1) and P-256, P-384, P-521 (RFC 5480
/// §2.1.1.1).
const BSI_CURVES: &[(&str, &str)] = &[
    ("1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1"),
    ("1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1"),
    ("1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1"),
    ("1.2.840.10045.3.1.7", "P-256"),
    ("1.3.132.0.34", "P-384"),
    ("1.3.132.0.35", "P-521"),
];

/// Leaf signature algorithms of BSI TR-02102-2 table 12: RSASSA-PSS and
/// ECDSA with SHA-2. The `rsa_pkcs1_*` schemes were recommended only up to
/// 2025.
const BSI_SIGNATURES: &[(&str, &str)] = &[
    ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
    ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
    ("1.2.840.10045.4.3.4", "ecdsa-with-SHA512"),
    ("1.2.840.113549.1.1.10", "RSASSA-PSS"),
];

/// BSI TR-02102-2 (version 2025-01): TLSv1.2 and TLSv1.3 (§3.2), the
/// TLSv1.3 suites `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384` and
/// `TLS_AES_128_CCM_SHA256` (table 13), RSA keys of at least 3000 bits
/// (table 14) and ECDSA on the §3.6.2 curves. No HSTS or lifetime limits.
static BSI_TR_02102_2: Rules = Rules {
    versions: &[ProtocolVersion::TLS12, ProtocolVersion::TLS13],
    required: &[],
    tls13_suites: &[0x1301, 0x1302, 0x1304],
    suites: BSI_SUITES,
    strong_suites: false,
    tls13_groups: BSI_TLS13_GROUPS,
    groups: BSI_TLS12_GROUPS,
    dh_primes: &[],
    dh_min_bits: None,
    rsa_bits: Some(3000),
    curves: BSI_CURVES,
    keys: &[],
    signatures: BSI_SIGNATURES,
    lifespan_days: None,
    hsts_max_age: None,
};

/// All TLSv1.3 suites of RFC 8446 appendix B.4: AES-GCM, ChaCha20-Poly1305
/// and AES-CCM all have 128-bit or larger keys.
const TLS13_SUITES: &[u16] = &[0x1301, 0x1302, 0x1303, 0x1304, 0x1305];

/// Groups of at least 112-bit security (NIST SP 800-57 part 1 table 2):
/// `secp224r1`, `secp256r1`, `secp384r1`, `secp521r1`, `x25519`, `x448`, the brainpool
/// curves for TLSv1.2 (RFC 7027) and TLSv1.3 (RFC 8734), `ffdhe2048` to
/// `ffdhe8192` (RFC 7919), ML-KEM (draft-ietf-tls-mlkem) and the hybrid
/// ML-KEM groups (draft-ietf-tls-ecdhe-mlkem).
const PCI_GROUPS: &[u16] = &[
    0x0015, 0x0017, 0x0018, 0x0019, 0x001d, 0x001e, 0x001a, 0x001b, 0x001c, 0x001f, 0x0020, 0x0021,
    0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0200, 0x0201, 0x0202, 0x11eb, 0x11ec, 0x11ed,
];

/// ECDSA curves of at least 112-bit security (NIST SP 800-57 part 1 table 2):
/// P-224 (RFC 5480 §2.1.1.1) plus the BSI list.
const PCI_CURVES: &[(&str, &str)] = &[
    ("1.3.132.0.33", "P-224"),
    ("1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1"),
    ("1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1"),
    ("1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1"),
    ("1.2.840.10045.3.1.7", "P-256"),
    ("1.3.132.0.34", "P-384"),
    ("1.3.132.0.35", "P-521"),
];

/// `EdDSA` key and signature algorithms (RFC 8410 §3): Ed25519 and Ed448.
const EDDSA: &[(&str, &str)] = &[("1.3.101.112", "Ed25519"), ("1.3.101.113", "Ed448")];

/// Leaf signature algorithms of at least 112-bit security: the NIST list
/// (SHA-2 with RSA or ECDSA) plus `EdDSA`.
const PCI_SIGNATURES: &[(&str, &str)] = &[
    ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
    ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
    ("1.2.840.10045.4.3.4", "ecdsa-with-SHA512"),
    ("1.2.840.113549.1.1.11", "sha256WithRSAEncryption"),
    ("1.2.840.113549.1.1.12", "sha384WithRSAEncryption"),
    ("1.2.840.113549.1.1.13", "sha512WithRSAEncryption"),
    ("1.2.840.113549.1.1.10", "RSASSA-PSS"),
    ("1.3.101.112", "Ed25519"),
    ("1.3.101.113", "Ed448"),
];

/// PCI DSS v4.0.1 requirement 4.2.1: no SSL or early TLS, so TLSv1.2 and
/// TLSv1.3, and "strong cryptography" (glossary: at least 112 bits of
/// effective key strength, pointing to NIST SP 800-57 part 1). PCI DSS names
/// no suite list, so every TLSv1.2 suite without a broken or 64-bit block
/// cipher passes, including CBC and non-forward-secret suites; groups, DHE
/// primes and keys need 112-bit security (RSA and DHE 2048 bits, ECC
/// 224 bits). DSA keys are reported because FIPS 186-5 withdrew DSA
/// signature generation. No HSTS or lifetime limits.
static PCI_DSS_4: Rules = Rules {
    versions: &[ProtocolVersion::TLS12, ProtocolVersion::TLS13],
    required: &[],
    tls13_suites: TLS13_SUITES,
    suites: &[],
    strong_suites: true,
    tls13_groups: PCI_GROUPS,
    groups: PCI_GROUPS,
    dh_primes: &[],
    dh_min_bits: Some(2048),
    rsa_bits: Some(2048),
    curves: PCI_CURVES,
    keys: EDDSA,
    signatures: PCI_SIGNATURES,
    lifespan_days: None,
    hsts_max_age: None,
};

/// ML-DSA-87 (FIPS 204), the only CNSA 2.0 signature algorithm, as both
/// key and signature algorithm (NIST CSOR OID, RFC 9881).
const ML_DSA_87: &[(&str, &str)] = &[("2.16.840.1.101.3.4.3.19", "ML-DSA-87")];

/// CNSA 2.0 (draft-becker-cnsa2-tls-profile-05): TLSv1.3 only and required
/// (§6), `TLS_AES_256_GCM_SHA384` (§4), the `MLKEM1024` group (§7.2) and
/// ML-DSA-87 certificates (§8). No HSTS or lifetime limits.
static CNSA_2: Rules = Rules {
    versions: &[ProtocolVersion::TLS13],
    required: &[ProtocolVersion::TLS13],
    tls13_suites: &[0x1302],
    suites: &[],
    strong_suites: false,
    tls13_groups: &[0x0202],
    groups: &[],
    dh_primes: &[],
    dh_min_bits: None,
    rsa_bits: None,
    curves: &[],
    keys: ML_DSA_87,
    signatures: ML_DSA_87,
    lifespan_days: None,
    hsts_max_age: None,
};

/// Scan results a policy is checked against. `None` means the part was not
/// measured (skipped by the scan profile or failed); it is then reported in
/// a `policy.incomplete` finding instead of being assumed compliant.
#[derive(Debug, Clone, Copy)]
pub struct PolicyInput<'a> {
    /// Protocol detection results.
    pub protocols: &'a [ProtocolResult],
    /// Accepted cipher suites per protocol version.
    pub ciphers: Option<&'a [CipherResult]>,
    /// Versions whose cipher suite enumeration failed. Only versions the
    /// policy allows make the check incomplete.
    pub cipher_errors: &'a [ProtocolVersion],
    /// Key exchange groups per protocol version.
    pub key_exchange: Option<&'a [KeyExchangeResult]>,
    /// Versions whose key exchange probe failed, like `cipher_errors`.
    pub key_exchange_errors: &'a [ProtocolVersion],
    /// DER certificate chain, leaf first.
    pub chain: Option<&'a [Vec<u8>]>,
    /// Reply to `GET /`.
    pub http: Option<&'a HttpResponse>,
}

/// Findings for everything in `input` that `policy` does not allow.
#[must_use]
pub fn policy_findings(policy: Policy, input: &PolicyInput<'_>) -> Vec<Finding> {
    let rules = policy.rules();
    let mut findings = Vec::new();
    let mut untested = Vec::new();

    let mut protocols_untested = false;
    for r in input.protocols {
        let allowed = rules.versions.contains(&r.version);
        let required = rules.required.contains(&r.version);
        match r.support {
            ProtocolSupport::Supported if !allowed => findings.push(deviation(
                "policy.protocol",
                policy,
                &format!("{} is offered", r.version),
            )),
            ProtocolSupport::NotSupported if required => findings.push(Finding::new(
                "policy.protocol",
                DEVIATION,
                format!("{} is not offered, but {policy} requires it", r.version),
            )),
            ProtocolSupport::Error(_) if !allowed || required => protocols_untested = true,
            _ => {}
        }
    }
    if protocols_untested {
        untested.push("protocol versions");
    }
    let failed = |errors: &[ProtocolVersion]| errors.iter().any(|v| rules.versions.contains(v));
    match input.ciphers {
        Some(ciphers) => {
            findings.extend(cipher_deviations(policy, ciphers));
            if failed(input.cipher_errors) {
                untested.push("cipher suites");
            }
        }
        None => untested.push("cipher suites"),
    }
    match input.key_exchange {
        Some(results) => {
            findings.extend(group_deviations(policy, results));
            if failed(input.key_exchange_errors)
                || results.iter().any(|r| {
                    rules.versions.contains(&r.version)
                        && r.dh_suites.iter().any(|d| d.bits.is_none())
                })
            {
                untested.push("key exchange groups");
            }
        }
        None => untested.push("key exchange groups"),
    }
    match input.chain.and_then(<[_]>::first) {
        Some(leaf) => findings.extend(certificate_deviations(policy, leaf)),
        None => untested.push("certificate"),
    }
    if let Some(min_age) = rules.hsts_max_age {
        match input.http {
            Some(response) => findings.extend(hsts_deviation(policy, response, min_age)),
            None => untested.push("HSTS"),
        }
    }
    if !untested.is_empty() {
        findings.push(Finding::new(
            "policy.incomplete",
            Severity::Info,
            format!(
                "{policy} could not be fully checked: {} not measured",
                untested.join(", ")
            ),
        ));
    }
    findings
}

/// A finding for something `policy` does not allow.
fn deviation(id: &str, policy: Policy, what: &str) -> Finding {
    Finding::new(
        id,
        DEVIATION,
        format!("{what}, which {policy} does not allow"),
    )
}

/// Accepted suites outside the policy, for the versions it allows (other
/// versions are already reported as `policy.protocol`).
fn cipher_deviations(policy: Policy, ciphers: &[CipherResult]) -> Vec<Finding> {
    let rules = policy.rules();
    let mut findings = Vec::new();
    for result in ciphers
        .iter()
        .filter(|r| rules.versions.contains(&r.version))
    {
        let tls13 = result.version == ProtocolVersion::TLS13;
        let allowed = if tls13 {
            rules.tls13_suites
        } else {
            rules.suites
        };
        for &suite in &result.suites {
            let listed = u16::try_from(suite).is_ok_and(|s| allowed.contains(&s));
            let strong = rules.strong_suites && !tls13 && strong_suite(result.version, suite);
            if !(listed || strong) {
                findings.push(deviation(
                    "policy.cipher",
                    policy,
                    &format!(
                        "{} accepts {}",
                        result.version,
                        cipher_name(result.version, suite)
                    ),
                ));
            }
        }
    }
    findings
}

/// Accepted groups and TLSv1.2 DHE primes outside the policy, each
/// reported once.
fn group_deviations(policy: Policy, results: &[KeyExchangeResult]) -> Vec<Finding> {
    let rules = policy.rules();
    let mut seen = Vec::new();
    for result in results
        .iter()
        .filter(|r| rules.versions.contains(&r.version))
    {
        let allowed = if result.version == ProtocolVersion::TLS13 {
            rules.tls13_groups
        } else {
            rules.groups
        };
        for &group in &result.groups {
            let what = format!(
                "key exchange group {} (0x{group:04x}) is accepted",
                group_name(group)
            );
            if !allowed.contains(&group) && !seen.contains(&what) {
                seen.push(what);
            }
        }
        let primes: Vec<_> = if result.dh_suites.is_empty() {
            result.dh_prime.iter().collect()
        } else {
            result
                .dh_suites
                .iter()
                .filter_map(|d| d.prime.as_ref())
                .collect()
        };
        for prime in primes {
            if let Some(what) = prime_deviation(prime, allowed, rules)
                && !seen.contains(&what)
            {
                seen.push(what);
            }
        }
    }
    seen.iter()
        .map(|what| deviation("policy.group", policy, what))
        .collect()
}

/// What to report about TLSv1.2 DHE prime `prime`, unless it is an allowed
/// RFC 7919 group, one of the `dh_primes` the policy allows by name, or at
/// least `dh_min_bits` long. Otherwise unknown primes are never allowed.
fn prime_deviation(prime: &[u8], allowed: &[u16], rules: &Rules) -> Option<String> {
    let known = testls_data::known_dh_prime(prime);
    if let Some(group) = known.and_then(|k| ffdhe_group(k.name)) {
        return (!allowed.contains(&group)).then(|| {
            format!(
                "key exchange group {} (0x{group:04x}) is accepted",
                group_name(group)
            )
        });
    }
    let digits: Vec<_> = prime.iter().skip_while(|&&b| b == 0).collect();
    let bits = digits
        .first()
        .map_or(0, |b| digits.len() * 8 - b.leading_zeros() as usize);
    if rules.dh_min_bits.is_some_and(|min| bits >= min) {
        return None;
    }
    match known {
        Some(k) if rules.dh_primes.contains(&k.name) => None,
        Some(k) => Some(format!("DHE uses {}", k.name)),
        None => Some(format!("DHE uses a custom {bits}-bit prime")),
    }
}

/// Whether TLSv1.2 suite `id` reaches 112-bit strength: no rating of
/// medium or worse in [`cipher_severity`] (null, anonymous, export, RC4,
/// DES, RC2, MD5, 3DES), no other 64-bit block cipher (IDEA, GOST 28147
/// and Magma, Sweet32) and a name the IANA registry knows.
fn strong_suite(version: ProtocolVersion, id: u32) -> bool {
    let (severity, key, _) = cipher_severity(version, id);
    let name = cipher_name(version, id);
    severity < Severity::Medium
        && key != "unknown"
        && !["_IDEA_", "_28147_", "_MAGMA_"]
            .iter()
            .any(|block64| name.contains(block64))
}

/// The `supported_groups` code point (RFC 7919 §8) of RFC 7919 appendix A
/// group `name`.
fn ffdhe_group(name: &str) -> Option<u16> {
    match name {
        "ffdhe2048" => Some(0x0100),
        "ffdhe3072" => Some(0x0101),
        "ffdhe4096" => Some(0x0102),
        "ffdhe6144" => Some(0x0103),
        "ffdhe8192" => Some(0x0104),
        _ => None,
    }
}

/// SHA-2 hashes allowed in RSASSA-PSS parameters (RFC 8017 appendix A.2.3,
/// NIST CSOR OIDs): SHA-256, SHA-384, SHA-512.
const PSS_HASHES: &[&str] = &[
    "2.16.840.1.101.3.4.2.1",
    "2.16.840.1.101.3.4.2.2",
    "2.16.840.1.101.3.4.2.3",
];

/// Whether an RSASSA-PSS signature uses a SHA-2 hash; true for other
/// algorithms.
fn pss_hash_allowed(cert: &X509Certificate<'_>) -> bool {
    match SignatureAlgorithm::try_from(&cert.signature_algorithm) {
        Ok(SignatureAlgorithm::RSASSA_PSS(params)) => {
            PSS_HASHES.contains(&params.hash_algorithm_oid().to_id_string().as_str())
        }
        Ok(_) => true,
        Err(_) => cert.signature_algorithm.algorithm.to_id_string() != "1.2.840.113549.1.1.10",
    }
}

/// Leaf key, signature and validity period outside the policy.
fn certificate_deviations(policy: Policy, leaf: &[u8]) -> Vec<Finding> {
    let rules = policy.rules();
    let Ok(([], cert)) = parse_x509_certificate(leaf) else {
        return vec![Finding::new(
            "policy.incomplete",
            Severity::Info,
            format!("{policy} could not be fully checked: leaf certificate cannot be parsed"),
        )];
    };
    let mut findings = Vec::new();
    if let Some(what) = key_deviation(rules, &cert) {
        findings.push(deviation("policy.cert_key", policy, &what));
    }
    let signature = cert.signature_algorithm.algorithm.to_id_string();
    if !rules.signatures.iter().any(|(oid, _)| *oid == signature) || !pss_hash_allowed(&cert) {
        findings.push(deviation(
            "policy.cert_signature",
            policy,
            &format!(
                "leaf certificate is signed with {}{}",
                label(&signature, PCI_SIGNATURES.iter().chain(ML_DSA_87)),
                if pss_hash_allowed(&cert) {
                    ""
                } else {
                    " using a non-SHA-2 hash"
                }
            ),
        ));
    }
    let validity = cert.validity();
    let days = (validity.not_after.timestamp() - validity.not_before.timestamp()) / DAY;
    if let Some(max) = rules.lifespan_days
        && days > max
    {
        findings.push(deviation(
            "policy.cert_lifespan",
            policy,
            &format!("leaf certificate is valid for {days} days, more than {max}"),
        ));
    }
    findings
}

/// Name of `oid` from `table`, or the dotted OID itself.
fn label<'a>(oid: &str, table: impl IntoIterator<Item = &'a (&'a str, &'static str)>) -> String {
    table
        .into_iter()
        .find(|(o, _)| *o == oid)
        .map_or_else(|| oid.to_owned(), |(_, name)| (*name).to_owned())
}

/// Why the leaf's public key is outside the policy, if it is.
fn key_deviation(rules: &Rules, cert: &X509Certificate<'_>) -> Option<String> {
    let spki = cert.public_key();
    let algorithm = spki.algorithm.algorithm.to_id_string();
    if rules.keys.iter().any(|(oid, _)| *oid == algorithm) {
        return None;
    }
    match spki.parsed() {
        Ok(PublicKey::RSA(key)) => {
            let bits = key.key_size();
            match rules.rsa_bits {
                None => Some(format!("leaf certificate has an RSA {bits}-bit key")),
                Some(min) if bits < min => Some(format!(
                    "leaf certificate has an RSA key of only {bits} bits"
                )),
                Some(_) => None,
            }
        }
        Ok(PublicKey::EC(_)) => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| Oid::try_from(p).ok())
                .map(|oid| oid.to_id_string());
            match curve {
                Some(c) if rules.curves.iter().any(|(oid, _)| *oid == c) => None,
                Some(c) => Some(format!(
                    "leaf certificate has an EC key on curve {}",
                    label(&c, PCI_CURVES)
                )),
                None => Some("leaf certificate has an EC key without a named curve".to_owned()),
            }
        }
        Ok(_) | Err(_) => Some(format!(
            "leaf certificate has a key of algorithm {}",
            label(&algorithm, ML_DSA_87.iter().chain(EDDSA))
        )),
    }
}

/// Missing, invalid or too short HSTS policy.
fn hsts_deviation(policy: Policy, response: &HttpResponse, min_age: u64) -> Option<Finding> {
    let what = match response.header("strict-transport-security").map(parse_hsts) {
        None => "no Strict-Transport-Security header is sent".to_owned(),
        Some(Err(e)) => format!("the Strict-Transport-Security header is invalid ({e})"),
        Some(Ok(hsts)) if hsts.max_age < min_age => format!(
            "HSTS max-age is {} seconds, less than {min_age}",
            hsts.max_age
        ),
        Some(Ok(_)) => return None,
    };
    Some(deviation("policy.hsts", policy, &what))
}

#[cfg(test)]
mod tests {
    use testls_probe::CipherOrder;

    use super::*;

    /// Self-signed P-256 leaf signed with ecdsa-with-SHA256, valid 365 days.
    const EC_LOCALHOST: &[u8] = include_bytes!("testdata/ec-localhost.der");
    /// Self-signed RSA-2048 leaf signed with sha256WithRSAEncryption, 365 days.
    const RSA2048: &[u8] = include_bytes!("testdata/rsa2048-no-san.der");
    /// Self-signed RSA-1024 leaf signed with SHA-1.
    const RSA1024_SHA1: &[u8] = include_bytes!("testdata/rsa1024-sha1-wildcard.der");
    /// RSA-PSS leaf signed with SHA-1.
    const RSA_PSS_SHA1: &[u8] = include_bytes!("testdata/rsa-pss-sha1.der");
    /// Self-signed ML-DSA-87 leaf, valid 90 days.
    const MLDSA87: &[u8] = include_bytes!("testdata/mldsa87-localhost.der");
    /// Self-signed Ed25519 leaf, valid 90 days.
    const ED25519: &[u8] = include_bytes!("testdata/ed25519-localhost.der");
    /// Self-signed localhost certificate with a P-224 key, signed with
    /// `ecdsa-with-SHA256`, valid for 90 days.
    const P224: &[u8] = include_bytes!("testdata/p224-localhost.der");

    /// Protocol results with `versions` supported.
    fn protocols(versions: &[ProtocolVersion]) -> Vec<ProtocolResult> {
        ProtocolVersion::ALL
            .iter()
            .map(|&version| ProtocolResult {
                version,
                support: if versions.contains(&version) {
                    ProtocolSupport::Supported
                } else {
                    ProtocolSupport::NotSupported
                },
            })
            .collect()
    }

    /// Cipher result accepting `suites` at `version`.
    fn ciphers(version: ProtocolVersion, suites: &[u32]) -> CipherResult {
        CipherResult {
            version,
            suites: suites.to_vec(),
            order: CipherOrder::Server,
        }
    }

    /// Key exchange result accepting `groups` at `version`.
    fn groups(version: ProtocolVersion, groups: &[u16]) -> KeyExchangeResult {
        KeyExchangeResult {
            version,
            groups: groups.to_vec(),
            group_order: CipherOrder::Server,
            dh_bits: None,
            dh_prime: None,
            dh_key_reused: None,
            dh_suites: Vec::new(),
        }
    }

    /// Decodes upper-case hex.
    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Reply carrying `hsts` as its HSTS header, if any.
    fn http(hsts: Option<&str>) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: hsts
                .map(|v| ("strict-transport-security".to_owned(), v.to_owned()))
                .into_iter()
                .collect(),
        }
    }

    /// Finding ids and messages.
    fn summary(findings: &[Finding]) -> Vec<(String, String)> {
        findings
            .iter()
            .map(|f| (f.id.clone(), f.message.clone()))
            .collect()
    }

    /// A server built to the intermediate profile has no deviations from it
    /// but several from modern.
    #[test]
    fn intermediate_server() {
        let protocols = protocols(&[ProtocolVersion::TLS12, ProtocolVersion::TLS13]);
        let ciphers = [
            ciphers(ProtocolVersion::TLS12, &[0xc02f, 0xc030]),
            ciphers(ProtocolVersion::TLS13, &[0x1301, 0x1302]),
        ];
        let key_exchange = [
            groups(ProtocolVersion::TLS12, &[0x001d, 0x0017]),
            groups(ProtocolVersion::TLS13, &[0x11ec, 0x001d]),
        ];
        let chain = [RSA2048.to_vec()];
        let response = http(Some("max-age=63072000"));
        let input = PolicyInput {
            protocols: &protocols,
            ciphers: Some(&ciphers),
            cipher_errors: &[],
            key_exchange: Some(&key_exchange),
            key_exchange_errors: &[],
            chain: Some(&chain),
            http: Some(&response),
        };
        assert_eq!(policy_findings(Policy::MozillaIntermediate, &input), []);

        let ids: Vec<_> = policy_findings(Policy::MozillaModern, &input)
            .into_iter()
            .map(|f| {
                assert_eq!(f.severity, Severity::Medium);
                f.id
            })
            .collect();
        assert_eq!(
            ids,
            [
                "policy.protocol",
                "policy.cert_key",
                "policy.cert_signature",
                "policy.cert_lifespan"
            ]
        );
    }

    /// Every kind of deviation, with its message.
    #[test]
    fn deviations() {
        let protocols = protocols(&[ProtocolVersion::TLS10, ProtocolVersion::TLS12]);
        let ciphers = [
            ciphers(ProtocolVersion::TLS10, &[0x002f]),
            ciphers(ProtocolVersion::TLS12, &[0xc02f, 0x009c]),
        ];
        let key_exchange = [groups(ProtocolVersion::TLS12, &[0x001d, 0x0019, 0x0019])];
        let chain = [RSA1024_SHA1.to_vec()];
        let response = http(Some("max-age=86400"));
        let input = PolicyInput {
            protocols: &protocols,
            ciphers: Some(&ciphers),
            cipher_errors: &[],
            key_exchange: Some(&key_exchange),
            key_exchange_errors: &[],
            chain: Some(&chain),
            http: Some(&response),
        };
        let tail = ", which mozilla-intermediate does not allow";
        let expected = [
            ("policy.protocol", "TLSv1.0 is offered"),
            (
                "policy.cipher",
                "TLSv1.2 accepts TLS_RSA_WITH_AES_128_GCM_SHA256",
            ),
            (
                "policy.group",
                "key exchange group secp521r1 (0x0019) is accepted",
            ),
            (
                "policy.cert_key",
                "leaf certificate has an RSA key of only 1024 bits",
            ),
            (
                "policy.cert_signature",
                "leaf certificate is signed with 1.2.840.113549.1.1.5",
            ),
            (
                "policy.hsts",
                "HSTS max-age is 86400 seconds, less than 63072000",
            ),
        ]
        .map(|(id, what)| (id.to_owned(), format!("{what}{tail}")));
        assert_eq!(
            summary(&policy_findings(Policy::MozillaIntermediate, &input)),
            expected
        );
    }

    /// Unmeasured parts are reported once, not assumed compliant.
    #[test]
    fn incomplete() {
        let protocols = protocols(&[ProtocolVersion::TLS13]);
        let input = PolicyInput {
            protocols: &protocols,
            ciphers: None,
            cipher_errors: &[],
            key_exchange: None,
            key_exchange_errors: &[],
            chain: None,
            http: None,
        };
        let findings = policy_findings(Policy::MozillaModern, &input);
        assert_eq!(
            summary(&findings),
            [(
                "policy.incomplete".to_owned(),
                "mozilla-modern could not be fully checked: cipher suites, key exchange \
                 groups, certificate, HSTS not measured"
                    .to_owned()
            )]
        );
        assert_eq!(findings[0].severity, Severity::Info);

        let chain = [b"junk".to_vec()];
        let input = PolicyInput {
            chain: Some(&chain),
            ..input
        };
        assert!(
            policy_findings(Policy::MozillaModern, &input)
                .iter()
                .any(|f| f.message.ends_with("leaf certificate cannot be parsed"))
        );
    }

    /// Failed probes make the check incomplete only where they matter: a
    /// disallowed protocol version, or suites/groups of an allowed one.
    #[test]
    fn failed_probes() {
        let protocols = protocols(&[ProtocolVersion::TLS12, ProtocolVersion::TLS13]);
        let chain = [RSA2048.to_vec()];
        let response = http(Some("max-age=63072000"));
        let input = PolicyInput {
            protocols: &protocols,
            ciphers: Some(&[]),
            cipher_errors: &[ProtocolVersion::TLS10],
            key_exchange: Some(&[]),
            key_exchange_errors: &[ProtocolVersion::SSL3],
            chain: Some(&chain),
            http: Some(&response),
        };
        assert_eq!(policy_findings(Policy::MozillaIntermediate, &input), []);

        let input = PolicyInput {
            cipher_errors: &[ProtocolVersion::TLS12],
            key_exchange_errors: &[ProtocolVersion::TLS13],
            ..input
        };
        assert_eq!(
            summary(&policy_findings(Policy::MozillaIntermediate, &input)),
            [(
                "policy.incomplete".to_owned(),
                "mozilla-intermediate could not be fully checked: cipher suites, key \
                 exchange groups not measured"
                    .to_owned()
            )]
        );

        let mut errored = protocols.clone();
        assert_eq!(errored[2].version, ProtocolVersion::TLS10);
        errored[2].support = ProtocolSupport::Error("timed out".to_owned());
        let input = PolicyInput {
            protocols: &errored,
            cipher_errors: &[],
            key_exchange_errors: &[],
            ..input
        };
        assert_eq!(
            summary(&policy_findings(Policy::MozillaIntermediate, &input)),
            [(
                "policy.incomplete".to_owned(),
                "mozilla-intermediate could not be fully checked: protocol versions not \
                 measured"
                    .to_owned()
            )]
        );
    }

    /// Modern accepts its own certificate type and rejects missing HSTS.
    #[test]
    fn modern_certificate_and_hsts() {
        let deviations = |der: &[u8]| -> Vec<String> {
            certificate_deviations(Policy::MozillaModern, der)
                .into_iter()
                .map(|f| f.id)
                .collect()
        };
        assert_eq!(deviations(EC_LOCALHOST), ["policy.cert_lifespan"]);
        assert_eq!(
            certificate_deviations(Policy::MozillaIntermediate, EC_LOCALHOST),
            []
        );
        assert_eq!(
            hsts_deviation(Policy::MozillaModern, &http(None), MOZILLA_HSTS_MAX_AGE)
                .map(|f| f.message),
            Some(
                "no Strict-Transport-Security header is sent, which mozilla-modern does not allow"
                    .to_owned()
            )
        );
        assert!(
            hsts_deviation(Policy::MozillaModern, &http(Some("max-age=x")), 1)
                .is_some_and(|f| f.message.contains("is invalid"))
        );
    }

    /// NIST SP 800-52r2 allows DHE and CCM but not `ChaCha20` or x25519, and
    /// asks for neither HSTS nor short certificate lifetimes.
    #[test]
    fn nist_server() {
        let protocols = protocols(&[ProtocolVersion::TLS12, ProtocolVersion::TLS13]);
        let ciphers = [
            ciphers(ProtocolVersion::TLS12, &[0xc02f, 0x009e, 0xc0a2, 0x009c]),
            ciphers(ProtocolVersion::TLS13, &[0x1301, 0x1304, 0x1303]),
        ];
        let key_exchange = [
            groups(ProtocolVersion::TLS12, &[0x0017, 0x0100]),
            groups(ProtocolVersion::TLS13, &[0x0018, 0x001d]),
        ];
        let chain = [RSA2048.to_vec()];
        let input = PolicyInput {
            protocols: &protocols,
            ciphers: Some(&ciphers),
            cipher_errors: &[],
            key_exchange: Some(&key_exchange),
            key_exchange_errors: &[],
            chain: Some(&chain),
            http: None,
        };
        let tail = ", which nist-800-52r2 does not allow";
        let expected = [
            (
                "policy.cipher",
                "TLSv1.2 accepts TLS_RSA_WITH_AES_128_GCM_SHA256",
            ),
            (
                "policy.cipher",
                "TLSv1.3 accepts TLS_CHACHA20_POLY1305_SHA256",
            ),
            (
                "policy.group",
                "key exchange group x25519 (0x001d) is accepted",
            ),
        ]
        .map(|(id, what)| (id.to_owned(), format!("{what}{tail}")));
        assert_eq!(
            summary(&policy_findings(Policy::Nist80052r2, &input)),
            expected
        );

        let legacy = self::protocols(&[ProtocolVersion::TLS11, ProtocolVersion::TLS12]);
        let chain = [RSA1024_SHA1.to_vec()];
        let input = PolicyInput {
            protocols: &legacy,
            ciphers: Some(&[]),
            key_exchange: Some(&[]),
            chain: Some(&chain),
            ..input
        };
        let ids: Vec<_> = policy_findings(Policy::Nist80052r2, &input)
            .into_iter()
            .map(|f| f.id)
            .collect();
        assert_eq!(
            ids,
            [
                "policy.protocol",
                "policy.protocol",
                "policy.cert_key",
                "policy.cert_signature"
            ]
        );
    }

    /// BSI TR-02102-2 allows brainpool groups (with the code points of the
    /// matching TLS version), DHE with `ffdhe3072` and ECDSA leaves, but
    /// not SHA-1 CBC suites, `ChaCha20`, x25519, `ffdhe2048`, RSA keys below
    /// 3000 bits or PKCS #1 v1.5 signatures.
    #[test]
    fn bsi_server() {
        let protocols = protocols(&[ProtocolVersion::TLS12, ProtocolVersion::TLS13]);
        let ciphers = [
            ciphers(ProtocolVersion::TLS12, &[0xc02f, 0x009e, 0xc013, 0xcca8]),
            ciphers(ProtocolVersion::TLS13, &[0x1301, 0x1304, 0x1303]),
        ];
        let key_exchange = [
            groups(
                ProtocolVersion::TLS12,
                &[0x0017, 0x001a, 0x0101, 0x0100, 0x0020],
            ),
            groups(ProtocolVersion::TLS13, &[0x001f, 0x001d, 0x001b]),
        ];
        let chain = [EC_LOCALHOST.to_vec()];
        let input = PolicyInput {
            protocols: &protocols,
            ciphers: Some(&ciphers),
            cipher_errors: &[],
            key_exchange: Some(&key_exchange),
            key_exchange_errors: &[],
            chain: Some(&chain),
            http: None,
        };
        let tail = ", which bsi-tr-02102-2 does not allow";
        let expected = [
            (
                "policy.cipher",
                "TLSv1.2 accepts TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            ),
            (
                "policy.cipher",
                "TLSv1.2 accepts TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            ),
            (
                "policy.cipher",
                "TLSv1.3 accepts TLS_CHACHA20_POLY1305_SHA256",
            ),
            (
                "policy.group",
                "key exchange group ffdhe2048 (0x0100) is accepted",
            ),
            (
                "policy.group",
                "key exchange group brainpoolP384r1tls13 (0x0020) is accepted",
            ),
            (
                "policy.group",
                "key exchange group x25519 (0x001d) is accepted",
            ),
            (
                "policy.group",
                "key exchange group brainpoolP384r1 (0x001b) is accepted",
            ),
        ]
        .map(|(id, what)| (id.to_owned(), format!("{what}{tail}")));
        assert_eq!(
            summary(&policy_findings(Policy::BsiTr021022, &input)),
            expected
        );

        let chain = [RSA2048.to_vec()];
        let input = PolicyInput {
            ciphers: Some(&[]),
            key_exchange: Some(&[]),
            chain: Some(&chain),
            ..input
        };
        let expected = [
            (
                "policy.cert_key",
                "leaf certificate has an RSA key of only 2048 bits",
            ),
            (
                "policy.cert_signature",
                "leaf certificate is signed with sha256WithRSAEncryption",
            ),
        ]
        .map(|(id, what)| (id.to_owned(), format!("{what}{tail}")));
        assert_eq!(
            summary(&policy_findings(Policy::BsiTr021022, &input)),
            expected
        );
    }

    /// Every MODP group NIST SP 800-52r2 accepts names a known prime, so a
    /// typo cannot turn into a false `DHE uses MODP group N` finding.
    #[test]
    fn nist_dh_primes_known() {
        for name in NIST_DH_PRIMES {
            assert!(
                testls_data::known_dh_primes()
                    .iter()
                    .any(|k| k.name == *name),
                "{name} is not a known DH prime"
            );
        }
    }

    /// TLSv1.2 DHE primes count as groups even without `supported_groups`:
    /// BSI TR-02102-2 rejects `ffdhe2048`, `ffdhe6144`, MODP group 14 and
    /// custom primes; NIST SP 800-52r2 accepts MODP group 14 but not custom
    /// primes.
    #[test]
    fn dhe_primes() {
        let dhe = |prime: Option<Vec<u8>>| KeyExchangeResult {
            dh_prime: prime,
            ..groups(ProtocolVersion::TLS12, &[])
        };
        let known = |name: &str| {
            testls_data::known_dh_primes()
                .iter()
                .find(|k| k.name == name)
                .map(|k| unhex(k.hex))
        };
        let mut custom = vec![0, 0x7f];
        custom.extend([0xff; 255]);
        let key_exchange = [
            dhe(known("ffdhe2048")),
            dhe(known("ffdhe3072")),
            dhe(known("ffdhe6144")),
            dhe(known("MODP group 14")),
            dhe(Some(custom)),
        ];
        let input = PolicyInput {
            key_exchange: Some(&key_exchange),
            ..bsi_input()
        };
        let messages = |policy| -> Vec<String> {
            policy_findings(policy, &input)
                .into_iter()
                .filter(|f| f.id == "policy.group")
                .map(|f| f.message)
                .collect()
        };
        let tail = ", which bsi-tr-02102-2 does not allow";
        assert_eq!(
            messages(Policy::BsiTr021022),
            [
                format!("key exchange group ffdhe2048 (0x0100) is accepted{tail}"),
                format!("key exchange group ffdhe6144 (0x0103) is accepted{tail}"),
                format!("DHE uses MODP group 14{tail}"),
                format!("DHE uses a custom 2047-bit prime{tail}"),
            ]
        );
        assert_eq!(
            messages(Policy::Nist80052r2),
            ["DHE uses a custom 2047-bit prime, which nist-800-52r2 does not allow"]
        );
    }

    /// Policy checks all measured suite primes and reports incomplete coverage.
    #[test]
    fn mixed_dhe_policy() {
        use testls_probe::DhSuiteResult;
        let mut k = groups(ProtocolVersion::TLS12, &[]);
        k.dh_suites = vec![
            DhSuiteResult {
                suite: 0x0033,
                bits: Some(2048),
                prime: Some(unhex(testls_data::known_dh_primes()[11].hex)),
                key_reused: Some(false),
            },
            DhSuiteResult {
                suite: 0x0034,
                bits: Some(1024),
                prime: Some(vec![0xff; 128]),
                key_reused: Some(false),
            },
            DhSuiteResult {
                suite: 0x003a,
                bits: None,
                prime: None,
                key_reused: None,
            },
        ];
        let results = [k];
        let input = PolicyInput {
            key_exchange: Some(&results),
            ..bsi_input()
        };
        let findings = policy_findings(Policy::PciDss4, &input);
        assert!(
            findings
                .iter()
                .any(|f| f.id == "policy.group" && f.message.contains("1024-bit"))
        );
        assert!(
            findings
                .iter()
                .any(|f| f.id == "policy.incomplete" && f.message.contains("key exchange"))
        );
    }

    /// Input with nothing measured but an empty cipher and certificate scan.
    fn bsi_input() -> PolicyInput<'static> {
        PolicyInput {
            protocols: &[],
            ciphers: Some(&[]),
            cipher_errors: &[],
            key_exchange: Some(&[]),
            key_exchange_errors: &[],
            chain: None,
            http: None,
        }
    }

    /// NIST requires TLSv1.3 and SHA-2 hashes in RSASSA-PSS signatures.
    #[test]
    fn nist_requirements() {
        let tail = ", which nist-800-52r2 does not allow";
        let input = PolicyInput {
            protocols: &[],
            ciphers: Some(&[]),
            cipher_errors: &[],
            key_exchange: Some(&[]),
            key_exchange_errors: &[],
            chain: None,
            http: None,
        };
        let tls12_only = self::protocols(&[ProtocolVersion::TLS12]);
        let unknown = [ProtocolResult {
            version: ProtocolVersion::TLS13,
            support: ProtocolSupport::Error("timeout".into()),
        }];
        let input = PolicyInput {
            protocols: &tls12_only,
            chain: None,
            ..input
        };
        assert_eq!(
            summary(&policy_findings(Policy::Nist80052r2, &input)),
            [(
                "policy.protocol".to_owned(),
                "TLSv1.3 is not offered, but nist-800-52r2 requires it".to_owned()
            )]
            .into_iter()
            .chain([(
                "policy.incomplete".to_owned(),
                "nist-800-52r2 could not be fully checked: certificate not measured".to_owned()
            )])
            .collect::<Vec<_>>()
        );
        let input = PolicyInput {
            protocols: &unknown,
            ..input
        };
        assert_eq!(
            summary(&policy_findings(Policy::Nist80052r2, &input)),
            [(
                "policy.incomplete".to_owned(),
                "nist-800-52r2 could not be fully checked: protocol versions, certificate not measured".to_owned()
            )]
        );
        assert_eq!(
            summary(&certificate_deviations(Policy::Nist80052r2, RSA_PSS_SHA1)),
            [(
                "policy.cert_signature".to_owned(),
                format!("leaf certificate is signed with RSASSA-PSS using a non-SHA-2 hash{tail}")
            )]
        );
        assert_eq!(
            certificate_deviations(Policy::Nist80052r2, EC_LOCALHOST),
            []
        );
    }

    /// CNSA 2.0 accepts only TLSv1.3 with AES-256-GCM, ML-KEM-1024 and an
    /// ML-DSA-87 certificate.
    #[test]
    fn cnsa_server() {
        let protocols = protocols(&[ProtocolVersion::TLS13]);
        let ciphers = [ciphers(ProtocolVersion::TLS13, &[0x1302])];
        let key_exchange = [groups(ProtocolVersion::TLS13, &[0x0202])];
        let chain = [MLDSA87.to_vec()];
        let input = PolicyInput {
            protocols: &protocols,
            ciphers: Some(&ciphers),
            cipher_errors: &[],
            key_exchange: Some(&key_exchange),
            key_exchange_errors: &[],
            chain: Some(&chain),
            http: None,
        };
        assert_eq!(policy_findings(Policy::Cnsa2, &input), []);
        assert_eq!(
            summary(&certificate_deviations(
                Policy::MozillaIntermediate,
                MLDSA87
            )),
            [
                (
                    "policy.cert_key".to_owned(),
                    "leaf certificate has a key of algorithm ML-DSA-87, which \
                     mozilla-intermediate does not allow"
                        .to_owned()
                ),
                (
                    "policy.cert_signature".to_owned(),
                    "leaf certificate is signed with ML-DSA-87, which \
                     mozilla-intermediate does not allow"
                        .to_owned()
                )
            ]
        );

        let protocols = self::protocols(&[ProtocolVersion::TLS12, ProtocolVersion::TLS13]);
        let ciphers = [self::ciphers(ProtocolVersion::TLS13, &[0x1301, 0x1302])];
        let key_exchange = [self::groups(ProtocolVersion::TLS13, &[0x11ec, 0x0202])];
        let chain = [EC_LOCALHOST.to_vec()];
        let input = PolicyInput {
            protocols: &protocols,
            ciphers: Some(&ciphers),
            key_exchange: Some(&key_exchange),
            chain: Some(&chain),
            ..input
        };
        let tail = ", which cnsa-2.0 does not allow";
        let expected = [
            ("policy.protocol", "TLSv1.2 is offered"),
            ("policy.cipher", "TLSv1.3 accepts TLS_AES_128_GCM_SHA256"),
            (
                "policy.group",
                "key exchange group X25519MLKEM768 (0x11ec) is accepted",
            ),
            (
                "policy.cert_key",
                "leaf certificate has an EC key on curve P-256",
            ),
            (
                "policy.cert_signature",
                "leaf certificate is signed with ecdsa-with-SHA256",
            ),
        ]
        .map(|(id, what)| (id.to_owned(), format!("{what}{tail}")));
        assert_eq!(summary(&policy_findings(Policy::Cnsa2, &input)), expected);
    }

    /// PCI DSS accepts any TLSv1.2 suite, group, DHE prime and key of at
    /// least 112-bit strength, CBC and non-forward-secret suites included,
    /// and rejects early TLS, 64-bit block ciphers and short keys.
    #[test]
    fn pci_server() {
        let known = |name: &str| {
            testls_data::known_dh_primes()
                .iter()
                .find(|k| k.name == name)
                .map(|k| unhex(k.hex))
        };
        let dhe = |prime: Option<Vec<u8>>| KeyExchangeResult {
            dh_prime: prime,
            ..groups(ProtocolVersion::TLS12, &[0x0017])
        };
        let mut custom2048 = vec![0x80];
        custom2048.extend([0xff; 255]);
        let protocols = protocols(&[ProtocolVersion::TLS12, ProtocolVersion::TLS13]);
        let ciphers = [
            ciphers(ProtocolVersion::TLS12, &[0xc02f, 0xc013, 0x009c, 0x0041]),
            ciphers(ProtocolVersion::TLS13, &[0x1301, 0x1302, 0x1303, 0x1304]),
        ];
        let key_exchange = [
            groups(ProtocolVersion::TLS13, &[0x11ec, 0x001d, 0x0018]),
            groups(ProtocolVersion::TLS12, &[0x0015, 0x0017]),
            dhe(known("MODP group 14")),
            dhe(known("RFC 5114 2048-bit group (256-bit subgroup)")),
            dhe(Some(custom2048)),
        ];
        let chain = [RSA2048.to_vec()];
        let input = PolicyInput {
            protocols: &protocols,
            ciphers: Some(&ciphers),
            cipher_errors: &[],
            key_exchange: Some(&key_exchange),
            key_exchange_errors: &[],
            chain: Some(&chain),
            http: None,
        };
        assert_eq!(policy_findings(Policy::PciDss4, &input), []);
        assert_eq!(certificate_deviations(Policy::PciDss4, ED25519), []);
        assert_eq!(certificate_deviations(Policy::PciDss4, EC_LOCALHOST), []);
        assert_eq!(certificate_deviations(Policy::PciDss4, P224), []);
        assert_eq!(
            summary(&certificate_deviations(Policy::BsiTr021022, P224)),
            [(
                "policy.cert_key".to_owned(),
                "leaf certificate has an EC key on curve P-224, which bsi-tr-02102-2 does not allow"
                    .to_owned()
            )]
        );

        let mut custom2047 = vec![0x7f];
        custom2047.extend([0xff; 255]);
        let protocols = self::protocols(&[ProtocolVersion::TLS11, ProtocolVersion::TLS12]);
        let ciphers = [self::ciphers(
            ProtocolVersion::TLS12,
            &[0xc02f, 0x000a, 0x0005, 0x0007, 0xffff],
        )];
        let key_exchange = [
            self::groups(ProtocolVersion::TLS12, &[0x0017, 0x0016]),
            dhe(known("MODP group 5")),
            dhe(Some(custom2047)),
        ];
        let chain = [RSA1024_SHA1.to_vec()];
        let input = PolicyInput {
            protocols: &protocols,
            ciphers: Some(&ciphers),
            key_exchange: Some(&key_exchange),
            chain: Some(&chain),
            ..input
        };
        let tail = ", which pci-dss-4 does not allow";
        let expected = [
            ("policy.protocol", "TLSv1.1 is offered"),
            (
                "policy.cipher",
                "TLSv1.2 accepts TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            ),
            ("policy.cipher", "TLSv1.2 accepts TLS_RSA_WITH_RC4_128_SHA"),
            ("policy.cipher", "TLSv1.2 accepts TLS_RSA_WITH_IDEA_CBC_SHA"),
            ("policy.cipher", "TLSv1.2 accepts unknown"),
            (
                "policy.group",
                "key exchange group secp256k1 (0x0016) is accepted",
            ),
            ("policy.group", "DHE uses MODP group 5"),
            ("policy.group", "DHE uses a custom 2047-bit prime"),
            (
                "policy.cert_key",
                "leaf certificate has an RSA key of only 1024 bits",
            ),
            (
                "policy.cert_signature",
                "leaf certificate is signed with 1.2.840.113549.1.1.5",
            ),
        ]
        .map(|(id, what)| (id.to_owned(), format!("{what}{tail}")));
        assert_eq!(summary(&policy_findings(Policy::PciDss4, &input)), expected);
    }

    /// Names round-trip through `FromStr`.
    #[test]
    fn names() {
        for policy in Policy::ALL {
            assert_eq!(policy.as_str().parse::<Policy>(), Ok(policy));
        }
        assert_eq!("MOZILLA-MODERN".parse(), Ok(Policy::MozillaModern));
        assert_eq!("NIST-800-52R2".parse(), Ok(Policy::Nist80052r2));
        assert_eq!("CNSA-2.0".parse(), Ok(Policy::Cnsa2));
        assert_eq!("BSI-TR-02102-2".parse(), Ok(Policy::BsiTr021022));
        assert_eq!("PCI-DSS-4".parse(), Ok(Policy::PciDss4));
        assert!("pci".parse::<Policy>().is_err());
    }
}
