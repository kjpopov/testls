//! Whether the server's certificate chain leads to a trusted root.
//!
//! Path building and verification are done by `rustls-webpki` against a
//! [`TrustStore`], which defaults to the Mozilla root program as shipped in
//! `webpki-roots` and can instead hold the operating system's roots or a
//! custom bundle. Validity, host name, key, and signature problems of the
//! leaf are reported by [`certificate_findings`](crate::certificate_findings)
//! and not repeated here.

use std::time::Duration;

use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, Error, KeyUsage};
use x509_parser::parse_x509_certificate;

use crate::{Finding, Severity};

/// A set of trust anchors that certificate chains are verified against.
#[derive(Debug, Clone)]
pub struct TrustStore {
    /// The root certificates' subject, public key, and name constraints.
    anchors: Vec<TrustAnchor<'static>>,
}

impl TrustStore {
    /// The Mozilla root program for TLS server authentication, as bundled in
    /// `webpki-roots`.
    #[must_use]
    pub fn webpki() -> Self {
        Self {
            anchors: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        }
    }

    /// Builds a store from DER root certificates.
    ///
    /// # Errors
    ///
    /// Returns a message naming the first certificate that is not a usable
    /// trust anchor.
    pub fn from_certificates<'a>(
        certificates: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, String> {
        let anchors = certificates
            .into_iter()
            .enumerate()
            .map(|(index, der)| {
                webpki::anchor_from_trusted_cert(&CertificateDer::from(der))
                    .map(|anchor| anchor.to_owned())
                    .map_err(|e| format!("root certificate #{index}: {e:?}"))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { anchors })
    }

    /// Builds a store from a PEM bundle of root certificates; other PEM
    /// sections are ignored.
    ///
    /// # Errors
    ///
    /// Returns a message if the PEM is malformed, contains no certificate,
    /// or a certificate is not a usable trust anchor.
    pub fn from_pem(pem: &[u8]) -> Result<Self, String> {
        let certificates = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("invalid PEM: {e}"))?;
        if certificates.is_empty() {
            return Err("no certificates found".to_owned());
        }
        Self::from_certificates(certificates.iter().map(AsRef::as_ref))
    }

    /// The operating system's trust store, as read by `rustls-native-certs`:
    /// the keychain on macOS, the certificate store on Windows, and the
    /// OpenSSL bundle elsewhere. `SSL_CERT_FILE` and `SSL_CERT_DIR` override
    /// the platform store when set.
    ///
    /// # Errors
    ///
    /// Returns a message if no usable root certificate could be loaded.
    /// Otherwise the store comes with any partial load errors, which the
    /// caller should surface as warnings.
    pub fn system() -> Result<(Self, Vec<String>), String> {
        let loaded = rustls_native_certs::load_native_certs();
        let errors = loaded.errors.iter().map(ToString::to_string).collect();
        Self::from_system_certificates(loaded.certs.iter().map(AsRef::as_ref), errors)
    }

    /// Builds a store from the certificates and load errors reported for
    /// the system store.
    ///
    /// System stores can hold certificates that are not usable trust anchors
    /// (for example with unsupported extensions); those are skipped instead
    /// of failing the whole store. Partial load errors are handed back
    /// alongside the store so they can be reported.
    fn from_system_certificates<'a>(
        certificates: impl IntoIterator<Item = &'a [u8]>,
        errors: Vec<String>,
    ) -> Result<(Self, Vec<String>), String> {
        let anchors: Vec<_> = certificates
            .into_iter()
            .filter_map(|der| {
                webpki::anchor_from_trusted_cert(&CertificateDer::from(der))
                    .ok()
                    .map(|anchor| anchor.to_owned())
            })
            .collect();
        if !anchors.is_empty() {
            return Ok((Self { anchors }, errors));
        }
        match errors.as_slice() {
            [] => Err("no usable root certificates found".to_owned()),
            [e] => Err(format!("no usable root certificates: {e}")),
            [e, rest @ ..] => Err(format!(
                "no usable root certificates: {e} (+{} more)",
                rest.len()
            )),
        }
    }

    /// Number of trust anchors in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether the store has no trust anchors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

/// Verifies a DER certificate chain (leaf first) for TLS server
/// authentication against `store` at Unix time `now`.
///
/// Returns a single `cert.untrusted` finding when no valid path to a trust
/// anchor exists, and nothing for an empty or unparsable chain (those are
/// reported by [`certificate_findings`](crate::certificate_findings)).
#[must_use]
pub fn trust_findings(chain: &[Vec<u8>], now: i64, store: &TrustStore) -> Vec<Finding> {
    let Some(leaf_der) = chain.first() else {
        return Vec::new();
    };
    let Some(time) = verification_time(leaf_der, now) else {
        return Vec::new();
    };
    let leaf_der = CertificateDer::from(leaf_der.as_slice());
    let Ok(leaf) = EndEntityCert::try_from(&leaf_der) else {
        return Vec::new();
    };
    let intermediates: Vec<CertificateDer<'_>> = chain[1..]
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();

    match leaf.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &store.anchors,
        &intermediates,
        time,
        KeyUsage::server_auth(),
        None,
        None,
    ) {
        Ok(_) => Vec::new(),
        Err(e) => vec![Finding::new(
            "cert.untrusted",
            Severity::High,
            format!("certificate chain is not trusted: {}", reason(&e, chain)),
        )],
    }
}

/// The time to verify the chain at: `now`, clamped into the leaf's validity
/// period so that an expired or not-yet-valid leaf (already reported by the
/// certificate checks) does not hide the trust result.
fn verification_time(leaf_der: &[u8], now: i64) -> Option<UnixTime> {
    let (_, leaf) = parse_x509_certificate(leaf_der).ok()?;
    let validity = leaf.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    let time = if not_before <= not_after {
        now.clamp(not_before, not_after)
    } else {
        now
    };
    let secs = u64::try_from(time).ok()?;
    Some(UnixTime::since_unix_epoch(Duration::from_secs(secs)))
}

/// Human-readable explanation of a path-building failure.
///
/// Self-signed leaves often carry `basicConstraints CA:TRUE` (the OpenSSL
/// default), which webpki reports as a CA used as an end entity.
fn reason(error: &Error, chain: &[Vec<u8>]) -> String {
    match error {
        Error::UnknownIssuer | Error::CaUsedAsEndEntity if is_self_issued(&chain[0]) => {
            "self-signed certificate".to_owned()
        }
        Error::UnknownIssuer => "issuer is not a trusted root".to_owned(),
        Error::CertExpired { .. } => "a chain certificate has expired".to_owned(),
        Error::CertNotValidYet { .. } => "a chain certificate is not yet valid".to_owned(),
        Error::CaUsedAsEndEntity => "leaf certificate is a CA certificate".to_owned(),
        Error::CertDistrusted => "chain uses a distrusted certificate".to_owned(),
        Error::RequiredEkuNotFoundContext(_) => {
            "leaf certificate is not valid for server authentication".to_owned()
        }
        Error::UnsupportedSignatureAlgorithmContext(_)
        | Error::UnsupportedSignatureAlgorithmForPublicKeyContext(_) => {
            "chain uses an unsupported signature algorithm".to_owned()
        }
        Error::InvalidSignatureForPublicKey => "a chain signature is invalid".to_owned(),
        other => format!("{other:?}"),
    }
}

/// Whether the certificate's subject equals its issuer.
fn is_self_issued(der: &[u8]) -> bool {
    parse_x509_certificate(der).is_ok_and(|(_, cert)| cert.subject() == cert.issuer())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test root CA (P-256), valid 2026-01-01..2027-01-01.
    const ROOT: &[u8] = include_bytes!("testdata/trust-root.der");
    /// Intermediate CA signed by [`ROOT`], same validity.
    const INTERMEDIATE: &[u8] = include_bytes!("testdata/trust-intermediate.der");
    /// Leaf for `localhost` signed by [`INTERMEDIATE`], same validity.
    const LEAF: &[u8] = include_bytes!("testdata/trust-leaf.der");
    /// Self-signed `localhost` leaf, same validity.
    const SELF_SIGNED: &[u8] = include_bytes!("testdata/ec-localhost.der");

    /// 2026-07-01T00:00:00Z, inside every fixture's validity period.
    const MID_2026: i64 = 1_782_864_000;
    /// 2028-01-01T00:00:00Z, after every fixture has expired.
    const YEAR_2028: i64 = 1_830_297_600;

    /// Expected message list when there are no findings.
    const NONE: [&str; 0] = [];

    /// A store that trusts only the test root.
    fn test_store() -> TrustStore {
        TrustStore::from_certificates([ROOT]).unwrap()
    }

    /// Runs the trust check and returns the finding messages.
    fn messages(chain: &[&[u8]], now: i64, store: &TrustStore) -> Vec<String> {
        let chain: Vec<Vec<u8>> = chain.iter().map(|der| der.to_vec()).collect();
        trust_findings(&chain, now, store)
            .into_iter()
            .map(|f| {
                assert_eq!(f.id, "cert.untrusted");
                assert_eq!(f.severity, Severity::High);
                f.message
            })
            .collect()
    }

    /// A complete chain to a trusted root has no findings, with or without
    /// the root itself included.
    #[test]
    fn trusted_chain() {
        let store = test_store();
        assert_eq!(messages(&[LEAF, INTERMEDIATE], MID_2026, &store), NONE);
        assert_eq!(
            messages(&[LEAF, INTERMEDIATE, ROOT], MID_2026, &store),
            NONE
        );
    }

    /// A missing intermediate breaks the path.
    #[test]
    fn missing_intermediate() {
        assert_eq!(
            messages(&[LEAF], MID_2026, &test_store()),
            ["certificate chain is not trusted: issuer is not a trusted root"]
        );
    }

    /// The test root is not in the Mozilla store.
    #[test]
    fn unknown_root() {
        assert_eq!(
            messages(&[LEAF, INTERMEDIATE], MID_2026, &TrustStore::webpki()),
            ["certificate chain is not trusted: issuer is not a trusted root"]
        );
    }

    /// A self-signed leaf gets a specific message.
    #[test]
    fn self_signed() {
        assert_eq!(
            messages(&[SELF_SIGNED], MID_2026, &TrustStore::webpki()),
            ["certificate chain is not trusted: self-signed certificate"]
        );
    }

    /// An expired leaf is reported by the certificate checks, not here.
    #[test]
    fn expired_leaf_not_repeated() {
        assert_eq!(
            messages(&[LEAF, INTERMEDIATE], YEAR_2028, &test_store()),
            NONE
        );
    }

    /// Empty and unparsable chains are left to the certificate checks.
    #[test]
    fn empty_or_garbage() {
        let store = test_store();
        assert_eq!(messages(&[], MID_2026, &store), NONE);
        assert_eq!(messages(&[b"garbage"], MID_2026, &store), NONE);
    }

    /// The bundled Mozilla store is populated; garbage is not a trust anchor.
    #[test]
    fn stores() {
        assert!(!TrustStore::webpki().is_empty());
        assert_eq!(test_store().len(), 1);
        assert!(TrustStore::from_certificates([b"garbage".as_slice()]).is_err());
    }

    /// The system store skips unusable certificates and fails only when no
    /// anchor is left, quoting the first load error if there is one.
    /// Partial load errors come back as warnings next to the store.
    #[test]
    fn system_store_from_certificates() {
        let (store, warnings) =
            TrustStore::from_system_certificates([b"garbage".as_slice(), ROOT], Vec::new())
                .unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(warnings, Vec::<String>::new());
        assert_eq!(messages(&[LEAF, INTERMEDIATE], MID_2026, &store), NONE);

        let (partial, warnings) =
            TrustStore::from_system_certificates([ROOT], vec!["unreadable file".to_owned()])
                .unwrap();
        assert_eq!(partial.len(), 1);
        assert_eq!(warnings, ["unreadable file"]);

        assert_eq!(
            TrustStore::from_system_certificates([b"garbage".as_slice()], Vec::new()).unwrap_err(),
            "no usable root certificates found"
        );
        assert_eq!(
            TrustStore::from_system_certificates([], vec!["permission denied".to_owned()])
                .unwrap_err(),
            "no usable root certificates: permission denied"
        );
        assert_eq!(
            TrustStore::from_system_certificates(
                [],
                vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]
            )
            .unwrap_err(),
            "no usable root certificates: a (+2 more)"
        );
    }

    /// PEM bundles load every certificate and reject empty input.
    #[test]
    fn pem_store() {
        let pem = include_bytes!("testdata/trust-root.pem");
        let store = TrustStore::from_pem(pem).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(messages(&[LEAF, INTERMEDIATE], MID_2026, &store), NONE);
        assert!(TrustStore::from_pem(b"").is_err());
        assert!(TrustStore::from_pem(b"-----BEGIN CERTIFICATE-----\n!!\n").is_err());
    }
}
