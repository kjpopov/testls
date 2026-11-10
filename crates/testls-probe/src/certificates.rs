//! Certificate chain retrieval over a full rustls handshake.
//!
//! The verifier used here accepts every chain: the goal is to record what the
//! server presents, not to decide whether to trust it. Trust is evaluated
//! later by the checks. The handshake signature is checked against the leaf
//! key, so a peer relaying someone else's certificate without its private
//! key fails the handshake instead of being reported as that server.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use testls_wire::ProtocolVersion;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use x509_parser::public_key::PublicKey;

use crate::{ProbeError, Transport};

/// Certificate chain presented by a server during a full handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateChain {
    /// Protocol version the handshake negotiated.
    pub version: ProtocolVersion,
    /// DER-encoded certificates in the order the server sent them, leaf first.
    pub certificates: Vec<Vec<u8>>,
    /// DER-encoded OCSP response stapled to the handshake (RFC 6066 §8,
    /// RFC 8446 §4.4.2.1), if the server sent one.
    pub ocsp_response: Option<Vec<u8>>,
    /// Whether the handshake signature was verified against the leaf key.
    /// `false` when ring cannot check the key (ML-DSA, RSA under 2048 bits,
    /// P-521, Ed448) and the scheme fits it.
    pub signature_verified: bool,
}

/// Completes a TLS 1.2/1.3 handshake and returns the server's certificate
/// chain without validating it.
///
/// The handshake signature must match the leaf key when it can be checked;
/// see [`CertificateChain::signature_verified`].
///
/// `sni` is sent as the server name; without it the target IP is used and
/// no SNI extension is sent.
///
/// # Errors
/// Returns a [`ProbeError`] on connect/I/O failure, timeout, or if the
/// handshake fails (for example, a server that only speaks TLS 1.1 or older).
pub async fn fetch_certificates(
    transport: &Transport,
    sni: Option<&str>,
) -> Result<CertificateChain, ProbeError> {
    let verifier = Arc::new(AcceptAll::new());
    let tls = connect_tls(transport, sni, config_with(verifier.clone())).await?;
    let (_, conn) = tls.get_ref();
    let version = conn
        .protocol_version()
        .map(|v| ProtocolVersion(u16::from(v)))
        .ok_or(ProbeError::Unexpected(
            "handshake finished without a version",
        ))?;
    let certificates = conn
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .map(|c| c.as_ref().to_vec())
        .collect();
    Ok(CertificateChain {
        version,
        certificates,
        ocsp_response: verifier.take_ocsp_response(),
        signature_verified: verifier.signature_verified(),
    })
}

/// Opens a TCP connection and completes a TLS handshake with `config`.
///
/// `sni` is sent as the server name; without it the target IP is used and
/// no SNI extension is sent.
///
/// # Errors
/// Returns a [`ProbeError`] on connect/I/O failure, timeout, or a failed
/// handshake.
pub(crate) async fn connect_tls(
    transport: &Transport,
    sni: Option<&str>,
    config: ClientConfig,
) -> Result<TlsStream<TcpStream>, ProbeError> {
    let server_name = match sni {
        Some(name) => ServerName::try_from(name.to_owned())
            .map_err(|_| ProbeError::Unexpected("SNI is not a valid server name"))?,
        None => ServerName::from(transport.addr.ip()),
    };
    let stream = transport.connect().await?;
    stream.set_nodelay(true).map_err(ProbeError::Io)?;

    let connector = TlsConnector::from(Arc::new(config));
    timeout(
        transport.read_timeout,
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| ProbeError::Timeout)?
    .map_err(ProbeError::Io)
}

/// Client config offering TLS 1.2 and 1.3 with the recording verifier.
pub(crate) fn client_config() -> ClientConfig {
    config_with(Arc::new(AcceptAll::new()))
}

/// Client config offering only TLS 1.2 with the recording verifier.
pub(crate) fn tls12_client_config() -> ClientConfig {
    let verifier = Arc::new(AcceptAll::new());
    ClientConfig::builder_with_provider(verifier.provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("ring supports TLS 1.2")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

/// Client config offering only TLS 1.3 with the recording verifier.
pub(crate) fn tls13_client_config() -> ClientConfig {
    let verifier = Arc::new(AcceptAll::new());
    ClientConfig::builder_with_provider(verifier.provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("ring supports TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

/// Client config offering TLS 1.2 and 1.3 that verifies with `verifier`.
///
/// rustls always sends the `status_request` extension, so servers that
/// staple OCSP responses hand them to the verifier.
fn config_with(verifier: Arc<AcceptAll>) -> ClientConfig {
    ClientConfig::builder_with_provider(verifier.provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

/// Signature schemes ring cannot verify, advertised so servers whose only
/// certificate uses them still send their chain (IANA TLS `SignatureScheme`
/// registry: 0x0603 P-521, 0x0808 Ed448, 0x0904-0x0906 ML-DSA).
/// In TLS 1.2 rustls only takes the schemes of the cipher suite's
/// signature algorithm, which ring lacks for Ed448, so an Ed448 server still
/// fails the TLS 1.2 fetch.
const UNVERIFIABLE_SCHEMES: [SignatureScheme; 5] = [
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ED448,
    SignatureScheme::ML_DSA_44,
    SignatureScheme::ML_DSA_65,
    SignatureScheme::ML_DSA_87,
];

/// Verifier that accepts any certificate, rejects handshake signatures that
/// do not match the leaf key, and keeps the stapled OCSP response.
#[derive(Debug)]
struct AcceptAll {
    /// Provider whose signature schemes are advertised and verified.
    provider: Arc<CryptoProvider>,
    /// Stapled OCSP response seen during the handshake.
    ocsp_response: Mutex<Option<Vec<u8>>>,
    /// Set when a handshake signature was accepted without verification.
    unverified: AtomicBool,
}

impl AcceptAll {
    /// Verifier using the ring provider, with nothing recorded yet.
    fn new() -> Self {
        Self {
            provider: Arc::new(ring::default_provider()),
            ocsp_response: Mutex::new(None),
            unverified: AtomicBool::new(false),
        }
    }

    /// Takes the recorded stapled OCSP response, if any.
    fn take_ocsp_response(&self) -> Option<Vec<u8>> {
        self.ocsp_response
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// Whether every handshake signature seen so far was verified.
    fn signature_verified(&self) -> bool {
        !self.unverified.load(Ordering::Relaxed)
    }

    /// Turns a signature verification `result` into the verifier's answer.
    ///
    /// A failed check fails the handshake: the peer may not hold the key of
    /// the certificate it presented. The one exception is a leaf key ring
    /// cannot verify, signed with a scheme that fits that key (see
    /// [`unverifiable`]); it is accepted and recorded as unverified, so weak
    /// or post-quantum servers are still reported. `tls12` is set for a
    /// TLS 1.2 handshake.
    fn check(
        &self,
        result: Result<HandshakeSignatureValid, rustls::Error>,
        cert: &CertificateDer<'_>,
        scheme: SignatureScheme,
        tls12: bool,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        match result {
            Ok(valid) => Ok(valid),
            Err(_) if unverifiable(cert, scheme, tls12) => {
                self.unverified.store(true, Ordering::Relaxed);
                Ok(HandshakeSignatureValid::assertion())
            }
            Err(e) => Err(e),
        }
    }
}

/// OID of the P-521 curve (RFC 5480).
const P521_OID: &str = "1.3.132.0.35";

/// Whether `cert` has a key ring cannot verify and `scheme` fits that key.
///
/// Covers RSA keys under 2048 bits with an RSA scheme, P-521 with
/// `ecdsa_secp521r1_sha512`, Ed448 with `ed448`, and ML-DSA with the scheme
/// of the same parameter set. In TLS 1.2 (`tls12`) ECDSA schemes only name
/// the hash (RFC 8446 §4.2.3), so P-521 with any ECDSA scheme and any curve
/// with SHA-512 also count; ring has neither. Key OIDs: RFC 8017 (RSA),
/// RFC 5480 (EC curves), RFC 8410 (Ed448), RFC 9881 (ML-DSA).
fn unverifiable(cert: &CertificateDer<'_>, scheme: SignatureScheme, tls12: bool) -> bool {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert.as_ref()) else {
        return false;
    };
    let spki = cert.public_key();
    let key = spki.algorithm.algorithm.to_id_string();
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|oid| oid.to_id_string());
    match (key.as_str(), scheme) {
        (
            "1.2.840.113549.1.1.1",
            SignatureScheme::RSA_PKCS1_SHA1
            | SignatureScheme::RSA_PKCS1_SHA256
            | SignatureScheme::RSA_PKCS1_SHA384
            | SignatureScheme::RSA_PKCS1_SHA512
            | SignatureScheme::RSA_PSS_SHA256
            | SignatureScheme::RSA_PSS_SHA384
            | SignatureScheme::RSA_PSS_SHA512,
        ) => matches!(spki.parsed(), Ok(PublicKey::RSA(k)) if k.key_size() < 2048),
        ("1.2.840.10045.2.1", SignatureScheme::ECDSA_NISTP521_SHA512) => {
            tls12 || curve.as_deref() == Some(P521_OID)
        }
        (
            "1.2.840.10045.2.1",
            SignatureScheme::ECDSA_NISTP256_SHA256 | SignatureScheme::ECDSA_NISTP384_SHA384,
        ) => tls12 && curve.as_deref() == Some(P521_OID),
        ("1.3.101.113", SignatureScheme::ED448)
        | ("2.16.840.1.101.3.4.3.17", SignatureScheme::ML_DSA_44)
        | ("2.16.840.1.101.3.4.3.18", SignatureScheme::ML_DSA_65)
        | ("2.16.840.1.101.3.4.3.19", SignatureScheme::ML_DSA_87) => true,
        _ => false,
    }
}

impl ServerCertVerifier for AcceptAll {
    /// Accepts the chain unconditionally and records a non-empty stapled
    /// OCSP response; trust is checked elsewhere.
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !ocsp_response.is_empty() {
            *self
                .ocsp_response
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(ocsp_response.to_vec());
        }
        Ok(ServerCertVerified::assertion())
    }

    /// Checks the TLS 1.2 handshake signature against the leaf key; see
    /// [`AcceptAll::check`].
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let result = rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        );
        self.check(result, cert, dss.scheme, true)
    }

    /// Checks the TLS 1.3 handshake signature against the leaf key; see
    /// [`AcceptAll::check`].
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let result = rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        );
        self.check(result, cert, dss.scheme, false)
    }

    /// Advertises every scheme the crypto provider knows plus
    /// [`UNVERIFIABLE_SCHEMES`]; their signatures are accepted but recorded
    /// as unverified, so servers with only such a certificate still send
    /// their chain.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let mut schemes = self
            .provider
            .signature_verification_algorithms
            .supported_schemes();
        for scheme in UNVERIFIABLE_SCHEMES {
            if !schemes.contains(&scheme) {
                schemes.push(scheme);
            }
        }
        schemes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::{CertificateError, ServerConfig};
    use std::net::SocketAddr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    /// Self-signed P-256 certificate for `localhost` (valid until 2126).
    const CERT: &[u8] = include_bytes!("testdata/localhost.cert.der");
    /// PKCS#8 private key for [`CERT`].
    const KEY: &[u8] = include_bytes!("testdata/localhost.key.der");
    /// Unrelated P-256 PKCS#8 private key (does not match [`CERT`]).
    const WRONG_KEY: &[u8] = include_bytes!("testdata/wrong.key.der");
    /// Self-signed certificate with a 1024-bit RSA key (`small-rsa.example`).
    const RSA1024_CERT: &[u8] = include_bytes!("testdata/rsa1024.cert.der");
    /// Self-signed ML-DSA-65 certificate (`mldsa.example`).
    const MLDSA65_CERT: &[u8] = include_bytes!("testdata/mldsa65.cert.der");
    /// Self-signed P-521 certificate (`p521.example`).
    const P521_CERT: &[u8] = include_bytes!("testdata/p521.cert.der");
    /// Self-signed Ed448 certificate (`ed448.example`).
    const ED448_CERT: &[u8] = include_bytes!("testdata/ed448.cert.der");

    /// Starts a one-shot rustls server limited to `versions`.
    async fn serve(versions: &[&'static rustls::SupportedProtocolVersion]) -> SocketAddr {
        serve_with_ocsp(versions, Vec::new()).await
    }

    /// Starts a one-shot rustls server limited to `versions` that staples
    /// `ocsp` (nothing when empty).
    async fn serve_with_ocsp(
        versions: &[&'static rustls::SupportedProtocolVersion],
        ocsp: Vec<u8>,
    ) -> SocketAddr {
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert_with_ocsp(
                vec![CertificateDer::from(CERT.to_vec())],
                PrivateKeyDer::try_from(KEY.to_vec()).unwrap(),
                ocsp,
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            if let Ok(mut tls) = acceptor.accept(s).await {
                let _ = tls.shutdown().await;
            }
        });
        addr
    }

    /// P-521, Ed448 and ML-DSA schemes are advertised once, next to the
    /// provider's schemes.
    #[test]
    fn advertises_unverifiable_schemes() {
        let schemes = AcceptAll::new().supported_verify_schemes();
        for scheme in UNVERIFIABLE_SCHEMES {
            assert_eq!(schemes.iter().filter(|s| **s == scheme).count(), 1);
        }
        assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
    }

    /// Failed checks fail the handshake, except for a key ring cannot verify
    /// signed with a scheme that fits it; that is recorded as unverified.
    #[test]
    fn checks_signature_results() {
        let p256 = CertificateDer::from(CERT.to_vec());
        let rsa1024 = CertificateDer::from(RSA1024_CERT.to_vec());
        let bad = || {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::BadSignature,
            ))
        };
        // rustls reports schemes ring lacks, such as ML-DSA, this way.
        let unsupported = || {
            Err(rustls::Error::PeerMisbehaved(
                rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
            ))
        };
        let mismatch = || {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                    signature_algorithm_id: Vec::new(),
                    public_key_algorithm_id: Vec::new(),
                },
            ))
        };

        let verifier = AcceptAll::new();
        let ok = Ok(HandshakeSignatureValid::assertion());
        let ecdsa = SignatureScheme::ECDSA_NISTP256_SHA256;
        assert!(verifier.check(ok, &p256, ecdsa, false).is_ok());
        assert!(verifier.check(bad(), &p256, ecdsa, false).is_err());
        // A P-256 leaf with an ML-DSA or RSA scheme is a mismatch.
        let mldsa = SignatureScheme::ML_DSA_65;
        assert!(verifier.check(unsupported(), &p256, mldsa, false).is_err());
        let rsa = SignatureScheme::RSA_PSS_SHA256;
        assert!(verifier.check(mismatch(), &p256, rsa, false).is_err());
        assert!(verifier.check(bad(), &rsa1024, ecdsa, false).is_err());
        assert!(verifier.signature_verified());

        let mldsa_cert = CertificateDer::from(MLDSA65_CERT.to_vec());
        let mldsa44 = SignatureScheme::ML_DSA_44;
        assert!(
            verifier
                .check(unsupported(), &mldsa_cert, mldsa44, false)
                .is_err()
        );
        assert!(verifier.signature_verified());

        assert!(verifier.check(bad(), &rsa1024, rsa, false).is_ok());
        assert!(!verifier.signature_verified());

        let verifier = AcceptAll::new();
        assert!(
            verifier
                .check(unsupported(), &mldsa_cert, mldsa, false)
                .is_ok()
        );
        assert!(!verifier.signature_verified());

        let p521 = CertificateDer::from(P521_CERT.to_vec());
        let ed448 = CertificateDer::from(ED448_CERT.to_vec());
        let verifier = AcceptAll::new();
        let ed448_scheme = SignatureScheme::ED448;
        assert!(
            verifier
                .check(unsupported(), &p521, ed448_scheme, false)
                .is_err()
        );
        assert!(verifier.check(unsupported(), &ed448, mldsa, false).is_err());
        assert!(verifier.signature_verified());
        let p521_scheme = SignatureScheme::ECDSA_NISTP521_SHA512;
        assert!(
            verifier
                .check(unsupported(), &p521, p521_scheme, false)
                .is_ok()
        );
        assert!(!verifier.signature_verified());
        let verifier = AcceptAll::new();
        assert!(
            verifier
                .check(unsupported(), &ed448, ed448_scheme, false)
                .is_ok()
        );
        assert!(!verifier.signature_verified());

        // TLS 1.2 ECDSA schemes name only the hash, so P-256 with SHA-512 and
        // P-521 with SHA-256 fit; TLS 1.3 binds the curve.
        let verifier = AcceptAll::new();
        assert!(
            verifier
                .check(unsupported(), &p256, p521_scheme, false)
                .is_err()
        );
        assert!(verifier.check(unsupported(), &p521, ecdsa, false).is_err());
        assert!(
            verifier
                .check(unsupported(), &rsa1024, p521_scheme, true)
                .is_err()
        );
        assert!(verifier.signature_verified());
        assert!(
            verifier
                .check(unsupported(), &p256, p521_scheme, true)
                .is_ok()
        );
        assert!(!verifier.signature_verified());
        let verifier = AcceptAll::new();
        assert!(verifier.check(mismatch(), &p521, ecdsa, true).is_ok());
        assert!(!verifier.signature_verified());
    }

    /// Server that always presents one certificate and key, matching or not.
    #[derive(Debug)]
    struct WrongKey(Arc<rustls::sign::CertifiedKey>);

    impl rustls::server::ResolvesServerCert for WrongKey {
        /// Always returns the mismatched certificate and key.
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(Arc::clone(&self.0))
        }
    }

    /// A server that does not hold the key of its certificate fails the
    /// fetch over TLS 1.2 and 1.3.
    #[tokio::test]
    async fn rejects_wrong_handshake_key() {
        let key = PrivateKeyDer::try_from(WRONG_KEY.to_vec()).unwrap();
        let key = ring::sign::any_supported_type(&key).unwrap();
        let certified = Arc::new(rustls::sign::CertifiedKey::new(
            vec![CertificateDer::from(CERT.to_vec())],
            key,
        ));
        assert!(certified.keys_match().is_err());
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_protocol_versions(&[version])
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(WrongKey(Arc::clone(&certified))));
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (s, _) = listener.accept().await.unwrap();
                acceptor.accept(s).await.is_err()
            });
            let r = fetch_certificates(&Transport::new(addr), Some("localhost")).await;
            assert!(r.is_err(), "{version:?}: {r:?}");
            assert!(server.await.unwrap(), "{version:?}");
        }
    }

    /// Signing key that answers with a fixed ML-DSA-65 placeholder, standing
    /// in for a post-quantum server ring cannot sign for.
    #[derive(Debug)]
    struct FakeMlDsa;

    impl rustls::sign::SigningKey for FakeMlDsa {
        /// Signs with ML-DSA-65 when the client offers it.
        fn choose_scheme(
            &self,
            offered: &[SignatureScheme],
        ) -> Option<Box<dyn rustls::sign::Signer>> {
            offered
                .contains(&SignatureScheme::ML_DSA_65)
                .then(|| Box::new(FakeMlDsa) as Box<dyn rustls::sign::Signer>)
        }

        /// Not an algorithm rustls knows.
        fn algorithm(&self) -> rustls::SignatureAlgorithm {
            rustls::SignatureAlgorithm::Unknown(0x05)
        }
    }

    impl rustls::sign::Signer for FakeMlDsa {
        /// Returns placeholder bytes; the client cannot check them anyway.
        fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
            Ok(vec![0; 3309])
        }

        /// ML-DSA-65.
        fn scheme(&self) -> SignatureScheme {
            SignatureScheme::ML_DSA_65
        }
    }

    /// A TLS 1.3 server with an ML-DSA-65 certificate keeps its chain, marked
    /// as not verified.
    #[tokio::test]
    async fn accepts_unverifiable_handshake() {
        let certified = Arc::new(rustls::sign::CertifiedKey::new(
            vec![CertificateDer::from(MLDSA65_CERT.to_vec())],
            Arc::new(FakeMlDsa),
        ));
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(WrongKey(certified)));
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            if let Ok(mut tls) = acceptor.accept(s).await {
                let _ = tls.shutdown().await;
            }
        });
        let chain = fetch_certificates(&Transport::new(addr), Some("localhost"))
            .await
            .unwrap();
        assert_eq!(chain.certificates, vec![MLDSA65_CERT.to_vec()]);
        assert!(!chain.signature_verified);
    }

    /// TLS 1.3 handshake returns the leaf certificate and version.
    #[tokio::test]
    async fn fetches_chain_over_tls13() {
        let addr = serve(&[&rustls::version::TLS13]).await;
        let chain = fetch_certificates(&Transport::new(addr), Some("localhost"))
            .await
            .unwrap();
        assert_eq!(chain.version, ProtocolVersion::TLS13);
        assert_eq!(chain.certificates, vec![CERT.to_vec()]);
        assert_eq!(chain.ocsp_response, None);
        assert!(chain.signature_verified);
    }

    /// A stapled OCSP response is recorded over TLS 1.3 and TLS 1.2.
    #[tokio::test]
    async fn records_stapled_ocsp_response() {
        let ocsp = b"\x30\x03\x0a\x01\x00".to_vec();
        for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
            let addr = serve_with_ocsp(&[version], ocsp.clone()).await;
            let chain = fetch_certificates(&Transport::new(addr), Some("localhost"))
                .await
                .unwrap();
            assert_eq!(chain.ocsp_response.as_ref(), Some(&ocsp), "{version:?}");
        }
    }

    /// TLS 1.2 handshake works too, even without SNI.
    #[tokio::test]
    async fn fetches_chain_over_tls12_without_sni() {
        let addr = serve(&[&rustls::version::TLS12]).await;
        let chain = fetch_certificates(&Transport::new(addr), None)
            .await
            .unwrap();
        assert_eq!(chain.version, ProtocolVersion::TLS12);
        assert_eq!(chain.certificates, vec![CERT.to_vec()]);
        assert!(chain.signature_verified);
    }

    /// A non-TLS peer is reported as an I/O error, not a panic.
    #[tokio::test]
    async fn non_tls_server_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        });
        let r = fetch_certificates(&Transport::new(addr), None).await;
        assert!(matches!(r, Err(ProbeError::Io(_))), "{r:?}");
    }
}
