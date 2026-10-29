//! Certificate chain retrieval over a full rustls handshake.
//!
//! The verifier accepts every chain but verifies handshake signatures. It
//! records what the server presents; trust is evaluated later by the checks.

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
}

/// Completes a TLS 1.2/1.3 handshake and returns the server's certificate
/// chain without validating it.
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

/// Verifier that accepts certificate chains, verifies possession of the key,
/// and records the stapled OCSP response.
#[derive(Debug)]
struct AcceptAll {
    /// Provider whose signature schemes are advertised.
    provider: Arc<CryptoProvider>,
    /// Stapled OCSP response seen during the handshake.
    ocsp_response: Mutex<Option<Vec<u8>>>,
}

impl AcceptAll {
    /// Verifier using the ring provider, with nothing recorded yet.
    fn new() -> Self {
        Self {
            provider: Arc::new(ring::default_provider()),
            ocsp_response: Mutex::new(None),
        }
    }

    /// Takes the recorded stapled OCSP response, if any.
    fn take_ocsp_response(&self) -> Option<Vec<u8>> {
        self.ocsp_response
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
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

    /// Verifies the TLS 1.2 handshake signature with the leaf public key.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    /// Verifies the TLS 1.3 handshake signature with the leaf public key.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    /// Advertises only schemes whose handshake signatures can be verified.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ServerConfig;
    use rustls::pki_types::PrivateKeyDer;
    use std::net::SocketAddr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    /// Self-signed P-256 certificate for `localhost` (valid until 2126).
    const CERT: &[u8] = include_bytes!("testdata/localhost.cert.der");
    /// PKCS#8 private key for [`CERT`].
    const KEY: &[u8] = include_bytes!("testdata/localhost.key.der");

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

    /// Unverifiable algorithms are not negotiated.
    #[test]
    fn advertises_only_verifiable_schemes() {
        let schemes = AcceptAll::new().supported_verify_schemes();
        assert_eq!(
            schemes,
            ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        );
        assert!(!schemes.contains(&SignatureScheme::ML_DSA_44));
    }

    /// Resolver deliberately bypassing the server builder's key-match check.
    #[derive(Debug)]
    struct WrongKey(Arc<rustls::sign::CertifiedKey>);

    impl rustls::server::ResolvesServerCert for WrongKey {
        /// Presents the test certificate with an unrelated signing key.
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(Arc::clone(&self.0))
        }
    }

    /// Both protocol versions reject a signature from the wrong private key.
    #[tokio::test]
    async fn rejects_wrong_handshake_key() {
        let key =
            PrivateKeyDer::try_from(include_bytes!("testdata/wrong.key.der").to_vec()).unwrap();
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
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                TlsAcceptor::from(Arc::new(config))
                    .accept(stream)
                    .await
                    .is_err()
            });
            assert!(
                fetch_certificates(&Transport::new(addr), Some("localhost"))
                    .await
                    .is_err()
            );
            assert!(server.await.unwrap());
        }
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
