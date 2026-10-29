//! Opt-in revocation check against the certificate issuer's services.
//!
//! The OCSP responders named in the leaf certificate are asked first
//! (RFC 6960 Appendix A.1, `POST`); when none answers with a verifiable
//! response, the CRLs from its distribution points are downloaded
//! (RFC 5280 §4.2.1.13). Only `http://` URLs are used, as both RFCs expect.
//! The first verifiable answer ends the check.

use testls_checks::{
    RevocationCheck, RevocationMethod, RevocationUrls, ocsp_request, verify_crl,
    verify_ocsp_response,
};
use testls_probe::{Fetcher, HttpBody};

/// Largest accepted OCSP response; real responses are a few KiB.
pub const MAX_OCSP_RESPONSE: usize = 64 * 1024;

/// Largest accepted CRL; large public CAs publish CRLs of several MiB.
pub const MAX_CRL: usize = 16 * 1024 * 1024;

/// Most `http://` URLs tried per method, so a certificate listing many
/// cannot make the scan contact an unbounded number of hosts.
pub const MAX_URLS: usize = 4;

/// Queries the OCSP responders, then the CRL distribution points, in
/// `urls` until one gives a verifiable status for the leaf of `chain`.
///
/// Returns every attempt in order; URLs that are not `http://` are
/// skipped, and at most [`MAX_URLS`] are tried per method. `now` is the
/// current time as a Unix timestamp.
pub async fn check_revocation(
    fetcher: Fetcher,
    chain: &[Vec<u8>],
    urls: &RevocationUrls,
    now: i64,
) -> Vec<RevocationCheck> {
    let mut checks = Vec::new();
    let ocsp = Fetcher {
        max_body: MAX_OCSP_RESPONSE,
        ..fetcher.clone()
    };
    for url in urls.ocsp.iter().filter(|u| is_http(u)).take(MAX_URLS) {
        let outcome = match ocsp_request(chain) {
            Ok(request) => ok_body(ocsp.post(url, "application/ocsp-request", &request).await)
                .and_then(|body| verify_ocsp_response(&body, chain, now).map(Into::into)),
            Err(e) => Err(e),
        };
        let done = outcome.is_ok();
        checks.push(RevocationCheck {
            method: RevocationMethod::Ocsp,
            url: url.clone(),
            outcome,
        });
        if done {
            return checks;
        }
    }
    let crl = Fetcher {
        max_body: MAX_CRL,
        ..fetcher
    };
    for url in urls.crl.iter().filter(|u| is_http(u)).take(MAX_URLS) {
        let outcome = ok_body(crl.get(url).await).and_then(|body| verify_crl(&body, chain));
        let done = outcome.is_ok();
        checks.push(RevocationCheck {
            method: RevocationMethod::Crl,
            url: url.clone(),
            outcome,
        });
        if done {
            break;
        }
    }
    checks
}

/// Reports whether `url` uses the `http` scheme (case-insensitive).
fn is_http(url: &str) -> bool {
    url.get(..7)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"))
}

/// Returns the body of a `200 OK` reply, or why there is none.
fn ok_body(reply: Result<HttpBody, testls_probe::ProbeError>) -> Result<Vec<u8>, String> {
    match reply {
        Ok(reply) if reply.status == 200 => Ok(reply.body),
        Ok(reply) => Err(format!("HTTP status {}", reply.status)),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    //! Tests against local HTTP servers serving the generated OCSP fixtures
    //! (`scripts/gen-ocsp-fixtures.sh`).

    use std::net::SocketAddr;
    use std::time::Duration;

    use testls_checks::CertStatus;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;

    /// Leaf certificate the fixtures answer for.
    const LEAF: &[u8] = include_bytes!("../../testls-checks/src/testdata/ocsp-leaf.der");
    /// Issuer of [`LEAF`].
    const CA: &[u8] = include_bytes!("../../testls-checks/src/testdata/ocsp-ca.der");
    /// CA-signed OCSP response saying [`LEAF`] is good.
    const GOOD: &[u8] = include_bytes!("../../testls-checks/src/testdata/ocsp-good.der");
    /// CRL from [`CA`] that does not list [`LEAF`].
    const CRL: &[u8] = include_bytes!("../../testls-checks/src/testdata/ocsp-crl.der");

    /// Fetcher with short timeouts for local servers.
    fn fetcher() -> Fetcher {
        Fetcher {
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(2),
            max_body: 0,
            source: None,
            proxy: None,
            allowed_endpoints: vec![],
        }
    }

    /// Current Unix time.
    fn now() -> i64 {
        crate::unix_now()
    }

    /// Serves one HTTP reply with `status` and `body`, returning the server
    /// address and the request line it received.
    async fn serve(
        status: u16,
        body: &'static [u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 4096];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                request.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&request);
                if let Some(end) = text.find("\r\n\r\n") {
                    let length = text[..end]
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .map_or(0, |v| v.parse::<usize>().unwrap());
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            s.write_all(head.as_bytes()).await.unwrap();
            s.write_all(body).await.unwrap();
            let _ = s.shutdown().await;
            String::from_utf8_lossy(&request)
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned()
        });
        (addr, task)
    }

    /// A good OCSP answer ends the check before any CRL is fetched.
    #[tokio::test]
    async fn responder_first() {
        let (addr, server) = serve(200, GOOD).await;
        let urls = RevocationUrls {
            ocsp: vec![format!("http://{addr}/ocsp")],
            crl: vec!["http://127.0.0.1:9/never.crl".into()],
        };
        let checks = check_revocation(
            Fetcher {
                allowed_endpoints: vec![addr],
                ..fetcher()
            },
            &[LEAF.to_vec(), CA.to_vec()],
            &urls,
            now(),
        )
        .await;
        assert_eq!(server.await.unwrap(), "POST /ocsp HTTP/1.1");
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].method, RevocationMethod::Ocsp);
        assert_eq!(checks[0].outcome.as_ref().unwrap().status, CertStatus::Good);
    }

    /// A failing responder falls back to the CRL; non-HTTP URLs are
    /// skipped.
    #[tokio::test]
    async fn crl_fallback() {
        let (ocsp_addr, ocsp_server) = serve(500, b"").await;
        let (crl_addr, crl_server) = serve(200, CRL).await;
        let urls = RevocationUrls {
            ocsp: vec![format!("http://{ocsp_addr}/")],
            crl: vec![
                "ldap://crl.example.test/ca".into(),
                format!("HTTP://{crl_addr}/ca.crl"),
            ],
        };
        let checks = check_revocation(
            Fetcher {
                allowed_endpoints: vec![ocsp_addr, crl_addr],
                ..fetcher()
            },
            &[LEAF.to_vec(), CA.to_vec()],
            &urls,
            now(),
        )
        .await;
        assert_eq!(ocsp_server.await.unwrap(), "POST / HTTP/1.1");
        assert_eq!(crl_server.await.unwrap(), "GET /ca.crl HTTP/1.1");
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].outcome.as_ref().unwrap_err(), "HTTP status 500");
        assert_eq!(checks[1].method, RevocationMethod::Crl);
        assert_eq!(checks[1].outcome.as_ref().unwrap().status, CertStatus::Good);
    }

    /// Without an issuer nothing can be verified, and every URL is tried.
    #[tokio::test]
    async fn missing_issuer() {
        let urls = RevocationUrls {
            ocsp: vec!["http://127.0.0.1:9/".into()],
            crl: vec![],
        };
        let checks = check_revocation(fetcher(), &[LEAF.to_vec()], &urls, now()).await;
        assert_eq!(checks.len(), 1);
        assert_eq!(
            checks[0].outcome.as_ref().unwrap_err(),
            "issuer certificate missing from chain"
        );
    }

    /// At most [`MAX_URLS`] URLs are tried per method.
    #[tokio::test]
    async fn url_limit() {
        let many: Vec<String> = (0..10).map(|i| format!("http://127.0.0.1:9/{i}")).collect();
        let urls = RevocationUrls {
            ocsp: many.clone(),
            crl: vec![],
        };
        let checks = check_revocation(fetcher(), &[LEAF.to_vec()], &urls, now()).await;
        assert_eq!(checks.len(), MAX_URLS);
        assert_eq!(checks[MAX_URLS - 1].url, many[MAX_URLS - 1]);
    }

    /// Only the `http` scheme is accepted.
    #[test]
    fn http_scheme() {
        assert!(is_http("http://a/"));
        assert!(is_http("HtTp://a/"));
        assert!(!is_http("https://a/"));
        assert!(!is_http("ldap://a"));
        assert!(!is_http("http:"));
    }
}
