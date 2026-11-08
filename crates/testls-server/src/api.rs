//! Routes, request checks and handlers of the REST API.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HOST, LOCATION,
    REFERRER_POLICY, WWW_AUTHENTICATE, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{self, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use testls_checks::{Policy, Severity};
use testls_probe::{Starttls, Transport, public_address};
use testls_report::{Format, Painter, csv, html, json, junit, markdown, sarif, text};
use testls_scan::target::{self, Host, Target};
use testls_scan::{Event, Options, ScanProfile};
use tokio::sync::{OwnedSemaphorePermit, watch};

use crate::history::{Finished, Section, Status};
use crate::{Config, Shared};

/// Policy for API responses: nothing may load, and no page may frame them.
const API_POLICY: &str = "default-src 'none'; frame-ancestors 'none'";

/// Policy for the HTML report, which carries its own inline styles.
const HTML_POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'";

/// Largest request body accepted; a scan request needs a few hundred bytes.
const MAX_BODY: usize = 16 * 1024;

/// Builds the router over `shared`.
pub(crate) fn routes(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/scans", get(list).post(start))
        .route("/scans/{id}", get(show))
        .route("/scans/{id}/events", get(events))
        .route("/scans/{id}/report", get(report))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(Arc::clone(&shared), guard))
        .with_state(shared)
}

/// An error answered as `{"error": message}` with a status code.
#[derive(Debug)]
struct ApiError(StatusCode, String);

impl ApiError {
    /// A 400 Bad Request with `message`.
    fn bad(message: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, message.into())
    }

    /// A 404 for a scan id the history does not hold.
    fn not_found() -> Self {
        Self(StatusCode::NOT_FOUND, "no such scan".to_owned())
    }
}

impl IntoResponse for ApiError {
    /// Renders the error as JSON.
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

/// Rejects unauthorised requests and adds security headers to every
/// response.
async fn guard(State(shared): State<Arc<Shared>>, request: Request, next: Next) -> Response {
    let response = match authorize(&shared.config, request.headers()) {
        Ok(()) => next.run(request).await,
        Err(e) => {
            let unauthorized = e.0 == StatusCode::UNAUTHORIZED;
            let mut response = e.into_response();
            if unauthorized {
                response
                    .headers_mut()
                    .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            }
            response
        }
    };
    harden(response)
}

/// Adds headers that keep browsers from sniffing, framing, caching or
/// leaking responses. Handlers may set a looser content policy first.
fn harden(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers
        .entry(CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static(API_POLICY));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Checks the bearer token when one is configured; otherwise the `Host`
/// header must name the loopback interface, which defeats DNS rebinding.
fn authorize(config: &Config, headers: &HeaderMap) -> Result<(), ApiError> {
    if let Some(token) = &config.token {
        let given = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        return if given.is_some_and(|g| same(g.as_bytes(), token.as_bytes())) {
            Ok(())
        } else {
            Err(ApiError(
                StatusCode::UNAUTHORIZED,
                "missing or wrong token".to_owned(),
            ))
        };
    }
    let host = headers.get(HOST).and_then(|v| v.to_str().ok());
    if host.is_some_and(loopback_host) {
        Ok(())
    } else {
        Err(ApiError(
            StatusCode::FORBIDDEN,
            "without a token only loopback hosts are served".to_owned(),
        ))
    }
}

/// Compares two byte strings in time that depends only on their lengths.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Whether a `Host` header value names the loopback interface, with or
/// without a port.
fn loopback_host(host: &str) -> bool {
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split_once(']').map_or(rest, |(name, _)| name)
    } else {
        host.split_once(':').map_or(host, |(name, _)| name)
    };
    name.eq_ignore_ascii_case("localhost")
        || name.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Body of `POST /scans`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanRequest {
    /// Host name or IP address, optionally with `:port`.
    target: String,
    /// STARTTLS protocol to upgrade with, such as `smtp`.
    starttls: Option<String>,
    /// SNI name; defaults to the target's host name.
    sni: Option<String>,
    /// Scan depth: `quick`, `default` or `full`.
    profile: Option<String>,
    /// Check the certificates for revocation.
    #[serde(default)]
    revocation: bool,
    /// Compliance policies to check against.
    #[serde(default)]
    policies: Vec<String>,
}

/// A scan request whose values all parsed.
#[derive(Debug)]
struct Parsed {
    /// Host and port to scan.
    target: Target,
    /// STARTTLS protocol, if any.
    starttls: Option<Starttls>,
    /// Options for the scan pipeline.
    options: Options,
}

impl ScanRequest {
    /// Parses the request values, naming the first bad one.
    fn parse(self) -> Result<Parsed, ApiError> {
        let starttls = self
            .starttls
            .as_deref()
            .map(str::parse::<Starttls>)
            .transpose()
            .map_err(ApiError::bad)?;
        let port = starttls.map_or(target::DEFAULT_PORT, Starttls::default_port);
        let target = Target::parse_with_port(self.target.trim(), port)
            .map_err(|e| ApiError::bad(format!("{}: {e}", self.target)))?;
        let mut options = Options::default();
        if let Some(profile) = self.profile.as_deref() {
            options.profile = profile.parse::<ScanProfile>().map_err(ApiError::bad)?;
        }
        for name in &self.policies {
            let policy = name.parse::<Policy>().map_err(ApiError::bad)?;
            if !options.policies.contains(&policy) {
                options.policies.push(policy);
            }
        }
        options.revocation = self.revocation;
        options.sni = match self.sni.as_deref().filter(|s| !s.is_empty()) {
            // Probes put the SNI into plaintext `Host` headers, so it must
            // be a plain host name.
            Some(sni) => {
                Some(target::host_name(sni).map_err(|e| ApiError::bad(format!("sni: {e}")))?)
            }
            None => target.default_sni().map(str::to_owned),
        };
        Ok(Parsed {
            target,
            starttls,
            options,
        })
    }
}

/// Reply to `POST /scans`.
#[derive(Debug, Serialize)]
struct Started {
    /// Id of the new scan.
    id: u64,
    /// Always `running`.
    status: Status,
}

/// `POST /scans`: checks the request and limits, then starts the scan in
/// the background and answers 202 with its id.
async fn start(
    State(shared): State<Arc<Shared>>,
    Json(request): Json<ScanRequest>,
) -> Result<Response, ApiError> {
    let parsed = request.parse()?;
    let config = &shared.config;
    // Limits come before the name lookup, so refused requests cost no DNS
    // work and a lookup counts against both limits.
    let permit = Arc::clone(&shared.slots).try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too many scans running".to_owned(),
        )
    })?;
    if !shared.admit(Instant::now()) {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too many scans started in the last minute".to_owned(),
        ));
    }
    let addr = resolve(&parsed.target, config).await?;
    if !config.allow_private && !public_address(addr.ip()) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            format!("{} is not a public address", addr.ip()),
        ));
    }
    let name = parsed.target.to_string();
    let header = text::header(&name, addr, parsed.options.sni.as_deref());
    let id = shared
        .history
        .insert(name.clone(), header, testls_scan::unix_now())
        .ok_or_else(|| {
            ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "history is full of running scans".to_owned(),
            )
        })?;
    let mut transport = Transport::new(addr);
    transport.connect_timeout = config.connect_timeout;
    transport.read_timeout = config.read_timeout;
    transport.starttls = parsed.starttls;
    let mut options = parsed.options;
    options.revocation_allow_private = config.allow_private;
    tokio::spawn(run(
        Arc::clone(&shared),
        id,
        name,
        transport,
        options,
        permit,
    ));
    let location = HeaderValue::from_str(&format!("/scans/{id}"))
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let status = Status::Running;
    Ok((
        StatusCode::ACCEPTED,
        [(LOCATION, location)],
        Json(Started { id, status }),
    )
        .into_response())
}

/// Resolves the target to the first address the resolver returns, so the
/// address checked against the private-range block is the one scanned.
async fn resolve(target: &Target, config: &Config) -> Result<SocketAddr, ApiError> {
    match &target.host {
        Host::Ip(ip) => Ok(SocketAddr::new(*ip, target.port)),
        Host::Name(name) => {
            let lookup = tokio::net::lookup_host((name.as_str(), target.port));
            let mut addrs = tokio::time::timeout(config.connect_timeout, lookup)
                .await
                .map_err(|_| ApiError::bad(format!("{name}: name lookup timed out")))?
                .map_err(|e| ApiError::bad(format!("{name}: {e}")))?;
            addrs
                .next()
                .ok_or_else(|| ApiError::bad(format!("{name}: no addresses")))
        }
    }
}

/// Runs one scan, recording each section as it finishes and the report or
/// error at the end. Holds `_permit` until done.
async fn run(
    shared: Arc<Shared>,
    id: u64,
    target: String,
    transport: Transport,
    options: Options,
    _permit: OwnedSemaphorePermit,
) {
    let mut on_event = {
        let shared = Arc::clone(&shared);
        move |event: Event<'_>| shared.history.push(id, section(event))
    };
    let config = &shared.config;
    let scan = testls_scan::scan(transport, &options, &config.trust_store, &mut on_event);
    match tokio::time::timeout(config.scan_timeout, scan).await {
        Ok(Ok(scan)) => shared.history.finish(id, finished(&target, &scan)),
        Ok(Err(e)) => shared.history.fail(id, e.to_string()),
        Err(_) => shared.history.fail(
            id,
            format!("scan timed out after {}s", config.scan_timeout.as_secs()),
        ),
    }
}

/// A section event as sent to clients.
fn section(event: Event<'_>) -> Section {
    Section {
        name: event.section(),
        version: event.version().map(|v| v.to_string()),
        text: event.text(Painter::new(false)),
    }
}

/// Report data for a finished scan. Findings are triaged as in the CLI:
/// `ok` ones dropped, the rest most severe first.
fn finished(target: &str, scan: &testls_scan::Scan) -> Finished {
    let mut findings = scan.findings.clone();
    findings.retain(|f| f.severity > Severity::Ok);
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let paint = Painter::new(false);
    let tail = format!(
        "\n{}{}",
        text::findings(&findings, paint),
        text::grade(&scan.grade, paint)
    );
    let report = json::Report {
        target,
        addr: scan.addr,
        sni: scan.sni.as_deref(),
        started_at: scan.started_at,
        protocols: &scan.protocols,
        ciphers: &scan.ciphers,
        key_exchange: &scan.key_exchange,
        post_quantum: &scan.post_quantum,
        certificate: &scan.certificate,
        http: &scan.http,
        revocation: scan.revocation.as_ref(),
        vulnerabilities: &scan.vulnerabilities,
        intolerance: &scan.intolerance,
        details: &scan.details,
        grade: &scan.grade,
        findings: &findings,
        suppressed: &[],
    };
    Finished {
        json: json::render(&report),
        tail,
        summary: sarif::Scan {
            target: target.to_owned(),
            addr: scan.addr,
            grade: scan.grade.clone(),
            findings,
        },
    }
}

/// One entry of `GET /scans`.
#[derive(Debug, Serialize)]
struct Summary {
    /// Scan id.
    id: u64,
    /// Target as `host:port`.
    target: String,
    /// Unix time the scan was requested.
    created_at: i64,
    /// Where the scan stands.
    status: Status,
    /// Grade letter once done, such as `A+`.
    #[serde(skip_serializing_if = "Option::is_none")]
    grade: Option<String>,
}

/// `GET /scans`: kept scans, newest first.
async fn list(State(shared): State<Arc<Shared>>) -> Json<Vec<Summary>> {
    let guard = shared.history.lock();
    Json(
        guard
            .0
            .iter()
            .rev()
            .map(|r| Summary {
                id: r.id,
                target: r.target.clone(),
                created_at: r.created_at,
                status: r.status,
                grade: r
                    .finished
                    .as_ref()
                    .map(|f| f.summary.grade.letter.as_str().to_owned()),
            })
            .collect(),
    )
}

/// `GET /scans/{id}`: one scan with its sections so far, the error if it
/// failed and the JSON report once done.
async fn show(
    State(shared): State<Arc<Shared>>,
    Path(id): Path<u64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    shared
        .history
        .with(id, |r| {
            let report = r
                .finished
                .as_ref()
                .and_then(|f| serde_json::from_str::<serde_json::Value>(&f.json).ok());
            Json(serde_json::json!({
                "id": r.id,
                "target": r.target,
                "created_at": r.created_at,
                "status": r.status,
                "header": r.header,
                "sections": r.sections,
                "error": r.error,
                "report": report,
            }))
        })
        .ok_or_else(ApiError::not_found)
}

/// Cursor of one progress stream.
#[derive(Debug)]
struct Progress {
    /// Service state.
    shared: Arc<Shared>,
    /// Scan being followed.
    id: u64,
    /// Wakes when the scan changes; closes when it leaves the history.
    changed: watch::Receiver<()>,
    /// Sections already sent.
    sent: usize,
    /// Whether the final event went out.
    done: bool,
    /// Stream slot, freed when the response body is dropped.
    _permit: OwnedSemaphorePermit,
}

/// What the stream sends next.
enum Step {
    /// A section not yet sent.
    Section(Section),
    /// The scan is still running with nothing new.
    Wait,
    /// The scan ended with this status and error.
    End(Status, Option<String>),
}

impl Progress {
    /// Waits for the next event: each section once, then `done` with the
    /// final status. Ends when the scan leaves the history.
    async fn next(mut self) -> Option<(Result<sse::Event, Infallible>, Self)> {
        loop {
            if self.done {
                return None;
            }
            self.changed.mark_unchanged();
            let step = self.shared.history.with(self.id, |r| {
                match (r.sections.get(self.sent), r.status) {
                    (Some(s), _) => Step::Section(s.clone()),
                    (None, Status::Running) => Step::Wait,
                    (None, status) => Step::End(status, r.error.clone()),
                }
            })?;
            match step {
                Step::Section(section) => {
                    let event = sse::Event::default()
                        .event("section")
                        .id(self.sent.to_string())
                        .json_data(&section)
                        .unwrap_or_default();
                    self.sent += 1;
                    return Some((Ok(event), self));
                }
                Step::Wait => self.changed.changed().await.ok()?,
                Step::End(status, error) => {
                    let event = sse::Event::default()
                        .event("done")
                        .json_data(serde_json::json!({ "status": status, "error": error }))
                        .unwrap_or_default();
                    self.done = true;
                    return Some((Ok(event), self));
                }
            }
        }
    }
}

/// `GET /scans/{id}/events`: progress as server-sent events. A
/// `section` event carries each finished section; a final `done` event
/// carries the status. Reconnecting clients resume after `Last-Event-ID`.
/// At most `max_streams` streams are open at once; each ends with its
/// scan.
async fn events(
    State(shared): State<Arc<Shared>>,
    Path(id): Path<u64>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<sse::Event, Infallible>>>, ApiError> {
    let changed = shared
        .history
        .subscribe(id)
        .ok_or_else(ApiError::not_found)?;
    let permit = Arc::clone(&shared.streams)
        .try_acquire_owned()
        .map_err(|_| {
            ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "too many progress streams open".to_owned(),
            )
        })?;
    let sent = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .map_or(0, |last| last.saturating_add(1));
    let progress = Progress {
        shared,
        id,
        changed,
        sent,
        done: false,
        _permit: permit,
    };
    let stream = futures_util::stream::unfold(progress, Progress::next);
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// Query of `GET /scans/{id}/report`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportQuery {
    /// Output format; `json` by default.
    format: Option<String>,
    /// Severity at which the summary formats count a finding as failing;
    /// `high` by default.
    fail_on: Option<String>,
}

/// `GET /scans/{id}/report`: the report of a finished scan in any CLI
/// output format.
async fn report(
    State(shared): State<Arc<Shared>>,
    Path(id): Path<u64>,
    Query(query): Query<ReportQuery>,
) -> Result<Response, ApiError> {
    let format = query
        .format
        .as_deref()
        .map(str::parse::<Format>)
        .transpose()
        .map_err(|e| ApiError::bad(e.to_string()))?
        .unwrap_or(Format::Json);
    let fail_on = query
        .fail_on
        .as_deref()
        .map(str::parse::<Severity>)
        .transpose()
        .map_err(|e| ApiError::bad(e.to_string()))?
        .unwrap_or(Severity::High);
    let body = shared
        .history
        .with(id, |r| {
            let finished = r.finished.as_ref()?;
            let scans = std::slice::from_ref(&finished.summary);
            Some(match format {
                Format::Text => {
                    let mut out = r.header.clone();
                    for s in &r.sections {
                        out.push('\n');
                        out.push_str(&s.text);
                    }
                    out + &finished.tail
                }
                Format::Json => finished.json.clone(),
                Format::Sarif => sarif::render(scans, true),
                Format::Junit => junit::render(scans, &[], fail_on),
                Format::Markdown => markdown::render(scans, &[], fail_on),
                Format::Csv => csv::render(scans, &[], fail_on),
                Format::Html => html::render(scans, &[], fail_on),
            })
        })
        .ok_or_else(ApiError::not_found)?
        .ok_or_else(|| ApiError(StatusCode::CONFLICT, "scan has no report".to_owned()))?;
    let content_type = match format {
        Format::Text => "text/plain; charset=utf-8",
        Format::Json => "application/json",
        Format::Sarif => "application/sarif+json",
        Format::Junit => "application/xml",
        Format::Markdown => "text/markdown; charset=utf-8",
        Format::Csv => "text/csv; charset=utf-8",
        Format::Html => "text/html; charset=utf-8",
    };
    let mut response = ([(CONTENT_TYPE, content_type)], body).into_response();
    if format == Format::Html {
        response.headers_mut().insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(HTML_POLICY),
        );
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    //! Unit tests for the request checks and handlers.

    use std::time::Duration;

    use axum::body::{Body, to_bytes};
    use axum::http::Method;
    use tower::ServiceExt;

    use super::*;
    use crate::router;

    /// Sends one request to a fresh copy of `app`, with `Host: localhost`
    /// unless `headers` names another, and returns status, headers and body.
    async fn send(
        app: &Router,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> (StatusCode, HeaderMap, String) {
        let mut request = Request::builder().method(method).uri(uri);
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
            request = request.header(HOST, "localhost:8080");
        }
        for (k, v) in headers {
            request = request.header(*k, *v);
        }
        let request = match body {
            Some(b) => request
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(b.to_owned())),
            None => request.body(Body::empty()),
        }
        .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    /// Settings that allow scanning the loopback interface.
    fn private() -> Config {
        Config {
            allow_private: true,
            connect_timeout: Duration::from_secs(1),
            ..Config::default()
        }
    }

    /// Loopback host names pass with and without ports; others fail.
    #[test]
    fn loopback_hosts() {
        for host in [
            "localhost",
            "LOCALHOST:80",
            "127.0.0.1:8080",
            "[::1]:80",
            "[::1]",
        ] {
            assert!(loopback_host(host), "{host}");
        }
        for host in [
            "example.com",
            "evil.localhost.example",
            "10.0.0.1:80",
            "[::2]",
        ] {
            assert!(!loopback_host(host), "{host}");
        }
        assert!(same(b"abc", b"abc"));
        assert!(!same(b"abc", b"abd"));
        assert!(!same(b"abc", b"abcd"));
    }

    /// Without a token, only loopback `Host` headers are served, and every
    /// response carries the security headers.
    #[tokio::test]
    async fn host_check() {
        let app = router(Config::default());
        let (status, headers, body) = send(&app, Method::GET, "/scans", &[], None).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "[]"));
        assert_eq!(headers[CONTENT_SECURITY_POLICY], API_POLICY);
        assert_eq!(headers[X_CONTENT_TYPE_OPTIONS], "nosniff");
        let (status, headers, _) = send(
            &app,
            Method::GET,
            "/scans",
            &[("host", "attacker.example")],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(headers[CONTENT_SECURITY_POLICY], API_POLICY);
    }

    /// With a token, every request must carry it, whatever the host.
    #[tokio::test]
    async fn token_check() {
        let app = router(Config {
            token: Some("s3cret".to_owned()),
            ..Config::default()
        });
        let (status, headers, _) = send(&app, Method::GET, "/scans", &[], None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers[WWW_AUTHENTICATE], "Bearer");
        let wrong = [("authorization", "Bearer s3cre")];
        let (status, _, _) = send(&app, Method::GET, "/scans", &wrong, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let right = [
            ("authorization", "Bearer s3cret"),
            ("host", "scanner.example"),
        ];
        let (status, _, _) = send(&app, Method::GET, "/scans", &right, None).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// Bad values are named in a 400 reply.
    #[tokio::test]
    async fn bad_requests() {
        let app = router(private());
        for (body, needle) in [
            (r#"{"target":"a b c"}"#, "a b c"),
            (r#"{"target":"localhost","profile":"deep"}"#, "deep"),
            (r#"{"target":"localhost","starttls":"gopher"}"#, "gopher"),
            (r#"{"target":"localhost","policies":["nope"]}"#, "nope"),
            (r#"{"target":"localhost","sni":"a\r\nX-Evil: 1"}"#, "sni"),
            (r#"{"target":"localhost","sni":"a b"}"#, "sni"),
        ] {
            let (status, _, reply) = send(&app, Method::POST, "/scans", &[], Some(body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(reply.contains(needle), "{reply}");
        }
        let unknown = r#"{"target":"localhost","color":true}"#;
        let (status, _, _) = send(&app, Method::POST, "/scans", &[], Some(unknown)).await;
        assert!(status.is_client_error());
        let (status, _, _) = send(&app, Method::GET, "/scans/7", &[], None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, _) = send(&app, Method::GET, "/scans/7/events", &[], None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let huge = format!(
            r#"{{"target":"localhost","sni":"{}"}}"#,
            "a".repeat(MAX_BODY)
        );
        let (status, _, _) = send(&app, Method::POST, "/scans", &[], Some(&huge)).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// Repeated policies count once, and SNI values are normalised.
    #[test]
    fn request_values() {
        let request: ScanRequest = serde_json::from_str(
            r#"{"target":"example.com","sni":"WWW.Example.com.",
                "policies":["pci-dss-4","pci-dss-4","cnsa-2.0","pci-dss-4"]}"#,
        )
        .unwrap();
        let parsed = request.parse().unwrap();
        assert_eq!(parsed.options.policies, [Policy::PciDss4, Policy::Cnsa2]);
        assert_eq!(parsed.options.sni.as_deref(), Some("www.example.com"));
    }

    /// A listener on the loopback interface that accepts connections and
    /// never answers, so scans against it stay running.
    async fn stalled() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        addr
    }

    /// Private targets are refused unless allowed.
    #[tokio::test]
    async fn private_targets() {
        let app = router(Config::default());
        for target in ["127.0.0.1:9", "10.1.2.3", "[::1]:443"] {
            let body = format!(r#"{{"target":"{target}"}}"#);
            let (status, _, reply) = send(&app, Method::POST, "/scans", &[], Some(&body)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{target}");
            assert!(reply.contains("not a public address"), "{reply}");
        }
    }

    /// A scan of a closed port runs in the background, streams its
    /// protocols section and fails without a report.
    #[tokio::test]
    async fn failed_scan() {
        let app = router(private());
        let body = r#"{"target":"127.0.0.1:9","profile":"quick"}"#;
        let (status, headers, reply) = send(&app, Method::POST, "/scans", &[], Some(body)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(headers[LOCATION], "/scans/1");
        assert_eq!(reply, r#"{"id":1,"status":"running"}"#);

        let (status, headers, stream) = send(&app, Method::GET, "/scans/1/events", &[], None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[CONTENT_TYPE], "text/event-stream");
        assert!(stream.contains("event: section\n"), "{stream}");
        assert!(stream.contains(r#""section":"protocols""#), "{stream}");
        assert!(
            stream.contains(r#"{"error":"no protocol could be tested","status":"failed"}"#),
            "{stream}"
        );
        let resumed = [("last-event-id", "0")];
        let (_, _, rest) = send(&app, Method::GET, "/scans/1/events", &resumed, None).await;
        assert!(!rest.contains("event: section"), "{rest}");
        assert!(rest.contains("event: done"), "{rest}");

        let (status, _, scan) = send(&app, Method::GET, "/scans/1", &[], None).await;
        assert_eq!(status, StatusCode::OK);
        let scan: serde_json::Value = serde_json::from_str(&scan).unwrap();
        assert_eq!(scan["status"], "failed");
        assert_eq!(scan["target"], "127.0.0.1:9");
        assert_eq!(scan["sections"][0]["section"], "protocols");
        assert!(scan["report"].is_null());

        let (_, _, list) = send(&app, Method::GET, "/scans", &[], None).await;
        assert!(list.contains(r#""status":"failed""#), "{list}");
        let (status, _, _) = send(&app, Method::GET, "/scans/1/report", &[], None).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, _, _) = send(&app, Method::GET, "/scans/1/report?format=pdf", &[], None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// Scans beyond the concurrency limit are refused before the target
    /// name is looked up, and progress streams beyond their limit too.
    #[tokio::test]
    async fn concurrency_limit() {
        let app = router(Config {
            max_concurrent: 1,
            max_streams: 1,
            read_timeout: Duration::from_secs(30),
            ..private()
        });
        let body = format!(r#"{{"target":"{}"}}"#, stalled().await);
        let (status, _, _) = send(&app, Method::POST, "/scans", &[], Some(&body)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        // A name that cannot resolve: a 429 rather than a 400 shows the
        // limit is checked first.
        let unresolvable = r#"{"target":"scan.invalid"}"#;
        let (status, _, reply) = send(&app, Method::POST, "/scans", &[], Some(unresolvable)).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(reply.contains("too many scans running"), "{reply}");

        let request = Request::builder()
            .uri("/scans/1/events")
            .header(HOST, "localhost")
            .body(Body::empty())
            .unwrap();
        let open = app.clone().oneshot(request).await.unwrap();
        assert_eq!(open.status(), StatusCode::OK);
        let (status, _, reply) = send(&app, Method::GET, "/scans/1/events", &[], None).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(reply.contains("too many progress streams"), "{reply}");
        drop(open);
        let request = Request::builder()
            .uri("/scans/1/events")
            .header(HOST, "localhost")
            .body(Body::empty())
            .unwrap();
        let reopened = app.clone().oneshot(request).await.unwrap();
        assert_eq!(reopened.status(), StatusCode::OK);
    }

    /// Scans beyond the rate limit are refused before the target name is
    /// looked up.
    #[tokio::test]
    async fn rate_limit_first() {
        let app = router(Config {
            max_per_minute: 1,
            ..private()
        });
        let body = r#"{"target":"127.0.0.1:9","profile":"quick"}"#;
        let (status, _, _) = send(&app, Method::POST, "/scans", &[], Some(body)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let unresolvable = r#"{"target":"scan.invalid"}"#;
        let (status, _, reply) = send(&app, Method::POST, "/scans", &[], Some(unresolvable)).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(reply.contains("last minute"), "{reply}");
    }

    /// A scan that outlives `scan_timeout` fails and frees its slot.
    #[tokio::test]
    async fn timeout_frees_slot() {
        let app = router(Config {
            max_concurrent: 1,
            scan_timeout: Duration::from_millis(200),
            read_timeout: Duration::from_secs(30),
            ..private()
        });
        let body = format!(r#"{{"target":"{}"}}"#, stalled().await);
        let (status, _, _) = send(&app, Method::POST, "/scans", &[], Some(&body)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (_, _, stream) = send(&app, Method::GET, "/scans/1/events", &[], None).await;
        assert!(stream.contains("scan timed out"), "{stream}");
        let (status, _, _) = send(&app, Method::POST, "/scans", &[], Some(&body)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }
}
