//! Embedded browser UI: one page with its script and style sheet, compiled
//! into the binary. The page uses the REST API like any other client.

use axum::Router;
use axum::http::HeaderValue;
use axum::http::header::{CONTENT_SECURITY_POLICY, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

/// Policy for the UI: script, styles and requests from this origin only, no
/// inline code, no plugins, no forms posting elsewhere, no framing.
pub(crate) const UI_POLICY: &str = "default-src 'none'; script-src 'self'; \
     style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; \
     frame-ancestors 'none'";

/// Paths the UI is served from. They hold no scan data, so they are served
/// without a token; the page asks for one before calling the API.
pub(crate) const PATHS: [&str; 3] = ["/", "/ui/app.js", "/ui/app.css"];

/// The page.
const INDEX: &str = include_str!("../ui/index.html");

/// The script, plain JavaScript without a build step.
const SCRIPT: &str = include_str!("../ui/app.js");

/// The style sheet.
const STYLE: &str = include_str!("../ui/app.css");

/// Routes serving the UI files.
pub(crate) fn routes<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route(
            PATHS[0],
            get(|| async { asset("text/html; charset=utf-8", INDEX) }),
        )
        .route(
            PATHS[1],
            get(|| async { asset("text/javascript; charset=utf-8", SCRIPT) }),
        )
        .route(
            PATHS[2],
            get(|| async { asset("text/css; charset=utf-8", STYLE) }),
        )
}

/// One UI file with its content type and the UI content policy.
fn asset(content_type: &'static str, body: &'static str) -> Response {
    let mut response = ([(CONTENT_TYPE, content_type)], body).into_response();
    response
        .headers_mut()
        .insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(UI_POLICY));
    response
}

#[cfg(test)]
mod tests {
    //! Checks on the embedded files.

    use super::*;

    /// The script never parses markup from strings, so scanned text cannot
    /// inject elements; the page loads nothing inline.
    #[test]
    fn no_markup_sinks() {
        for sink in [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function",
        ] {
            assert!(!SCRIPT.contains(sink), "app.js uses {sink}");
        }
        assert!(!INDEX.contains("<script>"), "inline script");
        assert!(!INDEX.contains("style="), "inline style");
        assert!(!INDEX.contains("<style"), "inline style sheet");
        assert!(
            !INDEX
                .split_whitespace()
                .any(|w| w.starts_with("on") && w.contains('=')),
            "inline event handler"
        );
    }

    /// The page references the script and style sheet by their paths.
    #[test]
    fn page_links_assets() {
        assert!(INDEX.contains(r#"src="/ui/app.js""#));
        assert!(INDEX.contains(r#"href="/ui/app.css""#));
    }
}
