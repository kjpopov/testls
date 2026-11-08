//! HTTP service behind `testls serve`: starts scans through a small REST API,
//! streams their progress as server-sent events and keeps a bounded
//! in-memory history of reports.
//!
//! | Method | Path | Purpose |
//! | --- | --- | --- |
//! | `POST` | `/scans` | Start a scan |
//! | `GET` | `/scans` | List kept scans, newest first |
//! | `GET` | `/scans/{id}` | One scan with its sections and JSON report |
//! | `GET` | `/scans/{id}/events` | Progress as server-sent events |
//! | `GET` | `/scans/{id}/report?format=` | Report in a CLI output format |
//! | `GET` | `/explanations/{id}` | Explanation of a finding id |
//! | `GET` | `/` | Browser UI (with `/ui/app.js` and `/ui/app.css`) |

mod api;
mod history;
mod ui;

use std::collections::VecDeque;
use std::fmt::{self, Write as _};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use testls_checks::TrustStore;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use history::History;

/// Settings for the service.
#[derive(Clone)]
#[non_exhaustive]
pub struct Config {
    /// Bearer token every request must carry. Without one, only requests
    /// whose `Host` header names the loopback interface are served, which
    /// keeps web pages on other origins out through DNS rebinding.
    pub token: Option<String>,
    /// Allow targets on loopback, private and other special-purpose
    /// addresses, and revocation fetches from them.
    pub allow_private: bool,
    /// Most scans kept in the history; the oldest finished one goes first.
    pub max_history: usize,
    /// Most scans running at once.
    pub max_concurrent: usize,
    /// Most scans started per minute.
    pub max_per_minute: usize,
    /// Most progress streams open at once.
    pub max_streams: usize,
    /// Time limit for one scan.
    pub scan_timeout: Duration,
    /// TCP connect timeout per probe connection.
    pub connect_timeout: Duration,
    /// Read timeout per probe connection.
    pub read_timeout: Duration,
    /// Roots that certificate chains are validated against.
    pub trust_store: TrustStore,
}

impl Default for Config {
    /// Loopback-only service without a token, blocking private targets.
    fn default() -> Self {
        Self {
            token: None,
            allow_private: false,
            max_history: 100,
            max_concurrent: 4,
            max_per_minute: 30,
            max_streams: 64,
            scan_timeout: Duration::from_secs(300),
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(10),
            trust_store: TrustStore::webpki(),
        }
    }
}

impl fmt::Debug for Config {
    /// Shows every setting but the token, which is redacted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("allow_private", &self.allow_private)
            .field("max_history", &self.max_history)
            .field("max_concurrent", &self.max_concurrent)
            .field("max_per_minute", &self.max_per_minute)
            .field("max_streams", &self.max_streams)
            .field("scan_timeout", &self.scan_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("read_timeout", &self.read_timeout)
            .field("trust_store", &self.trust_store)
            .finish()
    }
}

/// Shared state behind every request.
struct Shared {
    /// Service settings.
    config: Config,
    /// Kept scans.
    history: History,
    /// One permit per scan allowed to run at once.
    slots: Arc<Semaphore>,
    /// One permit per progress stream allowed open at once.
    streams: Arc<Semaphore>,
    /// Start times of the scans in the last minute, oldest first.
    recent: Mutex<VecDeque<Instant>>,
}

impl fmt::Debug for Shared {
    /// Shows the settings and history; the semaphore and rate window are
    /// internal bookkeeping.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared")
            .field("config", &self.config)
            .field("history", &self.history)
            .finish_non_exhaustive()
    }
}

impl Shared {
    /// Fresh state for `config`.
    fn new(config: Config) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(config.max_concurrent.max(1))),
            streams: Arc::new(Semaphore::new(config.max_streams.max(1))),
            history: History::new(config.max_history),
            recent: Mutex::new(VecDeque::new()),
            config,
        }
    }

    /// Records a scan start unless `max_per_minute` scans already started
    /// in the last minute.
    fn admit(&self, now: Instant) -> bool {
        let mut recent = self
            .recent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while recent
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            recent.pop_front();
        }
        if recent.len() >= self.config.max_per_minute {
            return false;
        }
        recent.push_back(now);
        true
    }
}

/// The service's routes with `config` applied.
///
/// Without a token the routes trust the `Host` header to tell loopback
/// clients apart, so serve them only on a loopback listener unless
/// `config.token` is set; [`serve`] enforces this.
pub fn router(config: Config) -> Router {
    api::routes(Arc::new(Shared::new(config)))
}

/// Serves the API on `listener` until `shutdown` completes.
///
/// # Errors
///
/// Refuses a listener beyond the loopback interface when `config` has no
/// token; otherwise returns the I/O error that stopped the server.
pub async fn serve(
    listener: TcpListener,
    config: Config,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    check_listener(listener.local_addr()?, &config)?;
    axum::serve(listener, router(config))
        .with_graceful_shutdown(shutdown)
        .await
}

/// Refuses to serve on `addr` without a non-empty token unless it is a
/// loopback address.
fn check_listener(addr: SocketAddr, config: &Config) -> std::io::Result<()> {
    let token = config.token.as_deref().is_some_and(|t| !t.is_empty());
    if token || addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{addr} is not a loopback address, so a token is required"),
        ))
    }
}

/// A random 256-bit token, hex-encoded, for services reachable beyond the
/// loopback interface.
///
/// # Errors
///
/// Returns the error when the operating system has no randomness to give.
pub fn random_token() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(bytes.iter().fold(String::with_capacity(64), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    }))
}

#[cfg(test)]
mod tests {
    //! Unit tests for the service settings and rate limit.

    use super::*;

    /// Tokens are 64 hex digits and differ between calls.
    #[test]
    fn tokens() {
        let a = random_token().unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, random_token().unwrap());
    }

    /// The rate window admits `max_per_minute` starts and frees up after a
    /// minute.
    #[test]
    fn rate_limit() {
        let state = Shared::new(Config {
            max_per_minute: 2,
            ..Config::default()
        });
        let start = Instant::now();
        assert!(state.admit(start));
        assert!(state.admit(start));
        assert!(!state.admit(start + Duration::from_secs(59)));
        assert!(state.admit(start + Duration::from_secs(60)));
    }

    /// Listeners beyond loopback need a non-empty token, also through
    /// `serve`.
    #[tokio::test]
    async fn listener_check() {
        let any: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let local: SocketAddr = "[::1]:8080".parse().unwrap();
        let open = Config::default();
        let empty = Config {
            token: Some(String::new()),
            ..Config::default()
        };
        let token = Config {
            token: Some("s3cret".to_owned()),
            ..Config::default()
        };
        assert!(check_listener(local, &open).is_ok());
        assert!(check_listener(any, &open).is_err());
        assert!(check_listener(any, &empty).is_err());
        assert!(check_listener(any, &token).is_ok());

        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let error = serve(listener, open, std::future::ready(()))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    /// `Debug` output never shows the token.
    #[test]
    fn token_redacted() {
        let config = Config {
            token: Some("s3cret".to_owned()),
            ..Config::default()
        };
        let shown = format!("{config:?}");
        assert!(!shown.contains("s3cret"), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
    }
}
