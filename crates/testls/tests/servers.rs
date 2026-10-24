//! End-to-end scans against the local servers in `tests/servers`.
//!
//! Ignored by default; start the servers first (see
//! `tests/servers/compose.yaml`), then run with `--ignored`.

use std::net::TcpStream;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Exit code and captured stdout of one `testls` run.
struct Scan {
    code: i32,
    stdout: String,
}

impl Scan {
    /// Returns the first trimmed stdout line starting with `prefix`; panics if none.
    fn line(&self, prefix: &str) -> &str {
        self.stdout
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("no line starting with {prefix:?} in:\n{}", self.stdout))
    }

    /// Reports whether stdout contains `needle` anywhere.
    fn has(&self, needle: &str) -> bool {
        self.stdout.contains(needle)
    }
}

/// Test CA that signed the servers' certificate.
const CA_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/servers/ca.pem");

/// Blocks until `addr` accepts TCP connections; fails after 30 seconds.
fn wait_for(addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(addr).is_err() {
        assert!(Instant::now() < deadline, "server {addr} did not come up");
        sleep(Duration::from_millis(200));
    }
}

/// Waits for the server at `addr`, then runs the `testls` binary against it.
fn scan(addr: &str, args: &[&str]) -> Scan {
    wait_for(addr);
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(addr)
        .args(args)
        .output()
        .expect("run testls");
    Scan {
        code: out.status.code().expect("exit code"),
        stdout: String::from_utf8(out.stdout).expect("utf-8 output"),
    }
}

/// TLS 1.0–1.2 server with every cipher enabled: expects deprecated
/// protocols, client cipher order, an anonymous suite, and exit code 1.
#[test]
#[ignore = "needs tests/servers running"]
fn legacy_server() {
    let s = scan("127.0.0.1:14433", &[]);
    assert_eq!(s.line("SSLv3"), "SSLv3    not offered");
    assert_eq!(s.line("TLSv1.0 "), "TLSv1.0  offered");
    assert_eq!(s.line("TLSv1.1 "), "TLSv1.1  offered");
    assert_eq!(s.line("TLSv1.2 "), "TLSv1.2  offered");
    assert_eq!(s.line("TLSv1.3 "), "TLSv1.3  not offered");
    assert_eq!(s.line("Ciphers TLSv1.2"), "Ciphers TLSv1.2 client order");
    assert!(s.has("0x0034  TLS_DH_anon_WITH_AES_128_CBC_SHA"));
    assert!(s.has("critical TLSv1.2 TLS_DH_anon_WITH_AES_128_CBC_SHA: anonymous"));
    assert!(s.has("medium   TLSv1.0 offered: deprecated (RFC 8996)"));
    assert!(s.has("info     TLSv1.2: server follows the client's cipher order"));
    assert_eq!(s.line("Certificate"), "Certificate (TLSv1.2)");
    assert_eq!(s.line("#0"), "#0 CN=localhost");
    assert_eq!(s.line("names"), "names   localhost, 127.0.0.1");
    assert!(s.has("high     certificate chain is not trusted: issuer is not a trusted root"));
    assert_eq!(
        s.code, 1,
        "critical findings must fail the default threshold"
    );
}

/// TLS 1.2+ server with strong suites in server order and a certificate
/// from a trusted CA: expects no findings even at `--fail-on info`, and exit
/// code 0.
#[test]
#[ignore = "needs tests/servers running"]
fn modern_server() {
    let s = scan(
        "127.0.0.1:14434",
        &["--fail-on", "info", "--ca-file", CA_FILE],
    );
    assert_eq!(s.line("TLSv1.1 "), "TLSv1.1  not offered");
    assert_eq!(s.line("TLSv1.2 "), "TLSv1.2  offered");
    assert_eq!(s.line("TLSv1.3 "), "TLSv1.3  offered");
    assert_eq!(s.line("Ciphers TLSv1.2"), "Ciphers TLSv1.2 server order");
    assert_eq!(s.line("Ciphers TLSv1.3"), "Ciphers TLSv1.3 server order");
    assert!(s.has("0x1302  TLS_AES_256_GCM_SHA384"));
    assert!(s.has("0xcca8  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"));
    assert_eq!(s.line("Certificate"), "Certificate (TLSv1.3)");
    assert_eq!(s.line("key"), "key     RSA 2048 bits");
    assert_eq!(s.line("Findings"), "Findings");
    assert!(s.stdout.trim_end().ends_with("none"), "{}", s.stdout);
    assert_eq!(s.code, 0);
}

/// `--color` default (`auto`) leaves piped output plain; `always` colours
/// headings and severities; `never` stays plain.
#[test]
#[ignore = "needs tests/servers running"]
fn color_modes() {
    let plain = scan("127.0.0.1:14433", &[]);
    assert!(!plain.has("\x1b["), "{}", plain.stdout);

    let coloured = scan("127.0.0.1:14433", &["--color", "always"]);
    assert!(
        coloured.has("\x1b[1mProtocols\x1b[0m"),
        "{}",
        coloured.stdout
    );
    assert!(
        coloured.has("\x1b[33moffered\x1b[0m"),
        "{}",
        coloured.stdout
    );
    assert!(
        coloured.has("\x1b[1;31mcritical\x1b[0m"),
        "{}",
        coloured.stdout
    );
    assert_eq!(coloured.code, plain.code);

    let never = scan("127.0.0.1:14433", &["--color", "never"]);
    assert!(!never.has("\x1b["), "{}", never.stdout);
}

/// `--format json` prints one parseable document with the schema version,
/// the same findings as text output, and the same exit code.
#[test]
#[ignore = "needs tests/servers running"]
fn json_report() {
    let s = scan(
        "127.0.0.1:14433",
        &["--format", "json", "--color", "always"],
    );
    assert!(!s.has("\x1b["), "{}", s.stdout);
    let v: serde_json::Value = serde_json::from_str(&s.stdout).expect("valid JSON");
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["target"]["address"], "127.0.0.1:14433");
    let tls10 = v["protocols"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["version"] == "TLSv1.0")
        .unwrap();
    assert_eq!(tls10["status"], "offered");
    assert!(
        v["ciphers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["protocol"] == "TLSv1.2" && c["order"] == "client")
    );
    assert_eq!(v["certificate"]["chain"][0]["subject"], "CN=localhost");
    assert_eq!(v["findings"][0]["severity"], "critical");
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "cert.untrusted")
    );
    assert_eq!(s.code, 1);
}

/// Without the test CA the same server's certificate is untrusted, and an
/// SNI name it does not cover is a mismatch.
#[test]
#[ignore = "needs tests/servers running"]
fn untrusted_certificate() {
    let s = scan("127.0.0.1:14434", &["--sni", "example.com"]);
    assert!(s.has("high     certificate chain is not trusted: issuer is not a trusted root"));
    assert!(s.has("high     certificate does not cover example.com"));
    assert_eq!(s.code, 1);
}

/// An unreadable `--ca-file` is a scan error (exit code 2), reported before
/// any connection is made.
#[test]
fn bad_ca_file_is_scan_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .args(["127.0.0.1:1", "--ca-file", "/nonexistent/ca.pem"])
        .output()
        .expect("run testls");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).expect("utf-8 output");
    assert!(stderr.contains("cannot load"), "{stderr}");
}

/// `--system-roots` trusts the operating system's store; `SSL_CERT_FILE`
/// replaces that store, so pointing it at the test CA makes the chain
/// trusted without touching the machine's roots.
#[test]
#[ignore = "needs tests/servers running"]
fn system_roots_trust_ssl_cert_file() {
    let addr = "127.0.0.1:14434";
    wait_for(addr);
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .args([addr, "--system-roots", "--fail-on", "info"])
        .env("SSL_CERT_FILE", CA_FILE)
        .env_remove("SSL_CERT_DIR")
        .output()
        .expect("run testls");
    let stdout = String::from_utf8(out.stdout).expect("utf-8 output");
    assert!(!stdout.contains("not trusted"), "{stdout}");
    assert_eq!(out.status.code(), Some(0), "{stdout}");
}

/// A system store with no usable roots is a scan error (exit code 2),
/// reported before any connection is made.
#[test]
fn empty_system_roots_is_scan_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .args(["127.0.0.1:1", "--system-roots"])
        .env("SSL_CERT_FILE", "/nonexistent/ca.pem")
        .env_remove("SSL_CERT_DIR")
        .output()
        .expect("run testls");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).expect("utf-8 output");
    assert!(stderr.contains("cannot load system roots"), "{stderr}");
}

/// `--system-roots` and `--ca-file` select different stores and cannot be
/// combined.
#[test]
fn system_roots_conflicts_with_ca_file() {
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .args(["127.0.0.1:1", "--system-roots", "--ca-file", CA_FILE])
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_CERT_DIR")
        .output()
        .expect("run testls");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).expect("utf-8 output");
    assert!(stderr.contains("cannot be used with"), "{stderr}");
}

/// With no `SSL_CERT_*` override the platform store itself must load; the
/// closed port then yields the usual scan error rather than a store error.
/// A machine without any CA bundle (a minimal container) may report an empty
/// store, but no other loader error is accepted.
#[test]
fn platform_system_roots_load() {
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .args(["127.0.0.1:1", "--system-roots"])
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_CERT_DIR")
        .output()
        .expect("run testls");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).expect("utf-8 output");
    let empty_store = stderr.contains("cannot load system roots: no usable root certificates");
    assert!(
        empty_store || !stderr.contains("cannot load system roots"),
        "{stderr}"
    );
}

/// A closed port must be reported as a scan error (exit code 2). Port 1 on
/// loopback is closed, so no server is needed.
#[test]
fn unreachable_is_scan_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .args(["127.0.0.1:1", "--connect-timeout", "2"])
        .output()
        .expect("run testls");
    assert_eq!(out.status.code(), Some(2));
}
