//! End-to-end scans against the local servers in `tests/servers`.
//!
//! Ignored by default; start the servers first (see
//! `tests/servers/compose.yaml`), then run with `--ignored`.

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    while !ready(addr) {
        assert!(Instant::now() < deadline, "server {addr} did not come up");
        sleep(Duration::from_millis(200));
    }
}

/// Reports whether `addr` accepts a connection and keeps it open. Docker's
/// port proxy accepts connections before the container listens, then closes
/// them, so an immediate EOF means the server is not up yet.
fn ready(addr: &str) -> bool {
    let Ok(stream) = TcpStream::connect(addr) else {
        return false;
    };
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set read timeout");
    match stream.peek(&mut [0; 1]) {
        Ok(n) => n > 0,
        Err(e) => matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
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
    assert!(s.has("medium   TLSv1.0 offered: deprecated (RFC 8996) [protocol.tls10]"));
    assert!(s.has("info     TLSv1.2: server follows the client's cipher order"));
    assert_eq!(
        s.line("Key exchange TLSv1.2"),
        "Key exchange TLSv1.2 client order"
    );
    assert!(s.has("0x001d  x25519"));
    assert!(s.has("DH      1024 bits"));
    assert!(s.has("DH 0x0034  1024 bits"));
    assert_eq!(s.line("Certificate"), "Certificate (TLSv1.2)");
    assert_eq!(s.line("#0"), "#0 CN=localhost");
    assert_eq!(s.line("names"), "names   localhost, 127.0.0.1");
    assert!(s.has("high     certificate chain is not trusted: issuer is not a trusted root"));
    assert!(s.has("BEAST                          vulnerable     TLS_"));
    assert!(s.has("[vuln.beast]"));
    assert_eq!(
        s.line("Logjam"),
        "Logjam                         vulnerable     TLSv1.0 uses the well-known Oakley group 2 (RFC 2409, section 6.2) [vuln.logjam]"
    );
    assert_eq!(
        s.line("Downgrade"),
        "Downgrade (TLS_FALLBACK_SCSV)  not vulnerable TLS_FALLBACK_SCSV honoured"
    );
    assert_eq!(
        s.line("Raccoon"),
        "Raccoon                        not vulnerable fresh DH public value per handshake"
    );
    assert_eq!(
        s.line("ALPACA"),
        "ALPACA                         vulnerable     unknown ALPN protocol accepted, review ALPACA risk [vuln.alpaca]"
    );
    assert_eq!(
        s.line("ClientHello tolerance"),
        "ClientHello tolerance TLSv1.2"
    );
    assert!(!s.has("intolerance."), "{}", s.stdout);
    assert_eq!(
        s.line("extended master secret"),
        "extended master secret  yes (TLSv1.2)"
    );
    assert_eq!(
        s.line("downgrade sentinel"),
        "downgrade sentinel      not tested"
    );
    assert_eq!(s.line("F T"), "F T");
    assert_eq!(
        s.code, 1,
        "critical findings must fail the default threshold"
    );
}

/// TLS 1.2+ server with strong suites in server order and a certificate
/// from a trusted CA: expects only the missing HTTP security headers, which
/// `s_server -www` never sends, and exit code 0 at `--fail-on medium`.
#[test]
#[ignore = "needs tests/servers running"]
fn modern_server() {
    let s = scan(
        "127.0.0.1:14434",
        &["--fail-on", "medium", "--ca-file", CA_FILE],
    );
    assert_eq!(s.line("TLSv1.1 "), "TLSv1.1  not offered");
    assert_eq!(s.line("TLSv1.2 "), "TLSv1.2  offered");
    assert_eq!(s.line("TLSv1.3 "), "TLSv1.3  offered");
    assert_eq!(s.line("Ciphers TLSv1.2"), "Ciphers TLSv1.2 server order");
    assert_eq!(s.line("Ciphers TLSv1.3"), "Ciphers TLSv1.3 server order");
    assert!(s.has("0x1302  TLS_AES_256_GCM_SHA384"));
    assert!(s.has("0xcca8  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"));
    assert_eq!(
        s.line("Key exchange TLSv1.3"),
        "Key exchange TLSv1.3 server order"
    );
    assert!(s.has("0x11ec  X25519MLKEM768"));
    assert_eq!(s.line("status "), "status                 ready");
    assert!(s.has("ML-KEM groups          X25519MLKEM768 (0x11ec)"));
    assert_eq!(s.line("draft Kyber groups"), "draft Kyber groups     none");
    assert_eq!(s.line("Certificate"), "Certificate (TLSv1.3)");
    assert_eq!(s.line("key"), "key     RSA 2048 bits");
    assert_eq!(s.line("SCTs"), "SCTs    0");
    assert_eq!(s.line("OCSP"), "OCSP     not stapled");
    assert_eq!(s.line("HTTP headers"), "HTTP headers (status 200)");
    assert!(!s.has("Set-Cookie") && !s.has("Alt-Svc"));
    assert_eq!(
        s.line("Strict-Transport-Security"),
        "Strict-Transport-Security  not set"
    );
    let vulns = s.stdout.split_once("\nVulnerabilities\n").expect("vulns").1;
    let vulns = vulns.split_once("\n\n").expect("section end").0;
    assert_eq!(vulns.lines().count(), 15, "{vulns}");
    assert!(
        vulns.lines().all(|l| l.contains(" not vulnerable ")),
        "{vulns}"
    );
    let tolerance = s
        .stdout
        .split_once("\nClientHello tolerance TLSv1.3\n")
        .expect("tolerance")
        .1;
    let tolerance = tolerance.split_once("\n\n").expect("section end").0;
    assert_eq!(tolerance.lines().count(), 5, "{tolerance}");
    assert!(
        tolerance.lines().all(|l| l.ends_with(" tolerated")),
        "{tolerance}"
    );
    let details = s
        .stdout
        .split_once("\nHandshake details\n")
        .expect("details")
        .1;
    let details = details.split_once("\n\n").expect("section end").0;
    assert_eq!(
        details.lines().map(str::trim).collect::<Vec<_>>(),
        [
            "extended master secret  yes (TLSv1.2)",
            "downgrade sentinel      yes (TLSv1.2)",
            "session tickets         yes (TLSv1.3)",
            "0-RTT early data        no",
        ]
    );
    let findings = s.stdout.split_once("\nFindings\n").expect("findings").1;
    let (findings, grade) = findings.split_once("\n\nGrade\n").expect("grade");
    assert_eq!(grade, "  A-\n    low findings: hsts.missing\n");
    let lines: Vec<&str> = findings.lines().map(str::trim).collect();
    assert_eq!(
        lines,
        [
            "low      no Strict-Transport-Security header [hsts.missing]",
            "info     no OCSP response stapled [ocsp.not_stapled]",
            "info     no X-Content-Type-Options: nosniff header [header.x_content_type_options]",
            "info     no restrictive X-Frame-Options header or CSP frame-ancestors directive [header.framing]",
            "info     no Content-Security-Policy header [header.content_security_policy]",
            "info     no Referrer-Policy header [header.referrer_policy]",
        ],
        "{}",
        s.stdout
    );
    assert_eq!(s.code, 0);
    let order = [
        "\nProtocols\n",
        "\nCiphers TLSv1.2",
        "\nKey exchange TLSv1.2",
        "\nCiphers TLSv1.3",
        "\nKey exchange TLSv1.3",
        "\nPost-quantum readiness\n",
        "\nCertificate (",
        "\nHTTP headers (",
        "\nVulnerabilities\n",
        "\nClientHello tolerance",
        "\nHandshake details\n",
        "\nFindings\n",
        "\nGrade\n",
    ]
    .map(|heading| s.stdout.find(heading).expect(heading));
    assert!(order.is_sorted(), "sections out of order:\n{}", s.stdout);
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
    assert_eq!(v["schema_version"], 2);
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
    let kx = v["key_exchange"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["protocol"] == "TLSv1.2")
        .unwrap();
    assert_eq!(kx["group_order"], "client");
    assert_eq!(kx["dh_bits"], 1024);
    let dh_suites = kx["dh_suites"].as_array().unwrap();
    assert!(
        dh_suites
            .iter()
            .any(|d| d["suite"] == "0x0033" && d["bits"] == 2048)
    );
    assert!(
        dh_suites
            .iter()
            .any(|d| d["suite"] == "0x0034" && d["bits"] == 1024)
    );
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "dh.weak")
    );
    assert!(
        kx["groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["name"] == "x25519" && g["severity"] == "ok")
    );
    assert_eq!(v["certificate"]["chain"][0]["subject"], "CN=localhost");
    assert_eq!(
        v["certificate"]["ocsp"],
        serde_json::json!({"stapled": false, "status": null})
    );
    assert_eq!(v["http"]["status"], 200);
    assert_eq!(
        v["http"]["headers"]["strict-transport-security"],
        serde_json::Value::Null
    );
    assert_eq!(v["http"]["hsts"], serde_json::Value::Null);
    assert_eq!(v["revocation"], serde_json::Value::Null);
    let beast = v["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == "beast")
        .unwrap();
    assert_eq!(beast["status"], "vulnerable");
    assert_eq!(beast["finding"], "vuln.beast");
    assert_eq!(v["intolerance"]["protocol"], "TLSv1.2");
    assert_eq!(v["intolerance"]["tests"]["grease"], "tolerated");
    assert_eq!(v["details"]["protocol"], "TLSv1.2");
    assert_eq!(v["post_quantum"]["status"], "not tested");
    assert_eq!(v["details"]["extended_master_secret"], true);
    assert_eq!(v["details"]["downgrade_sentinel"], serde_json::Value::Null);
    assert_eq!(v["grade"]["letter"], "F");
    assert_eq!(v["grade"]["untrusted"], true);
    assert_eq!(v["findings"][0]["severity"], "critical");
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "cert.untrusted")
    );
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "hsts.missing" && f["severity"] == "low")
    );
    assert_eq!(s.code, 1);
}

/// `--revocation` adds a revocation section; the test certificate names no
/// OCSP responder or CRL, so no other server is contacted.
#[test]
#[ignore = "needs tests/servers running"]
fn revocation_without_sources() {
    let s = scan("127.0.0.1:14434", &["--revocation", "--ca-file", CA_FILE]);
    assert!(
        s.has("Revocation\n  no HTTP OCSP responder or CRL named\n"),
        "{}",
        s.stdout
    );
    assert!(s.has("info     certificate names no HTTP OCSP responder or CRL"));
    let j = scan(
        "127.0.0.1:14434",
        &["--revocation", "--ca-file", CA_FILE, "--format", "json"],
    );
    let v: serde_json::Value = serde_json::from_str(&j.stdout).expect("valid JSON");
    assert_eq!(v["revocation"], serde_json::json!({"checks": []}));
}

/// Without the test CA the same server's certificate is untrusted, and an
/// SNI name it does not cover is a mismatch; both cap the grade at C with
/// the T marker.
#[test]
#[ignore = "needs tests/servers running"]
fn untrusted_certificate() {
    let s = scan("127.0.0.1:14434", &["--sni", "example.com"]);
    assert!(s.has("high     certificate chain is not trusted: issuer is not a trusted root"));
    assert!(s.has("high     certificate does not cover example.com"));
    assert_eq!(s.line("C T"), "C T");
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
        .args([addr, "--system-roots", "--fail-on", "medium"])
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
/// store; a loader error (`no usable root certificates: <error>`) still fails.
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
    let empty_store = stderr.contains("no usable root certificates found");
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

/// `testls explain <id>` describes a finding; an unknown id is an error
/// (exit code 2). No server is needed.
#[test]
fn explain_subcommand() {
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .args(["explain", "cipher.rc4"])
        .output()
        .expect("run testls");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8(out.stdout).expect("utf-8 output");
    assert!(
        stdout.starts_with("cipher.rc4: RC4 cipher suite\n"),
        "{stdout}"
    );
    assert!(stdout.contains("Reference: RFC 7465"), "{stdout}");

    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .args(["explain", "cipher.nope"])
        .output()
        .expect("run testls");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).expect("utf-8 output");
    assert!(stderr.contains("unknown finding id"), "{stderr}");
}

/// Several targets, here one positional and one from `--file`, are scanned
/// in order; JSON becomes an array and the worst exit code wins.
#[test]
#[ignore = "needs tests/servers running"]
fn multiple_targets() {
    wait_for("127.0.0.1:14433");
    wait_for("127.0.0.1:14434");
    let list = std::env::temp_dir().join(format!("testls-multi-{}", std::process::id()));
    std::fs::write(
        &list,
        "# test servers, one as a CIDR range\n127.0.0.1/32:14434\n",
    )
    .expect("write list");
    let run = |format: &str| {
        Command::new(env!("CARGO_BIN_EXE_testls"))
            .args(["127.0.0.1:14433", "--file"])
            .arg(&list)
            .args(["--ca-file", CA_FILE, "--format", format])
            .output()
            .expect("run testls")
    };
    let text = run("text");
    let stdout = String::from_utf8(text.stdout).expect("utf-8 output");
    let headers: Vec<&str> = stdout
        .lines()
        .filter(|l| l.starts_with("Target: "))
        .collect();
    assert_eq!(headers.len(), 2, "{stdout}");
    assert!(headers[0].starts_with("Target: 127.0.0.1:14433"));
    assert!(headers[1].starts_with("Target: 127.0.0.1:14434"));
    assert_eq!(text.status.code(), Some(1));
    let json = run("json");
    std::fs::remove_file(&list).expect("remove list");
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).expect("valid JSON");
    let docs = v.as_array().expect("array");
    assert_eq!(docs.len(), 2);
    assert_eq!(docs[0]["target"]["input"], "127.0.0.1:14433");
    assert_eq!(docs[1]["target"]["input"], "127.0.0.1:14434");
    assert_eq!(json.status.code(), Some(1));
}

/// A bad line in `--file` is a scan error that names the line, reported
/// before any connection is made.
#[test]
fn bad_target_file_is_scan_error() {
    let list = std::env::temp_dir().join(format!("testls-bad-list-{}", std::process::id()));
    std::fs::write(&list, "127.0.0.1:1\nftp://example.com\n").expect("write list");
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg("--file")
        .arg(&list)
        .output()
        .expect("run testls");
    std::fs::remove_file(&list).expect("remove list");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).expect("utf-8 output");
    assert!(stderr.contains(":2: unsupported URL scheme"), "{stderr}");
}

/// `--starttls smtp` upgrades the Postfix connection before every probe and
/// skips the HTTP headers.
#[test]
#[ignore = "needs tests/servers running"]
fn smtp_starttls() {
    let s = scan(
        "127.0.0.1:14425",
        &[
            "--starttls",
            "smtp",
            "--sni",
            "localhost",
            "--ca-file",
            CA_FILE,
        ],
    );
    assert_eq!(s.line("TLSv1.1 "), "TLSv1.1  not offered");
    assert_eq!(s.line("TLSv1.2 "), "TLSv1.2  offered");
    assert_eq!(s.line("TLSv1.3 "), "TLSv1.3  offered");
    assert_eq!(s.line("Certificate"), "Certificate (TLSv1.3)");
    assert_eq!(s.line("#0"), "#0 CN=localhost");
    assert_eq!(
        s.line("HTTP headers"),
        "HTTP headers: not checked over --starttls smtp"
    );
    assert!(!s.has("cert.untrusted"), "{}", s.stdout);

    let j = scan(
        "127.0.0.1:14425",
        &[
            "--starttls",
            "smtp",
            "--sni",
            "localhost",
            "--ca-file",
            CA_FILE,
            "--format",
            "json",
        ],
    );
    let v: serde_json::Value = serde_json::from_str(&j.stdout).expect("valid JSON");
    assert_eq!(
        v["http"]["error"],
        serde_json::json!("not checked over --starttls smtp")
    );
}

/// Without STARTTLS, the plain SMTP port answers no `ClientHello`, so no
/// protocol is offered.
#[test]
#[ignore = "needs tests/servers running"]
fn smtp_without_starttls() {
    let s = scan(
        "127.0.0.1:14425",
        &["--profile", "quick", "--ca-file", CA_FILE],
    );
    assert_eq!(s.line("TLSv1.2 "), "TLSv1.2  not offered");
    assert_eq!(s.line("TLSv1.3 "), "TLSv1.3  not offered");
    assert!(s.has("[protocol.no_modern]"), "{}", s.stdout);
    assert_eq!(s.code, 1);
}

/// Fixture DNS (`CoreDNS`) published on loopback by `tests/servers`.
const FIXTURE_DNS: &str = "127.0.0.1:15353";

/// Runs `testls` with `args`, waiting for the SMTP fixture first; returns
/// exit code, stdout and stderr.
fn mx_scan(args: &[&str]) -> (i32, String, String) {
    wait_for("127.0.0.1:14425");
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .args(["--mx-dns", FIXTURE_DNS])
        .args(args)
        .output()
        .expect("run testls");
    (
        out.status.code().expect("exit code"),
        String::from_utf8(out.stdout).expect("utf-8 output"),
        String::from_utf8(out.stderr).expect("utf-8 output"),
    )
}

/// `--mx` resolves the MX of `fixtures.test` through the fixture DNS to
/// `smtp.fixtures.test`, then scans it with SMTP STARTTLS (address pinned
/// to the published port by `--resolve`); the findings of the fixture's
/// anonymous suites give exit code 1, never 2. An unknown domain is a scan
/// error.
#[test]
#[ignore = "needs tests/servers running"]
fn mx_lookup() {
    let (code, stdout, stderr) = mx_scan(&[
        "--mx",
        "fixtures.test:14425",
        "--resolve",
        "smtp.fixtures.test:14425:127.0.0.1",
        "--sni",
        "localhost",
        "--ca-file",
        CA_FILE,
        "--profile",
        "quick",
    ]);
    assert!(stdout.contains("smtp.fixtures.test"), "{stdout}{stderr}");
    assert!(stdout.contains("TLSv1.2  offered"), "{stdout}{stderr}");
    assert_eq!(code, 1, "{stdout}{stderr}");

    let (code, stdout, stderr) = mx_scan(&["--mx", "nonexistent.fixtures.test:14425"]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(
        format!("{stdout}{stderr}").contains("domain does not exist"),
        "{stdout}{stderr}"
    );
}

/// IMAP and POP3 STARTTLS on Dovecot, FTP `AUTH TLS` on vsftpd, XMPP
/// STARTTLS on Prosody (stream addressed to the SNI name) and LDAP
/// `StartTLS` on `OpenLDAP` and `SSLRequest` on PostgreSQL and `MariaDB`:
/// TLS 1.2+ with a trusted certificate matching the SNI name.
#[test]
#[ignore = "needs tests/servers running"]
fn other_starttls() {
    for (addr, protocol) in [
        ("127.0.0.1:14143", "imap"),
        ("127.0.0.1:14110", "pop3"),
        ("127.0.0.1:14021", "ftp"),
        ("127.0.0.1:15222", "xmpp"),
        ("127.0.0.1:14389", "ldap"),
        ("127.0.0.1:15432", "postgres"),
        ("127.0.0.1:13306", "mysql"),
    ] {
        let s = scan(
            addr,
            &[
                "--starttls",
                protocol,
                "--sni",
                "localhost",
                "--ca-file",
                CA_FILE,
                "--profile",
                "quick",
            ],
        );
        assert_eq!(s.line("TLSv1.1 "), "TLSv1.1  not offered", "{protocol}");
        assert_eq!(s.line("TLSv1.2 "), "TLSv1.2  offered", "{protocol}");
        assert_eq!(s.line("TLSv1.3 "), "TLSv1.3  offered", "{protocol}");
        assert_eq!(s.line("#0"), "#0 CN=localhost", "{protocol}");
        assert_eq!(
            s.line("names"),
            "names   localhost, 127.0.0.1",
            "{protocol}"
        );
        assert!(!s.has("cert.hostname_mismatch"), "{}", s.stdout);
        assert!(!s.has("cert.untrusted"), "{}", s.stdout);
    }
}

/// Reads a bounded raw MySQL packet or TLS record for the test-only relay.
async fn mysql_robot_frame(stream: &mut tokio::net::TcpStream, mysql: bool) -> Vec<u8> {
    let header_len = if mysql { 4 } else { 5 };
    let mut frame = vec![0; header_len];
    stream.read_exact(&mut frame).await.expect("relay header");
    let len = if mysql {
        usize::try_from(u32::from_le_bytes([frame[0], frame[1], frame[2], 0])).unwrap()
    } else {
        usize::from(u16::from_be_bytes([frame[3], frame[4]]))
    };
    assert!(len <= 18 * 1024, "oversized relay frame");
    frame.resize(header_len + len, 0);
    stream
        .read_exact(&mut frame[header_len..])
        .await
        .expect("relay body");
    frame
}

/// Relays one real MariaDB exchange and observes the request and client framing.
///
/// No handshake bytes are synthesized or changed. RFC 5246 §7.4.6–7 requires
/// an empty client Certificate immediately before `ClientKeyExchange` here.
async fn relay_mysql_robot_handshake(mut client: tokio::net::TcpStream) -> (bool, bool) {
    let mut server = tokio::net::TcpStream::connect("127.0.0.1:13306")
        .await
        .expect("MariaDB");
    client
        .write_all(&mysql_robot_frame(&mut server, true).await)
        .await
        .unwrap();
    server
        .write_all(&mysql_robot_frame(&mut client, true).await)
        .await
        .unwrap();
    server
        .write_all(&mysql_robot_frame(&mut client, false).await)
        .await
        .unwrap();
    let mut pending = Vec::new();
    let mut requested = false;
    let mut done = false;
    while !done {
        let frame = mysql_robot_frame(&mut server, false).await;
        assert_eq!(frame[0], 22, "plaintext server handshake");
        client.write_all(&frame).await.unwrap();
        pending.extend_from_slice(&frame[5..]);
        assert!(pending.len() <= 256 * 1024, "oversized server handshake");
        let mut offset = 0;
        while let Some((message, used)) = testls_wire::parse_handshake(&pending[offset..]).unwrap()
        {
            requested |= message.typ == testls_wire::handshake_type::CERTIFICATE_REQUEST;
            done |= message.typ == testls_wire::handshake_type::SERVER_HELLO_DONE;
            offset += used;
        }
        pending.drain(..offset);
    }
    let frame = mysql_robot_frame(&mut client, false).await;
    assert_eq!(frame[0], 22, "client handshake");
    let (certificate, used) = testls_wire::parse_handshake(&frame[5..]).unwrap().unwrap();
    let (cke, cke_used) = testls_wire::parse_handshake(&frame[5 + used..])
        .unwrap()
        .unwrap();
    let empty_before_cke = certificate.typ == testls_wire::handshake_type::CERTIFICATE
        && certificate.body == [0, 0, 0]
        && cke.typ == 16 // ClientKeyExchange, RFC 5246 §A.4.
        && 5 + used + cke_used == frame.len();
    server.write_all(&frame).await.unwrap();
    for typ in [20, 22] {
        let frame = mysql_robot_frame(&mut client, false).await;
        assert_eq!(frame[0], typ, "CCS then bogus encrypted Finished");
        server.write_all(&frame).await.unwrap();
    }
    client
        .write_all(&mysql_robot_frame(&mut server, false).await)
        .await
        .unwrap();
    (requested, empty_before_cke)
}

/// Observes all eight real MariaDB ROBOT exchanges, then checks the CLI verdict.
#[tokio::test]
#[ignore = "needs tests/servers running"]
async fn mysql_robot_optional_client_certificate() {
    wait_for("127.0.0.1:13306");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut transport = testls_probe::Transport::new(listener.local_addr().unwrap());
    transport.starttls = Some(testls_probe::Starttls::Mysql);
    transport.read_timeout = Duration::from_secs(3);
    let observer = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(30), async {
            for _ in 0..8 {
                let (client, _) = listener.accept().await.unwrap();
                let (requested, empty_before_cke) = relay_mysql_robot_handshake(client).await;
                assert!(requested, "MariaDB must send CertificateRequest");
                assert!(empty_before_cke, "empty Certificate must precede CKE");
            }
        })
        .await
        .expect("bounded MariaDB observation");
    });
    let result = testls_probe::probe_robot(
        &transport,
        testls_wire::ProtocolVersion::TLS12,
        0x002f,
        Some("localhost"),
    )
    .await;
    observer.await.unwrap();
    assert!(matches!(
        result,
        Err(testls_probe::ProbeError::Unexpected(
            "no reproducible RSA padding alert difference"
        ))
    ));
    let s = scan(
        "127.0.0.1:13306",
        &[
            "--starttls",
            "mysql",
            "--sni",
            "localhost",
            "--ca-file",
            CA_FILE,
            "--profile",
            "quick",
            "--intrusive",
            "--format",
            "json",
        ],
    );
    assert_ne!(s.code, 2, "{}", s.stdout);
    let report: serde_json::Value = serde_json::from_str(&s.stdout).expect("valid JSON");
    let robot = report["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities")
        .iter()
        .find(|v| v["id"] == "robot")
        .expect("ROBOT result");
    assert_eq!(robot["status"], "not tested", "{}", s.stdout);
    assert!(
        robot["detail"]
            .as_str()
            .expect("ROBOT detail")
            .contains("no reproducible RSA padding alert difference"),
        "{}",
        s.stdout
    );
    assert!(!s.has("vuln.robot"), "{}", s.stdout);
}

/// Sends one HTTP/1.1 request to `server` and returns status and body.
/// Only for replies with a `Content-Length` body.
fn http(server: &str, method: &str, path: &str, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(server).expect("connect to testls serve");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("send request");
    let mut reply = String::new();
    stream.read_to_string(&mut reply).expect("read reply");
    let (head, body) = reply.split_once("\r\n\r\n").expect("reply head");
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status code");
    (status, body.to_owned())
}

/// `testls serve` scans a local server to completion and offers its report
/// in every format.
#[test]
#[ignore = "needs tests/servers running"]
fn serve_scan() {
    wait_for("127.0.0.1:14434");
    let mut child = Command::new(env!("CARGO_BIN_EXE_testls"))
        .args(["serve", "--listen", "127.0.0.1:0", "--allow-private"])
        .args(["--ca-file", CA_FILE])
        .stderr(Stdio::piped())
        .spawn()
        .expect("run testls serve");
    let mut line = String::new();
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr"));
    stderr.read_line(&mut line).expect("read listen address");
    let server = line
        .trim()
        .rsplit("http://")
        .next()
        .expect("listen address")
        .to_owned();

    let (status, _) = http(
        &server,
        "POST",
        "/scans",
        r#"{"target":"127.0.0.1:14434","profile":"quick"}"#,
    );
    assert_eq!(status, 202);
    let deadline = Instant::now() + Duration::from_secs(120);
    let scan = loop {
        let (_, body) = http(&server, "GET", "/scans/1", "");
        if !body.contains(r#""status":"running""#) {
            break body;
        }
        assert!(Instant::now() < deadline, "scan did not finish");
        sleep(Duration::from_millis(500));
    };
    assert!(scan.contains(r#""status":"done""#), "{scan}");
    assert!(scan.contains(r#""section":"certificate""#), "{scan}");

    let (status, text) = http(&server, "GET", "/scans/1/report?format=text", "");
    assert_eq!(status, 200);
    assert!(text.contains("TLSv1.3  offered"), "{text}");
    assert!(text.contains("Grade"), "{text}");
    for (format, needle) in [
        ("json", "\"schema_version\""),
        ("sarif", "\"runs\""),
        ("junit", "<testsuites"),
        ("markdown", "127.0.0.1:14434"),
        ("csv", "127.0.0.1:14434"),
        ("html", "<html"),
    ] {
        let (status, body) = http(
            &server,
            "GET",
            &format!("/scans/1/report?format={format}"),
            "",
        );
        assert_eq!(status, 200, "{format}");
        assert!(body.contains(needle), "{format}: {body}");
    }
    stop_server(child, stderr);
}

/// Stops `testls serve` with an interrupt, which shuts it down cleanly and
/// lets coverage data from the child be written.
#[cfg(unix)]
fn stop_server(mut child: std::process::Child, mut stderr: impl Read) {
    let interrupted = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("run kill");
    assert!(interrupted.success());
    let status = child.wait().expect("reap testls serve");
    let mut rest = String::new();
    stderr.read_to_string(&mut rest).expect("read stderr");
    assert!(status.success(), "{status}: {rest}");
    assert!(rest.contains("shutting down"), "{rest}");
}

/// Stops `testls serve` where `kill -INT` is not available.
#[cfg(not(unix))]
fn stop_server(mut child: std::process::Child, _stderr: impl Read) {
    child.kill().expect("stop testls serve");
    child.wait().expect("reap testls serve");
}

/// OpenSSL 1.0.1f discloses memory but yields no ROBOT alert difference.
#[test]
#[ignore = "needs tests/servers running"]
fn heartbleed_server() {
    let ordinary = scan("127.0.0.1:14435", &["--profile", "quick"]);
    assert!(!ordinary.has("Heartbleed"));
    assert!(!ordinary.has("Ticketbleed"));
    assert!(!ordinary.has("ROBOT"));
    let attack = scan("127.0.0.1:14435", &["--profile", "quick", "--intrusive"]);
    assert!(attack.has("[vuln.heartbleed]"), "{}", attack.stdout);
    assert!(attack.has("Ticketbleed"), "{}", attack.stdout);
    // This fixture returns the same bad_record_mac alert for all RSA vectors;
    // only a reproducible alert difference could establish a ROBOT oracle.
    let robot = attack.line("ROBOT");
    assert!(robot.contains("not tested"), "{robot}");
    assert!(
        robot.contains("no reproducible RSA padding alert difference"),
        "{robot}"
    );
    assert!(!attack.has("[vuln.robot]"), "{}", attack.stdout);
    assert_eq!(attack.code, 1);
}

/// OpenSSL 1.0.1g drops the malformed request; silence is not a safe verdict.
#[test]
#[ignore = "needs tests/servers running"]
fn heartbleed_patched_server() {
    let scan = scan("127.0.0.1:14436", &["--profile", "quick", "--intrusive"]);
    assert!(scan.has("Heartbleed"), "{}", scan.stdout);
    assert!(!scan.has("[vuln.heartbleed]"), "{}", scan.stdout);
    assert!(scan.line("Heartbleed").contains("not tested"));
    assert!(scan.has("Ticketbleed"), "{}", scan.stdout);
    assert!(!scan.has("[vuln.ticketbleed]"), "{}", scan.stdout);
}

/// Detects early CCS on OpenSSL 1.0.1g only when explicitly requested.
#[test]
#[ignore = "needs tests/servers running"]
fn ccs_injection_server() {
    let ordinary = scan("127.0.0.1:14436", &["--profile", "quick"]);
    assert!(!ordinary.has("CCS injection"));
    let attack = scan("127.0.0.1:14436", &["--profile", "quick", "--intrusive"]);
    assert!(
        attack
            .stdout
            .lines()
            .any(|line| line.contains("high") && line.contains("[vuln.ccs_injection]")),
        "{}",
        attack.stdout
    );
    assert!(attack.line("CCS injection").contains("vulnerable"));
}

/// The fixed OpenSSL version must not produce a CCS injection finding.
#[test]
#[ignore = "needs tests/servers running"]
fn ccs_injection_patched_server() {
    let scan = scan("127.0.0.1:14437", &["--profile", "quick", "--intrusive"]);
    assert!(!scan.has("[vuln.ccs_injection]"), "{}", scan.stdout);
    assert!(scan.line("CCS injection").contains("not tested"));
}

/// Scans a wolfSSL ROBOT fixture and asserts an inconclusive ROBOT verdict.
///
/// The fixture negotiates only `TLS_RSA_WITH_AES_128_CBC_SHA` at TLS 1.2.
fn assert_wolfssl_robot_not_tested(addr: &str) {
    let scan = scan(addr, &["--profile", "quick", "--intrusive"]);
    assert!(scan.line("TLSv1.2").contains("offered"), "{}", scan.stdout);
    assert!(scan.has("TLS_RSA_WITH_AES_128_CBC_SHA"), "{}", scan.stdout);
    let robot = scan.line("ROBOT");
    assert!(robot.contains("not tested"), "{robot}");
    assert!(robot.contains("0x002f"), "{robot}");
    assert!(robot.contains("no comparable fatal alert"), "{robot}");
    assert!(!scan.has("[vuln.robot]"), "{}", scan.stdout);
}

/// Scans a wolfSSL ROBOT fixture and asserts the flow-oracle finding.
///
/// The fixture signals invalid padding by closing right after the
/// `ClientKeyExchange`, so the alert oracle stays inconclusive while the flow
/// oracle confirms the difference.
fn assert_wolfssl_robot_vulnerable(addr: &str) {
    let scan = scan(addr, &["--profile", "quick", "--intrusive"]);
    assert!(scan.line("TLSv1.2").contains("offered"), "{}", scan.stdout);
    assert!(scan.has("TLS_RSA_WITH_AES_128_CBC_SHA"), "{}", scan.stdout);
    let robot = scan.line("ROBOT");
    assert!(robot.contains("vulnerable"), "{robot}");
    assert!(robot.contains("0x002f"), "{robot}");
    assert!(
        robot.contains("early close on invalid RSA padding"),
        "{robot}"
    );
    assert!(scan.has("[vuln.robot]"), "{}", scan.stdout);
}

/// Reads one TLS record from a blocking stream: `(type, body)`.
fn read_tls_record(stream: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut header = [0; 5];
    stream.read_exact(&mut header)?;
    let mut body = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
    stream.read_exact(&mut body)?;
    Ok((header[0], body))
}

/// Encrypts a TLS 1.2 RSA premaster block for the leaf certificate's key.
///
/// RFC 8017 §7.2.1 / RFC 5246 §7.4.7.1: `00 02 PS 00 03 03 random[46]`.
/// With `valid == false` the block type is `01`, which a correct EME-PKCS1
/// decoder must reject.
fn rsa_premaster(leaf: &[u8], valid: bool) -> Vec<u8> {
    use num_bigint::BigUint;
    use x509_parser::public_key::PublicKey;
    let (_, cert) = x509_parser::parse_x509_certificate(leaf).expect("leaf certificate");
    let PublicKey::RSA(key) = cert.public_key().parsed().expect("public key") else {
        panic!("fixture certificate has no RSA key");
    };
    let modulus = BigUint::from_bytes_be(key.modulus);
    let len = modulus.to_bytes_be().len();
    let mut block = vec![0x55; len];
    block[0] = 0;
    block[1] = if valid { 2 } else { 1 };
    block[len - 49] = 0;
    block[len - 48..len - 46].copy_from_slice(&[3, 3]);
    let encrypted = BigUint::from_bytes_be(&block)
        .modpow(&BigUint::from_bytes_be(key.exponent), &modulus)
        .to_bytes_be();
    let mut out = vec![0; len - encrypted.len()];
    out.extend_from_slice(&encrypted);
    out
}

/// Sends only a `ClientKeyExchange` and reports whether the server closes
/// within two seconds (`true`) or keeps waiting for `ChangeCipherSpec`.
fn wolfssl_closes_after_cke(addr: &str, valid: bool) -> bool {
    wait_for(addr);
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let hello =
        testls_probe::hello::client_hello(testls_wire::ProtocolVersion::TLS12, vec![0x002f], None)
            .encode()
            .expect("encode hello");
    stream.write_all(&hello).expect("send hello");
    let mut pending = Vec::new();
    let mut leaf = None;
    'flight: loop {
        let (typ, body) = read_tls_record(&mut stream).expect("server flight");
        assert_eq!(typ, 22, "unexpected record in server flight");
        pending.extend_from_slice(&body);
        let mut offset = 0;
        while let Some((message, used)) =
            testls_wire::parse_handshake(&pending[offset..]).expect("handshake")
        {
            offset += used;
            match message.typ {
                testls_wire::handshake_type::CERTIFICATE => {
                    leaf = testls_wire::parse_certificate_list(message.body)
                        .expect("certificate list")
                        .into_iter()
                        .next();
                }
                testls_wire::handshake_type::SERVER_HELLO_DONE => break 'flight,
                _ => {}
            }
        }
        pending.drain(..offset);
    }
    let encrypted = rsa_premaster(&leaf.expect("server certificate"), valid);
    let len = u16::try_from(encrypted.len()).unwrap();
    let mut record = vec![22, 3, 3];
    record.extend_from_slice(&(len + 6).to_be_bytes());
    record.extend_from_slice(&[16, 0]);
    record.extend_from_slice(&(len + 2).to_be_bytes());
    record.extend_from_slice(&len.to_be_bytes());
    record.extend_from_slice(&encrypted);
    stream.write_all(&record).expect("send ClientKeyExchange");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let mut byte = [0; 1];
    !matches!(
        stream.read(&mut byte),
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
    )
}

/// wolfSSL 3.12.2 (CVE-2017-13099) leaks padding validity by closing early;
/// the flow oracle confirms `vuln.robot`.
#[test]
#[ignore = "needs tests/servers running"]
fn robot_wolfssl_vulnerable_server() {
    assert_wolfssl_robot_vulnerable("127.0.0.1:14438");
}

/// Confirms the 3.12.2 fixture still exposes the flow oracle independently of
/// the scanner: a valid block waits, a malformed one closes at once.
#[test]
#[ignore = "needs tests/servers running"]
fn robot_wolfssl_vulnerable_flow_oracle() {
    assert!(!wolfssl_closes_after_cke("127.0.0.1:14438", true));
    assert!(wolfssl_closes_after_cke("127.0.0.1:14438", false));
}

/// wolfSSL 3.13.0 (fixed) must never produce a ROBOT finding.
#[test]
#[ignore = "needs tests/servers running"]
fn robot_wolfssl_patched_server() {
    assert_wolfssl_robot_not_tested("127.0.0.1:14439");
}

/// Confirms the 3.13.0 fixture waits for `ChangeCipherSpec` after both blocks.
#[test]
#[ignore = "needs tests/servers running"]
fn robot_wolfssl_patched_flow_oracle() {
    assert!(!wolfssl_closes_after_cke("127.0.0.1:14439", true));
    assert!(!wolfssl_closes_after_cke("127.0.0.1:14439", false));
}
