//! End-to-end scans against the local servers in `tests/servers`.
//!
//! Ignored by default; start the servers first (see
//! `tests/servers/compose.yaml`), then run with `--ignored`.

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
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
    assert!(s.has("DH      2048 bits"));
    assert_eq!(s.line("Certificate"), "Certificate (TLSv1.2)");
    assert_eq!(s.line("#0"), "#0 CN=localhost");
    assert_eq!(s.line("names"), "names   localhost, 127.0.0.1");
    assert!(s.has("high     certificate chain is not trusted: issuer is not a trusted root"));
    assert!(s.has("BEAST                          vulnerable     TLS_"));
    assert!(s.has("[vuln.beast]"));
    assert_eq!(
        s.line("Logjam"),
        "Logjam                         not vulnerable 2048-bit MODP group 14"
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
        "ALPACA                         vulnerable     unknown ALPN protocol accepted [vuln.alpaca]"
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
    let kx = v["key_exchange"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["protocol"] == "TLSv1.2")
        .unwrap();
    assert_eq!(kx["group_order"], "client");
    assert_eq!(kx["dh_bits"], 2048);
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
    BufReader::new(child.stderr.take().expect("stderr"))
        .read_line(&mut line)
        .expect("read listen address");
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
    child.kill().expect("stop testls serve");
    child.wait().expect("reap testls serve");
}
