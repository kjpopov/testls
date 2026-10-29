//! End-to-end scan of an in-process TLS server that sends banners,
//! `Alt-Svc` and cookies, checking the JSON, SARIF, JUnit, Markdown,
//! CSV and HTML reports, finding ids, suppressions, baselines, profiles
//! and policies.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::sync::Arc;
use std::thread;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

/// Test certificate for `localhost`, shared with the probe crate.
const CERT: &[u8] = include_bytes!("../../testls-probe/src/testdata/localhost.cert.der");
/// Private key for [`CERT`].
const KEY: &[u8] = include_bytes!("../../testls-probe/src/testdata/localhost.key.der");

/// HTTP reply with a versioned banner, `Alt-Svc` and two weak cookies.
const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\n\
Server: nginx/1.25.3\r\n\
X-Powered-By: PHP/8.3\r\n\
Alt-Svc: h3=\":443\"; ma=60\r\n\
Set-Cookie: session=abc; HttpOnly\r\n\
Set-Cookie: theme=dark; Secure; SameSite=None\r\n\
Content-Length: 0\r\n\
Connection: close\r\n\r\n";

/// Starts a TLS server on a free port that answers every request with
/// [`REPLY`]; failed handshakes from the raw probes are ignored.
fn serve() -> SocketAddr {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(CERT.to_vec())],
            PrivateKeyDer::try_from(KEY.to_vec()).expect("key"),
        )
        .expect("certificate");
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("address");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let config = Arc::clone(&config);
            thread::spawn(move || handle(config, stream));
        }
    });
    addr
}

/// Completes one TLS connection, reads the request head and sends [`REPLY`].
fn handle(config: Arc<ServerConfig>, stream: TcpStream) {
    let Ok(conn) = ServerConnection::new(config) else {
        return;
    };
    let mut tls = StreamOwned::new(conn, stream);
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match tls.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    }
    let _ = tls.write_all(REPLY);
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

/// Banners, `Alt-Svc` and cookie attributes appear in the JSON report and
/// produce their findings.
#[test]
fn json_reports_http_extras() {
    let addr = serve();
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(addr.to_string())
        .args([
            "--sni",
            "localhost",
            "--format",
            "json",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("run testls");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON output");
    let http = &v["http"];
    assert_eq!(http["status"], 200, "{http}");
    assert_eq!(
        http["banners"]["server"],
        serde_json::json!(["nginx/1.25.3"])
    );
    assert_eq!(
        http["banners"]["x-powered-by"],
        serde_json::json!(["PHP/8.3"])
    );
    assert_eq!(
        http["alt_svc"],
        serde_json::json!([{"protocol": "h3", "authority": ":443", "max_age": 60}])
    );
    assert_eq!(
        http["cookies"],
        serde_json::json!([
            {"name": "session", "secure": false, "http_only": true, "same_site": null},
            {"name": "theme", "secure": true, "http_only": false, "same_site": "None"},
        ])
    );
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter_map(|f| f["id"].as_str())
        .collect();
    for id in [
        "header.banner",
        "cookie.insecure",
        "cookie.no_httponly",
        "cookie.no_samesite",
    ] {
        assert!(ids.contains(&id), "missing {id} in {ids:?}");
    }
    assert!(!ids.contains(&"header.alt_svc_invalid"), "{ids:?}");
}

/// `--format sarif` prints one SARIF 2.1.0 log whose results carry the
/// finding ids as rule ids, each backed by a rule in the driver.
#[test]
fn sarif_reports_findings() {
    let addr = serve();
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(addr.to_string())
        .args(["--sni", "localhost", "--format", "sarif"])
        .args(["--fail-on", "critical"])
        .output()
        .expect("run testls");
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("SARIF output");
    assert_eq!(v["version"], "2.1.0");
    let run = &v["runs"][0];
    assert_eq!(run["invocations"][0]["executionSuccessful"], true);
    let rules: Vec<&str> = run["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();
    let results = run["results"].as_array().expect("results");
    for result in results {
        let id = result["ruleId"].as_str().expect("ruleId");
        let index =
            usize::try_from(result["ruleIndex"].as_u64().expect("ruleIndex")).expect("index");
        assert_eq!(rules[index], id);
        assert_eq!(result["properties"]["address"], addr.to_string());
    }
    assert!(
        results.iter().any(|r| r["ruleId"] == "cookie.insecure"),
        "{results:?}"
    );
}

/// `--format junit` prints one XML document with a suite per address and
/// failures where the exit code fails; unresolvable targets are errors.
#[test]
fn junit_reports_failures() {
    let addr = serve();
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(addr.to_string())
        .arg("unresolvable.invalid:443")
        .args(["--sni", "localhost", "--format", "junit"])
        .args(["--fail-on", "low"])
        .output()
        .expect("run testls");
    assert_eq!(out.status.code(), Some(2));
    let xml = String::from_utf8(out.stdout).expect("UTF-8");
    assert!(xml.starts_with("<?xml "), "{xml}");
    assert!(xml.ends_with("</testsuites>\n"), "{xml}");
    assert!(xml.contains(&format!("({addr})")), "{xml}");
    assert!(xml.contains("<testcase name=\"cookie.insecure\""), "{xml}");
    assert!(xml.contains("<failure "), "{xml}");
    assert!(
        xml.contains("<testsuite name=\"unresolvable.invalid:443\""),
        "{xml}"
    );
    assert!(xml.contains("<error message=\"cannot resolve: "), "{xml}");
}

/// `--format markdown` summarises the scan, marks findings at or above
/// `--fail-on` and lists targets that failed to scan.
#[test]
fn markdown_reports_failures() {
    let addr = serve();
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(addr.to_string())
        .arg("unresolvable.invalid:443")
        .args(["--sni", "localhost", "--format", "markdown"])
        .args(["--fail-on", "low"])
        .output()
        .expect("run testls");
    assert_eq!(out.status.code(), Some(2));
    let md = String::from_utf8(out.stdout).expect("UTF-8");
    assert!(md.starts_with("# testls report\n"), "{md}");
    assert!(md.contains("1 scanned, 1 failed to scan"), "{md}");
    assert!(md.contains(&format!("## {addr} ({addr})")), "{md}");
    assert!(md.contains("| ❌ | low | `cookie.insecure` |"), "{md}");
    assert!(
        md.contains("| unresolvable.invalid:443 | cannot resolve: "),
        "{md}"
    );
}

/// `--format csv` prints one row per finding, flags findings at or above
/// `--fail-on` and adds a `scan.error` row for targets that failed to scan.
#[test]
fn csv_reports_failures() {
    let addr = serve();
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(addr.to_string())
        .arg("unresolvable.invalid:443")
        .args(["--sni", "localhost", "--format", "csv"])
        .args(["--fail-on", "low"])
        .output()
        .expect("run testls");
    assert_eq!(out.status.code(), Some(2));
    let csv = String::from_utf8(out.stdout).expect("UTF-8");
    assert!(
        csv.starts_with("target,address,severity,id,message,failing\r\n"),
        "{csv}"
    );
    assert!(
        csv.contains(&format!("{addr},{addr},low,cookie.insecure,")),
        "{csv}"
    );
    assert!(
        csv.lines()
            .any(|l| l.starts_with("unresolvable.invalid:443,,,scan.error,")
                && l.contains("cannot resolve: ")
                && l.ends_with(",true")),
        "{csv}"
    );
}

/// `--format html` prints one page with the scanned address, escaped
/// findings and the failed target.
#[test]
fn html_reports_failures() {
    let addr = serve();
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(addr.to_string())
        .arg("unresolvable.invalid:443")
        .args(["--sni", "localhost", "--format", "html"])
        .args(["--fail-on", "low"])
        .output()
        .expect("run testls");
    assert_eq!(out.status.code(), Some(2));
    let html = String::from_utf8(out.stdout).expect("UTF-8");
    assert!(html.starts_with("<!DOCTYPE html>\n"), "{html}");
    assert!(html.ends_with("</html>\n"), "{html}");
    assert!(
        html.contains(&format!("<h2>{addr} ({addr})</h2>")),
        "{html}"
    );
    assert!(
        html.contains("<td class=\"low\">low</td><td><code>cookie.insecure</code></td>"),
        "{html}"
    );
    assert!(
        html.contains("<td>unresolvable.invalid:443</td><td>cannot resolve: "),
        "{html}"
    );
}

/// `--resolve` connects a host name that does not exist to the local
/// server and keeps the name as target and SNI.
#[test]
fn resolve_pins_address() {
    let addr = serve();
    let target = format!("pinned.invalid:{}", addr.port());
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(&target)
        .args(["--resolve", &format!("{target}:{}", addr.ip())])
        .args(["--format", "json", "--fail-on", "critical"])
        .output()
        .expect("run testls");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON output");
    let scanned = &v["target"];
    assert_eq!(scanned["input"], target);
    assert_eq!(scanned["address"], addr.to_string());
    assert_eq!(scanned["sni"], "pinned.invalid");
    assert_eq!(v["http"]["status"], 200, "{}", v["http"]);
}

/// Starts an HTTP `CONNECT` proxy on a free port that tunnels every
/// request to `forward` and records each request line it accepts.
fn proxy(forward: SocketAddr) -> (SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("address");
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let log = Arc::clone(&log);
            thread::spawn(move || tunnel(client, forward, &log));
        }
    });
    (addr, seen)
}

/// Reads one `CONNECT` request from `client`, connects to `forward`
/// instead of its target and relays bytes both ways until either side
/// closes.
fn tunnel(mut client: TcpStream, forward: SocketAddr, log: &std::sync::Mutex<Vec<String>>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match client.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head);
    let line = head.lines().next().unwrap_or_default().to_owned();
    if !line.starts_with("CONNECT ") {
        return;
    }
    let Ok(mut server) = TcpStream::connect(forward) else {
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
        return;
    };
    log.lock().expect("log").push(line);
    let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
    let (Ok(mut client_r), Ok(mut server_w)) = (client.try_clone(), server.try_clone()) else {
        return;
    };
    let up = thread::spawn(move || {
        let _ = std::io::copy(&mut client_r, &mut server_w);
        let _ = server_w.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut server, &mut client);
    let _ = client.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
}

/// `--proxy` tunnels every probe through the proxy to the scanned address;
/// an unresolvable proxy is a scan error. The target is unreachable
/// directly, so a probe that bypassed the proxy would report an error.
#[test]
fn proxy_tunnels_scan() {
    let target = "192.0.2.1:443";
    let (proxy, seen) = proxy(serve());
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(target)
        .args(["--sni", "localhost", "--proxy", &format!("http://{proxy}")])
        .args(["--format", "json", "--fail-on", "critical"])
        .output()
        .expect("run testls");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON output");
    assert_eq!(v["target"]["address"], target);
    assert_eq!(v["http"]["status"], 200, "{}", v["http"]);
    let findings = v["findings"].as_array().expect("findings");
    for id in ["intolerance.error", "handshake.error"] {
        assert!(findings.iter().all(|f| f["id"] != id), "{findings:?}");
    }
    let seen = seen.lock().expect("log");
    assert!(seen.len() > 1, "{seen:?}");
    let expected = format!("CONNECT {target} HTTP/1.1");
    assert!(seen.iter().all(|l| *l == expected), "{seen:?}");

    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(target)
        .args(["--proxy", "proxy.invalid:3128"])
        .output()
        .expect("run testls");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot resolve proxy"), "{stderr}");
}

/// `--source-ip` scans from the given address and rejects targets that
/// have no address in its family as a scan error.
#[test]
fn source_ip() {
    let addr = serve();
    let run = |source: &str| {
        Command::new(env!("CARGO_BIN_EXE_testls"))
            .arg(addr.to_string())
            .args(["--source-ip", source])
            .args(["--format", "json", "--fail-on", "critical"])
            .output()
            .expect("run testls")
    };
    let out = run("127.0.0.1");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON output");
    assert_eq!(v["http"]["status"], 200, "{}", v["http"]);

    let out = run("::1");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        format!("{stdout}{stderr}").contains("--source-ip ::1"),
        "{stdout}{stderr}"
    );
}

/// `--config` suppressions move matching findings into `suppressed` with
/// their reason, and expired or unknown entries are warned about.
#[test]
fn config_suppresses_findings() {
    let addr = serve();
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("suppress.toml");
    std::fs::write(
        &path,
        format!(
            "[[suppress]]\nid = \"cookie.insecure\"\ntarget = \"{addr}\"\nreason = \"legacy app\"\n\n\
             [[suppress]]\nid = \"cookie.no_httponly\"\nreason = \"old\"\nexpires = 2000-01-01\n\n\
             [[suppress]]\nid = \"no.such.id\"\nreason = \"typo\"\n"
        ),
    )
    .expect("write config");
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(addr.to_string())
        .args([
            "--sni",
            "localhost",
            "--format",
            "json",
            "--fail-on",
            "critical",
        ])
        .arg("--config")
        .arg(&path)
        .output()
        .expect("run testls");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON output");
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter_map(|f| f["id"].as_str())
        .collect();
    assert!(!ids.contains(&"cookie.insecure"), "{ids:?}");
    assert!(ids.contains(&"cookie.no_httponly"), "{ids:?}");
    let suppressed = v["suppressed"].as_array().expect("suppressed");
    assert_eq!(suppressed.len(), 1, "{suppressed:?}");
    assert_eq!(suppressed[0]["id"], "cookie.insecure");
    assert_eq!(suppressed[0]["reason"], "legacy app");
    assert!(
        stderr.contains("cookie.no_httponly expired on 2000-01-01"),
        "{stderr}"
    );
    assert!(stderr.contains("unknown finding id no.such.id"), "{stderr}");

    let missing = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(addr.to_string())
        .args(["--config", "no/such/file.toml"])
        .output()
        .expect("run testls");
    assert_eq!(missing.status.code(), Some(2));
}

/// A `--baseline` report from an earlier scan accepts its findings: a
/// rescan reports none of them, exits 0 at `--fail-on low` and lists them
/// as suppressed "in baseline".
#[test]
fn baseline_accepts_known_findings() {
    let addr = serve();
    let scan = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_testls"))
            .arg(addr.to_string())
            .args(["--sni", "localhost", "--format", "json", "--fail-on", "low"])
            .args(extra)
            .output()
            .expect("run testls")
    };
    let first = scan(&[]);
    assert_eq!(first.status.code(), Some(1), "findings at or above low");
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("baseline.json");
    std::fs::write(&path, &first.stdout).expect("write baseline");

    let again = scan(&["--baseline", path.to_str().expect("UTF-8 path")]);
    assert_eq!(again.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&again.stdout).expect("JSON output");
    assert_eq!(v["findings"], serde_json::json!([]));
    let suppressed = v["suppressed"].as_array().expect("suppressed");
    assert!(
        suppressed
            .iter()
            .any(|s| s["id"] == "cookie.insecure" && s["reason"] == "in baseline"),
        "{suppressed:?}"
    );

    let missing = scan(&["--baseline", "no/such/baseline.json"]);
    assert_eq!(missing.status.code(), Some(2));
}

/// `--profile quick` skips key exchange, HTTP, tolerance and detail
/// probes and says so in the JSON; `full` turns on the revocation check.
#[test]
fn profiles_select_probes() {
    let addr = serve();
    let run = |profile: &str| {
        let out = Command::new(env!("CARGO_BIN_EXE_testls"))
            .arg(addr.to_string())
            .args(["--sni", "localhost", "--format", "json"])
            .args(["--fail-on", "critical", "--profile", profile])
            .output()
            .expect("run testls");
        assert_eq!(out.status.code(), Some(0), "{profile}");
        serde_json::from_slice::<serde_json::Value>(&out.stdout).expect("JSON output")
    };
    let quick = run("quick");
    let skipped = "skipped by --profile quick";
    assert_eq!(quick["key_exchange"], serde_json::json!([]));
    assert_eq!(quick["post_quantum"]["status"], "not tested");
    for section in ["http", "intolerance", "details"] {
        assert_eq!(quick[section]["error"], skipped, "{section}");
    }
    assert!(quick["revocation"].is_null());
    assert_ne!(quick["ciphers"], serde_json::json!([]));
    let ids = quick["findings"].to_string();
    assert!(!ids.contains("cookie.insecure"), "{ids}");

    let full = run("full");
    assert!(full["revocation"].is_object(), "{}", full["revocation"]);
    assert_eq!(full["http"]["status"], 200);
}

/// `--policy` adds `policy.*` findings for what the policy does not allow,
/// and `policy.incomplete` when the quick profile skips parts of it.
#[test]
fn policy_reports_deviations() {
    let addr = serve();
    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_testls"))
            .arg(addr.to_string())
            .args(["--sni", "localhost", "--format", "json"])
            .args(args)
            .output()
            .expect("run testls");
        let v = serde_json::from_slice::<serde_json::Value>(&out.stdout).expect("JSON output");
        let findings: Vec<(String, String)> = v["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .filter(|f| f["id"].as_str().is_some_and(|id| id.starts_with("policy.")))
            .map(|f| {
                (
                    f["id"].as_str().unwrap_or_default().to_owned(),
                    f["message"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        (out.status.code(), findings)
    };

    let (code, findings) = run(&["--fail-on", "medium", "--policy", "mozilla-modern"]);
    assert_eq!(code, Some(1));
    let ids: Vec<&str> = findings.iter().map(|(id, _)| id.as_str()).collect();
    assert!(ids.contains(&"policy.protocol"), "{findings:?}");
    assert!(ids.contains(&"policy.hsts"), "{findings:?}");
    assert!(!ids.contains(&"policy.incomplete"), "{findings:?}");
    assert!(
        findings
            .iter()
            .all(|(_, m)| m.ends_with("which mozilla-modern does not allow")),
        "{findings:?}"
    );

    let (code, findings) = run(&[
        "--fail-on",
        "critical",
        "--profile",
        "quick",
        "--policy",
        "mozilla-intermediate",
    ]);
    assert_eq!(code, Some(2));
    assert!(
        findings.iter().any(|(id, m)| id == "policy.incomplete"
            && m.contains("key exchange groups, HSTS not measured")),
        "{findings:?}"
    );

    let (_, findings) = run(&["--fail-on", "critical", "--policy", "nist-800-52r2"]);
    assert!(
        findings
            .iter()
            .any(|(id, m)| id == "policy.cipher" && m.contains("TLS_CHACHA20_POLY1305_SHA256")),
        "{findings:?}"
    );
    assert!(
        findings.iter().all(|(id, m)| id != "policy.hsts"
            && id != "policy.incomplete"
            && m.ends_with("which nist-800-52r2 does not allow")),
        "{findings:?}"
    );

    let (_, findings) = run(&["--fail-on", "critical", "--policy", "bsi-tr-02102-2"]);
    assert!(
        findings
            .iter()
            .any(|(id, m)| id == "policy.cipher" && m.contains("TLS_CHACHA20_POLY1305_SHA256")),
        "{findings:?}"
    );
    assert!(
        findings.iter().all(|(id, m)| id != "policy.hsts"
            && id != "policy.incomplete"
            && m.ends_with("which bsi-tr-02102-2 does not allow")),
        "{findings:?}"
    );

    // The rustls server offers only TLSv1.2 and TLSv1.3 AEAD suites with
    // forward secrecy and an ECDSA P-256 certificate: compliant.
    let (_, findings) = run(&["--fail-on", "critical", "--policy", "pci-dss-4"]);
    assert_eq!(findings, []);

    let (_, findings) = run(&["--fail-on", "critical", "--policy", "cnsa-2.0"]);
    for id in ["policy.cipher", "policy.cert_key", "policy.cert_signature"] {
        assert!(
            findings.iter().any(|(i, _)| i == id),
            "{id} missing: {findings:?}"
        );
    }
    assert!(
        findings.iter().all(|(id, m)| id != "policy.hsts"
            && id != "policy.incomplete"
            && m.ends_with("which cnsa-2.0 does not allow")),
        "{findings:?}"
    );

    let (_, findings) = run(&["--fail-on", "critical"]);
    assert_eq!(findings, []);
}
