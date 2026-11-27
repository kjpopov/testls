# Using testls

Run `testls --help` for every option and `testls explain FINDING-ID` for
what a finding means and why it matters.

## What it checks

| Area | Details |
| --- | --- |
| Protocols | SSLv2, SSLv3, TLS 1.0–1.3 |
| Cipher suites | Per-protocol enumeration, server preference, weak and obsolete suites |
| Key exchange | Supported groups (X25519, ECDHE curves, ML-KEM hybrids), DHE parameters |
| Certificates | Expiry, chain, hostname, key size, signature, lifetime, embedded SCTs |
| Revocation | OCSP stapling, OCSP and CRL lookups |
| HTTP headers | HSTS, preload, cookies, header hygiene |
| Vulnerabilities | Derived checks: POODLE, BEAST, SWEET32, Logjam, BREACH, ALPACA, Opossum, … |
| Handshake | ClientHello tolerance, TLSv1.3 details, post-quantum readiness |

## Inspect a capture offline

`testls pcap capture.pcap` reads a local classic pcap (up to 64 MiB). Each
line shows the capture timestamp, endpoints, and fields from a visible
`ClientHello`, `ServerHello`, or `HelloRetryRequest`. A client offer is not
a server selection; a server selection does not prove the handshake finished.

Start capturing before the TCP handshake. The importer follows the first TLS
hello in each TCP direction over Ethernet II or raw IPv4/IPv6. It accepts
in-order segments and matching retransmissions, including hellos split across
TLS records. It skips mid-stream traffic, STARTTLS, VLANs, IP fragments and
IPv6 extension headers. A gap or conflicting overlap abandons that direction.
It remembers the last 1,024 finished directions to suppress duplicate TCP
openers. It tracks up to 128 unfinished directions and reads up to 80 KiB of TCP
prefix per direction for a hello body of up to 64 KiB.

Zero observed hellos is a valid result, including for encrypted or incomplete
captures. An unreadable, malformed or unsupported capture returns exit code 2;
lines printed before a framing error describe only the valid prefix.

### Browser build

The browser viewer reads the selected file in a local Web Worker. It uses the
same decoder as `testls pcap` and displays the first 2,048 hellos, with totals
for the whole file. There is no scan service or file upload. Build it from
the repository root with the `wasm-bindgen` CLI matching `Cargo.lock`:

```sh
rustup target add wasm32-unknown-unknown
id=$(cargo pkgid --locked wasm-bindgen)
cargo install --locked --bin wasm-bindgen --version "${id##*@}" wasm-bindgen-cli
sh scripts/build-pcap-web.sh
python3 -m http.server 8000 --bind 127.0.0.1 --directory target/pcap-web
```

Open `http://127.0.0.1:8000/` and choose a capture. To embed the reader, import
the generated `testls_wasm.js` module, `await init()` (its default export),
and call `inspectCapture(bytes)` with a `Uint8Array`. It returns plain text or
throws on invalid input. `maxCaptureBytes()` gives the limit to check before
loading a file into memory. Use `textContent` to display the result.

## Targets

```bash
# A host (port 443 by default)
testls example.com

# Several targets, from the command line and a file (one per line)
testls example.com example.org:8443 --file hosts.txt

# Every address in a range, or every address of a host
testls 192.0.2.0/28:8443
testls --all-addresses example.com

# A mail server with SMTP STARTTLS (port 25 by default)
testls --starttls smtp mail.example.com
testls --starttls smtp mail.example.com:587
# IMAP (port 143), POP3 (port 110), FTP AUTH TLS (port 21), XMPP
# (port 5222), LDAP StartTLS (port 389), PostgreSQL (port 5432) and
# MySQL/MariaDB (port 3306) work the same way
testls --starttls imap mail.example.com
testls --starttls ftp ftp.example.com
testls --starttls ldap ldap.example.com
testls --starttls postgres db.example.com
testls --starttls mysql db.example.com
# XMPP addresses the stream to the SNI name; set --sni when the XMPP
# domain differs from the host name
testls --starttls xmpp --sni example.com xmpp.example.com

# Every mail server (MX host) of a domain, with SMTP STARTTLS on port 25
testls --mx example.com
```

## Connection control

`--delay 250ms` makes the scanner wait at least 250 milliseconds between
TCP connection starts within each target scan, including STARTTLS. The first
starts immediately. Use whole milliseconds (`ms`) or seconds (`s`); the
default is zero. Waiting does not use the connect timeout. DNS and
third-party revocation fetches are separate.

With `--proxy`, the delay spaces connections **from the scanner to the proxy**.
The proxy decides when to connect to the target and may start several upstream
connections close together, even when the scanner spaces its requests.

`--parallel 3` tests up to three protocol versions at once. The range is 1–8
and the default is 1. With both flags set, the scanner still spaces its own
connection starts, even when earlier offers are pending. Later measurements
and targets run in order, and protocol output retains its usual order.

```bash
# Scan a host name at a fixed address, e.g. a new server before a DNS change
testls --resolve example.com:443:192.0.2.10 example.com

# Connect from a chosen local address on a multi-homed host
testls --source-ip 192.0.2.5 example.com

# Scan through an HTTP proxy (CONNECT, no authentication)
testls --proxy proxy.example:3128 example.com

# Trust the operating system's roots or a private CA instead of Mozilla's
testls --system-roots intranet.example
testls --ca-file my-ca.pem 10.0.0.5 --sni intranet.example
```

## Scan depth

```bash
# Also ask the CA's OCSP responder or CRL whether the certificate is revoked
testls --revocation example.com

# Revocation lookups refuse private and loopback addresses; allow them for
# an internal CA
testls --revocation --revocation-allow-private intranet.example

# Quick check (protocols, cipher suites, certificate) or everything,
# including revocation and every address of the host
testls --profile quick example.com
testls --profile full example.com
```

## Output formats

| `--format` | Use |
| --- | --- |
| `text` (default) | Terminal, sections printed as they finish |
| `json` | Scripts; see [json-schema.md](json-schema.md) |
| `sarif` | SARIF 2.1.0 log for GitHub code scanning |
| `junit` | JUnit XML for CI test reports |
| `markdown` | CI job summaries and pull request comments |
| `csv` | One row per finding, for spreadsheets; a target that failed to scan gets a `scan.error` row |
| `html` | Self-contained page to share or archive |

```bash
testls --format sarif example.com > testls.sarif
testls --format markdown example.com >> "$GITHUB_STEP_SUMMARY"
```

## Grade

Each completed scan ends with a letter grade (A+, A, A-, B, C, F) and the reasons it
is not better; `T` marks an untrusted or mismatched certificate. It is
testls' own model, not SSL Labs', and does not affect the exit status. See
[grading.md](grading.md).

## Exit status

| Code | Meaning |
| --- | --- |
| `0` | No finding at or above `--fail-on` (default `high`) |
| `1` | At least one finding at or above `--fail-on` |
| `2` | The scan itself failed |

## Intrusive probes

`testls --intrusive example.com` enables Heartbleed, CCS injection,
Ticketbleed and ROBOT probes, including with the `quick` profile. No profile
enables them automatically; the server API does not expose them.

ROBOT compares RSA padding responses at one measured static RSA suite per
TLS 1.0–1.2 version. A reproducible fatal-alert difference against a
`bad_record_mac` control produces a high `vuln.robot` finding. The probe also
sends the `ClientKeyExchange` alone: a server that answers a malformed block
with an alert or an early close while the valid block keeps waiting for the
client's `Finished` leaks the same oracle and is reported as vulnerable.
Equal alerts, equal flows, other responses, and unsupported suites are **not
tested**; they do not establish that the server is safe. Only these padding
variants and the selected suites are covered; timing oracles are not.
An optional client-certificate request is validated before sending an empty
certificate; this probe never uses client credentials. Required-client-auth
refusal and any change to the request between attempts are **not tested**.
A changed certificate or request stops that suite's probe without retries;
alert differences from changing authentication policies are not oracle evidence.

A correlated heartbeat response with an extra payload byte confirms
`vuln.heartbleed` (critical). Disclosure is limited to one byte beyond the
supplied payload and the byte is never reported. A fatal `bad_record_mac`
after early CCS and bogus ciphertext indicates premature cipher activation,
reported as `vuln.ccs_injection` (high); CVE-2014-0224 exploitation also
requires a vulnerable client and a man in the middle. Ticketbleed first
completes a TLS 1.2 handshake for a session ticket, then requests resumption
with a 31-byte session ID; an ID extended by one byte in the abbreviated
server flight produces a high `vuln.ticketbleed` finding for **possible**
memory exposure (CVE-2016-9244; NVD 7.5 High). An unchanged echo is reported
as not vulnerable. TLS 1.3-only servers are not tested. Some servers extend the ID without disclosing
memory, so check the server implementation. The Heartbleed and CCS probes do
not complete the handshake; the ticket probe does, and its handshake supports
the TLS 1.2 algorithms available to rustls, so older-only servers remain not
tested. Rejection, silence, unavailable tickets and other responses are
**not tested** and do not establish that a server is safe. TLS 1.3 is not
tested.

## Compliance policies

`--policy` reports everything a published configuration does not allow
(severity `medium`). Repeat it to check several. When a part the policy
covers was skipped (for example by `--profile quick`) or its probe failed,
an extra `policy.incomplete` finding (severity `info`) names it; it does not
trigger `--fail-on medium`.

| Policy | Source |
| --- | --- |
| `mozilla-modern`, `mozilla-intermediate` | Mozilla Server Side TLS 6.0 |
| `nist-800-52r2` | NIST SP 800-52 Rev. 2 (TLS servers and clients of US federal systems) |
| `bsi-tr-02102-2` | BSI TR-02102-2 (German federal guideline) |
| `pci-dss-4` | PCI DSS v4.0.1 (strong cryptography, no early TLS) |
| `cnsa-2.0` | CNSA 2.0 (TLSv1.3, ML-KEM-1024, ML-DSA-87) |

```bash
testls --policy mozilla-intermediate --fail-on medium example.com
```

## Suppressions

To accept a known finding, add it to `.testls.toml` in the working directory
(or pass `--config FILE`). Suppressed findings are listed separately, do not
count towards `--fail-on` and come back after `expires`:

```toml
[[suppress]]
id = "cookie.insecure"
target = "example.com"       # optional, default: every target
reason = "legacy app, replaced in Q1"
expires = 2026-12-31         # optional, last day (UTC) the entry applies
```

## Baseline

To fail only on new findings, save a JSON report and pass it as baseline:

```sh
testls --format json example.com > baseline.json
testls --baseline baseline.json --fail-on low example.com
```

A finding counts as known only if its severity has not risen since the
baseline. Failed or incomplete measurements (`*.error`, `*.incomplete`,
`cert.unparsable`) are never known.

## Web service

`testls serve` runs an HTTP service that starts scans and streams their
progress:

```sh
testls serve                       # http://127.0.0.1:8080, no token
testls serve --listen 0.0.0.0:8080 # prints a generated bearer token
```

Open the address in a browser for the UI: a scan form (target, STARTTLS,
profile, SNI, revocation, policies), live section progress, the grade,
findings filterable by severity with an explanation per finding,
certificate expiry, protocols, vulnerabilities, recent scans and report
export. When the service needs a token the page asks for it and keeps it
in the browser tab only.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/scans` | Start a scan; answers `202` with its `id` |
| `GET` | `/scans` | Recent scans, newest first |
| `GET` | `/scans/{id}` | Sections so far, error, JSON report once done |
| `GET` | `/scans/{id}/events` | Server-sent events: `section` per section, then `done` |
| `GET` | `/scans/{id}/report?format=FORMAT` | Report in any `--format`; `fail_on=` for summary formats |
| `GET` | `/explanations/{id}` | What `testls explain ID` prints, as JSON |
| `GET` | `/` | Browser UI |

```sh
curl -X POST localhost:8080/scans -H 'content-type: application/json' \
  -d '{"target":"example.com","profile":"quick"}'
curl -N localhost:8080/scans/1/events
curl 'localhost:8080/scans/1/report?format=html' > report.html
```

The request body takes `target` (with optional `:port`), `starttls`,
`sni`, `profile`, `revocation` and `policies`. Suppressions and baselines
do not apply.

### Service safety

- Without a token, only requests whose `Host` header names loopback are
  served. On other addresses every request needs
  `Authorization: Bearer TOKEN`; `--token-file` sets the token.
- Targets on loopback, private and other special-purpose addresses are
  refused unless `--allow-private`.
- `--max-concurrent`, `--max-per-minute`, `--max-history`,
  `--max-streams` and `--scan-timeout` bound the load; scans are kept in
  memory only.
- The service speaks plain HTTP. Beyond loopback, put it behind a TLS
  reverse proxy or tunnel so the token is not sent in the clear.

Ctrl-C (and SIGTERM on Unix) stops the service after open connections
close. If they are still open after 10 seconds it stops anyway with exit
code 0. A second signal stops it at once with exit code 130.
