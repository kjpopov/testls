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

Safety:

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
