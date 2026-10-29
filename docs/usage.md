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
| Vulnerabilities | Derived checks: POODLE, BEAST, SWEET32, Logjam, … |
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

## Exit status

| Code | Meaning |
| --- | --- |
| `0` | No finding at or above `--fail-on` (default `high`) |
| `1` | At least one finding at or above `--fail-on` |
| `2` | The scan failed or a required measurement / requested policy is incomplete |

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

Baselines only accept the same finding ID for the same target at an equal or
lower severity. Escalations remain visible; error and incomplete findings are
never accepted by a baseline. Suppression does not change scan completeness.

Revocation fetches default to public unicast IPs on HTTP port 80. Private,
loopback, link-local, reserved and transition addresses are blocked. To use a
trusted internal responder or nonstandard port, repeat
`--revocation-endpoint IP:PORT` for each exact destination to permit. The
allowance does not itself enable revocation checks. DNS is resolved locally
once per request; direct connections and proxy CONNECT tunnels use the checked
IP, while HTTP Host retains the endpoint hostname. Redirects are not followed.

Full TLS handshakes verify the server's signature even when collecting an
untrusted or expired certificate. The ring provider cannot verify ML-DSA, so
ML-DSA-only servers produce an incomplete certificate measurement instead of an
unverified successful handshake. Named/partitioned CRLs are reported as
unsupported until distribution-point scope matching is implemented.

Required measurements are protocol detection, cipher enumeration, certificate
retrieval/parsing, and key exchange when selected by the profile. Any failure
returns exit 2 before suppression/baseline filtering; an incomplete requested
policy also returns 2. Optional probes and intentional profile skips alone do
not imply scan failure. Partial results remain available in the report.
