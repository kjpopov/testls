# Changelog

All notable changes to `testls` are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Explicit `--intrusive` pre-handshake Heartbleed and CCS injection probes
  for measured TLS 1.0–1.2 versions. Correlated Heartbleed disclosure creates
  a critical finding; early CCS with a bad record MAC creates a high finding.
  Refused or unanswered probes remain inconclusive.
- Opt-in Ticketbleed probe for TLS 1.2 session ticket resumption; abnormal
  session ID extension creates a high finding for possible memory exposure;
  an unchanged echo reports not vulnerable. Skipped when TLS 1.2 is not offered.

## [0.6.0] - 2026-11-08

### Added

- New library crate `testls-scan` runs the whole scan pipeline and reports
  each finished section as a typed event; the CLI is built on it and its
  output is unchanged. It is the base for the v0.6 web service.
- `testls serve` runs an HTTP service (crate `testls-server`): start scans
  with `POST /scans`, follow them live as server-sent events, list recent
  scans and download reports in every output format. It listens on
  127.0.0.1 by default, demands a bearer token on other addresses, refuses
  private targets unless `--allow-private`, and limits concurrent scans,
  scans per minute and scan time. Ctrl-C (and SIGTERM on Unix) shuts it
  down gracefully; a second signal stops it at once.
- `testls serve` includes a browser UI at `/`: scan form, live progress,
  grade, findings with severity filter and explanations, certificate
  expiry, history and report export. Plain JavaScript embedded in the
  binary, served under a strict content security policy.

## [0.5.0] - 2026-10-30

STARTTLS for mail, FTP, XMPP, LDAP and database servers, `--mx`, BREACH,
ALPACA and Opossum verdicts, a letter grade, and the security fixes from
the external audit in #117. Intrusive checks moved to the backlog.

### Added

- `--starttls smtp|imap|pop3|ftp|xmpp|ldap|postgres|mysql` upgrades each
  connection with the protocol's STARTTLS command (`AUTH TLS` for FTP, the
  `StartTLS` extended operation for LDAP, `SSLRequest` for PostgreSQL and
  MySQL/MariaDB) before the TLS handshake, so mail, FTP, XMPP, directory and
  database servers can be scanned. Targets without a port use the
  protocol's standard port (25, 143, 110, 21, 5222, 389, 5432, 3306); HTTP
  headers are not checked. XMPP addresses the stream to the SNI name.
- `--mx` scans the mail servers of each target domain instead of the
  domain: its MX hosts, sorted by preference, each with `--starttls smtp`
  on port 25 (or the target's port). A domain without MX records is
  scanned itself; a null MX, an unknown domain or a failed lookup is a
  scan error for that target (exit code 2). IP and CIDR targets are
  rejected.
- BREACH verdict (`breach`, finding `vuln.breach`, low): the `GET /`
  request now offers `Accept-Encoding: gzip, deflate, br, zstd`, and a
  reply with a content coding other than `identity` is reported as
  vulnerable. Without an HTTP reply (quick profile, `--starttls`, non-HTTP
  service) it is not tested.
- ALPACA verdict (`alpaca`, finding `vuln.alpaca`, low): the handshake
  feature probe sends one more hello at the best version offering only an
  unknown ALPN protocol; a server that completes the handshake instead of
  answering `no_application_protocol` is reported as vulnerable. Not
  tested under the quick profile.
- Opossum verdict (`opossum`, finding `vuln.opossum`, medium): a plaintext
  `OPTIONS *` request with `Upgrade: TLS/1.0` (RFC 2817) goes to the
  scanned port and port 80; a `101 Switching Protocols` reply to TLS on
  either is reported as vulnerable. Not tested under the quick profile or
  `--starttls`.
- Letter grade per scan (A+, A, A-, B, C, F, with `T` for an untrusted or
  mismatched certificate and the reasons it is not better), testls' own
  model documented in [docs/grading.md](docs/grading.md), not SSL Labs'.
  The worst finding of severity `low` or worse caps it, `policy.*`
  findings excepted, before suppressions and baseline. Shown in every
  format (`grade` object in JSON); it does not change the exit status.

### Security

- Text reports and CSV escape control characters in server-supplied text
  (error messages, findings, suppression reasons, targets, SNI,
  vulnerability details, STARTTLS replies and XMPP stream errors), so a
  malicious server cannot send terminal escape sequences. Reported by
  @r4d1um in #117.
- `--baseline` treats a finding as known only if its severity has not risen
  since the baseline, and never treats failed or incomplete measurements
  (`*.error`, `*.incomplete`, `cert.unparsable`) as known. An invalid
  severity in the baseline is a scan error. Reported by @r4d1um in #117.
- The certificate fetch checks the server's handshake signature against its
  certificate, so a peer relaying another server's certificate fails with
  `cert.error`. Signatures testls cannot check (ML-DSA, P-521, Ed448, RSA keys
  under 2048 bits) are reported as `cert.signature_unverified`. Reported by @r4d1um in
  #117.
- A partitioned CRL is used only if its distribution point matches one in the
  certificate, so a CRL for another partition can no longer report a revoked
  certificate as good. Reported by @r4d1um in #117.
- Revocation lookups refuse loopback, private, link-local and other
  non-public addresses, so a certificate cannot point the scanner at internal
  services. `--revocation-allow-private` allows them for internal CAs.
  Reported by @r4d1um in #117.

## [0.4.3] - 2026-10-27

Patch release with a readable `--help` and the shorter README on the
Marketplace page. v0.4.2 was created by mistake from the GitHub web UI; it has no build of
its own, so skip it.

### Changed

- `testls --help` shows options as two aligned columns, flags on the left
  and wrapped descriptions on the right, at most 100 columns wide.
- The README is short; details moved to `docs/usage.md`, `docs/install.md`
  and a GitHub Action guide in `docs/github-action.md`.

## [0.4.1] - 2026-10-27

Patch release so the GitHub Action can be listed on the Marketplace.

### Changed

- The GitHub Action is named "testls TLS scanner", so it can be listed on
  the GitHub Marketplace (the name `testls` is taken).

## [0.4.0] - 2026-10-27

Workflow: several targets, connection control, CI report formats,
suppressions and baselines, scan profiles, compliance policies and packaging.

### Added

- Several targets per run: list them on the command line or in a file with
  `--file` (one per line, `#` comments). JSON output becomes an array of
  documents and the exit code is the worst of all targets.
- CIDR ranges as targets, such as `192.0.2.0/28` or `[2001:db8::/120]:8443`
  (at most 16 host bits).
- `--all-addresses` scans every A/AAAA address of a host name and warns on
  stderr when they differ in protocols, cipher suites or certificate.
- `--resolve HOST:PORT:ADDR[,ADDR...]` connects to the given addresses
  instead of looking up the target host name, keeping the name for SNI.
- `--source-ip ADDR` connects from a chosen local address, for the target
  and for revocation lookups.
- `--proxy [http://]HOST:PORT` tunnels all connections through an HTTP
  proxy with `CONNECT`, including revocation lookups.
- `--format sarif` prints one SARIF 2.1.0 log of all findings, for GitHub
  code scanning and other SARIF tools.
- `--format junit` prints one JUnit XML document for CI test reports:
  findings at or above `--fail-on` are failures, failed scans are errors.
- `--format markdown` prints one Markdown summary for CI job summaries and
  pull request comments, marking findings at or above `--fail-on`.
- `--format csv` prints one CSV row per finding for spreadsheets and
  scripts, plus a `scan.error` row for each target that failed to scan.
- `--format html` prints one self-contained HTML page with the same
  summary and findings as the Markdown report, for sharing and archiving.
- Suppressions in `.testls.toml` (or `--config FILE`): each entry names a
  finding id, an optional target, a reason and an optional expiry date.
  Suppressed findings are listed separately (JSON `suppressed`) and do not
  count towards `--fail-on`; expired and unknown entries warn on stderr.
- `--baseline FILE` takes an earlier `--format json` report: findings it
  lists for the same target and id are suppressed with reason
  `in baseline`, so only new findings fail the scan.
- `--profile quick|default|full` picks the scan depth: `quick` checks
  protocols, cipher suites and the certificate only, `default` is the
  previous behaviour, `full` adds `--revocation` and `--all-addresses`.
- `--policy mozilla-modern|mozilla-intermediate` (repeatable) reports what
  the Mozilla Server Side TLS 6.0 profile does not allow as `policy.*`
  findings; parts the scan did not measure give `policy.incomplete`.
- `--policy nist-800-52r2` checks against NIST SP 800-52r2 for government
  servers: TLSv1.2 and TLSv1.3 (both required), the listed suites and groups, RSA of at
  least 2048 bits or ECDSA on P-256/P-384.
- `--policy bsi-tr-02102-2` checks against BSI TR-02102-2 (2025-01):
  TLSv1.2 and TLSv1.3, forward-secret suites, NIST and brainpool groups,
  RSA of at least 3000 bits, RSASSA-PSS or ECDSA signatures.
- `--policy pci-dss-4` checks against PCI DSS v4.0.1 requirement 4.2.1:
  TLSv1.2 and TLSv1.3, no broken or 64-bit block cipher suites, groups,
  DHE primes and keys of at least 112-bit strength.
- `--policy cnsa-2.0` checks against the NSA CNSA 2.0 TLS profile: TLSv1.3
  only (required), `TLS_AES_256_GCM_SHA384`, ML-KEM-1024 and ML-DSA-87
  certificates.
- `testls completions SHELL` prints a completion script for bash, zsh,
  fish, PowerShell or elvish, `testls man` prints the man page, and
  `testls man --dir DIR` writes it with one page per subcommand.
- crates.io packaging: `cargo binstall testls` fetches the release archive
  and `cargo install --locked testls` builds from source; releases publish
  the crates with trusted publishing once the maintainer enables it.
- Homebrew tap (`Formula/`), Scoop bucket (`bucket/`) and winget manifests
  (`packaging/winget/`) for the release archives, generated from a
  release's `SHA256SUMS` by `scripts/gen-packages.py`.
- Container image `ghcr.io/kjpopov/testls` (linux/amd64 and linux/arm64,
  distroless, unprivileged), pushed by the release workflow.
- GitHub Action (`action.yml`): installs a release with checksum
  verification, adds it to `PATH` and optionally runs it with `args`.

## [0.3.0] - 2026-10-26

Finding ids, derived vulnerabilities, ClientHello tolerance, TLSv1.3 details,
post-quantum readiness, certificate lifetime and HTTP extras.

### Added

- `testls explain [ID]` describes a finding id with its rationale and a
  reference, or lists every id when none is given.
- Vulnerabilities section (text and JSON `vulnerabilities` array) with
  POODLE, BEAST, SWEET32, RC4, FREAK, Logjam, DROWN, CRIME, insecure
  renegotiation, `TLS_FALLBACK_SCSV`, forward secrecy and Raccoon verdicts,
  derived without attack traffic.
- Findings `vuln.beast`, `vuln.crime`, `vuln.renegotiation`,
  `vuln.fallback_scsv`, `vuln.logjam` and `vuln.raccoon`.
- The Logjam verdict names well-known DH primes (RFC 2409, 3526, 5114,
  7919), and a second DHE handshake checks whether the server reuses its DH
  public value.
- ClientHello tolerance section (text and JSON `intolerance` object):
  unknown version, unknown extension, GREASE, a record-filling hello and a
  fragmented hello, with `intolerance.*` findings for rejections.
- Post-quantum readiness section (text and JSON `post_quantum` object):
  TLSv1.3 ML-KEM groups, draft Kyber code points listed separately, and
  whether the server prefers ML-KEM.
- Handshake details section (text and JSON `details` object): extended
  master secret, TLSv1.3 downgrade sentinel, session tickets and 0-RTT,
  with `handshake.no_ems`, `handshake.no_downgrade_sentinel` and
  `handshake.early_data` findings.
- Leaf certificates show their embedded Certificate Transparency timestamp
  count (text `SCTs` line, JSON `chain[].scts`). Chains to the bundled
  Mozilla roots are checked against the Baseline Requirements lifetime limit
  and for missing SCTs (`cert.too_long`, `cert.no_sct`, `cert.sct_invalid`).
- HTTP headers section lists `Server`/`X-Powered-By` banners, `Alt-Svc`
  alternatives and cookie attributes (JSON `http.banners`, `http.alt_svc`,
  `http.cookies`), with `header.banner`, `header.alt_svc_invalid` and
  `cookie.*` findings.

### Changed

- Obsolete draft Kyber groups are rated low and reported as `group.weak`.
- Text output shows each finding's id in brackets, e.g.
  `[hsts.missing]`.

## [0.2.0] - 2026-10-25

Key exchange, HTTP security headers and revocation checks.

### Added

- Key exchange section per offered protocol: supported groups in the
  server's order (including X25519MLKEM768 and other ML-KEM hybrids for
  TLSv1.3) and the DH prime size for DHE suites.
- Findings for deprecated curves (RFC 8422), DH primes below 2048 bits, and
  TLSv1.3 without a post-quantum (ML-KEM) group.
- `key_exchange` array in the JSON report (additive; schema version stays 1).
- HTTP headers section from one `GET /` over a full handshake: HSTS
  (RFC 6797) with preload eligibility, Content-Security-Policy,
  X-Frame-Options, X-Content-Type-Options, and Referrer-Policy.
- Findings for a missing, invalid, disabled, or short (under 180 days) HSTS
  policy, a preload request that does not meet the preload list's
  requirements, and missing security headers (info).
- `http` object in the JSON report (additive).
- Stapled OCSP response check (RFC 6960): the response is verified against
  the issuer or a delegated responder and shown in the certificate section.
- Findings for a revoked, unknown, invalid, or stale OCSP response, a
  Must-Staple certificate (RFC 7633) without a staple, and no staple (info).
- `certificate.ocsp` object in the JSON report (additive).
- `--revocation`: ask the issuer's OCSP responder, falling back to its CRLs,
  whether the leaf certificate is revoked. Off by default because it
  contacts servers other than the target.
- Findings for a revoked certificate, an unknown or stale answer, and no
  usable OCSP responder or CRL (info); `revocation` object in the JSON
  report (additive).

## [0.1.0] - 2026-10-24

First stable release of the command-line scanner.

### Added

- Certificate checks: validity period, hostname/SAN match, key type and size,
  signature algorithm, and chain trust against the bundled Mozilla roots.
- `--ca-file` to trust only the roots in a PEM bundle, and `--system-roots` to
  trust the operating system's store (`SSL_CERT_FILE` / `SSL_CERT_DIR`
  override it).
- Findings with severities (`ok` to `critical`) for protocols, cipher suites
  and certificates; `--fail-on` sets the exit-status threshold (exit `0`, `1`,
  or `2` on scan errors).
- `--format json` with a versioned schema ([docs/json-schema.md](docs/json-schema.md)).
- Coloured text output with `--color auto|always|never`, honouring `NO_COLOR`.

### Changed

- Text rendering moved into the `testls-report` crate.

### Security

- Control characters in certificate details are escaped before printing.

### Project

- CI: required checks for fmt, clippy, tests on Linux/macOS/Windows, MSRV,
  static musl builds, integration tests against local OpenSSL servers,
  coverage, `cargo deny`, `zizmor` and `cargo fuzz` runs on the wire parsers.
- Dependabot updates with a 7-day cooldown; actions pinned by commit.

## [0.1.0-alpha.1] - 2026-10-23

First pre-release.

### Added

- Protocol detection for SSLv2, SSLv3 and TLS 1.0–1.3 with a hand-written
  handshake codec.
- Cipher suite enumeration per protocol and server preference detection.
- Target parsing for host, host:port, IPv4/IPv6 and URLs, plus `--sni`.
- Release binaries for Linux (static musl), macOS and Windows.

[Unreleased]: https://github.com/kjpopov/testls/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/kjpopov/testls/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/kjpopov/testls/compare/v0.4.3...v0.5.0
[0.4.3]: https://github.com/kjpopov/testls/compare/v0.4.1...v0.4.3
[0.4.1]: https://github.com/kjpopov/testls/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/kjpopov/testls/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kjpopov/testls/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kjpopov/testls/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kjpopov/testls/compare/v0.1.0-alpha.1...v0.1.0
[0.1.0-alpha.1]: https://github.com/kjpopov/testls/releases/tag/v0.1.0-alpha.1
