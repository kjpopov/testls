# testls — Project Plan

Living document. Decisions are recorded in the log at the bottom.

## Positioning

- Rust-native TLS/SSL scanner, **inspired by** testssl.sh — no output or
  exit-code compatibility promise.
- Clean-room: no code or data from testssl.sh (GPLv2). Data from IANA/RFCs.
- Single static binary, no OpenSSL, no subprocesses.
- Server mode is a **local/internal tool**, not a public scanning service.

## Architecture

```text
crates/ (Cargo workspace)
├─ testls-wire     # TLS record/handshake codec: build ClientHello, parse
│                  # ServerHello / Alert / Certificate. No I/O. Fuzzable.
├─ testls-data     # Cipher suites, groups, sig-algs (generated from IANA CSV)
├─ testls-probe    # Async probes over TCP using testls-wire
│                  # (protocol support, cipher enumeration, server preference)
├─ testls-checks   # Findings: certificate, headers, vulns; severity model
├─ testls-report   # Text + JSON renderers, exit-code policy
├─ testls-server   # axum REST + SSE, embedded UI (v0.6)
└─ testls (bin)    # clap CLI, wires everything together
```

Two connection paths:

1. **Raw probe path** (`testls-wire` + tokio TCP): sends hand-crafted
   ClientHellos and reads only up to ServerHello/Alert/Certificate. Needed
   because rustls refuses SSLv2/SSLv3/TLS1.0/1.1 and weak ciphers.
2. **Full handshake path** (rustls with a permissive verifier that records,
   not rejects): fetches cert chain for validation, performs HTTP requests for
   header checks.

## Milestones

### v0.1 — Core scanner CLI
- [x] Workspace skeleton, CI (fmt, clippy, test, MSRV), static musl build
- [x] Dependency audit in CI: `cargo deny` (RustSec advisories, bans, licences, sources)
- [x] Dependabot: weekly grouped updates for crates, GitHub Actions and test images
- [x] Workflow audit in CI: `zizmor` (pinned actions, least-privilege tokens)
- [x] Coverage in CI: `cargo llvm-cov` over unit and integration tests
      (job summary + lcov artifact, informational)
- [x] Fuzzing: `cargo fuzz` targets for the `testls-wire` parsers, run in CI
- [x] Release workflow (cross-platform binaries on tag); released as v0.1.0
- [x] `testls-data`: IANA cipher suite, group, sig-scheme registries → generated Rust tables
- [x] `testls-wire`: ClientHello builder (SSLv2-compat, SSLv3, TLS1.0–1.3),
      ServerHello/HelloRetryRequest/Alert parser, extensions (SNI,
      supported_versions, supported_groups, signature_algorithms, key_share)
- [x] Protocol detection: SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3
- [x] Cipher enumeration per protocol (iterative removal) + server preference
- [x] Certificate: chain, expiry, hostname/SAN, key type/size, sig algorithm,
      trust against webpki-roots or a `--ca-file` bundle
- [x] `--system-roots`: trust the operating system's root store
- [x] Output: coloured, TTY-aware text (`--color auto|always|never`)
- [x] Output: JSON (`--format json`, versioned schema in [json-schema.md](json-schema.md))
- [x] Exit codes: 0 ok, 1 findings ≥ `--fail-on` (default `high`), 2 scan error
- [x] Target parsing: host, host:port, URL, IPv4/IPv6, explicit `--sni`
- [x] Integration tests against local test servers (see Testing)

### v0.2 — Key exchange, headers, revocation
- [x] Supported groups incl. X25519MLKEM768, ECDHE curve list, DH param size
- [x] HSTS / preload / security headers via full-handshake path
- [x] OCSP stapling
- [x] OCSP responder, CRL (opt-in `--revocation`)
- [x] Released as v0.2.0

### v0.3 — Findings & derived vulnerabilities
- [x] Finding IDs: keep the dotted IDs as a stable contract, show them in
  text output, and add `testls explain <id>` with a short rationale and
  reference
- [x] Derived vulnerability checks from data the scan already collects (no extra
  attack traffic): POODLE (SSLv3), BEAST, SWEET32, RC4, FREAK (export RSA),
  Logjam (weak or common DH primes, RFC 7919 groups named), DROWN (SSLv2),
  CRIME (TLS compression), insecure renegotiation, `TLS_FALLBACK_SCSV`
  support, no forward secrecy, Raccoon (DH key reuse indicators)
- [x] ClientHello intolerance probes: oversized hellos, unknown versions and
  extensions, GREASE (RFC 8701), fragmented records
- [x] TLSv1.3 details: 0-RTT, session tickets, downgrade sentinel (RFC 8446
  §4.1.3), Extended Master Secret (RFC 7627) for TLSv1.2
- [x] Post-quantum readiness summary: label draft Kyber codepoints separately
  from the standard ML-KEM groups
- [x] Certificate lifetime against the CA/Browser Forum Baseline Requirements
  (publicly trusted certificates only) and embedded SCT parsing
- [x] HTTP extras: `Alt-Svc`, `Server`/`X-Powered-By` banners, cookie flags
- [x] Released as v0.3.0

### v0.4 — Workflow
- [x] Multiple targets on the command line and with `--file`
- [x] CIDR ranges (at most 16 host bits per range)
- [x] `--all-addresses`: scan every A/AAAA address and warn on divergence
- [x] `--resolve HOST:PORT:ADDR[,ADDR...]`
- [x] `--source-ip`
- [x] `--proxy` (HTTP `CONNECT`)
- [x] SARIF output (`--format sarif`)
- [x] JUnit output (`--format junit`)
- [x] Markdown output (`--format markdown`)
- [x] CSV output (`--format csv`)
- [x] HTML output (`--format html`)
- [x] `.testls.toml` suppressions with expiry dates
- [x] `--baseline`
- [x] Scan profiles (`--profile quick|default|full`)
- [x] Mozilla policies (`--policy mozilla-modern|mozilla-intermediate`)
- [x] NIST SP 800-52r2 policy (`--policy nist-800-52r2`)
- [x] CNSA 2.0 policy (`--policy cnsa-2.0`)
- [x] BSI TR-02102-2 policy (`--policy bsi-tr-02102-2`)
- [x] PCI DSS policy (`--policy pci-dss-4`)
- [x] Shell completions and man page (`testls completions`, `testls man`)
- [x] crates.io metadata, `cargo binstall` and a trusted-publishing release job
- [x] Homebrew tap, Scoop bucket and winget manifests
  (`scripts/gen-packages.py`)
- [x] Container image (`ghcr.io/kjpopov/testls`) and GitHub Action
  (`action.yml`)
- [x] Released as v0.4.0
- [x] Released as v0.4.1 (Marketplace action name)
- [x] Released as v0.4.3 (two-column `--help`, short README; v0.4.2 was a web UI mistake)

### v0.5 — STARTTLS, intrusive probes, grading
- [x] STARTTLS: SMTP, IMAP, POP3, FTP, XMPP, LDAP, PostgreSQL, MySQL
  (`--starttls smtp|imap|pop3|ftp|xmpp|ldap|postgres|mysql`)
- `--mx`: scan a domain's mail exchangers (needs SMTP STARTTLS)
- Intrusive checks behind `--intrusive`: Heartbleed, CCS injection,
  Ticketbleed, ROBOT
- Application-layer checks: BREACH, ALPACA, Opossum
- Own grading model (documented, not SSL Labs-compatible)

### v0.6 — Web service
- `testls serve`: axum, binds 127.0.0.1 by default
- REST: `POST /scans`, `GET /scans/{id}`, `GET /scans/{id}/events` (SSE)
- Embedded SPA (static assets via `include_bytes!`/rust-embed)
- Safety: token auth when binding non-loopback, private/link-local target
  blocking toggle, concurrency + rate limits, scan timeouts

## Testing strategy

- Unit tests + `proptest` round-trips for the wire codec
- `cargo-fuzz` targets for the wire parsers in `fuzz/` (record framing,
  handshake reassembly, ServerHello, Certificate, Alert, SSLv2): one minute
  per target on PRs that touch `testls-wire`, ten minutes weekly
- Integration: `tests/servers/compose.yaml` runs `openssl s_server`
  containers with specific protocol/cipher sets (podman or docker);
  `crates/testls/tests/servers.rs` scans them (`--ignored`, own CI job).
- Coverage: `cargo llvm-cov --workspace -- --include-ignored` with the
  test servers running; reported in the job summary, no threshold.
  The JSON renderer is checked field by field against expected documents
- Opt-in live tests against badssl.com (not in default CI)

## Backlog

Not scheduled; pulled into a milestone when someone picks it up.

- PKI: CAA and DANE/TLSA lookups, AIA intermediate fetching, chain order,
  more trust stores
- HTTP/3 (QUIC) and Encrypted Client Hello detection; DTLS
- Library API, pcap import, WASM build
- Release trust: Sigstore signatures, SLSA provenance, SBOM, macOS
  notarization
- Docs: catalogue of checks, mapping from testssl.sh options, threat model

## Open questions

- Default scan profile: what runs without flags, and how long it may take
- Rate limiting / politeness defaults towards scanned servers

## Decision log

| # | Decision | Rationale |
| --- | --- | --- |
| 1 | v0.1 = core scanner CLI only | Engine is the hard, valuable part |
| 2 | Custom raw handshake codec + rustls for full connections | rustls can't negotiate legacy protocols/ciphers; keeps pure-Rust static build |
| 3 | "Inspired by" testssl.sh, no compatibility promise | Avoids huge parity burden |
| 4 | Browser component = web UI embedded in binary; no WebExtension | Browser extension APIs don't expose TLS details (Chrome) |
| 5 | Server mode is local/internal, localhost by default | Avoids SSRF / open-scanner abuse |
| 6 | Clean-room, data from IANA/RFCs | testssl.sh is GPLv2; we're MIT/Apache |
| 7 | Multi-crate Cargo workspace | Isolated, fuzzable wire codec |
| 8 | tokio; bounded parallel probes (default 8 per target, configurable) | Shared runtime with axum server later |
| 9 | Edition 2024, MSRV = stable − 2 (currently 1.97) | Modern Rust, reasonable compatibility |
| 10 | Release targets: Linux x86_64/aarch64 musl, macOS x86_64/arm64, Windows x86_64 | Static Linux; self-contained elsewhere |
| 11 | Trust roots: webpki-roots default, `--system-roots` opt-in | Reproducible results across machines |
| 12 | GitHub + GitHub Actions | Existing repo host |
| 13 | Severity levels ok < info < low < medium < high < critical; `--fail-on` defaults to `high` | Weak-but-common configs (CBC, no PFS) should not fail CI by default |
| 14 | rustls with the `ring` crypto provider (no `aws-lc-rs`) | Simple cross-builds for static musl and Windows: no cmake/nasm toolchain |
| 15 | Trust is checked with `rustls-webpki` path building, at a time clamped into the leaf's validity period | Same verifier as rustls clients; expiry is reported once, by the certificate checks |
| 16 | `--ca-file` replaces the bundled roots with a PEM bundle; the leaf is matched against the SNI name, else the target IP | Lets private PKIs and the integration tests get a clean trust result |
| 17 | Colour defaults to `--color auto`: on for terminals, off when piped or `NO_COLOR` is set; hand-written ANSI codes, no colour crate; on Windows `auto` also requires enabling virtual terminal processing (via `anstyle-query`, already pulled in by clap) | Same convention as cargo/git/ripgrep; logs and files stay clean; legacy Windows consoles would print raw escape codes |
| 18 | JSON output (`--format json`) is one document printed at the end, built with serde from dedicated schema structs; `schema_version` bumps only on breaking changes; times are Unix seconds | Internal types can change without breaking consumers; additive fields stay compatible; integers avoid date-format parsing |
| 19 | `cargo deny` checks advisories daily, on pushes to `main`/`develop` and on pull requests; advisories block a pull request only when it changes a `Cargo.toml` or `Cargo.lock`, while licences, bans and sources always block | New advisories should be fixed promptly, but must not fail unrelated PRs; a PR that adds a vulnerable crate must still fail |
| 20 | Dependabot groups minor/patch crate and action bumps into one weekly PR each; the test image base is pinned by digest; majors and security fixes get their own PRs; version updates wait 7 days after a release | Few PRs to review, while breaking upgrades stay isolated |
| 21 | Actions are pinned to full commit SHAs with the tag in a comment; workflows default to `contents: read` and checkout does not persist credentials; `zizmor` gates workflow changes | A moved tag or compromised action cannot change what CI runs; jobs cannot push with the token they were given |
| 22 | Coverage comes from `cargo llvm-cov` on Linux, including the integration tests; it is published as a job summary and lcov artifact, without a third-party service, token or failing threshold | The CLI is only exercised end to end, so unit tests alone under-report it; a hard threshold would block small PRs for noise |
| 23 | Fuzz targets live in a standalone `fuzz/` crate (own lockfile, nightly only) and run with libFuzzer for a short time in CI, only when `testls-wire`, `fuzz/` or the root `Cargo.toml` change, plus a longer weekly run; no corpus is committed yet | Parsers of untrusted network input are the riskiest code; keeping nightly out of the workspace leaves the stable and MSRV builds unaffected |
| 24 | `--system-roots` loads the OS store with `rustls-native-certs` (keychain, Windows store, OpenSSL bundle; `SSL_CERT_FILE`/`SSL_CERT_DIR` override); certificates webpki cannot use as anchors are skipped, partial load errors are printed as warnings, and only an empty result is a scan error; it conflicts with `--ca-file` | Maintained rustls-ecosystem crate with no OpenSSL link; real system stores contain odd roots that must not break the whole scan |
| 25 | Every CI check is required on `main` (`protectmain` ruleset). Workflows that only matter for some files (`zizmor`, `fuzz`) still run on every pull request and skip their work in a step instead of using `paths:` filters; CI and coverage cancel superseded pull request runs; cargo commands run with `--locked` | A path-filtered required check never reports and blocks unrelated PRs; `--locked` catches a stale `Cargo.lock` on the PR instead of at release time |
| 26 | Releases are cut from `main` by a version-bump PR that updates `Cargo.toml` and `CHANGELOG.md` (Keep a Changelog); the `v*` tag is pushed after it merges, and the release workflow publishes binaries with generated notes; tags with a `-` suffix are pre-releases | The changelog is curated for users, while generated notes still credit every PR; the workflow refuses tags that don't match `Cargo.toml` |
| 27 | Supported groups are enumerated per offered version by offering a shrinking group list and removing each selected group: TLSv1.3 sends an empty `key_share` so the server names its choice in a HelloRetryRequest, while TLSv1.0–1.2 read the named curve from the ECDHE ServerKeyExchange. The DH prime size comes from a DHE ServerKeyExchange. Curves below `secp256r1` rate medium (RFC 8422 §5.1.1), DH primes below 1024 bits high and below 2048 medium; TLSv1.3 without an ML-KEM group is info | No key shares need computing, so no crypto dependency is added and every registered group, including ML-KEM hybrids, can be probed |
| 28 | HTTP headers come from one `GET /` (HTTP/1.1, ALPN `http/1.1`, `Connection: close`) over the rustls full handshake; only the status line and header section are read (64 KiB cap) and redirects are not followed. A missing, invalid, disabled, or short (under 180 days) HSTS policy is low; missing CSP, framing protection, `nosniff`, and Referrer-Policy are info; a failed fetch is info because many TLS services do not speak HTTP | The headers of the first response are what a browser applies to this origin; reusing rustls avoids a new HTTP dependency, and low/info severities keep `--fail-on high` usable for non-web endpoints |
| 29 | The stapled OCSP response is parsed with a small DER reader (RFC 6960) and verified against the chain's issuer or a delegated responder carrying the OCSPSigning EKU; the `CertID` may use SHA-1 or SHA-2. Revoked is critical, unknown, invalid, or stale (outside `thisUpdate`/`nextUpdate`, or older than one day without `nextUpdate`, with 5 minutes of clock skew) is medium, a Must-Staple certificate (RFC 7633) without a staple is high, and no staple at all is info | No OCSP crate is mature and permissively licensed; `ring` is already in the tree for the digests and `x509-parser` verifies the signature. Not stapling is common and only costs privacy and latency, while a broken staple makes browsers that honour it fail |
| 30 | OCSP test fixtures are generated by `scripts/gen-ocsp-fixtures.sh` (OpenSSL 3+) and gitignored rather than committed; tests take their clock from the generated response's `thisUpdate`. A delegated OCSP responder must also allow `digitalSignature` when it carries a keyUsage extension (RFC 5280 §4.2.1.3) | Committed binary fixtures are opaque to review and expire; a script documents how each certificate and response is built. CI runs the script before the build on every runner |
| 31 | Revocation checks against the issuer's services are opt-in (`--revocation`). The OCSP responders from Authority Information Access are queried first (`POST`, SHA-1 `CertID`, no nonce, RFC 5019), then the CRLs from CRL Distribution Points (capped at 16 MiB); only `http://` URLs are used, and the first verifiable answer decides. Revoked is critical, unknown or stale is medium, and no source or every attempt failing is info. Indirect and delta CRLs are not supported | Querying the CA leaks which site is scanned to a third party and adds latency, so it is off by default. Responders are cheaper than CRLs; HTTP is what RFC 6960 and RFC 5280 expect and avoids a TLS bootstrap loop |
| 32 | The wire codec stays hand-rolled instead of building the read side on a parser crate such as `tls-parser` | It already covers every message the probes need, is fuzzed in CI, and accepts the malformed and legacy input a scanner must tolerate without another dependency |
| 33 | Network policy: apart from the target, DNS lookups (CAA, DANE/TLSA, MX) will be on by default with one opt-out switch, while every other third-party service (OCSP/CRL, AIA fetching, CT logs) is opt-in with its own flag, like `--revocation`; an umbrella flag is added only once two or more such flags exist | DNS reveals little beyond the scanned name, while contacting a CA or log tells a third party what is scanned; per-feature flags keep air-gapped and pentest use explicit |
| 34 | Roadmap order: v0.3 findings and derived vulnerability checks, v0.4 workflow (targets, formats, policies, packaging), v0.5 STARTTLS, intrusive probes behind `--intrusive` and grading, v0.6 web service | Derived checks reuse data already collected and need no attack traffic; workflow features make the scanner usable in CI before it grows new protocols; intrusive probes stay opt-in |
| 35 | Every finding id has an entry in a static catalogue in `testls-checks` (title, rationale, reference) that `testls explain [id]` prints; text output shows the id in brackets after each finding. A unit test compares the catalogue with the id literals in the check sources so the two cannot drift | Users can look up why a finding matters without leaving the terminal, and the suppressions and baselines planned for v0.4 can key on the ids shown. The wording is original and cites RFCs or standards |
| 36 | A Vulnerabilities section lists twelve named issues (POODLE, BEAST, SWEET32, RC4, FREAK, Logjam, DROWN, CRIME, insecure renegotiation, missing `TLS_FALLBACK_SCSV`, no forward secrecy, Raccoon) as vulnerable, not vulnerable or not tested, judged from data the scan already collects plus three plain handshakes (DEFLATE offered, renegotiation_info checked, fallback SCSV at a lower version) and a second DHE handshake for key reuse. New `vuln.*` findings are emitted only where no other check already reports the issue; the rest point to the existing id. Well-known DH primes (RFC 2409, 3526, 5114, 7919) are recognised by value | Users get the familiar vulnerability names without the scanner sending attack traffic, and the findings list does not report the same weakness twice. Logjam relies on shared primes, so naming them shows when a server uses a precomputation target |
| 37 | A ClientHello tolerance section sends five well-formed but unusual hellos at the best offered version (future version 0x0305, unassigned extension, GREASE values, a hello filling a 16 KiB record, 16-byte record fragments) after a plain baseline handshake. A rejection is a finding: unknown version or extension is medium, GREASE and record-size quirks are low; a failed baseline leaves every test untested | Intolerant servers break new clients and push browsers toward insecure fallback; the baseline separates intolerance from servers that simply refuse the plain hello |
| 38 | A Handshake details section checks extended master secret (RFC 7627) and, when TLSv1.3 is offered, the downgrade sentinel (RFC 8446 §4.1.3) with one raw hello at the best TLSv1.2-or-older version, and session tickets plus their 0-RTT limit with one rustls TLSv1.3 handshake that records tickets but never resumes. Missing EMS is low, a missing sentinel medium, 0-RTT info | Raw hellos read the ServerHello directly; tickets arrive only after the handshake, so a real TLSv1.3 client is needed. Not resuming or sending early data keeps the probe passive |
| 39 | A Post-quantum readiness section summarises the TLSv1.3 groups already measured: ready (any registered ML-KEM group, pure or hybrid), draft only (only the obsolete draft Kyber code points), not ready or not tested, with the server's preference for ML-KEM. Groups are classified by their IANA name; draft Kyber code points are rated low and surface as `group.weak` | No extra traffic is needed, and naming the draft code points separately shows servers that deployed pre-standard Kyber and never moved to FIPS 203 ML-KEM |
| 40 | Certificate lifetime is checked against CA/B Forum BR §6.3.2 (398 days before 15 March 2026, then 200, 100 and 47 days by issue date) and embedded SCTs are counted (`cert.too_long`, `cert.no_sct`, `cert.sct_invalid`). These findings apply only when the chain verifies against the bundled Mozilla roots; the system store and `--ca-file` may hold private roots the BR do not bind. SCT signatures are not verified | The BR bind only publicly trusted CAs, so private PKI must not be flagged; verifying SCTs needs a CT log list, a moving data dependency |
| 41 | HTTP extras reuse the single `GET /` reply: `Server` values with a version and any `X-Powered-By` are info (`header.banner`); cookies lacking `Secure` or using `SameSite=None` without it are low, missing `HttpOnly` or `SameSite` info; a malformed `Alt-Svc` is info. Header text is shown with control characters replaced | No extra requests; banners and cookie flags are hardening hints, while a cookie sent over plain HTTP is a real exposure |
| 42 | Several targets (positional and `--file`, one per line with `#` comments) are scanned one after another with one trust store. Text output prints the sections per target; JSON prints the usual document for one target and an array of documents for more, leaving out targets whose scan failed. The exit code is the worst per target (2 over 1 over 0). A bad `--file` line stops the run before any connection | A single target keeps the schema-1 document unchanged for existing scripts; sequential scans keep the per-server politeness of a single scan; failing early on a typo avoids a half-finished batch |
| 43 | A CIDR target (`192.0.2.0/28`, `192.0.2.0/28:8443`, `[2001:db8::/120]:8443`) expands to every address in the range, including network and broadcast addresses, scanned without SNI. A range may have at most 16 host bits (65,536 addresses) | Plain expansion keeps results predictable; the cap stops a typo such as `/8` from starting a scan of millions of hosts |
| 44 | `--all-addresses` scans each distinct A/AAAA address of a host name as its own report (same SNI, one JSON document each). Addresses whose offered protocols, accepted cipher suites or leaf certificate differ from the first address produce a warning on stderr, not a finding. `--mx` moves to v0.5 | Load balancers and dual-stack hosts often drift apart; a stderr warning flags it without changing the JSON schema or the exit code; MX targets are only useful once SMTP STARTTLS exists |
| 45 | `--resolve HOST:PORT:ADDR[,ADDR...]` uses curl's syntax and is repeatable; the first entry matching a target's host name and port replaces its DNS lookup (the first address is scanned, or all with `--all-addresses`). Only target lookups are overridden, not OCSP/CRL hosts | Familiar syntax for testing a server before a DNS change or behind a load balancer; keeping the name as target and SNI makes the report match the real deployment |
| 46 | CodeRabbit is configured in `.coderabbit.yaml` (chill profile, replaced by the assertive trial in #55; per-crate path instructions, title/changelog/JSON-schema/docstring pre-merge checks as warnings) and auto-approves PRs it rates low merge risk once all threads are resolved and the pre-merge checks pass. Agents push all fixes for a review round in one commit | The config makes the repo rules explicit to the reviewer; approval gives a clear merge signal; one commit per round stays within the 10 reviews per hour budget |
| 47 | `--source-ip ADDR` binds every connection, target probes and OCSP/CRL fetches alike, to ADDR. Target addresses of the other family are dropped (scan error if none remain); revocation lookups skip them | Multi-homed scanners need one egress address for firewall rules and logs; failing early beats confusing connect errors |
| 48 | `--proxy [http://]HOST:PORT` tunnels every connection through an HTTP proxy with `CONNECT` (RFC 9110 §9.3.6); no authentication or SOCKS yet. Target names are resolved locally and tunnelled by IP, so the reported address and `--resolve` work as without a proxy; OCSP/CRL lookups go through the proxy by host name. `--source-ip` then binds the connection to the proxy and no longer filters target addresses | Networks that need a proxy usually block direct egress, so third-party lookups must use it too; tunnelling by IP keeps one code path for address selection and the report |
| 49 | `--format sarif` prints one SARIF 2.1.0 log for the whole run: one rule per finding id (text from `testls explain`), one result per finding with `level` error (critical/high), warning (medium/low) or note, a `security-severity` property for GitHub code scanning, the location `https://TARGET/` and a stable `primaryLocationLineHash` fingerprint of id, target and message. `executionSuccessful` is false when any scan failed | Code-scanning tools need SARIF to track TLS findings across runs; findings have no source file, so the target URI stands in as the location and the fingerprint keeps alerts stable |
| 50 | `--format junit` prints one JUnit XML document for the whole run: a `<testsuite>` per scanned address (`TARGET (ADDR)`), a `<testcase>` per finding named by its id, a `<failure>` when its severity is at or above `--fail-on` (others pass with the message in `<system-out>`), and a suite with one `<error>` case per target whose scan failed. Written by hand with XML escaping, no XML crate | CI systems render JUnit natively; tying failures to `--fail-on` makes the report agree with the exit code, and the format is small enough not to need a dependency |
| 51 | `--format markdown` prints one GitHub Flavored Markdown document for the whole run: a summary line, a table of finding counts per severity for each scanned address, one section per address with its findings most severe first (❌ marks those at or above `--fail-on`), and a table of targets whose scan failed. Text is backslash-escaped so messages cannot break tables or inject HTML | Fits `$GITHUB_STEP_SUMMARY` and PR comments without post-processing; it reuses the SARIF/JUnit inputs, so all summary formats agree |
| 52 | `--format csv` prints one RFC 4180 document for the whole run: a header row, then one row per finding (`target,address,severity,id,message,failing`), most severe first per address, and a `scan.error` row per target whose scan failed. Fields that start with `=`, `+`, `-`, `@`, tab or CR get a leading `'` | Flat rows load straight into spreadsheets and `awk`/`csvkit`; the prefix stops scanned server text (cookie names, banners) from running as spreadsheet formulas (CSV injection) |
| 53 | `--format html` prints one self-contained HTML page with the Markdown report's layout: summary line, counts table, one findings table per address (failing rows highlighted) and scan errors. Styles are inline, nothing is loaded, and a `Content-Security-Policy` meta tag (`default-src 'none'; style-src 'unsafe-inline'`) forbids scripts; all scanned text is HTML-escaped | One file to attach to tickets or archive as a CI artefact, viewable offline; the CSP is defence in depth against server-controlled text running as script in the reader's browser |
| 54 | Suppressions live in `.testls.toml` in the working directory (optional) or the file given by `--config` (must exist). Each `[[suppress]]` entry needs a finding `id` and a non-empty `reason`, and may limit itself to one `target` (CLI target syntax, CIDR ranges included) and set `expires`, a TOML date that is the last UTC day the entry applies. A suppressed finding moves to a separate list (text section, JSON `suppressed` with the reason) and no longer counts towards `--fail-on` or the summary formats; expired entries and unknown ids warn on stderr. Parsed with the `toml` crate, unknown keys rejected | A mandatory reason keeps accepted risks visible, and an optional expiry date keeps them temporary when set; dates without times avoid time-zone surprises; rejecting unknown keys catches typos that would silently stop a suppression |
| 55 | CodeRabbit runs the `assertive` profile as a trial from PR #85 until changed, evaluated on the next five PRs (#86–#90), with risk-focused path instructions (architecture, untrusted input in probe and report, check accuracy, CLI flag combinations). Afterwards we compare comments per PR, useful vs noise, review rounds and auto-approval rate with the chill PRs #77–#84 (about one useful comment per PR, 1–2 rounds) and keep or revert the profile | One maintainer reviews AI-written code, so the bot is the second reviewer; the trial checks whether extra detail finds real problems or only costs review rounds |
| 56 | `--baseline FILE` reads an earlier `--format json` report (one document or an array, `schema_version` must match). A finding is known when the baseline has a document with the same `target.input` and a finding with the same `id`; the message, address and severity are ignored. Known findings move to `suppressed` with reason `"in baseline"` after `.testls.toml` suppressions are applied; the baseline's own `suppressed` entries are not known. A missing or invalid baseline is a scan error (exit 2) | Reusing the JSON report needs no new file format and lets CI store the last run as an artefact. Messages carry versions and dates that change between runs, so ids are the stable key; keying on the input rather than the address keeps DNS changes from resurfacing old findings. Ignoring baseline suppressions keeps an expired `.testls.toml` entry from being silently renewed by the baseline |
| 57 | `--profile quick\|default\|full` sets scan depth. `quick` runs protocol detection, cipher enumeration and the certificate fetch only; the vulnerability verdicts that need key exchange or handshake-feature data become `not tested`, and skipped sections report the error `skipped by --profile quick` in JSON (no schema change). `default` is the old behaviour. `full` adds `--revocation` and `--all-addresses`; the separate flags still work with any profile | Most CI runs only need to catch protocol, cipher and certificate regressions, which take a fraction of the connections; reusing the existing error fields keeps the JSON schema stable, and making `full` a superset of existing flags avoids a second way to configure the same probes |
| 58 | `--policy NAME` (repeatable) checks the scan against a configuration profile and adds one `policy.*` finding (severity `medium`) per deviation: protocol, cipher suite, key exchange group, leaf key, signature, validity period and HSTS `max-age`. The first policies are Mozilla `modern` and `intermediate` from the Server Side TLS guidelines 6.0 (data transcribed from guidelines JSON, code points from IANA). Parts the scan did not measure (quick profile, failed probes) produce one `policy.incomplete` info finding instead of passing. Other policies (PCI DSS, NIST, BSI, CNSA 2.0) follow in separate PRs | Findings reuse `--fail-on`, suppressions, baselines and every output format with no schema change; one severity for all deviations keeps policy results apart from the security rating of the same weakness; reporting unmeasured parts avoids false compliance |
| 59 | `--policy nist-800-52r2` follows NIST SP 800-52r2 for servers with government clients: TLSv1.2 and TLSv1.3, both required so a server without TLSv1.3 deviates (§3.1, TLSv1.3 since 1 January 2024; TLSv1.0/1.1 for other clients are not modelled), the TLSv1.2 suites of §3.3.1.1 without the transition-only RSA key transport and PSK appendices, the TLSv1.3 suites of §3.3.1.2 (no ChaCha20), the SP 800-56A groups (NIST curves, ffdhe), RSA of at least 2048 bits or ECDSA on P-256/P-384, and SHA-2 RSA, RSASSA-PSS (with a SHA-2 hash) or ECDSA signatures. No HSTS or validity-period rule, so those parts are neither checked nor reported as incomplete; `Rules` makes both optional | Federal and regulated customers audit against this document; modelling the government profile keeps one strict reading instead of a flag per client population, and optional rules stop a policy from inventing requirements it does not have |
| 60 | `--policy cnsa-2.0` follows the NSA CNSA 2.0 TLS 1.3 profile (draft-becker-cnsa2-tls-profile-05, the only published TLS mapping of CNSA 2.0): TLSv1.3 only and required (§6), `TLS_AES_256_GCM_SHA384` (§4), only the `MLKEM1024` group (§7.2; hybrids such as `SecP384r1MLKEM1024` are not allowed) and ML-DSA-87 leaf keys and signatures (§8). `Rules` gains an allow-list of non-RSA/EC key algorithms by OID. The CertificateVerify scheme and client-side rules are not checked. The certificate fetch advertises ML-DSA schemes, but ring has no ML-KEM, so a server that accepts only `MLKEM1024` gives `policy.incomplete` for the certificate rather than a result (fixing that needs a post-quantum crypto provider such as aws-lc-rs, a C dependency) | National-security customers must move to CNSA 2.0 by 2030–2033; a pure post-quantum profile shows how far a server is from it. The profile is still a draft, so the rules cite its section numbers and get revisited when it becomes an RFC |
| 61 | CodeRabbit keeps the `assertive` profile after the trial of #55. PRs #86–#90 got 9 comments (about 8 useful, none noise; 4 Major), 2.2 review rounds on average and 3 of 5 auto-approvals; both withheld approvals cited concerns already resolved or accepted in a thread | Twice the useful comments of the chill baseline for under one extra round per PR; the withheld approvals cost one explanatory comment each, which the workflow's second merge rule already covers |
| 62 | `--policy bsi-tr-02102-2` follows BSI TR-02102-2 version 2025-01: TLSv1.2 and TLSv1.3 (§3.2, neither required), the forward-secret TLSv1.2 suites of table 3 (ECDHE and DHE with AES-CBC/GCM/CCM; the non-forward-secret table 4 suites, allowed only when forward secrecy is impossible, and the PSK suites are excluded), the TLSv1.3 suites of table 13 (no ChaCha20), the groups of tables 6 and 10 (NIST and brainpool curves, ffdhe3072/4096), RSA keys of at least 3000 bits (table 14), ECDSA on brainpool or NIST curves (§3.6.2) and RSASSA-PSS or ECDSA signatures (table 12; PKCS #1 v1.5 was recommended only up to 2025). The TLSv1.2 DHE prime the server picks counts as a group for every policy: RFC 7919 primes map to their code points, other primes are deviations (NIST also accepts the RFC 3526 MODP groups of 2048 bits or more). Brainpool code points are checked per TLS version (26-28 for TLSv1.2, 31-33 for TLSv1.3). Encrypt-then-MAC for CBC suites, DHE groups the server accepts but does not pick, and the end-of-use years are not checked | German public-sector and KRITIS operators are audited against TR-02102-2; using the strict forward-secret reading of the current version keeps one profile, and the unchecked conditions need probes testls does not have yet |
| 63 | `--policy pci-dss-4` reads PCI DSS v4.0.1 requirement 4.2.1 (no SSL or early TLS, so TLSv1.2 and TLSv1.3, neither required) and the glossary's "Strong Cryptography" (at least 112 bits of effective key strength, per NIST SP 800-57 part 1). PCI DSS lists no suites, so every IANA-named TLSv1.2 suite rated below medium passes (CBC and non-forward-secret included), while null, anonymous, export, RC4, DES, RC2, MD5, 3DES and other 64-bit block ciphers (IDEA, GOST 28147/Magma) and unknown suites deviate; all five TLSv1.3 suites pass. Groups need 112-bit security (NIST curves from P-224 up, x25519/x448, brainpool, ffdhe, ML-KEM and hybrids); TLSv1.2 DHE primes of at least 2048 bits pass whether known or custom (`Rules` gains `dh_min_bits` and `strong_suites`). Leaf keys: RSA of at least 2048 bits, ECDSA on NIST (P-224 and up) or brainpool curves, Ed25519/Ed448; signatures SHA-2 RSA/PSS, ECDSA, EdDSA | Assessors need a check that matches the standard rather than a stricter vendor profile; anything stricter (forward secrecy, AEAD only) is better expressed with the Mozilla or NIST policies |
| 64 | Shell completions and the man page are generated at run time by `testls completions SHELL` (bash, zsh, fish, PowerShell, elvish via `clap_complete`) and `testls man [--dir DIR]` (roff via `clap_mangen`; `--dir` adds one page per subcommand), not by a build script or committed files | They always match the binary's flags, packagers (Homebrew, Scoop) can call them during install, and the two small clap crates are permissively licensed with no further dependencies beyond `roff` |
| 65 | crates.io: all workspace crates are published (internal crates keep exact `=X.Y.Z` versions); `testls` carries `[package.metadata.binstall]` pointing at the release archives (`testls-vX.Y.Z-TARGET.tar.gz`, zip on Windows). The release workflow's `crates-io` job publishes with crates.io trusted publishing (OIDC via `rust-lang/crates-io-auth-action`, GitHub environment `crates-io`), gated by the repository variable `CRATES_IO_TRUSTED_PUBLISHING` because trusted publishing can only be configured for crates that exist; the first publish is manual | `cargo binstall` and `cargo install` are the usual way Rust users get CLI tools; OIDC avoids a long-lived API token in repository secrets, and the variable keeps releases green until the maintainer has claimed the names |
| 66 | Homebrew and Scoop packages live in this repository (`Formula/testls.rb` makes it a tap, `bucket/testls.json` a bucket) instead of separate `homebrew-testls`/`scoop-testls` repositories | One PR updates code and packages; the cost is the longer `brew tap kjpopov/testls URL` form. Both install the release archives (no source builds), the formula generates completions and man pages for releases after v0.3.0. winget manifests (schema 1.10.0, portable zip) are kept in `packaging/winget/X.Y.Z/` for the maintainer to submit to `microsoft/winget-pkgs`; agents do not open PRs there. `scripts/gen-packages.py SHA256SUMS` renders all three from a published release's checksums, so the release PR cannot carry them: a follow-up `chore/packages-X.Y.Z` PR does, after the GitHub release exists. |
| 67 | The container image is built in the release workflow from the released musl binaries (no rebuild, no emulation) on `gcr.io/distroless/static-debian13:nonroot` pinned by digest, for linux/amd64 and linux/arm64, tagged `X.Y.Z`, `X.Y` and `latest` (pre-releases only `X.Y.Z`) on ghcr.io with the job's `GITHUB_TOKEN`; CI builds and runs the same Dockerfile with the static binaries. The GitHub Action is a composite `action.yml` at the repository root that downloads a release archive, checks it against `SHA256SUMS`, adds it to `PATH` and optionally runs `args` (split on whitespace, globbing off); CI runs it on Linux, macOS and Windows | Distroless ships CA certificates for `--system-roots` without a shell or package manager, and reusing the release binaries means the image runs exactly what was released. A composite action needs no Node.js runtime or bundled JavaScript, and installing prebuilt binaries keeps it fast; users pin it to a commit SHA like every other action here |
| 68 | STARTTLS is a `Transport` setting (`starttls: Option<Starttls>`): `Transport::connect` runs the plain-text dialogue after the TCP or proxy connect and before every hello, within `read_timeout`. A refused, malformed or timed-out dialogue, or bytes after the server's final reply, is a `ProbeError::Connect` | Every probe (protocols, ciphers, certificates, HTTP headers, details) goes through `Transport::connect`, so one hook covers them all. `Connect` tells callers no hello was sent, so a server that will not upgrade is a scan error instead of looking like it refused a TLS version; rejecting trailing bytes stops a server or middlebox from injecting data into the TLS stream (the STARTTLS command-injection class) |
| 69 | `--starttls PROTOCOL` sets the transport's STARTTLS protocol for every target; targets without a port or scheme (CIDR ranges included) use the protocol's standard port (25 for SMTP). The HTTP headers section is skipped (reported as not checked, so policies with an HSTS rule add `policy.incomplete`). Through `--proxy`, bytes after the `CONNECT` reply feed the STARTTLS dialogue (the server greets first); immediate-TLS tunnels still reject them. The Postfix test server allows TLS 1.2+ with optional STARTTLS | Ports differ per protocol, so defaulting to 443 would almost always be wrong; mail and other STARTTLS services do not speak HTTP after the handshake, so asking for headers would only produce an `http.error` finding |
| 70 | IMAP and POP3 STARTTLS ask for capabilities first (`CAPABILITY`, `CAPA`) and stop with a connect error unless `STARTTLS`/`STLS` is listed, like SMTP's `EHLO` check. The Dovecot test server offers both on TLS 1.2+ and has a password database that rejects every login | Sending the upgrade command blindly would turn "not offered" into a confusing protocol error; Dovecot refuses to start without a password database |
| 71 | FTP uses `AUTH TLS` (RFC 4217 §4) right after the 220 greeting and needs a 234 reply; it skips `FEAT` because a server without TLS refuses `AUTH` anyway. Multi-line FTP replies end at the first line starting with the opening code and a space (RFC 959 §4.2), so indented lines inside may hold anything. The vsftpd test server has local logins on (it will not start otherwise) but no accounts with passwords | One round trip fewer than SMTP/IMAP/POP3; `AUTH` refusal is as clear a signal as a missing capability, and vsftpd requires a login type |
| 72 | XMPP (RFC 6120) opens a client stream addressed to the SNI name (target host or `--sni`, the IP address otherwise) and needs `starttls` in the stream features and a `proceed` answer; a `stream:error` reports its condition. `Transport` gains `host: Option<String>` and is no longer `Copy`. Replies are scanned for the expected element without an XML parser, capped at 64 KiB and required to be UTF-8. The Prosody test server requires STARTTLS, TLS 1.2+, no accounts | XMPP servers route by the `to` domain and refuse unknown hosts, so the IP address alone fails on most servers. A string field is the only way to carry the domain; no caller relied on `Copy`. A few fixed elements do not justify an XML parser dependency |
| 73 | LDAP sends the `StartTLS` extended request (RFC 4511 §4.14) as message 1 right after connecting and needs an `ExtendedResponse` with result 0 for that message; a notice of disconnection (message 0) or another result reports the code and diagnostic. A minimal BER reader handles single-byte tags and definite lengths only, as RFC 4511 §5.1 requires, capped at 64 KiB. The OpenLDAP test server has no database, TLS 1.2+ | LDAP servers send no greeting and do not advertise StartTLS before it is tried (the root DSE query would add a round trip for the same answer). The request is a fixed 31-byte message, and the response needs four fields, which does not justify an ASN.1 dependency |
| 74 | PostgreSQL sends `SSLRequest` (code 80877103) right after connecting and needs the single byte `S`; `N` reports that the server has no TLS and an `ErrorResponse` that it predates `SSLRequest`. Direct TLS (PostgreSQL 17 `sslnegotiation=direct`) is not used. The test server is a throwaway cluster with `--auth=reject`, TLS 1.2+ | `SSLRequest` works on every supported PostgreSQL version, while direct TLS needs 17+ and ALPN `postgresql`; one fixed message and a one-byte answer need no parser |
| 75 | MySQL reads the server's initial handshake, which must be protocol version 10 with `CLIENT_SSL`, then sends the 36-byte `SSLRequest` (sequence id 1, capabilities `CLIENT_LONG_PASSWORD`, `CLIENT_PROTOCOL_41`, `CLIENT_SSL`, `CLIENT_SECURE_CONNECTION`, charset 45); the server's next bytes are its TLS handshake. An ERR packet greeting (for example 1130, host not allowed) is reported with its code and text. The test server is MariaDB with a locked `'%'` account, TLS 1.2+ | The same `SSLRequest` works on MySQL 5.x–9.x and MariaDB; MariaDB greets hosts without a matching account with error 1130 instead of a handshake, so the test server has a locked `'%'` account, which nobody can log in to |
| 76 | Verify TLS handshake signatures while deferring chain trust; restrict certificate-directed HTTP fetches to public port-80 destinations with exact endpoint overrides and IP-pinned proxy tunnels; reject named CRL scopes; fail incomplete required scans with exit 2; preserve baseline severity escalations; escape terminal diagnostics | Security audit regressions must not produce authenticated, clean, or safe-to-display results without evidence |
