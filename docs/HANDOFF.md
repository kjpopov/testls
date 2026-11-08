# Session handoff

State left by the last agent session for the next one. Read this right
after [AGENTS.md](../AGENTS.md) (then [agent-workflow.md](agent-workflow.md)
if `gh` is allowed); update it when a session ends.

## State (2026-11-08)

- Latest release **v0.6.0** (web service: `testls serve`, REST/SSE,
  browser UI). Previous v0.5.0 (release PR `chore/release-0.5.0`; tag,
  GitHub release, container image `ghcr.io/kjpopov/testls:0.5.0`,
  Homebrew/Scoop in-repo via the packages PR). v0.4.2 was deleted (web UI
  mistake); skip it in compare links.
- v0.5.0 contains `--starttls smtp|imap|pop3|ftp|xmpp|ldap|postgres|mysql`
  (decisions #68–#75), `--mx` (#76–#77, `testls-probe/src/mx.rs`,
  `mail_hosts` in `main.rs`), PR #117 security hardening (#78–#81),
  Codecov upload and Test Analytics (#82, #86), BREACH/ALPACA/Opossum
  (#83–#85) and grading (#87–#89). Intrusive checks moved to the backlog
  (decision #90). Next decision log number: **#91**.
- Grading code map: `testls-checks/src/grade.rs` (`grade()`, `Grade`,
  `Letter`), rendered by `text::grade` / `grade_label` and every summary
  format via `sarif::Scan::grade`; `main.rs` grades before `triage`.
  Model documented in `docs/grading.md`. Adding a field to
  `sarif::Scan` means touching the `scan()` test helper in every summary
  format (sarif, markdown, html, csv, junit).
- Application-layer code map: BREACH reads `Content-Encoding` from the
  existing GET (`testls-probe/src/http.rs` sends `Accept-Encoding`); ALPACA
  is `HandshakeFeatures::strict_alpn` in `testls-probe/src/features.rs`
  (raw hello up to TLS 1.2, rustls handshake at TLS 1.3); Opossum is
  `testls-probe/src/upgrade.rs` (`OPTIONS *` + `Upgrade: TLS/1.0` to the
  scanned port and port 80, joined with the feature probe in
  `vulnerability_section`). Verdicts in `testls-checks/src/vulnerabilities.rs`
  (15 entries).
- PR #117 (external audit by r4d1um) is closed by the maintainer; all
  findings shipped in v0.5.0. Local branch `pr-117` can be deleted.
- Hardening code map: escaping via `printable()` in
  `testls-report/src/text.rs` and `csv::field`; baseline severity in
  `testls/src/baseline.rs` (`scan_failure`); handshake signature in
  `testls-probe/src/certificates.rs` (`AcceptAll::check`, `unverifiable`,
  `UNVERIFIABLE_SCHEMES`, finding `cert.signature_unverified`); CRL scope in
  `testls-checks/src/revocation.rs` (`check_scope`, `distribution_points`);
  revocation guard in `testls-probe/src/fetch.rs` (`Fetcher::allow_private`,
  `local_host`, `ends_in_number`, `public_address`), CLI flag
  `--revocation-allow-private`.
- `--mx` has unit tests only (fake UDP DNS server in `mx.rs`, CLI parsing
  in `main.rs`); no integration test (would need a DNS server in
  `tests/servers`). Outbound port 25 is blocked on the dev machine, so live
  `--mx` scans hang until the connect timeout.
- STARTTLS lives in `testls-probe/src/starttls.rs`; `Transport::connect`
  runs it after TCP/proxy connect, failures are `ProbeError::Connect`.
  `Transport` is no longer `Copy` (has `host` for XMPP).
- CodeRabbit runs the `assertive` profile with auto-approval up to `low`
  merge risk (PLAN #46, #55, #61).

## Waiting on the maintainer

- crates.io: trusted publishing works. v0.5.0 was published by rerunning
  only the skipped `crates-io` job (`gh run rerun RUN --job JOB`, at the
  maintainer's request) after the variable was moved from the `crates-io`
  environment to repository level (job `if:` cannot see environment vars).
- winget: deliberately postponed until there are more features (better odds
  with the moderators). Keep generating `packaging/winget/X.Y.Z/` in the
  packages PR, but do not remind the maintainer each release.

## Next work

1. v0.6.0 released: GitHub release, container, all 8 crates on crates.io,
   packages PR #151 merged. New crates need a manual first publish plus a
   trusted-publishing entry by the maintainer before `release.yml` can
   publish them (done for `testls-scan`, `testls-server`). Maintainer:
   Marketplace tick.
2. v0.6 web service done: `testls-scan` (#93), `testls-server` + `testls
   serve` (#94, #95), embedded UI (`crates/testls-server/ui/`, #96).
   Maintainer supplied the dashboard CSS (own project, reuse OK). Next:
   v0.7 monitoring sketch in PLAN (ask maintainer to settle scope).
   Next decision number: **#97**.
3. Backlog: intrusive checks (`--intrusive`: Heartbleed, CCS injection,
   Ticketbleed, ROBOT; a remote branch `feat/intrusive-checks` exists, not
   ours, check with the maintainer), `--delay`, `--parallel`.

## Habits that worked

- CodeRabbit no longer auto-reviews (repo under 10 stars; trigger with
  `@coderabbitai review`) and is slow. Maintainer prefers a local review
  by a `review` subagent with a GPT model (used `litellm/gpt-6.1-sol#high`);
  when the maintainer allows `gh` for the session, tell it to read the PR
  with the `gh` CLI (not webfetch) and post its findings as a PR review;
  fix them, then merge when CI is green.

- One topic per PR, all review fixes in one commit per round, reply to each
  thread; reviews take 10–15 minutes, poll with `sleep 290` and a 320 s tool
  timeout.
- Ask the maintainer design questions (question tool) before coding a
  roadmap item with open choices; record the answers as decisions.
- Decision numbers collide when parallel PRs land: before each PR, rebase on
  fresh `main` and recheck the last decision number (grading's #86 became
  #87 after #133 merged).
- Split a feature PR into model (checks crate, unit tests) and report/CLI
  (formats, integration tests, docs); open the second only after the first
  merges, then rebase it on `main`.
- Keep `scan()` in `main.rs` under clippy's 100-line limit by moving
  output assembly into helpers (`outcome()`).
- Decline wrong suggestions with a PR comment and point the maintainer to it
  in the final message.
- Stay inside the repository directory (use `target/` or
  `CARGO_TARGET_TMPDIR` for scratch files); the maintainer declines access
  elsewhere.
- Test servers: one Debian trixie image per service (pinned digest) in
  `tests/servers`; ports 14425 smtp, 14143/14110 imap/pop3, 14021 ftp,
  15222 xmpp, 14389 ldap, 15432 postgres, 13306 mysql. Gotchas: Docker
  `COPY --chmod` gives a missing target dir that mode too (create it first);
  the Docker port proxy accepts before the service listens (`wait_for` peeks);
  vsftpd needs `init: true` under Docker. CI container logs:
  `gh run view RUN --log --job JOB | grep "<svc>-1"`.
- CodeRabbit sometimes answers in issue comments or posts empty COMMENTED
  reviews; check both before assuming nothing changed. If it never reviews
  a PR (seen on docs-only #116), comment `@coderabbitai review`.
- External PRs: review with zero trust (check CI/workflow/dependency/binary
  changes first), post a per-finding review, then redo accepted parts as
  small PRs with `Co-authored-by` and a CHANGELOG credit
  ("Reported by @user in #N.").
- CRL/OCSP test fixtures come from `scripts/gen-ocsp-fixtures.sh`
  (gitignored output; rerun after editing it).
- hickory 0.26 sources are in `~/.cargo/registry/src/*/hickory-*-0.26.3`;
  grep them for API details (docs.rs lags).
