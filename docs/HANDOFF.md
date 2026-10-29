# Session handoff

State left by the last agent session for the next one. Read this right
after [AGENTS.md](../AGENTS.md) (then [agent-workflow.md](agent-workflow.md)
if `gh` is allowed); update it when a session ends.

## State (2026-10-28)

- Latest release **v0.4.3** (GitHub release, container image
  `ghcr.io/kjpopov/testls:0.4.3`, Homebrew/Scoop in-repo, Marketplace action).
  v0.4.2 was deleted (web UI mistake); skip it in compare links.
- `main` has unreleased v0.5 work: `--starttls
  smtp|imap|pop3|ftp|xmpp|ldap|postgres|mysql` (PRs #108–#115, decisions
  #68–#75). Next decision log number: **#76**.
- STARTTLS lives in `testls-probe/src/starttls.rs`; `Transport::connect`
  runs it after TCP/proxy connect, failures are `ProbeError::Connect`.
  `Transport` is no longer `Copy` (has `host` for XMPP).
- CodeRabbit runs the `assertive` profile with auto-approval up to `low`
  merge risk (PLAN #46, #55, #61).

## Waiting on the maintainer

- crates.io: GitHub environment `crates-io` and the variable
  `CRATES_IO_TRUSTED_PUBLISHING` are set up. The first manual
  `cargo publish --workspace --locked` of v0.4.3 and trusted publishing on
  each `testls*` crate may still be pending; check with
  `curl -s https://crates.io/api/v1/crates/testls`. From the next tag the
  `crates-io` job publishes; if it fails halfway, rerun failed jobs.
- winget: deliberately postponed until there are more features (better odds
  with the moderators). Keep generating `packaging/winget/X.Y.Z/` in the
  packages PR, but do not remind the maintainer each release.

## Next work

v0.5 in PLAN.md, suggested order:

1. `--mx` (needs SMTP STARTTLS and an MX lookup without new heavy deps; check
   `cargo deny` before adding a resolver crate).
2. Intrusive checks behind `--intrusive` (Heartbleed, CCS injection,
   Ticketbleed, ROBOT), one PR each.
3. Application-layer checks (BREACH, ALPACA, Opossum), then grading.

Open questions in PLAN.md (default profile runtime, politeness/rate limits)
still need a decision before grading.

## Habits that worked

- One topic per PR, all review fixes in one commit per round, reply to each
  thread; reviews take 10–15 minutes, poll with `sleep 290` and a 320 s tool
  timeout.
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
  reviews; check both before assuming nothing changed.

## Security audit fixes (2026-10-29)

Branch: `fix/security-audit`, based on `c1a876e`. Six fixes: verify TLS 1.2/1.3
handshake signatures; restrict certificate-directed HTTP requests to public
port-80 endpoints with repeatable exact `--revocation-endpoint` allowances;
reject named CRL scopes; exit 2 on incomplete required measurements/policies;
preserve baseline severity escalations/errors; escape terminal diagnostics.
Provider-unsupported ML-DSA-only handshakes now fail instead of accepting an
unverified signature. Generated fixtures include a signed partitioned CRL.
`wrong.key.der` is a deliberately unrelated, public test-only signing key.

Validation: workspace tests 359 passed, 11 container tests ignored; stable
Clippy with `-D warnings`; formatting; Rust 1.97.1 workspace check; cargo-deny
(advisories, bans, licenses, sources) pass. Original CLI reproductions confirm
exit 2 for partial scans, blocked loopback revocation, and escaped SMTP ANSI.
Docker/Podman are unavailable here, so container integration remains for CI.
Next decision-log number: 77. Contribution branch: `r4d1um/testls:fix/security-audit`;
PR targets `kjpopov/testls:main`. Container integration and maintainer review
remain required before merge.
