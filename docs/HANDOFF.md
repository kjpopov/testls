# Session handoff

State left by the last agent session for the next one. Read this right
after [AGENTS.md](../AGENTS.md) (then [agent-workflow.md](agent-workflow.md)
if `gh` is allowed); update it when a session ends.

## State (2026-11-10)

- Latest release **v0.6.0** (web service: `testls serve`, REST/SSE,
  browser UI). Previous v0.5.0 (release PR `chore/release-0.5.0`; tag,
  GitHub release, container image `ghcr.io/kjpopov/testls:0.5.0`,
  Homebrew/Scoop in-repo via the packages PR). v0.4.2 was deleted (web UI
  mistake); skip it in compare links.
- Merged 2026-11-10: PR #154 opt-in Heartbleed (`--intrusive`, decision
  #97, test server port 14435) and PR #155 (dependabot actions).
  Housekeeping: deleted local `pr-117`, `feat/web-ui`, `fix/server-review`
  and the six stale remote branches (`feat/cidr-targets`,
  `feat/report-http-headers`, `feat/intrusive-checks`, `feat/web-ui`,
  `fix/server-review`, CodeRabbit's `review-latest-pull-request`
  by-product of closed PR #153); only `origin/main` remained immediately
  after cleanup. PR #156 was subsequently merged by the maintainer;
  PR #157's CodeRabbit branch is now active.
- v0.5.0 contains `--starttls smtp|imap|pop3|ftp|xmpp|ldap|postgres|mysql`
  (decisions #68–#75), `--mx` (#76–#77, `testls-probe/src/mx.rs`,
  `mail_hosts` in `main.rs`), PR #117 security hardening (#78–#81),
  Codecov upload and Test Analytics (#82, #86), BREACH/ALPACA/Opossum
  (#83–#85) and grading (#87–#89). Intrusive checks moved to the backlog
  (decision #90), later scheduled for v0.6.1 (#98).
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
  findings shipped in v0.5.0.
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

## Local OpenCode configuration (2026-11-10)

- Added `lan-build` primary agent and `/lan` command to
  `~/.config/opencode/opencode.jsonc` at the maintainer's request. Command
  selects `lan/coder`; agent requests one-time OpenCode skill loading and
  concise inspect/act/verify cycles. Defaults, providers and permissions
  unchanged. JSONC parsing and configuration assertions pass; no live model
  run performed. Existing conflict markers in repository docs left untouched.
- Installed local TUI plugin `~/.config/opencode/llama-progress` via `cli.json`;
  disables only `opencode.sidebar.context`, reproduces cloud context/cost and
  shows read-only `/slots` telemetry for `local/coder` / `lan/coder`. Live
  input counts + indeterminate bar (API lacks prompt target), generation counts;
  server-wide, not session-correlated. Endpoints explicitly allow-listed,
  no credentials/redirects, 1s serialized polling, 2.5s timeout, 1MiB bound.
  Ten Node tests pass; live LAN fetch and CLI plugin reconciliation pass.
  Separate PTY visual smoke denied by permission; layout not visually checked.
  To uninstall remove both `-opencode.sidebar.context` and `./llama-progress`
  from `cli.json`. No model/server settings changed.

## Waiting on the maintainer

- crates.io: trusted publishing works. v0.5.0 was published by rerunning
  only the skipped `crates-io` job (`gh run rerun RUN --job JOB`, at the
  maintainer's request) after the variable was moved from the `crates-io`
  environment to repository level (job `if:` cannot see environment vars).
- winget: deliberately postponed until there are more features (better odds
  with the moderators). Keep generating `packaging/winget/X.Y.Z/` in the
  packages PR, but do not remind the maintainer each release.

## Intrusive checks implementation in progress

- v0.6.1 milestone (PLAN decision #98), one PR per check: first PR of
  the maintainer-selected series is merged (PR #154, 2026-11-10): opt-in
  Heartbleed only, `testls-probe/src/heartbleed.rs`,
  `Options::intrusive`, CLI `--intrusive`, OpenSSL 1.0.1f test server on
  port 14435. No profile or server API implicitly enables it. Correlated
  pre-handshake disclosure is critical; rejection and silence remain not
  tested.
- PR #154 CI repair: terminate the pre-handshake exchange after the bounded
  heartbeat to flush OpenSSL 1.0.1 buffered replies; scripted peers verify
  the termination record and heartbeat followed by a fatal alert.
- PR #157 (merged 2026-11-10) implements an opt-in early CCS probe in
  `testls-probe/src/ccs.rs`. A fatal `bad_record_mac` following the probe
  indicates early cipher activation; other replies remain not tested. The
  OpenSSL 1.0.1g and 1.0.1h fixtures exercise affected and patched versions.
- Ticketbleed merged in PR #158. ROBOT is implemented on the current branch
  in `testls-probe/src/robot.rs` and `testls-scan/src/sections.rs` (decision
  #101); it is opt-in and reports only reproducible alert differences. Equal
  alerts, failed comparisons and timing oracles remain untested. It uses
  `num-bigint`, already present transitively in the lockfile.
- v0.6.1 remains open until ROBOT is merged.
- PR #159 review fixes (2026-11-10): the missing-separator vector now
  excludes zero bytes from the premaster tail; the regression failed before
  the fix. Added malformed-flight, noncomparable-alert, invalid-key/input
  tests and a scripted positive scan-to-High-finding test. Strengthened the
  Heartbleed fixture's ROBOT assertion to require an inconclusive verdict
  and no ROBOT finding when all RSA vectors receive the same alert. Removed
  generated Markdown markers, restored list order, moved #101 into the
  decision table and documented `num-bigint` plus CERT/CC 7.5 vs NIST 5.9
  severity scores.
  Targeted LLVM coverage: `robot.rs` 428/429 lines (99.77%; only the defensive
  modulus guard is uncovered), `robot_section` 28/28 (100%). OCSP fixtures,
  fmt, Clippy (`-D warnings`), workspace tests with LLVM coverage, cargo-deny
  and MSRV (`rustup run 1.97 cargo check --workspace --locked`) pass.
  The strengthened Heartbleed integration and isolated patched-Heartbleed
  test pass. Initial parallel CCS tests hit a blocked shared fixture;
  maintainer authorized restarting only `servers-heartbleed-patched-1`.
  Sequential CCS retries pass. Fresh CI at `490fa3e` passes all 26 checks,
  including all 16 container tests. Codecov patch coverage is 99.82% (one
  uncovered defensive modulus guard), project coverage 97.88%. The original
  local SMTP test remains pending; CI's SMTP test passed.
  All five inline review threads are resolved; the outside-diff #102 fix
  was reported. CodeRabbit accepted the fixes; its follow-up low-value note
  is addressed in #101: attempt errors stop the suite's probe without
  retries per #89, accepting inconclusive results on transient failures.
  Human security review remains required; no merge authorized. Existing
  `handoff-local` stash is untouched.

## Next work

Next free decision: #102 (#99 CCS, #100 Ticketbleed in PR #158, #101 ROBOT). Recheck
fresh `main` before assigning a number.

1. v0.6.0 released: GitHub release, container, all 8 crates on crates.io,
   packages PR #151 merged. New crates need a manual first publish plus a
   trusted-publishing entry by the maintainer before `release.yml` can
   publish them (done for `testls-scan`, `testls-server`). Maintainer:
   Marketplace tick.
2. v0.6 web service done: `testls-scan` (#93), `testls-server` + `testls
   serve` (#94, #95), embedded UI (`crates/testls-server/ui/`, #96).
   Maintainer supplied the dashboard CSS (own project, reuse OK). Next:
   v0.7 monitoring sketch in PLAN (ask maintainer to settle scope).
3. v0.6.1: Heartbleed, CCS injection and Ticketbleed are merged; ROBOT is
   implemented on this branch and awaits review and merge. Later backlog:
   `--delay`, `--parallel`.

## Habits that worked

- Current review (2026-11-10): maintainer requested `lan/coder`
  (Qwen3.8 27B) for code reviews. LAN review of #157 completed; parent
  verified two low-priority follow-ups: TLS 1.0/1.1 evidence/framing tests
  and duplicate-ServerHello rejection. No blocker found. Speculative
  interoperability and wording-only suggestions were not forwarded.
  Posted COMMENT review on #157: `pullrequestreview-5840532885` at
  `065d761`. Maintainer requested fixes, commit/push and merge. Both
  findings addressed: versioned peer tests assert CCS/handshake framing
  and reject mismatched alert versions; duplicate hellos (identical or
  changed version/suite) are rejected before CCS. Regression reproduced
  the old behavior before the fix; all six CCS unit tests now pass.
  Initial-head CI is green, including all 16 container integration tests.
  Initial-head local workspace tests, fmt, Clippy and `cargo deny check` pass (deny
  emits existing dependency warnings). Local MSRV check unavailable:
  `rustup` is not installed. Local affected-server CCS integration passed
  on retry (177 s); patched-server CCS integration also passed (97 s).
  Only `ccs-patched` was started this session and stopped after tests;
  pre-existing Heartbleed containers were left running.
  Fix-round local workspace tests, fmt, Clippy (`-D warnings`), cargo-deny
  and both CCS integration tests pass (177 s total). Fixes committed/pushed
  in `6b0476c`; both core-review threads resolved. CI at `6b0476c` is green,
  including MSRV and integration. LAN fix rereview failed with a connection
  timeout (`ETIMEDOUT`), not a review verdict. CodeRabbit marked the runtime
  code LGTM at `6b0476c` and
  requested four documentation follow-ups: marker cleanup, one decision-
  number rule, intrusive CLI section placement and High-severity rationale.
  All addressed in `2afe893`; four threads replied to and resolved, rereview
  requested. Final-head CI/review pending; runtime severity unchanged
  (NVD CVSS 3.1 7.4 High; server-only evidence, client/MITM prerequisites).
  No approval or merge performed; human security review still required.
  Reviewer shell denials diagnosed: global `agents/review.md` allows only
  `git diff/log/show/status/blame` prefixes; `git -C`, `head`/`tail` pipes,
  `ls`, `cat` and `echo` are denied. At the maintainer's request, permanently
  added permission-aware instructions to `~/.config/opencode/agents/review.md`:
  simple Git commands with `workdir`, dedicated read/glob/grep tools, no
  repeated denied operations; parent handles tests and GitHub operations.
  Permissions and default model unchanged; LAN reviewer was also steered.

- CodeRabbit no longer auto-reviews (repo under 10 stars; trigger with
  `@coderabbitai review`) and is slow. Previously used a local review
  by a `review` subagent with a GPT model (`litellm/gpt-6.1-sol#high`);
  the latest maintainer request selects the LAN model above instead.
  When the maintainer allows `gh` for the session, the parent reads the PR
  with the `gh` CLI (not webfetch) and posts validated reviewer findings;
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
