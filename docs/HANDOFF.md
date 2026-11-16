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
- Ticketbleed merged in PR #158. ROBOT merged in PR #159 (2026-11-10),
  in `testls-probe/src/robot.rs` and `testls-scan/src/sections.rs` (decision
  #101); it is opt-in and reports only reproducible alert differences. Equal
  alerts, failed comparisons and timing oracles remain untested. It uses
  `num-bigint`, already present transitively in the lockfile.
- All four v0.6.1 intrusive checks are merged; the release is not cut yet.
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
  local SMTP test eventually passed; CI's SMTP test passed.
  All five inline review threads are resolved; the outside-diff #102 fix
  was reported. CodeRabbit accepted the fixes; its follow-up low-value note
  is addressed in #101: attempt errors stop the suite's probe without
  retries per #89, accepting inconclusive results on transient failures.
  The maintainer subsequently merged PR #159 at `2f61b5c`; the agent did not
  merge it. Existing `handoff-local` stash is untouched.

## Next work

- Local fixture cross-check (2026-11-10, branch `docs/local-fixture-audit`
  from merged PR #159 at `2f61b5c`): maintainer authorized local scans with
  both tools, GitHub issues for confirmed gaps and linked roadmap items.
  Initial sequential CLI-only comparisons finished for all 13 existing
  endpoints (five direct TLS, eight STARTTLS). Protocol/suite sets agree on
  twelve completed comparisons; FTP's comparator preflight failed although
  testls and independent OpenSSL accept AUTH TLS. The other four endpoints
  stalled with both tools even after authorized restarts of only
  `servers-heartbleed-1`, `servers-heartbleed-patched-1`,
  `servers-ccs-patched-1`, `servers-smtp-1`. Internal Heartbleed TLS works;
  an owned loopback SSH tunnel to the same containers also stalled and was
  closed. Fixture logs and an independent lookup implicate reverse DNS.
  Maintainer authorized temporary local peer-name entries in only those four
  containers. All four comparisons completed with the workaround, with
  expected Heartbleed/CCS findings; all original hosts files are restored and
  verified byte-for-byte. Bridge lookup again stalled after restoration;
  filed fixture reliability issue #163. No global DNS/network/SSH changes.
  No new wolfSSL fixture is built yet.
  Isolated testssl.sh v3.2.5 is pinned to
  `4f17be931a9d60f3f987975aea8221f1a8eaf7aa`; its source and data are not read
  or copied into this repository. Runner and raw results are outside the
  repository under the approved OpenCode temporary directory,
  `testls-fixture-audit-20261110/`. Both scanners use localhost SNI and the
  fixture CA; testssl.sh DNS and both external revocation fetches are off.
  Client simulation and grade comparison are excluded. Existing debug CLI
  SHA-256: `4dbd242409545e198527e1b3593a5e84ead400d34a6319ca7ba5dc357bdfd2eb`.
  Confirmed independently and filed: ROBOT optional client CertificateRequest
  handling on MariaDB (#160); absent real positive/patched ROBOT fixture pair
  (#161, candidate wolfSSL releases still unverified); DH suite sampling hides
  a 1024-bit accepted group on the legacy fixture (#162); peer reverse-DNS
  stalls in historical TLS/SMTP fixtures (#163). All are linked in
  PLAN; durable own-wording report: `docs/local-fixture-audit.md`. Keep
  `handoff-local` stash and other pre-existing containers untouched. No scanner
  implementation or image changes. FTP native-mode retry also failed at
  preflight; no external vulnerability/cipher parity claimed there. No scans
  remain running; owned SSH tunnels are closed and temporary hosts restored.

- PR #164 merged on maintainer request (2026-11-15) at `72b8e88`: reviewed
  all three documentation files, all 26 checks passed, CodeRabbit approved
  head `c5244d2`, and no review threads or actionable comments remained.
  Updated `origin/main` is merged into #165 without rewriting reviewed commits.

- Repeatable local fixture audit (2026-11-15, PR #165): maintainer selected
  local-only automation and review before issue filing (decision #102).
  Added `scripts/audit-fixtures.py`, manifest `tests/servers/audit.json`,
  synthetic adapter/process tests and `docs/fixture-audit.md`. Runner verifies
  the comparator pin, bounds sequential scans, preserves incomplete evidence
  and emits JSON/Markdown plus unconfirmed issue drafts. No automatic tool
  installation, container/DNS changes, CI workflow or GitHub writes.
  Existing fixtures are stopped; no full 13-fixture re-audit performed.
  Initial validation: 25 tests, docstrings, diff/fmt checks, OCSP fixtures,
  workspace Clippy (`-D warnings`), workspace tests and MSRV pass. Container
  tests remain ignored locally. All 27 initial-head CI checks passed, but
  CodeRabbit requested fixes. Review fixes: documented PATH `timeout` and the
  direct-TLS plain OPTIONS request to loopback port 80; verified the pinned
  public cipher-ID-only JSON on an authorized disposable loopback TLS listener;
  fixed the adapter, required a completion record and rejected reserved/fatal
  exit codes with partial JSON; checked input identities and comparator
  revision/clean state around every scanner invocation, skipping changed
  inputs and marking output unattributed. All 31 tests pass. No external
  implementation/tables/client data inspected or copied. Temporary listener
  smoke verified capture passes with matching provenance and both configured
   TLS 1.2 suites; listener is closed. These tests do not establish a real
   ROBOT oracle or full-fixture parity. Review-fix diff/fmt and docstrings pass.
   Next round: all 27 checks passed at `c05a860`, but CodeRabbit requested
   further fixes. Bound manifest parsing/hash to one byte snapshot and reject
   changed bytes before scans; synthetic orchestration now mocks `timeout`
   discovery. macOS examples resolve Homebrew's keg-only OpenSSL prefix.
   Scanner/metadata environments allow only PATH, fixed locale/time-zone and
   `PHONE_OUT=false`; inherited options, proxies and shell hooks are excluded
   and the exact environment is recorded. Every nonzero comparator exit is
   incomplete, even with a completion record; partial evidence is retained.
   All 34 tests, diff/fmt and docstrings pass. An additional pinned-comparator
   smoke with inherited `PHONE_OUT=true` and `BASH_ENV` passes in the controlled
   environment with matching provenance and both suites; its listener is closed.
   An empty-PATH suite run was permission-denied, not claimed as verified.
   Latest full review approved `fe3855e` with all 27 checks passing, but its
   outside-diff body flagged one valid completion gap. A warning `scanTime`
   could be accepted after exit 0. Regression reproduces the false completion;
   adapter now requires exactly one INFO record with elapsed whole seconds,
   retaining suites but marking warnings/malformed records incomplete.
   This successful shape is confirmed by the earlier authorized public output;
   no comparator implementation was inspected. All 35 tests, diff/fmt and
   docstrings pass; both earlier successful comparator captures still parse
   as complete with their two suites. Final-head CI passed; the maintainer
   merged #165 on 2026-11-16 at `7353f17`. Rechecked the supplied scanTime
   finding against merged code: already fixed, with the regression retaining
   offered suites after an interrupted completion; no follow-up change needed.
  During #165, local `cargo deny check` was blocked by `rustix 1.1.5`
  RUSTSEC-2026-0486; that PR did not change dependencies or create an issue.
  The agent did not merge #165; existing `handoff-local` stash is untouched.

- Rustix advisory maintenance (2026-11-16, `fix/rustix-advisory` from
  `7353f17`): reproduced RUSTSEC-2026-0486, then updated only the locked
  transitive `rustix` version/checksum to 1.1.6. Existing Windows dependency
  edges and all other locked packages are unchanged. No advisory suppression
  or direct dependency added; exploit reachability in testls is not established.
  OCSP fixtures, 35 audit-runner tests, fmt, workspace Clippy (`-D warnings`),
  workspace tests, MSRV and locked workspace check pass. Full
  `cargo deny check` passes; usual duplicate/license-exception warnings remain.
  Container tests are ignored locally; all CI checks pass, including integration
  and advisories. Maintainer merged PR #167 at `4c5ae675` (2026-11-16), choosing
  not to wait for the rate-limited CodeRabbit review. At the maintainer's request,
  commented on issue #166 with the fix and validation, then closed it as completed.
  The agent did not merge the PR; existing stash and containers remain untouched.

- ROBOT optional client certificate requests (#160, 2026-11-16): branch
  `fix/robot-client-certificate` from merged #167 main `4c5ae675`. Preserved
  the prior rustix closeout note and existing `handoff-local` stash. Accept
  one request after the server certificate, validate version-specific vectors
  and DER authority names, and send only an empty client Certificate before
  each RSA vector. Request presence/content must match between attempts;
  controls, repeated fatal-alert evidence and eight-connection bound unchanged.
  Regression failed before the fix; all 13 ROBOT tests pass, covering TLS
  1.0/1.1/1.2 framing, request fragmentation, malformed/duplicate/order
  rejection, request changes and required-client-auth refusal. MariaDB CLI
  integration passes: vectors complete, equal alerts remain not tested.
  Clean targeted coverage is 707/708 lines (99.86%); request helpers 39/39.
  Only the existing defensive RSA-modulus guard is uncovered.
  Maintainer authorized starting stopped existing fixtures and stopping only
  those started for this task; no container/DNS configuration changes.
  OCSP fixtures, fmt, workspace tests, final workspace Clippy (`-D warnings`),
  MSRV and cargo-deny pass. Full sequential container integration: 17/17 pass.
  Stopped all 12 previously stopped fixtures started for this task; no fixture
  configuration changes. Human security review required before merge; no
  merge authorization for this branch. PR #168 at `f7b3de1` has all CI and
  Codecov checks passing; patch coverage 100%, project coverage 97.77%.
  CodeRabbit skipped because the OSS review quota was exhausted (its note
  reported a 12-minute reset). No substantive review or approval yet; PR
  remains unmerged.
  Maintainer supplied an external agent review: no blockers. Review follow-up
  names the empty Certificate handshake (not a record), explains CKE capacity
  and ServerHello offsets, and rejects empty certificate types earlier.
  Keep independent expected wire bytes in tests, rather than sharing the
  production constant. RFC 2246 §7.4.4 explicitly requires the TLS 1.0
  authority vector minimum of three bytes; retain that version check.
  Expanded the request-change test to cover appearance, disappearance,
  content changes and a round-boundary change, plus no retry connections.
  Document this existing fail-inconclusive policy in usage and decision #101;
  it follows the no-retry bound of #89. All 13 ROBOT tests, workspace tests,
  Clippy (`-D warnings`), MSRV, fmt, OCSP fixtures and cargo-deny pass.
  Full sequential container rerun: 17/17 pass; stopped all 12 task-started
  fixtures again, without configuration/DNS changes. Request CodeRabbit
  after publishing all review fixes together; no merge authorization.
  CodeRabbit reviewed `5cb345c` after all CI/Codecov checks passed and requested
  two fixes. Its malformed authority Name (`30 01 ff`) reproduced acceptance
  before the fix: the X.509 parser discarded unread container content. Check
  complete Name/RDN/attribute consumption using the RFC 5280 §4.1.2.4 shape,
  then retain existing semantic validation. Regression covers unread bytes at
  every level, malformed tags/missing fields, multiple RDNs/attributes and a
  real certificate subject. A bounded test-only relay now observes all eight
  unchanged MariaDB exchanges: each real server CertificateRequest and an
  empty client Certificate immediately before CKE. Keep the CLI's equal-alert
  not-tested/no-finding assertions; no public output/schema change. All 14
  ROBOT unit tests, workspace tests and the real MariaDB relay/CLI regression
  pass. OCSP fixtures, fmt, cargo-deny, final Clippy (`-D warnings`) and MSRV
  including all test targets pass. Full sequential container integration:
  17/17 pass, including the transparent MariaDB observation. Stopped all 12
  task-started fixtures, without container/DNS configuration changes. Publish
  both review fixes in one commit and reply/resolve the two threads; fresh
  CI/CodeRabbit review required. No merge authorization.
  All CI/Codecov checks passed at `3c89d4d`; CodeRabbit requested one further
  fix: the locked OID parser does not check the attribute-type tag. Its NULL
  attribute-type Name reproduced acceptance before the fix. Require the
  universal, primitive OBJECT IDENTIFIER tag explicitly before existing OID
  parsing; regressions also reject other ASN.1 classes and constructed OIDs.
  All 14 ROBOT tests, workspace tests, all-target MSRV, Clippy, fmt, OCSP
  fixtures and cargo-deny pass. Full sequential container rerun: 17/17 pass.
  Stopped all 12 task-started fixtures without configuration changes. Publish
  this fix in one commit, then reply/resolve the review thread; fresh CI and
  CodeRabbit review required. No dependency/output changes or merge authorization.
  All CI/Codecov checks passed at `4af59e2`; CodeRabbit found that the locked
  OID parser also accepts malformed subidentifier contents. Its unterminated
  OID reproduced acceptance before the fix. Enforce X.690 §8.19.2 minimal,
  terminated base-128 subidentifiers and reject empty contents, retaining all
  prior DER checks. Regression tests cover the reported Name, boundaries,
  leading-zero encodings and valid multi-octet/large arcs without numeric limits.
  All 15 ROBOT tests, workspace tests, all-target MSRV, Clippy, fmt, OCSP
  fixtures and cargo-deny pass. Full sequential container rerun: 17/17 pass.
  Stopped all 12 task-started fixtures without configuration changes. Fresh CI
  and CodeRabbit review required; no dependency/output changes or merge authorization.
  At `a107af7`, all CI/Codecov checks pass; patch coverage is 99.77%, project
  97.79%. The sole uncovered patch line is the defensive `X509Name` trailing-
  content rejection after the stricter complete-consumption check. CodeRabbit
  skipped due to its review quota; no substantive current-head review yet.
  A later CodeRabbit pass at `a107af7` requested one fix: validate authority-name
  attribute-value contents. Its UTF8String Name (`30 0c 31 0a 30 08 06 03 55 04
  03 0c 01 ff`) reproduced acceptance before the fix because `Any::from_der`
  and `X509Name` read declared bytes without checking string contents. Require
  universal primitive values and validate their X.680 character sets (UTF-8/BMP/
  Universal decode without unpaired surrogates, IA5/Visible/Printable/Numeric
  per byte; Teletex/General/Graphic and non-strings stay unconstrained). Both
  the malformed Name and its `61` control are regressions; a 28-case matrix
  covers each set. All 16 ROBOT tests, workspace tests, all-target MSRV, Clippy,
  fmt, OCSP fixtures and cargo-deny pass. Full sequential container rerun: 17/17
  pass; stopped all 12 task-started fixtures without configuration changes.
  Fresh CI and CodeRabbit review required; no dependency/output changes or merge
  authorization.
  CodeRabbit at `1dfc2fd` requested that valid constructed attribute values
  stay accepted and that BMPString surrogate pairs be rejected. Accept
  constructed values unless they are a string type (`string_type`): DER
  encodes strings primitive (X.690 §8.23), while other ANY values such as a
  `postalAddress` SEQUENCE of DirectoryString (RFC 4517 §3.3.24) remain valid;
  the class, complete `Any` consumption and `string_contents` checks remain.
  BMPString UTF-16 well-formedness already handles surrogate pairs, so the
  adjacent-surrogate rows are pinned and the code is unchanged. Deferred:
  constructed universal non-string, non-SEQUENCE values are accepted because
  `string_contents` passes other tags, and inner contents of constructed
  values are not schema-validated. 16 ROBOT tests (30-case string matrix),
  workspace tests, all-target MSRV, Clippy, fmt, OCSP fixtures, cargo-deny and
  full 17/17 container integration pass; stopped all 12 task-started fixtures
  without configuration changes. Fresh CI and CodeRabbit review required; no
  dependency/output changes or merge authorization.

Next free decision: #103 (#99 CCS, #100 Ticketbleed, #101 ROBOT, #102 local audit). Recheck
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
3. v0.6.1: Heartbleed, CCS injection, Ticketbleed and ROBOT are merged; prepare
   the release when the maintainer chooses. Later backlog:
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
