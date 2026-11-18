---
name: testls-chores
description: Use when delegated a testls chore - fixture containers, ignored integration tests, or PR CI/CodeRabbit polling.
---

# testls chores

Read-only runbook for helper agents. The caller owns code, commits and merges;
you run commands and report what happened.

## Hard rules

- No file edits, commits, pushes, merges, branch switches, thread resolution,
  or `gh` writes other than an explicitly requested `@coderabbitai review`.
- First run `git rev-parse --show-toplevel` and `git branch --show-current`.
  Stop and report if either differs from what the caller named. Other
  worktrees may belong to other agents; never touch them.
- Run exactly the commands given or listed here. Don't "fix" failures; report
  them.
- Podman, not docker. macOS has no `timeout`; use tool-level timeouts.
- Wait with one long command (`sleep`, `gh pr checks --watch`) and set the
  tool timeout to cover it; don't burn steps on short polls.
- Always end with a report, even when out of steps: `WAITING` plus the next
  action and when.
- Report verbatim: copy error lines, test names, review text. Never summarize
  a failure as "some tests failed".

## Chores

- Start, check or stop fixture servers, or run ignored integration tests:
  first read [Fixtures and integration tests](./references/fixtures.md).
- Watch CI, trigger or wait for CodeRabbit, collect review findings: needs
  the caller to confirm the maintainer allowed `gh` this session, else
  report `BLOCKED`. Then first read [PR polling](./references/pr-polling.md).

## Report format

```text
branch: <name> @ <short sha>
ran: <command>
result: PASS | FAIL | WAITING | BLOCKED
details:
  <verbatim lines that matter, max ~30>
```

One block per command group. No advice unless asked.
