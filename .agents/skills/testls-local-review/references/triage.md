# Triaging findings

Severity is CodeRabbit's guess, not a verdict. Read the cited code before
deciding; most rounds contain at least one finding that is wrong.

## Verdicts

- **Fix**: the claim holds and the fix stays inside the branch's topic.
  Add or change a test that would have caught it.
- **Refute**: the claim is wrong. Note the evidence (file:line, RFC section,
  existing test) so the same finding can be answered on the PR in one line.
- **Defer**: valid but out of scope. Open or name an issue; don't widen the
  PR.

## Checks before accepting a finding

- Does the code path exist? Findings often assume a caller, a
  deserializer or a fallback that the workspace doesn't have. Grep for it.
- Is it already handled elsewhere (shared helper, grading, policy)?
- Does it fight a recorded decision? Check the decision log in
  `docs/PLAN.md`; a finding doesn't overturn a decision without new
  evidence.
- Security findings in probes: confirm against the RFC, never weaken a
  verdict rule (alert/flow oracles, `not tested` vs proven negative) to
  satisfy a reviewer.
- Clean-room rule from AGENTS.md still applies to suggested code.

## Cost of nits

Trivial and info findings, and wording nits in docs, are optional. Batch the
cheap ones into the fix commit or skip them; never spend a second run on
them.
