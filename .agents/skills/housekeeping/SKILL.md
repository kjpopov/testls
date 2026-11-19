---
name: housekeeping
description: 'Use when asked to do housekeeping or clean up a repository: delete merged branches, remove stale worktrees and stashes, shrink build artifacts, refresh local refs.'
---

# Housekeeping

Runbook for repository cleanup: merged branches, worktrees, stashes, build
artifacts, local ref freshness. Destructive to refs and artifacts only; never
to committed history.

## Hard rules

- Before deleting anything, verify it is actually merged or stale (see
  [Procedures](./references/procedures.md)). "Looks old" is not a reason.
- Squash-merged branches are NOT detected by `git branch --merged`. Confirm
  the content landed on the target before deleting.
- Stashes, uncommitted or ignored work, and branches with unverified unique
  content are kept and reported, not deleted, unless the user explicitly
  named them. Never delete `main`.
- Delete remote refs in batches but expect partial failure: already-gone
  refs abort the whole batch. Retry with the surviving refs only.
- Push URLs may differ from fetch URLs (e.g. SSH vs HTTPS). If one fails
  with an auth error, retry over the other URL once, inline, without
  changing any git config, and only if both name the same repository.
- End with a report: what was deleted, what was kept and why, plus final
  state (`git branch -a`, `git worktree list`, `git stash list`).

## Workflow

1. Orient: `git rev-parse --show-toplevel`, `git branch --show-current`,
   `git remote -v`, `git worktree list`, `git stash list`.
2. `git fetch --prune origin` before listing merged branches.
3. Enumerate candidates, check each, delete the safe ones.
4. Report.

For candidate checks, deletion commands, and the squash-merge and
partial-batch traps, read [Procedures](./references/procedures.md).
