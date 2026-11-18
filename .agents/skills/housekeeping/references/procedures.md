# Housekeeping procedures

Candidate checks and deletion commands. Verify before deleting; a wrong
delete of a remote branch is recoverable but still costly.

## Merged remote branches

List after `git fetch --prune`:

```sh
git branch -r --merged origin/main | grep -v 'origin/HEAD'
```

Delete in one batch:

```sh
git push <fetch-url> --delete BR1 BR2 ...
git fetch --prune
```

Traps:

- **Partial batch failure.** If any ref no longer exists remotely, git
  prints `remote ref does not exist` for it and fails the whole push — the
  other deletions in that push did not happen. Collect the surviving refs
  from the error list and push them again.
- **Squash-merge blindness.** `--merged` misses squash-merged branches.
  `git cherry main BR` reports their commits as unique (`+`); that is a
  false positive for squash merges. Confirm by content: `git grep -il
  <feature-keyword> origin/main`, or read the handoff/PLAN notes for the
  merge commit, before deleting.
- **Current branch.** Never delete the branch checked out in any
  worktree; `git worktree list` shows which branch each uses.

## Local branches

After remote cleanup, delete local branches that are merged into `main`
or whose remote counterpart is gone:

```sh
git branch --merged main
git branch -D BRANCH          # only after the unique-content check above
```

## Worktrees

```sh
git -C <worktree-dir> status --short   # clean?
git worktree remove <worktree-dir>     # add --force only after user confirms
git worktree prune
```

Worktrees in temp directories (agent scratch space) on merged or detached
branches are the usual stale ones. A worktree with uncommitted changes is
reported, not removed.

## Stashes

```sh
git stash list
git stash show --stat stash@{0}
git diff stash@{0}^ stash@{0} | head -80
```

Compare the stashed diff against the target branch: if the content is
already there (possibly reworded), the stash is redundant and can be
dropped with `git stash drop`. If it carries unique notes or fixes, keep
it and say so — a stash that needs a manual merge is a report item, not a
cleanup item.

## Build artifacts

Measure before cleaning: `du -sh target` (Rust) and friends.
`cargo clean` frees everything at the cost of a full rebuild; `cargo
sweep` trims stale artifacts only. Prefer reporting the size and asking
when the user did not ask for "clean all".

## Local ref freshness

```sh
git fetch origin main:main   # fast-forward local main; fails if diverged
```

If it fails, report the divergence instead of forcing.

## Object hygiene

`git count-objects -vH` first: if `size-pack` is small and garbage is
near zero, `git gc` buys nothing. Otherwise `git gc --prune=now -q`.

## Push auth

If `git push` to the push URL fails with `Permission denied (publickey)`
or similar, check the agent (`ssh-add -l`) once, then retry the same push
against the fetch URL inline (e.g. `git push https://... --delete ...`).
Do not edit `git config` or add keys; report the auth mismatch instead.
