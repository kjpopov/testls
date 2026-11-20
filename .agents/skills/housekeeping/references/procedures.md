# Housekeeping procedures

Candidate checks and deletion commands. Verify before deleting; a wrong
delete of a remote branch is recoverable but still costly.

## Merged remote branches

List after `git fetch --prune origin`:

```sh
git for-each-ref --merged=refs/remotes/origin/main \
  --format='%(refname:lstrip=3)' refs/remotes/origin/ |
  awk '$0 != "HEAD" && $0 != "main"'
```

This lists branch names under `origin` and excludes the target branch. Never
delete the target or a remote's default branch, even if it appears merged.

First check that `git remote get-url origin` and every URL from
`git remote get-url --push --all origin` name the same repository; if not
(fork and upstream, or several push targets), report it and stop.

Capture each tip once, verify that exact object, and lease it, so a later
fetch cannot swap in an unchecked tip:

```sh
oid=$(git rev-parse refs/remotes/origin/BR)
git merge-base --is-ancestor "$oid" refs/remotes/origin/main && echo "BR $oid merged"
```

Leases cover only the deleted refs, not `main`. Run this only if remote
`main` is protected against force-pushes; if not, report and stop. Right
before the push, `git fetch --prune origin` again and repeat the ancestry
check (or, for squash merges, the content check below) with the captured
oids.

Delete in one atomic batch, leasing every ref, so a branch updated since the
check is not deleted:

```sh
git push --atomic origin --force-with-lease=refs/heads/BR1:<oid1> \
  --force-with-lease=refs/heads/BR2:<oid2> --delete BR1 BR2 ...
git fetch --prune origin
```

A `stale info` rejection means the branch moved: recheck it before
retrying.

Traps:

- **Partial batch failure.** With `--atomic`, any rejected ref (for
  example `remote ref does not exist` or `stale info`) fails the whole
  push. Run `git fetch --prune origin`, drop the refs that are gone or
  moved, and push the verified survivors again. Without `--atomic`, read
  each ref's result line before retrying.
- **Squash-merge blindness.** `--merged` misses squash-merged branches.
  Inspect the complete branch diff from its merge base, including additions,
  modifications, deletions, renames and binary files, and compare every
  change with the target and any later changes. A keyword match or a note
  alone does not establish that all branch work landed. If that cannot be
  verified, keep the branch and report it. An empty diff with commits in
  `git log refs/remotes/origin/main.."$oid"` (for example a change and its
  revert) is not proof either: keep and report. Inspect the captured tip,
  not a local branch of the same name:

  ```sh
  git diff --stat "$(git merge-base refs/remotes/origin/main "$oid")" "$oid"
  git diff --binary "$(git merge-base refs/remotes/origin/main "$oid")" "$oid"
  ```

- **Current branch.** Never delete the branch checked out in any
  worktree; `git worktree list` shows which branch each uses.

## Local branches

After remote cleanup, delete local branches that are merged into `main`
or whose remote counterpart is gone:

```sh
git branch --merged main | grep -vE '^[*+]? *main$'
git branch -vv | grep ': gone]'   # remote counterpart deleted
git for-each-ref --format='%(refname:short) %(upstream)' refs/heads/ | awk 'NF == 1'   # no upstream
oid=$(git rev-parse refs/heads/BRANCH)
```

A branch without an upstream is a candidate too; `gone` never shows for it.
Compare it with `refs/remotes/origin/BRANCH` after the fetch, and keep it
unless the checks below prove its work landed. Run the ancestry or content check on that captured local tip, not its
remote counterpart: it may hold commits that were never pushed. Confirm with
`git worktree list` that no worktree uses the branch (`update-ref` does not
refuse a checked-out branch). A rebase or bisect shows a detached HEAD but
still uses its branch, so run the busy check below on every worktree and
delete no local branch while any is busy. Never delete local `main`, even
though it is listed as merged. Only when all checks pass:

```sh
git worktree list --porcelain | grep -qxF 'branch refs/heads/BRANCH' \
  || git update-ref -d refs/heads/BRANCH "$oid"   # fails if BRANCH moved: recheck
```

## Worktrees

Check before removing; `git worktree remove` deletes ignored files too:

```sh
git -C <worktree-dir> ls-files -v | grep -E '^([a-z]|S)'   # assume-unchanged/skip-worktree: status hides edits, keep
git -C <worktree-dir> status --short --ignored --untracked-files=all   # only target/ allowed
for p in rebase-merge rebase-apply BISECT_LOG MERGE_HEAD CHERRY_PICK_HEAD REVERT_HEAD; do
  test -e "$(git -C <worktree-dir> rev-parse --path-format=absolute --git-path "$p")" && echo "busy: $p"
done
oid=$(git -C <worktree-dir> rev-parse HEAD)
git for-each-ref --contains="$oid" refs/heads/ refs/remotes/   # detached: empty means keep
```

Keep and report a worktree with assume-unchanged or skip-worktree files
(sparse checkouts included), uncommitted or ignored files (other than
build output such as `target/`), one that is busy (rebase, bisect, merge,
cherry-pick or revert in progress), or a detached one whose HEAD no branch
that stays after cleanup holds. Worktrees in agent scratch space on merged
or detached branches are the usual stale ones, but a clean worktree can still
be in use by another agent or session. Clean checks do not prove it is idle:
list the candidates and remove only those the user confirms. Record each
candidate's identity before asking:

```sh
git -C <worktree-dir> rev-parse --absolute-git-dir HEAD
git -C <worktree-dir> branch --show-current   # empty when detached
```

After the confirmation, rerun these and all checks above. If the git dir,
HEAD or branch changed, ask again for the current worktree; keep it if any
check now fails. Only when the rerun passes:

```sh
git worktree remove <worktree-dir>     # add --force only after user confirms
git worktree prune --dry-run --verbose
git worktree prune
```

Prune only when every dry-run entry is a directory you confirmed was
deleted; a worktree on an unmounted drive looks missing too. Otherwise keep
and report it (or `git worktree lock` it).

## Stashes

```sh
git stash list
git stash show --include-untracked --stat 'stash@{0}'
git stash show --include-untracked --patch 'stash@{0}'
```

Inspect the complete patch, including stashed untracked or ignored files,
and compare it with the target branch. Report redundant and unique content.
Keep every stash unless the user explicitly named it for deletion, even when
its content appears redundant.

## Build artifacts

Measure before cleaning: `du -sh target` (Rust) and friends.
`cargo clean` frees everything at the cost of a full rebuild; `cargo
sweep` trims stale artifacts only. Prefer reporting the size and asking
when the user did not ask for "clean all".

## Local ref freshness

```sh
git fetch origin main:main   # fast-forward local main; fails if diverged
```

This refuses to update `main` while it is checked out; then run
`git -C <that-worktree> merge --ff-only origin/main` there if it is clean
(`git -C <that-worktree> status --short --ignored` lists nothing outside
`target/`; a merge silently overwrites ignored files).
If either fails, report it instead of forcing.

## Object hygiene

Use `git count-objects -vH` to report object storage. Do not run `git gc`
or prune unreachable objects during routine cleanup: they may contain
recoverable commits or other work.

## Push auth

If `git push` to the push URL fails with `Permission denied (publickey)`
or similar, check the agent (`ssh-add -l`) once, then retry the same push
against the fetch URL inline (e.g. `git push https://... --delete ...`),
but only if both URLs name the same repository (not a fork and upstream).
Do not edit `git config` or add keys; report the auth mismatch instead.
