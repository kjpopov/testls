# Running a local review

Run from the root of the branch's checkout or worktree. CLI docs:
<https://docs.coderabbit.ai/cli>.

## Preflight

```sh
coderabbit auth status --agent    # need "authenticated":true
coderabbit usage                  # reviews left in the current window
git status --short                # must be empty: commit first
git fetch -q origin main && base=$(git merge-base origin/main HEAD) && echo "base=$base"
```

No `base=` line means the fetch or merge base failed: report `BLOCKED`. A
stale `origin/main` puts already-merged commits into the diff.

If usage shows no reviews left, report `BLOCKED` with the reset time; don't
pass `--use-credits` unless the maintainer said so.

## Review

A run usually takes a few minutes but can exceed 30. Don't let a tool
timeout cut it off: run it in the background, or set a timeout of at least
1800 s, and wait until the `complete` event appears (`heartbeat` events
mean it is still running). Keep the output in a file outside the checkout
so it doesn't show up as untracked:

```sh
out=$(mktemp "${TMPDIR:-/tmp}/testls-review.XXXXXX")
coderabbit review --agent --gate major --committed --base-commit "$base" > "$out" 2>&1
echo "exit=$? out=$out"
```

`--gate major` reviews the whole diff fresh and sets the exit code:
`0` = no major or critical finding, `2` = at least one, `1` = the review
failed or is incomplete (findings so far are not the full picture).

The output is NDJSON after a plain-text `Tip:` line. Event types include
`review_context`, `status`, `heartbeat` (liveness only), `finding`,
`error`, `complete`. Check the run finished:

```sh
grep -E '"type":"(complete|error)"' "$out" | jq -c 'del(.reviewedFiles)'
```

The run counts only with exit 0 or 2 and a `complete` event with
`"status":"review_completed"`, `outcome` not `failed`, no positive
`unreviewedFileCount`, and no `reused: true`. `"status":"review_skipped"`
means the scope had no changes: check `$base`. Anything else: report it
verbatim, don't call the branch clean. Format: the
[agent mode docs](https://docs.coderabbit.ai/cli/agent-mode).

## Findings

```sh
grep '"type":"finding"' "$out" | jq -r '
  .severity + " " + .fileName + ":" + (.startLine|tostring) + " " + .title'
```

Full text of one finding (N counts from 0); `codegenInstructions` and
`suggestions` hold the proposed fix when present:

```sh
grep '"type":"finding"' "$out" | jq -s '.[N] | {comment, codegenInstructions, suggestions}'
```

Triage from `$out` only: `coderabbit review findings` can show an older
run's findings when the latest run had none.

## Second run

Only after fixing a critical or major finding. Commit the fix, then repeat
"Review" with the same `$base`.
