# Running a local review

Run from the root of the branch's checkout or worktree. CLI docs:
<https://docs.coderabbit.ai/cli>.

## Preflight

```sh
coderabbit auth status --agent    # need "authenticated":true
coderabbit usage                  # reviews left in the current window
git status --short                # must be empty: commit first
git fetch -q origin main
base=$(git merge-base origin/main HEAD)
```

If usage shows no reviews left, report `BLOCKED` with the reset time; don't
pass `--use-credits` unless the maintainer said so.

## Review

A run takes 2-6 minutes, sometimes up to 15: set the tool timeout to 900 s
and wait with one command. Keep the output in a file outside the checkout
so it doesn't show up as untracked:

```sh
out=$(mktemp "${TMPDIR:-/tmp}/testls-review.XXXXXX")
coderabbit review --agent --committed --base-commit "$base" > "$out" 2>&1
echo "exit=$?"
```

The output is NDJSON after a plain-text `Tip:` line. Event types:
`review_context`, `heartbeat` (liveness only), `finding`, `complete`.

Check the run finished:

```sh
grep '"type":"complete"' "$out" | jq -c '{status, findings, message}'
```

Anything but `"status":"review_completed"` (or no `complete` line) means no
review happened: report it verbatim, don't call the branch clean.

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

`coderabbit review findings` shows the last stored review again without a
new run.

## Second run

Only after fixing a critical or major finding. Commit the fix, then repeat
"Review" with the same `$base`. The CLI reuses its last checkpoint; add
`--fresh` only if it reports nothing changed although you committed fixes.
