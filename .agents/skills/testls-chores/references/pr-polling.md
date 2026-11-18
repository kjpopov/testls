# PR polling

Observe a PR and report; never merge, push, reply or resolve threads.
`N` is the PR number, `OWNER/REPO` from `gh repo view --json nameWithOwner`.
The full maintainer loop is in `docs/agent-workflow.md`.

## Status snapshot

```sh
gh pr view N --json headRefOid,mergeStateStatus,reviewDecision
gh pr checks N
```

Report failing or pending checks by name. For a failing job:

```sh
gh run view RUN_ID --json jobs --jq '.jobs[] | select(.conclusion=="failure") | .name + " " + .url'
gh run view RUN_ID --log-failed | tail -40
```

A job cancelled at its time limit with no test failure is likely infra;
report it as such, don't rerun unless asked.

## CodeRabbit verdict

Latest non-comment review and whether it covers the head commit:

```sh
gh api --paginate --slurp repos/OWNER/REPO/pulls/N/reviews | jq -r '[.[][]
  | select(.user.login == "coderabbitai[bot]" and .state != "COMMENTED")]
  | last | .state + " " + .commit_id'
```

Last completed CodeRabbit review of any state, the fallback anchor for
rate limits:

```sh
gh api --paginate --slurp repos/OWNER/REPO/pulls/N/reviews | jq -r '[.[][]
  | select(.user.login == "coderabbitai[bot]")] | sort_by(.submitted_at)
  | last | .submitted_at'
```

Unresolved threads, all pages:

```sh
gh api graphql --paginate -f query='query($endCursor: String) {
  repository(owner: "OWNER", name: "REPO") { pullRequest(number: N) {
    reviewThreads(first: 50, after: $endCursor) {
      pageInfo { hasNextPage endCursor }
      nodes { isResolved comments(first: 1) { nodes { databaseId path line body } } }
    } } } }' \
  --jq '.data.repository.pullRequest.reviewThreads.nodes[] | select(.isResolved|not) | .comments.nodes[0]'
```

Copy each unresolved comment's id, path, line and the "Prompt for AI Agents"
section verbatim.

Review bodies hold outside-diff and nitpick items, which have no thread,
and maintainer requests. Read every review body from every author,
including `COMMENTED` ones:

```sh
gh api --paginate --slurp repos/OWNER/REPO/pulls/N/reviews | jq -r '.[][]
  | select(.body != "")
  | "=== " + .user.login + " " + .state + " " + .commit_id + "\n" + .body'
```

Report every non-CodeRabbit review body verbatim as an open item; only the
caller decides whether it is settled.

Done when merge state is `CLEAN`, no unresolved threads, no open
non-CodeRabbit review items, and either:

- verdict `APPROVED` on the head, or
- CodeRabbit withheld approval ("Automatic approval withheld", merge risk)
  but its latest review on the head has no actionable comments and its
  check completed. Report this as `PASS` with the withheld reason quoted.

Run the snapshot's `gh pr view` again after collecting the verdict and
threads; if `headRefOid` changed, repeat everything for the new head. Only
then report `result: PASS`; the caller merges.

## Rate limits

Post `@coderabbitai review` only when the caller explicitly asked for it;
otherwise report the limit and stop.

CodeRabbit's free plan allows few reviews per hour. Before posting, read its
limit messages across all pages, newest last:

```sh
gh api --paginate --slurp repos/OWNER/REPO/issues/N/comments | jq -r '[.[][]
  | select(.user.login == "coderabbitai[bot]")
  | select(.body | test("rate limited|Review limit reached"; "i"))]
  | sort_by(.updated_at) | .[] | "=== " + .updated_at + "\n"
  + ([.body | split("\n")[] | select(test("limit|available in|minute"; "i"))] | join("\n"))'
```

- If one says "rate limited" or "Review limit reached" with "available in M
  minutes", wait until its `updated_at` + M + 2 minutes. CodeRabbit edits
  the same comment, so `updated_at` is the anchor, not `created_at`.
- Without a stated time, wait until one hour after the last completed review.
- The estimate is not reliable. Right before posting, read the comments
  again; if the newest one now names a later time, wait for that instead.
  Never post while limited.
- Post `@coderabbitai review` at most once per window
  (`gh pr comment N -b "@coderabbitai review"`). If limited again, report
  `BLOCKED` with the limit message and new time; don't post again.

## Waiting

Agents often have a small step budget, so wait with one long command, not
many short polls. Set the tool timeout to the expected wait plus 60 s; if
the tool caps timeouts lower, use the largest allowed wait.

- CI: `gh pr checks N --watch --interval 60` blocks until every check
  finishes (add `--fail-fast` to stop on the first failure). Its exit
  status is not a verdict; read the result with
  `gh pr checks N --json name,bucket --jq '.[] | select(.bucket != "pass" and .bucket != "skipping")'`.
  A `CodeRabbit` check of `skipping` means no review ran (usually rate
  limited).
- CodeRabbit window (only if the caller asked for a review): one
  `sleep SECONDS` until the computed time, then re-read comments and post.
- CodeRabbit review after posting: it takes a few minutes; `sleep 600`, then
  run the verdict commands once.

Stop and report on: new review, new unresolved thread, check failure,
`PASS`, or limit hit again. If the step budget is nearly used up, report
`WAITING` with the next action and time instead of running out silently.
