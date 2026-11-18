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
gh run view RUN_ID --json jobs --jq '.jobs[] | select(.conclusion=="failure") | "\(.databaseId) \(.name)"'
mkdir -p target
if gh run view --job JOB_ID --log-failed > target/job-JOB_ID.log; then
  sed -n '/---- .* stdout ----$/,$p' target/job-JOB_ID.log
else
  echo "log fetch failed: exit=$?"
fi
```

Run the `if` block once per failed job (`JOB_ID` is the `databaseId`
printed first). If the fetch failed, report its error verbatim as
`BLOCKED` for that job and don't read the file. Otherwise report the
test failure sections printed, complete. If nothing prints (build, lint or
setup failure), find the first error and report from there to the end:

```sh
grep -nE -m1 'error(\[E[0-9]+\])?:|FAILED|panicked' target/job-JOB_ID.log
sed -n 'LINE,$p' target/job-JOB_ID.log
```

`LINE` is the number `grep` printed; if it printed nothing, report the
whole file.

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
      nodes { isResolved comments(first: 100) { totalCount nodes { databaseId path line author { login } body } } }
    } } } }' \
  --jq '.data.repository.pullRequest.reviewThreads.nodes[] | select(.isResolved|not) | .comments'
```

For each unresolved thread copy the first comment's id, path, line and
"Prompt for AI Agents" section, plus every reply verbatim with its author.
If `totalCount` exceeds 100, say so in the report.

Review bodies hold outside-diff and nitpick items, which have no thread,
and maintainer requests. Read every review body from every author,
including `COMMENTED` ones:

```sh
gh api --paginate --slurp repos/OWNER/REPO/pulls/N/reviews | jq -r '.[][]
  | select(.body != "")
  | "=== " + .user.login + " " + .state + " " + .commit_id + "\n" + .body'
```

Report verbatim as open items every non-CodeRabbit review body and every
outside-diff or nitpick item in CodeRabbit bodies on any commit, even in an
`APPROVED` review; a later head does not settle them. They stay open until
the caller says they are settled.

Done when merge state is `CLEAN`, every check from the `--json` command in
[Waiting](#waiting) has finished in `pass` or `skipping`, no unresolved
threads, no open review-body items, and either:

- verdict `APPROVED` on the head, or
- CodeRabbit withheld approval ("Automatic approval withheld", merge risk)
  but its latest review on the head has no actionable comments and the
  `CodeRabbit` check shows `Review completed` (not skipped). Report this
  as `PASS` with the withheld reason quoted.

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
  | select(.body | test("rate limited|review limit (is currently )?reached"; "i"))]
  | sort_by(.updated_at) | .[] | "=== " + .updated_at + "\n"
  + ([.body | split("\n")[] | select(test("limit|available in|minute"; "i"))] | join("\n"))'
```

- Use only the newest limit message (printed last). If it says "rate
  limited", "Review limit reached" or "review limit is currently reached"
  with "available in M minutes", wait until its
  `updated_at` + M + 2 minutes. CodeRabbit edits the same comment, so
  `updated_at` is the anchor, not `created_at`.
- Without a stated time, wait until one hour after the last completed review.
  If that command prints `null` (no completed review), report `BLOCKED`
  with the limit message; don't guess a time.
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
  `gh pr checks N --json name,state,bucket,description,link --jq '.[] | select(.name == "CodeRabbit" or (.bucket != "pass" and .bucket != "skipping"))'`.
  `CodeRabbit` is always listed. Report a skipped `CodeRabbit` check with
  its raw `state` and `description` verbatim; don't infer the cause. A rate limit is confirmed
  only by a limit comment (see [Rate limits](#rate-limits)).
- CodeRabbit window (only if the caller asked for a review): one
  `sleep SECONDS` until the computed time, then re-read comments and post.
- CodeRabbit review after posting: it takes a few minutes; `sleep 600`, then
  run the verdict commands once.

Stop and report on: new review, new unresolved thread, check failure,
`PASS`, or limit hit again. If the step budget is nearly used up, report
`WAITING` with the next action and time instead of running out silently.
