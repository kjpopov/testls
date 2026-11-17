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

Unresolved threads:

```sh
gh api graphql -f query='{repository(owner:"OWNER",name:"REPO"){pullRequest(number:N){reviewThreads(first:50){nodes{isResolved comments(first:1){nodes{databaseId path line body}}}}}}}' \
  --jq '.data.repository.pullRequest.reviewThreads.nodes[] | select(.isResolved|not) | .comments.nodes[0]'
```

Copy each unresolved comment's id, path, line and the "Prompt for AI Agents"
section verbatim. Also check review bodies for outside-diff and nitpick
items, which have no thread.

Done when: verdict `APPROVED` on `headRefOid`, no unresolved threads, merge
state `CLEAN`. Then report `result: PASS`; the caller merges.

## Rate limits

CodeRabbit's free plan allows few reviews per hour. Before posting
`@coderabbitai review`, read its newest issue comments:

```sh
gh api repos/OWNER/REPO/issues/N/comments \
  --jq '[.[] | select(.user.login=="coderabbitai[bot]")] | .[-3:][] | .created_at + " " + (.body[:300])'
```

- If one says "rate limited" or "Review limit reached" with "available in M
  minutes", wait until its `created_at` + M + 2 minutes. Never post while
  limited.
- Without a stated time, wait until one hour after the last completed review.
- Post `@coderabbitai review` at most once per window
  (`gh pr comment N -b "@coderabbitai review"`). If limited again, wait once
  more, then report `BLOCKED` with the limit message.

## Waiting loop

Repeat snapshot + verdict with `sleep 240` between rounds (tool timeout about
320 s). Stop and report on: new review, new unresolved thread, check failure,
`PASS`, or after the number of rounds the caller set (default 6).
