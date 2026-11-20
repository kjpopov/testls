# Agent workflow

How AI agents run the PR loop on `testls` with the `gh` CLI and CodeRabbit.
Only follow this when the maintainer has allowed `gh` for the session;
otherwise push branches and stop (see [AGENTS.md](../AGENTS.md)).

## Loop per roadmap item

1. If the roadmap item leaves design choices open, ask the maintainer
   before coding and record the answers in the PLAN decision log.
2. Branch from an up-to-date `main` (`git checkout main && git pull --ff-only`).
3. Split the item into small PRs, usually **wire/data → probe → checks →
   report/CLI** (docs, `docs/json-schema.md`, `CHANGELOG.md`, PLAN checkbox and
   decision log go into the last PR).
4. Before pushing: rebase on fresh `main`, then run everything in AGENTS.md
   "Before you push", plus integration tests for scanner changes, and a
   local CodeRabbit review if the CLI is set up
   ([testls-local-review](../.agents/skills/testls-local-review/SKILL.md)).
   Recheck the last PLAN decision number; if another PR took yours,
   renumber to the next free one (and fix references) before merging.
5. `git push -u origin BRANCH`, then
   `gh pr create --base main --title "area: subject" --body "..."`.
6. Wait for CI and CodeRabbit (5-10 min), fix comments, repeat. One review
   round = one fix commit (see "Answering comments").
7. Merge when green and CodeRabbit is happy (see below):
   `gh pr merge N --merge --delete-branch`, then pull `main`.

Stacked branches: open the PR for the next layer only after the lower one is
merged, then `git rebase origin/main` (or `git rebase --onto origin/main OLD`)
so the PR always targets `main`. CodeRabbit auto-reviews only PRs whose base
is `main`; never target another feature branch (an earlier PR got merged into
its parent branch by mistake).

## Checking status

```sh
gh pr checks N                      # CodeRabbit row: pending -> "Review completed"
gh pr view N --json mergeStateStatus --jq .mergeStateStatus   # CLEAN = ready
```

Reviews, including **outside-diff and nitpick comments, which appear only in
the review body**, and reviews by the maintainer:

```sh
gh api repos/kjpopov/testls/pulls/N/reviews --jq '.[]
  | select(.user.login != "kjpopov" or (.body | length) > 0)
  | .user.login + " " + .commit_id[:7] + " "
    + (.body | capture("Actionable comments posted: (?<n>[0-9]+)").n // "none")
    + " " + (.body | test("Outside diff|Nitpick") | tostring)'
gh api repos/kjpopov/testls/pulls/N/reviews/ID --jq .body   # read one body
```

Inline comments (save to a file, then `jq`, to avoid shell quoting issues):

```sh
mkdir -p target
gh api repos/kjpopov/testls/pulls/N/comments > target/prN.json
jq -r '.[] | (.id|tostring) + " " + .path + ":" + (.line|tostring)' target/prN.json
```

CodeRabbit is happy when either:

- its latest verdict (last non-`COMMENTED` review) is `APPROVED`, its
  `commit_id` equals `headRefOid`, and the merge state is `CLEAN`:

  ```sh
  gh pr view N --json headRefOid,mergeStateStatus
  gh api --paginate --slurp repos/kjpopov/testls/pulls/N/reviews | jq -r '[.[][]
    | select(.user.login == "coderabbitai[bot]" and .state != "COMMENTED")]
    | last | .state + " " + .commit_id'
  ```

- or, when it withholds approval (merge risk above `low`, see
  `.coderabbit.yaml`, or an explained pre-merge check failure), the latest commit's review has no actionable comments,
  all CodeRabbit threads are resolved, `gh pr checks` shows "Review
  completed" and the merge state is `CLEAN`;
  mention the risk to the maintainer.

Auto-approval also needs resolved threads and passing pre-merge checks
(title, changelog, JSON schema, docstrings; listed in the summary comment).
They are in warning mode, so GitHub never blocks on them, but a failing one
may withhold approval. Fix it if you can; if you explain it in a PR comment
instead, the PR may merge without approval under the second rule above, and
you must point the maintainer to the explanation. Always read every
review body before merging: a maintainer `TODO` review was once missed.

## Answering comments

- Collect every comment of a round (inline, outside-diff, nitpick) first,
  then push **all fixes in one commit**: each push triggers a review and the
  plan allows 10 reviews per hour. Each inline comment has a "Prompt for AI
  Agents" section; use it as the fix spec, but verify against the code.
- Fix in a new commit (don't force-push over reviewed commits), then reply:
  `gh api repos/kjpopov/testls/pulls/N/comments/ID/replies -f body="Fixed in abc1234: ..."`.
- Outside-diff/nitpick items have no thread: answer with `gh pr comment N -b "..."`.
- Declining is fine with a reason (RFC citation, scope); CodeRabbit usually
  accepts, resolves the thread and stores a learning so it won't ask again.
- CodeRabbit resolves threads after a fix reply. Leftovers:
  `gh api graphql -f query='{repository(owner:"kjpopov",name:"testls"){pullRequest(number:N){reviewThreads(first:50){nodes{id isResolved}}}}}'`
  then `gh api graphql -f query='mutation{resolveReviewThread(input:{threadId:"ID"}){thread{isResolved}}}'`.
- If CodeRabbit pauses or skips: `gh pr comment N -b "@coderabbitai review"`.
- To preview `.coderabbit.yaml` changes, mark the PR as draft
  (`gh pr ready N --undo`) and comment `@coderabbitai review --preview-config`.
  Keep it draft until CodeRabbit posts the preview, then `gh pr ready N`.

## Waiting

Use `sleep 240` with a tool timeout of 300000 ms; longer sleeps hit the
timeout. Work on the next branch while a review runs.

## Releases

1. Release PR `chore/release-X.Y.Z`: version in `Cargo.toml` (workspace and
   internal `=X.Y.Z` deps), `cargo update -w --offline`, `fuzz/Cargo.lock`,
   `CHANGELOG.md` section with date and compare links, version in the
   examples of `README.md`, `docs/install.md` and `docs/github-action.md`,
   PLAN "Released as vX.Y.Z".
2. After merge: `git tag -a vX.Y.Z -m "testls vX.Y.Z" MERGE_SHA && git push origin vX.Y.Z`.
3. `release.yml` builds five targets, publishes the GitHub release and pushes
   the container image to `ghcr.io/kjpopov/testls` (after the first push the
   maintainer makes the package public in its settings, once); check
   with `gh run list --workflow release.yml` and `gh release view vX.Y.Z`.
4. Its `crates-io` job then publishes the workspace with crates.io trusted
   publishing. Maintainer setup, once: publish the first version by hand
   (`cargo publish --workspace`), add trusted publishing for
   `kjpopov/testls`, workflow `release.yml`, environment `crates-io` to
   every `testls*` crate on crates.io, create that GitHub environment, and
   set the repository variable `CRATES_IO_TRUSTED_PUBLISHING=true` (not an
   environment variable: the job's `if:` runs before the environment
   applies). Until then the job is skipped. If it fails halfway, rerun it: crates already
   published at that version are skipped. Agents never publish to crates.io.
5. Packages PR `chore/packages-X.Y.Z` once the release exists:
   `gh release download vX.Y.Z -p SHA256SUMS -O target/SHA256SUMS` and
   `python3 scripts/gen-packages.py target/SHA256SUMS` update `Formula/`,
   `bucket/` and `packaging/winget/`. After merge, tell the maintainer to
   submit `packaging/winget/X.Y.Z/` to `microsoft/winget-pkgs` (for example
   with `wingetcreate submit`), unless [HANDOFF.md](HANDOFF.md) says winget
   is postponed.
6. Marketplace: the maintainer edits the GitHub release and ticks "Publish
   this Action to the GitHub Marketplace". GitHub checks `action.yml` at the
   tag, and its `name` must be unique across actions, users and
   organizations (`testls` is taken). The Marketplace page shows the root
   `README.md`, so it leads with the action and links to
   `docs/github-action.md`. Publish on the release the workflow created;
   creating a new release in the web UI makes a new tag (v0.4.2 that way
   had no build).

## Things learned the hard way

- OCSP fixtures are gitignored: run `scripts/gen-ocsp-fixtures.sh` after a
  fresh checkout or `cargo test` fails in `testls-checks`.
- Check `git branch --show-current` before committing when juggling stacked
  branches.
- Run the MSRV check from AGENTS.md; it needs `rustup` (setup in
  [HANDOFF.md](HANDOFF.md)). Without it `cargo +1.97` fails; say so in the PR
  and rely on the CI `msrv` job.
- clippy `too_many_lines` (100) bites `main.rs` and long JSON test
  fixtures; extract helpers or compact expected JSON.
- The test servers' CA key was discarded; certificates needing a CA we
  control are generated by scripts or committed as static fixtures.
- CodeRabbit posts a `COMMENTED` review, then a separate `APPROVED` one
  for the same commit; when approval is expected, wait for both before
  judging a round. If approval is withheld (risk above `low` or a failed
  pre-merge check), use the second rule under "Checking status".
- Approved rounds can still carry "Outside diff range" comments in the
  review body; they have no thread, so only reading the body finds them.
- `@coderabbitai review --preview-config` on a non-draft PR does nothing;
  a config on the PR branch is applied anyway ("Layers: Repository YAML").
- Mention clean-room sources (RFC/IANA section) in every new data table or
  check.
- CodeRabbit can set `CHANGES_REQUESTED` for a single Minor comment; a
  later `APPROVED` review on the head commit replaces it.
- The single-comment endpoint is `repos/OWNER/REPO/pulls/comments/ID`,
  without the PR number.
- CodeRabbit can withhold approval citing a concern it already withdrew
  or accepted in a thread; the "Automatic approval withheld" note is not
  updated. Resolve the thread, explain in a PR comment and use the second
  rule under "Checking status".
