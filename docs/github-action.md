# testls GitHub Action

Scan your TLS endpoints in a GitHub Actions workflow and fail the job when
the configuration gets worse. The action downloads a `testls` release,
checks it against the release's `SHA256SUMS`, puts it on `PATH` and
optionally runs it.

Runs on GitHub-hosted and self-hosted runners: Linux (x64, ARM64), macOS
(x64, ARM64) and Windows (x64). It needs network access to github.com and
to the hosts you scan. GitHub-hosted runners have every tool it uses;
self-hosted runners need `bash`, `curl`, `awk`, `cut`, `gh` (only for
`version: latest`), `sha256sum` (`shasum` on macOS), and `tar` (`7z` on
Windows).

## Quick start

```yaml
name: TLS
on:
  schedule:
    - cron: "0 6 * * 1"   # every Monday
  workflow_dispatch:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: kjpopov/testls@v0.6.0
        with:
          args: --fail-on medium example.com
```

The job fails (exit status 1) when a finding is `medium` or worse, and
when the scan itself fails (exit status 2).

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `args` | empty | Arguments for `testls`, split on whitespace. No quoting or globbing. Empty installs `testls` only. |
| `version` | `latest` | Release to install, such as `v0.6.0`. |
| `token` | `github.token` | Token used to look up the latest release. |

## Outputs

| Output | Description |
| --- | --- |
| `version` | Installed release, such as `v0.6.0`. |

## Pin the version

`uses: kjpopov/testls@v0.6.0` runs the action from that tag but, with
`version: latest`, installs the newest scanner. For reproducible runs, pin
both, ideally the action to its commit SHA:

```yaml
- uses: kjpopov/testls@<commit-sha> # v0.6.0
  with:
    version: v0.6.0
    args: --fail-on medium example.com
```

Tags are annotated; the commit SHA is on the `^{}` line of
`git ls-remote https://github.com/kjpopov/testls 'refs/tags/v0.6.0*'`.
Dependabot updates both the SHA and the comment.

## Examples

### Code scanning alerts (SARIF)

Findings appear under **Security → Code scanning** and in pull requests.

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: kjpopov/testls@v0.6.0
      - run: testls --format sarif --fail-on critical example.com > testls.sarif
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: testls.sarif
          category: testls
```

Use the action without `args` and run `testls` yourself whenever you need a
redirect, quoting or several commands.

### Job summary

```yaml
- uses: kjpopov/testls@v0.6.0
- run: testls --format markdown --fail-on medium example.com >> "$GITHUB_STEP_SUMMARY"
```

### Test report (JUnit)

```yaml
- uses: kjpopov/testls@v0.6.0
- run: testls --format junit --fail-on medium example.com > testls.xml
- uses: actions/upload-artifact@v7
  if: always()
  with:
    name: testls-junit
    path: testls.xml
```

Any JUnit viewer (test reporter actions, GitLab, Jenkins) can show one test
case per finding and one failure per finding at or above `--fail-on`.

### Many hosts

Keep the targets in the repository, one per line (`host`, `host:port`,
IP address or CIDR range):

```yaml
- uses: actions/checkout@v7
  with:
    persist-credentials: false
- uses: kjpopov/testls@v0.6.0
  with:
    args: --fail-on high --file hosts.txt
```

### Compliance policy

```yaml
- uses: kjpopov/testls@v0.6.0
  with:
    args: --policy mozilla-intermediate --fail-on medium example.com
```

Policies: `mozilla-modern`, `mozilla-intermediate`, `nist-800-52r2`,
`bsi-tr-02102-2`, `pci-dss-4`, `cnsa-2.0`.

### Accept known findings

Check out the repository so `testls` finds `.testls.toml` in the working
directory. Suppressed findings are still listed but do not fail the job,
and come back after `expires`:

```toml
[[suppress]]
id = "cookie.insecure"
target = "example.com"       # optional, default: every target
reason = "legacy app, replaced in Q1"
expires = 2026-12-31         # optional
```

To fail only on new findings, commit a JSON report and pass it with
`--baseline`:

```sh
testls --format json example.com > baseline.json
```

```yaml
- uses: actions/checkout@v7
  with:
    persist-credentials: false
- uses: kjpopov/testls@v0.6.0
  with:
    args: --baseline baseline.json --fail-on low example.com
```

### Internal hosts

Runners on your network can scan private servers. Trust your CA, pin the
address or go through a proxy. Check out the repository so the CA file
exists:

```yaml
- uses: actions/checkout@v7
  with:
    persist-credentials: false
- uses: kjpopov/testls@v0.6.0
  with:
    args: --ca-file certs/internal-ca.pem --resolve app.internal:443:10.0.0.5 app.internal
```

## More

- All options: `testls --help`, or [usage](usage.md).
- What a finding means: `testls explain FINDING-ID`.
- JSON report format: [json-schema.md](json-schema.md).

Only scan systems you own or are authorized to test.
