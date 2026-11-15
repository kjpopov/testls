# Repeatable local fixture audits

Run a standardized black-box comparison without changing services, installing
tools, or publishing issues. The Python 3.11+ runner needs only the standard
library and works on macOS/Linux. It is separate from the Rust scanner and
normal CI. Vulnerable fixtures must remain loopback-only.

## Prepare once, explicitly

1. Build the CLI and start the existing fixtures yourself when needed:

   ```sh
   cargo build -p testls --locked
   podman compose -f tests/servers/compose.yaml up -d --build
   ```

   The runner never builds, starts, restarts, stops, or edits containers. It
   does not apply the temporary DNS workaround used in the original audit.
   If fixtures stall, resolve their health separately; see issue
   [#163](https://github.com/kjpopov/testls/issues/163).

2. Keep the external comparator in a separate checkout, outside this
   repository. Obtain the exact release in `tests/servers/audit.json`:

   ```sh
   git clone --depth 1 --branch v3.2.5 \
     https://github.com/testssl/testssl.sh.git "$HOME/testssl-audit"
   git -C "$HOME/testssl-audit" rev-parse HEAD
   ```

   Expected revision: `4f17be931a9d60f3f987975aea8221f1a8eaf7aa`.
   The runner rejects mismatched revisions and dirty/untracked checkout
   content. It does not inspect or import comparator implementation, tables
   or client data; it hashes the entry script and uses public CLI/JSON fields.
   No comparator files become repository dependencies.

3. Choose an existing OpenSSL binary explicitly. Record its version with
   each run; tool availability and optional engines affect coverage.

## Plan and run

Preview the fixture manifest and commands without invoking any scanner or
requiring tools/containers to exist:

```sh
python3 scripts/audit-fixtures.py plan \
  --testssl-dir "$HOME/testssl-audit" --openssl /opt/homebrew/bin/openssl
```

Run every fixture sequentially, using the already-built CLI:

```sh
python3 scripts/audit-fixtures.py run \
  --testssl-dir "$HOME/testssl-audit" --openssl /opt/homebrew/bin/openssl \
  --output target/fixture-audits/run-001
```

On Linux, use the actual OpenSSL path, for example `/usr/bin/openssl`.
Use `--testls /path/to/testls` to select another existing CLI. A new output
directory is required: previous evidence is never overwritten. Select a
subset with repeated `--fixture` options:

```sh
python3 scripts/audit-fixtures.py run \
  --testssl-dir "$HOME/testssl-audit" --openssl /opt/homebrew/bin/openssl \
  --fixture modern --fixture mysql --output target/fixture-audits/run-002
```

The manifest fixes ports, STARTTLS modes, expected protocols and historical
Heartbleed/CCS controls. Targets cannot be changed to remote hosts. Both tools
use loopback, `localhost` SNI and the fixture CA. The testls default profile
plus explicit `--intrusive` covers the intrusive probes without external
revocation fetches. Comparator DNS, grading and client simulation are excluded.
No independent handshake containing ephemeral secrets is captured automatically.

Per-process budgets default to 600 seconds for testls and 900 seconds for the
comparator; override with `--testls-budget` and `--comparator-budget` (1–3600).
Timeouts and Ctrl-C stop only owned scanner process groups. There are no
automatic retries, DNS edits or recovery restarts. An unavailable tool or
wrong comparator revision fails before scanning.

## Evidence and interpretation

Each run writes private local artifacts (directory mode 0700, files created
under umask 077):

- `summary.json`: schema-v1 report, exact commands, return codes, durations,
  normalized measurements, selected fixture controls and provenance. Includes
  repository revision/dirty state, manifest and CA hashes, comparator revision
  and entry-script hash, binary hashes/versions and process budgets.
- `summary.md`: per-fixture result, candidate differences, incomplete sections
  and explicit vulnerability-scope notes.
- `NAME.testls.json`, `NAME.testssl.json`: original local scanner outputs.
  Stdout and stderr are separate; warnings cannot corrupt testls JSON.
- `NAME.issue-draft.md`: **unconfirmed**, review-only reproduction/checklist for
  differences or incomplete measurements. No GitHub API calls are made.

Reports are checkpointed after each scanner pair; interruption retains earlier
results and marks the run unfinished. Raw logs can contain sensitive data:
review/redact them before sharing, and keep outputs outside version control.

Runner exit codes are separate from the scanner's finding threshold:

| Code | Meaning |
| --- | --- |
| 0 | Measured protocol/suite sets and declared controls agree |
| 1 | Candidate disagreement requiring review |
| 2 | Incomplete, interrupted or invalid run; may also contain disagreements |

testls exit 1 is valid measurement output, not a process error. The comparator
has a different exit-code contract: usable protocol/cipher sections can survive
optional-dependency warnings. Missing/failed sections and malformed output are
not interpreted as empty sets or successful negatives. JSON shape, duplicate
measurements and numeric suite identifiers are checked; unfamiliar output is
inconclusive. Only the pinned flat JSON format is supported.

Suites are compared by numeric IANA identifiers, not names, severity labels,
grades or ordering. Known fixture controls also catch both tools agreeing on
an unexpected server configuration. A patched `no_positive` control accepts
`not tested` without calling it safe. A positive control that is `not tested`
is incomplete. Generic `not tested` or missing vulnerability results remain
scope notes, not negative verdicts; protocol/suite agreement does not imply a
complete vulnerability assessment. FTP comparator preflight may still fail
despite a usable testls scan. No real positive ROBOT fixture exists yet (#161).

## Review and maintenance

1. Check environment failures first: healthy fixtures, service readiness,
   reverse DNS, tool versions and missing comparator dependencies.
2. Repeat the affected fixture sequentially. Reproduce candidate scanner gaps
   with an independent handshake and primary RFC/IANA evidence.
3. Separate scope/policy differences, comparator limitations and expected
   vulnerable fixtures from actual scanner defects. Neither tool is ground truth.
4. Search existing GitHub issues. Only confirmed gaps get a published issue
   and a linked `docs/PLAN.md` item; draft files are not automatically filed.
5. When fixtures change, update their manifest controls and rerun the audit.
   When upgrading the comparator, update tag/revision together, verify its
   public output adapter and add independently constructed parser tests.

Run the automation's tests without tools, containers or network access:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -v
```

The [original local audit PR](https://github.com/kjpopov/testls/pull/164) records known gaps #160–#163
and its environment-specific workaround. Keep that historical evidence separate
from new runs. The clean-room rule still forbids copying external implementation,
cipher tables, client-simulation data or wording into testls.
