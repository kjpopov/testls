# Fixtures and integration tests

Run from the repository root of the branch the caller named. Services and
ports are defined in `tests/servers/compose.yaml`; `tests/servers/README.md`
explains each one.

## Start

Start only the services the caller lists (all builds take minutes):

```sh
podman compose -f tests/servers/compose.yaml up -d --build SERVICE...
podman compose -f tests/servers/compose.yaml ps
```

Without service names everything starts. Report any service not `Up`, with
`podman compose -f tests/servers/compose.yaml logs --tail 30 SERVICE`.

## Run ignored tests

Tests that need servers are `#[ignore]` in `crates/testls/tests/servers.rs`.
Pass the caller's name filters (substring match, several allowed):

Use a log of your own; other agents may run tests in the same checkout:

```sh
log=target/servers-test-$$.log
cargo test -p testls --test servers -- --ignored FILTER... > "$log" 2>&1
echo "exit=$? log=$log"
grep -E "^test |test result|panicked|FAILED" "$log"
```

Example filters: `robot_wolfssl heartbleed ccs_injection`. All of them:
drop the filters.

`PASS` needs `exit=0` and, for every filter, at least one `test ... ok`
line whose name contains it. A filter that matched no test (typo, renamed
test) is `FAIL` even with `exit=0`; name it. If the exit is non-zero and
`grep` shows no failing test, it is a build or setup error: report
`tail -40 "$log"`. For a failing test, report its `panicked at` line plus
the assertion message from the log.

If OCSP fixtures are missing, run `scripts/gen-ocsp-fixtures.sh` once, then
retry.

## Stop

Only when the caller asks; another agent may use the same containers:

```sh
podman compose -f tests/servers/compose.yaml down
```
