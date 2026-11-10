# Local fixture cross-check — 2026-11-10

Local, black-box comparison of the 13 endpoints in
`tests/servers/compose.yaml`. This is not a compatibility promise, a full
vulnerability assessment, or evidence that an inconclusive probe is safe.

## Reproduction context

- Repository baseline: `2f61b5cb9d369ac6b0c7202f08507d33f04a25e4`, including
  merged ROBOT PR #159.
- Existing debug CLI: version `0.6.0`, SHA-256
  `4dbd242409545e198527e1b3593a5e84ead400d34a6319ca7ba5dc357bdfd2eb`.
  No rebuild or Cargo test invocation was used for this audit.
- macOS arm64, existing Podman fixtures; scans run sequentially against
  loopback, with `localhost` SNI and `tests/servers/ca.pem`.
- External comparator: testssl.sh `v3.2.5`, pinned upstream commit
  `4f17be931a9d60f3f987975aea8221f1a8eaf7aa`, using Homebrew OpenSSL `4.1.0`.
  Installed only in the approved temporary directory, not as a repository
  dependency. Its implementation and protocol/client data were not read or
  copied. This report uses independently written summaries, not its wording.
- No external revocation queries, scanner hostname lookups, client simulation,
  or grade comparison. Fixture-side reverse-DNS lookups are a separate local
  environment issue below. Optional comparator checks requiring unavailable
  dependencies are not treated as successful negative tests.

CLI template, with `--starttls PROTOCOL` added for upgraded connections:

```sh
./target/debug/testls --profile default --intrusive \
  --connect-timeout 3 --read-timeout 3 \
  --sni localhost --ca-file tests/servers/ca.pem \
  --color never --format json 127.0.0.1:PORT
```

External CLI template, run from its isolated checkout; `CA` is the absolute
fixture CA path and `RESULT` is outside this repository:

```sh
/bin/bash ./testssl.sh --warnings batch --color 0 --nodns none \
  --ip 127.0.0.1 --add-ca "$CA" --connect-timeout 3 --openssl-timeout 5 \
  --disable-rating -p -s -E -P -f -S -h -U -g \
  --jsonfile "$RESULT" localhost:PORT
```

Add `--starttls PROTOCOL` for upgraded connections and
`--xmpphost localhost` for XMPP. These select protocol, cipher, preference,
certificate, header and vulnerability checks without client simulation.
External tool exit codes are not interchangeable with testls exit codes;
inspect completed sections and warnings rather than assuming zero means safe.

## Results

Cipher comparisons use IANA suite identifiers, not displayed cipher names or
severity labels. TLS 1.0, 1.1, 1.2 and 1.3 columns below count accepted suites;
a dash means that version was not offered.

| Endpoint | Port / upgrade | TLS 1.0 | TLS 1.1 | TLS 1.2 | TLS 1.3 | Comparison |
| --- | --- | --- | --- | --- | --- | --- |
| Modern | 14434 / direct | — | — | 3 | 3 | Protocols and suite sets agree |
| Legacy | 14433 / direct | 16 | 16 | 56 | — | Protocols and suite sets agree |
| Heartbleed affected | 14435 / direct | — | — | 1 | — | Protocols and suite sets agree after local DNS workaround |
| Heartbleed patched / CCS affected | 14436 / direct | — | — | 1 | — | Protocols and suite sets agree after local DNS workaround |
| CCS patched | 14437 / direct | — | — | 1 | — | Protocols and suite sets agree after local DNS workaround |
| SMTP | 14425 / smtp | — | — | 56 | 3 | Protocols and suite sets agree after local DNS workaround |
| IMAP | 14143 / imap | — | — | 11 | 3 | Protocols and suite sets agree |
| POP3 | 14110 / pop3 | — | — | 11 | 3 | Protocols and suite sets agree |
| XMPP | 15222 / xmpp | — | — | 6 | 3 | Protocols and suite sets agree |
| LDAP | 14389 / ldap | — | — | 13 | 3 | Protocols and suite sets agree |
| PostgreSQL | 15432 / postgres | — | — | 40 | 3 | Protocols and suite sets agree |
| MySQL | 13306 / mysql | — | — | 20 | 3 | Protocols and suite sets agree; ROBOT interoperability gap below |
| FTP | 14021 / ftp | — | — | 1 | 3 | testls measurement only; comparator preflight failed |

All 13 endpoints were scanned with testls. Twelve completed comparator
protocol/suite sections agree exactly with testls; FTP remains incomplete.

Historical vulnerability controls behaved as expected:

| Port | Heartbleed in testls | CCS injection in testls | External comparison |
| --- | --- | --- | --- |
| 14435 | Critical finding | High finding | Both positive |
| 14436 | Not tested, no finding | High finding | Heartbleed negative; CCS positive |
| 14437 | Not tested, no finding | Not tested, no finding | Both negative |

ROBOT remained inconclusive on all three historical endpoints because the
RSA vectors produced no reproducible alert difference. They are not positive
ROBOT fixtures. Negative external results do not change that evidence limit.

The first pass could not scan the three historical OpenSSL endpoints
(14435–14437) or SMTP (14425) with either tool. Independent TCP/TLS checks
also stalled. The maintainer authorized restarting only those four
containers; the published ports still stalled on sequential retry. A TLS
handshake inside the Heartbleed container succeeded. An owned, loopback-only
SSH tunnel to the same containers did not fix the stall and was closed.
Its host key was obtained through the configured Podman connection and
pinned in a temporary known-hosts file; no global SSH configuration changed.
Historical TLS logs reported reverse-DNS failures, and resolving the local
bridge peer inside a container independently timed out. The maintainer
authorized temporary peer-name entries in only those four containers, with
original hosts files backed up outside the repository. Resolution worked with
those entries; all four sequential comparisons completed. The hosts files
were restored and verified byte-for-byte; the independent bridge lookup again
stalled after restoration. CLI scans dropped from about 18-second errors to
0.48–1.11-second completed reports. This local fixture reliability gap is
tracked in issue #163, not attributed to a scanner vulnerability verdict.

FTP (14021) completed with testls, but the comparator stopped at its STARTTLS
preflight. Independent `FEAT` and `AUTH TLS` exchanges showed the server
accepts the upgrade without listing it in `FEAT`; OpenSSL completed TLS 1.2
with the fixture CA. No cipher parity or negative vulnerability conclusion
is claimed for this incomplete comparator run. A documented `--ssl-native`
retry also stopped at preflight; that mode's accuracy warnings preclude
treating it as an equivalent comparison even if it had completed.

## Confirmed gaps and roadmap

1. [Issue #160](https://github.com/kjpopov/testls/issues/160): ROBOT rejects an
   otherwise usable static-RSA server flight containing an optional client
   certificate request. MariaDB on port 13306 repeatedly produced this
   inconclusive result. An independent TLS 1.2 `AES128-SHA` handshake showed
   the request, an empty client certificate and successful completion without
   client credentials. `robot.rs::flight` currently permits only ServerHello,
   Certificate and ServerHelloDone; the outgoing probe also lacks the empty
   client certificate needed for this flow. Support must preserve ordering,
   bounds and reproducible-alert requirements. This does **not** establish
   that MariaDB has a ROBOT oracle.
2. [Issue #161](https://github.com/kjpopov/testls/issues/161): no real positive
   ROBOT container fixture exists; positive coverage currently uses scripted
   peers. Candidate upstream wolfSSL `v3.12.2-stable` and `v3.13.0-stable`
   releases bracket CVE-2017-13099 according to the vendor. They have not been
   built or verified here. A fixture must demonstrate an observable oracle
   compatible with the probe's fatal-alert evidence before asserting a
   vulnerable verdict; an affected release alone is insufficient.
3. [Issue #162](https://github.com/kjpopov/testls/issues/162): DH measurement
   samples only one server-selected suite per version. The legacy endpoint
   repeatedly reports 2048-bit DH and a negative Logjam verdict in testls,
   with no `dh.weak` finding. Independent TLS 1.2 handshakes instead negotiate
   1024 bits for suite `0x0034`, 2048 bits for `0x0033`, and 3072 bits for
   `0x003a`. The 1024-bit result persists with and without offered FFDHE groups.
   Sampling all accepted suites together hides the weaker suite; incomplete
   parameter coverage must not support a global negative verdict. The known
   prime identity of the 1024-bit sample was not established here, and the
   endpoint's anonymous suites are already correctly reported as critical.
4. [Issue #163](https://github.com/kjpopov/testls/issues/163): historical TLS
   and SMTP fixtures can stall when local peer reverse DNS is unavailable.
   The independently verified workaround and restoration above isolate this
   environment problem. A durable fix should avoid unnecessary peer-name
   lookups without hard-coded VM addresses or global DNS changes.

All four items are linked in the [PLAN backlog](PLAN.md#backlog). No scanner
implementation or fixture image was changed during this audit.

## Differences not filed as defects

- `NotTested` remains inconclusive, even where the comparator reports a
  negative result. The intrusive checks intentionally require specific,
  reproducible evidence and do not prove absence of every oracle.
- Legacy anonymous suites, CBC and old protocols are already reported by
  testls. Different cipher-order and HTTP-header severities are policy
  differences, not missing measurements.
- The deliberately long-lived private fixture certificate has no external
  revocation endpoints. Public-PKI lifetime/revocation policy comparisons are
  not equivalent to this audit's private CA trust context.
- A CBC-based susceptibility warning is not an independently demonstrated
  timing attack. Missing external engines or `socat` leave dependent checks
  incomplete; they do not prove either vulnerability or safety.
- Certificate, HTTP and ticket full-handshake paths cannot complete against
  the historical fixtures offering only static RSA. Their error/inconclusive
  fields are consistent with the rustls full-handshake path's limited legacy
  coverage (PLAN architecture and decision #2), not silently successful tests.

## Primary references and local evidence

- [RFC 5246 §§7.4.4, 7.4.6 and 7.4.7](https://www.rfc-editor.org/rfc/rfc5246.html):
  server client-certificate requests, empty client certificates and
  ClientKeyExchange ordering.
- [RFC 5246 §7.4.3](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.3)
  and [RFC 7919 §§3–4](https://www.rfc-editor.org/rfc/rfc7919.html): finite-field
  DH parameters, group negotiation and custom-group handling.
- [wolfSSL security advisories](https://www.wolfssl.com/docs/security-vulnerabilities/)
  and [upstream fix #1229](https://github.com/wolfSSL/wolfssl/pull/1229):
  candidate historical ROBOT release boundaries, not fixture verification.
- Runner, command manifests and raw outputs are local-only under
  `testls-fixture-audit-20261110/` in the approved OpenCode temporary directory.
  Initial outputs are in `results/`, restart retries in `retry-results/`,
  temporary-tunnel comparisons in `tunnel-results/` with an explicit route
  manifest. Tunnel ports 24435–24437 and 24425 map to the original historical
  TLS and SMTP containers; do not confuse them with new fixtures.
  Completed workaround comparisons are in `dns-retry-results/`, with
  restoration recorded in `dns-hosts-restored.json`; `ftp-native-results/`
  records the unsuccessful native-mode retry. All owned tunnels are closed.
  TLS diagnostic logs can contain ephemeral secrets; do not publish them
  unredacted. GitHub issues contain only independently written reproductions.
