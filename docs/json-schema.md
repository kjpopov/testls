# JSON report schema

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:2db999b6a6ba266d2bd0150f06a88ea6b652362028fce7d5be8d6ef6ca5ca95b -->

`testls --format json` prints one JSON document to stdout when the scan
finishes. With several targets it prints a JSON array holding one document
per target, in scan order. This page describes schema version **2**. Version 2 changes `dh_bits` from one selected suite to the smallest measured prime; version 1 baseline files must be regenerated.

<!-- /coderabbit-ai-generated:v1 -->

## Stability

- `schema_version` changes when a field is removed, renamed, or changes
  meaning or type.
- New fields may be added without a version bump. Consumers should ignore
  fields they do not know.
- Finding `id`s are stable. New ids may appear in any release;
  `testls explain <id>` describes each one.
- Scan errors (exit code 2) print a message to stderr and no JSON. With
  several targets, a target whose scan fails is left out of the array and
  the others are still reported.
- With `--profile quick`, `key_exchange` is empty, `post_quantum` is
  `"not tested"`, and `http`, `intolerance` and `details` carry the error
  `"skipped by --profile quick"`.
- The exit code is the same as for text output (see `--fail-on`); with
  several targets the worst one wins (2 over 1 over 0).

## Document

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:ba97129952f29742d631daedb93a6bf3921f0949ca1a1164ef2c3cbba59120f9 -->

| Field | Type | Description |
| --- | --- | --- |
| `schema_version` | integer | Schema version, currently `2` |
| `tool.name` | string | Always `"testls"` |
| `tool.version` | string | testls version |
| `target.input` | string | Target as given on the command line |
| `target.address` | string | Socket address that was scanned, e.g. `"192.0.2.1:443"` or `"[2001:db8::1]:443"` |
| `target.sni` | string or null | SNI name sent, `null` if none |
| `started_at` | integer | Scan start, Unix time in seconds |
| `protocols` | array | One [protocol](#protocol) per probed version, oldest first |
| `ciphers` | array | One [cipher list](#cipher-list) per offered version |
| `key_exchange` | array | One [key exchange](#key-exchange) per offered version |
| `post_quantum` | object | [Post-quantum readiness](#post-quantum-readiness) of TLSv1.3 |
| `certificate` | object | The [certificate chain](#certificate-chain) |
| `http` | object | [HTTP headers](#http-headers) of the reply to `GET /` |
| `revocation` | object or null | [Revocation](#revocation) check with `--revocation`; `null` without it |
| `vulnerabilities` | array | [Vulnerabilities](#vulnerability) derived from the scan data |
| `intolerance` | object | [ClientHello tolerance](#clienthello-tolerance) tests |
| `details` | object | [Handshake details](#handshake-details) |
| `grade` | object | Overall [grade](#grade) |
| `findings` | array | [Findings](#finding), most severe first |
| `suppressed` | array | [Suppressed findings](#suppressed-finding) from `.testls.toml` or `--baseline`, most severe first |

<!-- /coderabbit-ai-generated:v1 -->

### Protocol

| Field | Type | Description |
| --- | --- | --- |
| `version` | string | `"SSLv2"`, `"SSLv3"`, `"TLSv1.0"`, `"TLSv1.1"`, `"TLSv1.2"`, or `"TLSv1.3"` |
| `status` | string | `"offered"`, `"not_offered"`, or `"error"` |
| `error` | string | Only when `status` is `"error"` |

### Cipher list

| Field | Type | Description |
| --- | --- | --- |
| `protocol` | string | Protocol version, as above |
| `order` | string or null | `"server"` or `"client"` preference; `null` if fewer than two suites were accepted or enumeration failed |
| `suites` | array | Suites in the server's order of choice |
| `suites[].id` | string | Hex code point: `"0xc02f"`, or six digits for SSLv2 cipher specs (`"0x010080"`) |
| `suites[].name` | string | IANA name |
| `suites[].severity` | string | Severity of the suite, see [Finding](#finding) |
| `error` | string | Only when enumeration failed; `suites` is then empty |

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:e08d2b44b9db6caeb8a3e0b4b916a9df67f50e98a39804776be5f1faa6c400fd -->

### Key exchange

| Field | Type | Description |
| --- | --- | --- |
| `protocol` | string | Protocol version, as above |
| `group_order` | string or null | `"server"` or `"client"`; null if fewer than two groups or the probe failed |
| `groups` | array | Supported named groups, with `id`, `name` and `severity` |
| `dh_bits` | integer or null | Smallest measured finite-field DH prime size; null if none measured |
| `dh_suites` | array | One entry per accepted DHE or anonymous DH suite, including unmeasured DHE-PSK |
| `dh_suites[].suite` | string | IANA cipher code point, e.g. `"0x0034"` |
| `dh_suites[].bits` | integer or null | Prime size; null if unmeasured |
| `dh_suites[].prime` | string or null | Prime in big-endian hexadecimal; null if unmeasured |
| `dh_suites[].key_reused` | boolean or null | Reuse across two handshakes with the same suite, prime and generator; null if incomparable or unmeasured |
| `error` | string | Only when the overall probe failed; `groups` and `dh_suites` are then empty |



<!-- /coderabbit-ai-generated:v1 -->

### Post-quantum readiness

| Field | Type | Description |
| --- | --- | --- |
| `status` | string | `"ready"` (an ML-KEM group), `"draft only"` (only obsolete draft Kyber code points), `"not ready"`, or `"not tested"` (no TLSv1.3 groups measured) |
| `groups` | array | Accepted ML-KEM groups (pure or hybrid), same fields as `key_exchange[].groups` |
| `draft_groups` | array | Accepted draft Kyber code points, same fields |
| `preferred` | bool or null | Server picks an ML-KEM group over every classical group; `null` without a server group order or ML-KEM group |

### Certificate chain

| Field | Type | Description |
| --- | --- | --- |
| `protocol` | string or null | Version of the handshake that fetched the chain; `null` on error |
| `chain` | array | Certificates as sent by the server, leaf first |
| `chain[].subject` | string | Subject distinguished name |
| `chain[].issuer` | string | Issuer distinguished name |
| `chain[].not_before` | integer | Start of validity, Unix time |
| `chain[].not_after` | integer | End of validity, Unix time |
| `chain[].names` | array of strings | DNS names and IP addresses from the subject alternative names |
| `chain[].key` | string | Key algorithm and size, e.g. `"RSA 2048 bits"` |
| `chain[].scts` | integer | Number of embedded Certificate Transparency timestamps; absent when the SCT list cannot be read |
| `chain[].error` | string | Only for a certificate that cannot be parsed; the other fields are then absent |
| `ocsp` | object or null | Stapled OCSP response for the leaf; `null` on error |
| `ocsp.stapled` | boolean | The server stapled a response |
| `ocsp.status` | string or null | `good`, `revoked`, `unknown`, or `invalid`; `null` when not stapled |
| `ocsp.produced_at` | integer | When the response was signed, Unix time; only for a verified response |
| `ocsp.this_update` | integer | Start of the validity interval, Unix time; only for a verified response |
| `ocsp.next_update` | integer | End of the validity interval, Unix time; absent when the responder gave none |
| `ocsp.revocation_time` | integer | Only when `revoked`: revocation time, Unix time |
| `ocsp.revocation_reason` | string | Only when `revoked` with a reason: RFC 5280 `CRLReason` name, e.g. `"keyCompromise"` |
| `ocsp.error` | string | Only when `invalid`: why the response failed to parse or verify |
| `error` | string | Only when the chain could not be retrieved; `chain` is then empty |

### HTTP headers

One `GET /` request is sent over a full handshake; redirects are not followed.
It offers `Accept-Encoding: gzip, deflate, br, zstd` like a browser, so the
`breach` verdict can see whether the reply is compressed.

| Field | Type | Description |
| --- | --- | --- |
| `status` | integer or null | HTTP status code; `null` on error |
| `headers` | object | Each security header by lowercase name (`strict-transport-security`, `content-security-policy`, `x-frame-options`, `x-content-type-options`, `referrer-policy`), first value or `null` when not set; empty on error |
| `hsts` | object or null | Parsed `Strict-Transport-Security` policy from the first header; `null` when missing or invalid |
| `hsts.max_age` | integer | `max-age` in seconds |
| `hsts.include_subdomains` | boolean | `includeSubDomains` is present |
| `hsts.preload` | boolean | `preload` is present |
| `hsts.preload_eligible` | boolean | `max-age` is at least one year and both `includeSubDomains` and `preload` are present |
| `banners` | object | Arrays of `server` and `x-powered-by` values by lowercase name, one entry per field value in order, control characters replaced by `?`; only headers that are set |
| `alt_svc` | array or null | Alternative services from all `Alt-Svc` headers in order (RFC 7838), empty when missing or `clear`; `null` when malformed or on error |
| `alt_svc[].protocol` | string | ALPN protocol id, e.g. `h3` |
| `alt_svc[].authority` | string | Alternative authority, e.g. `:443` |
| `alt_svc[].max_age` | integer | Freshness lifetime in seconds (`ma`, default 86400) |
| `cookies` | array | One entry per `Set-Cookie` header with a `name=value` pair |
| `cookies[].name` | string | Cookie name |
| `cookies[].secure` | boolean | `Secure` is present |
| `cookies[].http_only` | boolean | `HttpOnly` is present |
| `cookies[].same_site` | string or null | `SameSite` value, `null` when absent |
| `error` | string | Only when the headers could not be fetched, e.g. the server does not speak HTTP |

### Revocation

Only with `--revocation`: the OCSP responders named in the leaf certificate
are queried first, then its CRLs are downloaded, until one gives a verifiable
answer. Only `http://` URLs are used. Non-public addresses are refused
unless `--revocation-allow-private` is given; such attempts have the error
`non-public address refused`.

| Field | Type | Description |
| --- | --- | --- |
| `checks` | array | Each attempt in the order made; empty when the certificate names no HTTP OCSP responder or CRL |
| `checks[].method` | string | `ocsp` or `crl` |
| `checks[].url` | string | URL that was queried |
| `checks[].status` | string | `good`, `revoked`, `unknown`, or `error` |
| `checks[].this_update` | integer | Start of the validity interval, Unix time; absent on error |
| `checks[].next_update` | integer | End of the validity interval, Unix time; absent when none was given |
| `checks[].revocation_time` | integer | Only when `revoked`: revocation time, Unix time |
| `checks[].revocation_reason` | string | Only when `revoked` with a reason: RFC 5280 `CRLReason` name |
| `checks[].error` | string | Only on `error`: why fetching or verification failed |
| `error` | string | Only when no check could be made, e.g. the chain could not be retrieved |

### Vulnerability

Named vulnerabilities judged from the protocols, cipher suites, key exchange,
handshake features, HTTP headers and HTTP upgrade replies the scan collected; no
attack traffic is sent. Always the same fifteen entries in a fixed order.

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | Stable id: `poodle`, `beast`, `sweet32`, `rc4`, `freak`, `logjam`, `drown`, `crime`, `renegotiation`, `fallback_scsv`, `no_forward_secrecy`, `raccoon`, `breach`, `alpaca`, `opossum` |
| `name` | string | Display name, e.g. `"POODLE"` |
| `status` | string | `"vulnerable"`, `"not vulnerable"`, or `"not tested"` |
| `detail` | string | Short reason for the verdict; wording may change |
| `finding` | string or null | Only when `vulnerable`: id of the [finding](#finding) that reports it |

### ClientHello tolerance

Unusual but valid ClientHellos sent at the best offered version. Each test
is `"tolerated"`, `"rejected"`, or `null` when not tested (no usable
version, the plain handshake failed, or the server was unreachable).

| Field | Type | Description |
| --- | --- | --- |
| `protocol` | string or null | Version the tests used, e.g. `"TLSv1.3"` |
| `tests.unknown_version` | string or null | A future version (0x0305) is offered |
| `tests.unknown_extension` | string or null | An unassigned extension type is added |
| `tests.grease` | string or null | GREASE values (RFC 8701) in suites, extensions, groups, signature algorithms and versions |
| `tests.oversized` | string or null | The handshake message fills a whole 16 KiB record |
| `tests.fragmented` | string or null | The ClientHello is split across 16-byte records |
| `error` | string | Only when the probe failed |

### Handshake details

Each field is `null` when not tested.

| Field | Type | Description |
| --- | --- | --- |
| `protocol` | string or null | TLSv1.2-or-older version used for the next two fields |
| `extended_master_secret` | bool or null | Server negotiates the extended master secret (RFC 7627) |
| `downgrade_sentinel` | bool or null | Only when TLSv1.3 is offered: the older-version ServerHello carries the downgrade sentinel (RFC 8446 §4.1.3) |
| `session_tickets` | bool or null | Server issues TLSv1.3 session tickets |
| `max_early_data` | integer or null | Largest 0-RTT early data size in a ticket; `0` = no 0-RTT |
| `error` | string | Only when the probe failed |

### Grade

testls' own letter grade, see [grading.md](grading.md). It is computed
from the findings before suppressions and baseline.

| Field | Type | Description |
| --- | --- | --- |
| `letter` | string | `"A+"`, `"A"`, `"A-"`, `"B"`, `"C"`, or `"F"` |
| `untrusted` | bool | Certificate untrusted or not covering the host (T marker) |
| `incomplete` | bool | A probe failed; the grade may be too good |
| `reasons` | array of strings | Why the grade is not better; wording may change |

### Finding

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | Stable identifier, e.g. `"protocol.tls10"`, `"cert.untrusted"` |
| `severity` | string | `"info"`, `"low"`, `"medium"`, `"high"`, or `"critical"` |
| `message` | string | Human-readable description; wording may change |

Suite and group severities can also be `"ok"`. Findings with severity `ok` are not
reported.

### Suppressed finding

A [finding](#finding) silenced by an active `.testls.toml` (or `--config`)
entry, or listed for the same `target.input` in the `--baseline` report
with the same or a higher severity (failed or incomplete measurements are
never taken from the baseline).
It does not count towards `--fail-on`.

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | As in [finding](#finding) |
| `severity` | string | As in [finding](#finding) |
| `message` | string | As in [finding](#finding) |
| `reason` | string | The `reason` given in the suppression entry, or `"in baseline"` |

## Example

Abbreviated:

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:4ca923f86dbad72e8351ddec36e200013b537e5f4c3978adf3382a332bfcac1a -->

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:c873d59bcf80136d1fbf4f9275deff711c5fbccbcbbce5aace2fa748bdaf4d93 -->

```json
{
  "schema_version": 2,
  "tool": { "name": "testls", "version": "0.1.0" },
  "target": { "input": "example.com", "address": "192.0.2.1:443", "sni": "example.com" },
  "started_at": 1792835801,
  "protocols": [
    { "version": "TLSv1.2", "status": "offered" },
    { "version": "TLSv1.3", "status": "offered" }
  ],
  "ciphers": [
    {
      "protocol": "TLSv1.3",
      "order": "server",
      "suites": [
        { "id": "0x1302", "name": "TLS_AES_256_GCM_SHA384", "severity": "ok" }
      ]
    }
  ],
  "key_exchange": [
    {
      "protocol": "TLSv1.3",
      "group_order": "server",
      "groups": [
        { "id": "0x11ec", "name": "X25519MLKEM768", "severity": "ok" },
        { "id": "0x001d", "name": "x25519", "severity": "ok" }
      ],
      "dh_bits": null,
      "dh_suites": []
    }
  ],
  "post_quantum": {
    "status": "ready",
    "groups": [
      { "id": "0x11ec", "name": "X25519MLKEM768", "severity": "ok" }
    ],
    "draft_groups": [],
    "preferred": true
  },
  "certificate": {
    "protocol": "TLSv1.3",
    "chain": [
      {
        "subject": "CN=example.com",
        "issuer": "CN=Example CA",
        "not_before": 1767225600,
        "not_after": 1798761600,
        "names": ["example.com"],
        "key": "EC 256 bits",
        "scts": 2
      }
    ],
    "ocsp": {
      "stapled": true,
      "status": "good",
      "produced_at": 1792918114,
      "this_update": 1792918114,
      "next_update": 1793522914
    }
  },
  "http": {
    "status": 200,
    "headers": {
      "content-security-policy": null,
      "referrer-policy": "no-referrer",
      "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY"
    },
    "hsts": { "max_age": 63072000, "include_subdomains": true, "preload": true, "preload_eligible": true },
    "banners": { "server": ["nginx"] },
    "alt_svc": [{ "protocol": "h3", "authority": ":443", "max_age": 86400 }],
    "cookies": [{ "name": "sid", "secure": true, "http_only": true, "same_site": "Lax" }]
  },
  "revocation": {
    "checks": [
      { "method": "ocsp", "url": "http://ocsp.example.net/", "status": "good", "this_update": 1792918114, "next_update": 1793522914 }
    ]
  },
  "vulnerabilities": [
    { "id": "poodle", "name": "POODLE", "status": "not vulnerable", "detail": "SSLv3 not offered", "finding": null },
    { "id": "beast", "name": "BEAST", "status": "vulnerable", "detail": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "finding": "vuln.beast" }
  ],
  "intolerance": {
    "protocol": "TLSv1.3",
    "tests": { "fragmented": "tolerated", "grease": "tolerated", "oversized": "rejected", "unknown_extension": "tolerated", "unknown_version": "tolerated" }
  },
  "details": {
    "protocol": "TLSv1.2", "extended_master_secret": true, "downgrade_sentinel": true,
    "session_tickets": true, "max_early_data": 0
  },
  "grade": { "letter": "A+", "untrusted": false, "incomplete": false, "reasons": [] },
  "findings": [
    { "id": "protocol.no_tls13", "severity": "info", "message": "..." }
  ],
  "suppressed": []
}
```

<!-- /coderabbit-ai-generated:v1 -->

<!-- /coderabbit-ai-generated:v1 -->
