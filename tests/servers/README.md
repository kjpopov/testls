# Integration test servers

`compose.yaml` starts OpenSSL `s_server` instances, a Postfix server
with SMTP STARTTLS (`Dockerfile.postfix`, port 14425), a Dovecot
server with IMAP and POP3 STARTTLS (`Dockerfile.dovecot`, ports 14143 and
14110), a vsftpd server with FTP `AUTH TLS` (`Dockerfile.vsftpd`, port
14021), a Prosody server with XMPP STARTTLS (`Dockerfile.prosody`,
port 15222), an OpenLDAP server with LDAP StartTLS (`Dockerfile.slapd`,
port 14389), a PostgreSQL server with `SSLRequest`
(`Dockerfile.postgres`, port 15432) and a MariaDB server with `SSLRequest`
(`Dockerfile.mariadb`, port 13306) used by `crates/testls/tests/servers.rs`.

`Dockerfile.heartbleed` builds historical OpenSSL releases (ports
14435–14437). `Dockerfile.wolfssl` builds the wolfSSL example server for ROBOT
coverage: 3.12.2 (CVE-2017-13099, port 14438) and 3.13.0 (fixed, port 14439),
TLS 1.2 `AES128-SHA` only. On invalid RSA padding 3.12.2 sends `close_notify`
right after the ClientKeyExchange; for a valid block it waits for the client's
Finished. 3.13.0 waits in both cases. testls reports the differing flow as a
high `vuln.robot` on 3.12.2 and not tested on 3.13.0. Both releases answer a
hello without a shared suite with `TLS_NULL_WITH_NULL_NULL`, so scans also
report `cipher.null` and a certificate fetch error. Check by hand:

```sh
testls --intrusive --profile quick 127.0.0.1:14438
```

Every fixture resolves names through the `dns` service (CoreDNS,
`Dockerfile.coredns`), on the fixed compose network `10.253.53.0/24`.
`fixtures.test.zone` and its reverse zone give each fixture, the gateway and
the name server A and PTR records; keep them in step with the static
addresses in `compose.yaml`. Clients outside the network, such as the
address a runtime's port forwarder connects from, get a generated
`ip-a-b-c-d.peer.fixtures.test` PTR record and a matching A record. Other
names are refused, so no query leaves the network. OpenSSL `s_server`
and Postfix look up each client's name; without these records every
connection waited for the host resolver to time out (#163). The `dns`
service also listens on `127.0.0.1:15353/udp`; the `mx_lookup` test points
the hidden `--mx-dns` option at it (#189). Check by hand:

```sh
podman exec servers-smtp-1 getent hosts 10.253.53.1 smtp.fixtures.test
```

`server.pem` (SAN `localhost`, `127.0.0.1`; valid 2026–2126) is signed by the
test CA in `ca.pem`. The CA key was discarded after signing. `server.key` is a
test-only key; never use it anywhere else.

For repeatable local comparisons with a pinned, external black-box scanner,
see [fixture audits](../../docs/fixture-audit.md). The versioned fixture
manifest is `audit.json`; the runner never alters or starts these services.
