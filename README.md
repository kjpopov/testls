# testls

[![CI](https://github.com/kjpopov/testls/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kjpopov/testls/actions/workflows/ci.yml)
[![Release](https://github.com/kjpopov/testls/actions/workflows/release.yml/badge.svg)](https://github.com/kjpopov/testls/actions/workflows/release.yml)
[![Coverage](https://codecov.io/gh/kjpopov/testls/graph/badge.svg)](https://codecov.io/gh/kjpopov/testls)
[![Latest release](https://img.shields.io/github/v/release/kjpopov/testls?include_prereleases&sort=semver)](https://github.com/kjpopov/testls/releases)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

> `$ test ls` does nothing. `testls` protects your web servers.

TLS/SSL scanner written in Rust and inspired by [testssl.sh](https://testssl.sh).
Single static binary with its own handshake engine (SSLv2–TLS 1.3), no
OpenSSL, no subprocesses.

It checks protocols, cipher suites, key exchange, certificates, revocation,
HTTP security headers, known vulnerabilities and post-quantum readiness,
and fits CI: SARIF, JUnit, Markdown and other report formats, exit codes,
suppressions, baselines and compliance policies (Mozilla, NIST, BSI,
PCI DSS, CNSA 2.0).

## GitHub Action

```yaml
- uses: kjpopov/testls@v0.6.0
  with:
    args: --fail-on medium example.com
```

See the [GitHub Action guide](docs/github-action.md) for code scanning,
job summaries, policies and pinning.

## Install

```bash
brew tap kjpopov/testls https://github.com/kjpopov/testls
brew install kjpopov/testls/testls
```

Or download a binary for Linux, macOS or Windows from the
[releases page](https://github.com/kjpopov/testls/releases), use Scoop, or
the container image `ghcr.io/kjpopov/testls`. See
[docs/install.md](docs/install.md).

## Quick start

```bash
testls example.com                                # scan port 443
testls --fail-on medium example.com:8443          # exit 1 on medium or worse
testls --format sarif example.com > testls.sarif  # for code scanning
testls --policy mozilla-intermediate example.com  # compliance check
testls explain hsts.missing                       # what a finding means
```

Exit status: `0` no finding at or above `--fail-on` (default `high`), `1`
at least one, `2` the scan failed.

## Documentation

- [Usage](docs/usage.md): targets, connection options, output formats,
  policies, suppressions and baselines
- [Grading](docs/grading.md): how the letter grade is computed
- [Install](docs/install.md): all packages, shell completions, man pages
- [GitHub Action](docs/github-action.md)
- [JSON report format](docs/json-schema.md)
- [Roadmap and decisions](docs/PLAN.md), [changelog](CHANGELOG.md)

Next: a local web service with a REST API and browser UI (v0.6).

## Responsible use

Only scan systems you own or are authorized to test.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). This project was designed and
architected by the maintainer; implementation was assisted by LLM tooling,
and all code paths were designed, reviewed and tested by a human.

## License

Dual-licensed under the [MIT License](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE), at your option.

Inspired by [testssl.sh](https://testssl.sh) by Dirk Wetter. `testls` is an
independent, clean-room implementation, not a fork, and does not reuse
testssl.sh code or data (testssl.sh is GPLv2).
