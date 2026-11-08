//! Parsing of user-supplied scan targets.

use std::fmt;
use std::net::IpAddr;

/// Port used when the target does not specify one.
pub const DEFAULT_PORT: u16 = 443;

/// Host part of a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// DNS name (lowercased, without trailing dot).
    Name(String),
    /// Literal IP address.
    Ip(IpAddr),
}

impl fmt::Display for Host {
    /// Writes the name, or the address with IPv6 in brackets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(n) => f.write_str(n),
            Self::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]"),
            Self::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// A scan target: `host`, `host:port`, `[v6]:port`, or an `https://` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Host to connect to.
    pub host: Host,
    /// TCP port.
    pub port: u16,
}

impl Target {
    /// Server name to send in SNI: the DNS name, or none for IP literals.
    #[must_use]
    pub fn default_sni(&self) -> Option<&str> {
        match &self.host {
            Host::Name(n) => Some(n),
            Host::Ip(_) => None,
        }
    }
}

impl fmt::Display for Target {
    /// Writes `host:port`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Why a target string was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseTargetError(String);

impl fmt::Display for ParseTargetError {
    /// Writes the reason.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseTargetError {}

/// A [`ParseTargetError`] with `msg`.
fn err(msg: impl Into<String>) -> ParseTargetError {
    ParseTargetError(msg.into())
}

impl std::str::FromStr for Target {
    type Err = ParseTargetError;

    /// Parses a target, defaulting the port to [`DEFAULT_PORT`].
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse_with_port(input, DEFAULT_PORT)
    }
}

impl Target {
    /// Parses `input` like [`str::parse`], using `default_port` when the
    /// target names neither a port nor a URL scheme.
    ///
    /// # Errors
    ///
    /// [`ParseTargetError`] naming what is wrong with `input`.
    pub fn parse_with_port(input: &str, default_port: u16) -> Result<Self, ParseTargetError> {
        let s = input.trim();
        let (s, scheme_port) = match s.split_once("://") {
            Some((scheme, rest)) => {
                let port = match scheme.to_ascii_lowercase().as_str() {
                    "https" => DEFAULT_PORT,
                    other => return Err(err(format!("unsupported URL scheme `{other}`"))),
                };
                (rest, Some(port))
            }
            None => (s, None),
        };
        // Drop path, query, fragment and userinfo.
        let authority = s.split(['/', '?', '#']).next().unwrap_or_default();
        let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
        if authority.is_empty() {
            return Err(err("empty host"));
        }

        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let (ip, after) = rest
                .split_once(']')
                .ok_or_else(|| err("missing `]` in IPv6 address"))?;
            let ip: IpAddr = ip.parse().map_err(|_| err("invalid IPv6 address"))?;
            let port = match after {
                "" => None,
                p => Some(
                    p.strip_prefix(':')
                        .ok_or_else(|| err("unexpected text after `]`"))?,
                ),
            };
            (Host::Ip(ip), port)
        } else if let Ok(ip) = authority.parse::<IpAddr>() {
            // Bare IPv6 without brackets, or plain IPv4.
            (Host::Ip(ip), None)
        } else {
            let (host, port) = match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            };
            let host = match host.parse::<IpAddr>() {
                Ok(ip @ IpAddr::V4(_)) => Host::Ip(ip),
                Ok(IpAddr::V6(_)) => return Err(err("IPv6 address with port must use [brackets]")),
                Err(_) => Host::Name(validate_name(host)?),
            };
            (host, port)
        };

        let port = match port {
            Some(p) => p
                .parse::<u16>()
                .ok()
                .filter(|&p| p != 0)
                .ok_or_else(|| err(format!("invalid port `{p}`")))?,
            None => scheme_port.unwrap_or(default_port),
        };
        Ok(Self { host, port })
    }
}

/// Most host bits a CIDR range may have, so one argument expands to at
/// most 65,536 targets.
pub const MAX_CIDR_HOST_BITS: u32 = 16;

/// One command-line or `--file` entry: a single [`Target`] or a CIDR range
/// (`192.0.2.0/30`, `192.0.2.0/30:8443`, `[2001:db8::/126]:8443`) expanded
/// to every address it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSpec(pub Vec<Target>);

impl std::str::FromStr for TargetSpec {
    type Err = ParseTargetError;

    /// Parses a target or CIDR range, defaulting the port to
    /// [`DEFAULT_PORT`].
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse_with_port(input, DEFAULT_PORT)
    }
}

impl TargetSpec {
    /// Parses `input` like [`str::parse`], using `default_port` when the
    /// target or range names neither a port nor a URL scheme.
    ///
    /// # Errors
    ///
    /// [`ParseTargetError`] naming what is wrong with `input`.
    pub fn parse_with_port(input: &str, default_port: u16) -> Result<Self, ParseTargetError> {
        let s = input.trim();
        match cidr_parts(s)? {
            Some((ip, len, port)) => expand_cidr(ip, len, port, default_port).map(Self),
            None => Ok(Self(vec![Target::parse_with_port(s, default_port)?])),
        }
    }
}

/// Address, prefix length and optional port of a CIDR range.
type CidrParts<'a> = (IpAddr, &'a str, Option<&'a str>);

/// Splits `s` into address, prefix length and port when it is CIDR
/// notation; `None` means it is an ordinary target.
///
/// An IP literal followed by `/` and one to three digits counts as a CIDR
/// range unless the digits continue as a path (`.`, `/`, `?`, `#`), so
/// `192.0.2.1/2024.html` stays a URL path while `192.0.2.0/24x` is an
/// error rather than a silently truncated target.
fn cidr_parts(s: &str) -> Result<Option<CidrParts<'_>>, ParseTargetError> {
    if s.contains("://") {
        return Ok(None);
    }
    let bracketed = s.starts_with('[');
    let (inner, port) = match s.strip_prefix('[') {
        Some(rest) => {
            let Some((inner, after)) = rest.split_once(']') else {
                return Ok(None);
            };
            let port = match after {
                "" => None,
                p => match p.strip_prefix(':') {
                    Some(p) => Some(p),
                    None => return Ok(None),
                },
            };
            (inner, port)
        }
        None => (s, None),
    };
    let Some((ip, tail)) = inner.split_once('/') else {
        return Ok(None);
    };
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return Ok(None);
    };
    let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
    let (len, rest) = tail.split_at(digits);
    if !(1..=3).contains(&digits) || rest.starts_with(['.', '/', '?', '#']) {
        return Ok(None);
    }
    match rest.strip_prefix(':') {
        None if rest.is_empty() => Ok(Some((ip, len, port))),
        Some(p) if !bracketed && ip.is_ipv4() => Ok(Some((ip, len, Some(p)))),
        Some(_) if !bracketed => Err(err("IPv6 CIDR range with port must use [brackets]")),
        _ => Err(err(format!("invalid CIDR range `{s}`"))),
    }
}

/// Lists every address of the range `ip/len` with `port` (default
/// `default_port`).
fn expand_cidr(
    ip: IpAddr,
    len: &str,
    port: Option<&str>,
    default_port: u16,
) -> Result<Vec<Target>, ParseTargetError> {
    let bits = if ip.is_ipv4() { 32 } else { 128 };
    let len: u32 = len
        .parse()
        .ok()
        .filter(|&l| l <= bits)
        .ok_or_else(|| err(format!("invalid prefix length `/{len}`")))?;
    let host_bits = bits - len;
    if host_bits > MAX_CIDR_HOST_BITS {
        return Err(err(format!(
            "CIDR range `/{len}` is too large; at most {MAX_CIDR_HOST_BITS} host bits are allowed"
        )));
    }
    let port = match port {
        None => default_port,
        Some(p) => p
            .parse::<u16>()
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(|| err(format!("invalid port `{p}`")))?,
    };
    let base = match ip {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    };
    let network = base >> host_bits << host_bits;
    Ok((0..1u128 << host_bits)
        .map(|offset| {
            let n = network | offset;
            let ip = match ip {
                // The value fits: an IPv4 network plus at most 16 host bits.
                IpAddr::V4(_) => IpAddr::V4(u32::try_from(n).unwrap_or_default().into()),
                IpAddr::V6(_) => IpAddr::V6(n.into()),
            };
            Target {
                host: Host::Ip(ip),
                port,
            }
        })
        .collect())
}

/// A `--resolve HOST:PORT:ADDR[,ADDR...]` entry: connect to these
/// addresses instead of looking up `HOST` when it is scanned on `PORT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveOverride {
    /// Host name the entry applies to (lowercased, without trailing dot).
    pub host: String,
    /// Port the entry applies to.
    pub port: u16,
    /// Addresses to use, in the given order.
    pub addrs: Vec<IpAddr>,
}

impl ResolveOverride {
    /// Whether this entry applies to `target`.
    #[must_use]
    pub fn matches(&self, target: &Target) -> bool {
        target.port == self.port && matches!(&target.host, Host::Name(n) if *n == self.host)
    }
}

impl std::str::FromStr for ResolveOverride {
    type Err = ParseTargetError;

    /// Parses `HOST:PORT:ADDR[,ADDR...]`.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut parts = input.trim().splitn(3, ':');
        let (Some(host), Some(port), Some(addrs)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(err("expected HOST:PORT:ADDR[,ADDR...]"));
        };
        let host = validate_name(host)?;
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(|| err(format!("invalid port `{port}`")))?;
        let addrs = addrs
            .split(',')
            .map(|a| {
                let bare = a
                    .strip_prefix('[')
                    .and_then(|a| a.strip_suffix(']'))
                    .unwrap_or(a);
                bare.parse::<IpAddr>()
                    .map_err(|_| err(format!("invalid address `{a}`")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { host, port, addrs })
    }
}

/// A `--proxy [http://]HOST:PORT` value: an HTTP proxy that supports
/// `CONNECT` (RFC 9110 §9.3.6). Authentication is not supported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySpec(pub Target);

impl std::str::FromStr for ProxySpec {
    type Err = ParseTargetError;

    /// Parses `[http://]HOST:PORT`.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let s = input.trim();
        let s = match s.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => rest,
            Some((scheme, _)) => return Err(err(format!("unsupported proxy scheme `{scheme}`"))),
            None => s,
        };
        let s = s.strip_suffix('/').unwrap_or(s);
        if s.contains('@') {
            return Err(err("proxy authentication is not supported"));
        }
        if s.contains(['/', '?', '#']) {
            return Err(err("proxy must be HOST:PORT without a path"));
        }
        let target: Target = s.parse()?;
        // Target parsing defaults the port; a proxy has no standard one.
        let bare_v6 = matches!(target.host, Host::Ip(IpAddr::V6(_))) && !s.starts_with('[');
        if bare_v6 || !s.ends_with(&format!(":{}", target.port)) {
            return Err(err("proxy port is required (HOST:PORT)"));
        }
        Ok(Self(target))
    }
}

/// Checks that `name` is a DNS host name, as needed for an SNI value, and
/// returns it lowercased without a trailing dot.
///
/// # Errors
///
/// [`ParseTargetError`] when a label is empty, too long or holds anything
/// but letters, digits, `-` and `_`.
pub fn host_name(name: &str) -> Result<String, ParseTargetError> {
    validate_name(name)
}

/// Lowercases `name` and checks its labels; see [`host_name`].
fn validate_name(name: &str) -> Result<String, ParseTargetError> {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if name.is_empty() || name.len() > 253 || !name.split('.').all(label_ok) {
        return Err(err(format!("invalid host name `{name}`")));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    //! Unit tests for target, range, override and proxy parsing.

    use super::*;

    /// Parses `s` as a target.
    fn t(s: &str) -> Target {
        s.parse().unwrap()
    }

    /// Host, port, URL and IP literal forms parse.
    #[test]
    fn forms() {
        assert_eq!(t("Example.COM").to_string(), "example.com:443");
        assert_eq!(t("example.com:8443").port, 8443);
        assert_eq!(
            t("https://example.com/path?q=1").to_string(),
            "example.com:443"
        );
        assert_eq!(t("https://user@example.com:4443/").port, 4443);
        assert_eq!(t("192.0.2.1").to_string(), "192.0.2.1:443");
        assert_eq!(t("192.0.2.1:993").port, 993);
        assert_eq!(t("2001:db8::1").to_string(), "[2001:db8::1]:443");
        assert_eq!(t("[2001:db8::1]:8443").to_string(), "[2001:db8::1]:8443");
        assert_eq!(t("example.com.").host, Host::Name("example.com".into()));
    }

    /// Expands a spec to its display strings.
    fn spec(s: &str) -> Vec<String> {
        let TargetSpec(list) = s.parse().unwrap();
        list.iter().map(ToString::to_string).collect()
    }

    /// CIDR ranges expand to every covered address, keeping the port.
    #[test]
    fn cidr_ranges() {
        assert_eq!(
            spec("192.0.2.5/30"),
            [
                "192.0.2.4:443",
                "192.0.2.5:443",
                "192.0.2.6:443",
                "192.0.2.7:443"
            ]
        );
        assert_eq!(spec("192.0.2.9/32:8443"), ["192.0.2.9:8443"]);
        assert_eq!(
            spec("[192.0.2.0/31]:993"),
            ["192.0.2.0:993", "192.0.2.1:993"]
        );
        assert_eq!(
            spec("[2001:db8::/127]:8443"),
            ["[2001:db8::]:8443", "[2001:db8::1]:8443"]
        );
        assert_eq!(spec("2001:db8::7/128"), ["[2001:db8::7]:443"]);
        assert_eq!(spec("0.0.0.0/16").len(), 65_536);
        assert_eq!(spec("example.com:8443"), ["example.com:8443"]);
        assert_eq!(spec("https://192.0.2.1/30"), ["192.0.2.1:443"]);
        assert_eq!(spec("192.0.2.1/2024.html"), ["192.0.2.1:443"]);
        assert_eq!(spec("192.0.2.1/24/index.html"), ["192.0.2.1:443"]);
        assert_eq!(spec("192.0.2.1/1234"), ["192.0.2.1:443"]);
        for bad in [
            "192.0.2.0/24x",
            "2001:db8::/120:8443",
            "[2001:db8::/120]8443",
            "192.0.2.0/24:8443x",
            "192.0.2.0/33",
            "192.0.2.0/15",
            "2001:db8::/64",
            "192.0.2.0/30:0",
            "[2001:db8::/126]x",
            "192.0.2.0/30:http",
        ] {
            assert!(
                bad.parse::<TargetSpec>().is_err(),
                "{bad} should be rejected"
            );
        }
    }

    /// `--resolve` entries parse curl-style and match on host and port.
    #[test]
    fn resolve_overrides() {
        let r: ResolveOverride = "Example.com.:443:192.0.2.1,[2001:db8::1],2001:db8::2"
            .parse()
            .unwrap();
        assert_eq!(r.host, "example.com");
        assert_eq!(r.port, 443);
        assert_eq!(
            r.addrs,
            ["192.0.2.1", "2001:db8::1", "2001:db8::2"].map(|a| a.parse::<IpAddr>().unwrap())
        );
        assert!(r.matches(&t("example.com")));
        assert!(!r.matches(&t("example.com:8443")));
        assert!(!r.matches(&t("www.example.com")));
        assert!(!r.matches(&t("192.0.2.1")));
        for bad in [
            "example.com",
            "example.com:443",
            "example.com:443:",
            "example.com:0:192.0.2.1",
            "example.com:443:192.0.2.1,",
            "exa mple.com:443:192.0.2.1",
            "example.com:443:host.example",
        ] {
            assert!(
                bad.parse::<ResolveOverride>().is_err(),
                "{bad} should be rejected"
            );
        }
    }

    /// `--proxy` takes `[http://]HOST:PORT` and rejects anything else.
    #[test]
    fn proxy_specs() {
        for (input, expected) in [
            ("proxy.example:3128", "proxy.example:3128"),
            ("HTTP://Proxy.Example:8080/", "proxy.example:8080"),
            ("192.0.2.1:3128", "192.0.2.1:3128"),
            ("[2001:db8::1]:3128", "[2001:db8::1]:3128"),
        ] {
            let ProxySpec(target) = input.parse().unwrap();
            assert_eq!(target.to_string(), expected);
        }
        for bad in [
            "proxy.example",
            "[2001:db8::1]",
            "2001:db8::1",
            "::1:3128",
            "https://proxy.example:3128",
            "socks5://proxy.example:1080",
            "http://user:pw@proxy.example:3128",
            "http://proxy.example:3128/path",
            "proxy.example:0",
        ] {
            assert!(
                bad.parse::<ProxySpec>().is_err(),
                "{bad} should be rejected"
            );
        }
    }

    /// Names default the SNI; IP literals send none. SNI values must be
    /// host names.
    #[test]
    fn sni() {
        assert_eq!(t("example.com").default_sni(), Some("example.com"));
        assert_eq!(t("192.0.2.1").default_sni(), None);
        assert_eq!(host_name("WWW.Example.com.").unwrap(), "www.example.com");
        for bad in ["a\r\nX-Evil: 1", "a b", "", "a..b"] {
            assert!(host_name(bad).is_err(), "{bad:?}");
        }
    }

    /// Malformed targets are rejected.
    #[test]
    fn rejects() {
        for bad in [
            "",
            "http://example.com",
            "example.com:0",
            "example.com:99999",
            "exa mple.com",
            "-bad.com",
            "[2001:db8::1",
            "[::1]x",
        ] {
            assert!(bad.parse::<Target>().is_err(), "{bad} should be rejected");
        }
    }
}
