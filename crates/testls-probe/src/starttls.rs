//! Plain-text protocol dialogues that switch a connection to TLS
//! (STARTTLS) before the first `ClientHello`.

use std::fmt;
use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::ProbeError;

/// Largest server reply accepted during the dialogue, in bytes.
const MAX_REPLY: usize = 64 * 1024;

/// Application protocol to upgrade to TLS before probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Starttls {
    /// SMTP `STARTTLS` (RFC 3207).
    Smtp,
    /// IMAP `STARTTLS` (RFC 9051 §6.2.1).
    Imap,
    /// POP3 `STLS` (RFC 2595 §4).
    Pop3,
    /// FTP `AUTH TLS` (RFC 4217 §4).
    Ftp,
    /// XMPP client-to-server `starttls` (RFC 6120 §5).
    Xmpp,
    /// LDAP `StartTLS` extended operation (RFC 4511 §4.14).
    Ldap,
    /// PostgreSQL `SSLRequest` (PostgreSQL docs, "Frontend/Backend Protocol",
    /// "SSL Session Encryption").
    Postgres,
    /// MySQL and MariaDB `SSLRequest` (MySQL docs, "Client/Server Protocol",
    /// `Protocol::HandshakeV10` and `Protocol::SSLRequest`).
    Mysql,
}

impl Starttls {
    /// All protocols, in the order they are listed on the command line.
    pub const ALL: [Self; 8] = [
        Self::Smtp,
        Self::Imap,
        Self::Pop3,
        Self::Ftp,
        Self::Xmpp,
        Self::Ldap,
        Self::Postgres,
        Self::Mysql,
    ];

    /// Name used on the command line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Smtp => "smtp",
            Self::Imap => "imap",
            Self::Pop3 => "pop3",
            Self::Ftp => "ftp",
            Self::Xmpp => "xmpp",
            Self::Ldap => "ldap",
            Self::Postgres => "postgres",
            Self::Mysql => "mysql",
        }
    }

    /// Well-known port of the protocol's plain-text service.
    #[must_use]
    pub fn default_port(self) -> u16 {
        match self {
            Self::Smtp => 25,
            Self::Imap => 143,
            Self::Pop3 => 110,
            Self::Ftp => 21,
            Self::Xmpp => 5222,
            Self::Ldap => 389,
            Self::Postgres => 5432,
            Self::Mysql => 3306,
        }
    }

    /// Runs the protocol's dialogue on `stream` until the server is ready
    /// for a `ClientHello`. `early` holds server bytes already read from
    /// `stream` (by a proxy tunnel) and is consumed first. `host` names the
    /// server where the protocol needs it (the XMPP `to` address).
    ///
    /// # Errors
    /// Returns [`ProbeError::Connect`] when the server refuses, does not
    /// offer STARTTLS, sends a malformed or oversized reply, closes the
    /// connection, or sends bytes after its final reply (which would be
    /// injected into the TLS stream).
    pub(crate) async fn upgrade(
        self,
        stream: &mut TcpStream,
        early: Vec<u8>,
        host: &str,
    ) -> Result<(), ProbeError> {
        let reader = Replies { data: early };
        match self {
            Self::Smtp => smtp(stream, reader).await,
            Self::Imap => imap(stream, reader).await,
            Self::Pop3 => pop3(stream, reader).await,
            Self::Ftp => ftp(stream, reader).await,
            Self::Xmpp => xmpp(stream, reader, host).await,
            Self::Ldap => ldap(stream, reader).await,
            Self::Postgres => postgres(stream, reader).await,
            Self::Mysql => mysql(stream, reader).await,
        }
    }
}

impl fmt::Display for Starttls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Starttls {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|p| p.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| format!("unknown STARTTLS protocol {s:?}"))
    }
}

/// Builds the error for a failed dialogue.
fn error(msg: String) -> ProbeError {
    ProbeError::Connect(io::Error::other(msg))
}

/// SMTP dialogue (RFC 5321 §4.2, RFC 3207 §4): greeting, `EHLO`, check
/// the `STARTTLS` keyword, `STARTTLS`, expect 220.
async fn smtp(stream: &mut TcpStream, mut reader: Replies) -> Result<(), ProbeError> {
    let greeting = reader.smtp(stream).await?;
    expect(&greeting, 220, "greeting")?;
    send(stream, b"EHLO testls.invalid\r\n").await?;
    let ehlo = reader.smtp(stream).await?;
    expect(&ehlo, 250, "EHLO")?;
    // Each line after the first is one extension keyword (RFC 5321 §4.1.1.1).
    if !ehlo.lines[1..].iter().any(|l| {
        l.split_ascii_whitespace()
            .next()
            .is_some_and(|k| k.eq_ignore_ascii_case("STARTTLS"))
    }) {
        return Err(error("SMTP server does not offer STARTTLS".into()));
    }
    send(stream, b"STARTTLS\r\n").await?;
    let ready = reader.smtp(stream).await?;
    expect(&ready, 220, "STARTTLS")?;
    reader.finish()
}

/// IMAP dialogue (RFC 9051 §6.1.1, §6.2.1, §7.1): `* OK` greeting,
/// `CAPABILITY` must list `STARTTLS`, then `STARTTLS` must be answered `OK`.
async fn imap(stream: &mut TcpStream, mut reader: Replies) -> Result<(), ProbeError> {
    let greeting = reader.line(stream).await?;
    if !greeting
        .strip_prefix("* ")
        .is_some_and(|rest| status_is(rest, "OK"))
    {
        return Err(error(format!("server answered greeting with {greeting:?}")));
    }
    send(stream, b"a CAPABILITY\r\n").await?;
    let caps = reader.imap(stream, "a").await?;
    expect_imap(&caps, "CAPABILITY")?;
    let offered = caps.iter().any(|l| {
        let mut words = l.split_ascii_whitespace();
        words.next() == Some("*")
            && words
                .next()
                .is_some_and(|w| w.eq_ignore_ascii_case("CAPABILITY"))
            && words.any(|w| w.eq_ignore_ascii_case("STARTTLS"))
    });
    if !offered {
        return Err(error("IMAP server does not offer STARTTLS".into()));
    }
    send(stream, b"b STARTTLS\r\n").await?;
    let ready = reader.imap(stream, "b").await?;
    expect_imap(&ready, "STARTTLS")?;
    reader.finish()
}

/// Fails unless the tagged (last) line of an IMAP response is `OK`.
fn expect_imap(lines: &[String], step: &str) -> Result<(), ProbeError> {
    let last = lines.last().map_or("", String::as_str);
    match last.split_once(' ') {
        Some((_, rest)) if status_is(rest, "OK") => Ok(()),
        _ => Err(error(format!("server answered {step} with {last:?}"))),
    }
}

/// POP3 dialogue (RFC 1939 §4, RFC 2449 §5, RFC 2595 §4): `+OK`
/// greeting, `CAPA` must list `STLS`, then `STLS` must be answered `+OK`.
async fn pop3(stream: &mut TcpStream, mut reader: Replies) -> Result<(), ProbeError> {
    let greeting = reader.line(stream).await?;
    // RFC 2449 §3: `greeting = "+OK" [resp-code] *gchar`, so text such as an
    // APOP timestamp may follow `+OK` without a space.
    if !greeting
        .get(..3)
        .is_some_and(|s| s.eq_ignore_ascii_case("+OK"))
    {
        return Err(error(format!("server answered greeting with {greeting:?}")));
    }
    send(stream, b"CAPA\r\n").await?;
    let status = reader.line(stream).await?;
    expect_pop3(&status, "CAPA")?;
    let mut offered = false;
    let mut total = 0;
    loop {
        let line = reader.line(stream).await?;
        if line == "." {
            break;
        }
        count(&mut total, &line)?;
        offered |= line
            .split_ascii_whitespace()
            .next()
            .is_some_and(|k| k.eq_ignore_ascii_case("STLS"));
    }
    if !offered {
        return Err(error("POP3 server does not offer STLS".into()));
    }
    send(stream, b"STLS\r\n").await?;
    let ready = reader.line(stream).await?;
    expect_pop3(&ready, "STLS")?;
    reader.finish()
}

/// Fails unless a POP3 command status line is exactly `+OK` or starts
/// with `+OK ` (RFC 2449 §3 `single-line`).
fn expect_pop3(line: &str, step: &str) -> Result<(), ProbeError> {
    if status_is(line, "+OK") {
        Ok(())
    } else {
        Err(error(format!("server answered {step} with {line:?}")))
    }
}

/// FTP dialogue (RFC 959 §4.2, RFC 4217 §4): 220 greeting, `AUTH TLS`,
/// expect 234. A server without TLS refuses `AUTH`, so `FEAT` is not needed.
async fn ftp(stream: &mut TcpStream, mut reader: Replies) -> Result<(), ProbeError> {
    let greeting = reader.ftp(stream).await?;
    expect(&greeting, 220, "greeting")?;
    send(stream, b"AUTH TLS\r\n").await?;
    let ready = reader.ftp(stream).await?;
    expect(&ready, 234, "AUTH TLS")?;
    reader.finish()
}

/// PostgreSQL `SSLRequest` message: length 8 and request code 80877103
/// (PostgreSQL docs, "Frontend/Backend Protocol", "Message Formats").
const POSTGRES_SSL_REQUEST: &[u8] = &[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];

/// PostgreSQL dialogue: send `SSLRequest`, expect the single byte `S`.
/// `N` means the server has no TLS; an `ErrorResponse` (`E`) comes from
/// servers that predate `SSLRequest`.
async fn postgres(stream: &mut TcpStream, mut reader: Replies) -> Result<(), ProbeError> {
    send(stream, POSTGRES_SSL_REQUEST).await?;
    match reader.byte(stream).await? {
        b'S' => reader.finish(),
        b'N' => Err(error("PostgreSQL server does not offer TLS".into())),
        b'E' => Err(error("server answered SSLRequest with an error".into())),
        b => Err(error(format!(
            "malformed server reply: unexpected byte {b:#04x}"
        ))),
    }
}

/// MySQL `CLIENT_SSL` capability flag (MySQL docs, "Capabilities Flags").
const MYSQL_CLIENT_SSL: u32 = 0x0800;

/// MySQL `SSLRequest` packet (MySQL docs, `Protocol::SSLRequest`): header
/// with payload length 32 and sequence id 1, then capabilities
/// `CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SSL |
/// CLIENT_SECURE_CONNECTION`, maximum packet size 16 MiB, character set
/// 45 (`utf8mb4_general_ci`) and 23 reserved zero bytes.
const MYSQL_SSL_REQUEST: &[u8] = &[
    32, 0, 0, 1, // header
    0x01, 0x8a, 0, 0, // capabilities
    0, 0, 0, 1,  // max packet size
    45, // character set
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// MySQL dialogue: read the server's initial handshake packet, which must
/// be protocol version 10 with `CLIENT_SSL`, then send `SSLRequest`. The
/// server answers with its TLS handshake; there is no plain-text reply.
async fn mysql(stream: &mut TcpStream, mut reader: Replies) -> Result<(), ProbeError> {
    let header = reader.take(stream, 4).await?;
    let len = usize::from(header[0]) | usize::from(header[1]) << 8 | usize::from(header[2]) << 16;
    if header[3] != 0 || len == 0 {
        return Err(malformed_mysql());
    }
    if len > MAX_REPLY {
        return Err(error(format!("server reply exceeds {MAX_REPLY} bytes")));
    }
    let payload = reader.take(stream, len).await?;
    match payload[0] {
        // ERR packet: 0xff, error code, then (in a greeting) the message.
        0xff => {
            let code = payload
                .get(1..3)
                .map_or(0, |c| u16::from_le_bytes([c[0], c[1]]));
            let text = String::from_utf8_lossy(payload.get(3..).unwrap_or_default());
            return Err(error(format!("MySQL server sent error {code} {text:?}")));
        }
        10 => {}
        v => return Err(error(format!("unsupported MySQL protocol version {v}"))),
    }
    // Server version (NUL-terminated), connection id (4), auth data (8),
    // filler (1), then the lower two capability bytes, character set (1),
    // status (2), upper capability bytes (2), auth data length (1) and 10
    // reserved bytes, all of which must be present.
    let version_end = payload[1..]
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(malformed_mysql)?;
    let at = 1 + version_end + 1 + 4 + 8 + 1;
    if payload.len() < at + 18 {
        return Err(malformed_mysql());
    }
    let caps = &payload[at..at + 2];
    if u32::from(u16::from_le_bytes([caps[0], caps[1]])) & MYSQL_CLIENT_SSL == 0 {
        return Err(error("MySQL server does not offer TLS".into()));
    }
    reader.finish()?;
    send(stream, MYSQL_SSL_REQUEST).await
}

/// Builds the error for a malformed MySQL packet.
fn malformed_mysql() -> ProbeError {
    error("malformed MySQL handshake".into())
}

/// TLS namespace of the XMPP `starttls`, `proceed` and `failure` elements
/// (RFC 6120 §5.4.2).
const XMPP_TLS: &str = "urn:ietf:params:xml:ns:xmpp-tls";

/// XMPP client dialogue (RFC 6120 §4.2, §5.4.2): open a stream to `host`,
/// the features must offer `starttls`, send it, expect `proceed`.
async fn xmpp(stream: &mut TcpStream, mut reader: Replies, host: &str) -> Result<(), ProbeError> {
    let header = format!(
        "<?xml version='1.0'?><stream:stream to='{}' version='1.0' \
         xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>",
        xml_escape(host)
    );
    send(stream, header.as_bytes()).await?;
    let features = reader.xml(stream, &["stream:features"]).await?;
    if !features.contains("<stream:features") {
        if let Some(condition) = stream_error(&features) {
            return Err(error(format!("XMPP server sent stream error {condition}")));
        }
        return Err(error(format!(
            "XMPP server sent no stream features: {}",
            excerpt(&features)
        )));
    }
    if !has_tls_element(&features, "starttls") {
        return Err(error("XMPP server does not offer STARTTLS".into()));
    }
    send(stream, format!("<starttls xmlns='{XMPP_TLS}'/>").as_bytes()).await?;
    let answer = reader.xml(stream, &["proceed", "failure"]).await?;
    // Whitespace keepalives may come first (RFC 6120 §4.6.1).
    let answer = answer.trim_start();
    let proceed = start_tag(answer, "proceed").is_some_and(|(start, _)| start == 0)
        && element_end(answer, "proceed") == Some(answer.len())
        && has_tls_element(answer, "proceed");
    if !proceed {
        return Err(error(format!(
            "server answered starttls with {}",
            excerpt(answer)
        )));
    }
    reader.finish()
}

/// Escapes `s` for a single-quoted XML attribute value.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&apos;")
        .replace('"', "&quot;")
}

/// Name of the first child of a `stream:error` element in `s`, the error
/// condition (RFC 6120 §4.9.2), such as `host-unknown`.
fn stream_error(s: &str) -> Option<&str> {
    let start = s.find("<stream:error")?;
    let rest = &s[start + 1..];
    let child = &rest[rest.find('<')? + 1..];
    let end = child.find(|c: char| c == '/' || c == '>' || c.is_ascii_whitespace())?;
    Some(&child[..end]).filter(|name| !name.is_empty())
}

/// First 200 characters of `s`, for error messages.
fn excerpt(s: &str) -> String {
    format!("{:?}", s.chars().take(200).collect::<String>())
}

/// Byte offset just past the first complete element named one of `names`
/// in `data`, or past a `stream:error` element or the stream's closing tag.
/// `None` until one of them is complete.
fn xml_end(data: &str, names: &[&str]) -> Option<usize> {
    let mut best: Option<usize> = None;
    let mut keep = |end: Option<usize>| {
        if let Some(end) = end {
            best = Some(best.map_or(end, |b| b.min(end)));
        }
    };
    for name in names.iter().copied().chain(["stream:error"]) {
        keep(element_end(data, name));
    }
    keep(
        data.find("</stream:stream>")
            .map(|i| i + "</stream:stream>".len()),
    );
    best
}

/// Byte range of the first complete `<name ...>` start tag in `data`,
/// from `<` to just past `>`.
fn start_tag(data: &str, name: &str) -> Option<(usize, usize)> {
    let open = format!("<{name}");
    let mut from = 0;
    while let Some(i) = data[from..].find(&open).map(|i| from + i) {
        let after = i + open.len();
        // Skip longer names that share the prefix, such as `<proceeding`.
        match data[after..].chars().next() {
            Some(c) if c == '>' || c == '/' || c.is_ascii_whitespace() => {
                return Some((i, after + data[after..].find('>')? + 1));
            }
            Some(_) => from = after,
            None => return None,
        }
    }
    None
}

/// Reports whether `data` has a `<name>` start tag declaring the XMPP TLS
/// namespace.
fn has_tls_element(data: &str, name: &str) -> bool {
    start_tag(data, name).is_some_and(|(start, end)| data[start..end].contains(XMPP_TLS))
}

/// Byte offset just past the first complete `<name ...>` element in
/// `data`, whether empty (`<name/>`) or with content and `</name>`.
fn element_end(data: &str, name: &str) -> Option<usize> {
    let (_, tag_end) = start_tag(data, name)?;
    if data[..tag_end].ends_with("/>") {
        return Some(tag_end);
    }
    let close = format!("</{name}>");
    data[tag_end..]
        .find(&close)
        .map(|j| tag_end + j + close.len())
}

/// LDAP `StartTLS` request (RFC 4511 §4.14.1): an `LDAPMessage` with
/// message ID 1 and an `ExtendedRequest` naming `1.3.6.1.4.1.1466.20037`.
const LDAP_STARTTLS: &[u8] = b"\x30\x1d\x02\x01\x01\x77\x18\x80\x161.3.6.1.4.1.1466.20037";

/// `StartTLS` extended operation OID (RFC 4511 §4.14.1).
const LDAP_STARTTLS_OID: &[u8] = b"1.3.6.1.4.1.1466.20037";

/// LDAP dialogue (RFC 4511 §4.14): no greeting; send the `StartTLS`
/// extended request and expect an `ExtendedResponse` with result
/// `success` (0) for message ID 1.
async fn ldap(stream: &mut TcpStream, mut reader: Replies) -> Result<(), ProbeError> {
    send(stream, LDAP_STARTTLS).await?;
    let message = reader.ber(stream).await?;
    let (id, rest) = ber_field(&message, 0x02)?;
    let (response, controls) = ber_field(rest, 0x78)?;
    let (code, rest) = ber_field(response, 0x0a)?;
    let (_matched_dn, rest) = ber_field(rest, 0x04)?;
    let (diagnostic, rest) = ber_field(rest, 0x04)?;
    if code.is_empty() || code.len() > 4 {
        return Err(malformed_ldap());
    }
    let code = code.iter().fold(0u32, |n, &b| n << 8 | u32::from(b));
    let diagnostic = String::from_utf8_lossy(diagnostic);
    // Message ID 0 is an unsolicited notification, such as the notice of
    // disconnection (RFC 4511 §4.4.1), with its own response name.
    if id == [0] {
        return Err(error(format!(
            "server sent unsolicited notification with result {code} {diagnostic:?}"
        )));
    }
    if id != [1] {
        return Err(malformed_ldap());
    }
    // Only referral [3] (with result referral, 10) and responseName [10]
    // with the StartTLS OID may follow, no responseValue, and only controls
    // [0] after the response (RFC 4511 §4.1.1, §4.1.9, §4.1.10, §4.14.2).
    let mut rest = if code == 10 {
        optional_ber_field(rest, 0xa3)?
    } else {
        rest
    };
    if rest.first() == Some(&0x8a) {
        let (name, after) = ber_field(rest, 0x8a)?;
        if name != LDAP_STARTTLS_OID {
            return Err(malformed_ldap());
        }
        rest = after;
    }
    if !rest.is_empty() || !optional_ber_field(controls, 0xa0)?.is_empty() {
        return Err(malformed_ldap());
    }
    if code != 0 {
        return Err(error(format!(
            "server answered StartTLS with result {code} {diagnostic:?}"
        )));
    }
    reader.finish()
}

/// Error for an LDAP reply that is not valid BER or not the expected
/// `ExtendedResponse`.
fn malformed_ldap() -> ProbeError {
    error("malformed LDAP reply".into())
}

/// One BER element: tag, value, and the bytes after it.
type Element<'a> = (u8, &'a [u8], &'a [u8]);

/// Splits one BER element off `data` (RFC 4511 §5.1: single-byte tags,
/// definite lengths): returns its tag, value and the bytes after it, or
/// `None` while `data` is incomplete.
///
/// # Errors
/// Fails on multi-byte tags, the indefinite length form, lengths over
/// four bytes, and elements longer than `MAX_REPLY` with tag and length.
fn ber_split(data: &[u8]) -> Result<Option<Element<'_>>, ProbeError> {
    let (Some(&tag), Some(&first)) = (data.first(), data.get(1)) else {
        return Ok(None);
    };
    if tag & 0x1f == 0x1f {
        return Err(malformed_ldap());
    }
    let (len, head) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        // 0x80 alone is the indefinite form, which LDAP forbids.
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return Err(malformed_ldap());
        }
        let Some(bytes) = data.get(2..2 + n) else {
            return Ok(None);
        };
        let len = bytes.iter().fold(0usize, |l, &b| l << 8 | usize::from(b));
        (len, 2 + n)
    };
    if len > MAX_REPLY - head {
        return Err(error(format!("server reply exceeds {MAX_REPLY} bytes")));
    }
    Ok(data
        .get(head..head + len)
        .map(|value| (tag, value, &data[head + len..])))
}

/// Splits a complete BER element with tag `tag` off `data`; returns its
/// value and the bytes after it.
fn ber_field(data: &[u8], tag: u8) -> Result<(&[u8], &[u8]), ProbeError> {
    match ber_split(data)? {
        Some((t, value, rest)) if t == tag => Ok((value, rest)),
        _ => Err(malformed_ldap()),
    }
}

/// Skips an optional BER element with tag `tag` at the start of `data`;
/// returns the bytes after it.
fn optional_ber_field(data: &[u8], tag: u8) -> Result<&[u8], ProbeError> {
    if data.first() == Some(&tag) {
        Ok(ber_field(data, tag)?.1)
    } else {
        Ok(data)
    }
}

/// Reports whether the first space-separated word of `s` is the status
/// `token` (ASCII case-insensitive), so `OKAY` does not pass as `OK`.
fn status_is(s: &str, token: &str) -> bool {
    s.split(' ')
        .next()
        .is_some_and(|w| w.eq_ignore_ascii_case(token))
}

/// Writes `data` to `stream`.
async fn send(stream: &mut TcpStream, data: &[u8]) -> Result<(), ProbeError> {
    stream.write_all(data).await.map_err(ProbeError::Connect)
}

/// Fails unless `reply` has status `code`.
fn expect(reply: &Reply, code: u16, step: &str) -> Result<(), ProbeError> {
    if reply.code == code {
        return Ok(());
    }
    let text = reply.lines.first().map_or("", String::as_str);
    let text = text.escape_debug();
    Err(error(format!(
        "server answered {step} with {} {text}",
        reply.code
    )))
}

/// Adds `line` and its CRLF to `total`, failing once a reply passes
/// `MAX_REPLY`; counting the CRLF bounds replies made of empty lines.
fn count(total: &mut usize, line: &str) -> Result<(), ProbeError> {
    *total += line.len() + 2;
    if *total > MAX_REPLY {
        return Err(error(format!("server reply exceeds {MAX_REPLY} bytes")));
    }
    Ok(())
}

/// One multi-line reply: status code and the text of each line.
#[derive(Debug, PartialEq, Eq)]
struct Reply {
    /// Three-digit status code.
    code: u16,
    /// Text after the code and separator on each line.
    lines: Vec<String>,
}

/// Buffered reader for line-based server replies.
#[derive(Debug, Default)]
struct Replies {
    /// Bytes received but not yet consumed.
    data: Vec<u8>,
}

impl Replies {
    /// Reads the next CRLF-terminated line, without the line ending.
    async fn line(&mut self, stream: &mut TcpStream) -> Result<String, ProbeError> {
        loop {
            if let Some(end) = self.data.windows(2).position(|w| w == b"\r\n") {
                let line = String::from_utf8_lossy(&self.data[..end]).into_owned();
                self.data.drain(..end + 2);
                return Ok(line);
            }
            if self.data.len() > MAX_REPLY {
                return Err(error(format!("server reply exceeds {MAX_REPLY} bytes")));
            }
            self.fill(stream).await?;
        }
    }

    /// Appends the next chunk read from `stream`; the server closing the
    /// connection is an error.
    async fn fill(&mut self, stream: &mut TcpStream) -> Result<(), ProbeError> {
        let mut buf = [0; 4096];
        let n = stream.read(&mut buf).await.map_err(ProbeError::Connect)?;
        if n == 0 {
            return Err(error("server closed the connection during STARTTLS".into()));
        }
        self.data.extend_from_slice(&buf[..n]);
        Ok(())
    }

    /// Reads an SMTP-style reply: lines of `NNN-text` ending with one
    /// `NNN text` (RFC 5321 §4.2.1).
    async fn smtp(&mut self, stream: &mut TcpStream) -> Result<Reply, ProbeError> {
        let mut lines = Vec::new();
        let mut code = None;
        let mut total = 0;
        loop {
            let line = self.line(stream).await?;
            count(&mut total, &line)?;
            let bytes = line.as_bytes();
            let malformed = || error(format!("malformed server reply {line:?}"));
            if bytes.len() < 3 || !bytes[..3].iter().all(u8::is_ascii_digit) {
                return Err(malformed());
            }
            let this: u16 = line[..3].parse().map_err(|_| malformed())?;
            if *code.get_or_insert(this) != this {
                return Err(malformed());
            }
            let last = match bytes.get(3) {
                None | Some(b' ') => true,
                Some(b'-') => false,
                Some(_) => return Err(malformed()),
            };
            lines.push(line.get(4..).unwrap_or("").to_owned());
            if last {
                return Ok(Reply { code: this, lines });
            }
        }
    }

    /// Reads an FTP reply (RFC 959 §4.2): one `NNN text` line, or
    /// `NNN-text`, any lines, and a closing `NNN text` with the same code.
    async fn ftp(&mut self, stream: &mut TcpStream) -> Result<Reply, ProbeError> {
        let first = self.line(stream).await?;
        let bytes = first.as_bytes();
        let malformed = || error(format!("malformed server reply {first:?}"));
        if bytes.len() < 3 || !bytes[..3].iter().all(u8::is_ascii_digit) {
            return Err(malformed());
        }
        let code: u16 = first[..3].parse().map_err(|_| malformed())?;
        let mut lines = vec![first.get(4..).unwrap_or("").to_owned()];
        match bytes.get(3) {
            Some(b' ') => return Ok(Reply { code, lines }),
            Some(b'-') => {}
            _ => return Err(malformed()),
        }
        let prefix = first[..3].to_owned();
        let mut total = first.len() + 2;
        loop {
            let line = self.line(stream).await?;
            count(&mut total, &line)?;
            let last = line
                .strip_prefix(&prefix)
                .is_some_and(|rest| rest.starts_with(' '));
            lines.push(line);
            if last {
                return Ok(Reply { code, lines });
            }
        }
    }

    /// Reads IMAP response lines up to and including the one tagged
    /// `tag` (RFC 9051 §2.2.2); untagged lines come first.
    async fn imap(&mut self, stream: &mut TcpStream, tag: &str) -> Result<Vec<String>, ProbeError> {
        let mut lines = Vec::new();
        let mut total = 0;
        loop {
            let line = self.line(stream).await?;
            count(&mut total, &line)?;
            let tagged = line.split_once(' ').is_some_and(|(t, _)| t == tag);
            if !tagged && !line.starts_with("* ") {
                return Err(error(format!("malformed server reply {line:?}")));
            }
            lines.push(line);
            if tagged {
                return Ok(lines);
            }
        }
    }

    /// Reads XML until an element named one of `names`, a stream error or
    /// the end of the stream is complete (see [`xml_end`]); returns
    /// everything up to it.
    async fn xml(&mut self, stream: &mut TcpStream, names: &[&str]) -> Result<String, ProbeError> {
        loop {
            // XMPP is UTF-8 (RFC 6120 §11.6); a split character at the end
            // waits for more data, any other invalid byte is malformed.
            let valid = match std::str::from_utf8(&self.data) {
                Ok(text) => text,
                Err(e) if e.error_len().is_none() => {
                    std::str::from_utf8(&self.data[..e.valid_up_to()]).unwrap_or_default()
                }
                Err(_) => return Err(error("malformed server reply: invalid UTF-8".into())),
            };
            if let Some(end) = xml_end(valid, names) {
                let reply = valid[..end].to_owned();
                self.data.drain(..end);
                return Ok(reply);
            }
            if self.data.len() > MAX_REPLY {
                return Err(error(format!("server reply exceeds {MAX_REPLY} bytes")));
            }
            self.fill(stream).await?;
        }
    }

    /// Reads one BER `SEQUENCE` (an LDAP message) and returns its value.
    async fn ber(&mut self, stream: &mut TcpStream) -> Result<Vec<u8>, ProbeError> {
        loop {
            if self.data.first().is_some_and(|&tag| tag != 0x30) {
                return Err(malformed_ldap());
            }
            if let Some((_, value, rest)) = ber_split(&self.data)? {
                let value = value.to_vec();
                let used = self.data.len() - rest.len();
                self.data.drain(..used);
                return Ok(value);
            }
            self.fill(stream).await?;
        }
    }

    /// Reads a single byte.
    async fn byte(&mut self, stream: &mut TcpStream) -> Result<u8, ProbeError> {
        if self.data.is_empty() {
            self.fill(stream).await?;
        }
        Ok(self.data.remove(0))
    }

    /// Reads exactly `n` bytes.
    async fn take(&mut self, stream: &mut TcpStream, n: usize) -> Result<Vec<u8>, ProbeError> {
        while self.data.len() < n {
            self.fill(stream).await?;
        }
        Ok(self.data.drain(..n).collect())
    }

    /// Fails when the server sent bytes past its last reply.
    fn finish(self) -> Result<(), ProbeError> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(error("server sent data after its STARTTLS reply".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    /// Fake server that plays `script`: each entry is the client line it
    /// expects (none for the greeting) and the bytes it answers with.
    /// Returns its address and the lines it received.
    async fn server(
        script: &'static [(Option<&'static str>, &'static [u8])],
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            let mut reader = Replies::default();
            for (expected, reply) in script {
                if let Some(expected) = expected {
                    let line = reader.line(&mut s).await.unwrap();
                    assert_eq!(&line, expected);
                    got.push(line);
                }
                s.write_all(reply).await.unwrap();
            }
            got
        });
        (addr, task)
    }

    /// Script of a fake server; see [`server`].
    type Script = &'static [(Option<&'static str>, &'static [u8])];

    /// Connects to `addr` and runs the SMTP upgrade.
    async fn upgrade(addr: SocketAddr) -> Result<(), ProbeError> {
        upgrade_with(Starttls::Smtp, addr).await
    }

    /// Connects to `addr` and runs the `protocol` upgrade.
    async fn upgrade_with(protocol: Starttls, addr: SocketAddr) -> Result<(), ProbeError> {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        protocol
            .upgrade(&mut stream, Vec::new(), "example.org")
            .await
    }

    /// Fake XMPP or LDAP server: for each entry, reads until the client
    /// data ends with the expected suffix, then answers. Returns its address
    /// and everything the client sent (lossily decoded as UTF-8).
    async fn xmpp_server(script: XmppScript) -> (SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            for (suffix, reply) in script {
                while !got.ends_with(suffix.as_bytes()) {
                    let mut buf = [0; 1024];
                    let n = s.read(&mut buf).await.unwrap();
                    assert!(n > 0, "client closed early");
                    got.extend_from_slice(&buf[..n]);
                }
                s.write_all(reply).await.unwrap();
            }
            String::from_utf8_lossy(&got).into_owned()
        });
        (addr, task)
    }

    /// Script of a fake XMPP server; see [`xmpp_server`].
    type XmppScript = &'static [(&'static str, &'static [u8])];

    /// Stream header ending the client's first XMPP message.
    const XMPP_OPEN: &str = "xmlns:stream='http://etherx.jabber.org/streams'>";
    /// The client's `starttls` request.
    const XMPP_STARTTLS: &str = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
    /// Server stream header and features offering STARTTLS.
    const XMPP_FEATURES: &[u8] = b"<?xml version='1.0'?><stream:stream from='example.org' \
        version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>\
        <stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/>\
        </starttls></stream:features>";

    /// The XMPP dialogue opens a stream to the host, sends `starttls` and
    /// accepts `proceed`, even when the features arrive in pieces.
    #[tokio::test]
    async fn xmpp_upgrade() {
        let (addr, got) = xmpp_server(&[
            (XMPP_OPEN, XMPP_FEATURES),
            (
                XMPP_STARTTLS,
                b" <proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
            ),
        ])
        .await;
        upgrade_with(Starttls::Xmpp, addr).await.unwrap();
        let got = got.await.unwrap();
        assert!(got.contains("to='example.org'"), "{got}");
    }

    /// The `to` address is escaped, and features split across reads are
    /// reassembled.
    #[tokio::test]
    async fn xmpp_split_features() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let (head, tail) = XMPP_FEATURES.split_at(150);
            s.write_all(head).await.unwrap();
            s.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            s.write_all(tail).await.unwrap();
            let mut got = Vec::new();
            while !got.ends_with(XMPP_STARTTLS.as_bytes()) {
                let mut buf = [0; 1024];
                let n = s.read(&mut buf).await.unwrap();
                assert!(n > 0);
                got.extend_from_slice(&buf[..n]);
            }
            s.write_all(b"<proceed xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"></proceed>")
                .await
                .unwrap();
            String::from_utf8(got).unwrap()
        });
        let mut stream = TcpStream::connect(addr).await.unwrap();
        Starttls::Xmpp
            .upgrade(&mut stream, Vec::new(), "a'b<c")
            .await
            .unwrap();
        let got = server.await.unwrap();
        assert!(got.contains("to='a&apos;b&lt;c'"), "{got}");
    }

    /// XMPP refusals, stream errors, garbage and injected bytes are connect
    /// errors.
    #[tokio::test]
    async fn xmpp_errors() {
        let cases: [(XmppScript, &str); 9] = [
            (
                &[(
                    XMPP_OPEN,
                    b"<stream:stream><stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>",
                )],
                "does not offer STARTTLS",
            ),
            (
                &[(
                    XMPP_OPEN,
                    b"<stream:stream><stream:features><starttls xmlns='urn:example'/><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>",
                )],
                "does not offer STARTTLS",
            ),
            (
                &[
                    (XMPP_OPEN, XMPP_FEATURES),
                    (XMPP_STARTTLS, b"<proceed/>"),
                ],
                "starttls with \"<proceed/>\"",
            ),
            (
                &[(
                    XMPP_OPEN,
                    b"<stream:stream><stream:error><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>",
                )],
                "stream error host-unknown",
            ),
            (
                &[(XMPP_OPEN, b"<stream:stream></stream:stream>")],
                "no stream features",
            ),
            (&[(XMPP_OPEN, b"SSH-2.0-x\r\n")], "closed the connection"),
            (&[(XMPP_OPEN, b"\xff\xfe<stream:features/>")], "invalid UTF-8"),
            (
                &[
                    (XMPP_OPEN, XMPP_FEATURES),
                    (
                        XMPP_STARTTLS,
                        b"<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:stream>",
                    ),
                ],
                "starttls with \"<failure",
            ),
            (
                &[
                    (XMPP_OPEN, XMPP_FEATURES),
                    (
                        XMPP_STARTTLS,
                        b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/><message/>",
                    ),
                ],
                "data after its STARTTLS reply",
            ),
        ];
        for (script, expected) in cases {
            let (addr, _got) = xmpp_server(script).await;
            let Err(ProbeError::Connect(e)) = upgrade_with(Starttls::Xmpp, addr).await else {
                panic!("XMPP upgrade accepted {script:?}");
            };
            assert!(e.to_string().contains(expected), "{e}");
        }
    }

    /// Replies made of empty lines still hit the size limit, since line
    /// endings count towards it.
    #[tokio::test]
    async fn empty_line_flood() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let flood = "\r\n".repeat(MAX_REPLY);
        for (protocol, head) in [
            (Starttls::Ftp, "220-hi\r\n"),
            (Starttls::Pop3, "+OK hi\r\n+OK\r\n"),
        ] {
            let mut stream = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let early = format!("{head}{flood}").into_bytes();
            let Err(ProbeError::Connect(e)) = protocol.upgrade(&mut stream, early, "").await else {
                panic!("{protocol} accepted an endless reply");
            };
            assert!(e.to_string().contains("exceeds"), "{e}");
        }
    }

    /// SMTP and FTP refusal diagnostics escape terminal control characters.
    #[test]
    fn refusal_controls_are_escaped() {
        let reply = Reply {
            code: 500,
            lines: vec!["bad \x1b[2J\rhidden".into()],
        };
        let error = expect(&reply, 220, "greeting").unwrap_err().to_string();
        assert!(!error.contains('\x1b'));
        assert!(!error.contains('\r'));
        assert!(error.contains("\\u{1b}"));
    }

    /// Runs `protocol` against each script and checks the error mentions
    /// the expected text.
    async fn assert_errors(protocol: Starttls, cases: &[(Script, &str)]) {
        for &(script, expected) in cases {
            let (addr, _got) = server(script).await;
            let Err(ProbeError::Connect(e)) = upgrade_with(protocol, addr).await else {
                panic!("{protocol} upgrade accepted {script:?}");
            };
            assert!(e.to_string().contains(expected), "{e}");
        }
    }

    /// The dialogue sends EHLO and STARTTLS and accepts a multi-line
    /// greeting and EHLO reply.
    #[tokio::test]
    async fn smtp_upgrade() {
        let (addr, got) = server(&[
            (None, b"220-mx.example ESMTP\r\n220 ready\r\n"),
            (
                Some("EHLO testls.invalid"),
                b"250-mx.example\r\n250-PIPELINING\r\n250-starttls\r\n250 8BITMIME\r\n",
            ),
            (Some("STARTTLS"), b"220 2.0.0 go ahead\r\n"),
        ])
        .await;
        upgrade(addr).await.unwrap();
        assert_eq!(got.await.unwrap(), ["EHLO testls.invalid", "STARTTLS"]);
    }

    /// Refusals, missing STARTTLS, garbage and injected bytes are connect
    /// errors.
    #[tokio::test]
    async fn smtp_errors() {
        let cases: [(Script, &str); 6] = [
            (&[(None, b"554 go away\r\n")], "greeting with 554 go away"),
            (&[(None, b"SSH-2.0-x\r\n")], "malformed server reply"),
            (&[(None, b"220 hi")], "closed the connection"),
            (
                &[
                    (None, b"220 hi\r\n"),
                    (Some("EHLO testls.invalid"), b"250-mx\r\n250 SIZE 1\r\n"),
                ],
                "does not offer STARTTLS",
            ),
            (
                &[
                    (None, b"220 hi\r\n"),
                    (Some("EHLO testls.invalid"), b"250-mx\r\n250 STARTTLS\r\n"),
                    (Some("STARTTLS"), b"454 TLS not available\r\n"),
                ],
                "STARTTLS with 454",
            ),
            (
                &[
                    (None, b"220 hi\r\n"),
                    (Some("EHLO testls.invalid"), b"250-mx\r\n250 STARTTLS\r\n"),
                    (Some("STARTTLS"), b"220 go\r\n250 injected\r\n"),
                ],
                "data after its STARTTLS reply",
            ),
        ];
        assert_errors(Starttls::Smtp, &cases).await;
    }

    /// Mixed codes within one reply are rejected.
    #[tokio::test]
    async fn smtp_mixed_codes() {
        let (addr, _got) = server(&[(None, b"220-hi\r\n250 there\r\n")]).await;
        let Err(ProbeError::Connect(e)) = upgrade(addr).await else {
            panic!("accepted mixed codes");
        };
        assert!(e.to_string().contains("malformed"), "{e}");
    }

    /// The IMAP dialogue checks `CAPABILITY` and accepts a tagged `OK`.
    #[tokio::test]
    async fn imap_upgrade() {
        let (addr, got) = server(&[
            (None, b"* OK [CAPABILITY IMAP4rev1] ready\r\n"),
            (
                Some("a CAPABILITY"),
                b"* CAPABILITY IMAP4rev1 starttls LOGINDISABLED\r\na OK done\r\n",
            ),
            (Some("b STARTTLS"), b"b OK Begin TLS negotiation now\r\n"),
        ])
        .await;
        upgrade_with(Starttls::Imap, addr).await.unwrap();
        assert_eq!(got.await.unwrap(), ["a CAPABILITY", "b STARTTLS"]);
    }

    /// IMAP refusals, missing STARTTLS and injected bytes are connect errors.
    #[tokio::test]
    async fn imap_errors() {
        let cases: [(Script, &str); 7] = [
            (&[(None, b"* BYE busy\r\n")], "greeting with \"* BYE busy\""),
            (
                &[
                    (None, b"* OK hi\r\n"),
                    (Some("a CAPABILITY"), b"* CAPABILITY IMAP4rev1\r\na OK\r\n"),
                ],
                "does not offer STARTTLS",
            ),
            (
                &[
                    (None, b"* OK hi\r\n"),
                    (Some("a CAPABILITY"), b"garbage\r\n"),
                ],
                "malformed server reply",
            ),
            (
                &[
                    (None, b"* OK hi\r\n"),
                    (Some("a CAPABILITY"), b"* CAPABILITY STARTTLS\r\na OK\r\n"),
                    (Some("b STARTTLS"), b"b NO not now\r\n"),
                ],
                "STARTTLS with \"b NO not now\"",
            ),
            (
                &[
                    (None, b"* OK hi\r\n"),
                    (Some("a CAPABILITY"), b"* CAPABILITY STARTTLS\r\na OK\r\n"),
                    (Some("b STARTTLS"), b"b OKAY go\r\n"),
                ],
                "STARTTLS with \"b OKAY go\"",
            ),
            (&[(None, b"* OKAY hi\r\n")], "greeting with \"* OKAY hi\""),
            (
                &[
                    (None, b"* OK hi\r\n"),
                    (Some("a CAPABILITY"), b"* CAPABILITY STARTTLS\r\na OK\r\n"),
                    (Some("b STARTTLS"), b"b OK go\r\n* injected\r\n"),
                ],
                "data after its STARTTLS reply",
            ),
        ];
        assert_errors(Starttls::Imap, &cases).await;
    }

    /// The POP3 dialogue reads the multi-line `CAPA` list and sends `STLS`.
    #[tokio::test]
    async fn pop3_upgrade() {
        let (addr, got) = server(&[
            (None, b"+OK<1896.697170952@dbc.mtview.ca.us>\r\n"),
            (Some("CAPA"), b"+OK\r\nTOP\r\nstls\r\nSASL PLAIN\r\n.\r\n"),
            (Some("STLS"), b"+OK Begin TLS negotiation now\r\n"),
        ])
        .await;
        upgrade_with(Starttls::Pop3, addr).await.unwrap();
        assert_eq!(got.await.unwrap(), ["CAPA", "STLS"]);
    }

    /// POP3 refusals, missing STLS and injected bytes are connect errors.
    #[tokio::test]
    async fn pop3_errors() {
        let cases: [(Script, &str); 7] = [
            (&[(None, b"-ERR busy\r\n")], "greeting with \"-ERR busy\""),
            (&[(None, b"+O\r\n")], "greeting with \"+O\""),
            (
                &[(None, b"+OK hi\r\n"), (Some("CAPA"), b"-ERR unknown\r\n")],
                "CAPA with \"-ERR unknown\"",
            ),
            (
                &[
                    (None, b"+OK hi\r\n"),
                    (Some("CAPA"), b"+OK\r\nTOP\r\n.\r\n"),
                ],
                "does not offer STLS",
            ),
            (
                &[
                    (None, b"+OK hi\r\n"),
                    (Some("CAPA"), b"+OK\r\nSTLS\r\n.\r\n"),
                    (Some("STLS"), b"-ERR no\r\n"),
                ],
                "STLS with \"-ERR no\"",
            ),
            (
                &[
                    (None, b"+OK hi\r\n"),
                    (Some("CAPA"), b"+OK\r\nSTLS\r\n.\r\n"),
                    (Some("STLS"), b"+OKAY\r\n"),
                ],
                "STLS with \"+OKAY\"",
            ),
            (
                &[
                    (None, b"+OK hi\r\n"),
                    (Some("CAPA"), b"+OK\r\nSTLS\r\n.\r\n"),
                    (Some("STLS"), b"+OK go\r\n+OK injected\r\n"),
                ],
                "data after its STARTTLS reply",
            ),
        ];
        assert_errors(Starttls::Pop3, &cases).await;
    }

    /// The FTP dialogue accepts a multi-line greeting and sends `AUTH TLS`.
    #[tokio::test]
    async fn ftp_upgrade() {
        let (addr, got) = server(&[
            (
                None,
                b"220-Welcome\r\n  220 is not the end\r\n220 ready\r\n",
            ),
            (Some("AUTH TLS"), b"234 Proceed with negotiation.\r\n"),
        ])
        .await;
        upgrade_with(Starttls::Ftp, addr).await.unwrap();
        assert_eq!(got.await.unwrap(), ["AUTH TLS"]);
    }

    /// FTP refusals, garbage and injected bytes are connect errors.
    #[tokio::test]
    async fn ftp_errors() {
        let cases: [(Script, &str); 7] = [
            (&[(None, b"421 busy\r\n")], "greeting with 421 busy"),
            (&[(None, b"SSH-2.0-x\r\n")], "malformed server reply"),
            (&[(None, b"220\r\n")], "malformed server reply"),
            (&[(None, b"220-hi\r\n221 bye\r\n")], "closed the connection"),
            (&[(None, b"220-hi\r\n220\r\n")], "closed the connection"),
            (
                &[
                    (None, b"220 hi\r\n"),
                    (
                        Some("AUTH TLS"),
                        b"530 Please login with USER and PASS.\r\n",
                    ),
                ],
                "AUTH TLS with 530",
            ),
            (
                &[
                    (None, b"220 hi\r\n"),
                    (Some("AUTH TLS"), b"234 go\r\n200 injected\r\n"),
                ],
                "data after its STARTTLS reply",
            ),
        ];
        assert_errors(Starttls::Ftp, &cases).await;
    }

    /// End of the client's LDAP `StartTLS` request.
    const LDAP_OID: &str = "1.3.6.1.4.1.1466.20037";

    /// The LDAP dialogue sends the `StartTLS` request and accepts a
    /// success response, also with long-form lengths and trailing fields.
    #[tokio::test]
    async fn ldap_upgrade() {
        let replies: [&'static [u8]; 3] = [
            // slapd 2.6: success, empty matched DN and diagnostic.
            b"\x30\x0c\x02\x01\x01\x78\x07\x0a\x01\x00\x04\x00\x04\x00",
            // Long-form lengths, diagnostic text and the response OID.
            b"\x30\x81\x28\x02\x01\x01\x78\x82\x00\x21\x0a\x01\x00\x04\x00\x04\x02ok\
              \x8a\x161.3.6.1.4.1.1466.20037",
            // Empty controls after the response.
            b"\x30\x0e\x02\x01\x01\x78\x07\x0a\x01\x00\x04\x00\x04\x00\xa0\x00",
        ];
        for reply in replies {
            let script = Box::leak(Box::new([(LDAP_OID, reply)]));
            let (addr, got) = xmpp_server(script).await;
            upgrade_with(Starttls::Ldap, addr).await.unwrap();
            let got = got.await.unwrap();
            assert_eq!(got, String::from_utf8_lossy(LDAP_STARTTLS));
        }
    }

    /// Refusals, notices of disconnection, broken BER, unexpected fields,
    /// oversized replies and injected bytes are connect errors.
    #[tokio::test]
    async fn ldap_errors() {
        let cases: &[(&'static [u8], &str)] = &[
            (
                b"\x30\x19\x02\x01\x01\x78\x14\x0a\x01\x34\x04\x00\x04\x0dnot available",
                "result 52 \"not available\"",
            ),
            (
                b"\x30\x0c\x02\x01\x00\x78\x07\x0a\x01\x02\x04\x00\x04\x00",
                "unsolicited notification with result 2",
            ),
            (
                b"\x30\x2a\x02\x01\x00\x78\x25\x0a\x01\x34\x04\x00\x04\x06closed\
                  \x8a\x161.3.6.1.4.1.1466.20036",
                "unsolicited notification with result 52 \"closed\"",
            ),
            (
                b"\x30\x0c\x02\x01\x02\x78\x07\x0a\x01\x00\x04\x00\x04\x00",
                "malformed",
            ),
            (
                b"\x30\x0a\x02\x01\x01\x65\x05\x0a\x01\x00\x04\x00",
                "malformed",
            ),
            (b"\x30\x80\x02\x01\x01\x00\x00", "malformed"),
            (
                b"\x30\x0f\x02\x01\x01\x78\x0a\x0a\x01\x00\x04\x00\x04\x00\x04\x01x",
                "malformed",
            ),
            (
                b"\x30\x0e\x02\x01\x01\x78\x07\x0a\x01\x00\x04\x00\x04\x00\x04\x00",
                "malformed",
            ),
            (
                b"\x30\x11\x02\x01\x01\x78\x0c\x0a\x01\x00\x04\x00\x04\x00\x8a\x031.2",
                "malformed",
            ),
            (
                b"\x30\x10\x02\x01\x01\x78\x0b\x0a\x01\x00\x04\x00\x04\x00\x8b\x02hi",
                "malformed",
            ),
            (
                b"\x30\x0e\x02\x01\x01\x78\x09\x0a\x01\x00\x04\x00\x04\x00\xa3\x00",
                "malformed",
            ),
            (
                b"\x30\x0e\x02\x01\x01\x78\x09\x0a\x01\x0a\x04\x00\x04\x00\xa3\x00",
                "result 10",
            ),
            (b"\x30\x84\x7f\xff\xff\xff", "exceeds"),
            (b"\x30\x83\x01\x00\x00", "exceeds"),
            (b"220 mail.example ESMTP\r\n", "malformed"),
            (b"\x30\x0c\x02\x01\x01\x78", "closed the connection"),
            (
                b"\x30\x0c\x02\x01\x01\x78\x07\x0a\x01\x00\x04\x00\x04\x00\x16\x03\x01",
                "data after its STARTTLS reply",
            ),
        ];
        for &(reply, expected) in cases {
            let script = Box::leak(Box::new([(LDAP_OID, reply)]));
            let (addr, _got) = xmpp_server(script).await;
            let Err(ProbeError::Connect(e)) = upgrade_with(Starttls::Ldap, addr).await else {
                panic!("LDAP upgrade accepted {reply:?}");
            };
            assert!(e.to_string().contains(expected), "{e}");
        }
    }

    /// Fake PostgreSQL server: reads the 8-byte `SSLRequest`, answers with
    /// `reply` and returns what it read.
    async fn postgres_server(
        reply: &'static [u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut got = [0; 8];
            s.read_exact(&mut got).await.unwrap();
            s.write_all(reply).await.unwrap();
            got.to_vec()
        });
        (addr, task)
    }

    /// The client sends `SSLRequest` and accepts `S`.
    #[tokio::test]
    async fn postgres_upgrade() {
        let (addr, got) = postgres_server(b"S").await;
        upgrade_with(Starttls::Postgres, addr).await.unwrap();
        assert_eq!(got.await.unwrap(), POSTGRES_SSL_REQUEST);
    }

    /// Refusals, errors, other bytes, closed connections and injected bytes
    /// are connect errors.
    #[tokio::test]
    async fn postgres_errors() {
        let cases: &[(&'static [u8], &str)] = &[
            (b"N", "does not offer TLS"),
            (b"E\0\0\0\x08SFATAL\0\0", "with an error"),
            (b"H", "unexpected byte 0x48"),
            (b"", "closed the connection"),
            (b"S\x16\x03\x03", "data after its STARTTLS reply"),
        ];
        for &(reply, expected) in cases {
            let (addr, _got) = postgres_server(reply).await;
            let Err(ProbeError::Connect(e)) = upgrade_with(Starttls::Postgres, addr).await else {
                panic!("PostgreSQL upgrade accepted {reply:?}");
            };
            assert!(e.to_string().contains(expected), "{e}");
        }
    }

    /// Builds a MySQL packet with sequence id `seq` around `payload`.
    fn mysql_packet(seq: u8, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(payload.len()).unwrap().to_le_bytes();
        let mut packet = vec![len[0], len[1], len[2], seq];
        packet.extend_from_slice(payload);
        packet
    }

    /// Builds a protocol 10 handshake payload with the lower capability
    /// bytes `caps`, shaped like MariaDB 11.8's greeting.
    fn mysql_greeting(caps: u16) -> Vec<u8> {
        let mut p = vec![10];
        p.extend_from_slice(b"11.8.3-MariaDB-0+deb13u1\0");
        p.extend_from_slice(&[3, 0, 0, 0]); // connection id
        p.extend_from_slice(b"abcdefgh\0"); // auth data and filler
        p.extend_from_slice(&caps.to_le_bytes());
        p.extend_from_slice(&[45, 2, 0, 0xff, 0x81, 21]); // charset, status, caps, auth len
        p.extend_from_slice(&[0; 10]);
        p.extend_from_slice(b"ijklmnopqrst\0mysql_native_password\0");
        p
    }

    /// Fake MySQL server: sends `greeting` and closes its sending side, then
    /// returns up to 36 bytes the client sends.
    async fn mysql_server(greeting: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(&greeting).await.unwrap();
            s.shutdown().await.unwrap();
            let mut got = Vec::new();
            let _ = s.take(36).read_to_end(&mut got).await;
            got
        });
        (addr, task)
    }

    /// The client reads a split greeting, then sends `SSLRequest`.
    #[tokio::test]
    async fn mysql_upgrade() {
        assert_eq!(MYSQL_SSL_REQUEST.len(), 36);
        let (addr, got) = mysql_server(mysql_packet(0, &mysql_greeting(0xfffe))).await;
        upgrade_with(Starttls::Mysql, addr).await.unwrap();
        assert_eq!(got.await.unwrap(), MYSQL_SSL_REQUEST);
    }

    /// Missing TLS, errors, other versions, short or oversized packets,
    /// closed connections and extra bytes are connect errors, and the
    /// client sends nothing.
    #[tokio::test]
    async fn mysql_errors() {
        let mut extra = mysql_packet(0, &mysql_greeting(0xfffe));
        extra.push(0);
        let mut error_packet = vec![0xff, 0x6a, 0x04];
        error_packet.extend_from_slice(b"Host '10.0.0.1' is not allowed");
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (
                mysql_packet(0, &mysql_greeting(0xfffe & !0x0800)),
                "does not offer TLS",
            ),
            (
                mysql_packet(0, &error_packet),
                "error 1130 \"Host '10.0.0.1'",
            ),
            (mysql_packet(0, b"\x09old\0"), "protocol version 9"),
            (mysql_packet(0, b"\x0a11.8"), "malformed MySQL handshake"),
            (
                mysql_packet(0, &mysql_greeting(0xfffe)[..41]),
                "malformed MySQL handshake",
            ),
            (
                mysql_packet(0, &mysql_greeting(0xfffe)[..56]),
                "malformed MySQL handshake",
            ),
            (
                mysql_packet(0, b"\x0a11.8\0\x03\0\0\0"),
                "malformed MySQL handshake",
            ),
            (
                mysql_packet(1, &mysql_greeting(0xfffe)),
                "malformed MySQL handshake",
            ),
            (vec![0, 0, 0, 0], "malformed MySQL handshake"),
            (vec![0xff, 0xff, 0xff, 0], "exceeds"),
            (
                mysql_packet(0, &mysql_greeting(0xfffe))[..20].to_vec(),
                "closed the connection",
            ),
            (extra, "data after its STARTTLS reply"),
        ];
        for (greeting, expected) in cases {
            let (addr, got) = mysql_server(greeting).await;
            let Err(ProbeError::Connect(e)) = upgrade_with(Starttls::Mysql, addr).await else {
                panic!("MySQL upgrade accepted greeting for {expected}");
            };
            assert!(e.to_string().contains(expected), "{e}");
            assert!(got.await.unwrap().is_empty(), "{expected}");
        }
    }

    /// Names round-trip through `FromStr`, case-insensitively.
    #[test]
    fn names() {
        for p in Starttls::ALL {
            assert_eq!(p.as_str().to_uppercase().parse::<Starttls>(), Ok(p));
        }
        assert!("gopher".parse::<Starttls>().is_err());
        assert_eq!(Starttls::Smtp.default_port(), 25);
        assert_eq!(Starttls::Imap.default_port(), 143);
        assert_eq!(Starttls::Pop3.default_port(), 110);
        assert_eq!(Starttls::Ftp.default_port(), 21);
        assert_eq!(Starttls::Xmpp.default_port(), 5222);
        assert_eq!(Starttls::Ldap.default_port(), 389);
        assert_eq!(Starttls::Postgres.default_port(), 5432);
        assert_eq!(Starttls::Mysql.default_port(), 3306);
    }
}
