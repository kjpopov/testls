//! Entry points for the fuzz targets in `fuzz/`; not part of the public API.
//!
//! The parsers they reach are crate-private, so each target calls one of
//! these functions with attacker-controlled bytes and ignores the result.

use tokio::io::{AsyncWriteExt, duplex};

use crate::Starttls;
use crate::http::{complete_head, parse_head};

/// Largest server input a fuzzed STARTTLS dialogue accepts, in bytes; it
/// bounds the in-memory pipe so the dialogue's own writes never block.
const MAX_INPUT: usize = 128 * 1024;

/// Feeds `data` to the HTTP response head parser the way the probe does:
/// find the end of the header section, then parse it.
pub fn http_head(data: &[u8]) {
    if let Ok(Some(end)) = complete_head(data) {
        let _ = parse_head(&data[..end]);
    }
    let _ = parse_head(data);
}

/// Runs the `protocol` STARTTLS dialogue against a server that sends `data`
/// and then closes its sending side.
pub async fn starttls(protocol: Starttls, data: &[u8]) {
    let (mut client, mut server) = duplex(2 * MAX_INPUT);
    let data = &data[..data.len().min(MAX_INPUT)];
    if server.write_all(data).await.is_err() || server.shutdown().await.is_err() {
        return;
    }
    let _ = protocol
        .upgrade(&mut client, Vec::new(), "example.test")
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete head and a truncated one both go through without panics.
    #[test]
    fn http_head_accepts_any_bytes() {
        http_head(b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n");
        http_head(b"HTTP/1.1 200 OK\r\nServer");
        http_head(b"\xff\x00\r\n\r\n");
        http_head(b"");
    }

    /// Every protocol survives empty, short and oversized server input.
    #[tokio::test]
    async fn starttls_ends_on_any_bytes() {
        let big = vec![b'a'; MAX_INPUT + 10];
        for protocol in Starttls::ALL {
            starttls(protocol, b"").await;
            starttls(protocol, b"220 hi\r\n").await;
            starttls(protocol, &big).await;
        }
    }
}
