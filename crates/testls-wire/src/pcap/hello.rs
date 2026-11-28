//! First cleartext hello in each observed TCP direction. Require its SYN so
//! that a capture starting inside ciphertext cannot masquerade as a handshake.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    time::Duration,
};

use super::{Capture, tcp};
use crate::{
    DecodeError, MAX_FRAGMENT_LEN, ProtocolVersion, ServerHello, codec::Reader, ext,
    parse_handshake,
};

/// Details from one visible TLS hello, not evidence of a completed handshake.
#[derive(Debug, PartialEq, Eq)]
pub enum Hello {
    /// Client offer; in TLS 1.3 the legacy field is TLS 1.2 (RFC 8446 §4.1.2).
    Client {
        /// Value in the legacy version field.
        legacy_version: ProtocolVersion,
        /// Ordered list in `supported_versions`, empty if absent.
        offered_versions: Vec<ProtocolVersion>,
        /// Number of cipher suite entries offered by the client.
        cipher_count: usize,
    },
    /// Values in a `ServerHello` or `HelloRetryRequest` (RFC 8446 §4.1.3–4).
    Server {
        /// Selected version, taken from `supported_versions` if present.
        version: ProtocolVersion,
        /// Cipher suite code point as transmitted.
        cipher_suite: u16,
        /// Whether the random identifies a `HelloRetryRequest`.
        retry: bool,
    },
}

/// A parsed hello, timestamped at the packet that completed the observation.
#[derive(Debug, PartialEq, Eq)]
pub struct Observation {
    /// Packet timestamp from the capture.
    pub timestamp: Duration,
    /// Sending endpoint.
    pub source: SocketAddr,
    /// Receiving endpoint.
    pub destination: SocketAddr,
    /// Visible, unencrypted fields only.
    pub hello: Hello,
}

/// Parse the client vectors from RFC 5246 §7.4.1.2 and RFC 8446 §4.2.1.
fn client(body: &[u8]) -> Option<Hello> {
    let mut r = Reader::new(body);
    let legacy_version = ProtocolVersion(r.u16("client_version").ok()?);
    r.take(32, "random").ok()?;
    if r.prefixed(1, "session_id").ok()?.rest().len() > 32 {
        return None;
    }
    let suites = r.prefixed(2, "cipher_suites").ok()?.rest();
    if suites.is_empty()
        || !suites.len().is_multiple_of(2)
        || r.prefixed(1, "compression_methods").ok()?.is_empty()
    {
        return None;
    }
    let mut offered_versions = Vec::new();
    if !r.is_empty() {
        let mut extensions = r.prefixed(2, "extensions").ok()?;
        while !extensions.is_empty() {
            let typ = extensions.u16("extension_type").ok()?;
            let mut data = extensions.prefixed(2, "extension_data").ok()?;
            if typ == ext::SUPPORTED_VERSIONS {
                let mut list = data.prefixed(1, "versions").ok()?;
                if !offered_versions.is_empty() || list.is_empty() || !data.is_empty() {
                    return None;
                }
                while !list.is_empty() {
                    offered_versions.push(ProtocolVersion(list.u16("version").ok()?));
                }
            }
        }
    }
    r.finish("client_hello").ok()?;
    Some(Hello::Client {
        legacy_version,
        offered_versions,
        cipher_count: suites.len() / 2,
    })
}

/// At most 128 directions, each retaining at most 80 KiB of TCP prefix and
/// 64 KiB of first-handshake body plus its header (independent of pcap size).
const MAX_DIRECTIONS: usize = 128;
const MAX_PREFIX: usize = 80 * 1024;
const MAX_MESSAGE: usize = 64 * 1024;

/// Contiguous bytes starting at the observed SYN, plus handshake fragments
/// from completed TLS records. Cursors advance monotonically across segments.
struct Prefix {
    first: u32,
    bytes: Vec<u8>,
    consumed: usize,
    handshake: Vec<u8>,
}

impl Prefix {
    /// Incorporate overlapping retransmissions only if the overlap is identical.
    /// `Err` abandons this direction on gaps, conflicts, non-TLS or size limits.
    fn accept(&mut self, seq: u32, payload: &[u8]) -> Result<Option<Hello>, ()> {
        let offset = seq.wrapping_sub(self.first) as usize;
        let old = self.bytes.get(offset..).ok_or(())?;
        let overlap = old.len().min(payload.len());
        if old[..overlap] != payload[..overlap] {
            return Err(());
        }
        let new = &payload[overlap..];
        let count = new.len().min(MAX_PREFIX - self.bytes.len());
        self.bytes.extend_from_slice(&new[..count]);
        while let Some((&typ, rest)) = self.bytes[self.consumed..].split_first() {
            if typ != 22 {
                return Err(());
            }
            let Some(([3, 0..=3, hi, lo], data)) = rest.split_first_chunk::<4>() else {
                if rest.len() >= 4 {
                    return Err(());
                }
                break;
            };
            let len = usize::from(u16::from_be_bytes([*hi, *lo]));
            if len == 0 || len > MAX_FRAGMENT_LEN {
                return Err(());
            }
            let Some(fragment) = data.get(..len) else {
                break;
            };
            self.consumed += 5 + len;
            // A later message may share the final record; retain only the first.
            self.handshake
                .extend_from_slice(&fragment[..len.min(MAX_MESSAGE + 4 - self.handshake.len())]);
            if !matches!(self.handshake[0], 1 | 2) {
                return Err(());
            }
            if let Some((msg, _)) = parse_handshake(&self.handshake).map_err(|_| ())? {
                if msg.typ == 1 {
                    return client(msg.body).ok_or(()).map(Some);
                }
                let h = ServerHello::parse(msg.body).map_err(|_| ())?;
                return Ok(Some(Hello::Server {
                    version: h.negotiated_version().map_err(|_| ())?,
                    cipher_suite: h.cipher_suite,
                    retry: h.is_hello_retry_request(),
                }));
            }
            if self.handshake.len() == MAX_MESSAGE + 4 {
                return Err(());
            }
        }
        if self.bytes.len() == MAX_PREFIX {
            return Err(());
        }
        Ok(None)
    }
}

type Direction = (SocketAddr, SocketAddr);

/// Retire payload buffers immediately but remember the last 1,024 finished
/// directions by endpoint pair and first sequence number (RFC 9293 §3.4).
#[derive(Default)]
struct Directions {
    active: HashMap<Direction, Prefix>,
    retired: HashSet<(Direction, u32)>,
    retirement_order: VecDeque<(Direction, u32)>,
}

impl Directions {
    /// Drop this direction's bytes and keep a bounded duplicate-detection window.
    fn retire(&mut self, key: Direction) {
        if let Some(p) = self.active.remove(&key) {
            let id = (key, p.first);
            self.retired.insert(id);
            self.retirement_order.push_back(id);
            if self.retirement_order.len() > 1024
                && let Some(oldest) = self.retirement_order.pop_front()
            {
                self.retired.remove(&oldest);
            }
        }
    }

    /// Accept a new sequence space, an active SYN retransmission, or neither.
    fn start(&mut self, key: Direction, first: u32, ack: bool) -> bool {
        if self.retired.contains(&(key, first)) {
            return false;
        }
        if self.active.get(&key).is_some_and(|p| p.first == first) {
            return true;
        }
        self.retire(key);
        if !ack {
            self.retire((key.1, key.0));
        }
        if self.active.len() >= MAX_DIRECTIONS {
            return false;
        }
        self.active.insert(
            key,
            Prefix {
                first,
                bytes: Vec::new(),
                consumed: 0,
                handshake: Vec::new(),
            },
        );
        true
    }
}

/// Inspect classic Ethernet II or raw IP pcap records in capture order. Calls
/// `observe` once the initial cleartext hello in a SYN-anchored TCP direction is
/// complete. Stops that direction on a gap, conflicting overlap, or size limit;
/// ignores IP fragments, IPv6 extension headers and mid-stream captures.
/// At most 128 directions are buffered; further SYNs are skipped at capacity.
/// Retransmitted SYNs for the most recent 1,024 retired directions are ignored.
/// Returns the number of packet records read, including skipped packets.
///
/// # Errors
/// Returns a framing error for malformed pcap input or an unsupported link
/// type. Earlier observations may already have been delivered to the callback.
pub fn inspect(bytes: &[u8], mut observe: impl FnMut(Observation)) -> Result<usize, DecodeError> {
    let capture = Capture::new(bytes)?;
    let link = capture.link_type();
    if !matches!(link, 1 | 101) {
        return Err(DecodeError::Invalid {
            field: "pcap link type (expected Ethernet or raw IP)",
        });
    }
    let fcs = usize::from(capture.fcs_bytes().unwrap_or(0));
    let mut streams = Directions::default();
    let mut packets = 0;
    for packet in capture {
        let packet = packet?;
        packets += 1;
        // A rewritten file can preserve a short original length (§5). In that
        // case the available packet data is the minimum possible wire size.
        let original = (packet.original_len as usize).max(packet.data.len());
        let Some(wire_len) = original.checked_sub(fcs) else {
            continue;
        };
        let frame = &packet.data[..packet.data.len().min(wire_len)];
        let Some(s) = tcp::segment(link, frame) else {
            continue;
        };
        let key = s.endpoints;
        if s.flags & 4 != 0 {
            streams.retire(key);
            streams.retire((key.1, key.0));
            continue;
        }
        let syn = s.flags & 2 != 0;
        let seq = s.sequence.wrapping_add(u32::from(syn));
        if syn && !streams.start(key, seq, s.flags & 16 != 0) {
            continue;
        }
        let Some(p) = streams.active.get_mut(&key) else {
            continue;
        };
        if !s.data.is_empty() {
            match p.accept(seq, s.data) {
                Ok(None) => (),
                Ok(Some(hello)) => {
                    observe(Observation {
                        timestamp: packet.timestamp,
                        source: key.0,
                        destination: key.1,
                        hello,
                    });
                    streams.retire(key);
                }
                Err(()) => {
                    streams.retire(key);
                }
            }
        }
        if s.flags & 1 != 0 {
            streams.retire(key);
        }
    }
    Ok(packets)
}
