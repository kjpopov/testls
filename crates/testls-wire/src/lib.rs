//! TLS record and handshake codec: `ClientHello` builders and `ServerHello`,
//! `Alert`, `Certificate`, and `ServerKeyExchange` parsers. No I/O.

mod client_hello;
mod codec;
mod key_exchange;
pub mod pcap;
mod record;
mod server;
mod version;

pub use client_hello::{
    CONTENT_HANDSHAKE, ClientHello, Extension, HANDSHAKE_CLIENT_HELLO, KeyShareEntry,
    MAX_FRAGMENT_LEN, Ssl2ClientHello, ext,
};
pub use codec::{DecodeError, EncodeError};
pub use key_exchange::{DheParams, EcdheParams};
pub use record::{AnyRecord, ContentType, Record, Ssl2Record, parse_record};
pub use server::{
    Alert, AlertLevel, HRR_RANDOM, HandshakeMessage, RawExtension, ServerHello, Ssl2ServerHello,
    handshake_type, parse_certificate_list, parse_handshake,
};
pub use version::ProtocolVersion;
