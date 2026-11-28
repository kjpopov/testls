#![no_main]
//! Exercise classic capture framing and bounded TCP/TLS hello decoding.

use libfuzzer_sys::fuzz_target;
use testls_wire::pcap::{Capture, inspect};

fuzz_target!(|bytes: &[u8]| {
    let _ = inspect(bytes, |observation| {
        std::hint::black_box(observation);
    });
    if let Ok(capture) = Capture::new(bytes) {
        for packet in capture {
            std::hint::black_box(packet).ok();
        }
    }
});
