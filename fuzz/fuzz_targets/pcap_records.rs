#![no_main]
//! Exercise classic capture headers and all subsequent record boundaries.

use libfuzzer_sys::fuzz_target;
use testls_wire::pcap::Capture;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(capture) = Capture::new(bytes) {
        for packet in capture {
            std::hint::black_box(packet).ok();
        }
    }
});
