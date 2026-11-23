//! Parses arbitrary bytes as an HTTP/1.x response head.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    testls_probe::fuzzing::http_head(data);
});
