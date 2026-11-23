//! Runs a STARTTLS dialogue against a server that sends arbitrary bytes. The
//! first byte picks the protocol, the rest is the server's reply stream.

#![no_main]

use libfuzzer_sys::fuzz_target;
use testls_probe::Starttls;

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let protocol = Starttls::ALL[usize::from(first) % Starttls::ALL.len()];
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    runtime.block_on(testls_probe::fuzzing::starttls(protocol, rest));
});
