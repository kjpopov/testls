//! Browser bindings for offline classic pcap inspection. No socket or file I/O.

use std::fmt::Write as _;

use js_sys::Uint8Array;
use testls_wire::pcap;
use wasm_bindgen::prelude::*;

/// Maximum file size in bytes. Call before reading a browser `File` into memory.
#[must_use]
#[wasm_bindgen(js_name = maxCaptureBytes)]
pub fn max_capture_bytes() -> u32 {
    pcap::MAX_CAPTURE_BYTES
}

/// Return the same observations as the CLI, limiting lines retained for display.
/// Always validate to EOF and include the full observation count on success.
fn report(bytes: &[u8], rows: usize) -> Result<String, testls_wire::DecodeError> {
    let mut output = String::new();
    let mut total = 0;
    let packets = pcap::inspect(bytes, |observation| {
        if total < rows {
            writeln!(output, "{observation}").expect("writing to String cannot fail");
        }
        total += 1;
    })?;
    if total > rows {
        writeln!(output, "Additional hellos omitted: {}", total - rows)
            .expect("writing to String cannot fail");
    }
    writeln!(
        output,
        "Packets read: {packets}; visible TLS hellos: {total}"
    )
    .expect("writing to String cannot fail");
    Ok(output)
}

/// Inspect a local capture in memory. Returns plain text for a `textContent` sink.
/// The first 2,048 observations are displayed; the summary counts all hellos.
///
/// # Errors
/// Throws a JavaScript error for an oversized, malformed or unsupported capture.
#[wasm_bindgen(js_name = inspectCapture)]
pub fn inspect_capture(bytes: &Uint8Array) -> Result<String, JsError> {
    if bytes.length() > max_capture_bytes() {
        return Err(JsError::new("capture exceeds 64 MiB"));
    }
    report(&bytes.to_vec(), 2048).map_err(|e| JsError::new(&e.to_string()))
}
