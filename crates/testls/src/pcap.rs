//! Offline capture import. This path reads one local file and writes text only.

use std::{
    fs::File,
    io::{self, Read as _},
    path::Path,
    process::ExitCode,
};

use testls_wire::pcap;

/// Inspect the bounded input and print an explicit count even for an empty observation set.
fn import(file: &Path, out: &mut impl io::Write) -> io::Result<()> {
    let mut bytes = Vec::new();
    File::open(file)?
        .take(u64::from(pcap::MAX_CAPTURE_BYTES) + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > pcap::MAX_CAPTURE_BYTES as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "capture exceeds 64 MiB",
        ));
    }
    let mut count = 0usize;
    let mut written = Ok(());
    let packets = pcap::inspect(&bytes, |observation| {
        if written.is_ok() {
            written = writeln!(out, "{observation}");
        }
        count += 1;
    })
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    written?;
    writeln!(out, "Packets read: {packets}; visible TLS hellos: {count}")?;
    out.flush()
}

/// Map read, decode and output errors to the CLI error code.
pub(super) fn command(file: &Path) -> ExitCode {
    match import(file, &mut io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error reading capture: {e}");
            ExitCode::from(2)
        }
    }
}
