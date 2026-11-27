//! Offline capture import. This path reads one local file and writes text only.

use std::{
    fs::File,
    io::{self, Read as _},
    path::Path,
    process::ExitCode,
};

use testls_wire::pcap::{self, Hello, Observation};

/// Limit both ordinary files and inputs whose size changes after opening.
const MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Render numeric endpoints and visible handshake fields only, in capture order.
fn line(out: &mut impl io::Write, observation: Observation) -> io::Result<()> {
    let t = observation.timestamp;
    write!(
        out,
        "{}.{:09} {} -> {}  ",
        t.as_secs(),
        t.subsec_nanos(),
        observation.source,
        observation.destination
    )?;
    match observation.hello {
        Hello::Client {
            legacy_version,
            offered_versions,
            cipher_count,
        } => {
            write!(
                out,
                "ClientHello legacy={legacy_version} offered_ciphers={cipher_count}"
            )?;
            if !offered_versions.is_empty() {
                write!(out, " supported_versions=")?;
                for (i, version) in offered_versions.iter().enumerate() {
                    if i != 0 {
                        write!(out, ",")?;
                    }
                    write!(out, "{version}")?;
                }
            }
            writeln!(out)
        }
        Hello::Server {
            version,
            cipher_suite,
            retry,
        } => {
            let kind = if retry {
                "HelloRetryRequest"
            } else {
                "ServerHello"
            };
            writeln!(out, "{kind} selected={version} cipher=0x{cipher_suite:04x}")
        }
    }
}

/// Inspect the bounded input and print an explicit count even for an empty observation set.
fn import(file: &Path, out: &mut impl io::Write) -> io::Result<()> {
    let mut bytes = Vec::new();
    File::open(file)?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "capture exceeds 64 MiB",
        ));
    }
    let mut count = 0usize;
    let mut written = Ok(());
    let packets = pcap::inspect(&bytes, |observation| {
        if written.is_ok() {
            written = line(out, observation);
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
