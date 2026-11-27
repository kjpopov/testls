# Using the native scan API

Use `testls-scan`, `testls-probe` and `testls-checks` at matching versions.
Run the future on a Tokio runtime with I/O and timers enabled. Supply one
resolved socket address, the DNS name to check, and the roots you trust.
For example, add these dependencies to a binary crate:

```toml
[dependencies]
testls-scan = "0.6.2"
testls-probe = "0.6.2"
testls-checks = "0.6.2"
tokio = { version = "1", features = ["macros", "rt", "net", "time"] }
```

Then check a local TLS service on port 8443 from `src/main.rs`:

```no_run
use testls_checks::TrustStore;
use testls_probe::Transport;
use testls_scan::{Options, ScanProfile, scan};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = "127.0.0.1:8443".parse()?;
    let mut options = Options::default();
    options.sni = Some("localhost".into());
    options.profile = ScanProfile::Quick;
    let result = scan(Transport::new(target), &options, &TrustStore::webpki(),
        &mut |event| println!("finished {}", event.section()),
    ).await?;

    println!("grade: {} (incomplete: {})", result.grade, result.grade.incomplete);
    for finding in &result.findings {
        println!("{}: {}", finding.id, finding.severity);
    }
    Ok(())
}
```

`scan` returns `Err(ScanError::NoProtocol)` when every protocol attempt
errors. A successful return can still contain an untrusted certificate,
unmeasured sections, or an incomplete grade. Inspect the typed section
results and findings rather than treating `Ok` as a pass.

The progress callback borrows each section for the duration of the call;
retain the final `Scan` for owned results. Host resolution, multi-target
iteration, suppressions, baselines and process exit codes are the caller's
responsibility. Use a wildcard arm when matching non-exhaustive types.
