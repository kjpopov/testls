//! `testls` command-line interface.

mod baseline;
mod config;
mod profile;
mod revocation;
mod target;

use std::fmt::Write as _;
use std::io::{IsTerminal as _, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::builder::TypedValueParser as _;
use clap::{CommandFactory as _, Parser, Subcommand};
use testls_checks::{
    Finding, Policy, PolicyInput, RevocationCheck, Severity, TrustStore, Vulnerability,
    assess_vulnerabilities, baseline_findings, certificate_findings, cipher_findings,
    describe_certificate, details_findings, explain, explanations, http_extra_findings,
    http_findings, intolerance_findings, is_trusted, key_exchange_findings, ocsp_findings,
    policy_findings, post_quantum_readiness, protocol_findings, revocation_findings,
    revocation_urls, trust_findings, verify_ocsp_response, vulnerability_findings,
};
use testls_probe::{
    CipherResult, Fetcher, HandshakeDetails, HttpResponse, Intolerance, KeyExchangeResult,
    ProtocolResult, ProtocolSupport, Starttls, Transport, detect_protocols, enumerate_ciphers,
    fetch_certificates, fetch_http_headers, probe_details, probe_features, probe_intolerance,
    probe_key_exchange,
};
use testls_report::text::{self, CertificateSection, CipherSection, KeyExchangeSection};
use testls_report::{ColorChoice, Format, Painter, csv, html, json, junit, markdown, sarif};
use testls_wire::ProtocolVersion;

use baseline::Baseline;
use config::Config;
use profile::ScanProfile;
use target::{Host, ProxySpec, ResolveOverride, Target, TargetSpec};
use testls_report::json::Suppressed;

/// TLS/SSL scanner inspired by testssl.sh.
#[derive(Debug, Parser)]
#[command(
    version,
    about,
    max_term_width = 100,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
struct Cli {
    /// Extra commands; without one, `testls` scans the target.
    #[command(subcommand)]
    command: Option<Command>,

    /// Targets: host, host:port, [ipv6]:port, https:// URL, or a CIDR range
    /// such as `192.0.2.0/28` or `[2001:db8::/120]:8443` (at most 16 host
    /// bits). Several targets are scanned one after another.
    #[arg(required_unless_present = "file", value_name = "TARGET", value_parser = target_arg)]
    targets: Vec<String>,

    /// Read more targets from FILE, one per line in the same forms; blank
    /// lines and lines starting with `#` are skipped.
    #[arg(long, value_name = "FILE")]
    file: Option<PathBuf>,

    /// Server name to send in SNI (defaults to the target host name).
    #[arg(long)]
    sni: Option<String>,

    /// TCP connect timeout in seconds.
    #[arg(long, default_value_t = 5, value_name = "SECS")]
    connect_timeout: u64,

    /// Per-probe read timeout in seconds.
    #[arg(long, default_value_t = 10, value_name = "SECS")]
    read_timeout: u64,

    /// Exit with status 1 if any finding is at least this severe.
    #[arg(long, default_value_t = Severity::High, value_name = "SEVERITY",
          value_parser = clap::builder::PossibleValuesParser::new(Severity::ALL.map(Severity::as_str))
              .map(|s| s.parse::<Severity>().expect("listed value")))]
    fail_on: Severity,

    /// Trust only the root certificates in this PEM file instead of the
    /// bundled Mozilla roots.
    #[arg(long, value_name = "FILE")]
    ca_file: Option<PathBuf>,

    /// Trust the operating system's root certificates instead of the
    /// bundled Mozilla roots (`SSL_CERT_FILE` / `SSL_CERT_DIR` override the
    /// platform store).
    #[arg(long, conflicts_with = "ca_file")]
    system_roots: bool,

    /// Also ask the certificate issuer's OCSP responder, falling back to its
    /// CRLs, whether the leaf certificate is revoked. This contacts servers
    /// other than the target.
    #[arg(long)]
    revocation: bool,

    /// Permit this exact IP:port for revocation fetches in addition to public
    /// HTTP endpoints on port 80. Use only for a trusted issuer endpoint.
    #[arg(long, value_name = "IP:PORT")]
    revocation_endpoint: Vec<SocketAddr>,

    /// How much to scan: `quick` checks protocols, cipher suites and the
    /// certificate only; `default` runs every probe of the target; `full`
    /// adds `--revocation` and `--all-addresses`.
    #[arg(long, default_value_t = ScanProfile::Default, value_name = "PROFILE",
          value_parser = clap::builder::PossibleValuesParser::new(ScanProfile::ALL.map(ScanProfile::as_str))
              .map(|s| s.parse::<ScanProfile>().expect("listed value")))]
    profile: ScanProfile,

    /// Also report everything a configuration policy does not allow, as
    /// `policy.*` findings. Repeat to check several policies.
    #[arg(long = "policy", value_name = "POLICY",
          value_parser = clap::builder::PossibleValuesParser::new(Policy::ALL.map(Policy::as_str))
              .map(|s| s.parse::<Policy>().expect("listed value")))]
    policies: Vec<Policy>,

    /// Scan every A/AAAA address a host name resolves to, and warn when
    /// the addresses differ in protocols, cipher suites or certificate.
    #[arg(long)]
    all_addresses: bool,

    /// Connect to ADDR instead of looking up HOST when it is scanned on
    /// PORT, keeping HOST for SNI (curl-style `HOST:PORT:ADDR[,ADDR...]`;
    /// repeatable). Only target lookups are overridden.
    #[arg(long, value_name = "HOST:PORT:ADDR")]
    resolve: Vec<ResolveOverride>,

    /// Connect from this local IP address, for the target and for
    /// revocation lookups. Target addresses of the other address family
    /// are skipped.
    #[arg(long, value_name = "ADDR")]
    source_ip: Option<IpAddr>,

    /// Tunnel all connections through this HTTP proxy with `CONNECT`
    /// (`[http://]HOST:PORT`, no authentication). Target names are still
    /// resolved locally (see `--resolve`); revocation lookups pass host
    /// names to the proxy. With `--source-ip`, only the connection to the
    /// proxy is bound and target addresses are not filtered by family.
    #[arg(long, value_name = "HOST:PORT")]
    proxy: Option<ProxySpec>,

    /// Upgrade each connection with this protocol's STARTTLS command before
    /// the TLS handshake. Targets without a port use the protocol's
    /// standard port (25 for `smtp`, 143 for `imap`, 110 for `pop3`, 21 for
    /// `ftp`, 5222 for `xmpp`, 389 for `ldap`, 5432 for `postgres`, 3306 for
    /// `mysql`), and HTTP headers are not checked. XMPP addresses the stream to the SNI name.
    #[arg(long, value_name = "PROTOCOL",
          value_parser = clap::builder::PossibleValuesParser::new(Starttls::ALL.map(Starttls::as_str))
              .map(|s| s.parse::<Starttls>().expect("listed value")))]
    starttls: Option<Starttls>,

    /// Read suppressions from this TOML file instead of `.testls.toml` in
    /// the working directory (which is optional).
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Compare with a previous `--format json` report: findings it already
    /// lists for the same target are set aside as suppressed, so only new
    /// findings count towards `--fail-on`.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Colour the output: `auto` colours only on a terminal when `NO_COLOR`
    /// is unset.
    #[arg(long, default_value_t = ColorChoice::Auto, value_name = "WHEN",
          value_parser = clap::builder::PossibleValuesParser::new(ColorChoice::ALL.map(ColorChoice::as_str))
              .map(|s| s.parse::<ColorChoice>().expect("listed value")))]
    color: ColorChoice,

    /// Output format: `text` prints sections as they finish, `json` prints
    /// one document at the end, `sarif` prints one SARIF 2.1.0 log of the
    /// findings at the end, `junit` prints one JUnit XML document at the
    /// end with findings at or above `--fail-on` as failures, `markdown`
    /// prints one Markdown summary at the end, `csv` prints one CSV row
    /// per finding at the end, `html` prints one self-contained HTML page at
    /// the end.
    #[arg(long, default_value_t = Format::Text, value_name = "FORMAT",
          value_parser = clap::builder::PossibleValuesParser::new(Format::ALL.map(Format::as_str))
              .map(|s| s.parse::<Format>().expect("listed value")))]
    format: Format,
}

/// Subcommands besides the default scan.
#[derive(Debug, Subcommand)]
enum Command {
    /// Describe a finding id, or list all ids when none is given.
    Explain {
        /// Finding id as shown in brackets in the findings list.
        id: Option<String>,
    },
    /// Print a shell completion script.
    Completions {
        /// Shell to complete for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Print the man page in roff format, or write all pages to a directory.
    Man {
        /// Write `testls.1` and one page per subcommand (such as
        /// `testls-explain.1`) to this directory instead of printing
        /// `testls.1`.
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
}

/// Resolves the target to every distinct socket address it maps to, in
/// resolver order. The first `--resolve` entry matching the target
/// replaces the DNS lookup. With a `source` address, only addresses of
/// its family are kept.
async fn addresses(
    target: &Target,
    overrides: &[ResolveOverride],
    source: Option<IpAddr>,
) -> std::io::Result<Vec<SocketAddr>> {
    let found: Vec<SocketAddr> = match &target.host {
        Host::Ip(ip) => vec![SocketAddr::new(*ip, target.port)],
        Host::Name(_) if let Some(o) = overrides.iter().find(|o| o.matches(target)) => o
            .addrs
            .iter()
            .map(|ip| SocketAddr::new(*ip, target.port))
            .collect(),
        Host::Name(name) => tokio::net::lookup_host((name.as_str(), target.port))
            .await?
            .collect(),
    };
    let mut addrs = Vec::new();
    for addr in found {
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
    if addrs.is_empty() {
        return Err(std::io::Error::other("no addresses found"));
    }
    if let Some(ip) = source {
        addrs.retain(|a| a.is_ipv4() == ip.is_ipv4());
        if addrs.is_empty() {
            return Err(std::io::Error::other(format!(
                "no address in the address family of --source-ip {ip}"
            )));
        }
    }
    Ok(addrs)
}

/// Resolves `--proxy` to the first address of its host, of the family of
/// `source` when given; `None` without a proxy.
async fn proxy_address(
    proxy: Option<&ProxySpec>,
    source: Option<IpAddr>,
) -> std::io::Result<Option<SocketAddr>> {
    let Some(ProxySpec(proxy)) = proxy else {
        return Ok(None);
    };
    let addrs = addresses(proxy, &[], source)
        .await
        .map_err(|e| std::io::Error::new(e.kind(), format!("cannot resolve proxy {proxy}: {e}")))?;
    Ok(addrs.first().copied())
}

/// Reports whether stdout is a terminal that can render ANSI colour.
///
/// On Windows this also turns on virtual terminal processing for the
/// console; a console that refuses it counts as not colour-capable, so
/// `--color auto` falls back to plain text there.
fn colour_terminal() -> bool {
    std::io::stdout().is_terminal() && anstyle_query::windows::enable_ansi_colors().unwrap_or(true)
}

/// Prints `testls explain` output: exit code 0, or 2 for an unknown id.
fn explain_command(id: Option<&str>) -> ExitCode {
    match explain_text(id) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

/// Text for `testls explain`: one finding in detail, or a list of all ids.
fn explain_text(id: Option<&str>) -> Result<String, String> {
    let Some(id) = id else {
        let width = explanations().iter().map(|e| e.id.len()).max().unwrap_or(0);
        let mut out = String::new();
        for e in explanations() {
            let _ = writeln!(out, "{:<width$}  {}", e.id, e.title);
        }
        return Ok(out);
    };
    let e = explain(id).ok_or_else(|| {
        format!("unknown finding id `{id}`; run `testls explain` to list all ids")
    })?;
    Ok(format!(
        "{}: {}\n\n{}\n\nReference: {}\n",
        e.id, e.title, e.rationale, e.reference
    ))
}

/// Completion script for `shell`, as printed by `testls completions`.
fn completion_script(shell: clap_complete::Shell) -> Vec<u8> {
    let mut out = Vec::new();
    clap_complete::generate(shell, &mut Cli::command(), "testls", &mut out);
    out
}

/// Man page in roff format, as printed by `testls man`.
fn man_page() -> Vec<u8> {
    let mut out = Vec::new();
    clap_mangen::Man::new(Cli::command())
        .render(&mut out)
        .expect("writing to a Vec cannot fail");
    out
}

/// Writes `testls.1` and one page per subcommand to `dir`, which must
/// exist: exit code 0, or 2 when a page cannot be written.
fn write_man_pages(dir: &std::path::Path) -> ExitCode {
    match clap_mangen::generate_to(Cli::command(), dir) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: cannot write man pages to {}: {e}", dir.display());
            ExitCode::from(2)
        }
    }
}

/// Writes generated output to stdout: exit code 0, or 2 when stdout fails.
fn print_bytes(bytes: &[u8]) -> ExitCode {
    let mut stdout = std::io::stdout().lock();
    match stdout.write_all(bytes).and_then(|()| stdout.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: cannot write output: {e}");
            ExitCode::from(2)
        }
    }
}

/// Runs the selected command and maps the outcome to the exit code contract.
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match &cli.command {
        Some(Command::Explain { id }) => explain_command(id.as_deref()),
        Some(Command::Completions { shell }) => print_bytes(&completion_script(*shell)),
        Some(Command::Man { dir: None }) => print_bytes(&man_page()),
        Some(Command::Man { dir: Some(dir) }) => write_man_pages(dir),
        None => scan_all(&cli).await,
    }
}

/// Collects the targets from the command line and `--file`, in that order,
/// with CIDR ranges expanded.
fn targets(cli: &Cli) -> Result<Vec<Target>, String> {
    let port = default_port(cli);
    let mut targets = Vec::new();
    for arg in &cli.targets {
        let spec = TargetSpec::parse_with_port(arg, port).map_err(|e| format!("{arg}: {e}"))?;
        targets.extend(spec.0);
    }
    if let Some(path) = &cli.file {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        targets
            .extend(parse_target_list(&text, port).map_err(|e| format!("{}:{e}", path.display()))?);
    }
    if targets.is_empty() {
        return Err("no targets given".to_owned());
    }
    Ok(targets)
}

/// Checks a command-line target, keeping it as text so that [`targets`]
/// can apply the `--starttls` default port.
fn target_arg(s: &str) -> Result<String, target::ParseTargetError> {
    s.parse::<TargetSpec>().map(|_| s.to_owned())
}

/// Port for targets that name none: the `--starttls` protocol's standard
/// port, else 443.
fn default_port(cli: &Cli) -> u16 {
    cli.starttls
        .map_or(target::DEFAULT_PORT, Starttls::default_port)
}

/// Parses a target list: one target per line, skipping blank lines and
/// `#` comments, with `port` for targets that name none. Errors name the
/// 1-based line number.
fn parse_target_list(text: &str, port: u16) -> Result<Vec<Target>, String> {
    text.lines()
        .enumerate()
        .map(|(n, line)| (n + 1, line.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(n, line)| {
            TargetSpec::parse_with_port(line, port)
                .map(|s| s.0)
                .map_err(|e| format!("{n}: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|lists| lists.concat())
}

/// Scans every target in turn. The exit code is 2 if any scan failed,
/// else 1 if any target has a finding at or above `--fail-on`, else 0.
/// JSON output is one document for a single target and an array of
/// documents otherwise; SARIF and JUnit output is one document covering
/// all targets.
async fn scan_all(cli: &Cli) -> ExitCode {
    let ready = targets(cli).and_then(|t| {
        let config = Config::load(cli.config.as_deref())?;
        let baseline = cli.baseline.as_deref().map(Baseline::load).transpose()?;
        Ok((t, trust_store(cli)?, (config, baseline.unwrap_or_default())))
    });
    let (targets, store, (config, baseline)) = match ready {
        Ok(ready) => ready,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let today = config::utc_date(unix_now());
    for s in config.expired(today) {
        eprintln!(
            "warning: suppression of {} expired on {}; the finding is reported again",
            s.id,
            s.expires_text()
        );
    }
    for id in config.unknown_ids() {
        eprintln!("warning: suppression of unknown finding id {id}");
    }
    let proxy = match proxy_address(cli.proxy.as_ref(), cli.source_ip).await {
        Ok(proxy) => proxy,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    // Through a proxy, the source address only has to reach the proxy.
    let family = cli.source_ip.filter(|_| proxy.is_none());
    let mut code = 0;
    let mut scans = 0;
    let mut documents = Vec::new();
    let mut finding_scans = Vec::new();
    let mut failures = Vec::new();
    for target in &targets {
        let addrs = match addresses(target, &cli.resolve, family).await {
            Ok(addrs) => selected(cli, addrs),
            Err(e) => {
                scans += 1;
                let outcome = Outcome::failed(target, &format!("cannot resolve: {e}"));
                code = code.max(outcome.code);
                failures.extend(outcome.failure);
                continue;
            }
        };
        let mut profiles = Vec::new();
        for addr in addrs {
            if scans > 0 && cli.format == Format::Text {
                println!();
            }
            scans += 1;
            let outcome = scan(
                cli,
                &store,
                (&config, &baseline),
                target,
                transport(cli, addr, proxy),
            )
            .await;
            code = code.max(outcome.code);
            documents.extend(outcome.json);
            finding_scans.extend(outcome.findings);
            failures.extend(outcome.failure);
            profiles.extend(outcome.profile.map(|p| (addr, p)));
        }
        for warning in divergence(&profiles) {
            eprintln!("warning: {target}: {warning}");
        }
    }
    if cli.format == Format::Json {
        print!("{}", json_output(scans, &documents));
    }
    if cli.format == Format::Sarif {
        print!("{}", sarif::render(&finding_scans, code < 2));
    }
    if cli.format == Format::Junit {
        print!("{}", junit::render(&finding_scans, &failures, cli.fail_on));
    }
    if cli.format == Format::Markdown {
        print!(
            "{}",
            markdown::render(&finding_scans, &failures, cli.fail_on)
        );
    }
    if cli.format == Format::Csv {
        print!("{}", csv::render(&finding_scans, &failures, cli.fail_on));
    }
    if cli.format == Format::Html {
        print!("{}", html::render(&finding_scans, &failures, cli.fail_on));
    }
    ExitCode::from(code)
}

/// What must match across the addresses of one host: offered protocols,
/// accepted cipher suites per protocol, and the leaf certificate.
#[derive(Debug, PartialEq, Eq)]
struct Profile {
    /// Protocol versions the address offers.
    protocols: Vec<ProtocolVersion>,
    /// Accepted cipher suites per protocol, sorted; `None` if enumeration
    /// failed.
    suites: Vec<(ProtocolVersion, Option<Vec<u32>>)>,
    /// DER of the leaf certificate, if one was retrieved.
    leaf: Option<Vec<u8>>,
}

/// Describes how each address differs from the first scanned address.
fn divergence(profiles: &[(SocketAddr, Profile)]) -> Vec<String> {
    let Some(((first_addr, first), rest)) = profiles.split_first() else {
        return Vec::new();
    };
    rest.iter()
        .filter_map(|(addr, p)| {
            let aspects: Vec<&str> = [
                (p.protocols != first.protocols, "protocols"),
                (p.suites != first.suites, "cipher suites"),
                (p.leaf != first.leaf, "certificate"),
            ]
            .into_iter()
            .filter_map(|(differs, aspect)| differs.then_some(aspect))
            .collect();
            (!aspects.is_empty())
                .then(|| format!("{addr} differs from {first_addr} in {}", aspects.join(", ")))
        })
        .collect()
}

/// Combines the JSON documents of a run: the document itself for one
/// target (nothing if its scan failed), else an array of the documents.
fn json_output(targets: usize, documents: &[String]) -> String {
    if targets == 1 {
        documents.concat()
    } else {
        json::render_array(documents)
    }
}

/// Result of scanning one target.
#[derive(Debug)]
struct Outcome {
    /// Exit code for this target alone (0, 1 or 2).
    code: u8,
    /// Rendered JSON document, when `--format json` and the scan ran.
    json: Option<String>,
    /// Findings for SARIF, JUnit, Markdown, CSV or HTML output, when one of
    /// those formats is chosen and the scan ran.
    findings: Option<sarif::Scan>,
    /// Why the scan failed, for JUnit, Markdown, CSV and HTML output.
    failure: Option<junit::Failure>,
    /// Summary compared across a host's addresses, when the scan ran.
    profile: Option<Profile>,
}

impl Outcome {
    /// Retains partial results while giving incomplete scans precedence over
    /// the finding threshold in the process status and summary reports.
    fn completed(
        cli: &Cli,
        (target, addr): (String, SocketAddr),
        incomplete: bool,
        findings: Vec<Finding>,
        json: Option<String>,
        profile: Profile,
    ) -> Self {
        let code = if incomplete {
            2
        } else {
            u8::from(findings.iter().any(|f| f.severity >= cli.fail_on))
        };
        let failure = incomplete.then(|| junit::Failure {
            target: target.clone(),
            error: "required scan measurements are incomplete".to_owned(),
        });
        let findings = cli.format.is_summary().then_some(sarif::Scan {
            target,
            addr,
            findings,
        });
        Self {
            code,
            json,
            findings,
            failure,
            profile: Some(profile),
        }
    }

    /// A scan that failed before producing a report.
    fn failed(target: &Target, error: &str) -> Self {
        eprintln!("error: {target}: {error}");
        Self {
            code: 2,
            json: None,
            findings: None,
            failure: Some(junit::Failure {
                target: target.to_string(),
                error: error.to_owned(),
            }),
            profile: None,
        }
    }
}

/// Builds the painter from `--color`, the terminal, and `NO_COLOR`.
fn painter(cli: &Cli) -> Painter {
    Painter::new(cli.color.enabled(
        cli.color != ColorChoice::Never && colour_terminal(),
        std::env::var("NO_COLOR").ok().as_deref(),
    ))
}

/// Keeps every resolved address with `--all-addresses` or `--profile full`,
/// otherwise only the first.
fn selected(cli: &Cli, mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    if !(cli.all_addresses || cli.profile.full()) {
        addrs.truncate(1);
    }
    addrs
}

/// Builds the transport to `addr` with the timeouts and source address in
/// `cli`, tunnelled through the resolved `proxy` when given.
fn transport(cli: &Cli, addr: SocketAddr, proxy: Option<SocketAddr>) -> Transport {
    let mut transport = Transport::new(addr);
    transport.connect_timeout = Duration::from_secs(cli.connect_timeout);
    transport.read_timeout = Duration::from_secs(cli.read_timeout);
    transport.source = cli.source_ip;
    transport.proxy = proxy;
    transport.starttls = cli.starttls;
    transport
}

/// Scans `scan_target` over `transport` with the options in `cli`,
/// setting aside the findings the suppressions or the baseline in `rules`
/// accept.
async fn scan(
    cli: &Cli,
    store: &TrustStore,
    rules: (&Config, &Baseline),
    scan_target: &Target,
    mut transport: Transport,
) -> Outcome {
    let paint = painter(cli);
    let sni = cli.sni.as_deref().or(scan_target.default_sni());
    transport.host = sni.map(str::to_owned);
    let addr = transport.addr;

    let started_at = unix_now();
    let target = scan_target.to_string();
    let show = |section: String| {
        if cli.format == Format::Text {
            print!("{section}");
        }
    };

    show(text::header(&target, addr, sni));
    let protocols = detect_protocols(&transport, sni).await;
    show(format!("\n{}", text::protocols(&protocols, paint)));
    if protocols
        .iter()
        .all(|r| matches!(r.support, ProtocolSupport::Error(_)))
    {
        return Outcome::failed(scan_target, "no protocol could be tested");
    }
    let mut findings = protocol_findings(&protocols);

    let deep = cli.profile.deep();
    let (ciphers, key_exchange) = suite_sections(
        &transport,
        &protocols,
        sni,
        deep,
        &mut findings,
        paint,
        &show,
    )
    .await;
    let post_quantum = post_quantum_readiness(&measured(&key_exchange));
    if deep {
        show(format!("\n{}", text::post_quantum(&post_quantum, paint)));
    }

    let host = sni.map_or_else(|| addr.ip().to_string(), str::to_owned);
    let (certificate, cert_findings, chain) =
        certificate_section(&transport, sni, &host, store).await;
    show(format!("\n{}", text::certificate(&certificate, paint)));
    findings.extend(cert_findings);

    let revocation = if cli.revocation || cli.profile.full() {
        let (section, more) = revocation_section(
            &transport,
            chain.as_deref(),
            cli.revocation_endpoint.clone(),
        )
        .await;
        show(format!("\n{}", text::revocation(&section, paint)));
        findings.extend(more);
        Some(section)
    } else {
        None
    };

    let (http, vulns, intolerance, details) = later_sections(
        &transport,
        (&protocols, &ciphers, &key_exchange),
        sni,
        deep,
        &mut findings,
        paint,
        &show,
    )
    .await;
    let measured_parts = (&protocols[..], &ciphers[..], &key_exchange[..]);
    findings.extend(policy_section(cli, measured_parts, chain.as_deref(), &http));

    let incomplete = incomplete_scan(&protocols, &ciphers, &key_exchange, &certificate, &findings);
    let (findings, suppressed) = triage(findings, rules, scan_target, started_at);
    show(format!("\n{}", text::findings(&findings, paint)));
    show(text::suppressed(&suppressed, paint));

    let json = (cli.format == Format::Json).then(|| {
        json::render(&json::Report {
            target: &target,
            addr,
            sni,
            started_at,
            protocols: &protocols,
            ciphers: &ciphers,
            key_exchange: &key_exchange,
            post_quantum: &post_quantum,
            certificate: &certificate,
            http: &http,
            revocation: revocation.as_ref(),
            vulnerabilities: &vulns,
            intolerance: &intolerance,
            details: &details,
            findings: &findings,
            suppressed: &suppressed,
        })
    });
    Outcome::completed(
        cli,
        (target, addr),
        incomplete,
        findings,
        json,
        profile(&protocols, &ciphers, chain.as_deref()),
    )
}

/// Required measurements must succeed even when errors are suppressed or below
/// the finding threshold. Optional HTTP and profile-skipped probes do not count.
fn incomplete_scan(
    protocols: &[ProtocolResult],
    ciphers: &[CipherSection],
    key_exchange: &[KeyExchangeSection],
    certificate: &Result<CertificateSection, String>,
    findings: &[Finding],
) -> bool {
    protocols
        .iter()
        .any(|p| matches!(p.support, ProtocolSupport::Error(_)))
        || ciphers.iter().any(|s| s.outcome.is_err())
        || key_exchange.iter().any(|s| s.outcome.is_err())
        || certificate
            .as_ref()
            .map_or(true, |c| c.certificates.iter().any(Result::is_err))
        || findings.iter().any(|f| f.id == "policy.incomplete")
}

/// `policy.*` findings for each `--policy`. Successful cipher suite and key
/// exchange probes are checked per version; failed probes of versions a
/// policy allows make it incomplete (the quick profile skips key exchange).
fn policy_section(
    cli: &Cli,
    (protocols, ciphers, key_exchange): (
        &[ProtocolResult],
        &[CipherSection],
        &[KeyExchangeSection],
    ),
    chain: Option<&[Vec<u8>]>,
    http: &Result<HttpResponse, String>,
) -> Vec<Finding> {
    let (ciphers, cipher_errors) = measured_versions(ciphers, |s| (s.version, &s.outcome));
    let (key_exchange, key_exchange_errors) =
        measured_versions(key_exchange, |s| (s.version, &s.outcome));
    let input = PolicyInput {
        protocols,
        ciphers: Some(&ciphers),
        cipher_errors: &cipher_errors,
        key_exchange: cli.profile.deep().then_some(&key_exchange[..]),
        key_exchange_errors: &key_exchange_errors,
        chain,
        http: http.as_ref().ok(),
    };
    cli.policies
        .iter()
        .flat_map(|&p| policy_findings(p, &input))
        .collect()
}

/// The results of the sections that succeeded, and the protocol versions of
/// those that failed.
fn measured_versions<S, T: Clone>(
    sections: &[S],
    outcome: impl Fn(&S) -> (ProtocolVersion, &Result<T, String>),
) -> (Vec<T>, Vec<ProtocolVersion>) {
    let mut results = Vec::new();
    let mut failed = Vec::new();
    for section in sections {
        match outcome(section) {
            (_, Ok(result)) => results.push(result.clone()),
            (version, Err(_)) => failed.push(version),
        }
    }
    (results, failed)
}

/// Drops `ok` findings, sorts the rest most severe first and splits off
/// those `config` suppresses for `target` on the day of `now`, then those
/// `baseline` already lists. Both lists stay most severe first.
fn triage(
    mut findings: Vec<Finding>,
    (config, baseline): (&Config, &Baseline),
    target: &Target,
    now: i64,
) -> (Vec<Finding>, Vec<Suppressed>) {
    findings.retain(|f| f.severity > Severity::Ok);
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let (findings, mut suppressed) = config.apply(target, findings, config::utc_date(now));
    let (findings, known) = baseline.apply(&target.to_string(), findings);
    suppressed.extend(known);
    suppressed.sort_by_key(|s| std::cmp::Reverse(s.finding.severity));
    (findings, suppressed)
}

/// Summarises one scan for comparison with the host's other addresses.
fn profile(
    protocols: &[ProtocolResult],
    ciphers: &[CipherSection],
    chain: Option<&[Vec<u8>]>,
) -> Profile {
    Profile {
        protocols: protocols
            .iter()
            .filter(|r| r.support == ProtocolSupport::Supported)
            .map(|r| r.version)
            .collect(),
        suites: ciphers
            .iter()
            .map(|s| {
                let suites = s.outcome.as_ref().ok().map(|c| {
                    let mut suites = c.suites.clone();
                    suites.sort_unstable();
                    suites
                });
                (s.version, suites)
            })
            .collect(),
        leaf: chain.and_then(<[_]>::first).cloned(),
    }
}

/// Loads the trust store selected on the command line: a `--ca-file`
/// bundle, the system roots, or the bundled Mozilla roots. Partial errors
/// while reading the system roots are printed as warnings.
fn trust_store(cli: &Cli) -> Result<TrustStore, String> {
    if let Some(path) = &cli.ca_file {
        std::fs::read(path)
            .map_err(|e| e.to_string())
            .and_then(|pem| TrustStore::from_pem(&pem))
            .map_err(|e| format!("cannot load {}: {e}", path.display()))
    } else if cli.system_roots {
        let (store, warnings) =
            TrustStore::system().map_err(|e| format!("cannot load system roots: {e}"))?;
        for warning in warnings {
            eprintln!("warning: system roots: {warning}");
        }
        Ok(store)
    } else {
        Ok(TrustStore::webpki())
    }
}

/// Current time as a Unix timestamp.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

/// Enumerates the cipher suites of one protocol `version`.
async fn cipher_section(
    transport: &Transport,
    version: ProtocolVersion,
    sni: Option<&str>,
) -> CipherSection {
    CipherSection {
        version,
        outcome: enumerate_ciphers(transport, version, sni)
            .await
            .map_err(|e| e.to_string()),
    }
}

/// Findings for one cipher section; a failed enumeration is informational.
fn section_findings(section: &CipherSection) -> Vec<Finding> {
    match &section.outcome {
        Ok(c) => cipher_findings(c),
        Err(e) => vec![Finding::new(
            "cipher.error",
            Severity::Info,
            format!("{} ciphers could not be enumerated: {e}", section.version),
        )],
    }
}

/// Probes the supported groups and DH parameter size of one protocol
/// `version`, using the suites accepted in the cipher `section`.
///
/// When cipher enumeration failed the accepted suites are unknown, so the
/// key exchange section reports that instead of probing.
async fn key_exchange_section(
    transport: &Transport,
    section: &CipherSection,
    sni: Option<&str>,
) -> KeyExchangeSection {
    let outcome = match &section.outcome {
        Ok(c) => probe_key_exchange(transport, section.version, &c.suites, sni)
            .await
            .map_err(|e| e.to_string()),
        Err(_) => Err("cipher enumeration failed".to_owned()),
    };
    KeyExchangeSection {
        version: section.version,
        outcome,
    }
}

/// Enumerates the cipher suites of each supported protocol and, when
/// `deep` is set, probes its key exchange, adding their findings to
/// `findings` and handing each rendered section to `show` as it finishes.
async fn suite_sections(
    transport: &Transport,
    protocols: &[ProtocolResult],
    sni: Option<&str>,
    deep: bool,
    findings: &mut Vec<Finding>,
    paint: Painter,
    show: &dyn Fn(String),
) -> (Vec<CipherSection>, Vec<KeyExchangeSection>) {
    let mut ciphers = Vec::new();
    let mut key_exchange = Vec::new();
    for r in protocols {
        if r.support != ProtocolSupport::Supported {
            continue;
        }
        let section = cipher_section(transport, r.version, sni).await;
        show(format!("\n{}", text::ciphers(&section, paint)));
        findings.extend(section_findings(&section));
        if deep {
            let kx = key_exchange_section(transport, &section, sni).await;
            show(format!("\n{}", text::key_exchange(&kx, paint)));
            findings.extend(kx_findings(&kx));
            key_exchange.push(kx);
        }
        ciphers.push(section);
    }
    (ciphers, key_exchange)
}

/// Fetches HTTP headers, derives vulnerabilities and runs the tolerance
/// and detail probes; all but the vulnerability verdicts are skipped
/// unless `deep` is set. Adds their findings to `findings` and hands each
/// rendered section to `show`.
async fn later_sections(
    transport: &Transport,
    (protocols, ciphers, key_exchange): (
        &[ProtocolResult],
        &[CipherSection],
        &[KeyExchangeSection],
    ),
    sni: Option<&str>,
    deep: bool,
    findings: &mut Vec<Finding>,
    paint: Painter,
    show: &dyn Fn(String),
) -> (
    Result<HttpResponse, String>,
    Vec<Vulnerability>,
    Result<Intolerance, String>,
    Result<HandshakeDetails, String>,
) {
    let http = if let Some(protocol) = transport.starttls {
        let status = format!("not checked over --starttls {protocol}");
        show(format!("\nHTTP headers: {status}"));
        Err(status)
    } else if deep {
        let (http, http_findings) = http_section(transport, sni).await;
        show(format!("\n{}", text::http(&http, paint)));
        findings.extend(http_findings);
        http
    } else {
        skipped()
    };

    let vulns = vulnerability_section(transport, protocols, ciphers, key_exchange, sni, deep).await;
    show(format!("\n{}", text::vulnerabilities(&vulns, paint)));
    findings.extend(vulnerability_findings(&vulns));

    if !deep {
        return (http, vulns, skipped(), skipped());
    }
    let (intolerance, intolerance_findings) = intolerance_section(transport, ciphers, sni).await;
    show(format!("\n{}", text::intolerance(&intolerance, paint)));
    findings.extend(intolerance_findings);
    let (details, details_findings) = details_section(transport, ciphers, sni).await;
    show(format!("\n{}", text::details(&details, paint)));
    findings.extend(details_findings);
    (http, vulns, intolerance, details)
}

/// Result of a section the `quick` profile leaves out: an error naming
/// the profile.
fn skipped<T>() -> Result<T, String> {
    Err(profile::SKIPPED.to_owned())
}

/// Findings for one key exchange section; a failed probe is informational.
fn kx_findings(section: &KeyExchangeSection) -> Vec<Finding> {
    match &section.outcome {
        Ok(k) => key_exchange_findings(k),
        Err(e) => vec![Finding::new(
            "group.error",
            Severity::Info,
            format!("{} key exchange could not be probed: {e}", section.version),
        )],
    }
}

/// Certificate section, its findings, and the DER chain when it was
/// retrieved.
type CertificateOutcome = (
    Result<CertificateSection, String>,
    Vec<Finding>,
    Option<Vec<Vec<u8>>>,
);

/// Fetches and checks the certificate chain, returning its description,
/// findings, and the chain itself.
///
/// The leaf is checked against `host`, the SNI name or the target IP.
async fn certificate_section(
    transport: &Transport,
    sni: Option<&str>,
    host: &str,
    store: &TrustStore,
) -> CertificateOutcome {
    let chain = match fetch_certificates(transport, sni).await {
        Ok(chain) => chain,
        Err(e) => {
            let finding = Finding::new(
                "cert.error",
                Severity::Info,
                format!("certificate could not be retrieved: {e}"),
            );
            return (Err(e.to_string()), vec![finding], None);
        }
    };
    let now = unix_now();
    let mut findings = certificate_findings(&chain.certificates, Some(host), now);
    if store.is_public() && is_trusted(&chain.certificates, now, store) {
        findings.extend(baseline_findings(&chain.certificates));
    }
    findings.extend(trust_findings(&chain.certificates, now, store));
    let ocsp_response = chain.ocsp_response.as_deref();
    findings.extend(ocsp_findings(&chain.certificates, ocsp_response, now));
    let ocsp = ocsp_response.map(|der| verify_ocsp_response(der, &chain.certificates, now));
    let section = CertificateSection {
        version: chain.version,
        certificates: chain
            .certificates
            .iter()
            .map(|der| describe_certificate(der))
            .collect(),
        ocsp,
    };
    (Ok(section), findings, Some(chain.certificates))
}

/// Checks the leaf of `chain` against the issuer's OCSP responders and
/// CRLs. Without a chain or with unreadable URLs the check cannot run,
/// which is informational.
///
/// Requests use the connect and read timeouts of `transport`.
async fn revocation_section(
    transport: &Transport,
    chain: Option<&[Vec<u8>]>,
    allowed_endpoints: Vec<SocketAddr>,
) -> (Result<Vec<RevocationCheck>, String>, Vec<Finding>) {
    let fetcher = Fetcher {
        connect_timeout: transport.connect_timeout,
        read_timeout: transport.read_timeout,
        max_body: 0,
        allowed_endpoints,
        source: transport.source,
        proxy: transport.proxy,
    };
    let urls = chain
        .ok_or_else(|| "certificate chain could not be retrieved".to_owned())
        .and_then(|chain| {
            let leaf = chain.first().ok_or("empty certificate chain")?;
            revocation_urls(leaf).map(|urls| (chain, urls))
        });
    match urls {
        Ok((chain, urls)) => {
            let now = unix_now();
            let checks = revocation::check_revocation(fetcher, chain, &urls, now).await;
            let findings = revocation_findings(&checks, now);
            (Ok(checks), findings)
        }
        Err(e) => {
            let finding = Finding::new(
                "revocation.error",
                Severity::Info,
                format!("revocation status could not be checked: {e}"),
            );
            (Err(e), vec![finding])
        }
    }
}

/// Fetches the reply to `GET /` and checks HSTS, security headers, banners,
/// `Alt-Svc`, and cookies.
///
/// A server that does not speak HTTP is common for non-web TLS services,
/// so a failed fetch is informational.
async fn http_section(
    transport: &Transport,
    sni: Option<&str>,
) -> (Result<HttpResponse, String>, Vec<Finding>) {
    match fetch_http_headers(transport, sni).await {
        Ok(response) => {
            let mut findings = http_findings(&response);
            findings.extend(http_extra_findings(&response));
            (Ok(response), findings)
        }
        Err(e) => {
            let finding = Finding::new(
                "http.error",
                Severity::Info,
                format!("HTTP headers could not be retrieved: {e}"),
            );
            (Err(e.to_string()), vec![finding])
        }
    }
}

/// Probes compression, renegotiation and downgrade protection when `probe`
/// is set, then derives the named vulnerabilities from everything the scan
/// collected.
///
/// A failed or skipped feature probe leaves the affected verdicts as not
/// tested.
async fn vulnerability_section(
    transport: &Transport,
    protocols: &[ProtocolResult],
    ciphers: &[CipherSection],
    key_exchange: &[KeyExchangeSection],
    sni: Option<&str>,
    probe: bool,
) -> Vec<Vulnerability> {
    let ciphers: Vec<CipherResult> = ciphers
        .iter()
        .filter_map(|s| s.outcome.as_ref().ok().cloned())
        .collect();
    let key_exchange = measured(key_exchange);
    let features = if probe {
        probe_features(transport, &ciphers, sni).await.ok()
    } else {
        None
    };
    assess_vulnerabilities(protocols, &ciphers, &key_exchange, features.as_ref())
}

/// Sends unusual but valid `ClientHello`s at the best offered version.
///
/// A probe error becomes an informational `intolerance.error` finding.
async fn intolerance_section(
    transport: &Transport,
    ciphers: &[CipherSection],
    sni: Option<&str>,
) -> (Result<Intolerance, String>, Vec<Finding>) {
    let ciphers: Vec<CipherResult> = ciphers
        .iter()
        .filter_map(|s| s.outcome.as_ref().ok().cloned())
        .collect();
    match probe_intolerance(transport, &ciphers, sni).await {
        Ok(result) => {
            let findings = intolerance_findings(&result);
            (Ok(result), findings)
        }
        Err(e) => {
            let finding = Finding::new(
                "intolerance.error",
                Severity::Info,
                format!("ClientHello tolerance could not be tested: {e}"),
            );
            (Err(e.to_string()), vec![finding])
        }
    }
}

/// The key exchange results that were measured without error.
fn measured(sections: &[KeyExchangeSection]) -> Vec<KeyExchangeResult> {
    sections
        .iter()
        .filter_map(|s| s.outcome.as_ref().ok().cloned())
        .collect()
}

/// Probes extended master secret, the downgrade sentinel, session tickets
/// and 0-RTT.
///
/// A probe error becomes an informational `handshake.error` finding.
async fn details_section(
    transport: &Transport,
    ciphers: &[CipherSection],
    sni: Option<&str>,
) -> (Result<HandshakeDetails, String>, Vec<Finding>) {
    let ciphers: Vec<CipherResult> = ciphers
        .iter()
        .filter_map(|s| s.outcome.as_ref().ok().cloned())
        .collect();
    match probe_details(transport, &ciphers, sni).await {
        Ok(result) => {
            let findings = details_findings(&result);
            (Ok(result), findings)
        }
        Err(e) => {
            let finding = Finding::new(
                "handshake.error",
                Severity::Info,
                format!("handshake details could not be probed: {e}"),
            );
            (Err(e.to_string()), vec![finding])
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the scan helpers.

    use super::*;

    /// Missing mandatory evidence and incomplete policies fail independently
    /// of finding severity, while intentionally skipped optional checks do not.
    #[test]
    fn required_measurements_must_complete() {
        let cert = Ok(CertificateSection {
            version: ProtocolVersion::TLS13,
            certificates: vec![],
            ocsp: None,
        });
        assert!(!incomplete_scan(&[], &[], &[], &cert, &[]));
        assert!(incomplete_scan(
            &[],
            &[],
            &[],
            &Err("handshake failed".into()),
            &[]
        ));
        let protocols = [ProtocolResult {
            version: ProtocolVersion::TLS13,
            support: ProtocolSupport::Error("timeout".into()),
        }];
        assert!(incomplete_scan(&protocols, &[], &[], &cert, &[]));
        let findings = [Finding::new(
            "policy.incomplete",
            Severity::Info,
            "missing evidence",
        )];
        assert!(incomplete_scan(&[], &[], &[], &cert, &findings));
    }

    /// `explain` describes one id, lists all ids, and rejects unknown ones.
    #[test]
    fn explain_output() {
        let one = explain_text(Some("hsts.missing")).expect("known id");
        assert!(one.starts_with("hsts.missing: No HSTS header\n\n"), "{one}");
        assert!(one.ends_with("\n\nReference: RFC 6797\n"), "{one}");
        let all = explain_text(None).expect("list");
        assert_eq!(all.lines().count(), explanations().len());
        assert!(all.lines().any(|l| l.starts_with("hsts.missing ")));
        assert!(explain_text(Some("nope")).is_err());
    }

    /// Completion scripts and the man page cover the scan flags and
    /// subcommands, and their commands parse without a target.
    #[test]
    fn generated_docs() {
        for shell in [clap_complete::Shell::Bash, clap_complete::Shell::Zsh] {
            let script = String::from_utf8(completion_script(shell)).expect("UTF-8");
            assert!(script.contains("--fail-on"), "{shell}");
            assert!(script.contains("explain"), "{shell}");
        }
        let man = String::from_utf8(man_page()).expect("UTF-8");
        assert!(man.starts_with(".ie \\n(.g .ds Aq"), "{man}");
        assert!(man.contains(".TH testls 1"), "{man}");
        assert!(man.contains("\\-\\-policy"), "{man}");
        let cli = Cli::try_parse_from(["testls", "completions", "fish"]).expect("completions");
        assert!(matches!(cli.command, Some(Command::Completions { .. })));
        assert!(Cli::try_parse_from(["testls", "completions", "tcsh"]).is_err());
        let cli = Cli::try_parse_from(["testls", "man"]).expect("man");
        assert!(matches!(cli.command, Some(Command::Man { dir: None })));
        let cli = Cli::try_parse_from(["testls", "man", "--dir", "pages"]).expect("man --dir");
        assert!(matches!(cli.command, Some(Command::Man { dir: Some(_) })));
        Cli::command().debug_assert();
    }

    /// A scan needs a target; `explain` does not, and the two do not mix.
    #[test]
    fn command_line_forms() {
        assert!(Cli::try_parse_from(["testls"]).is_err());
        assert!(Cli::try_parse_from(["testls", "example.com"]).is_ok());
        let cli = Cli::try_parse_from(["testls", "explain"]).expect("explain");
        assert!(matches!(cli.command, Some(Command::Explain { id: None })));
        let cli = Cli::try_parse_from(["testls", "explain", "hsts"]).expect("explain id");
        assert!(matches!(
            cli.command,
            Some(Command::Explain { id: Some(_) })
        ));
        let cli = Cli::try_parse_from(["testls", "a.example", "b.example:8443"]).expect("two");
        assert_eq!(cli.targets.len(), 2);
        let cli = Cli::try_parse_from(["testls", "192.0.2.0/30"]).expect("range");
        assert_eq!(targets(&cli).expect("targets").len(), 4);
        let cli = Cli::try_parse_from(["testls", "--file", "hosts.txt"]).expect("file only");
        assert_eq!(cli.targets, Vec::<String>::new());
        assert!(Cli::try_parse_from(["testls", "http://a.example"]).is_err());
    }

    /// `--starttls` picks the protocol's port for targets that name none.
    #[test]
    fn starttls_ports() {
        let cli =
            Cli::try_parse_from(["testls", "--starttls", "smtp", "a.example", "b.example:587"])
                .expect("starttls");
        assert_eq!(cli.starttls, Some(Starttls::Smtp));
        let names: Vec<String> = targets(&cli)
            .expect("targets")
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(names, ["a.example:25", "b.example:587"]);
        let cli =
            Cli::try_parse_from(["testls", "--starttls", "smtp", "192.0.2.0/31"]).expect("range");
        let names: Vec<String> = targets(&cli)
            .expect("targets")
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(names, ["192.0.2.0:25", "192.0.2.1:25"]);
        let cli = Cli::try_parse_from(["testls", "--starttls", "imap", "a.example"]).expect("imap");
        assert_eq!(targets(&cli).expect("targets")[0].port, 143);
        assert_eq!(
            parse_target_list("a.example\n", 25).expect("list")[0].port,
            25
        );
        assert!(Cli::try_parse_from(["testls", "--starttls", "gopher", "a.example"]).is_err());
    }

    /// Target lists skip blanks and comments and name the bad line.
    #[test]
    fn target_lists() {
        let list =
            parse_target_list("# hosts\n\na.example\n  b.example:8443  \n", 443).expect("list");
        let names: Vec<String> = list.iter().map(ToString::to_string).collect();
        assert_eq!(names, ["a.example:443", "b.example:8443"]);
        let list = parse_target_list("192.0.2.0/31:8443\n", 443).expect("range");
        assert_eq!(list.len(), 2);
        assert!(
            parse_target_list("ok.example\n192.0.2.0/8\n", 443)
                .unwrap_err()
                .starts_with("2: ")
        );
        let err = parse_target_list("a.example\nhttp://b.example\n", 443).unwrap_err();
        assert!(err.starts_with("2: "), "{err}");
        assert_eq!(parse_target_list("# only\n", 443).expect("empty"), vec![]);
    }

    /// A failed single target prints no JSON; failed targets in a run of
    /// several leave an array, empty if all failed.
    #[test]
    fn json_outputs() {
        let doc = "{}\n".to_string();
        assert_eq!(json_output(1, &[]), "");
        assert_eq!(json_output(1, std::slice::from_ref(&doc)), doc);
        assert_eq!(json_output(2, &[]), "[]\n");
        assert!(json_output(2, &[doc]).starts_with("[\n"));
    }

    /// Divergence names each address that differs from the first and how.
    #[test]
    fn divergence_report() {
        let profile = |protocols: Vec<ProtocolVersion>, leaf: &[u8]| Profile {
            protocols,
            suites: vec![(ProtocolVersion::TLS12, Some(vec![0xc02f]))],
            leaf: Some(leaf.to_vec()),
        };
        let a: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let b: SocketAddr = "192.0.2.2:443".parse().unwrap();
        let c: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(divergence(&[]), Vec::<String>::new());
        let same = [
            (a, profile(vec![ProtocolVersion::TLS12], b"x")),
            (b, profile(vec![ProtocolVersion::TLS12], b"x")),
        ];
        assert_eq!(divergence(&same), Vec::<String>::new());
        let mut odd = profile(vec![ProtocolVersion::TLS12, ProtocolVersion::TLS13], b"y");
        odd.suites[0].1 = None;
        let mixed = [
            (a, profile(vec![ProtocolVersion::TLS12], b"x")),
            (b, profile(vec![ProtocolVersion::TLS12], b"x")),
            (c, odd),
        ];
        assert_eq!(
            divergence(&mixed),
            [
                "[2001:db8::1]:443 differs from 192.0.2.1:443 in protocols, cipher suites, certificate"
            ]
        );
    }

    /// Only `--all-addresses` and `--profile full` scan every resolved address.
    #[test]
    fn address_selection() {
        let addrs: Vec<SocketAddr> = vec![
            "192.0.2.1:443".parse().unwrap(),
            "192.0.2.2:443".parse().unwrap(),
        ];
        for (args, count) in [
            (&["testls", "a.example"][..], 1),
            (&["testls", "--profile", "quick", "a.example"], 1),
            (&["testls", "--profile", "full", "a.example"], 2),
            (&["testls", "--all-addresses", "a.example"], 2),
            (
                &[
                    "testls",
                    "--all-addresses",
                    "--profile",
                    "quick",
                    "a.example",
                ],
                2,
            ),
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            assert_eq!(selected(&cli, addrs.clone()).len(), count, "{args:?}");
        }
    }

    /// IP targets and `localhost` resolve without duplicates; a matching
    /// `--resolve` entry replaces the lookup; `--source-ip` keeps only its
    /// address family.
    #[tokio::test]
    async fn address_lists() {
        let ip: Target = "192.0.2.1:8443".parse().unwrap();
        assert_eq!(
            addresses(&ip, &[], None).await.unwrap(),
            ["192.0.2.1:8443".parse::<SocketAddr>().unwrap()]
        );
        let pinned: Vec<ResolveOverride> = [
            "other.invalid:443:192.0.2.9",
            "host.invalid:443:192.0.2.1,192.0.2.1,[2001:db8::1]",
            "host.invalid:443:192.0.2.7",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        let host: Target = "host.invalid".parse().unwrap();
        assert_eq!(
            addresses(&host, &pinned, None).await.unwrap(),
            ["192.0.2.1:443", "[2001:db8::1]:443"].map(|a| a.parse::<SocketAddr>().unwrap())
        );
        let local: Target = "localhost:443".parse().unwrap();
        let addrs = addresses(&local, &pinned, None).await.unwrap();
        assert_ne!(addrs, Vec::new());
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
        let mut unique = addrs.clone();
        unique.dedup();
        assert_eq!(unique.len(), addrs.len());
        let v6: IpAddr = "::1".parse().unwrap();
        assert_eq!(
            addresses(&host, &pinned, Some(v6)).await.unwrap(),
            ["[2001:db8::1]:443".parse::<SocketAddr>().unwrap()]
        );
        let err = addresses(&ip, &[], Some(v6)).await.unwrap_err();
        assert!(err.to_string().contains("--source-ip ::1"), "{err}");
    }

    /// `--proxy` resolves to one address of the `--source-ip` family.
    #[tokio::test]
    async fn proxy_addresses() {
        assert_eq!(proxy_address(None, None).await.unwrap(), None);
        let proxy: ProxySpec = "192.0.2.1:3128".parse().unwrap();
        assert_eq!(
            proxy_address(Some(&proxy), None).await.unwrap(),
            Some("192.0.2.1:3128".parse().unwrap())
        );
        let err = proxy_address(Some(&proxy), Some("::1".parse().unwrap()))
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot resolve proxy 192.0.2.1:3128"),
            "{err}"
        );
    }

    /// `--file` errors and an empty list are scan errors before any connection.
    #[test]
    fn target_sources() {
        let cli = Cli::try_parse_from(["testls", "--file", "/nonexistent/hosts.txt"]).unwrap();
        assert!(targets(&cli).unwrap_err().starts_with("cannot read"));
        let dir = std::env::temp_dir().join(format!("testls-targets-{}", std::process::id()));
        std::fs::write(&dir, "# none\n").unwrap();
        let cli =
            Cli::try_parse_from(["testls", "a.example", "--file", dir.to_str().unwrap()]).unwrap();
        assert_eq!(targets(&cli).unwrap().len(), 1);
        let cli = Cli::try_parse_from(["testls", "--file", dir.to_str().unwrap()]).unwrap();
        assert_eq!(targets(&cli).unwrap_err(), "no targets given");
        std::fs::remove_file(&dir).unwrap();
    }

    /// A failed cipher enumeration is reported in the key exchange section
    /// without probing the server.
    #[tokio::test]
    async fn key_exchange_after_cipher_error() {
        // Nothing listens on port 9 of the discard address; no probe is sent.
        let transport = Transport::new(SocketAddr::from(([127, 0, 0, 1], 9)));
        let ciphers = CipherSection {
            version: ProtocolVersion::TLS12,
            outcome: Err("timed out".to_owned()),
        };
        let kx = key_exchange_section(&transport, &ciphers, None).await;
        assert_eq!(kx.version, ProtocolVersion::TLS12);
        assert_eq!(
            kx.outcome.as_ref().unwrap_err(),
            "cipher enumeration failed"
        );
        assert_eq!(kx_findings(&kx)[0].id, "group.error");
    }

    /// Without a certificate chain the revocation check reports why.
    #[tokio::test]
    async fn revocation_without_chain() {
        let transport = Transport::new(SocketAddr::from(([127, 0, 0, 1], 9)));
        let (section, findings) = revocation_section(&transport, None, vec![]).await;
        assert_eq!(
            section.unwrap_err(),
            "certificate chain could not be retrieved"
        );
        assert_eq!(findings[0].id, "revocation.error");
        let (section, findings) = revocation_section(&transport, Some(&[]), vec![]).await;
        assert_eq!(section.unwrap_err(), "empty certificate chain");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    /// A failed HTTP fetch becomes an informational finding.
    #[tokio::test]
    async fn http_error_is_info() {
        // Nothing listens on port 9 of the discard address.
        let transport = Transport::new(SocketAddr::from(([127, 0, 0, 1], 9)));
        let (http, findings) = http_section(&transport, None).await;
        assert!(http.is_err());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "http.error");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    /// A failed handshake feature probe leaves its verdicts untested.
    #[tokio::test]
    async fn vulnerabilities_without_features() {
        let transport = Transport::new(SocketAddr::from(([127, 0, 0, 1], 9)));
        let protocols = [ProtocolResult {
            version: ProtocolVersion::TLS12,
            support: ProtocolSupport::Supported,
        }];
        let ciphers = [CipherSection {
            version: ProtocolVersion::TLS12,
            outcome: Ok(CipherResult {
                version: ProtocolVersion::TLS12,
                suites: vec![0xc02f],
                order: testls_probe::CipherOrder::Server,
            }),
        }];
        let list = vulnerability_section(&transport, &protocols, &ciphers, &[], None, true).await;
        let crime = list.iter().find(|v| v.id == "crime").expect("crime");
        assert_eq!(crime.status, testls_checks::VulnStatus::NotTested);
        assert_eq!(vulnerability_findings(&list), vec![]);
    }

    /// A failed tolerance probe is reported as an info finding.
    #[tokio::test]
    async fn intolerance_error_is_info() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let ciphers = [CipherSection {
            version: ProtocolVersion::TLS12,
            outcome: Ok(CipherResult {
                version: ProtocolVersion::TLS12,
                suites: vec![0xc02f],
                order: testls_probe::CipherOrder::Server,
            }),
        }];
        let (section, findings) = intolerance_section(&Transport::new(addr), &ciphers, None).await;
        assert!(section.is_err());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "intolerance.error");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    /// A failed handshake details probe is reported as an info finding.
    #[tokio::test]
    async fn details_error_is_info() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let ciphers = [CipherSection {
            version: ProtocolVersion::TLS12,
            outcome: Ok(CipherResult {
                version: ProtocolVersion::TLS12,
                suites: vec![0xc02f],
                order: testls_probe::CipherOrder::Server,
            }),
        }];
        let (section, findings) = details_section(&Transport::new(addr), &ciphers, None).await;
        assert!(section.is_err());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "handshake.error");
        assert_eq!(findings[0].severity, Severity::Info);
    }
}
