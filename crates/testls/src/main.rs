//! `testls` command-line interface.

mod baseline;
mod config;
mod target;

use std::fmt::Write as _;
use std::io::{IsTerminal as _, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::builder::TypedValueParser as _;
use clap::{CommandFactory as _, Parser, Subcommand};
use testls_checks::{Finding, Policy, Severity, TrustStore, explain, explanations};
use testls_probe::{MxResolver, ProtocolResult, ProtocolSupport, Starttls, Transport};
use testls_report::text::{self, CipherSection};
use testls_report::{ColorChoice, Format, Painter, csv, html, json, junit, markdown, sarif};
use testls_wire::ProtocolVersion;

use baseline::Baseline;
use config::Config;
use target::{Host, ProxySpec, ResolveOverride, Target, TargetSpec};
use testls_report::json::Suppressed;
use testls_scan::{Event, Options, ScanProfile, unix_now};

/// TLS/SSL scanner inspired by testssl.sh.
#[derive(Debug, Parser)]
#[command(
    version,
    about,
    max_term_width = 100,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
// Each bool is an independent command-line flag, which clap models as a bool.
#[allow(clippy::struct_excessive_bools)]
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

    /// Let revocation lookups reach loopback, private, link-local and other
    /// non-public addresses, e.g. for an internal CA. The scanned server's
    /// certificate chooses these URLs, so they are refused by default, as are
    /// numeric host forms like `127.1` that cannot be checked via `--proxy`.
    #[arg(long)]
    revocation_allow_private: bool,

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

    /// Scan the mail servers of each target domain instead of the domain
    /// itself: every MX host is scanned with `--starttls smtp` on the
    /// target's port (25 by default). A domain without MX records is
    /// scanned itself; IP and CIDR targets are rejected.
    #[arg(long)]
    mx: bool,

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
    if cli.mx && cli.starttls.is_some_and(|s| s != Starttls::Smtp) {
        return Err("--mx scans mail servers and needs --starttls smtp".to_owned());
    }
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
    if cli.mx
        && let Some(t) = targets.iter().find(|t| matches!(t.host, Host::Ip(_)))
    {
        return Err(format!("{t}: --mx needs a domain name, not an IP address"));
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
    starttls(cli).map_or(target::DEFAULT_PORT, Starttls::default_port)
}

/// STARTTLS protocol to use: `--starttls`, or `smtp` with `--mx`.
fn starttls(cli: &Cli) -> Option<Starttls> {
    cli.starttls.or(cli.mx.then_some(Starttls::Smtp))
}

/// Hosts to scan: `targets` unchanged, or with `--mx` the mail servers
/// of each target domain on the target's port, with a failed outcome for
/// each domain whose lookup fails. Errs when the system resolver
/// configuration cannot be read.
async fn mail_hosts(
    cli: &Cli,
    targets: Vec<Target>,
) -> Result<(Vec<Target>, Vec<Outcome>), String> {
    if !cli.mx {
        return Ok((targets, Vec::new()));
    }
    let resolver =
        MxResolver::system(Duration::from_secs(cli.connect_timeout)).map_err(|e| e.to_string())?;
    let mut hosts = Vec::new();
    let mut failed = Vec::new();
    for target in &targets {
        let Host::Name(domain) = &target.host else {
            hosts.push(target.clone());
            continue;
        };
        match resolver.lookup(domain).await {
            Ok(found) => hosts.extend(found.into_iter().map(|host| Target {
                host: Host::Name(host),
                port: target.port,
            })),
            Err(e) => failed.push(Outcome::failed(target, &e.to_string())),
        }
    }
    Ok((hosts, failed))
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
    let hosts = match mail_hosts(cli, targets).await {
        Ok((hosts, failed)) => {
            for outcome in failed {
                scans += 1;
                code = code.max(outcome.code);
                failures.extend(outcome.failure);
            }
            hosts
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    for target in &hosts {
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
    print_report(cli, scans, &documents, &finding_scans, &failures, code);
    ExitCode::from(code)
}

/// Prints the reports that `--format` renders once at the end of the
/// run, from the `scans` count, JSON `documents`, `finding_scans`,
/// `failures` and the run's exit `code`.
fn print_report(
    cli: &Cli,
    scans: usize,
    documents: &[String],
    finding_scans: &[sarif::Scan],
    failures: &[junit::Failure],
    code: u8,
) {
    if cli.format == Format::Json {
        print!("{}", json_output(scans, documents));
    }
    if cli.format == Format::Sarif {
        print!("{}", sarif::render(finding_scans, code < 2));
    }
    if cli.format == Format::Junit {
        print!("{}", junit::render(finding_scans, failures, cli.fail_on));
    }
    if cli.format == Format::Markdown {
        print!("{}", markdown::render(finding_scans, failures, cli.fail_on));
    }
    if cli.format == Format::Csv {
        print!("{}", csv::render(finding_scans, failures, cli.fail_on));
    }
    if cli.format == Format::Html {
        print!("{}", html::render(finding_scans, failures, cli.fail_on));
    }
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
    transport.starttls = starttls(cli);
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
    transport: Transport,
) -> Outcome {
    let paint = painter(cli);
    let options = scan_options(cli, scan_target);
    let target = scan_target.to_string();
    let is_text = cli.format == Format::Text;
    if is_text {
        print!(
            "{}",
            text::header(&target, transport.addr, options.sni.as_deref())
        );
    }
    let mut on_event = |event: Event<'_>| {
        if is_text {
            print!("\n{}", render_event(event, paint));
        }
    };
    let scan = match testls_scan::scan(transport, &options, store, &mut on_event).await {
        Ok(scan) => scan,
        Err(e) => return Outcome::failed(scan_target, &e.to_string()),
    };

    let (findings, suppressed) = triage(scan.findings.clone(), rules, scan_target, scan.started_at);
    if is_text {
        print!("\n{}", text::findings(&findings, paint));
        print!("{}", text::suppressed(&suppressed, paint));
        print!("{}", text::grade(&scan.grade, paint));
    }

    let report = json::Report {
        target: &target,
        addr: scan.addr,
        sni: scan.sni.as_deref(),
        started_at: scan.started_at,
        protocols: &scan.protocols,
        ciphers: &scan.ciphers,
        key_exchange: &scan.key_exchange,
        post_quantum: &scan.post_quantum,
        certificate: &scan.certificate,
        http: &scan.http,
        revocation: scan.revocation.as_ref(),
        vulnerabilities: &scan.vulnerabilities,
        intolerance: &scan.intolerance,
        details: &scan.details,
        grade: &scan.grade,
        findings: &findings,
        suppressed: &suppressed,
    };
    outcome(cli, &report, scan.chain.as_deref())
}

/// Scan options from the command line; the SNI name defaults to the host
/// name of `scan_target`.
fn scan_options(cli: &Cli, scan_target: &Target) -> Options {
    let mut options = Options::default();
    options.sni = cli
        .sni
        .as_deref()
        .or(scan_target.default_sni())
        .map(str::to_owned);
    options.profile = cli.profile;
    options.revocation = cli.revocation;
    options.revocation_allow_private = cli.revocation_allow_private;
    options.policies.clone_from(&cli.policies);
    options
}

/// Text rendering of one finished scan section.
fn render_event(event: Event<'_>, paint: Painter) -> String {
    match event {
        Event::Protocols(p) => text::protocols(p, paint),
        Event::Ciphers(s) => text::ciphers(s, paint),
        Event::KeyExchange(s) => text::key_exchange(s, paint),
        Event::PostQuantum(pq) => text::post_quantum(pq, paint),
        Event::Certificate(c) => text::certificate(c, paint),
        Event::Revocation(r) => text::revocation(r, paint),
        Event::Http(h) => text::http(h, paint),
        Event::HttpSkipped(reason) => format!("HTTP headers: {reason}"),
        Event::Vulnerabilities(v) => text::vulnerabilities(v, paint),
        Event::Intolerance(i) => text::intolerance(i, paint),
        Event::Details(d) => text::details(d, paint),
    }
}

/// Outcome of a scan that ran: the exit code from the findings and the
/// report in the chosen machine-readable format.
fn outcome(cli: &Cli, report: &json::Report<'_>, chain: Option<&[Vec<u8>]>) -> Outcome {
    Outcome {
        code: u8::from(report.findings.iter().any(|f| f.severity >= cli.fail_on)),
        json: (cli.format == Format::Json).then(|| json::render(report)),
        findings: cli.format.is_summary().then(|| sarif::Scan {
            target: report.target.to_owned(),
            addr: report.addr,
            grade: report.grade.clone(),
            findings: report.findings.to_vec(),
        }),
        failure: None,
        profile: Some(profile(report.protocols, report.ciphers, chain)),
    }
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

#[cfg(test)]
mod tests {
    //! Unit tests for the scan helpers.

    use super::*;

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

    /// `--mx` implies `--starttls smtp` and port 25, keeps explicit ports,
    /// and rejects other protocols and IP targets.
    #[test]
    fn mx_targets() {
        let cli =
            Cli::try_parse_from(["testls", "--mx", "a.example", "b.example:587"]).expect("mx");
        assert_eq!(starttls(&cli), Some(Starttls::Smtp));
        let names: Vec<String> = targets(&cli)
            .expect("targets")
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(names, ["a.example:25", "b.example:587"]);
        let cli = Cli::try_parse_from(["testls", "--mx", "--starttls", "smtp", "a.example"])
            .expect("mx smtp");
        assert!(targets(&cli).is_ok());
        let cli = Cli::try_parse_from(["testls", "--mx", "--starttls", "imap", "a.example"])
            .expect("mx imap");
        assert!(targets(&cli).expect_err("imap").contains("--starttls smtp"));
        for ip in ["192.0.2.1", "192.0.2.0/31", "[2001:db8::1]:25"] {
            let cli = Cli::try_parse_from(["testls", "--mx", "a.example", ip]).expect("mx ip");
            assert!(targets(&cli).expect_err(ip).contains("needs a domain name"));
        }
        let cli = Cli::try_parse_from(["testls", "a.example"]).expect("plain");
        assert_eq!(starttls(&cli), None);
    }

    /// Without `--mx`, the targets are scanned unchanged.
    #[tokio::test]
    async fn mail_hosts_without_mx() {
        let cli = Cli::try_parse_from(["testls", "a.example"]).expect("plain");
        let (hosts, failed) = mail_hosts(&cli, targets(&cli).expect("targets"))
            .await
            .expect("hosts");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].to_string(), "a.example:443");
        assert!(failed.is_empty());
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
}
