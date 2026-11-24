//! Mail exchanger (MX) lookups for `--mx`, so mail domains can be scanned
//! by the hosts that actually accept their mail.

use std::fmt;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::net::{DnsError, NetError, NoRecords};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{Name, RData};

/// Error from an MX lookup.
#[derive(Debug)]
#[non_exhaustive]
pub enum MxError {
    /// The system resolver configuration could not be read.
    Config(String),
    /// The domain publishes a null MX (RFC 7505) and accepts no mail.
    NoMail,
    /// The domain does not exist (NXDOMAIN).
    NotFound,
    /// The query failed (timeout, server failure, malformed name, ...).
    Lookup(String),
}

impl fmt::Display for MxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "cannot read resolver configuration: {e}"),
            Self::NoMail => f.write_str("domain accepts no mail (null MX)"),
            Self::NotFound => f.write_str("domain does not exist"),
            Self::Lookup(e) => write!(f, "MX lookup failed: {e}"),
        }
    }
}

impl std::error::Error for MxError {}

/// DNS resolver for MX records.
#[derive(Debug, Clone)]
pub struct MxResolver {
    /// The underlying hickory resolver.
    inner: TokioResolver,
}

impl MxResolver {
    /// Resolver using the system configuration (`/etc/resolv.conf` on Unix,
    /// the registry on Windows), with `timeout` per DNS query.
    ///
    /// # Errors
    /// Returns [`MxError::Config`] when the system configuration cannot be
    /// read.
    pub fn system(timeout: Duration) -> Result<Self, MxError> {
        let mut builder =
            TokioResolver::builder_tokio().map_err(|e| MxError::Config(e.to_string()))?;
        builder.options_mut().timeout = timeout;
        let inner = builder
            .build()
            .map_err(|e| MxError::Config(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Resolver that asks only the DNS server at `server` over UDP, without
    /// retries, caching or the hosts file; for tests against a fake or
    /// fixture server.
    ///
    /// # Errors
    /// Returns [`MxError::Config`] when the resolver cannot be built.
    pub fn with_server(server: std::net::SocketAddr, timeout: Duration) -> Result<Self, MxError> {
        use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig};
        use hickory_resolver::net::runtime::TokioRuntimeProvider;

        let mut name_server = NameServerConfig::udp(server.ip());
        for connection in &mut name_server.connections {
            connection.port = server.port();
        }
        let config = ResolverConfig::from_name_servers(vec![name_server]);
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        builder.options_mut().timeout = timeout;
        builder.options_mut().attempts = 1;
        builder.options_mut().cache_size = 0;
        builder.options_mut().use_hosts_file = ResolveHosts::Never;
        let inner = builder
            .build()
            .map_err(|e| MxError::Config(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Mail exchangers of `domain`, most preferred first: sorted by
    /// preference, then name; lowercase, without trailing dot, without
    /// duplicates. A domain without MX records yields itself (implicit MX,
    /// RFC 5321 §5.1).
    ///
    /// `domain` is looked up as a fully qualified name, without search
    /// domains.
    ///
    /// # Errors
    /// [`MxError::NoMail`] for a null MX (RFC 7505), [`MxError::NotFound`]
    /// for NXDOMAIN and [`MxError::Lookup`] for any other failure.
    pub async fn lookup(&self, domain: &str) -> Result<Vec<String>, MxError> {
        let mut name = Name::from_ascii(domain).map_err(|e| MxError::Lookup(e.to_string()))?;
        name.set_fqdn(true);
        let records = match self.inner.mx_lookup(name).await {
            Ok(lookup) => lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::MX(mx) => Some((mx.preference, mx.exchange.clone())),
                    _ => None,
                })
                .collect(),
            Err(e) if e.is_nx_domain() => return Err(MxError::NotFound),
            Err(e) if no_records(&e) => Vec::new(),
            Err(e) => return Err(MxError::Lookup(e.to_string())),
        };
        exchanges(domain, records)
    }
}

/// Whether `e` is an empty answer for an existing name (NODATA).
fn no_records(e: &NetError) -> bool {
    matches!(
        e,
        NetError::Dns(DnsError::NoRecordsFound(NoRecords {
            response_code: ResponseCode::NoError,
            ..
        }))
    )
}

/// Turns `(preference, exchange)` records into the host list described at
/// [`MxResolver::lookup`].
fn exchanges(domain: &str, mut records: Vec<(u16, Name)>) -> Result<Vec<String>, MxError> {
    if records.is_empty() {
        return Ok(vec![domain.trim_end_matches('.').to_ascii_lowercase()]);
    }
    // RFC 7505 §3: a null MX is the only MX of its domain; ignore a root
    // exchange mixed with real ones.
    let null = records.iter().any(|(_, name)| name.is_root());
    records.retain(|(_, name)| !name.is_root());
    if records.is_empty() && null {
        return Err(MxError::NoMail);
    }
    let mut hosts: Vec<(u16, String)> = records
        .into_iter()
        .map(|(preference, name)| {
            let host = name.to_lowercase().to_ascii();
            (preference, host.trim_end_matches('.').to_owned())
        })
        .collect();
    hosts.sort();
    let mut out: Vec<String> = Vec::with_capacity(hosts.len());
    for (_, host) in hosts {
        if !out.contains(&host) {
            out.push(host);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query};
    use hickory_resolver::proto::rr::Record;
    use hickory_resolver::proto::rr::rdata::{CNAME, MX};
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;

    /// Shorthand for a fully qualified [`Name`].
    fn name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    /// Fake DNS server answering one query with `code` and `answers`.
    /// Returns its address and the query it received.
    async fn server(
        code: ResponseCode,
        answers: Vec<RData>,
    ) -> (SocketAddr, tokio::task::JoinHandle<Query>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buf = [0; 512];
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..n]).unwrap();
            let query = request.queries[0].clone();
            let mut reply = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            reply.metadata.response_code = code;
            reply.metadata.recursion_desired = true;
            reply.metadata.recursion_available = true;
            reply.add_query(query.clone());
            for rdata in answers {
                reply.add_answer(Record::from_rdata(query.name().clone(), 60, rdata));
            }
            socket
                .send_to(&reply.to_vec().unwrap(), peer)
                .await
                .unwrap();
            query
        });
        (addr, task)
    }

    /// Looks up `example.com` against a fake server with `code` and
    /// `answers`, checking the query that was sent.
    async fn lookup(code: ResponseCode, answers: Vec<RData>) -> Result<Vec<String>, MxError> {
        let (addr, task) = server(code, answers).await;
        let resolver = MxResolver::with_server(addr, Duration::from_secs(2)).unwrap();
        let result = resolver.lookup("Example.COM").await;
        let query = task.await.unwrap();
        assert_eq!(query.name().to_lowercase(), name("example.com."));
        assert!(query.name().is_fqdn());
        assert_eq!(
            query.query_type(),
            hickory_resolver::proto::rr::RecordType::MX
        );
        result
    }

    /// Records come back sorted by preference, then name, lowercase and
    /// deduplicated; other record types are ignored.
    #[tokio::test]
    async fn sorts_and_dedupes() {
        let hosts = lookup(
            ResponseCode::NoError,
            vec![
                RData::MX(MX::new(20, name("b.example.com."))),
                RData::MX(MX::new(10, name("MX2.example.com."))),
                RData::MX(MX::new(10, name("mx1.example.com."))),
                RData::MX(MX::new(30, name("mx2.example.com."))),
                RData::CNAME(CNAME(name("other.example.com."))),
            ],
        )
        .await
        .unwrap();
        assert_eq!(
            hosts,
            ["mx1.example.com", "mx2.example.com", "b.example.com"]
        );
    }

    /// A domain without MX records is its own mail exchanger.
    #[tokio::test]
    async fn implicit_mx() {
        let hosts = lookup(ResponseCode::NoError, Vec::new()).await.unwrap();
        assert_eq!(hosts, ["example.com"]);
    }

    /// A null MX means the domain accepts no mail.
    #[tokio::test]
    async fn null_mx() {
        let err = lookup(
            ResponseCode::NoError,
            vec![RData::MX(MX::new(0, Name::root()))],
        )
        .await
        .unwrap_err();
        assert!(matches!(err, MxError::NoMail), "{err:?}");
    }

    /// NXDOMAIN is an error, not an implicit MX.
    #[tokio::test]
    async fn nxdomain() {
        let err = lookup(ResponseCode::NXDomain, Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(err, MxError::NotFound), "{err:?}");
    }

    /// Server failures are lookup errors.
    #[tokio::test]
    async fn servfail() {
        let err = lookup(ResponseCode::ServFail, Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(err, MxError::Lookup(_)), "{err:?}");
    }

    /// A root exchange mixed with real ones is ignored.
    #[test]
    fn root_mixed_with_real_exchanges() {
        let hosts = exchanges(
            "example.com",
            vec![(0, Name::root()), (10, name("mx.example.com."))],
        )
        .unwrap();
        assert_eq!(hosts, ["mx.example.com"]);
    }
}
