//! Post-quantum readiness: which TLSv1.3 key exchange groups resist a
//! future quantum computer, kept apart from the obsolete draft Kyber code
//! points.

use testls_probe::{CipherOrder, KeyExchangeResult};
use testls_wire::ProtocolVersion;

/// What kind of key exchange a named group provides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    /// Elliptic curve or finite-field group only.
    Classical,
    /// A registered ML-KEM group, pure or hybrid (FIPS 203).
    PostQuantum,
    /// A pre-standard Kyber code point that IANA lists as obsolete.
    DraftKyber,
}

/// Classifies group `id` by its IANA TLS Supported Groups registry name.
#[must_use]
pub fn group_kind(id: u16) -> GroupKind {
    match testls_data::group(id).map(|g| g.name) {
        Some(name) if name.contains("MLKEM") => GroupKind::PostQuantum,
        Some(name) if name.contains("Kyber") => GroupKind::DraftKyber,
        _ => GroupKind::Classical,
    }
}

/// Overall post-quantum verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqStatus {
    /// TLSv1.3 accepts at least one ML-KEM group.
    Ready,
    /// TLSv1.3 accepts only draft Kyber code points.
    DraftOnly,
    /// TLSv1.3 accepts only classical groups.
    NotReady,
    /// TLSv1.3 is not offered or its groups were not measured.
    NotTested,
}

impl PqStatus {
    /// Stable lower-case name used in reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::DraftOnly => "draft only",
            Self::NotReady => "not ready",
            Self::NotTested => "not tested",
        }
    }
}

/// Post-quantum readiness of the server's TLSv1.3 key exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostQuantum {
    /// Overall verdict.
    pub status: PqStatus,
    /// Accepted ML-KEM groups, in the order the server chose them.
    pub groups: Vec<u16>,
    /// Accepted draft Kyber code points.
    pub draft_groups: Vec<u16>,
    /// Whether the server picks an ML-KEM group over every classical one.
    /// `None` without a server group order or without ML-KEM groups.
    pub preferred: Option<bool>,
}

/// Summarises post-quantum readiness from the TLSv1.3 key exchange result.
///
/// Only TLSv1.3 matters: no ML-KEM group is defined for earlier versions.
#[must_use]
pub fn post_quantum_readiness(key_exchange: &[KeyExchangeResult]) -> PostQuantum {
    let Some(tls13) = key_exchange
        .iter()
        .find(|k| k.version == ProtocolVersion::TLS13 && !k.groups.is_empty())
    else {
        return PostQuantum {
            status: PqStatus::NotTested,
            groups: Vec::new(),
            draft_groups: Vec::new(),
            preferred: None,
        };
    };
    let of_kind = |kind| -> Vec<u16> {
        tls13
            .groups
            .iter()
            .copied()
            .filter(|&id| group_kind(id) == kind)
            .collect()
    };
    let groups = of_kind(GroupKind::PostQuantum);
    let draft_groups = of_kind(GroupKind::DraftKyber);
    let status = match (groups.is_empty(), draft_groups.is_empty()) {
        (false, _) => PqStatus::Ready,
        (true, false) => PqStatus::DraftOnly,
        (true, true) => PqStatus::NotReady,
    };
    let position = |kind| tls13.groups.iter().position(|&id| group_kind(id) == kind);
    let preferred = (tls13.group_order == CipherOrder::Server && !groups.is_empty()).then(|| {
        position(GroupKind::Classical).is_none_or(|c| position(GroupKind::PostQuantum) < Some(c))
    });
    PostQuantum {
        status,
        groups,
        draft_groups,
        preferred,
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the post-quantum summary.

    use super::*;

    /// TLSv1.3 key exchange result with `groups` in `order`.
    fn tls13(groups: &[u16], order: CipherOrder) -> KeyExchangeResult {
        KeyExchangeResult {
            version: ProtocolVersion::TLS13,
            groups: groups.to_vec(),
            group_order: order,
            dh_bits: None,
            dh_prime: None,
            dh_key_reused: None,
            dh_suites: Vec::new(),
        }
    }

    /// Groups are classified by registry name.
    #[test]
    fn kinds() {
        for id in [0x0200, 0x0202, 0x11eb, 0x11ec, 0x11ed, 0x11ee] {
            assert_eq!(group_kind(id), GroupKind::PostQuantum, "{id:#06x}");
        }
        assert_eq!(group_kind(0x6399), GroupKind::DraftKyber);
        assert_eq!(group_kind(0x639a), GroupKind::DraftKyber);
        for id in [0x001d, 0x0017, 0x0100, 0xfafa] {
            assert_eq!(group_kind(id), GroupKind::Classical, "{id:#06x}");
        }
    }

    /// ML-KEM groups make the server ready; preference follows server order.
    #[test]
    fn ready() {
        let pq = post_quantum_readiness(&[tls13(&[0x11ec, 0x001d, 0x6399], CipherOrder::Server)]);
        assert_eq!(pq.status, PqStatus::Ready);
        assert_eq!(pq.groups, [0x11ec]);
        assert_eq!(pq.draft_groups, [0x6399]);
        assert_eq!(pq.preferred, Some(true));

        let pq = post_quantum_readiness(&[tls13(&[0x001d, 0x11ec], CipherOrder::Server)]);
        assert_eq!(pq.preferred, Some(false));
        let pq = post_quantum_readiness(&[tls13(&[0x6399, 0x11ec, 0x001d], CipherOrder::Server)]);
        assert_eq!(pq.preferred, Some(true));
        let pq = post_quantum_readiness(&[tls13(&[0x001d, 0x11ec], CipherOrder::Client)]);
        assert_eq!(pq.preferred, None);
    }

    /// Draft-only, classical-only and unmeasured servers.
    #[test]
    fn not_ready() {
        let pq = post_quantum_readiness(&[tls13(&[0x639a, 0x001d], CipherOrder::Server)]);
        assert_eq!(pq.status, PqStatus::DraftOnly);
        assert_eq!(pq.preferred, None);

        let pq = post_quantum_readiness(&[tls13(&[0x001d], CipherOrder::Server)]);
        assert_eq!(pq.status, PqStatus::NotReady);

        let mut tls12 = tls13(&[0x11ec], CipherOrder::Server);
        tls12.version = ProtocolVersion::TLS12;
        assert_eq!(post_quantum_readiness(&[tls12]).status, PqStatus::NotTested);
        assert_eq!(
            post_quantum_readiness(&[tls13(&[], CipherOrder::NotApplicable)]).status,
            PqStatus::NotTested
        );
        assert_eq!(PqStatus::DraftOnly.as_str(), "draft only");
    }
}
