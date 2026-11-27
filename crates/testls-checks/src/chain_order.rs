//! Ordering evidence from the wire certificate list, independent of path building.

use std::collections::HashMap;

use x509_parser::certificate::X509Certificate;

use crate::{Finding, Severity};

/// Reports the first verifiable misplaced issuer. RFC 5246 §7.4.2 requires,
/// and RFC 8446 §4.4.2 recommends, that each certificate directly certify its
/// predecessor. TLS 1.3 also permits extraneous certificates for compatibility.
/// Missing issuers and ambiguous names alone are not evidence of misordering.
pub(super) fn misplaced_issuer(chain: &[Option<X509Certificate<'_>>]) -> Option<Finding> {
    if chain.len() < 3 {
        return None;
    }
    // Only unique subject names qualify as evidence. Never try every possible
    // path: indexing is linear and at most two signatures are checked per pair.
    let mut issuers = HashMap::new();
    for (index, cert) in chain.iter().enumerate().skip(1) {
        if let Some(cert) = cert {
            issuers
                .entry(cert.subject().as_raw())
                .and_modify(|index| *index = None)
                .or_insert(Some((index, cert.public_key())));
        }
    }
    for (child_index, pair) in chain.windows(2).enumerate() {
        let [Some(child), Some(next)] = pair else {
            continue;
        };
        let Some(&Some((issuer_index, key))) = issuers.get(child.issuer().as_raw()) else {
            continue;
        };
        if issuer_index == child_index || issuer_index == child_index + 1 {
            continue;
        }
        if child.verify_signature(Some(key)).is_ok()
            && child.verify_signature(Some(next.public_key())).is_err()
        {
            return Some(Finding::new(
                "cert.chain_order",
                Severity::Info,
                format!(
                    "presented chain: certificate #{child_index} is signed by certificate #{issuer_index}, not the following certificate #{}",
                    child_index + 1
                ),
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TrustStore, certificate_findings, is_trusted};

    /// Tests order of the *presented* certificates even when path building succeeds.
    #[test]
    fn presented_order_is_distinct_from_trust() {
        let leaf = include_bytes!("testdata/trust-leaf.der").to_vec();
        let intermediate = include_bytes!("testdata/trust-intermediate.der").to_vec();
        let root = include_bytes!("testdata/trust-root.der").to_vec();
        let roots = TrustStore::from_certificates([root.as_slice()]).unwrap();
        let now = 1_782_864_000;
        let order = |chain: &[Vec<u8>]| {
            certificate_findings(chain, None, now)
                .into_iter()
                .find(|f| f.id == "cert.chain_order")
        };
        let mut chain = [leaf, intermediate, root];
        assert!(order(&chain).is_none());
        assert!(order(&chain[..2]).is_none()); // omitted root
        chain.swap(1, 2);
        assert!(is_trusted(&chain, now, &roots));
        let finding = order(&chain).unwrap();
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.message.contains("#0 is signed by certificate #2"));
        assert!(order(&chain[..2]).is_none()); // issuer missing rather than misplaced
        chain[1] = vec![0];
        assert!(order(&chain).is_none()); // unreadable, preserve wire positions
    }

    /// A matching issuer name alone does not identify who signed the child.
    #[test]
    fn ambiguous_or_nonverifying_issuer_is_inconclusive() {
        let leaf = include_bytes!("testdata/trust-leaf.der").to_vec();
        let root = include_bytes!("testdata/trust-root.der").to_vec();
        let issuer = include_bytes!("testdata/trust-intermediate.der").to_vec();
        let mut chain = vec![leaf, root.clone(), issuer.clone(), issuer, root];
        let has_finding = |chain: &[Vec<u8>]| {
            certificate_findings(chain, None, 1_782_864_000)
                .iter()
                .any(|f| f.id == "cert.chain_order")
        };
        assert!(!has_finding(&chain)); // two candidate issuers with the same name
        chain.truncate(3);
        assert!(has_finding(&chain));
        *chain[0].last_mut().unwrap() ^= 1; // change the signature, not the issuer DN
        assert!(!has_finding(&chain));
    }
}
