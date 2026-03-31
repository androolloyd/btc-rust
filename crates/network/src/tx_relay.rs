use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use btc_primitives::hash::{Hash256, TxHash};

use crate::message::{InvItem, InvType};

/// Policy configuration for transaction relay behavior.
#[derive(Debug, Clone)]
pub struct RelayPolicy {
    /// Maximum number of txids per inv message.
    pub max_inv_size: usize,
    /// Seconds before a pending getdata request is considered timed out.
    pub request_timeout_secs: u64,
    /// Maximum number of outstanding getdata requests at any time.
    pub max_pending_requests: usize,
}

impl Default for RelayPolicy {
    fn default() -> Self {
        RelayPolicy {
            max_inv_size: 50_000,
            request_timeout_secs: 60,
            max_pending_requests: 100,
        }
    }
}

/// Manages the state for relaying transactions between peers.
///
/// Tracks which transactions have been announced to which peers, which
/// transactions we are waiting to receive, and which transaction hashes
/// we have seen recently (to avoid redundant requests).
pub struct TxRelay {
    /// Transactions we've announced to peers (txid -> set of peer addrs).
    announced: HashMap<TxHash, HashSet<SocketAddr>>,
    /// Transactions we're waiting to receive from peers (txid -> (peer, request time)).
    requested: HashMap<TxHash, (SocketAddr, Instant)>,
    /// Recently seen tx hashes (to avoid re-requesting).
    recently_seen: HashSet<TxHash>,
    /// Request timeout duration.
    request_timeout: Duration,
}

impl TxRelay {
    /// Create a new `TxRelay` with default settings (60-second request timeout).
    pub fn new() -> Self {
        TxRelay {
            announced: HashMap::new(),
            requested: HashMap::new(),
            recently_seen: HashSet::new(),
            request_timeout: Duration::from_secs(60),
        }
    }

    /// Create a new `TxRelay` with a custom relay policy.
    pub fn with_policy(policy: &RelayPolicy) -> Self {
        TxRelay {
            announced: HashMap::new(),
            requested: HashMap::new(),
            recently_seen: HashSet::new(),
            request_timeout: Duration::from_secs(policy.request_timeout_secs),
        }
    }

    /// Handle incoming `inv` messages from a peer.
    ///
    /// Returns the subset of `txids` that we should request via `getdata` --
    /// i.e., those that are not already known (recently seen) and not already
    /// requested from another peer.
    pub fn on_inv(&mut self, peer: SocketAddr, txids: Vec<TxHash>) -> Vec<TxHash> {
        let mut to_request = Vec::new();
        for txid in txids {
            if self.recently_seen.contains(&txid) {
                continue;
            }
            if self.requested.contains_key(&txid) {
                continue;
            }
            self.requested.insert(txid, (peer, Instant::now()));
            to_request.push(txid);
        }
        to_request
    }

    /// Mark a transaction as received.
    ///
    /// Removes it from the pending requests and adds it to the recently-seen
    /// set so we won't request it again.
    pub fn on_tx_received(&mut self, txid: &TxHash) {
        self.requested.remove(txid);
        self.recently_seen.insert(*txid);
    }

    /// Handle a transaction that has been accepted into our mempool.
    ///
    /// Given the full set of connected `peers`, returns `(peer, txid)` pairs
    /// for every peer that has *not* already been told about this transaction.
    /// This is used to build outgoing `inv` messages.
    pub fn on_tx_accepted(
        &mut self,
        txid: &TxHash,
        peers: &[SocketAddr],
    ) -> Vec<(SocketAddr, TxHash)> {
        let already_announced = self.announced.get(txid);
        let mut announcements = Vec::new();

        for &peer in peers {
            let should_announce = match already_announced {
                Some(set) => !set.contains(&peer),
                None => true,
            };
            if should_announce {
                announcements.push((peer, *txid));
            }
        }

        announcements
    }

    /// Build a list of `InvItem`s for announcing the given transaction hashes.
    pub fn build_inv_message(&self, txids: &[TxHash]) -> Vec<InvItem> {
        txids
            .iter()
            .map(|txid| InvItem {
                inv_type: InvType::Tx,
                hash: Hash256::from_bytes(txid.to_bytes()),
            })
            .collect()
    }

    /// Check for timed-out getdata requests.
    ///
    /// Returns `(peer, txid)` pairs for requests that have exceeded the
    /// timeout, removing them from the pending set so they can be retried
    /// from a different peer.
    pub fn check_timeouts(&mut self) -> Vec<(SocketAddr, TxHash)> {
        let now = Instant::now();
        let mut timed_out = Vec::new();

        let expired_txids: Vec<TxHash> = self
            .requested
            .iter()
            .filter(|(_, (_, when))| now.duration_since(*when) >= self.request_timeout)
            .map(|(txid, _)| *txid)
            .collect();

        for txid in expired_txids {
            if let Some((peer, _)) = self.requested.remove(&txid) {
                timed_out.push((peer, txid));
            }
        }

        timed_out
    }

    /// Record that we have announced a transaction to a specific peer.
    pub fn mark_announced(&mut self, txid: &TxHash, peer: &SocketAddr) {
        self.announced
            .entry(*txid)
            .or_default()
            .insert(*peer);
    }
}

impl Default for TxRelay {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(port: u16) -> SocketAddr {
        use std::net::{IpAddr, Ipv4Addr};
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    fn txhash(byte: u8) -> TxHash {
        TxHash::from_bytes([byte; 32])
    }

    #[test]
    fn test_on_inv_returns_only_unknown_txids() {
        let mut relay = TxRelay::new();
        let peer = addr(8333);
        let tx1 = txhash(1);
        let tx2 = txhash(2);

        // Mark tx1 as recently seen
        relay.recently_seen.insert(tx1);

        let to_request = relay.on_inv(peer, vec![tx1, tx2]);

        // Only tx2 should be requested since tx1 is already known
        assert_eq!(to_request, vec![tx2]);
    }

    #[test]
    fn test_on_inv_does_not_return_already_requested_txids() {
        let mut relay = TxRelay::new();
        let peer1 = addr(8333);
        let peer2 = addr(8334);
        let tx1 = txhash(1);

        // First peer announces tx1 — should be requested
        let first = relay.on_inv(peer1, vec![tx1]);
        assert_eq!(first, vec![tx1]);

        // Second peer announces the same tx1 — should NOT be requested again
        let second = relay.on_inv(peer2, vec![tx1]);
        assert!(second.is_empty());
    }

    #[test]
    fn test_on_tx_received_clears_from_requested() {
        let mut relay = TxRelay::new();
        let peer = addr(8333);
        let tx1 = txhash(1);

        relay.on_inv(peer, vec![tx1]);
        assert!(relay.requested.contains_key(&tx1));

        relay.on_tx_received(&tx1);
        assert!(!relay.requested.contains_key(&tx1));
        assert!(relay.recently_seen.contains(&tx1));
    }

    #[test]
    fn test_on_tx_accepted_returns_correct_announcement_pairs() {
        let mut relay = TxRelay::new();
        let peer1 = addr(8333);
        let peer2 = addr(8334);
        let peer3 = addr(8335);
        let tx1 = txhash(1);

        // Simulate: peer1 already knows about tx1 (we announced to them)
        relay.mark_announced(&tx1, &peer1);

        let peers = vec![peer1, peer2, peer3];
        let announcements = relay.on_tx_accepted(&tx1, &peers);

        // Should announce to peer2 and peer3, but NOT peer1
        assert_eq!(announcements.len(), 2);
        assert!(announcements.contains(&(peer2, tx1)));
        assert!(announcements.contains(&(peer3, tx1)));
        assert!(!announcements.iter().any(|(p, _)| *p == peer1));
    }

    #[test]
    fn test_check_timeouts_returns_expired_requests() {
        let mut relay = TxRelay::new();
        // Use a very short timeout for testing
        relay.request_timeout = Duration::from_millis(0);

        let peer = addr(8333);
        let tx1 = txhash(1);

        relay.on_inv(peer, vec![tx1]);

        // The request was created with Instant::now() and timeout is 0ms,
        // so it should be expired immediately (or after a tiny delay).
        std::thread::sleep(Duration::from_millis(1));

        let timed_out = relay.check_timeouts();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0], (peer, tx1));

        // The request should have been removed
        assert!(!relay.requested.contains_key(&tx1));
    }

    #[test]
    fn test_recently_seen_prevents_re_requesting() {
        let mut relay = TxRelay::new();
        let peer1 = addr(8333);
        let peer2 = addr(8334);
        let tx1 = txhash(1);

        // Receive tx1 from peer1
        relay.on_inv(peer1, vec![tx1]);
        relay.on_tx_received(&tx1);

        // Now peer2 announces the same tx — should be rejected
        let to_request = relay.on_inv(peer2, vec![tx1]);
        assert!(to_request.is_empty());
    }

    #[test]
    fn test_build_inv_message() {
        let relay = TxRelay::new();
        let tx1 = txhash(1);
        let tx2 = txhash(2);

        let items = relay.build_inv_message(&[tx1, tx2]);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].inv_type, InvType::Tx);
        assert_eq!(items[0].hash, Hash256::from_bytes(tx1.to_bytes()));
        assert_eq!(items[1].inv_type, InvType::Tx);
        assert_eq!(items[1].hash, Hash256::from_bytes(tx2.to_bytes()));
    }

    #[test]
    fn test_relay_policy_defaults() {
        let policy = RelayPolicy::default();
        assert_eq!(policy.max_inv_size, 50_000);
        assert_eq!(policy.request_timeout_secs, 60);
        assert_eq!(policy.max_pending_requests, 100);
    }

    #[test]
    fn test_with_policy_custom_timeout() {
        let policy = RelayPolicy {
            request_timeout_secs: 120,
            ..RelayPolicy::default()
        };
        let relay = TxRelay::with_policy(&policy);
        assert_eq!(relay.request_timeout, Duration::from_secs(120));
    }
}
