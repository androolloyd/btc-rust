use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use btc_primitives::network::Network;
use tracing::{debug, info, warn};

use crate::peer::PeerInfo;

// ---------------------------------------------------------------------------
// DNS Seeds
// ---------------------------------------------------------------------------

/// Official Bitcoin mainnet DNS seeds.
pub const MAINNET_DNS_SEEDS: &[&str] = &[
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.net",
    "seed.bitcoin.sprovoost.nl",
    "dnsseed.emzy.de",
    "seed.bitcoin.wiz.biz",
];

/// Official Bitcoin testnet DNS seeds.
pub const TESTNET_DNS_SEEDS: &[&str] = &[
    "testnet-seed.bitcoin.jonasschnelli.ch",
    "seed.tbtc.petertodd.net",
    "seed.testnet.bitcoin.sprovoost.nl",
    "testnet-seed.bluematt.me",
];

/// Signet DNS seeds.
pub const SIGNET_DNS_SEEDS: &[&str] = &[
    "seed.signet.bitcoin.sprovoost.nl",
];

/// Return the DNS seed list for the given network.
pub fn dns_seeds(network: Network) -> &'static [&'static str] {
    match network {
        Network::Mainnet => MAINNET_DNS_SEEDS,
        Network::Testnet => TESTNET_DNS_SEEDS,
        Network::Testnet4 => TESTNET_DNS_SEEDS,
        Network::Signet => SIGNET_DNS_SEEDS,
        Network::Regtest => &[], // regtest has no DNS seeds
    }
}

// ---------------------------------------------------------------------------
// Peer discovery
// ---------------------------------------------------------------------------

/// Resolve all DNS seeds for the given `network` and return a deduplicated
/// list of `SocketAddr` values (each with the network's default P2P port).
pub async fn discover_peers(network: Network) -> Vec<SocketAddr> {
    let seeds = dns_seeds(network);
    let port = network.default_port();
    let mut addrs = Vec::new();

    for seed in seeds {
        let host = format!("{}:{}", seed, port);
        let result: Result<Vec<SocketAddr>, _> = tokio::net::lookup_host(host.as_str())
            .await
            .map(|iter| iter.collect());
        match result {
            Ok(resolved) => {
                let count_before = addrs.len();
                for a in resolved {
                    let a = SocketAddr::new(a.ip(), port);
                    addrs.push(a);
                }
                debug!(
                    seed,
                    found = addrs.len() - count_before,
                    "resolved DNS seed"
                );
            }
            Err(e) => {
                warn!(seed, error = %e, "failed to resolve DNS seed");
            }
        }
    }

    // Deduplicate while preserving order.
    let mut seen = std::collections::HashSet::new();
    addrs.retain(|a| seen.insert(*a));

    info!(
        network = %network,
        total = addrs.len(),
        "peer discovery complete"
    );
    addrs
}

// ---------------------------------------------------------------------------
// Peer scoring
// ---------------------------------------------------------------------------

/// Reason a peer has been banned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanReason {
    /// Peer sent a message with the wrong magic bytes.
    WrongMagic,
    /// Peer sent an invalid / unparseable message.
    InvalidMessage,
    /// Peer misbehaved in some other protocol-specific way.
    Misbehaviour,
}

/// Lightweight per-peer score tracking.
#[derive(Debug, Clone)]
pub struct PeerScore {
    /// When we last heard from this peer.
    pub last_seen: Instant,
    /// Average response latency (if we have measurements).
    pub avg_latency_ms: Option<u64>,
    /// Accumulated penalty points.  A peer is considered banned when this
    /// reaches or exceeds [`BAN_THRESHOLD`].
    pub penalty: u32,
    /// If set, the peer is banned and should not be connected to.
    pub ban_reason: Option<BanReason>,
}

/// Penalty threshold at which a peer is automatically banned.
pub const BAN_THRESHOLD: u32 = 100;

impl PeerScore {
    pub fn new() -> Self {
        PeerScore {
            last_seen: Instant::now(),
            avg_latency_ms: None,
            penalty: 0,
            ban_reason: None,
        }
    }

    /// Record a response latency measurement.
    pub fn record_latency(&mut self, latency_ms: u64) {
        self.last_seen = Instant::now();
        self.avg_latency_ms = Some(match self.avg_latency_ms {
            Some(prev) => (prev + latency_ms) / 2,
            None => latency_ms,
        });
    }

    /// Apply a penalty.  If the accumulated penalty reaches the ban
    /// threshold the peer is automatically banned.
    pub fn add_penalty(&mut self, points: u32, reason: BanReason) {
        self.penalty = self.penalty.saturating_add(points);
        if self.penalty >= BAN_THRESHOLD {
            self.ban_reason = Some(reason);
        }
    }

    /// Immediately ban the peer.
    pub fn ban(&mut self, reason: BanReason) {
        self.penalty = BAN_THRESHOLD;
        self.ban_reason = Some(reason);
    }

    /// Returns `true` if this peer is currently banned.
    pub fn is_banned(&self) -> bool {
        self.ban_reason.is_some()
    }

    /// Mark the peer as seen right now.
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }
}

impl Default for PeerScore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PeerManager
// ---------------------------------------------------------------------------

/// Manages the set of known and connected peers.
pub struct PeerManager {
    /// Peers we know about but may or may not be connected to.
    known_peers: Vec<SocketAddr>,
    /// Currently connected peers.
    connected: HashMap<SocketAddr, PeerInfo>,
    /// Per-peer scoring / ban tracking.
    scores: HashMap<SocketAddr, PeerScore>,
    /// Maximum number of outbound connections.
    max_outbound: usize,
    /// Maximum number of inbound connections.
    max_inbound: usize,
    /// The network we are operating on.
    network: Network,
}

impl PeerManager {
    /// Create a new `PeerManager` with default connection limits.
    pub fn new(network: Network) -> Self {
        PeerManager {
            known_peers: Vec::new(),
            connected: HashMap::new(),
            scores: HashMap::new(),
            max_outbound: 8,
            max_inbound: 125,
            network,
        }
    }

    /// Bootstrap the manager by performing DNS seed discovery and populating
    /// `known_peers`.
    pub async fn bootstrap(&mut self) {
        let peers = discover_peers(self.network).await;
        for addr in peers {
            if !self.known_peers.contains(&addr) {
                self.known_peers.push(addr);
            }
        }
        info!(
            known = self.known_peers.len(),
            "bootstrap complete"
        );
    }

    /// Register a connected peer.
    pub fn add_peer(&mut self, addr: SocketAddr, info: PeerInfo) {
        if !self.known_peers.contains(&addr) {
            self.known_peers.push(addr);
        }
        self.scores.entry(addr).or_insert_with(PeerScore::new).touch();
        self.connected.insert(addr, info);
    }

    /// Remove a connected peer (disconnect).
    pub fn remove_peer(&mut self, addr: &SocketAddr) {
        self.connected.remove(addr);
    }

    /// Pick a random peer from `known_peers` that we are not already connected
    /// to and that is not banned.
    pub fn get_random_peer(&self) -> Option<SocketAddr> {
        let candidates: Vec<_> = self
            .known_peers
            .iter()
            .copied()
            .filter(|a| !self.connected.contains_key(a))
            .filter(|a| {
                self.scores
                    .get(a)
                    .map(|s| !s.is_banned())
                    .unwrap_or(true)
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        use rand::Rng;
        let idx = rand::thread_rng().gen_range(0..candidates.len());
        Some(candidates[idx])
    }

    /// Number of currently connected peers.
    pub fn connected_count(&self) -> usize {
        self.connected.len()
    }

    /// Returns `true` if we are below our desired outbound connection count.
    pub fn needs_more_peers(&self) -> bool {
        let outbound = self
            .connected
            .values()
            .filter(|p| !p.inbound)
            .count();
        outbound < self.max_outbound
    }

    /// Process an `addr` message from a peer — merge the new addresses into
    /// our known-peers list (deduplicating).
    pub fn on_addr_message(&mut self, addrs: Vec<SocketAddr>) {
        for addr in addrs {
            if !self.known_peers.contains(&addr) {
                self.known_peers.push(addr);
            }
        }
    }

    /// Retrieve the scoring entry for a given peer (if any).
    pub fn score(&self, addr: &SocketAddr) -> Option<&PeerScore> {
        self.scores.get(addr)
    }

    /// Retrieve a mutable scoring entry, creating a default one if it does
    /// not yet exist.
    pub fn score_mut(&mut self, addr: &SocketAddr) -> &mut PeerScore {
        self.scores.entry(*addr).or_insert_with(PeerScore::new)
    }

    /// Ban a peer immediately.
    pub fn ban_peer(&mut self, addr: &SocketAddr, reason: BanReason) {
        self.score_mut(addr).ban(reason);
        self.connected.remove(addr);
    }

    /// Return a snapshot of known peers.
    pub fn known_peers(&self) -> &[SocketAddr] {
        &self.known_peers
    }

    /// Return the network this manager operates on.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Maximum outbound connections.
    pub fn max_outbound(&self) -> usize {
        self.max_outbound
    }

    /// Maximum inbound connections.
    pub fn max_inbound(&self) -> usize {
        self.max_inbound
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::{PeerInfo, PeerState};
    use crate::protocol::{ProtocolVersion, ServiceFlags};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    // Helper: build a dummy PeerInfo for testing.
    fn dummy_peer_info(addr: SocketAddr, inbound: bool) -> PeerInfo {
        PeerInfo {
            addr,
            state: PeerState::Ready,
            version: ProtocolVersion::CURRENT,
            services: ServiceFlags::NETWORK,
            user_agent: "/test:0.0.1/".to_string(),
            start_height: 800_000,
            relay: true,
            inbound,
        }
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    // -----------------------------------------------------------------------
    // DNS seed list sanity checks
    // -----------------------------------------------------------------------

    #[test]
    fn mainnet_dns_seeds_non_empty() {
        assert!(!MAINNET_DNS_SEEDS.is_empty());
    }

    #[test]
    fn testnet_dns_seeds_non_empty() {
        assert!(!TESTNET_DNS_SEEDS.is_empty());
    }

    #[test]
    fn signet_dns_seeds_non_empty() {
        assert!(!SIGNET_DNS_SEEDS.is_empty());
    }

    #[test]
    fn regtest_has_no_dns_seeds() {
        assert!(dns_seeds(Network::Regtest).is_empty());
    }

    #[test]
    fn dns_seeds_returns_correct_list() {
        assert_eq!(dns_seeds(Network::Mainnet), MAINNET_DNS_SEEDS);
        assert_eq!(dns_seeds(Network::Testnet), TESTNET_DNS_SEEDS);
        assert_eq!(dns_seeds(Network::Signet), SIGNET_DNS_SEEDS);
    }

    // -----------------------------------------------------------------------
    // PeerManager — construction
    // -----------------------------------------------------------------------

    #[test]
    fn peer_manager_new_defaults() {
        let pm = PeerManager::new(Network::Mainnet);
        assert_eq!(pm.network(), Network::Mainnet);
        assert_eq!(pm.max_outbound(), 8);
        assert_eq!(pm.max_inbound(), 125);
        assert_eq!(pm.connected_count(), 0);
        assert!(pm.known_peers().is_empty());
    }

    // -----------------------------------------------------------------------
    // PeerManager — add / remove
    // -----------------------------------------------------------------------

    #[test]
    fn add_and_remove_peer() {
        let mut pm = PeerManager::new(Network::Mainnet);
        let a = addr(8333);
        let info = dummy_peer_info(a, false);

        pm.add_peer(a, info);
        assert_eq!(pm.connected_count(), 1);
        assert!(pm.known_peers().contains(&a));

        pm.remove_peer(&a);
        assert_eq!(pm.connected_count(), 0);
        // known_peers retains the address even after disconnect
        assert!(pm.known_peers().contains(&a));
    }

    #[test]
    fn add_peer_deduplicates_known() {
        let mut pm = PeerManager::new(Network::Mainnet);
        let a = addr(8333);
        let info = dummy_peer_info(a, false);

        pm.add_peer(a, info.clone());
        pm.remove_peer(&a);
        pm.add_peer(a, info);
        // The address should appear exactly once in known_peers.
        assert_eq!(pm.known_peers().iter().filter(|&&x| x == a).count(), 1);
    }

    // -----------------------------------------------------------------------
    // PeerManager — connected_count
    // -----------------------------------------------------------------------

    #[test]
    fn connected_count_tracking() {
        let mut pm = PeerManager::new(Network::Mainnet);

        let a1 = addr(1);
        let a2 = addr(2);
        let a3 = addr(3);

        pm.add_peer(a1, dummy_peer_info(a1, false));
        assert_eq!(pm.connected_count(), 1);

        pm.add_peer(a2, dummy_peer_info(a2, false));
        pm.add_peer(a3, dummy_peer_info(a3, true));
        assert_eq!(pm.connected_count(), 3);

        pm.remove_peer(&a2);
        assert_eq!(pm.connected_count(), 2);
    }

    // -----------------------------------------------------------------------
    // PeerManager — needs_more_peers
    // -----------------------------------------------------------------------

    #[test]
    fn needs_more_peers_initially_true() {
        let pm = PeerManager::new(Network::Mainnet);
        assert!(pm.needs_more_peers());
    }

    #[test]
    fn needs_more_peers_becomes_false() {
        let mut pm = PeerManager::new(Network::Mainnet);
        // Fill up the outbound slots (max_outbound = 8 by default).
        for i in 0..8 {
            let a = addr(8333 + i);
            pm.add_peer(a, dummy_peer_info(a, false));
        }
        assert!(!pm.needs_more_peers());
    }

    #[test]
    fn inbound_peers_do_not_count_for_needs_more() {
        let mut pm = PeerManager::new(Network::Mainnet);
        // Add 10 inbound peers — we should still need outbound ones.
        for i in 0..10 {
            let a = addr(9000 + i);
            pm.add_peer(a, dummy_peer_info(a, true));
        }
        assert!(pm.needs_more_peers());
    }

    // -----------------------------------------------------------------------
    // PeerManager — on_addr_message
    // -----------------------------------------------------------------------

    #[test]
    fn on_addr_message_merges_new_peers() {
        let mut pm = PeerManager::new(Network::Mainnet);
        let existing = addr(8333);
        pm.add_peer(existing, dummy_peer_info(existing, false));

        let new_addrs = vec![addr(8334), addr(8335), addr(8333)]; // 8333 is a dup
        pm.on_addr_message(new_addrs);

        assert_eq!(pm.known_peers().len(), 3); // 8333, 8334, 8335
    }

    // -----------------------------------------------------------------------
    // PeerManager — get_random_peer
    // -----------------------------------------------------------------------

    #[test]
    fn get_random_peer_returns_none_when_empty() {
        let pm = PeerManager::new(Network::Mainnet);
        assert!(pm.get_random_peer().is_none());
    }

    #[test]
    fn get_random_peer_skips_connected() {
        let mut pm = PeerManager::new(Network::Mainnet);
        let a = addr(8333);
        pm.add_peer(a, dummy_peer_info(a, false));
        // Only known peer is already connected.
        assert!(pm.get_random_peer().is_none());
    }

    #[test]
    fn get_random_peer_returns_unconnected() {
        let mut pm = PeerManager::new(Network::Mainnet);
        let connected = addr(8333);
        let available = addr(8334);

        pm.add_peer(connected, dummy_peer_info(connected, false));
        pm.on_addr_message(vec![available]);

        // The only candidate is the unconnected one.
        assert_eq!(pm.get_random_peer(), Some(available));
    }

    #[test]
    fn get_random_peer_skips_banned() {
        let mut pm = PeerManager::new(Network::Mainnet);
        let a = addr(8333);
        pm.on_addr_message(vec![a]);
        pm.ban_peer(&a, BanReason::WrongMagic);

        assert!(pm.get_random_peer().is_none());
    }

    // -----------------------------------------------------------------------
    // Peer scoring
    // -----------------------------------------------------------------------

    #[test]
    fn peer_score_defaults() {
        let score = PeerScore::new();
        assert!(!score.is_banned());
        assert_eq!(score.penalty, 0);
        assert!(score.avg_latency_ms.is_none());
    }

    #[test]
    fn peer_score_latency_tracking() {
        let mut score = PeerScore::new();
        score.record_latency(100);
        assert_eq!(score.avg_latency_ms, Some(100));
        score.record_latency(200);
        assert_eq!(score.avg_latency_ms, Some(150));
    }

    #[test]
    fn peer_score_penalty_accumulates() {
        let mut score = PeerScore::new();
        score.add_penalty(30, BanReason::Misbehaviour);
        assert!(!score.is_banned());
        assert_eq!(score.penalty, 30);

        score.add_penalty(30, BanReason::Misbehaviour);
        assert!(!score.is_banned());
        assert_eq!(score.penalty, 60);

        // Push past threshold.
        score.add_penalty(50, BanReason::InvalidMessage);
        assert!(score.is_banned());
        assert_eq!(score.ban_reason, Some(BanReason::InvalidMessage));
    }

    #[test]
    fn peer_score_immediate_ban() {
        let mut score = PeerScore::new();
        score.ban(BanReason::WrongMagic);
        assert!(score.is_banned());
        assert_eq!(score.penalty, BAN_THRESHOLD);
    }

    #[test]
    fn ban_peer_disconnects() {
        let mut pm = PeerManager::new(Network::Mainnet);
        let a = addr(8333);
        pm.add_peer(a, dummy_peer_info(a, false));
        assert_eq!(pm.connected_count(), 1);

        pm.ban_peer(&a, BanReason::InvalidMessage);
        assert_eq!(pm.connected_count(), 0);
        assert!(pm.score(&a).unwrap().is_banned());
    }

    // -----------------------------------------------------------------------
    // discover_peers — mocked (no real DNS)
    // -----------------------------------------------------------------------
    // We verify that `discover_peers` returns an empty list for Regtest
    // (which has no seeds) without hitting the network.

    #[tokio::test]
    async fn discover_peers_regtest_returns_empty() {
        let peers = discover_peers(Network::Regtest).await;
        assert!(peers.is_empty());
    }

    // --- PeerScore ---

    #[test]
    fn test_peer_score_default() {
        let score = PeerScore::default();
        assert!(!score.is_banned());
        assert_eq!(score.penalty, 0);
        assert!(score.avg_latency_ms.is_none());
    }

    #[test]
    fn test_peer_score_touch() {
        let mut score = PeerScore::new();
        let before = score.last_seen;
        // Touch should update last_seen (we can't test time precisely, but
        // we can verify it doesn't panic)
        score.touch();
        // last_seen should be >= before
        assert!(score.last_seen >= before);
    }

    #[test]
    fn test_peer_score_latency_first_measurement() {
        let mut score = PeerScore::new();
        score.record_latency(200);
        assert_eq!(score.avg_latency_ms, Some(200));
    }

    #[test]
    fn test_peer_score_latency_averaging() {
        let mut score = PeerScore::new();
        score.record_latency(100);
        score.record_latency(300);
        // Average of 100 and 300 = 200
        assert_eq!(score.avg_latency_ms, Some(200));
        score.record_latency(200);
        // Average of 200 and 200 = 200
        assert_eq!(score.avg_latency_ms, Some(200));
    }

    #[test]
    fn test_peer_score_penalty_below_threshold() {
        let mut score = PeerScore::new();
        score.add_penalty(50, BanReason::Misbehaviour);
        assert_eq!(score.penalty, 50);
        assert!(!score.is_banned());
        assert!(score.ban_reason.is_none());
    }

    #[test]
    fn test_peer_score_penalty_at_threshold() {
        let mut score = PeerScore::new();
        score.add_penalty(100, BanReason::InvalidMessage);
        assert_eq!(score.penalty, 100);
        assert!(score.is_banned());
        assert_eq!(score.ban_reason, Some(BanReason::InvalidMessage));
    }

    #[test]
    fn test_peer_score_penalty_saturating() {
        let mut score = PeerScore::new();
        score.add_penalty(u32::MAX, BanReason::Misbehaviour);
        assert_eq!(score.penalty, u32::MAX);
        score.add_penalty(1, BanReason::Misbehaviour);
        assert_eq!(score.penalty, u32::MAX); // saturating
    }

    #[test]
    fn test_ban_reason_values() {
        assert_ne!(BanReason::WrongMagic, BanReason::InvalidMessage);
        assert_ne!(BanReason::WrongMagic, BanReason::Misbehaviour);
        assert_ne!(BanReason::InvalidMessage, BanReason::Misbehaviour);
    }

    #[test]
    fn test_ban_reason_copy() {
        let reason = BanReason::WrongMagic;
        let copy = reason;
        assert_eq!(reason, copy);
    }

    // --- PeerManager advanced tests ---

    #[test]
    fn test_peer_manager_score_mut_creates_default() {
        let mut pm = PeerManager::new(Network::Mainnet);
        let a = addr(8333);
        // score_mut should create a default entry
        let score = pm.score_mut(&a);
        assert!(!score.is_banned());
        assert_eq!(score.penalty, 0);
    }

    #[test]
    fn test_peer_manager_score_returns_none_for_unknown() {
        let pm = PeerManager::new(Network::Mainnet);
        let a = addr(8333);
        assert!(pm.score(&a).is_none());
    }

    #[test]
    fn test_peer_manager_score_persists_after_add() {
        let mut pm = PeerManager::new(Network::Mainnet);
        let a = addr(8333);
        pm.add_peer(a, dummy_peer_info(a, false));
        let score = pm.score(&a);
        assert!(score.is_some());
    }

    #[test]
    fn test_peer_manager_ban_adds_to_scores() {
        let mut pm = PeerManager::new(Network::Mainnet);
        let a = addr(8333);
        pm.ban_peer(&a, BanReason::WrongMagic);
        assert!(pm.score(&a).unwrap().is_banned());
        assert_eq!(pm.score(&a).unwrap().ban_reason, Some(BanReason::WrongMagic));
    }

    #[test]
    fn test_peer_manager_remove_nonexistent_peer_noop() {
        let mut pm = PeerManager::new(Network::Mainnet);
        let a = addr(8333);
        // Should not panic
        pm.remove_peer(&a);
        assert_eq!(pm.connected_count(), 0);
    }

    #[test]
    fn test_peer_manager_on_addr_message_empty() {
        let mut pm = PeerManager::new(Network::Mainnet);
        pm.on_addr_message(vec![]);
        assert!(pm.known_peers().is_empty());
    }

    #[test]
    fn test_peer_manager_on_addr_message_deduplication() {
        let mut pm = PeerManager::new(Network::Mainnet);
        let a = addr(8333);
        pm.on_addr_message(vec![a, a, a]);
        assert_eq!(pm.known_peers().len(), 1);
    }

    #[test]
    fn test_peer_manager_network() {
        let pm = PeerManager::new(Network::Testnet);
        assert_eq!(pm.network(), Network::Testnet);
    }

    #[test]
    fn test_peer_manager_needs_more_peers_with_mix() {
        let mut pm = PeerManager::new(Network::Mainnet);
        // Add 4 outbound + 100 inbound
        for i in 0..4u16 {
            let a = addr(8333 + i);
            pm.add_peer(a, dummy_peer_info(a, false));
        }
        for i in 0..100u16 {
            let a = addr(9000 + i);
            pm.add_peer(a, dummy_peer_info(a, true));
        }
        // 4 < 8 outbound slots, so needs more
        assert!(pm.needs_more_peers());
    }

    #[test]
    fn test_peer_manager_get_random_peer_from_multiple() {
        let mut pm = PeerManager::new(Network::Mainnet);
        pm.on_addr_message(vec![addr(1), addr(2), addr(3), addr(4), addr(5)]);
        // Should return one of the known peers
        let peer = pm.get_random_peer();
        assert!(peer.is_some());
        let p = peer.unwrap();
        assert!(pm.known_peers().contains(&p));
    }

    // --- BAN_THRESHOLD constant ---

    #[test]
    fn test_ban_threshold() {
        assert_eq!(BAN_THRESHOLD, 100);
    }

    // --- PeerManager ban then get_random_peer ---

    #[test]
    fn test_ban_all_known_peers_no_random() {
        let mut pm = PeerManager::new(Network::Mainnet);
        let a1 = addr(1);
        let a2 = addr(2);
        pm.on_addr_message(vec![a1, a2]);
        pm.ban_peer(&a1, BanReason::InvalidMessage);
        pm.ban_peer(&a2, BanReason::Misbehaviour);
        assert!(pm.get_random_peer().is_none());
    }

    // --- Score mut with penalty ---

    #[test]
    fn test_score_mut_add_penalty() {
        let mut pm = PeerManager::new(Network::Mainnet);
        let a = addr(8333);
        pm.score_mut(&a).add_penalty(50, BanReason::Misbehaviour);
        assert_eq!(pm.score(&a).unwrap().penalty, 50);
        assert!(!pm.score(&a).unwrap().is_banned());
    }

    #[test]
    fn test_score_mut_record_latency() {
        let mut pm = PeerManager::new(Network::Mainnet);
        let a = addr(8333);
        pm.score_mut(&a).record_latency(100);
        assert_eq!(pm.score(&a).unwrap().avg_latency_ms, Some(100));
    }
}
