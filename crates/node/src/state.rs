//! # Shared Node State
//!
//! A single [`NodeState`] struct holds every piece of mutable runtime state that
//! the node's sub-systems (RPC, Esplora HTTP, ZMQ, Electrum, metrics) need.
//! Each field is wrapped in an `Arc<Atomic*>` or `Arc<RwLock<…>>` so that
//! cloning a `NodeState` is cheap and every clone sees the same live data.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use btc_primitives::network::Network;

use crate::http::MetricsCollector;

// ---------------------------------------------------------------------------
// NodeState
// ---------------------------------------------------------------------------

/// Shared, thread-safe state that is created once at startup and handed (by
/// `Arc`-clone or field-clone) to every sub-system of the node.
#[derive(Debug, Clone)]
pub struct NodeState {
    pub chain_height: Arc<AtomicU64>,
    pub best_hash: Arc<RwLock<String>>,
    pub peer_count: Arc<AtomicU64>,
    pub mempool_size: Arc<AtomicU64>,
    pub mempool_bytes: Arc<AtomicU64>,
    pub syncing: Arc<AtomicBool>,
    pub network: Network,
}

impl NodeState {
    /// Create a new `NodeState` initialised to genesis / zero values.
    pub fn new(network: Network) -> Self {
        let genesis_hash = match network {
            Network::Mainnet => {
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f".to_string()
            }
            Network::Testnet => {
                "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943".to_string()
            }
            Network::Signet => {
                "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6".to_string()
            }
            Network::Regtest => {
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206".to_string()
            }
            Network::Testnet4 => {
                "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043".to_string()
            }
        };

        Self {
            chain_height: Arc::new(AtomicU64::new(0)),
            best_hash: Arc::new(RwLock::new(genesis_hash)),
            peer_count: Arc::new(AtomicU64::new(0)),
            mempool_size: Arc::new(AtomicU64::new(0)),
            mempool_bytes: Arc::new(AtomicU64::new(0)),
            syncing: Arc::new(AtomicBool::new(false)),
            network,
        }
    }

    /// Update the chain tip height and best block hash.
    pub fn update_chain_tip(&self, height: u64, hash: &str) {
        self.chain_height.store(height, Ordering::SeqCst);
        if let Ok(mut guard) = self.best_hash.write() {
            *guard = hash.to_string();
        }
    }

    /// Update the connected peer count.
    pub fn update_peers(&self, count: u64) {
        self.peer_count.store(count, Ordering::SeqCst);
    }

    /// Update mempool statistics.
    pub fn update_mempool(&self, size: u64, bytes: u64) {
        self.mempool_size.store(size, Ordering::SeqCst);
        self.mempool_bytes.store(bytes, Ordering::SeqCst);
    }

    /// Return the Bitcoin Core-style network name used by RPC (`"main"`,
    /// `"test"`, `"signet"`, `"regtest"`).
    pub fn rpc_network_name(&self) -> String {
        match self.network {
            Network::Mainnet => "main".to_string(),
            Network::Testnet => "test".to_string(),
            Network::Testnet4 => "testnet4".to_string(),
            Network::Signet => "signet".to_string(),
            Network::Regtest => "regtest".to_string(),
        }
    }

    /// Build a [`MetricsCollector`] that shares the same atomic fields as this
    /// `NodeState`, so any update to the state is immediately visible in the
    /// Esplora / Prometheus endpoints.
    pub fn metrics_collector(&self) -> MetricsCollector {
        MetricsCollector {
            chain_height: Arc::clone(&self.chain_height),
            peer_count: Arc::clone(&self.peer_count),
            mempool_size: Arc::clone(&self.mempool_size),
            mempool_bytes: Arc::clone(&self.mempool_bytes),
            sync_progress: Arc::new(AtomicU64::new(0)),
            blocks_validated_total: Arc::new(AtomicU64::new(0)),
            utxo_set_size: Arc::new(AtomicU64::new(0)),
            best_block_hash: Arc::clone(&self.best_hash),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_state_new_mainnet() {
        let state = NodeState::new(Network::Mainnet);
        assert_eq!(state.chain_height.load(Ordering::SeqCst), 0);
        assert_eq!(
            *state.best_hash.read().unwrap(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert_eq!(state.peer_count.load(Ordering::SeqCst), 0);
        assert_eq!(state.mempool_size.load(Ordering::SeqCst), 0);
        assert_eq!(state.mempool_bytes.load(Ordering::SeqCst), 0);
        assert!(!state.syncing.load(Ordering::SeqCst));
        assert_eq!(state.network, Network::Mainnet);
    }

    #[test]
    fn test_node_state_new_regtest() {
        let state = NodeState::new(Network::Regtest);
        assert_eq!(
            *state.best_hash.read().unwrap(),
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
        );
        assert_eq!(state.network, Network::Regtest);
    }

    #[test]
    fn test_update_chain_tip() {
        let state = NodeState::new(Network::Mainnet);
        state.update_chain_tip(100, "00000000000000aabbccdd");
        assert_eq!(state.chain_height.load(Ordering::SeqCst), 100);
        assert_eq!(
            *state.best_hash.read().unwrap(),
            "00000000000000aabbccdd"
        );
    }

    #[test]
    fn test_update_peers() {
        let state = NodeState::new(Network::Mainnet);
        state.update_peers(8);
        assert_eq!(state.peer_count.load(Ordering::SeqCst), 8);
    }

    #[test]
    fn test_update_mempool() {
        let state = NodeState::new(Network::Mainnet);
        state.update_mempool(42, 12345);
        assert_eq!(state.mempool_size.load(Ordering::SeqCst), 42);
        assert_eq!(state.mempool_bytes.load(Ordering::SeqCst), 12345);
    }

    #[test]
    fn test_rpc_network_name() {
        assert_eq!(NodeState::new(Network::Mainnet).rpc_network_name(), "main");
        assert_eq!(NodeState::new(Network::Testnet).rpc_network_name(), "test");
        assert_eq!(NodeState::new(Network::Signet).rpc_network_name(), "signet");
        assert_eq!(
            NodeState::new(Network::Regtest).rpc_network_name(),
            "regtest"
        );
    }

    #[test]
    fn test_metrics_collector_shares_state() {
        let state = NodeState::new(Network::Mainnet);
        let metrics = state.metrics_collector();

        // Update state -- metrics should see the change.
        state.update_chain_tip(500, "00000000000000001111");
        assert_eq!(metrics.chain_height.load(Ordering::Relaxed), 500);
        assert_eq!(metrics.get_best_block_hash(), "00000000000000001111");

        state.update_peers(10);
        assert_eq!(metrics.peer_count.load(Ordering::Relaxed), 10);

        state.update_mempool(200, 50000);
        assert_eq!(metrics.mempool_size.load(Ordering::Relaxed), 200);
        assert_eq!(metrics.mempool_bytes.load(Ordering::Relaxed), 50000);
    }

    #[test]
    fn test_clone_shares_state() {
        let state = NodeState::new(Network::Mainnet);
        let state2 = state.clone();

        state.update_chain_tip(42, "aabbccdd");
        assert_eq!(state2.chain_height.load(Ordering::SeqCst), 42);
        assert_eq!(*state2.best_hash.read().unwrap(), "aabbccdd");
    }

    #[test]
    fn test_node_state_new_testnet() {
        let state = NodeState::new(Network::Testnet);
        assert_eq!(
            *state.best_hash.read().unwrap(),
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
        );
        assert_eq!(state.network, Network::Testnet);
    }

    #[test]
    fn test_node_state_new_signet() {
        let state = NodeState::new(Network::Signet);
        assert_eq!(
            *state.best_hash.read().unwrap(),
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
        );
        assert_eq!(state.network, Network::Signet);
    }

    #[test]
    fn test_update_chain_tip_zero() {
        let state = NodeState::new(Network::Mainnet);
        state.update_chain_tip(0, "deadbeef");
        assert_eq!(state.chain_height.load(Ordering::SeqCst), 0);
        assert_eq!(*state.best_hash.read().unwrap(), "deadbeef");
    }

    #[test]
    fn test_update_chain_tip_large_height() {
        let state = NodeState::new(Network::Mainnet);
        state.update_chain_tip(u64::MAX, "ffffffff");
        assert_eq!(state.chain_height.load(Ordering::SeqCst), u64::MAX);
    }

    #[test]
    fn test_update_peers_zero() {
        let state = NodeState::new(Network::Mainnet);
        state.update_peers(100);
        state.update_peers(0);
        assert_eq!(state.peer_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_update_mempool_zero() {
        let state = NodeState::new(Network::Mainnet);
        state.update_mempool(0, 0);
        assert_eq!(state.mempool_size.load(Ordering::SeqCst), 0);
        assert_eq!(state.mempool_bytes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_syncing_flag() {
        let state = NodeState::new(Network::Mainnet);
        assert!(!state.syncing.load(Ordering::SeqCst));
        state.syncing.store(true, Ordering::SeqCst);
        assert!(state.syncing.load(Ordering::SeqCst));
        state.syncing.store(false, Ordering::SeqCst);
        assert!(!state.syncing.load(Ordering::SeqCst));
    }

    #[test]
    fn test_node_state_debug() {
        let state = NodeState::new(Network::Mainnet);
        let debug = format!("{:?}", state);
        assert!(debug.contains("NodeState"));
    }

    #[test]
    fn test_rpc_handler_reflects_node_state() {
        use btc_rpc::handler::RpcHandler;

        let state = NodeState::new(Network::Regtest);
        let rpc = RpcHandler::new_with_state(
            Arc::clone(&state.chain_height),
            Arc::clone(&state.best_hash),
            state.rpc_network_name(),
            Arc::clone(&state.peer_count),
            Arc::clone(&state.mempool_size),
            Arc::clone(&state.mempool_bytes),
        );

        // Initially at height 0
        let req = btc_rpc::handler::RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "getblockcount".to_string(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = rpc.handle(&req);
        assert_eq!(resp.result.unwrap(), serde_json::json!(0));

        // Update via NodeState
        state.update_chain_tip(777, "00000000deadbeef");

        let resp = rpc.handle(&req);
        assert_eq!(resp.result.unwrap(), serde_json::json!(777));
    }

    #[test]
    fn test_metrics_collector_renders_updated_values() {
        let state = NodeState::new(Network::Mainnet);
        let metrics = state.metrics_collector();

        state.update_chain_tip(800_000, "00000000000000000001abc");
        state.update_peers(12);
        state.update_mempool(5000, 2_500_000);

        let output = metrics.render_prometheus();
        assert!(output.contains("btc_chain_height 800000"));
        assert!(output.contains("btc_peer_count 12"));
        assert!(output.contains("btc_mempool_size 5000"));
        assert!(output.contains("btc_mempool_bytes 2500000"));
    }
}
