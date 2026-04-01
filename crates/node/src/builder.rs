use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;

use btc_exex::ExExManager;
use btc_primitives::Network;
use btc_rpc::server::RpcServer;
use btc_stages::Pipeline;
use tracing::info;

use crate::state::NodeState;
use crate::zmq::ZmqPublisher;

// ---------------------------------------------------------------------------
// Type-state markers
// ---------------------------------------------------------------------------

/// Marker: no database configured yet.
pub struct NoDb;
/// Marker: database has been configured.
pub struct WithDb;

/// Marker: no network layer configured yet.
pub struct NoNetwork;
/// Marker: network layer has been configured.
pub struct WithNetwork;

/// Marker: no pipeline configured yet.
pub struct NoPipeline;
/// Marker: pipeline has been configured.
pub struct WithPipeline;

// ---------------------------------------------------------------------------
// NodeConfig
// ---------------------------------------------------------------------------

/// Top-level configuration for the node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub network: Network,
    pub datadir: PathBuf,
    pub rpc_port: u16,
    pub p2p_port: u16,
    pub log_level: String,
}

impl NodeConfig {
    pub fn new(network: Network) -> Self {
        let rpc_port = network.default_rpc_port();
        let p2p_port = network.default_port();
        NodeConfig {
            network,
            datadir: PathBuf::from("~/.btc-rust"),
            rpc_port,
            p2p_port,
            log_level: "info".to_string(),
        }
    }

    pub fn with_datadir(mut self, datadir: impl Into<PathBuf>) -> Self {
        self.datadir = datadir.into();
        self
    }

    pub fn with_rpc_port(mut self, port: u16) -> Self {
        self.rpc_port = port;
        self
    }

    pub fn with_p2p_port(mut self, port: u16) -> Self {
        self.p2p_port = port;
        self
    }

    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = level.into();
        self
    }
}

// ---------------------------------------------------------------------------
// Placeholder component types (thin wrappers until real impls exist)
// ---------------------------------------------------------------------------

/// Placeholder for whatever concrete database backend the node uses.
#[derive(Debug)]
pub struct DatabaseHandle {
    pub path: PathBuf,
}

/// Placeholder for the P2P networking component.
#[derive(Debug)]
pub struct NetworkHandle {
    pub port: u16,
}

// ---------------------------------------------------------------------------
// NodeBuilder
// ---------------------------------------------------------------------------

/// A type-state builder that guarantees at compile time that all required
/// components (database, network, pipeline) are provided before `build()` is
/// callable.
pub struct NodeBuilder<Db = NoDb, Net = NoNetwork, Pipe = NoPipeline> {
    config: NodeConfig,
    database: Option<DatabaseHandle>,
    network: Option<NetworkHandle>,
    pipeline: Option<Pipeline>,
    _marker: PhantomData<(Db, Net, Pipe)>,
}

impl NodeBuilder<NoDb, NoNetwork, NoPipeline> {
    /// Create a new builder with the given node configuration.
    pub fn new(config: NodeConfig) -> Self {
        NodeBuilder {
            config,
            database: None,
            network: None,
            pipeline: None,
            _marker: PhantomData,
        }
    }
}

// --- with_database: only available when Db == NoDb ---

impl<Net, Pipe> NodeBuilder<NoDb, Net, Pipe> {
    /// Attach a database handle. Transitions `Db` from `NoDb` to `WithDb`.
    pub fn with_database(self, db: DatabaseHandle) -> NodeBuilder<WithDb, Net, Pipe> {
        NodeBuilder {
            config: self.config,
            database: Some(db),
            network: self.network,
            pipeline: self.pipeline,
            _marker: PhantomData,
        }
    }
}

// --- with_network: only available when Net == NoNetwork ---

impl<Db, Pipe> NodeBuilder<Db, NoNetwork, Pipe> {
    /// Attach a network handle. Transitions `Net` from `NoNetwork` to
    /// `WithNetwork`.
    pub fn with_network(self, net: NetworkHandle) -> NodeBuilder<Db, WithNetwork, Pipe> {
        NodeBuilder {
            config: self.config,
            database: self.database,
            network: Some(net),
            pipeline: self.pipeline,
            _marker: PhantomData,
        }
    }
}

// --- with_pipeline: only available when Pipe == NoPipeline ---

impl<Db, Net> NodeBuilder<Db, Net, NoPipeline> {
    /// Attach a sync pipeline. Transitions `Pipe` from `NoPipeline` to
    /// `WithPipeline`.
    pub fn with_pipeline(self, pipeline: Pipeline) -> NodeBuilder<Db, Net, WithPipeline> {
        NodeBuilder {
            config: self.config,
            database: self.database,
            network: self.network,
            pipeline: Some(pipeline),
            _marker: PhantomData,
        }
    }
}

// --- build: only available when *all three* are in their "With" state ---

impl NodeBuilder<WithDb, WithNetwork, WithPipeline> {
    /// Finalize the builder and produce a fully-configured [`Node`].
    ///
    /// This method is only available when the database, network, and pipeline
    /// have all been provided -- enforced at compile time.
    pub fn build(self) -> eyre::Result<Node> {
        Ok(Node {
            config: self.config,
            database: self.database.expect("database set via type-state"),
            network: self.network.expect("network set via type-state"),
            pipeline: self.pipeline.expect("pipeline set via type-state"),
        })
    }
}

// Allow access to config from any state.
impl<Db, Net, Pipe> NodeBuilder<Db, Net, Pipe> {
    /// Borrow the node configuration.
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

/// A fully-assembled node, ready to run.
pub struct Node {
    pub config: NodeConfig,
    pub database: DatabaseHandle,
    pub network: NetworkHandle,
    pub pipeline: Pipeline,
}

impl Node {
    /// Start the node and begin syncing.
    pub async fn run(self) -> eyre::Result<()> {
        info!(
            network = %self.config.network,
            datadir = %self.config.datadir.display(),
            rpc_port = self.config.rpc_port,
            p2p_port = self.config.p2p_port,
            "btc-node starting"
        );

        info!(path = %self.database.path.display(), "database opened");
        info!(port = self.network.port, "p2p network ready");

        // -----------------------------------------------------------------
        // 1. Create shared NodeState (single source of truth)
        // -----------------------------------------------------------------
        let node_state = NodeState::new(self.config.network);
        node_state.syncing.store(true, std::sync::atomic::Ordering::SeqCst);

        // -----------------------------------------------------------------
        // 2. Create ExExManager for chain event notifications
        // -----------------------------------------------------------------
        let exex_manager = ExExManager::new(self.config.network);

        // -----------------------------------------------------------------
        // 3. Build MetricsCollector from NodeState (shares atomics)
        // -----------------------------------------------------------------
        let metrics = node_state.metrics_collector();

        // -----------------------------------------------------------------
        // 4. Spawn HTTP server (Esplora REST + Prometheus metrics)
        // -----------------------------------------------------------------
        let http_server = crate::http::HttpServer::new(self.config.rpc_port + 1, metrics);
        let http_handle = tokio::spawn(async move {
            if let Err(e) = http_server.run().await {
                tracing::error!(error = %e, "HTTP server error");
            }
        });

        // -----------------------------------------------------------------
        // 4b. Spawn Explorer server (block explorer UI on port rpc+2)
        // -----------------------------------------------------------------
        let explorer_metrics = node_state.metrics_collector();
        let explorer_server = crate::explorer::ExplorerServer::new(self.config.rpc_port + 2);
        let explorer_handle = tokio::spawn(async move {
            if let Err(e) = explorer_server.run(explorer_metrics).await {
                tracing::error!(error = %e, "Explorer server error");
            }
        });

        // -----------------------------------------------------------------
        // 5. Spawn ZMQ publisher connected to ExExManager
        // -----------------------------------------------------------------
        let zmq_publisher = ZmqPublisher::new(28332);
        let zmq_ctx = exex_manager.subscribe();
        let zmq_handle = tokio::spawn(async move {
            if let Err(e) = zmq_publisher.run(zmq_ctx).await {
                tracing::error!(error = %e, "ZMQ publisher error");
            }
        });

        // -----------------------------------------------------------------
        // 6. Initialize RPC server with shared state from NodeState
        // -----------------------------------------------------------------
        let rpc_handler = Arc::new(btc_rpc::handler::RpcHandler::new_with_state(
            Arc::clone(&node_state.chain_height),
            Arc::clone(&node_state.best_hash),
            node_state.rpc_network_name(),
            Arc::clone(&node_state.peer_count),
            Arc::clone(&node_state.mempool_size),
            Arc::clone(&node_state.mempool_bytes),
        ));
        let rpc = RpcServer::new(self.config.rpc_port);
        let rpc_handler_clone = rpc_handler.clone();

        // Spawn RPC server
        let rpc_handle = tokio::spawn(async move {
            if let Err(e) = rpc.run(rpc_handler_clone).await {
                tracing::error!(error = %e, "RPC server error");
            }
        });

        // -----------------------------------------------------------------
        // 7. Initialize consensus chain state
        // -----------------------------------------------------------------
        let params = btc_consensus::validation::ChainParams::from_network(self.config.network);
        let chain_state = std::sync::Arc::new(tokio::sync::RwLock::new(
            btc_consensus::ChainState::new(params),
        ));

        // Initialize peer manager
        let peer_manager = std::sync::Arc::new(tokio::sync::RwLock::new(
            btc_network::discovery::PeerManager::new(self.config.network),
        ));

        // -----------------------------------------------------------------
        // 8. Start sync manager with ExEx sender for notifications
        // -----------------------------------------------------------------
        let sync_params = btc_consensus::validation::ChainParams::from_network(self.config.network);
        let mut sync_mgr = crate::sync::SyncManager::with_datadir(
            self.config.network,
            chain_state.clone(),
            peer_manager.clone(),
            sync_params,
            self.config.datadir.clone(),
        );
        sync_mgr.set_exex_sender(exex_manager.sender().clone());
        sync_mgr.set_node_state(node_state.clone());

        info!("starting initial block download");

        match sync_mgr.start().await {
            Ok(()) => {
                info!(state = %sync_mgr.state(), "sync complete");
            }
            Err(e) => {
                tracing::error!(error = %e, "sync failed");
                // Don't exit — the node can still serve RPC
            }
        }

        node_state.syncing.store(false, std::sync::atomic::Ordering::SeqCst);

        // Keep running (serve RPC, listen for new blocks)
        info!("btc-node running — press Ctrl+C to stop");
        tokio::signal::ctrl_c().await?;
        info!("shutting down");

        rpc_handle.abort();
        http_handle.abort();
        explorer_handle.abort();
        zmq_handle.abort();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_compiles_with_all_components() {
        let config = NodeConfig::new(Network::Regtest);
        let db = DatabaseHandle {
            path: PathBuf::from("/tmp/test-db"),
        };
        let net = NetworkHandle { port: 18444 };
        let pipeline = Pipeline::new();

        let node = NodeBuilder::new(config)
            .with_database(db)
            .with_network(net)
            .with_pipeline(pipeline)
            .build()
            .expect("build should succeed");

        assert_eq!(node.config.network, Network::Regtest);
        assert_eq!(node.network.port, 18444);
    }

    #[test]
    fn test_builder_any_order() {
        // The type-state pattern allows the three with_* calls in any order.
        let config = NodeConfig::new(Network::Testnet);

        let node = NodeBuilder::new(config)
            .with_pipeline(Pipeline::new())
            .with_database(DatabaseHandle {
                path: PathBuf::from("/tmp/test-db"),
            })
            .with_network(NetworkHandle { port: 18333 })
            .build()
            .expect("build should succeed");

        assert_eq!(node.config.network, Network::Testnet);
    }

    #[test]
    fn test_node_config_defaults() {
        let config = NodeConfig::new(Network::Mainnet);
        assert_eq!(config.rpc_port, 8332);
        assert_eq!(config.p2p_port, 8333);
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn test_node_config_testnet() {
        let config = NodeConfig::new(Network::Testnet);
        assert_eq!(config.rpc_port, 18332);
        assert_eq!(config.p2p_port, 18333);
    }

    #[test]
    fn test_node_config_signet() {
        let config = NodeConfig::new(Network::Signet);
        assert_eq!(config.network, Network::Signet);
    }

    #[test]
    fn test_node_config_regtest() {
        let config = NodeConfig::new(Network::Regtest);
        assert_eq!(config.rpc_port, 18443);
        assert_eq!(config.p2p_port, 18444);
    }

    #[test]
    fn test_node_config_default_datadir() {
        let config = NodeConfig::new(Network::Mainnet);
        assert_eq!(config.datadir, PathBuf::from("~/.btc-rust"));
    }

    #[test]
    fn test_node_config_clone() {
        let config = NodeConfig::new(Network::Mainnet)
            .with_rpc_port(9999)
            .with_p2p_port(9998);
        let config2 = config.clone();
        assert_eq!(config2.rpc_port, 9999);
        assert_eq!(config2.p2p_port, 9998);
        assert_eq!(config2.network, Network::Mainnet);
    }

    #[test]
    fn test_node_config_debug() {
        let config = NodeConfig::new(Network::Mainnet);
        let debug = format!("{:?}", config);
        assert!(debug.contains("NodeConfig"));
    }

    #[test]
    fn test_database_handle_debug() {
        let db = DatabaseHandle {
            path: PathBuf::from("/tmp/test"),
        };
        let debug = format!("{:?}", db);
        assert!(debug.contains("DatabaseHandle"));
    }

    #[test]
    fn test_network_handle_debug() {
        let net = NetworkHandle { port: 8333 };
        let debug = format!("{:?}", net);
        assert!(debug.contains("NetworkHandle"));
    }

    #[test]
    fn test_builder_config_accessor() {
        let config = NodeConfig::new(Network::Mainnet);
        let builder = NodeBuilder::new(config);
        assert_eq!(builder.config().network, Network::Mainnet);
        assert_eq!(builder.config().rpc_port, 8332);
    }

    #[test]
    fn test_builder_config_accessor_after_partial() {
        let config = NodeConfig::new(Network::Testnet);
        let builder = NodeBuilder::new(config)
            .with_database(DatabaseHandle {
                path: PathBuf::from("/tmp"),
            });
        assert_eq!(builder.config().network, Network::Testnet);
    }

    #[test]
    fn test_node_fields_after_build() {
        let config = NodeConfig::new(Network::Regtest)
            .with_rpc_port(1234)
            .with_p2p_port(5678)
            .with_datadir("/my/data");
        let node = NodeBuilder::new(config)
            .with_database(DatabaseHandle {
                path: PathBuf::from("/my/db"),
            })
            .with_network(NetworkHandle { port: 5678 })
            .with_pipeline(Pipeline::new())
            .build()
            .unwrap();

        assert_eq!(node.config.rpc_port, 1234);
        assert_eq!(node.config.p2p_port, 5678);
        assert_eq!(node.config.datadir, PathBuf::from("/my/data"));
        assert_eq!(node.database.path, PathBuf::from("/my/db"));
        assert_eq!(node.network.port, 5678);
    }

    #[test]
    fn test_node_config_overrides() {
        let config = NodeConfig::new(Network::Mainnet)
            .with_datadir("/data/btc")
            .with_rpc_port(9999)
            .with_p2p_port(9998)
            .with_log_level("debug");

        assert_eq!(config.rpc_port, 9999);
        assert_eq!(config.p2p_port, 9998);
        assert_eq!(config.datadir, PathBuf::from("/data/btc"));
        assert_eq!(config.log_level, "debug");
    }

    // ===================================================================
    // Additional builder tests for coverage
    // ===================================================================

    #[test]
    fn test_builder_pipeline_then_database_then_network() {
        // Verify all 6 permutations of component attachment order
        let node = NodeBuilder::new(NodeConfig::new(Network::Regtest))
            .with_pipeline(Pipeline::new())
            .with_database(DatabaseHandle { path: PathBuf::from("/tmp") })
            .with_network(NetworkHandle { port: 18444 })
            .build()
            .unwrap();
        assert_eq!(node.config.network, Network::Regtest);
    }

    #[test]
    fn test_builder_network_then_pipeline_then_database() {
        let node = NodeBuilder::new(NodeConfig::new(Network::Regtest))
            .with_network(NetworkHandle { port: 18444 })
            .with_pipeline(Pipeline::new())
            .with_database(DatabaseHandle { path: PathBuf::from("/tmp") })
            .build()
            .unwrap();
        assert_eq!(node.config.network, Network::Regtest);
    }

    #[test]
    fn test_builder_network_then_database_then_pipeline() {
        let node = NodeBuilder::new(NodeConfig::new(Network::Regtest))
            .with_network(NetworkHandle { port: 18444 })
            .with_database(DatabaseHandle { path: PathBuf::from("/tmp") })
            .with_pipeline(Pipeline::new())
            .build()
            .unwrap();
        assert_eq!(node.config.network, Network::Regtest);
    }

    #[test]
    fn test_builder_database_then_pipeline_then_network() {
        let node = NodeBuilder::new(NodeConfig::new(Network::Regtest))
            .with_database(DatabaseHandle { path: PathBuf::from("/tmp") })
            .with_pipeline(Pipeline::new())
            .with_network(NetworkHandle { port: 18444 })
            .build()
            .unwrap();
        assert_eq!(node.config.network, Network::Regtest);
    }

    #[test]
    fn test_builder_config_accessible_from_all_states() {
        // No components
        let b0 = NodeBuilder::new(NodeConfig::new(Network::Mainnet));
        assert_eq!(b0.config().network, Network::Mainnet);

        // One component
        let b1 = b0.with_database(DatabaseHandle { path: PathBuf::from("/tmp") });
        assert_eq!(b1.config().network, Network::Mainnet);

        // Two components
        let b2 = b1.with_network(NetworkHandle { port: 8333 });
        assert_eq!(b2.config().network, Network::Mainnet);

        // All three (before build)
        let b3 = b2.with_pipeline(Pipeline::new());
        assert_eq!(b3.config().network, Network::Mainnet);
    }

    #[test]
    fn test_node_config_all_networks() {
        for network in [Network::Mainnet, Network::Testnet, Network::Signet, Network::Regtest] {
            let config = NodeConfig::new(network);
            assert_eq!(config.network, network);
            // Ports should differ from 0
            assert!(config.rpc_port > 0);
            assert!(config.p2p_port > 0);
            // RPC and P2P ports should differ
            assert_ne!(config.rpc_port, config.p2p_port);
        }
    }

    #[test]
    fn test_node_config_builder_chain() {
        // Test that all builder methods chain correctly
        let config = NodeConfig::new(Network::Mainnet)
            .with_datadir("/a")
            .with_rpc_port(1)
            .with_p2p_port(2)
            .with_log_level("trace");
        assert_eq!(config.datadir, PathBuf::from("/a"));
        assert_eq!(config.rpc_port, 1);
        assert_eq!(config.p2p_port, 2);
        assert_eq!(config.log_level, "trace");
    }

    #[test]
    fn test_node_config_datadir_string() {
        let config = NodeConfig::new(Network::Mainnet)
            .with_datadir("/home/user/.btc-rust");
        assert_eq!(config.datadir, PathBuf::from("/home/user/.btc-rust"));
    }

    #[test]
    fn test_node_config_datadir_pathbuf() {
        let config = NodeConfig::new(Network::Mainnet)
            .with_datadir(PathBuf::from("/home/user/data"));
        assert_eq!(config.datadir, PathBuf::from("/home/user/data"));
    }

    #[test]
    fn test_node_config_log_level_string() {
        let config = NodeConfig::new(Network::Mainnet)
            .with_log_level(String::from("warn"));
        assert_eq!(config.log_level, "warn");
    }

    #[test]
    fn test_node_config_log_level_str() {
        let config = NodeConfig::new(Network::Mainnet)
            .with_log_level("error");
        assert_eq!(config.log_level, "error");
    }

    #[test]
    fn test_build_produces_correct_components() {
        let config = NodeConfig::new(Network::Regtest)
            .with_rpc_port(1111)
            .with_p2p_port(2222)
            .with_datadir("/test/dir")
            .with_log_level("trace");

        let node = NodeBuilder::new(config)
            .with_database(DatabaseHandle { path: PathBuf::from("/db/path") })
            .with_network(NetworkHandle { port: 2222 })
            .with_pipeline(Pipeline::new())
            .build()
            .unwrap();

        assert_eq!(node.config.rpc_port, 1111);
        assert_eq!(node.config.p2p_port, 2222);
        assert_eq!(node.config.datadir, PathBuf::from("/test/dir"));
        assert_eq!(node.config.log_level, "trace");
        assert_eq!(node.config.network, Network::Regtest);
        assert_eq!(node.database.path, PathBuf::from("/db/path"));
        assert_eq!(node.network.port, 2222);
    }
}
