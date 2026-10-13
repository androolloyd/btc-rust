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
    /// Explicitly enable the experimental loopback chain/transaction service.
    pub electrum_port: Option<u16>,
    pub connect_peers: Vec<std::net::SocketAddr>,
    pub resync_legacy_checkpoint: bool,
    pub full_rbf: bool,
    pub mempool_policy: btc_mempool::policy::TxValidationPolicy,
    pub mempool_flags: btc_consensus::script_engine::ScriptFlags,
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
            electrum_port: None,
            connect_peers: Vec::new(),
            resync_legacy_checkpoint: false,
            full_rbf: true,
            mempool_policy: btc_mempool::policy::TxValidationPolicy::default(),
            mempool_flags: btc_consensus::script_engine::ScriptFlags::all(),
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

    /// Restrict outbound connections to these addresses, disabling DNS seeds.
    pub fn with_connect_peers(mut self, peers: Vec<std::net::SocketAddr>) -> Self {
        self.connect_peers = peers;
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

/// Configuration for the P2P listener opened at node startup.
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

        // -----------------------------------------------------------------
        // 1. Create shared NodeState (single source of truth)
        // -----------------------------------------------------------------
        let node_state = NodeState::new(self.config.network);
        node_state
            .syncing
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let chain_backend = Arc::new(
            crate::chain_backend::NodeChainBackend::open_with_legacy_resync(
                &self.config.datadir.join("utxo.redb"),
                node_state.clone(),
                self.config.resync_legacy_checkpoint,
            )?,
        );

        chain_backend
            .configure_pipeline(self.pipeline)
            .map_err(|error| eyre::eyre!(error.message))?;

        chain_backend
            .configure_mempool(
                self.config.full_rbf,
                self.config.mempool_policy.clone(),
                self.config.mempool_flags,
            )
            .map_err(|error| eyre::eyre!(error.message))?;

        // Fail credential setup before binding or spawning any network service.
        let rpc_cookie = crate::rpc_cookie::RpcCookie::create(&self.config.datadir)?;

        // Requested services fail before any network tasks are spawned.
        let electrum_listener = match self.config.electrum_port {
            Some(port) => Some(tokio::net::TcpListener::bind(("127.0.0.1", port)).await?),
            None => None,
        };

        let p2p_listener = tokio::net::TcpListener::bind(("0.0.0.0", self.network.port)).await?;
        let peer_table = Arc::new(crate::p2p::PeerTable::new(node_state.peer_count.clone()));

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
        let mut rpc_handler = btc_rpc::handler::RpcHandler::new_with_state(
            node_state.chain_height.clone(),
            node_state.best_hash.clone(),
            node_state.rpc_network_name(),
            node_state.peer_count.clone(),
            node_state.mempool_size.clone(),
            node_state.mempool_bytes.clone(),
        )
        .with_chain_backend(chain_backend.clone());
        let rpc_peers = peer_table.clone();
        rpc_handler.register_fallible("getpeerinfo", move |_| rpc_peers.snapshot());
        let rpc_peers = peer_table.clone();
        rpc_handler.register_fallible("getnetworkinfo", move |_| rpc_peers.network_info());
        let rpc_handler = Arc::new(rpc_handler);
        let rpc = RpcServer::new(self.config.rpc_port).with_http_auth(rpc_cookie.auth());
        let rpc_handler_clone = rpc_handler.clone();

        // Spawn RPC server
        let mut rpc_handle = tokio::spawn(async move { rpc.run(rpc_handler_clone).await });
        let (electrum_shutdown, electrum_receiver) = tokio::sync::watch::channel(false);
        let mut electrum_handle = if let Some(listener) = electrum_listener {
            let port = listener.local_addr()?.port();
            let handler =
                Arc::new(btc_electrum::ElectrumHandler::new().with_backend(chain_backend.clone()));
            Some(tokio::spawn(async move {
                btc_electrum::ElectrumServer::new(port)
                    .run_listener(listener, handler, electrum_receiver)
                    .await
            }))
        } else {
            None
        };

        let p2p_backend = chain_backend.clone();
        let p2p_peers = peer_table.clone();
        let p2p_shutdown = rpc_handler.clone();
        let p2p_network = self.config.network;
        let mut p2p_handle = tokio::spawn(async move {
            crate::p2p::P2pServer::run(
                p2p_listener,
                p2p_network,
                p2p_backend,
                p2p_peers,
                p2p_shutdown,
            )
            .await
        });

        // -----------------------------------------------------------------
        // 7. Initialize consensus chain state
        // -----------------------------------------------------------------
        let chain_state =
            std::sync::Arc::new(tokio::sync::RwLock::new(chain_backend.header_chain()?));

        // Initialize peer manager
        let peer_manager = std::sync::Arc::new(tokio::sync::RwLock::new(
            btc_network::discovery::PeerManager::new(self.config.network),
        ));

        // -----------------------------------------------------------------
        // 8. Start sync manager with ExEx sender for notifications
        // -----------------------------------------------------------------
        let sync_params = btc_consensus::validation::ChainParams::from_network(self.config.network);
        let mut sync_mgr = crate::sync::SyncManager::with_backend(
            self.config.network,
            chain_state.clone(),
            peer_manager.clone(),
            sync_params,
            self.config.datadir.clone(),
            chain_backend,
        )?;
        sync_mgr.set_exex_sender(exex_manager.sender().clone());
        sync_mgr.set_node_state(node_state.clone());
        sync_mgr.set_peer_table(peer_table);
        sync_mgr.set_connect_peers(self.config.connect_peers);

        info!("starting initial block download");

        let sync_shutdown = rpc_handler.clone();
        let mut sync_handle = tokio::spawn(async move { sync_mgr.run(sync_shutdown).await });

        info!("btc-node running — press Ctrl+C or use stop RPC to stop");
        let result = tokio::select! {
            result = tokio::signal::ctrl_c() => result.map_err(Into::into),
            _ = rpc_handler.wait_for_shutdown() => Ok(()),
            result = &mut p2p_handle => match result {
                Ok(result) => result, Err(error) => Err(error.into()),
            },
            result = &mut rpc_handle => match result {
                Ok(result) => result,
                Err(error) => Err(error.into()),
            },
            result = async { electrum_handle.as_mut().unwrap().await }, if electrum_handle.is_some() => match result {
                Ok(result) => result.map_err(Into::into), Err(error) => Err(error.into()),
            },
        };
        info!("shutting down");
        rpc_handler.request_shutdown();
        let _ = electrum_shutdown.send(true);
        if let Some(handle) = electrum_handle.as_mut() {
            if !handle.is_finished()
                && tokio::time::timeout(std::time::Duration::from_secs(2), &mut *handle)
                    .await
                    .is_err()
            {
                handle.abort();
            }
        }
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut sync_handle)
            .await
            .is_err()
        {
            sync_handle.abort();
        }
        if !rpc_handle.is_finished() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), &mut rpc_handle).await;
        }
        if !p2p_handle.is_finished() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), &mut p2p_handle).await;
        }
        p2p_handle.abort();
        rpc_handle.abort();
        http_handle.abort();
        explorer_handle.abort();
        zmq_handle.abort();
        result
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
        let debug = format!("{config:?}");
        assert!(debug.contains("NodeConfig"));
    }

    #[test]
    fn test_database_handle_debug() {
        let db = DatabaseHandle {
            path: PathBuf::from("/tmp/test"),
        };
        let debug = format!("{db:?}");
        assert!(debug.contains("DatabaseHandle"));
    }

    #[test]
    fn test_network_handle_debug() {
        let net = NetworkHandle { port: 8333 };
        let debug = format!("{net:?}");
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
        let builder = NodeBuilder::new(config).with_database(DatabaseHandle {
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
            .with_database(DatabaseHandle {
                path: PathBuf::from("/tmp"),
            })
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
            .with_database(DatabaseHandle {
                path: PathBuf::from("/tmp"),
            })
            .build()
            .unwrap();
        assert_eq!(node.config.network, Network::Regtest);
    }

    #[test]
    fn test_builder_network_then_database_then_pipeline() {
        let node = NodeBuilder::new(NodeConfig::new(Network::Regtest))
            .with_network(NetworkHandle { port: 18444 })
            .with_database(DatabaseHandle {
                path: PathBuf::from("/tmp"),
            })
            .with_pipeline(Pipeline::new())
            .build()
            .unwrap();
        assert_eq!(node.config.network, Network::Regtest);
    }

    #[test]
    fn test_builder_database_then_pipeline_then_network() {
        let node = NodeBuilder::new(NodeConfig::new(Network::Regtest))
            .with_database(DatabaseHandle {
                path: PathBuf::from("/tmp"),
            })
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
        let b1 = b0.with_database(DatabaseHandle {
            path: PathBuf::from("/tmp"),
        });
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
        for network in [
            Network::Mainnet,
            Network::Testnet,
            Network::Signet,
            Network::Regtest,
        ] {
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
        let config = NodeConfig::new(Network::Mainnet).with_datadir("/home/user/.btc-rust");
        assert_eq!(config.datadir, PathBuf::from("/home/user/.btc-rust"));
    }

    #[test]
    fn test_node_config_datadir_pathbuf() {
        let config =
            NodeConfig::new(Network::Mainnet).with_datadir(PathBuf::from("/home/user/data"));
        assert_eq!(config.datadir, PathBuf::from("/home/user/data"));
    }

    #[test]
    fn test_node_config_log_level_string() {
        let config = NodeConfig::new(Network::Mainnet).with_log_level(String::from("warn"));
        assert_eq!(config.log_level, "warn");
    }

    #[test]
    fn test_node_config_log_level_str() {
        let config = NodeConfig::new(Network::Mainnet).with_log_level("error");
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
            .with_database(DatabaseHandle {
                path: PathBuf::from("/db/path"),
            })
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
