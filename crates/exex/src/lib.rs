//! # Execution Extensions (ExEx)
//!
//! A plugin architecture inspired by reth that lets external consumers subscribe
//! to chain state changes without forking the node. Extensions implement the
//! [`ExEx`] trait and receive [`ExExNotification`]s through a broadcast channel
//! managed by the [`ExExManager`].

use btc_consensus::utxo::UtxoSetUpdate;
use btc_primitives::block::Block;
use btc_primitives::hash::BlockHash;
use btc_primitives::network::Network;
use std::future::Future;
use tokio::sync::broadcast;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Notification types
// ---------------------------------------------------------------------------

/// Chain events that execution extensions can subscribe to.
#[derive(Debug, Clone)]
pub enum ExExNotification {
    /// A new block has been committed to the canonical chain.
    BlockCommitted {
        height: u64,
        hash: BlockHash,
        block: Block,
        utxo_changes: UtxoSetUpdate,
    },

    /// A block has been reverted (disconnected) from the chain tip.
    BlockReverted {
        height: u64,
        hash: BlockHash,
    },

    /// A chain reorganisation has occurred.
    ChainReorged {
        /// The previous chain tip that was abandoned.
        old_tip: BlockHash,
        /// The new chain tip after the reorg.
        new_tip: BlockHash,
        /// The height of the common ancestor (fork point).
        fork_height: u64,
        /// Block hashes that were reverted from the old chain.
        reverted: Vec<BlockHash>,
        /// (height, hash) pairs of blocks committed on the new chain.
        committed: Vec<(u64, BlockHash)>,
    },
}

// ---------------------------------------------------------------------------
// ExExContext
// ---------------------------------------------------------------------------

/// Shared context handed to each execution extension on startup.
///
/// Provides the notification receiver and network information so extensions
/// can react to chain events appropriately.
pub struct ExExContext {
    /// Broadcast receiver for chain notifications.
    pub notifications: broadcast::Receiver<ExExNotification>,
    /// The Bitcoin network this node is operating on.
    pub network: Network,
}

// ---------------------------------------------------------------------------
// ExEx trait
// ---------------------------------------------------------------------------

/// The trait that execution extension plugins implement.
///
/// Each extension has a name (for logging/diagnostics) and a `start` method
/// that runs for the lifetime of the node, consuming chain notifications from
/// the provided [`ExExContext`].
pub trait ExEx: Send + 'static {
    /// Human-readable name for this extension.
    fn name(&self) -> &str;

    /// Run the extension. This method should loop over incoming notifications
    /// from `ctx.notifications` and process them. It returns when the
    /// extension is done (typically when the node shuts down or the channel
    /// closes).
    fn start(self, ctx: ExExContext) -> impl Future<Output = eyre::Result<()>> + Send;
}

// ---------------------------------------------------------------------------
// ExExManager
// ---------------------------------------------------------------------------

/// Manages the lifecycle and notification dispatch for execution extensions.
///
/// The pipeline (or any chain-processing component) uses the [`ExExManager`]
/// to emit [`ExExNotification`]s. Each registered extension receives a copy
/// through a `tokio::sync::broadcast` channel.
pub struct ExExManager {
    sender: broadcast::Sender<ExExNotification>,
    extensions: Vec<String>,
    network: Network,
}

impl ExExManager {
    /// Create a new manager with a default broadcast channel capacity.
    pub fn new(network: Network) -> Self {
        let (sender, _) = broadcast::channel(1024);
        Self {
            sender,
            extensions: Vec::new(),
            network,
        }
    }

    /// Create a new manager with a custom broadcast channel capacity.
    pub fn with_capacity(network: Network, capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            extensions: Vec::new(),
            network,
        }
    }

    /// Access the broadcast sender (for the pipeline to emit events directly).
    pub fn sender(&self) -> &broadcast::Sender<ExExNotification> {
        &self.sender
    }

    /// Create a new [`ExExContext`] that receives all future notifications.
    pub fn subscribe(&self) -> ExExContext {
        ExExContext {
            notifications: self.sender.subscribe(),
            network: self.network,
        }
    }

    /// Emit a notification to all subscribers.
    pub fn notify(&self, notification: ExExNotification) {
        match &notification {
            ExExNotification::BlockCommitted { height, hash, .. } => {
                info!(height, %hash, "ExEx: block committed");
            }
            ExExNotification::BlockReverted { height, hash } => {
                info!(height, %hash, "ExEx: block reverted");
            }
            ExExNotification::ChainReorged {
                old_tip,
                new_tip,
                fork_height,
                ..
            } => {
                info!(
                    %old_tip,
                    %new_tip,
                    fork_height,
                    "ExEx: chain reorged"
                );
            }
        }

        // broadcast::send returns Err only when there are no receivers,
        // which is fine -- it just means no extensions are listening.
        if self.sender.send(notification).is_err() {
            warn!("ExEx: no active receivers for notification");
        }
    }

    /// Register an extension by name (for tracking/diagnostics).
    pub fn register(&mut self, name: &str) {
        info!(name, "ExEx: registered extension");
        self.extensions.push(name.to_string());
    }

    /// List the names of all registered extensions.
    pub fn registered_extensions(&self) -> &[String] {
        &self.extensions
    }
}

// ---------------------------------------------------------------------------
// Example ExEx: LoggingExEx
// ---------------------------------------------------------------------------

/// A simple execution extension that logs every chain event it receives.
///
/// Useful as a reference implementation and for debugging.
pub struct LoggingExEx;

impl ExEx for LoggingExEx {
    fn name(&self) -> &str {
        "logging"
    }

    async fn start(self, mut ctx: ExExContext) -> eyre::Result<()> {
        info!(network = %ctx.network, "LoggingExEx started");

        loop {
            match ctx.notifications.recv().await {
                Ok(notification) => match &notification {
                    ExExNotification::BlockCommitted {
                        height,
                        hash,
                        block,
                        utxo_changes,
                    } => {
                        info!(
                            height,
                            %hash,
                            tx_count = block.transactions.len(),
                            utxos_created = utxo_changes.created.len(),
                            utxos_spent = utxo_changes.spent.len(),
                            "LoggingExEx: block committed"
                        );
                    }
                    ExExNotification::BlockReverted { height, hash } => {
                        info!(height, %hash, "LoggingExEx: block reverted");
                    }
                    ExExNotification::ChainReorged {
                        old_tip,
                        new_tip,
                        fork_height,
                        reverted,
                        committed,
                    } => {
                        info!(
                            %old_tip,
                            %new_tip,
                            fork_height,
                            reverted_count = reverted.len(),
                            committed_count = committed.len(),
                            "LoggingExEx: chain reorg"
                        );
                    }
                },
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "LoggingExEx: lagged behind, skipped notifications");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    info!("LoggingExEx: channel closed, shutting down");
                    return Ok(());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Example ExEx: MetricsExEx
// ---------------------------------------------------------------------------

/// An execution extension that tracks basic chain metrics:
/// - Current block height
/// - Total transaction count seen
/// - Estimated UTXO set size (created minus spent)
pub struct MetricsExEx {
    /// Current highest committed block height.
    pub current_height: u64,
    /// Total number of transactions processed.
    pub total_tx_count: u64,
    /// Running estimate of the UTXO set size.
    pub utxo_set_size: i64,
}

impl MetricsExEx {
    pub fn new() -> Self {
        Self {
            current_height: 0,
            total_tx_count: 0,
            utxo_set_size: 0,
        }
    }
}

impl Default for MetricsExEx {
    fn default() -> Self {
        Self::new()
    }
}

impl ExEx for MetricsExEx {
    fn name(&self) -> &str {
        "metrics"
    }

    async fn start(mut self, mut ctx: ExExContext) -> eyre::Result<()> {
        info!(network = %ctx.network, "MetricsExEx started");

        loop {
            match ctx.notifications.recv().await {
                Ok(notification) => match &notification {
                    ExExNotification::BlockCommitted {
                        height,
                        block,
                        utxo_changes,
                        ..
                    } => {
                        self.current_height = *height;
                        self.total_tx_count += block.transactions.len() as u64;
                        self.utxo_set_size += utxo_changes.created.len() as i64;
                        self.utxo_set_size -= utxo_changes.spent.len() as i64;

                        info!(
                            height = self.current_height,
                            total_tx_count = self.total_tx_count,
                            utxo_set_size = self.utxo_set_size,
                            "MetricsExEx: updated"
                        );
                    }
                    ExExNotification::BlockReverted { height, .. } => {
                        if *height <= self.current_height {
                            self.current_height = height.saturating_sub(1);
                        }
                        info!(
                            height = self.current_height,
                            "MetricsExEx: block reverted, height adjusted"
                        );
                    }
                    ExExNotification::ChainReorged {
                        committed,
                        reverted,
                        ..
                    } => {
                        // After a reorg, adjust height to the last committed block.
                        if let Some((h, _)) = committed.last() {
                            self.current_height = *h;
                        }
                        info!(
                            height = self.current_height,
                            reverted_blocks = reverted.len(),
                            committed_blocks = committed.len(),
                            "MetricsExEx: reorg processed"
                        );
                    }
                },
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "MetricsExEx: lagged behind, skipped notifications");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    info!("MetricsExEx: channel closed, shutting down");
                    return Ok(());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use btc_consensus::utxo::{UtxoEntry, UtxoSetUpdate};
    use btc_primitives::amount::Amount;
    use btc_primitives::block::{Block, BlockHeader};
    use btc_primitives::compact::CompactTarget;
    use btc_primitives::hash::{BlockHash, TxHash};
    use btc_primitives::script::ScriptBuf;
    use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

    /// Build a minimal test block with a single coinbase transaction.
    fn make_test_block() -> Block {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0x00]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::ZERO,
                time: 1231006505,
                bits: CompactTarget::MAX_TARGET,
                nonce: 0,
            },
            transactions: vec![coinbase],
        }
    }

    /// Build a test UtxoSetUpdate with the given counts of created/spent entries.
    fn make_utxo_update(created_count: usize, spent_count: usize) -> UtxoSetUpdate {
        let make_entry = |i: u8| {
            (
                OutPoint::new(TxHash::from_bytes([i; 32]), 0),
                UtxoEntry {
                    txout: TxOut {
                        value: Amount::from_sat(1000),
                        script_pubkey: ScriptBuf::from_bytes(vec![0x00]),
                    },
                    height: 0,
                    is_coinbase: false,
                },
            )
        };

        UtxoSetUpdate {
            created: (0..created_count as u8).map(make_entry).collect(),
            spent: (100..100 + spent_count as u8).map(make_entry).collect(),
        }
    }

    // -----------------------------------------------------------------------
    // Test: notification broadcast to multiple receivers
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_broadcast_to_multiple_receivers() {
        let manager = ExExManager::new(Network::Regtest);
        let mut ctx1 = manager.subscribe();
        let mut ctx2 = manager.subscribe();

        let block = make_test_block();
        let hash = block.block_hash();
        let utxo_changes = make_utxo_update(1, 0);

        manager.notify(ExExNotification::BlockCommitted {
            height: 1,
            hash,
            block: block.clone(),
            utxo_changes,
        });

        // Both receivers should get the notification.
        let n1 = ctx1.notifications.recv().await.unwrap();
        let n2 = ctx2.notifications.recv().await.unwrap();

        match (&n1, &n2) {
            (
                ExExNotification::BlockCommitted {
                    height: h1,
                    hash: hash1,
                    ..
                },
                ExExNotification::BlockCommitted {
                    height: h2,
                    hash: hash2,
                    ..
                },
            ) => {
                assert_eq!(*h1, 1);
                assert_eq!(*h2, 1);
                assert_eq!(*hash1, hash);
                assert_eq!(*hash2, hash);
            }
            _ => panic!("expected BlockCommitted notifications"),
        }
    }

    // -----------------------------------------------------------------------
    // Test: block committed notification
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_block_committed_notification() {
        let manager = ExExManager::new(Network::Mainnet);
        let mut ctx = manager.subscribe();

        let block = make_test_block();
        let hash = block.block_hash();
        let utxo_changes = make_utxo_update(3, 1);

        manager.notify(ExExNotification::BlockCommitted {
            height: 42,
            hash,
            block: block.clone(),
            utxo_changes,
        });

        let notification = ctx.notifications.recv().await.unwrap();
        match notification {
            ExExNotification::BlockCommitted {
                height,
                hash: recv_hash,
                block: recv_block,
                utxo_changes: recv_utxo,
            } => {
                assert_eq!(height, 42);
                assert_eq!(recv_hash, hash);
                assert_eq!(recv_block.transactions.len(), 1);
                assert_eq!(recv_utxo.created.len(), 3);
                assert_eq!(recv_utxo.spent.len(), 1);
            }
            _ => panic!("expected BlockCommitted"),
        }
    }

    // -----------------------------------------------------------------------
    // Test: block reverted notification
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_block_reverted_notification() {
        let manager = ExExManager::new(Network::Testnet);
        let mut ctx = manager.subscribe();

        let hash = BlockHash::from_bytes([0xab; 32]);
        manager.notify(ExExNotification::BlockReverted {
            height: 100,
            hash,
        });

        let notification = ctx.notifications.recv().await.unwrap();
        match notification {
            ExExNotification::BlockReverted {
                height,
                hash: recv_hash,
            } => {
                assert_eq!(height, 100);
                assert_eq!(recv_hash, hash);
            }
            _ => panic!("expected BlockReverted"),
        }
    }

    // -----------------------------------------------------------------------
    // Test: chain reorg notification
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_chain_reorg_notification() {
        let manager = ExExManager::new(Network::Mainnet);
        let mut ctx = manager.subscribe();

        let old_tip = BlockHash::from_bytes([0x01; 32]);
        let new_tip = BlockHash::from_bytes([0x02; 32]);
        let reverted_hash = BlockHash::from_bytes([0x03; 32]);
        let committed_hash = BlockHash::from_bytes([0x04; 32]);

        manager.notify(ExExNotification::ChainReorged {
            old_tip,
            new_tip,
            fork_height: 50,
            reverted: vec![reverted_hash],
            committed: vec![(51, committed_hash)],
        });

        let notification = ctx.notifications.recv().await.unwrap();
        match notification {
            ExExNotification::ChainReorged {
                old_tip: recv_old,
                new_tip: recv_new,
                fork_height,
                reverted,
                committed,
            } => {
                assert_eq!(recv_old, old_tip);
                assert_eq!(recv_new, new_tip);
                assert_eq!(fork_height, 50);
                assert_eq!(reverted.len(), 1);
                assert_eq!(reverted[0], reverted_hash);
                assert_eq!(committed.len(), 1);
                assert_eq!(committed[0], (51, committed_hash));
            }
            _ => panic!("expected ChainReorged"),
        }
    }

    // -----------------------------------------------------------------------
    // Test: ExExManager register and subscribe
    // -----------------------------------------------------------------------

    #[test]
    fn test_manager_register_and_subscribe() {
        let mut manager = ExExManager::new(Network::Regtest);

        assert!(manager.registered_extensions().is_empty());

        manager.register("logging");
        manager.register("metrics");
        manager.register("indexer");

        let extensions = manager.registered_extensions();
        assert_eq!(extensions.len(), 3);
        assert_eq!(extensions[0], "logging");
        assert_eq!(extensions[1], "metrics");
        assert_eq!(extensions[2], "indexer");

        // subscribe should return a context with the correct network.
        let ctx = manager.subscribe();
        assert_eq!(ctx.network, Network::Regtest);
    }

    // -----------------------------------------------------------------------
    // Test: ExEx trait implementations
    // -----------------------------------------------------------------------

    #[test]
    fn test_logging_exex_name() {
        let exex = LoggingExEx;
        assert_eq!(exex.name(), "logging");
    }

    #[test]
    fn test_metrics_exex_name() {
        let exex = MetricsExEx::new();
        assert_eq!(exex.name(), "metrics");
    }

    #[test]
    fn test_metrics_exex_default() {
        let exex = MetricsExEx::default();
        assert_eq!(exex.current_height, 0);
        assert_eq!(exex.total_tx_count, 0);
        assert_eq!(exex.utxo_set_size, 0);
    }

    // -----------------------------------------------------------------------
    // Test: manager with_capacity constructor
    // -----------------------------------------------------------------------

    #[test]
    fn test_manager_with_capacity() {
        let manager = ExExManager::with_capacity(Network::Signet, 16);
        assert!(manager.registered_extensions().is_empty());
        // Verify the sender works by subscribing.
        let _ctx = manager.subscribe();
    }

    // -----------------------------------------------------------------------
    // Test: notify with no receivers does not panic
    // -----------------------------------------------------------------------

    #[test]
    fn test_notify_no_receivers() {
        let manager = ExExManager::new(Network::Mainnet);
        // No subscribers -- should not panic.
        manager.notify(ExExNotification::BlockReverted {
            height: 1,
            hash: BlockHash::ZERO,
        });
    }

    // -----------------------------------------------------------------------
    // Test: LoggingExEx handles channel closure gracefully
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_logging_exex_channel_close() {
        let manager = ExExManager::new(Network::Regtest);
        let ctx = manager.subscribe();

        // Drop the manager (and thus the sender) to close the channel.
        drop(manager);

        let result = LoggingExEx.start(ctx).await;
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Test: MetricsExEx handles channel closure gracefully
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_metrics_exex_channel_close() {
        let manager = ExExManager::new(Network::Regtest);
        let ctx = manager.subscribe();

        drop(manager);

        let result = MetricsExEx::new().start(ctx).await;
        assert!(result.is_ok());
    }
}
