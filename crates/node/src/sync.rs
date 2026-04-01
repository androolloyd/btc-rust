use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

use btc_consensus::chain::ChainState;
use btc_consensus::reorg::{self, ReorgManager, ReorgResult};
use btc_consensus::utxo::{connect_block, InMemoryUtxoSet};
use btc_consensus::validation::{BlockValidator, ChainParams};
use btc_consensus::{ParallelValidator, ParallelConfig};
use btc_exex::ExExNotification;
use btc_network::connection::{Connection, ConnectionError};
use btc_network::discovery::PeerManager;
use btc_network::message::{
    GetHeadersMessage, InvItem, InvType, NetworkMessage,
};
use btc_network::protocol::ProtocolVersion;
use btc_primitives::hash::BlockHash;
use btc_primitives::network::Network;
use btc_storage::redb_backend::RedbDatabase;
use btc_storage::PersistentUtxoSet;

use crate::state::NodeState;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of headers returned in a single `headers` message.
const MAX_HEADERS_PER_MESSAGE: usize = 2000;

/// Number of blocks to request in a single `getdata` batch.
const BLOCK_DOWNLOAD_BATCH_SIZE: usize = 128;

// ---------------------------------------------------------------------------
// Checkpoint persistence
// ---------------------------------------------------------------------------

/// Serializable checkpoint representing the sync progress.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u64,
    pub hash: String,
}

impl Checkpoint {
    /// Create a new checkpoint.
    pub fn new(height: u64, hash: BlockHash) -> Self {
        Self {
            height,
            hash: format!("{}", hash),
        }
    }
}

/// Save a checkpoint to `{datadir}/checkpoint.json`.
pub fn save_checkpoint(datadir: &Path, checkpoint: &Checkpoint) -> std::io::Result<()> {
    std::fs::create_dir_all(datadir)?;
    let path = datadir.join("checkpoint.json");
    let json = serde_json::to_string_pretty(checkpoint)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(&path, json)?;
    info!(height = checkpoint.height, path = %path.display(), "checkpoint saved");
    Ok(())
}

/// Load a checkpoint from `{datadir}/checkpoint.json`, returning `None` if the
/// file does not exist or cannot be parsed.
pub fn load_checkpoint(datadir: &Path) -> Option<Checkpoint> {
    let path = datadir.join("checkpoint.json");
    let data = std::fs::read_to_string(&path).ok()?;
    let cp: Checkpoint = serde_json::from_str(&data).ok()?;
    info!(height = cp.height, path = %path.display(), "checkpoint loaded");
    Some(cp)
}

/// Open (or create) a `PersistentUtxoSet` backed by a redb database at the
/// given path. Returns `None` if the database cannot be opened.
pub fn open_persistent_utxo_set(
    db_path: &Path,
) -> Option<PersistentUtxoSet<RedbDatabase>> {
    let db = RedbDatabase::new(db_path).ok()?; db.init_tables().ok()?;
    Some(PersistentUtxoSet::new(Arc::new(db)))
}

// ---------------------------------------------------------------------------
// SyncState
// ---------------------------------------------------------------------------

/// Tracks the current phase of the sync process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncState {
    /// Not syncing -- waiting for a trigger.
    Idle,
    /// Establishing connections to peers.
    ConnectingPeers,
    /// Downloading and validating block headers.
    DownloadingHeaders { progress: u64, target: u64 },
    /// Downloading full blocks for validated headers.
    DownloadingBlocks { progress: u64, target: u64 },
    /// Fully synchronised with the network.
    Synced,
}

impl SyncState {
    /// Returns `true` when in a terminal / resting state.
    pub fn is_idle_or_synced(&self) -> bool {
        matches!(self, SyncState::Idle | SyncState::Synced)
    }
}

impl std::fmt::Display for SyncState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncState::Idle => write!(f, "idle"),
            SyncState::ConnectingPeers => write!(f, "connecting_peers"),
            SyncState::DownloadingHeaders { progress, target } => {
                write!(f, "downloading_headers ({}/{})", progress, target)
            }
            SyncState::DownloadingBlocks { progress, target } => {
                write!(f, "downloading_blocks ({}/{})", progress, target)
            }
            SyncState::Synced => write!(f, "synced"),
        }
    }
}

// ---------------------------------------------------------------------------
// Pure sync logic (extracted for testability)
// ---------------------------------------------------------------------------

/// Compute the overall sync progress as a fraction in `[0.0, 1.0]` from the
/// current [`SyncState`].
///
/// - Header sync maps to `[0.0, 0.1]` (first 10%)
/// - Block sync maps to `[0.1, 1.0]` (remaining 90%)
pub fn compute_progress(state: &SyncState) -> f64 {
    match state {
        SyncState::Idle | SyncState::ConnectingPeers => 0.0,
        SyncState::DownloadingHeaders { progress, target } => {
            if *target == 0 {
                0.0
            } else {
                (*progress as f64 / *target as f64) * 0.1
            }
        }
        SyncState::DownloadingBlocks { progress, target } => {
            if *target == 0 {
                0.1
            } else {
                0.1 + (*progress as f64 / *target as f64) * 0.9
            }
        }
        SyncState::Synced => 1.0,
    }
}

/// Compute the block download start height given our chain height and
/// an optional checkpoint height.
///
/// Returns `max(chain_height, checkpoint_height) + 1`, ensuring we never
/// re-download already-validated blocks.
pub fn compute_block_start(chain_height: u64, checkpoint_height: Option<u64>) -> u64 {
    let cp_height = checkpoint_height.unwrap_or(0);
    std::cmp::max(chain_height, cp_height) + 1
}

/// Returns `true` when a batch of headers indicates that the peer has
/// no more to send (the header sync round is complete).
///
/// A peer sends fewer than `MAX_HEADERS_PER_MESSAGE` headers when it
/// has reached its tip.
pub fn is_header_sync_complete(received_count: usize) -> bool {
    received_count < MAX_HEADERS_PER_MESSAGE
}

/// Compute the end height of a block download batch.
///
/// Given a starting height, the configured batch size, and the overall
/// target height, returns the (inclusive) end of the batch clamped to
/// `to`.
pub fn compute_batch_end(height: u64, batch_size: usize, to: u64) -> u64 {
    (height + batch_size as u64 - 1).min(to)
}

/// Determine whether a block at `height` should have its scripts
/// fully verified, given the assume-valid tracking state.
///
/// This wraps `ChainParams::should_verify_scripts` with the local
/// `assume_valid_height` cache for convenience.
pub fn should_verify_scripts(
    params: &ChainParams,
    block_height: u64,
    block_hash: &BlockHash,
    assume_valid_height: Option<u64>,
) -> bool {
    params.should_verify_scripts(block_height, block_hash, assume_valid_height)
}

/// Determine whether the undo data at `block_height` should be pruned,
/// given the configured `max_undo_depth`.
///
/// Returns `Some(cutoff)` with the height below which undo data should
/// be pruned, or `None` if no pruning is needed yet.
pub fn compute_undo_prune_cutoff(block_height: u64, max_undo_depth: u64) -> Option<u64> {
    if block_height > max_undo_depth {
        Some(block_height - max_undo_depth)
    } else {
        None
    }
}

/// Determine whether persistent UTXO data should be flushed at the
/// given block height. Flushes happen every 500 blocks.
pub fn should_flush_utxo(block_height: u64) -> bool {
    block_height % 500 == 0
}

/// Determine whether the UTXO set status should be logged at the given
/// block height (every 500 blocks).
pub fn should_log_utxo_status(block_height: u64) -> bool {
    block_height % 500 == 0
}

/// Determine whether block download is needed. Returns `true` if the
/// peer tip is at or beyond our start height.
pub fn should_download_blocks(peer_tip: u64, block_start: u64) -> bool {
    peer_tip >= block_start
}

/// Validate a policy preset string. Returns `Ok(())` for valid presets,
/// `Err` with the invalid name for unknown presets.
pub fn validate_policy(policy: &str) -> Result<(), String> {
    match policy {
        "core" | "consensus" | "all" => Ok(()),
        other => Err(format!(
            "unknown policy preset '{}': expected 'core', 'consensus', or 'all'",
            other
        )),
    }
}

/// Classify inventory items into block and transaction categories.
///
/// Returns `(block_count, tx_count)`.
pub fn classify_inv_items(items: &[InvItem]) -> (usize, usize) {
    let block_count = items
        .iter()
        .filter(|i| matches!(i.inv_type, InvType::Block | InvType::WitnessBlock))
        .count();
    let tx_count = items
        .iter()
        .filter(|i| matches!(i.inv_type, InvType::Tx | InvType::WitnessTx))
        .count();
    (block_count, tx_count)
}

/// Determine the output format from CLI flags.
///
/// Priority: `--json` flag > `--output <format>` > auto-detect.
pub fn determine_output_format(json_flag: bool, output_opt: Option<&str>) -> crate::output::OutputFormat {
    if json_flag {
        crate::output::OutputFormat::Json
    } else {
        crate::output::OutputFormat::from_str_opt(output_opt)
    }
}

/// Compute the next [`SyncState`] after processing a headers batch.
///
/// `received_count` is the number of headers in the batch,
/// `new_height` is the chain height after accepting the headers.
pub fn next_state_after_headers(
    received_count: usize,
    new_height: u64,
) -> SyncState {
    if is_header_sync_complete(received_count) {
        // Headers complete -- transition to block download
        SyncState::DownloadingHeaders {
            progress: new_height,
            target: new_height,
        }
    } else {
        SyncState::DownloadingHeaders {
            progress: new_height,
            target: new_height,
        }
    }
}

/// Compute the next [`SyncState`] during block download.
pub fn next_state_downloading_blocks(downloaded: u64, total: u64) -> SyncState {
    SyncState::DownloadingBlocks {
        progress: downloaded,
        target: total,
    }
}

/// Estimate the sync ETA in seconds given the current progress and
/// elapsed time since sync started.
///
/// Returns `None` if progress is zero (cannot estimate).
pub fn estimate_sync_eta(progress: f64, elapsed_secs: f64) -> Option<f64> {
    if progress <= 0.0 || progress >= 1.0 || elapsed_secs <= 0.0 {
        return None;
    }
    let rate = progress / elapsed_secs;
    let remaining = 1.0 - progress;
    Some(remaining / rate)
}

/// Compute sync speed in blocks per second.
///
/// Returns `None` if elapsed time is zero.
pub fn compute_sync_speed(blocks_processed: u64, elapsed_secs: f64) -> Option<f64> {
    if elapsed_secs <= 0.0 {
        return None;
    }
    Some(blocks_processed as f64 / elapsed_secs)
}

/// Check whether a received block hash is one we requested.
///
/// Returns `Some(height)` if the hash is in the pending set, `None` otherwise.
pub fn lookup_pending_block(
    pending: &HashMap<BlockHash, u64>,
    block_hash: &BlockHash,
) -> Option<u64> {
    pending.get(block_hash).copied()
}

/// Detect whether a chain reorganization has occurred during header sync.
///
/// Returns `true` if the best chain tip changed to a block that is NOT
/// a direct extension of the previous tip.
pub fn detect_potential_reorg(
    old_best_hash: &BlockHash,
    new_best_hash: &BlockHash,
    first_header_prev: &BlockHash,
) -> bool {
    if new_best_hash == old_best_hash {
        return false;
    }
    // A direct extension has the first new header's prev == old best
    first_header_prev != old_best_hash
}

// ---------------------------------------------------------------------------
// SyncEvent
// ---------------------------------------------------------------------------

/// Progress / lifecycle events emitted by the sync manager.
#[derive(Debug, Clone)]
pub enum SyncEvent {
    /// Successfully connected to a peer.
    PeerConnected { addr: SocketAddr },
    /// Received and validated a batch of headers.
    HeadersReceived { count: usize, height: u64 },
    /// A block has been validated and stored.
    BlockValidated { height: u64, hash: BlockHash },
    /// Initial block download is complete.
    SyncComplete { height: u64 },
    /// An error occurred during sync.
    Error { message: String },
}

// ---------------------------------------------------------------------------
// SyncError
// ---------------------------------------------------------------------------

/// Errors that may occur during the sync process.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("connection error: {0}")]
    Connection(#[from] ConnectionError),
    #[error("no peers available")]
    NoPeers,
    #[error("peer sent unexpected message: {0}")]
    UnexpectedMessage(String),
    #[error("header validation failed: {0}")]
    HeaderValidation(String),
    #[error("block validation failed: {0}")]
    BlockValidation(String),
    #[error("sync aborted: {0}")]
    Aborted(String),
    #[error("reorg error: {0}")]
    Reorg(#[from] btc_consensus::reorg::ReorgError),
}

// ---------------------------------------------------------------------------
// SyncManager
// ---------------------------------------------------------------------------

/// Coordinates IBD (Initial Block Download) by wiring the P2P network layer
/// to the consensus engine.
///
/// The overall flow is:
///   1. Bootstrap peer addresses via DNS seeds.
///   2. Connect to outbound peers and perform version handshakes.
///   3. Determine the best (tallest) chain height reported by peers.
///   4. Download all headers from genesis to tip via `getheaders`/`headers`.
///   5. Download full blocks in batches via `getdata`/`block`.
///   6. Transition to `Synced` and listen for new inventory announcements.
pub struct SyncManager {
    network: Network,
    chain_state: Arc<RwLock<ChainState>>,
    peer_manager: Arc<RwLock<PeerManager>>,
    sync_state: SyncState,
    /// In-memory UTXO set, built up during IBD.
    utxo_set: Arc<RwLock<InMemoryUtxoSet>>,
    /// Network-specific consensus parameters (assume-valid, activation heights, etc.).
    chain_params: ChainParams,
    /// Manages undo data for chain reorganisations.
    reorg_manager: ReorgManager,
    /// Once we encounter the block whose hash matches `chain_params.assume_valid`,
    /// we record its height here so that subsequent blocks can skip script
    /// verification via `should_verify_scripts`.
    assume_valid_height: Option<u64>,
    /// Optional broadcast sender for ExEx notifications.  When set, the sync
    /// manager emits `BlockCommitted` events after each block is validated.
    exex_sender: Option<broadcast::Sender<ExExNotification>>,
    /// Optional shared node state.  When set, the sync manager updates the
    /// chain tip after each block is validated.
    node_state: Option<NodeState>,
    /// Optional data directory for checkpoint and UTXO persistence.
    datadir: Option<PathBuf>,
    /// Optional persistent UTXO set backed by redb.  When set, UTXO updates
    /// are also applied to this database so that the node can resume sync
    /// without reprocessing all blocks.
    persistent_utxo: Option<PersistentUtxoSet<RedbDatabase>>,
    /// When an AssumeUTXO snapshot has been loaded, this records the snapshot
    /// height so the sync manager starts block download from snapshot_height + 1.
    /// Background validation from genesis is a TODO.
    snapshot_height: Option<u64>,
}

impl SyncManager {
    /// Default number of blocks of undo data to retain for reorg protection.
    const DEFAULT_MAX_UNDO_DEPTH: u64 = 100;

    /// Create a new `SyncManager`.
    pub fn new(
        network: Network,
        chain_state: Arc<RwLock<ChainState>>,
        peer_manager: Arc<RwLock<PeerManager>>,
        chain_params: ChainParams,
    ) -> Self {
        SyncManager {
            network,
            chain_state,
            peer_manager,
            sync_state: SyncState::Idle,
            utxo_set: Arc::new(RwLock::new(InMemoryUtxoSet::new())),
            chain_params,
            reorg_manager: ReorgManager::new(Self::DEFAULT_MAX_UNDO_DEPTH),
            assume_valid_height: None,
            exex_sender: None,
            node_state: None,
            datadir: None,
            persistent_utxo: None,
            snapshot_height: None,
        }
    }

    /// Create a `SyncManager` with a data directory for checkpoint and UTXO
    /// persistence.  If the redb database at `{datadir}/utxo.redb` can be
    /// opened, a `PersistentUtxoSet` is initialised and UTXO updates are
    /// persisted to disk during IBD.
    pub fn with_datadir(
        network: Network,
        chain_state: Arc<RwLock<ChainState>>,
        peer_manager: Arc<RwLock<PeerManager>>,
        chain_params: ChainParams,
        datadir: PathBuf,
    ) -> Self {
        // Load checkpoint — tells us where we left off
        if let Some(cp) = load_checkpoint(&datadir) {
            info!(height = cp.height, hash = %cp.hash, "resuming from checkpoint");
        }

        // Open persistent UTXO database
        let db_path = datadir.join("utxo.redb");
        let persistent_utxo = open_persistent_utxo_set(&db_path);
        if persistent_utxo.is_some() {
            info!(path = %db_path.display(), "persistent UTXO set opened");
        }

        SyncManager {
            network,
            chain_state,
            peer_manager,
            sync_state: SyncState::Idle,
            utxo_set: Arc::new(RwLock::new(InMemoryUtxoSet::new())),
            chain_params,
            reorg_manager: ReorgManager::new(Self::DEFAULT_MAX_UNDO_DEPTH),
            assume_valid_height: None,
            exex_sender: None,
            node_state: None,
            datadir: Some(datadir),
            persistent_utxo,
            snapshot_height: None,
        }
    }

    /// Set the ExEx broadcast sender so that block commit events are emitted.
    pub fn set_exex_sender(&mut self, sender: broadcast::Sender<ExExNotification>) {
        self.exex_sender = Some(sender);
    }

    /// Set the shared NodeState so that chain tip updates propagate to all
    /// sub-systems (RPC, HTTP, metrics, etc.).
    pub fn set_node_state(&mut self, state: NodeState) {
        self.node_state = Some(state);
    }

    /// Return a reference to the reorg manager (for testing / inspection).
    pub fn reorg_manager(&self) -> &ReorgManager {
        &self.reorg_manager
    }

    /// Return a reference to the datadir, if configured.
    pub fn datadir(&self) -> Option<&Path> {
        self.datadir.as_deref()
    }

    /// Return `true` if a persistent UTXO set is configured.
    pub fn has_persistent_utxo(&self) -> bool {
        self.persistent_utxo.is_some()
    }

    /// Set the AssumeUTXO snapshot height.  When set, the sync manager will
    /// start block download from `snapshot_height + 1` instead of genesis.
    ///
    /// TODO: implement background validation from genesis to snapshot height
    /// to fully validate the snapshot.
    pub fn set_snapshot_height(&mut self, height: u64) {
        info!(height, "AssumeUTXO snapshot height set — will sync from snapshot");
        self.snapshot_height = Some(height);
    }

    /// Return the snapshot height if an AssumeUTXO snapshot has been loaded.
    pub fn snapshot_height(&self) -> Option<u64> {
        self.snapshot_height
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Return the current sync state.
    pub fn state(&self) -> &SyncState {
        &self.sync_state
    }

    /// Return the sync progress as a fraction in `[0.0, 1.0]`.
    pub fn progress(&self) -> f64 {
        compute_progress(&self.sync_state)
    }

    /// Return the network this manager operates on.
    pub fn network(&self) -> Network {
        self.network
    }

    // ------------------------------------------------------------------
    // Main sync loop
    // ------------------------------------------------------------------

    /// Run the full IBD sequence.
    ///
    /// This is the top-level entry point that drives the sync from start to
    /// finish. In a production node this would be spawned as a long-lived
    /// tokio task.
    pub async fn start(&mut self) -> Result<(), SyncError> {
        info!(network = %self.network, "sync manager starting");

        // Phase 1 -- bootstrap peer addresses.
        self.sync_state = SyncState::ConnectingPeers;
        {
            let mut pm = self.peer_manager.write().await;
            pm.bootstrap().await;
        }

        // Phase 2 -- connect to peers and handshake.
        let mut conn = self.connect_to_peer().await?;

        // Phase 3 -- determine the remote tip height.
        let best_height = {
            let cs = self.chain_state.read().await;
            cs.best_height()
        };
        info!(our_height = best_height, "starting header sync");

        // Phase 4 -- header sync.
        let peer_tip = self.sync_headers(&mut conn).await?;

        // NOTE: checkpoint is only saved after BLOCK validation (not headers)
        // to prevent skipping block download on restart.

        // Phase 5 -- block sync.
        // Use checkpoint height, snapshot height, or chain state height —
        // skip blocks we already validated or that are covered by the snapshot.
        let block_start = {
            let cp_height = self.datadir.as_ref()
                .and_then(|d| load_checkpoint(d))
                .map(|cp| cp.height)
                .unwrap_or(0);
            let snap_height = self.snapshot_height.unwrap_or(0);
            // Start from whichever is highest: chain_state height, checkpoint, or snapshot
            let max_validated = std::cmp::max(best_height, std::cmp::max(cp_height, snap_height));
            max_validated + 1
        };
        if self.snapshot_height.is_some() {
            info!(
                snapshot_height = self.snapshot_height.unwrap(),
                block_start,
                "AssumeUTXO: skipping to post-snapshot sync"
            );
            // TODO: spawn background validation from genesis to snapshot_height
        }
        if peer_tip >= block_start {
            info!(from = block_start, to = peer_tip, "starting block download (skipping already-validated blocks)");
            self.sync_blocks(&mut conn, block_start, peer_tip).await?;
        }

        // Phase 6 -- synced.
        self.sync_state = SyncState::Synced;
        let final_height = {
            let cs = self.chain_state.read().await;
            cs.best_height()
        };
        info!(height = final_height, "initial block download complete");

        // Save checkpoint after block sync completes.
        if let Some(ref datadir) = self.datadir {
            let cs = self.chain_state.read().await;
            let best = cs.best_header();
            let cp = Checkpoint::new(cs.best_height(), best.header.block_hash());
            if let Err(e) = save_checkpoint(datadir, &cp) {
                warn!(error = %e, "failed to save checkpoint after block sync");
            }
        }

        // Flush persistent UTXO cache if available.
        if let Some(ref mut persistent) = self.persistent_utxo {
            if let Err(e) = persistent.flush_cache() {
                warn!(error = %e, "failed to flush persistent UTXO cache");
            }
        }

        // Phase 7 -- steady-state listening for new blocks and transactions.
        info!("entering steady state - listening for new blocks and transactions");
        self.steady_state_loop(&mut conn).await;

        Ok(())
    }

    // ------------------------------------------------------------------
    // Steady-state loop
    // ------------------------------------------------------------------

    /// After IBD completes, listen for new block and transaction announcements.
    async fn steady_state_loop(&mut self, peer: &mut Connection) {
        loop {
            match peer.recv_message().await {
                Ok(NetworkMessage::Inv(items)) => {
                    // Separate block and tx announcements.
                    let block_items: Vec<_> = items.iter()
                        .filter(|i| matches!(i.inv_type, InvType::Block | InvType::WitnessBlock))
                        .collect();
                    let tx_items: Vec<_> = items.iter()
                        .filter(|i| matches!(i.inv_type, InvType::Tx | InvType::WitnessTx))
                        .collect();

                    if !block_items.is_empty() {
                        debug!(count = block_items.len(), "steady state: received block inv");
                    }
                    if !tx_items.is_empty() {
                        debug!(count = tx_items.len(), "steady state: received tx inv announcements");
                    }
                }
                Ok(NetworkMessage::Tx(tx)) => {
                    let txid = tx.txid();
                    debug!(%txid, "steady state: received transaction from peer");
                }
                Ok(NetworkMessage::Ping(nonce)) => {
                    peer.send_message(NetworkMessage::Pong(nonce)).await.ok();
                }
                Ok(other) => {
                    debug!(cmd = other.command(), "steady state: ignoring message");
                }
                Err(e) => {
                    warn!(error = %e, "peer disconnected in steady state");
                    break;
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Peer connection
    // ------------------------------------------------------------------

    /// Connect to a single outbound peer, trying multiple addresses until one works.
    async fn connect_to_peer(&mut self) -> Result<Connection, SyncError> {
        // Collect all known peers and try them in order
        let addrs: Vec<SocketAddr> = {
            let pm = self.peer_manager.read().await;
            // Try up to 20 peers
            let mut candidates = Vec::new();
            for _ in 0..20 {
                if let Some(addr) = pm.get_random_peer() {
                    if !candidates.contains(&addr) {
                        candidates.push(addr);
                    }
                }
            }
            candidates
        };

        if addrs.is_empty() {
            return Err(SyncError::NoPeers);
        }

        for addr in &addrs {
            // Skip IPv6 if likely unsupported
            if addr.is_ipv6() {
                debug!(%addr, "skipping IPv6 peer");
                continue;
            }

            info!(%addr, "connecting to peer");
            let conn_result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                Connection::connect_outbound(*addr, self.network),
            ).await;

            let mut conn = match conn_result {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    warn!(%addr, error = %e, "connection failed, trying next peer");
                    continue;
                }
                Err(_) => {
                    warn!(%addr, "connection timed out, trying next peer");
                    continue;
                }
            };

            let our_height = {
                let cs = self.chain_state.read().await;
                cs.best_height() as i32
            };

            let handshake_result = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                conn.perform_handshake(self.network, our_height),
            ).await;

            match handshake_result {
                Ok(Ok(handshake)) => {
                    if let Some(ver) = handshake.peer_version() {
                        let peer_info = btc_network::peer::PeerInfo {
                            addr: *addr,
                            state: btc_network::peer::PeerState::Ready,
                            version: ProtocolVersion(ver.version),
                            services: btc_network::protocol::ServiceFlags(ver.services),
                            user_agent: ver.user_agent.clone(),
                            start_height: ver.start_height,
                            relay: ver.relay,
                            inbound: false,
                        };
                        let mut pm = self.peer_manager.write().await;
                        pm.add_peer(*addr, peer_info);
                    }
                    info!(%addr, "peer connected and handshake complete");
                    return Ok(conn);
                }
                Ok(Err(e)) => {
                    warn!(%addr, error = %e, "handshake failed, trying next peer");
                }
                Err(_) => {
                    warn!(%addr, "handshake timed out, trying next peer");
                }
            }
        }

        Err(SyncError::NoPeers)
    }

    // ------------------------------------------------------------------
    // Header sync
    // ------------------------------------------------------------------

    /// Download all headers from the peer until we are caught up.
    ///
    /// Returns the height of the highest header we now have.
    pub async fn sync_headers(
        &mut self,
        peer: &mut Connection,
    ) -> Result<u64, SyncError> {
        loop {
            // Build locator from our current best chain.
            let (locators, our_height, old_best_hash) = {
                let cs = self.chain_state.read().await;
                (
                    cs.get_locator_hashes(),
                    cs.best_height(),
                    cs.best_header().header.block_hash(),
                )
            };

            self.sync_state = SyncState::DownloadingHeaders {
                progress: our_height,
                target: our_height, // updated once we learn the real target
            };

            // Send getheaders.
            let get_headers = NetworkMessage::GetHeaders(GetHeadersMessage {
                version: ProtocolVersion::CURRENT.0,
                locator_hashes: locators,
                stop_hash: BlockHash::ZERO,
            });
            peer.send_message(get_headers).await?;

            // Receive headers response.
            let headers = self.recv_headers(peer).await?;
            let count = headers.len();

            if count == 0 {
                // No new headers -- we are caught up.
                debug!("no new headers received, header sync complete");
                break;
            }

            // Validate and accept each header.
            {
                let mut cs = self.chain_state.write().await;
                for header in &headers {
                    cs.accept_header(header.clone()).map_err(|e| {
                        SyncError::HeaderValidation(e.to_string())
                    })?;
                }
            }

            let (new_height, new_best_hash) = {
                let cs = self.chain_state.read().await;
                (cs.best_height(), cs.best_header().header.block_hash())
            };

            info!(
                received = count,
                height = new_height,
                "headers batch accepted"
            );

            // Detect potential chain reorganisation: if the best tip changed
            // to a block that is NOT a descendant of the old best, the chain
            // state has switched to a competing branch.
            if new_best_hash != old_best_hash {
                let cs = self.chain_state.read().await;
                let new_entry = cs.get_header(&new_best_hash);
                let is_descendant = new_entry.map_or(false, |e| {
                    // Walk back from new tip to see if old_best_hash is an
                    // ancestor.  Quick check: if the new best is simply one
                    // batch ahead (prev of first new header == old best) this
                    // is normal linear extension.  Otherwise it may be a
                    // reorg.
                    let first_new = &headers[0];
                    first_new.prev_blockhash == old_best_hash
                        || e.header.prev_blockhash == old_best_hash
                });
                if !is_descendant {
                    info!(
                        old_tip = %old_best_hash,
                        new_tip = %new_best_hash,
                        "potential chain reorganization detected during header sync"
                    );
                    // The reorg will be handled during block download: we
                    // will download blocks on the new best chain and the old
                    // chain blocks become stale.
                }
            }

            self.sync_state = SyncState::DownloadingHeaders {
                progress: new_height,
                target: new_height,
            };

            // If we received fewer than MAX_HEADERS_PER_MESSAGE, the peer has
            // no more to send.
            if count < MAX_HEADERS_PER_MESSAGE {
                break;
            }
        }

        let final_height = {
            let cs = self.chain_state.read().await;
            cs.best_height()
        };
        Ok(final_height)
    }

    /// Receive a `Headers` message from the peer, skipping unrelated messages.
    async fn recv_headers(
        &self,
        peer: &mut Connection,
    ) -> Result<Vec<btc_primitives::block::BlockHeader>, SyncError> {
        loop {
            let msg = peer.recv_message().await?;
            match msg {
                NetworkMessage::Headers(headers) => return Ok(headers),
                NetworkMessage::Ping(nonce) => {
                    // Respond to pings to stay connected.
                    peer.send_message(NetworkMessage::Pong(nonce)).await?;
                }
                NetworkMessage::SendHeaders
                | NetworkMessage::FeeFilter(_)
                | NetworkMessage::Addr(_) => {
                    // Ignore protocol bookkeeping messages.
                    continue;
                }
                NetworkMessage::GetHeaders(_) => {
                    // Peer asks us for headers — respond with empty headers
                    // (we're still syncing, we don't have anything useful to send)
                    if let Err(e) = peer.send_message(NetworkMessage::Headers(vec![])).await {
                        warn!(error = %e, "failed to respond to getheaders");
                    }
                }
                NetworkMessage::GetData(items) => {
                    // Peer asks for data — respond with notfound
                    if let Err(e) = peer.send_message(NetworkMessage::NotFound(items)).await {
                        warn!(error = %e, "failed to respond to getdata");
                    }
                }
                other => {
                    debug!(command = other.command(), "ignoring message during header sync");
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Block sync
    // ------------------------------------------------------------------

    /// Download and validate blocks in the range `[from, to]` (inclusive).
    pub async fn sync_blocks(
        &mut self,
        peer: &mut Connection,
        from: u64,
        to: u64,
    ) -> Result<(), SyncError> {
        info!(from, to, "starting block download");

        let total = to - from + 1;
        let mut downloaded: u64 = 0;

        let mut height = from;
        while height <= to {
            let batch_end = (height + BLOCK_DOWNLOAD_BATCH_SIZE as u64 - 1).min(to);

            // Build a map of requested block hash -> expected height so we can
            // verify that the peer sends the blocks we actually asked for
            // (BUG 1 fix: verify received block hashes against requested hashes).
            let (inv_items, expected_hash_to_height) = {
                let cs = self.chain_state.read().await;
                let mut items = Vec::new();
                let mut hash_map: HashMap<BlockHash, u64> = HashMap::new();
                for h in height..=batch_end {
                    if let Some(entry) = cs.get_header_by_height(h) {
                        let block_hash = entry.header.block_hash();
                        items.push(InvItem {
                            inv_type: InvType::WitnessBlock,
                            hash: btc_primitives::hash::Hash256::from_bytes(
                                *block_hash.as_bytes(),
                            ),
                        });
                        hash_map.insert(block_hash, h);
                    }
                }
                (items, hash_map)
            };

            if inv_items.is_empty() {
                warn!(height, "no header found at height, skipping");
                height = batch_end + 1;
                continue;
            }

            let expected_count = inv_items.len();

            // Mutable copy of the hash map so we can remove entries as blocks arrive.
            let mut pending_hashes = expected_hash_to_height;

            // Send getdata.
            if let Err(e) = peer.send_message(NetworkMessage::GetData(inv_items)).await {
                warn!(error = %e, height, "failed to send getdata, aborting block sync");
                return Err(SyncError::Connection(e));
            }

            // Receive blocks.  Peers may interleave protocol messages (ping,
            // sendcmpct, inv, getheaders, etc.) between blocks -- skip those
            // and keep waiting.  Apply a generous per-message timeout so we
            // don't hang forever on a stalled peer.
            let mut received = 0;
            while received < expected_count {
                let recv_result = tokio::time::timeout(
                    std::time::Duration::from_secs(120),
                    peer.recv_message(),
                ).await;

                let msg = match recv_result {
                    Ok(Ok(m)) => m,
                    Ok(Err(e)) => {
                        warn!(
                            error = %e,
                            height,
                            received,
                            expected = expected_count,
                            "connection error during block download"
                        );
                        return Err(SyncError::Connection(e));
                    }
                    Err(_) => {
                        warn!(
                            height,
                            received,
                            expected = expected_count,
                            "timeout waiting for block from peer"
                        );
                        return Err(SyncError::Aborted(
                            "timeout waiting for block data".into(),
                        ));
                    }
                };

                match msg {
                    NetworkMessage::Block(block) => {
                        received += 1;
                        let block_hash = block.block_hash();

                        // Verify the received block hash was one we requested
                        // and look up its expected height from the map.
                        let block_height = match pending_hashes.remove(&block_hash) {
                            Some(h) => h,
                            None => {
                                warn!(
                                    hash = %block_hash,
                                    "received unrequested block, skipping"
                                );
                                continue;
                            }
                        };

                        downloaded += 1;
                        let tx_count = block.transactions.len();

                        debug!(
                            height = block_height,
                            hash = %block_hash,
                            txs = tx_count,
                            "block received"
                        );

                        // -------------------------------------------------
                        // Step 1: Context-free block structure validation
                        // -------------------------------------------------
                        if let Err(e) = BlockValidator::validate_block(&block) {
                            warn!(
                                height = block_height,
                                hash = %block_hash,
                                error = %e,
                                "block failed structural validation"
                            );
                            return Err(SyncError::BlockValidation(format!(
                                "block {} at height {}: {}",
                                block_hash, block_height, e
                            )));
                        }

                        // -------------------------------------------------
                        // Step 2: Connect block to UTXO set (contextual
                        // validation: no double-spends, coinbase maturity,
                        // value conservation, reward limit).
                        // -------------------------------------------------
                        let utxo_update = {
                            // Use persistent UTXO set if available (for resume),
                            // otherwise fall back to in-memory set.
                            let utxo_set = self.utxo_set.read().await;
                            let connect_result = if let Some(ref persistent) = self.persistent_utxo {
                                // Try persistent first (has data from previous runs)
                                connect_block(&block, block_height, persistent)
                                    .or_else(|_| connect_block(&block, block_height, &*utxo_set))
                            } else {
                                connect_block(&block, block_height, &*utxo_set)
                            };
                            match connect_result {
                                Ok(update) => update,
                                Err(e) => {
                                    warn!(
                                        height = block_height,
                                        hash = %block_hash,
                                        error = %e,
                                        "block failed UTXO validation"
                                    );
                                    return Err(SyncError::BlockValidation(format!(
                                        "UTXO error for block {} at height {}: {}",
                                        block_hash, block_height, e
                                    )));
                                }
                            }
                        };

                        // -------------------------------------------------
                        // Track assume-valid height: if this block's hash
                        // matches chain_params.assume_valid, record its
                        // height so future blocks can skip scripts.
                        // -------------------------------------------------
                        if let Some(ref av_hash) = self.chain_params.assume_valid {
                            if &block_hash == av_hash && self.assume_valid_height.is_none() {
                                info!(
                                    height = block_height,
                                    hash = %block_hash,
                                    "assume-valid block found, recording height"
                                );
                                self.assume_valid_height = Some(block_height);
                            }
                        }

                        // -------------------------------------------------
                        // Step 3: Optionally verify scripts (skip when
                        // below assume-valid to speed up IBD).
                        // Must happen BEFORE applying the UTXO update so
                        // that the spent outputs are still available for
                        // script verification lookups.
                        // -------------------------------------------------
                        if self.chain_params.should_verify_scripts(
                            block_height,
                            &block_hash,
                            self.assume_valid_height,
                        ) {
                            let utxo_set = self.utxo_set.read().await;
                            let validator = ParallelValidator::new(ParallelConfig::default());
                            // Use persistent UTXO set if available (for resume scenarios
                            // where in-memory set is empty), otherwise use in-memory.
                            let validate_result = if let Some(ref persistent) = self.persistent_utxo {
                                validator.validate_block_scripts(&block, persistent, block_height, &self.chain_params)
                            } else {
                                validator.validate_block_scripts(&block, &*utxo_set, block_height, &self.chain_params)
                            };
                            if let Err(errors) = validate_result {
                                // During IBD, log script failures as warnings but continue.
                                // UTXO validation (Step 2) already passed, so chain state is safe.
                                // Script verification issues will be fixed and re-validated.
                                let first_err = &errors[0];
                                warn!(
                                    height = block_height,
                                    hash = %block_hash,
                                    failures = errors.len(),
                                    first_tx = first_err.0,
                                    first_input = first_err.1,
                                    first_error = %first_err.2,
                                    "script verification warning (continuing sync)"
                                );
                                return Err(SyncError::BlockValidation(format!(
                                    "script verification failed for block {} at height {}: {} error(s), first: tx {} input {}: {}",
                                    block_hash, block_height, errors.len(),
                                    first_err.0, first_err.1, first_err.2
                                )));
                            }
                        }

                        // -------------------------------------------------
                        // Step 4: Apply UTXO updates to the in-memory set
                        // -------------------------------------------------
                        {
                            let mut utxo_set = self.utxo_set.write().await;
                            utxo_set.apply_update(&utxo_update);
                            
                            if block_height % 500 == 0 {
                                info!(
                                    height = block_height,
                                    utxo_count = utxo_set.len(),
                                    created = utxo_update.created.len(),
                                    spent = utxo_update.spent.len(),
                                    "UTXO set status"
                                );
                            }
                        }

                        // -------------------------------------------------
                        // Step 4b: Persist UTXO updates in batches of 500 blocks
                        // The in-memory UTXO set (Step 4) has the authoritative
                        // state; we only persist periodically for crash recovery.
                        // -------------------------------------------------
                        if let Some(ref mut persistent) = self.persistent_utxo {
                            // Always apply (updates the in-memory cache inside PersistentUtxoSet)
                            persistent.apply_update_cached(&utxo_update);
                            // Flush to disk every 500 blocks + save checkpoint
                            if block_height % 500 == 0 {
                                if let Err(e) = persistent.flush_cache() {
                                    warn!(height = block_height, error = %e, "failed to flush UTXO cache");
                                }
                                // Save checkpoint so restarts skip these blocks
                                if let Some(ref datadir) = self.datadir {
                                    let cp = Checkpoint::new(block_height, block_hash);
                                    let _ = save_checkpoint(datadir, &cp);
                                }
                            }
                        }

                        // -------------------------------------------------
                        // Step 5: Store undo data for reorg protection and
                        // prune old entries beyond the configured depth.
                        // -------------------------------------------------
                        self.reorg_manager.store_undo(block_height, utxo_update.clone());
                        let max_undo = self.reorg_manager.max_undo_depth();
                        if block_height > max_undo {
                            self.reorg_manager.prune_undo(block_height - max_undo);
                        }

                        // -------------------------------------------------
                        // Step 6: Emit ExEx notification and update NodeState
                        // -------------------------------------------------
                        if let Some(ref sender) = self.exex_sender {
                            sender.send(ExExNotification::BlockCommitted {
                                height: block_height,
                                hash: block_hash,
                                block: block.clone(),
                                utxo_changes: utxo_update,
                            }).ok();
                        }
                        if let Some(ref ns) = self.node_state {
                            ns.update_chain_tip(block_height, &block_hash.to_string());
                        }

                        debug!(
                            height = block_height,
                            hash = %block_hash,
                            utxos = self.utxo_set.read().await.len(),
                            "block validated and connected"
                        );

                        self.sync_state = SyncState::DownloadingBlocks {
                            progress: downloaded,
                            target: total,
                        };
                    }
                    NetworkMessage::Inv(items) => {
                        // Handle tx announcements during block sync.
                        let tx_items: Vec<_> = items.iter()
                            .filter(|i| matches!(i.inv_type, InvType::Tx | InvType::WitnessTx))
                            .collect();
                        if !tx_items.is_empty() {
                            debug!(count = tx_items.len(), "received tx inv announcements during block sync");
                        }
                    }
                    NetworkMessage::Tx(tx) => {
                        let txid = tx.txid();
                        debug!(%txid, "received transaction from peer during block sync");
                    }
                    NetworkMessage::Ping(nonce) => {
                        if let Err(e) = peer.send_message(NetworkMessage::Pong(nonce)).await {
                            warn!(error = %e, "failed to send pong during block sync");
                        }
                    }
                    other => {
                        debug!(
                            command = other.command(),
                            "ignoring message during block sync"
                        );
                    }
                }
            }

            info!(
                batch_from = height,
                batch_to = batch_end,
                total_downloaded = downloaded,
                total_blocks = total,
                "block batch received"
            );

            height = batch_end + 1;
        }

        info!(blocks = downloaded, "block download complete");
        Ok(())
    }

    // ------------------------------------------------------------------
    // Reorg handling
    // ------------------------------------------------------------------

    /// Handle a chain reorganisation between `old_tip` and `new_tip`.
    ///
    /// This method uses the `ReorgManager`'s stored undo data to disconnect
    /// blocks from the old chain back to the fork point, then connects blocks
    /// on the new chain.  The `new_blocks` slice must contain the full blocks
    /// from the fork point (exclusive) to `new_tip` (inclusive), in order.
    pub async fn handle_reorg(
        &mut self,
        old_tip: BlockHash,
        new_tip: BlockHash,
        new_blocks: &[btc_primitives::block::Block],
    ) -> Result<ReorgResult, SyncError> {
        info!(%old_tip, %new_tip, "handling chain reorganization");

        let mut cs = self.chain_state.write().await;
        let mut utxo_set = self.utxo_set.write().await;

        let result = reorg::execute_reorg(
            &mut cs,
            &self.reorg_manager,
            &mut utxo_set,
            &old_tip,
            &new_tip,
            new_blocks,
        )?;

        info!(
            fork_point = %result.fork_point,
            fork_height = result.fork_height,
            disconnected = result.disconnected.len(),
            connected = result.connected.len(),
            depth = result.depth,
            "chain reorganization complete"
        );

        Ok(result)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use btc_consensus::validation::ChainParams;

    // -----------------------------------------------------------------------
    // SyncState tests
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Pure utility function tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_block_start_no_checkpoint() {
        assert_eq!(compute_block_start(0, None), 1);
        assert_eq!(compute_block_start(100, None), 101);
    }

    #[test]
    fn test_compute_block_start_with_checkpoint() {
        assert_eq!(compute_block_start(0, Some(50)), 51);
        assert_eq!(compute_block_start(100, Some(50)), 101);
        assert_eq!(compute_block_start(50, Some(100)), 101);
    }

    #[test]
    fn test_is_header_sync_complete() {
        assert!(is_header_sync_complete(0));
        assert!(is_header_sync_complete(1999));
        assert!(!is_header_sync_complete(2000));
        assert!(!is_header_sync_complete(3000));
    }

    #[test]
    fn test_compute_batch_end() {
        assert_eq!(compute_batch_end(0, 128, 1000), 127);
        assert_eq!(compute_batch_end(900, 128, 1000), 1000);
        assert_eq!(compute_batch_end(1000, 128, 1000), 1000);
        assert_eq!(compute_batch_end(0, 128, 50), 50);
    }

    #[test]
    fn test_should_verify_scripts_with_assume_valid() {
        // Use mainnet params and set assume_valid to get proper behavior.
        let mut params = ChainParams::mainnet();
        params.assume_valid = Some(BlockHash::from_bytes([0xcc; 32]));
        let hash = BlockHash::from_bytes([0xaa; 32]);
        // Without assume_valid_height, should verify (hash doesn't match assume_valid).
        assert!(should_verify_scripts(&params, 100, &hash, None));
        // With assume_valid_height, blocks at or below should skip.
        assert!(!should_verify_scripts(&params, 100, &hash, Some(200)));
        // Blocks above assume_valid_height should verify.
        assert!(should_verify_scripts(&params, 300, &hash, Some(200)));
    }

    #[test]
    fn test_should_verify_scripts_regtest_no_assume_valid() {
        // Regtest has no assume_valid set, so should always verify.
        let params = ChainParams::regtest();
        let hash = BlockHash::from_bytes([0xaa; 32]);
        assert!(should_verify_scripts(&params, 100, &hash, None));
        assert!(should_verify_scripts(&params, 100, &hash, Some(200)));
        assert!(should_verify_scripts(&params, 300, &hash, Some(200)));
    }

    #[test]
    fn test_compute_undo_prune_cutoff() {
        assert_eq!(compute_undo_prune_cutoff(50, 100), None);
        assert_eq!(compute_undo_prune_cutoff(100, 100), None);
        assert_eq!(compute_undo_prune_cutoff(101, 100), Some(1));
        assert_eq!(compute_undo_prune_cutoff(200, 100), Some(100));
    }

    #[test]
    fn test_should_flush_utxo() {
        assert!(should_flush_utxo(0));
        assert!(!should_flush_utxo(1));
        assert!(!should_flush_utxo(499));
        assert!(should_flush_utxo(500));
        assert!(should_flush_utxo(1000));
    }

    #[test]
    fn test_should_log_utxo_status() {
        assert!(should_log_utxo_status(0));
        assert!(!should_log_utxo_status(1));
        assert!(should_log_utxo_status(500));
    }

    #[test]
    fn test_should_download_blocks() {
        assert!(should_download_blocks(100, 1));
        assert!(should_download_blocks(100, 100));
        assert!(!should_download_blocks(99, 100));
    }

    #[test]
    fn test_validate_policy() {
        assert!(validate_policy("core").is_ok());
        assert!(validate_policy("consensus").is_ok());
        assert!(validate_policy("all").is_ok());
        assert!(validate_policy("unknown").is_err());
        assert!(validate_policy("").is_err());
        let err = validate_policy("bad").unwrap_err();
        assert!(err.contains("bad"));
    }

    #[test]
    fn test_classify_inv_items() {
        let items = vec![
            InvItem {
                inv_type: InvType::Tx,
                hash: btc_primitives::hash::Hash256::from_bytes([0x01; 32]),
            },
            InvItem {
                inv_type: InvType::WitnessTx,
                hash: btc_primitives::hash::Hash256::from_bytes([0x02; 32]),
            },
            InvItem {
                inv_type: InvType::Block,
                hash: btc_primitives::hash::Hash256::from_bytes([0x03; 32]),
            },
            InvItem {
                inv_type: InvType::WitnessBlock,
                hash: btc_primitives::hash::Hash256::from_bytes([0x04; 32]),
            },
        ];
        let (blocks, txs) = classify_inv_items(&items);
        assert_eq!(blocks, 2);
        assert_eq!(txs, 2);
    }

    #[test]
    fn test_classify_inv_items_empty() {
        let (blocks, txs) = classify_inv_items(&[]);
        assert_eq!(blocks, 0);
        assert_eq!(txs, 0);
    }

    #[test]
    fn test_determine_output_format_json_flag() {
        let f = determine_output_format(true, None);
        assert_eq!(f, crate::output::OutputFormat::Json);
    }

    #[test]
    fn test_determine_output_format_output_opt() {
        let f = determine_output_format(false, Some("json"));
        assert_eq!(f, crate::output::OutputFormat::Json);
        let f = determine_output_format(false, Some("text"));
        assert_eq!(f, crate::output::OutputFormat::Text);
    }

    #[test]
    fn test_determine_output_format_json_flag_overrides_output() {
        let f = determine_output_format(true, Some("text"));
        assert_eq!(f, crate::output::OutputFormat::Json);
    }

    #[test]
    fn test_determine_output_format_auto() {
        let f = determine_output_format(false, None);
        // In test env, auto should return Json (not a TTY)
        assert_eq!(f, crate::output::OutputFormat::Json);
    }

    // -----------------------------------------------------------------------
    // SyncState tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sync_state_idle_default() {
        let state = SyncState::Idle;
        assert!(state.is_idle_or_synced());
    }

    #[test]
    fn test_sync_state_synced_is_terminal() {
        let state = SyncState::Synced;
        assert!(state.is_idle_or_synced());
    }

    #[test]
    fn test_sync_state_downloading_is_not_terminal() {
        let state = SyncState::DownloadingHeaders {
            progress: 100,
            target: 800_000,
        };
        assert!(!state.is_idle_or_synced());

        let state = SyncState::DownloadingBlocks {
            progress: 50,
            target: 800_000,
        };
        assert!(!state.is_idle_or_synced());
    }

    #[test]
    fn test_sync_state_connecting_is_not_terminal() {
        let state = SyncState::ConnectingPeers;
        assert!(!state.is_idle_or_synced());
    }

    #[test]
    fn test_sync_state_display() {
        assert_eq!(SyncState::Idle.to_string(), "idle");
        assert_eq!(SyncState::ConnectingPeers.to_string(), "connecting_peers");
        assert_eq!(SyncState::Synced.to_string(), "synced");
        assert_eq!(
            SyncState::DownloadingHeaders {
                progress: 100,
                target: 1000,
            }
            .to_string(),
            "downloading_headers (100/1000)"
        );
        assert_eq!(
            SyncState::DownloadingBlocks {
                progress: 50,
                target: 200,
            }
            .to_string(),
            "downloading_blocks (50/200)"
        );
    }

    #[test]
    fn test_sync_state_equality() {
        assert_eq!(SyncState::Idle, SyncState::Idle);
        assert_eq!(SyncState::Synced, SyncState::Synced);
        assert_eq!(
            SyncState::DownloadingHeaders {
                progress: 10,
                target: 20,
            },
            SyncState::DownloadingHeaders {
                progress: 10,
                target: 20,
            }
        );
        assert_ne!(SyncState::Idle, SyncState::Synced);
        assert_ne!(
            SyncState::DownloadingHeaders {
                progress: 10,
                target: 20,
            },
            SyncState::DownloadingHeaders {
                progress: 11,
                target: 20,
            }
        );
    }

    // -----------------------------------------------------------------------
    // SyncState transitions (model the expected IBD state machine)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sync_state_transitions() {
        // Model the expected lifecycle: Idle -> ConnectingPeers ->
        // DownloadingHeaders -> DownloadingBlocks -> Synced
        let mut state = SyncState::Idle;
        assert!(state.is_idle_or_synced());

        state = SyncState::ConnectingPeers;
        assert!(!state.is_idle_or_synced());

        state = SyncState::DownloadingHeaders {
            progress: 0,
            target: 800_000,
        };
        assert!(!state.is_idle_or_synced());

        state = SyncState::DownloadingHeaders {
            progress: 400_000,
            target: 800_000,
        };
        assert!(!state.is_idle_or_synced());

        state = SyncState::DownloadingHeaders {
            progress: 800_000,
            target: 800_000,
        };
        assert!(!state.is_idle_or_synced());

        state = SyncState::DownloadingBlocks {
            progress: 0,
            target: 800_000,
        };
        assert!(!state.is_idle_or_synced());

        state = SyncState::DownloadingBlocks {
            progress: 800_000,
            target: 800_000,
        };
        assert!(!state.is_idle_or_synced());

        state = SyncState::Synced;
        assert!(state.is_idle_or_synced());
    }

    // -----------------------------------------------------------------------
    // Progress calculation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_progress_idle() {
        let sm = make_sync_manager_with_state(SyncState::Idle);
        assert_eq!(sm.progress(), 0.0);
    }

    #[test]
    fn test_progress_connecting() {
        let sm = make_sync_manager_with_state(SyncState::ConnectingPeers);
        assert_eq!(sm.progress(), 0.0);
    }

    #[test]
    fn test_progress_synced() {
        let sm = make_sync_manager_with_state(SyncState::Synced);
        assert_eq!(sm.progress(), 1.0);
    }

    #[test]
    fn test_progress_headers_midway() {
        let sm = make_sync_manager_with_state(SyncState::DownloadingHeaders {
            progress: 400_000,
            target: 800_000,
        });
        let p = sm.progress();
        // 50% of headers = 5% overall
        assert!((p - 0.05).abs() < 1e-9, "expected ~0.05, got {}", p);
    }

    #[test]
    fn test_progress_headers_complete() {
        let sm = make_sync_manager_with_state(SyncState::DownloadingHeaders {
            progress: 800_000,
            target: 800_000,
        });
        let p = sm.progress();
        assert!((p - 0.1).abs() < 1e-9, "expected ~0.1, got {}", p);
    }

    #[test]
    fn test_progress_blocks_midway() {
        let sm = make_sync_manager_with_state(SyncState::DownloadingBlocks {
            progress: 400_000,
            target: 800_000,
        });
        let p = sm.progress();
        // 50% of blocks = 0.1 + 0.45 = 0.55
        assert!((p - 0.55).abs() < 1e-9, "expected ~0.55, got {}", p);
    }

    #[test]
    fn test_progress_blocks_complete() {
        let sm = make_sync_manager_with_state(SyncState::DownloadingBlocks {
            progress: 800_000,
            target: 800_000,
        });
        let p = sm.progress();
        assert!((p - 1.0).abs() < 1e-9, "expected ~1.0, got {}", p);
    }

    #[test]
    fn test_progress_headers_zero_target() {
        let sm = make_sync_manager_with_state(SyncState::DownloadingHeaders {
            progress: 0,
            target: 0,
        });
        assert_eq!(sm.progress(), 0.0);
    }

    #[test]
    fn test_progress_blocks_zero_target() {
        let sm = make_sync_manager_with_state(SyncState::DownloadingBlocks {
            progress: 0,
            target: 0,
        });
        assert!((sm.progress() - 0.1).abs() < 1e-9);
    }

    #[test]
    fn test_progress_monotonically_increases() {
        // Walk through the expected states and verify progress never decreases.
        let states = vec![
            SyncState::Idle,
            SyncState::ConnectingPeers,
            SyncState::DownloadingHeaders {
                progress: 0,
                target: 1000,
            },
            SyncState::DownloadingHeaders {
                progress: 500,
                target: 1000,
            },
            SyncState::DownloadingHeaders {
                progress: 1000,
                target: 1000,
            },
            SyncState::DownloadingBlocks {
                progress: 0,
                target: 1000,
            },
            SyncState::DownloadingBlocks {
                progress: 500,
                target: 1000,
            },
            SyncState::DownloadingBlocks {
                progress: 1000,
                target: 1000,
            },
            SyncState::Synced,
        ];

        let mut prev = -1.0f64;
        for state in states {
            let sm = make_sync_manager_with_state(state.clone());
            let p = sm.progress();
            assert!(
                p >= prev,
                "progress went backwards: {} -> {} at state {:?}",
                prev,
                p,
                state
            );
            prev = p;
        }
    }

    // -----------------------------------------------------------------------
    // SyncManager construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sync_manager_new() {
        let sm = make_sync_manager();
        assert_eq!(*sm.state(), SyncState::Idle);
        assert_eq!(sm.progress(), 0.0);
        assert_eq!(sm.network(), Network::Regtest);
    }

    #[test]
    fn test_sync_manager_network() {
        let params = ChainParams::mainnet();
        let cs = Arc::new(RwLock::new(ChainState::new(params)));
        let pm = Arc::new(RwLock::new(PeerManager::new(Network::Mainnet)));
        let sync_params = ChainParams::mainnet();
        let sm = SyncManager::new(Network::Mainnet, cs, pm, sync_params);
        assert_eq!(sm.network(), Network::Mainnet);
    }

    // -----------------------------------------------------------------------
    // SyncEvent tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sync_event_debug() {
        let events = vec![
            SyncEvent::PeerConnected {
                addr: "127.0.0.1:8333".parse().unwrap(),
            },
            SyncEvent::HeadersReceived {
                count: 2000,
                height: 800_000,
            },
            SyncEvent::BlockValidated {
                height: 1,
                hash: BlockHash::ZERO,
            },
            SyncEvent::SyncComplete { height: 800_000 },
            SyncEvent::Error {
                message: "test error".into(),
            },
        ];
        // All variants should format without panicking.
        for event in &events {
            let _ = format!("{:?}", event);
        }
    }

    // -----------------------------------------------------------------------
    // SyncError tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sync_error_display() {
        let err = SyncError::NoPeers;
        assert_eq!(err.to_string(), "no peers available");

        let err = SyncError::UnexpectedMessage("inv".into());
        assert!(err.to_string().contains("inv"));

        let err = SyncError::HeaderValidation("bad timestamp".into());
        assert!(err.to_string().contains("bad timestamp"));

        let err = SyncError::BlockValidation("invalid merkle root".into());
        assert!(err.to_string().contains("invalid merkle root"));

        let err = SyncError::Aborted("user request".into());
        assert!(err.to_string().contains("user request"));
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    /// Build a `SyncManager` in the default (Idle) state for testing.
    fn make_sync_manager() -> SyncManager {
        let params = ChainParams::regtest();
        let cs = Arc::new(RwLock::new(ChainState::new(params)));
        let pm = Arc::new(RwLock::new(PeerManager::new(Network::Regtest)));
        let sync_params = ChainParams::regtest();
        SyncManager::new(Network::Regtest, cs, pm, sync_params)
    }

    /// Build a `SyncManager` pre-set to a particular state.
    fn make_sync_manager_with_state(state: SyncState) -> SyncManager {
        let mut sm = make_sync_manager();
        sm.sync_state = state;
        sm
    }

    // -----------------------------------------------------------------------
    // ReorgManager integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sync_manager_has_reorg_manager() {
        let sm = make_sync_manager();
        assert_eq!(
            sm.reorg_manager().max_undo_depth(),
            SyncManager::DEFAULT_MAX_UNDO_DEPTH,
            "reorg manager should be initialized with default undo depth"
        );
    }

    #[test]
    fn test_sync_manager_reorg_manager_stores_undo() {
        let mut sm = make_sync_manager();
        let update = btc_consensus::utxo::UtxoSetUpdate {
            spent: vec![],
            created: vec![],
        };
        sm.reorg_manager.store_undo(42, update);
        assert!(
            sm.reorg_manager().get_undo(42).is_some(),
            "should be able to store and retrieve undo data"
        );
        assert!(
            sm.reorg_manager().get_undo(43).is_none(),
            "should not find undo data at a different height"
        );
    }

    #[test]
    fn test_sync_manager_reorg_manager_prunes_undo() {
        let mut sm = make_sync_manager();
        for h in 1..=10u64 {
            sm.reorg_manager.store_undo(
                h,
                btc_consensus::utxo::UtxoSetUpdate {
                    spent: vec![],
                    created: vec![],
                },
            );
        }

        sm.reorg_manager.prune_undo(6);
        for h in 1..=5u64 {
            assert!(
                sm.reorg_manager().get_undo(h).is_none(),
                "height {} should be pruned",
                h
            );
        }
        for h in 6..=10u64 {
            assert!(
                sm.reorg_manager().get_undo(h).is_some(),
                "height {} should remain",
                h
            );
        }
    }

    #[test]
    fn test_sync_error_reorg_variant() {
        let reorg_err = btc_consensus::reorg::ReorgError::TooDeep {
            depth: 200,
            max: 100,
        };
        let sync_err: SyncError = reorg_err.into();
        let msg = sync_err.to_string();
        assert!(
            msg.contains("reorg") || msg.contains("200") || msg.contains("100"),
            "reorg error should be wrapped in SyncError: {}",
            msg
        );
    }

    #[test]
    fn test_sync_manager_default_undo_depth() {
        assert_eq!(
            SyncManager::DEFAULT_MAX_UNDO_DEPTH,
            100,
            "default undo depth should be 100 blocks"
        );
    }

    #[test]
    fn test_sync_manager_reorg_manager_accessor() {
        let sm = make_sync_manager();
        // Verify the accessor returns a reference to the internal reorg manager.
        let mgr = sm.reorg_manager();
        assert_eq!(mgr.max_undo_depth(), 100);
        assert!(
            mgr.get_undo(0).is_none(),
            "fresh reorg manager should have no undo data"
        );
    }

    // -----------------------------------------------------------------------
    // Checkpoint save/load tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_checkpoint_save_and_load() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let cp = Checkpoint::new(50_000, BlockHash::ZERO);

        save_checkpoint(dir.path(), &cp).expect("save should succeed");

        let loaded = load_checkpoint(dir.path());
        assert!(loaded.is_some(), "checkpoint should be loadable");
        let loaded = loaded.unwrap();
        assert_eq!(loaded.height, 50_000);
        assert_eq!(loaded, cp);
    }

    #[test]
    fn test_checkpoint_load_missing() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let loaded = load_checkpoint(dir.path());
        assert!(loaded.is_none(), "missing checkpoint should return None");
    }

    #[test]
    fn test_checkpoint_load_corrupt() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("checkpoint.json");
        std::fs::write(&path, "this is not json").expect("write should succeed");

        let loaded = load_checkpoint(dir.path());
        assert!(loaded.is_none(), "corrupt checkpoint should return None");
    }

    #[test]
    fn test_checkpoint_serialization_roundtrip() {
        let cp = Checkpoint {
            height: 840_000,
            hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f".to_string(),
        };
        let json = serde_json::to_string(&cp).expect("serialize should succeed");
        let deserialized: Checkpoint = serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(cp, deserialized);
    }

    // -----------------------------------------------------------------------
    // PersistentUtxoSet construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_persistent_utxo_set_construction() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let db_path = dir.path().join("utxo.redb");

        let persistent = open_persistent_utxo_set(&db_path);
        assert!(persistent.is_some(), "should be able to open persistent UTXO set");

        let persistent = persistent.unwrap();
        assert_eq!(persistent.cache_len(), 0, "fresh set should have empty cache");
    }

    #[test]
    fn test_sync_manager_with_datadir() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");

        let params = ChainParams::regtest();
        let cs = Arc::new(RwLock::new(ChainState::new(params)));
        let pm = Arc::new(RwLock::new(PeerManager::new(Network::Regtest)));
        let sync_params = ChainParams::regtest();

        let sm = SyncManager::with_datadir(
            Network::Regtest,
            cs,
            pm,
            sync_params,
            dir.path().to_path_buf(),
        );

        assert_eq!(*sm.state(), SyncState::Idle);
        assert!(sm.datadir().is_some());
        assert!(sm.has_persistent_utxo(), "should have persistent UTXO set when datadir is configured");
    }

    #[test]
    fn test_open_persistent_utxo_set_invalid_path() {
        // On some systems this may fail differently, but the function should
        // return None for an invalid path.
        let result = open_persistent_utxo_set(std::path::Path::new("/dev/null/impossible/path.redb"));
        assert!(result.is_none());
    }

    #[test]
    fn test_sync_manager_with_datadir_and_checkpoint() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Pre-create a checkpoint
        let cp = Checkpoint::new(100, BlockHash::ZERO);
        save_checkpoint(dir.path(), &cp).expect("save");

        let params = ChainParams::regtest();
        let cs = Arc::new(RwLock::new(ChainState::new(params)));
        let pm = Arc::new(RwLock::new(PeerManager::new(Network::Regtest)));
        let sync_params = ChainParams::regtest();

        let sm = SyncManager::with_datadir(
            Network::Regtest,
            cs,
            pm,
            sync_params,
            dir.path().to_path_buf(),
        );

        // The manager should have loaded the checkpoint (verified by log output)
        assert_eq!(*sm.state(), SyncState::Idle);
        assert!(sm.datadir().is_some());
    }

    #[test]
    fn test_checkpoint_overwrite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cp1 = Checkpoint::new(100, BlockHash::ZERO);
        save_checkpoint(dir.path(), &cp1).expect("save");
        let cp2 = Checkpoint::new(200, BlockHash::from_bytes([0xaa; 32]));
        save_checkpoint(dir.path(), &cp2).expect("save");
        let loaded = load_checkpoint(dir.path()).unwrap();
        assert_eq!(loaded.height, 200);
    }

    #[test]
    fn test_max_headers_per_message_constant() {
        assert_eq!(MAX_HEADERS_PER_MESSAGE, 2000);
    }

    #[test]
    fn test_block_download_batch_size_constant() {
        assert_eq!(BLOCK_DOWNLOAD_BATCH_SIZE, 128);
    }

    #[test]
    fn test_sync_manager_without_datadir_has_no_persistent_utxo() {
        let sm = make_sync_manager();
        assert!(sm.datadir().is_none());
        assert!(!sm.has_persistent_utxo());
    }

    // -----------------------------------------------------------------------
    // Steady-state inv handling tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_inv_type_filtering() {
        // Verify that the inv type filter logic correctly separates
        // block and tx items.
        let items = vec![
            InvItem {
                inv_type: InvType::Tx,
                hash: btc_primitives::hash::Hash256::from_bytes([0x01; 32]),
            },
            InvItem {
                inv_type: InvType::WitnessTx,
                hash: btc_primitives::hash::Hash256::from_bytes([0x02; 32]),
            },
            InvItem {
                inv_type: InvType::Block,
                hash: btc_primitives::hash::Hash256::from_bytes([0x03; 32]),
            },
            InvItem {
                inv_type: InvType::WitnessBlock,
                hash: btc_primitives::hash::Hash256::from_bytes([0x04; 32]),
            },
            InvItem {
                inv_type: InvType::Error,
                hash: btc_primitives::hash::Hash256::from_bytes([0x05; 32]),
            },
        ];

        let tx_items: Vec<_> = items.iter()
            .filter(|i| matches!(i.inv_type, InvType::Tx | InvType::WitnessTx))
            .collect();
        assert_eq!(tx_items.len(), 2, "should find 2 tx inv items");

        let block_items: Vec<_> = items.iter()
            .filter(|i| matches!(i.inv_type, InvType::Block | InvType::WitnessBlock))
            .collect();
        assert_eq!(block_items.len(), 2, "should find 2 block inv items");
    }

    // -----------------------------------------------------------------------
    // BUG 1: Verify received block hashes against requested hashes
    // -----------------------------------------------------------------------

    #[test]
    fn test_block_hash_lookup_map_construction() {
        // Verify that the HashMap<BlockHash, u64> pattern used in sync_blocks
        // correctly maps block hashes to their expected heights.
        let mut hash_map: HashMap<BlockHash, u64> = HashMap::new();
        let hash_a = BlockHash::from_bytes([0x01; 32]);
        let hash_b = BlockHash::from_bytes([0x02; 32]);
        let hash_c = BlockHash::from_bytes([0x03; 32]);

        hash_map.insert(hash_a, 100);
        hash_map.insert(hash_b, 101);
        hash_map.insert(hash_c, 102);

        // A known hash returns the correct height.
        assert_eq!(hash_map.get(&hash_a), Some(&100));
        assert_eq!(hash_map.get(&hash_b), Some(&101));
        assert_eq!(hash_map.get(&hash_c), Some(&102));

        // An unknown hash returns None (would be skipped in sync_blocks).
        let unknown = BlockHash::from_bytes([0xff; 32]);
        assert!(
            hash_map.get(&unknown).is_none(),
            "unknown hash should not be in the map"
        );

        // After removing a processed hash, it should no longer be found.
        hash_map.remove(&hash_a);
        assert!(
            hash_map.get(&hash_a).is_none(),
            "processed hash should be removed from the map"
        );
    }

    // -----------------------------------------------------------------------
    // BUG 9: assume_valid_height tracking
    // -----------------------------------------------------------------------

    #[test]
    fn test_sync_manager_assume_valid_height_initially_none() {
        let sm = make_sync_manager();
        assert!(
            sm.assume_valid_height.is_none(),
            "assume_valid_height should start as None"
        );
    }

    #[test]
    fn test_sync_manager_assume_valid_height_can_be_set() {
        let mut sm = make_sync_manager();
        sm.assume_valid_height = Some(500_000);
        assert_eq!(sm.assume_valid_height, Some(500_000));
    }

    #[test]
    fn test_sync_manager_set_exex_sender() {
        let mut sm = make_sync_manager();
        let (tx, _rx) = broadcast::channel(16);
        sm.set_exex_sender(tx);
        assert!(sm.exex_sender.is_some());
    }

    #[test]
    fn test_sync_manager_set_node_state() {
        let mut sm = make_sync_manager();
        let state = crate::state::NodeState::new(Network::Regtest);
        sm.set_node_state(state);
        assert!(sm.node_state.is_some());
    }

    #[test]
    fn test_checkpoint_new() {
        let hash = BlockHash::from_bytes([0xab; 32]);
        let cp = Checkpoint::new(42, hash);
        assert_eq!(cp.height, 42);
        assert!(cp.hash.len() > 0);
    }

    #[test]
    fn test_checkpoint_equality() {
        let cp1 = Checkpoint {
            height: 100,
            hash: "abc".to_string(),
        };
        let cp2 = Checkpoint {
            height: 100,
            hash: "abc".to_string(),
        };
        let cp3 = Checkpoint {
            height: 200,
            hash: "abc".to_string(),
        };
        assert_eq!(cp1, cp2);
        assert_ne!(cp1, cp3);
    }

    #[test]
    fn test_checkpoint_debug() {
        let cp = Checkpoint::new(1, BlockHash::ZERO);
        let debug = format!("{:?}", cp);
        assert!(debug.contains("Checkpoint"));
    }

    #[test]
    fn test_checkpoint_clone() {
        let cp = Checkpoint::new(1, BlockHash::ZERO);
        let cp2 = cp.clone();
        assert_eq!(cp, cp2);
    }

    #[test]
    fn test_save_checkpoint_creates_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let subdir = dir.path().join("nested").join("deep");
        let cp = Checkpoint::new(1, BlockHash::ZERO);
        save_checkpoint(&subdir, &cp).expect("save should create dirs");
        assert!(subdir.join("checkpoint.json").exists());
    }

    #[test]
    fn test_sync_state_clone() {
        let state = SyncState::DownloadingHeaders {
            progress: 100,
            target: 200,
        };
        let state2 = state.clone();
        assert_eq!(state, state2);
    }

    #[test]
    fn test_sync_error_connection() {
        let err = SyncError::Connection(ConnectionError::ConnectionClosed);
        let msg = err.to_string();
        assert!(msg.contains("connection"));
    }

    #[test]
    fn test_sync_event_clone() {
        let event = SyncEvent::SyncComplete { height: 100 };
        let event2 = event.clone();
        let _ = format!("{:?}", event2);
    }

    #[test]
    fn test_assume_valid_height_with_should_verify_scripts() {
        // Verify that passing assume_valid_height to should_verify_scripts
        // correctly skips scripts for blocks at or below that height.
        let mut params = ChainParams::mainnet();
        let av_hash = BlockHash::from_bytes([0xaa; 32]);
        params.assume_valid = Some(av_hash);

        let some_hash = BlockHash::from_bytes([0xbb; 32]);

        // Without assume_valid_height, blocks below the assume-valid block
        // would still require verification (unless their hash matches).
        assert!(params.should_verify_scripts(100, &some_hash, None));

        // With assume_valid_height set, blocks at or below should skip scripts.
        assert!(!params.should_verify_scripts(100, &some_hash, Some(500_000)));
        assert!(!params.should_verify_scripts(500_000, &some_hash, Some(500_000)));

        // Blocks above the assume_valid_height should still verify.
        assert!(params.should_verify_scripts(500_001, &some_hash, Some(500_000)));
    }

    // -----------------------------------------------------------------------
    // compute_progress (free function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_progress_fn_idle() {
        assert_eq!(compute_progress(&SyncState::Idle), 0.0);
    }

    #[test]
    fn test_compute_progress_fn_connecting() {
        assert_eq!(compute_progress(&SyncState::ConnectingPeers), 0.0);
    }

    #[test]
    fn test_compute_progress_fn_synced() {
        assert_eq!(compute_progress(&SyncState::Synced), 1.0);
    }

    #[test]
    fn test_compute_progress_headers_zero_target() {
        let state = SyncState::DownloadingHeaders { progress: 0, target: 0 };
        assert_eq!(compute_progress(&state), 0.0);
    }

    #[test]
    fn test_compute_progress_headers_midway() {
        let state = SyncState::DownloadingHeaders { progress: 400_000, target: 800_000 };
        let p = compute_progress(&state);
        assert!((p - 0.05).abs() < 1e-9, "expected ~0.05, got {}", p);
    }

    #[test]
    fn test_compute_progress_headers_complete() {
        let state = SyncState::DownloadingHeaders { progress: 800_000, target: 800_000 };
        let p = compute_progress(&state);
        assert!((p - 0.1).abs() < 1e-9, "expected ~0.1, got {}", p);
    }

    #[test]
    fn test_compute_progress_blocks_zero_target() {
        let state = SyncState::DownloadingBlocks { progress: 0, target: 0 };
        let p = compute_progress(&state);
        assert!((p - 0.1).abs() < 1e-9);
    }

    #[test]
    fn test_compute_progress_blocks_midway() {
        let state = SyncState::DownloadingBlocks { progress: 400_000, target: 800_000 };
        let p = compute_progress(&state);
        assert!((p - 0.55).abs() < 1e-9, "expected ~0.55, got {}", p);
    }

    #[test]
    fn test_compute_progress_blocks_complete() {
        let state = SyncState::DownloadingBlocks { progress: 800_000, target: 800_000 };
        let p = compute_progress(&state);
        assert!((p - 1.0).abs() < 1e-9, "expected ~1.0, got {}", p);
    }

    #[test]
    fn test_compute_progress_monotonic_through_lifecycle() {
        let states = [
            SyncState::Idle,
            SyncState::ConnectingPeers,
            SyncState::DownloadingHeaders { progress: 0, target: 1000 },
            SyncState::DownloadingHeaders { progress: 250, target: 1000 },
            SyncState::DownloadingHeaders { progress: 500, target: 1000 },
            SyncState::DownloadingHeaders { progress: 750, target: 1000 },
            SyncState::DownloadingHeaders { progress: 1000, target: 1000 },
            SyncState::DownloadingBlocks { progress: 0, target: 1000 },
            SyncState::DownloadingBlocks { progress: 250, target: 1000 },
            SyncState::DownloadingBlocks { progress: 500, target: 1000 },
            SyncState::DownloadingBlocks { progress: 750, target: 1000 },
            SyncState::DownloadingBlocks { progress: 1000, target: 1000 },
            SyncState::Synced,
        ];
        let mut prev = -1.0f64;
        for state in &states {
            let p = compute_progress(state);
            assert!(p >= prev, "progress went backwards: {} -> {} at {:?}", prev, p, state);
            prev = p;
        }
    }

    #[test]
    fn test_compute_progress_headers_quarter() {
        let state = SyncState::DownloadingHeaders { progress: 250, target: 1000 };
        let p = compute_progress(&state);
        assert!((p - 0.025).abs() < 1e-9, "expected 0.025, got {}", p);
    }

    #[test]
    fn test_compute_progress_blocks_quarter() {
        let state = SyncState::DownloadingBlocks { progress: 250, target: 1000 };
        let p = compute_progress(&state);
        // 0.1 + 0.25 * 0.9 = 0.1 + 0.225 = 0.325
        assert!((p - 0.325).abs() < 1e-9, "expected 0.325, got {}", p);
    }

    // -----------------------------------------------------------------------
    // compute_block_start (extended)
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_block_start_large_height() {
        assert_eq!(compute_block_start(800_000, None), 800_001);
    }

    #[test]
    fn test_compute_block_start_checkpoint_lower_than_chain() {
        assert_eq!(compute_block_start(100, Some(50)), 101);
    }

    #[test]
    fn test_compute_block_start_checkpoint_higher_than_chain() {
        assert_eq!(compute_block_start(50, Some(100)), 101);
    }

    #[test]
    fn test_compute_block_start_checkpoint_equal_to_chain() {
        assert_eq!(compute_block_start(100, Some(100)), 101);
    }

    #[test]
    fn test_compute_block_start_both_at_zero() {
        assert_eq!(compute_block_start(0, Some(0)), 1);
    }

    // -----------------------------------------------------------------------
    // is_header_sync_complete (extended)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_header_sync_complete_empty() {
        assert!(is_header_sync_complete(0));
    }

    #[test]
    fn test_is_header_sync_complete_partial() {
        assert!(is_header_sync_complete(100));
        assert!(is_header_sync_complete(1999));
    }

    #[test]
    fn test_is_header_sync_complete_over_batch() {
        assert!(!is_header_sync_complete(2001));
    }

    // -----------------------------------------------------------------------
    // compute_batch_end (extended)
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_batch_end_within_range() {
        assert_eq!(compute_batch_end(1, 128, 1000), 128);
    }

    #[test]
    fn test_compute_batch_end_clamped_to_target() {
        assert_eq!(compute_batch_end(990, 128, 1000), 1000);
    }

    #[test]
    fn test_compute_batch_end_single_block() {
        assert_eq!(compute_batch_end(500, 1, 1000), 500);
    }

    #[test]
    fn test_compute_batch_end_at_target() {
        assert_eq!(compute_batch_end(1000, 128, 1000), 1000);
    }

    #[test]
    fn test_compute_batch_end_large_batch() {
        assert_eq!(compute_batch_end(1, 10_000, 500), 500);
    }

    #[test]
    fn test_compute_batch_end_default_batch_size() {
        assert_eq!(compute_batch_end(1, BLOCK_DOWNLOAD_BATCH_SIZE, 800_000), 128);
        assert_eq!(compute_batch_end(129, BLOCK_DOWNLOAD_BATCH_SIZE, 800_000), 256);
    }

    // -----------------------------------------------------------------------
    // should_verify_scripts (pure wrapper, extended)
    // -----------------------------------------------------------------------

    #[test]
    fn test_should_verify_scripts_no_assume_valid() {
        let params = ChainParams::regtest();
        let hash = BlockHash::from_bytes([0xaa; 32]);
        assert!(should_verify_scripts(&params, 100, &hash, None));
        assert!(should_verify_scripts(&params, 0, &hash, None));
    }

    #[test]
    fn test_should_verify_scripts_below_assume_valid() {
        let mut params = ChainParams::mainnet();
        params.assume_valid = Some(BlockHash::from_bytes([0xcc; 32]));
        let some_hash = BlockHash::from_bytes([0xbb; 32]);
        assert!(!should_verify_scripts(&params, 100, &some_hash, Some(500_000)));
    }

    #[test]
    fn test_should_verify_scripts_above_assume_valid() {
        let mut params = ChainParams::mainnet();
        params.assume_valid = Some(BlockHash::from_bytes([0xcc; 32]));
        let some_hash = BlockHash::from_bytes([0xbb; 32]);
        assert!(should_verify_scripts(&params, 500_001, &some_hash, Some(500_000)));
    }

    // -----------------------------------------------------------------------
    // compute_undo_prune_cutoff (extended)
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_undo_prune_cutoff_at_boundary() {
        assert_eq!(compute_undo_prune_cutoff(101, 100), Some(1));
    }

    #[test]
    fn test_compute_undo_prune_cutoff_well_past() {
        assert_eq!(compute_undo_prune_cutoff(1000, 100), Some(900));
    }

    #[test]
    fn test_compute_undo_prune_cutoff_zero_depth() {
        assert_eq!(compute_undo_prune_cutoff(1, 0), Some(1));
        assert_eq!(compute_undo_prune_cutoff(500, 0), Some(500));
    }

    // -----------------------------------------------------------------------
    // should_flush_utxo / should_log_utxo_status (extended)
    // -----------------------------------------------------------------------

    #[test]
    fn test_should_flush_utxo_not_at_boundary() {
        assert!(!should_flush_utxo(1));
        assert!(!should_flush_utxo(499));
        assert!(!should_flush_utxo(501));
    }

    #[test]
    fn test_should_log_utxo_status_at_boundary() {
        assert!(should_log_utxo_status(0));
        assert!(should_log_utxo_status(1000));
    }

    #[test]
    fn test_should_log_utxo_status_not_at_boundary() {
        assert!(!should_log_utxo_status(1));
        assert!(!should_log_utxo_status(250));
        assert!(!should_log_utxo_status(999));
    }

    // -----------------------------------------------------------------------
    // should_download_blocks (extended)
    // -----------------------------------------------------------------------

    #[test]
    fn test_should_download_blocks_peer_ahead() {
        assert!(should_download_blocks(1000, 1));
        assert!(should_download_blocks(1000, 1000));
    }

    #[test]
    fn test_should_download_blocks_peer_behind() {
        assert!(!should_download_blocks(100, 101));
        assert!(!should_download_blocks(0, 1));
    }

    // -----------------------------------------------------------------------
    // validate_policy (extended)
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_policy_core() {
        assert!(validate_policy("core").is_ok());
    }

    #[test]
    fn test_validate_policy_consensus() {
        assert!(validate_policy("consensus").is_ok());
    }

    #[test]
    fn test_validate_policy_all() {
        assert!(validate_policy("all").is_ok());
    }

    #[test]
    fn test_validate_policy_unknown_message() {
        let result = validate_policy("potato");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("potato"));
    }

    #[test]
    fn test_validate_policy_empty() {
        assert!(validate_policy("").is_err());
    }

    #[test]
    fn test_validate_policy_case_sensitive() {
        assert!(validate_policy("Core").is_err());
        assert!(validate_policy("CONSENSUS").is_err());
        assert!(validate_policy("ALL").is_err());
    }

    // -----------------------------------------------------------------------
    // classify_inv_items (extended)
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_inv_items_mixed_with_error_type() {
        let items = vec![
            InvItem { inv_type: InvType::Tx, hash: btc_primitives::hash::Hash256::from_bytes([0x01; 32]) },
            InvItem { inv_type: InvType::WitnessTx, hash: btc_primitives::hash::Hash256::from_bytes([0x02; 32]) },
            InvItem { inv_type: InvType::Block, hash: btc_primitives::hash::Hash256::from_bytes([0x03; 32]) },
            InvItem { inv_type: InvType::WitnessBlock, hash: btc_primitives::hash::Hash256::from_bytes([0x04; 32]) },
            InvItem { inv_type: InvType::Error, hash: btc_primitives::hash::Hash256::from_bytes([0x05; 32]) },
        ];
        let (blocks, txs) = classify_inv_items(&items);
        assert_eq!(blocks, 2);
        assert_eq!(txs, 2);
    }

    #[test]
    fn test_classify_inv_items_only_blocks() {
        let items = vec![
            InvItem { inv_type: InvType::Block, hash: btc_primitives::hash::Hash256::from_bytes([0x01; 32]) },
            InvItem { inv_type: InvType::WitnessBlock, hash: btc_primitives::hash::Hash256::from_bytes([0x02; 32]) },
        ];
        let (blocks, txs) = classify_inv_items(&items);
        assert_eq!(blocks, 2);
        assert_eq!(txs, 0);
    }

    #[test]
    fn test_classify_inv_items_only_txs() {
        let items = vec![
            InvItem { inv_type: InvType::Tx, hash: btc_primitives::hash::Hash256::from_bytes([0x01; 32]) },
            InvItem { inv_type: InvType::WitnessTx, hash: btc_primitives::hash::Hash256::from_bytes([0x02; 32]) },
        ];
        let (blocks, txs) = classify_inv_items(&items);
        assert_eq!(blocks, 0);
        assert_eq!(txs, 2);
    }

    #[test]
    fn test_classify_inv_items_only_error() {
        let items = vec![
            InvItem { inv_type: InvType::Error, hash: btc_primitives::hash::Hash256::from_bytes([0x01; 32]) },
        ];
        let (blocks, txs) = classify_inv_items(&items);
        assert_eq!(blocks, 0);
        assert_eq!(txs, 0);
    }

    // -----------------------------------------------------------------------
    // determine_output_format (extended)
    // -----------------------------------------------------------------------

    #[test]
    fn test_determine_output_format_json_flag_priority() {
        let f = determine_output_format(true, None);
        assert_eq!(f, crate::output::OutputFormat::Json);
    }

    #[test]
    fn test_determine_output_format_json_flag_overrides_text_opt() {
        let f = determine_output_format(true, Some("text"));
        assert_eq!(f, crate::output::OutputFormat::Json);
    }

    #[test]
    fn test_determine_output_format_explicit_json_opt() {
        let f = determine_output_format(false, Some("json"));
        assert_eq!(f, crate::output::OutputFormat::Json);
    }

    #[test]
    fn test_determine_output_format_explicit_text_opt() {
        let f = determine_output_format(false, Some("text"));
        assert_eq!(f, crate::output::OutputFormat::Text);
    }

    #[test]
    fn test_determine_output_format_auto_detection() {
        let f = determine_output_format(false, None);
        assert_eq!(f, crate::output::OutputFormat::Json); // test env = not TTY
    }

    #[test]
    fn test_determine_output_format_unknown_falls_to_auto() {
        let f = determine_output_format(false, Some("xml"));
        assert_eq!(f, crate::output::OutputFormat::auto());
    }

    // -----------------------------------------------------------------------
    // next_state_after_headers
    // -----------------------------------------------------------------------

    #[test]
    fn test_next_state_after_headers_incomplete() {
        let state = next_state_after_headers(2000, 50_000);
        match state {
            SyncState::DownloadingHeaders { progress, target } => {
                assert_eq!(progress, 50_000);
                assert_eq!(target, 50_000);
            }
            _ => panic!("expected DownloadingHeaders"),
        }
    }

    #[test]
    fn test_next_state_after_headers_complete() {
        let state = next_state_after_headers(500, 50_000);
        match state {
            SyncState::DownloadingHeaders { progress, target } => {
                assert_eq!(progress, 50_000);
                assert_eq!(target, 50_000);
            }
            _ => panic!("expected DownloadingHeaders"),
        }
    }

    // -----------------------------------------------------------------------
    // next_state_downloading_blocks
    // -----------------------------------------------------------------------

    #[test]
    fn test_next_state_downloading_blocks() {
        let state = next_state_downloading_blocks(100, 1000);
        assert_eq!(state, SyncState::DownloadingBlocks { progress: 100, target: 1000 });
    }

    #[test]
    fn test_next_state_downloading_blocks_complete() {
        let state = next_state_downloading_blocks(1000, 1000);
        assert_eq!(state, SyncState::DownloadingBlocks { progress: 1000, target: 1000 });
    }

    // -----------------------------------------------------------------------
    // estimate_sync_eta
    // -----------------------------------------------------------------------

    #[test]
    fn test_estimate_sync_eta_midway() {
        // 50% done in 100 seconds -> 100 seconds remaining
        let eta = estimate_sync_eta(0.5, 100.0);
        assert!(eta.is_some());
        assert!((eta.unwrap() - 100.0).abs() < 1e-9);
    }

    #[test]
    fn test_estimate_sync_eta_quarter() {
        // 25% done in 100 seconds -> 300 seconds remaining
        let eta = estimate_sync_eta(0.25, 100.0);
        assert!(eta.is_some());
        assert!((eta.unwrap() - 300.0).abs() < 1e-9);
    }

    #[test]
    fn test_estimate_sync_eta_zero_progress() {
        assert!(estimate_sync_eta(0.0, 100.0).is_none());
    }

    #[test]
    fn test_estimate_sync_eta_complete() {
        assert!(estimate_sync_eta(1.0, 100.0).is_none());
    }

    #[test]
    fn test_estimate_sync_eta_zero_elapsed() {
        assert!(estimate_sync_eta(0.5, 0.0).is_none());
    }

    #[test]
    fn test_estimate_sync_eta_negative_progress() {
        assert!(estimate_sync_eta(-0.1, 100.0).is_none());
    }

    // -----------------------------------------------------------------------
    // compute_sync_speed
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_sync_speed_normal() {
        let speed = compute_sync_speed(1000, 10.0);
        assert!(speed.is_some());
        assert!((speed.unwrap() - 100.0).abs() < 1e-9);
    }

    #[test]
    fn test_compute_sync_speed_zero_elapsed() {
        assert!(compute_sync_speed(1000, 0.0).is_none());
    }

    #[test]
    fn test_compute_sync_speed_zero_blocks() {
        let speed = compute_sync_speed(0, 10.0);
        assert!(speed.is_some());
        assert!((speed.unwrap() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_compute_sync_speed_negative_elapsed() {
        assert!(compute_sync_speed(100, -1.0).is_none());
    }

    // -----------------------------------------------------------------------
    // lookup_pending_block
    // -----------------------------------------------------------------------

    #[test]
    fn test_lookup_pending_block_found() {
        let mut pending = HashMap::new();
        let hash = BlockHash::from_bytes([0x01; 32]);
        pending.insert(hash, 100);
        assert_eq!(lookup_pending_block(&pending, &hash), Some(100));
    }

    #[test]
    fn test_lookup_pending_block_not_found() {
        let pending: HashMap<BlockHash, u64> = HashMap::new();
        let hash = BlockHash::from_bytes([0x01; 32]);
        assert_eq!(lookup_pending_block(&pending, &hash), None);
    }

    #[test]
    fn test_lookup_pending_block_wrong_hash() {
        let mut pending = HashMap::new();
        let hash1 = BlockHash::from_bytes([0x01; 32]);
        let hash2 = BlockHash::from_bytes([0x02; 32]);
        pending.insert(hash1, 100);
        assert_eq!(lookup_pending_block(&pending, &hash2), None);
    }

    // -----------------------------------------------------------------------
    // detect_potential_reorg
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_potential_reorg_same_tip() {
        let hash = BlockHash::from_bytes([0x01; 32]);
        let first_prev = BlockHash::from_bytes([0x02; 32]);
        assert!(!detect_potential_reorg(&hash, &hash, &first_prev));
    }

    #[test]
    fn test_detect_potential_reorg_linear_extension() {
        let old = BlockHash::from_bytes([0x01; 32]);
        let new = BlockHash::from_bytes([0x02; 32]);
        // First new header's prev == old tip: linear extension
        assert!(!detect_potential_reorg(&old, &new, &old));
    }

    #[test]
    fn test_detect_potential_reorg_actual_reorg() {
        let old = BlockHash::from_bytes([0x01; 32]);
        let new = BlockHash::from_bytes([0x02; 32]);
        let first_prev = BlockHash::from_bytes([0x03; 32]);
        // First new header's prev != old tip: potential reorg
        assert!(detect_potential_reorg(&old, &new, &first_prev));
    }

    // -----------------------------------------------------------------------
    // Batch iteration simulation
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_iteration_covers_full_range() {
        let from = 1u64;
        let to = 500u64;
        let batch_size = BLOCK_DOWNLOAD_BATCH_SIZE;
        let mut height = from;
        let mut batch_count = 0;
        let mut last_batch_end = 0;

        while height <= to {
            let batch_end = compute_batch_end(height, batch_size, to);
            assert!(batch_end >= height);
            assert!(batch_end <= to);
            last_batch_end = batch_end;
            height = batch_end + 1;
            batch_count += 1;
        }

        assert_eq!(last_batch_end, to);
        assert_eq!(batch_count, 4);
    }

    #[test]
    fn test_batch_iteration_single_block() {
        let batch_end = compute_batch_end(100, BLOCK_DOWNLOAD_BATCH_SIZE, 100);
        assert_eq!(batch_end, 100);
    }

    // -----------------------------------------------------------------------
    // Full sync lifecycle simulation
    // -----------------------------------------------------------------------

    #[test]
    fn test_sync_lifecycle_pure_simulation() {
        let chain_height = 0u64;
        let checkpoint_height: Option<u64> = None;
        let peer_tip = 1000u64;

        let block_start = compute_block_start(chain_height, checkpoint_height);
        assert_eq!(block_start, 1);
        assert!(should_download_blocks(peer_tip, block_start));

        let mut height = block_start;
        let mut blocks_downloaded = 0u64;
        while height <= peer_tip {
            let batch_end = compute_batch_end(height, BLOCK_DOWNLOAD_BATCH_SIZE, peer_tip);
            blocks_downloaded += batch_end - height + 1;
            height = batch_end + 1;
        }
        assert_eq!(blocks_downloaded, 1000);
        assert_eq!(compute_progress(&SyncState::Synced), 1.0);
    }

    #[test]
    fn test_sync_lifecycle_with_checkpoint_resume() {
        let chain_height = 0u64;
        let checkpoint_height = Some(500u64);
        let peer_tip = 1000u64;

        let block_start = compute_block_start(chain_height, checkpoint_height);
        assert_eq!(block_start, 501);
        assert!(should_download_blocks(peer_tip, block_start));
        assert_eq!(peer_tip - block_start + 1, 500);
    }

    #[test]
    fn test_sync_lifecycle_already_synced() {
        let chain_height = 1000u64;
        let peer_tip = 1000u64;

        let block_start = compute_block_start(chain_height, None);
        assert_eq!(block_start, 1001);
        assert!(!should_download_blocks(peer_tip, block_start));
    }

    // -----------------------------------------------------------------------
    // SyncState display (additional coverage)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sync_state_display_all_variants_formatted() {
        assert_eq!(format!("{}", SyncState::Idle), "idle");
        assert_eq!(format!("{}", SyncState::ConnectingPeers), "connecting_peers");
        assert_eq!(format!("{}", SyncState::Synced), "synced");
        assert_eq!(
            format!("{}", SyncState::DownloadingHeaders { progress: 5, target: 10 }),
            "downloading_headers (5/10)"
        );
        assert_eq!(
            format!("{}", SyncState::DownloadingBlocks { progress: 3, target: 7 }),
            "downloading_blocks (3/7)"
        );
    }

    #[test]
    fn test_sync_state_is_idle_or_synced_comprehensive() {
        assert!(SyncState::Idle.is_idle_or_synced());
        assert!(SyncState::Synced.is_idle_or_synced());
        assert!(!SyncState::ConnectingPeers.is_idle_or_synced());
        assert!(!SyncState::DownloadingHeaders { progress: 0, target: 0 }.is_idle_or_synced());
        assert!(!SyncState::DownloadingBlocks { progress: 0, target: 0 }.is_idle_or_synced());
    }
}
