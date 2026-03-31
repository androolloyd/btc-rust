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
use btc_storage::qmdb_backend::QmdbDatabase;
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
) -> Option<PersistentUtxoSet<QmdbDatabase>> {
    let db = QmdbDatabase::new(db_path).ok()?;
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
    persistent_utxo: Option<PersistentUtxoSet<QmdbDatabase>>,
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
        }
    }

    /// Create a `SyncManager` with a data directory for checkpoint and UTXO
    /// persistence.  If the redb database at `{datadir}/utxo.qmdb` can be
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
        let checkpoint = load_checkpoint(&datadir);
        let resume_height = checkpoint.as_ref().map(|cp| {
            info!(height = cp.height, hash = %cp.hash, "resuming from checkpoint");
            cp.height
        }).unwrap_or(0);

        // Open persistent UTXO database
        let db_path = datadir.join("utxo.qmdb");
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

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Return the current sync state.
    pub fn state(&self) -> &SyncState {
        &self.sync_state
    }

    /// Return the sync progress as a fraction in `[0.0, 1.0]`.
    pub fn progress(&self) -> f64 {
        match &self.sync_state {
            SyncState::Idle => 0.0,
            SyncState::ConnectingPeers => 0.0,
            SyncState::DownloadingHeaders { progress, target } => {
                if *target == 0 {
                    0.0
                } else {
                    // Header sync is the first 10% of overall progress.
                    (*progress as f64 / *target as f64) * 0.1
                }
            }
            SyncState::DownloadingBlocks { progress, target } => {
                if *target == 0 {
                    0.1
                } else {
                    // Block sync is the remaining 90%.
                    0.1 + (*progress as f64 / *target as f64) * 0.9
                }
            }
            SyncState::Synced => 1.0,
        }
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

        // Save checkpoint after header sync completes.
        if let Some(ref datadir) = self.datadir {
            let cs = self.chain_state.read().await;
            let best = cs.best_header();
            let cp = Checkpoint::new(cs.best_height(), best.header.block_hash());
            if let Err(e) = save_checkpoint(datadir, &cp) {
                warn!(error = %e, "failed to save checkpoint after header sync");
            }
        }

        // Phase 5 -- block sync.
        // Use checkpoint height if available — skip blocks we already validated.
        let block_start = {
            let cp_height = self.datadir.as_ref()
                .and_then(|d| load_checkpoint(d))
                .map(|cp| cp.height)
                .unwrap_or(0);
            // Start from whichever is higher: chain_state height or checkpoint
            std::cmp::max(best_height, cp_height) + 1
        };
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
                            let utxo_set = self.utxo_set.read().await;
                            match connect_block(&block, block_height, &*utxo_set) {
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
                            if let Err(errors) = validator.validate_block_scripts(
                                &block,
                                &*utxo_set,
                                block_height,
                                &self.chain_params,
                            ) {
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
        let db_path = dir.path().join("utxo.qmdb");

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
}
