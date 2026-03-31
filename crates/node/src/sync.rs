use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use btc_consensus::chain::ChainState;
use btc_consensus::utxo::{connect_block, InMemoryUtxoSet};
use btc_consensus::validation::{BlockValidator, ChainParams};
use btc_consensus::{ParallelValidator, ParallelConfig};
use btc_network::connection::{Connection, ConnectionError};
use btc_network::discovery::PeerManager;
use btc_network::message::{
    GetHeadersMessage, InvItem, InvType, NetworkMessage,
};
use btc_network::protocol::ProtocolVersion;
use btc_primitives::hash::BlockHash;
use btc_primitives::network::Network;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of headers returned in a single `headers` message.
const MAX_HEADERS_PER_MESSAGE: usize = 2000;

/// Number of blocks to request in a single `getdata` batch.
const BLOCK_DOWNLOAD_BATCH_SIZE: usize = 16;

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
}

impl SyncManager {
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
        }
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

        // Phase 5 -- block sync.
        if peer_tip > best_height {
            self.sync_blocks(&mut conn, best_height + 1, peer_tip).await?;
        }

        // Phase 6 -- synced.
        self.sync_state = SyncState::Synced;
        let final_height = {
            let cs = self.chain_state.read().await;
            cs.best_height()
        };
        info!(height = final_height, "initial block download complete");

        Ok(())
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
            let (locators, our_height) = {
                let cs = self.chain_state.read().await;
                (cs.get_locator_hashes(), cs.best_height())
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

            let new_height = {
                let cs = self.chain_state.read().await;
                cs.best_height()
            };

            info!(
                received = count,
                height = new_height,
                "headers batch accepted"
            );

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

            // Collect the block hashes we need.  Use WitnessBlock (0x40000002)
            // so that the peer sends full witness data (required for segwit
            // networks like signet).
            let inv_items = {
                let cs = self.chain_state.read().await;
                let mut items = Vec::new();
                for h in height..=batch_end {
                    if let Some(entry) = cs.get_header_by_height(h) {
                        items.push(InvItem {
                            inv_type: InvType::WitnessBlock,
                            hash: btc_primitives::hash::Hash256::from_bytes(
                                *entry.header.block_hash().as_bytes(),
                            ),
                        });
                    }
                }
                items
            };

            if inv_items.is_empty() {
                warn!(height, "no header found at height, skipping");
                height = batch_end + 1;
                continue;
            }

            let expected_count = inv_items.len();

            // Send getdata.
            if let Err(e) = peer.send_message(NetworkMessage::GetData(inv_items)).await {
                warn!(error = %e, height, "failed to send getdata, aborting block sync");
                return Err(SyncError::Connection(e));
            }

            // Receive blocks.  Peers may interleave protocol messages (ping,
            // sendcmpct, inv, getheaders, etc.) between blocks — skip those
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
                        downloaded += 1;
                        let block_hash = block.block_hash();
                        let block_height = height + received as u64 - 1;
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
                        // Step 3: Optionally verify scripts (skip when
                        // below assume-valid to speed up IBD).
                        // Must happen BEFORE applying the UTXO update so
                        // that the spent outputs are still available for
                        // script verification lookups.
                        // -------------------------------------------------
                        if self.chain_params.should_verify_scripts(
                            block_height,
                            &block_hash,
                            None,
                        ) {
                            let utxo_set = self.utxo_set.read().await;
                            let validator = ParallelValidator::new(ParallelConfig::default());
                            if let Err(errors) = validator.validate_block_scripts(
                                &block,
                                &*utxo_set,
                                block_height,
                                &self.chain_params,
                            ) {
                                let first_err = &errors[0];
                                warn!(
                                    height = block_height,
                                    hash = %block_hash,
                                    failures = errors.len(),
                                    first_tx = first_err.0,
                                    first_input = first_err.1,
                                    first_error = %first_err.2,
                                    "block failed script validation"
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
}
