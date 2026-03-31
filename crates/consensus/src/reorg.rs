use std::collections::HashMap;

use btc_primitives::block::Block;
use btc_primitives::hash::BlockHash;
use thiserror::Error;
use tracing::{info, warn};

use crate::chain::ChainState;
use crate::utxo::{
    connect_block, disconnect_block, InMemoryUtxoSet, UtxoSetUpdate,
};
use crate::validation::BlockValidator;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ReorgError {
    #[error("fork point not found between old tip {old_tip} and new tip {new_tip}")]
    ForkPointNotFound {
        old_tip: BlockHash,
        new_tip: BlockHash,
    },

    #[error("reorg depth {depth} exceeds maximum undo depth {max}")]
    TooDeep { depth: u64, max: u64 },

    #[error("missing undo data for height {0}")]
    MissingUndoData(u64),

    #[error("block validation failed: {0}")]
    ValidationFailed(String),

    #[error("UTXO error while connecting block: {0}")]
    UtxoError(#[from] crate::utxo::UtxoError),

    #[error("old tip {0} not found in chain state")]
    OldTipNotFound(BlockHash),

    #[error("new tip {0} not found in chain state")]
    NewTipNotFound(BlockHash),
}

// ---------------------------------------------------------------------------
// ReorgResult
// ---------------------------------------------------------------------------

/// Summary of a completed chain reorganisation.
#[derive(Debug, Clone)]
pub struct ReorgResult {
    /// The common ancestor of the old and new chains.
    pub fork_point: BlockHash,
    /// Height of the fork point.
    pub fork_height: u64,
    /// Block hashes that were disconnected (old chain, tip-first order).
    pub disconnected: Vec<BlockHash>,
    /// Block hashes that were connected (new chain, base-first order).
    pub connected: Vec<BlockHash>,
    /// Depth of the reorganisation (number of blocks disconnected).
    pub depth: u64,
}

// ---------------------------------------------------------------------------
// ReorgManager
// ---------------------------------------------------------------------------

/// Manages undo data needed to roll back UTXO changes during chain
/// reorganisations.
pub struct ReorgManager {
    /// Undo data for each block height (for rolling back UTXO changes).
    undo_data: HashMap<u64, UtxoSetUpdate>,
    /// Maximum depth of stored undo data (default: 100 blocks for reorg
    /// protection).
    max_undo_depth: u64,
}

impl ReorgManager {
    /// Create a new `ReorgManager` with the given maximum undo depth.
    pub fn new(max_undo_depth: u64) -> Self {
        ReorgManager {
            undo_data: HashMap::new(),
            max_undo_depth,
        }
    }

    /// Store undo data for a block at the given height.
    pub fn store_undo(&mut self, height: u64, update: UtxoSetUpdate) {
        self.undo_data.insert(height, update);
    }

    /// Retrieve undo data for a block at the given height.
    pub fn get_undo(&self, height: u64) -> Option<&UtxoSetUpdate> {
        self.undo_data.get(&height)
    }

    /// Remove undo data for all heights strictly below `below_height`.
    pub fn prune_undo(&mut self, below_height: u64) {
        self.undo_data.retain(|&h, _| h >= below_height);
    }

    /// Return the maximum undo depth configured for this manager.
    pub fn max_undo_depth(&self) -> u64 {
        self.max_undo_depth
    }
}

// ---------------------------------------------------------------------------
// find_fork_point
// ---------------------------------------------------------------------------

/// Walk back from both tips until finding a common ancestor.
///
/// Returns `Some((fork_hash, fork_height))` if a common ancestor is found,
/// or `None` if the two chains share no common history (should not happen
/// on a well-formed chain).
pub fn find_fork_point(
    chain: &ChainState,
    old_tip: &BlockHash,
    new_tip: &BlockHash,
) -> Option<(BlockHash, u64)> {
    // Trivial case: same tip.
    if old_tip == new_tip {
        let entry = chain.get_header(old_tip)?;
        return Some((*old_tip, entry.height));
    }

    let mut old_entry = chain.get_header(old_tip)?.clone();
    let mut new_entry = chain.get_header(new_tip)?.clone();

    // Bring both cursors to the same height by walking the taller one back.
    while old_entry.height > new_entry.height {
        let prev = old_entry.header.prev_blockhash;
        old_entry = chain.get_header(&prev)?.clone();
    }
    while new_entry.height > old_entry.height {
        let prev = new_entry.header.prev_blockhash;
        new_entry = chain.get_header(&prev)?.clone();
    }

    // Now walk both back in lockstep until they meet.
    loop {
        let old_hash = old_entry.header.block_hash();
        let new_hash = new_entry.header.block_hash();

        if old_hash == new_hash {
            return Some((old_hash, old_entry.height));
        }

        // At genesis with no match — shouldn't happen on a valid chain.
        if old_entry.header.prev_blockhash == BlockHash::ZERO
            || new_entry.header.prev_blockhash == BlockHash::ZERO
        {
            return None;
        }

        old_entry = chain.get_header(&old_entry.header.prev_blockhash)?.clone();
        new_entry = chain.get_header(&new_entry.header.prev_blockhash)?.clone();
    }
}

// ---------------------------------------------------------------------------
// execute_reorg
// ---------------------------------------------------------------------------

/// Execute a chain reorganisation.
///
/// 1. Finds the fork point between `old_tip` and `new_tip`.
/// 2. Validates all new blocks before making any changes.
/// 3. Disconnects blocks from `old_tip` back to the fork point using stored
///    undo data.
/// 4. Connects blocks from the fork point to `new_tip`.
///
/// Returns a `ReorgResult` summarising the reorganisation.
pub fn execute_reorg(
    chain: &mut ChainState,
    reorg_mgr: &ReorgManager,
    utxo_set: &mut InMemoryUtxoSet,
    old_tip: &BlockHash,
    new_tip: &BlockHash,
    new_blocks: &[Block],
) -> Result<ReorgResult, ReorgError> {
    // --- Find fork point ---
    let (fork_hash, fork_height) =
        find_fork_point(chain, old_tip, new_tip).ok_or(ReorgError::ForkPointNotFound {
            old_tip: *old_tip,
            new_tip: *new_tip,
        })?;

    // --- Determine which blocks to disconnect ---
    let old_entry = chain
        .get_header(old_tip)
        .ok_or(ReorgError::OldTipNotFound(*old_tip))?;
    let old_height = old_entry.height;
    let reorg_depth = old_height - fork_height;

    info!(
        fork_point = %fork_hash,
        fork_height,
        reorg_depth,
        "chain reorganisation detected"
    );

    // --- Safety: reject reorgs deeper than our undo data ---
    if reorg_depth > reorg_mgr.max_undo_depth {
        warn!(
            depth = reorg_depth,
            max = reorg_mgr.max_undo_depth,
            "reorg too deep, rejecting"
        );
        return Err(ReorgError::TooDeep {
            depth: reorg_depth,
            max: reorg_mgr.max_undo_depth,
        });
    }

    // --- Validate all new blocks before disconnecting anything ---
    for block in new_blocks {
        BlockValidator::validate_block(block).map_err(|e| {
            ReorgError::ValidationFailed(e.to_string())
        })?;
    }

    // --- Collect block hashes to disconnect (tip → fork_point, exclusive) ---
    let mut blocks_to_disconnect = Vec::new();
    {
        let mut cursor = chain.get_header(old_tip).unwrap().clone();
        while cursor.header.block_hash() != fork_hash {
            blocks_to_disconnect.push((cursor.header.block_hash(), cursor.height));
            cursor = chain
                .get_header(&cursor.header.prev_blockhash)
                .unwrap()
                .clone();
        }
    }

    // --- Disconnect blocks (from tip backwards) ---
    let disconnected: Vec<BlockHash> =
        blocks_to_disconnect.iter().map(|(h, _)| *h).collect();

    for &(_hash, height) in &blocks_to_disconnect {
        let undo = reorg_mgr
            .get_undo(height)
            .ok_or(ReorgError::MissingUndoData(height))?;
        disconnect_block(utxo_set, undo);
    }

    info!(
        count = disconnected.len(),
        "disconnected blocks from old chain"
    );

    // --- Connect new blocks ---
    let mut connected = Vec::new();
    let mut current_height = fork_height;

    for block in new_blocks {
        current_height += 1;
        let update = connect_block(block, current_height, utxo_set)?;
        utxo_set.apply_update(&update);
        connected.push(block.block_hash());
    }

    info!(
        count = connected.len(),
        "connected blocks on new chain"
    );

    // --- Accept headers of new blocks into chain state ---
    for block in new_blocks {
        // Headers may already be accepted (if the chain state saw them
        // before we had the full blocks). Ignore duplicate-header errors.
        let _ = chain.accept_header(block.header);
    }

    Ok(ReorgResult {
        fork_point: fork_hash,
        fork_height,
        disconnected,
        connected,
        depth: reorg_depth,
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::amount::Amount;
    use btc_primitives::block::{Block, BlockHeader};
    use btc_primitives::compact::CompactTarget;
    use btc_primitives::hash::{BlockHash, TxHash};
    use btc_primitives::script::ScriptBuf;
    use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

    use crate::chain::{ChainState, HeaderEntry};
    use crate::utxo::{connect_block, InMemoryUtxoSet, UtxoEntry, UtxoSet, UtxoSetUpdate};
    use crate::validation::ChainParams;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build a regtest `ChainState`.
    fn regtest_chain() -> ChainState {
        ChainState::new(ChainParams::regtest())
    }

    /// Build a coinbase transaction with unique script_sig bytes (to make
    /// the txid unique so blocks get unique merkle roots / hashes).
    fn make_unique_coinbase_tx(value: Amount, nonce_bytes: &[u8]) -> Transaction {
        let mut sig = vec![0x04];
        sig.extend_from_slice(nonce_bytes);
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(sig),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    /// Create a block with valid merkle root from transactions.
    fn make_block_with_merkle(
        prev_hash: BlockHash,
        time: u32,
        bits: CompactTarget,
        transactions: Vec<Transaction>,
    ) -> Block {
        let txids: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.txid().to_bytes()).collect();
        let merkle_root = TxHash::from_bytes(btc_primitives::block::merkle_root(&txids));

        let mut header = BlockHeader {
            version: 1,
            prev_blockhash: prev_hash,
            merkle_root,
            time,
            bits,
            nonce: 0,
        };
        while !header.check_proof_of_work() {
            header.nonce += 1;
            assert!(header.nonce < 100_000_000, "could not mine block");
        }
        Block {
            header,
            transactions,
        }
    }

    /// Build a linear chain of `count` blocks on top of genesis, returning
    /// the headers that were accepted, the blocks themselves, and the
    /// `UtxoSetUpdate` for each block keyed by height.
    fn build_chain(
        chain: &mut ChainState,
        utxo_set: &mut InMemoryUtxoSet,
        count: usize,
    ) -> (Vec<BlockHash>, Vec<Block>, HashMap<u64, UtxoSetUpdate>) {
        let bits = ChainParams::regtest().pow_limit;
        let subsidy = crate::validation::block_subsidy(0);

        let mut hashes = Vec::new();
        let mut blocks = Vec::new();
        let mut undos = HashMap::new();

        for i in 0..count {
            let tip = chain.best_header().clone();
            let nonce_bytes = (i as u32).to_le_bytes();
            let cb = make_unique_coinbase_tx(subsidy, &nonce_bytes);
            let block = make_block_with_merkle(
                tip.header.block_hash(),
                tip.header.time + 600,
                bits,
                vec![cb],
            );
            let hash = chain.accept_header(block.header).unwrap();
            let height = chain.get_header(&hash).unwrap().height;
            let update = connect_block(&block, height, utxo_set).unwrap();
            utxo_set.apply_update(&update);
            undos.insert(height, update);
            hashes.push(hash);
            blocks.push(block);
        }

        (hashes, blocks, undos)
    }

    /// Build a fork starting from a specific entry in the chain. Returns
    /// the list of block hashes, the blocks, and the updates.
    fn build_fork(
        chain: &mut ChainState,
        fork_entry: &HeaderEntry,
        count: usize,
        fork_id: u8,
    ) -> (Vec<BlockHash>, Vec<Block>) {
        let bits = ChainParams::regtest().pow_limit;
        let subsidy = crate::validation::block_subsidy(0);

        let mut hashes = Vec::new();
        let mut blocks = Vec::new();
        let mut prev_entry = fork_entry.clone();

        for i in 0..count {
            // Use fork_id to create distinct coinbase txids on each fork.
            let mut nonce_bytes = vec![fork_id];
            nonce_bytes.extend_from_slice(&(i as u32).to_le_bytes());
            let cb = make_unique_coinbase_tx(subsidy, &nonce_bytes);
            let block = make_block_with_merkle(
                prev_entry.header.block_hash(),
                prev_entry.header.time + 600,
                bits,
                vec![cb],
            );
            let hash = chain.accept_header(block.header).unwrap();
            let entry = chain.get_header(&hash).unwrap().clone();
            hashes.push(hash);
            blocks.push(block);
            prev_entry = entry;
        }

        (hashes, blocks)
    }

    // -----------------------------------------------------------------------
    // Test: find_fork_point with a simple fork
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_fork_point_simple() {
        let mut chain = regtest_chain();
        let mut utxo_set = InMemoryUtxoSet::new();

        // Build a main chain: genesis -> B1 -> B2 -> B3
        let (main_hashes, _main_blocks, _undos) = build_chain(&mut chain, &mut utxo_set, 3);

        // Fork from B1 (height 1): B1 -> F2 -> F3 -> F4
        let fork_entry = chain.get_header(&main_hashes[0]).unwrap().clone();
        let (fork_hashes, _fork_blocks) = build_fork(&mut chain, &fork_entry, 3, 0xAA);

        // Fork point between B3 (main tip) and F4 (fork tip) should be B1.
        let (fork_hash, fork_height) =
            find_fork_point(&chain, &main_hashes[2], fork_hashes.last().unwrap())
                .expect("should find fork point");

        assert_eq!(fork_hash, main_hashes[0], "fork point should be B1");
        assert_eq!(fork_height, 1);
    }

    #[test]
    fn test_find_fork_point_same_tip() {
        let mut chain = regtest_chain();
        let mut utxo_set = InMemoryUtxoSet::new();

        let (hashes, _, _) = build_chain(&mut chain, &mut utxo_set, 3);
        let tip = hashes.last().unwrap();

        let (fork_hash, fork_height) =
            find_fork_point(&chain, tip, tip).expect("same tip should work");

        assert_eq!(fork_hash, *tip);
        assert_eq!(fork_height, 3);
    }

    #[test]
    fn test_find_fork_point_at_genesis() {
        let mut chain = regtest_chain();
        let mut utxo_set = InMemoryUtxoSet::new();

        // Build main chain: genesis -> A1
        let (main_hashes, _, _) = build_chain(&mut chain, &mut utxo_set, 1);

        // Fork from genesis: genesis -> F1
        let genesis_entry = chain.get_header_by_height(0).unwrap().clone();
        let (fork_hashes, _) = build_fork(&mut chain, &genesis_entry, 1, 0xBB);

        let (fork_hash, fork_height) =
            find_fork_point(&chain, &main_hashes[0], &fork_hashes[0])
                .expect("should find genesis as fork point");

        assert_eq!(fork_height, 0, "fork should be at genesis");
        assert_eq!(fork_hash, ChainParams::regtest().genesis_hash);
    }

    // -----------------------------------------------------------------------
    // Test: store/retrieve/prune undo data
    // -----------------------------------------------------------------------

    #[test]
    fn test_undo_data_store_retrieve() {
        let mut mgr = ReorgManager::new(100);

        let update = UtxoSetUpdate {
            spent: vec![],
            created: vec![(
                OutPoint::new(TxHash::from_bytes([0x01; 32]), 0),
                UtxoEntry {
                    txout: TxOut {
                        value: Amount::from_sat(1000),
                        script_pubkey: ScriptBuf::from_bytes(vec![0x00]),
                    },
                    height: 5,
                    is_coinbase: false,
                },
            )],
        };

        mgr.store_undo(5, update);
        assert!(mgr.get_undo(5).is_some());
        assert!(mgr.get_undo(6).is_none());
    }

    #[test]
    fn test_undo_data_prune() {
        let mut mgr = ReorgManager::new(100);

        // Store undo data at heights 1..=10.
        for h in 1..=10u64 {
            mgr.store_undo(
                h,
                UtxoSetUpdate {
                    spent: vec![],
                    created: vec![],
                },
            );
        }

        // Prune below height 6.
        mgr.prune_undo(6);

        for h in 1..=5u64 {
            assert!(mgr.get_undo(h).is_none(), "height {h} should be pruned");
        }
        for h in 6..=10u64 {
            assert!(mgr.get_undo(h).is_some(), "height {h} should remain");
        }
    }

    // -----------------------------------------------------------------------
    // Test: shallow reorg (1-2 blocks)
    // -----------------------------------------------------------------------

    #[test]
    fn test_shallow_reorg() {
        let mut chain = regtest_chain();
        let mut utxo_set = InMemoryUtxoSet::new();
        let mut reorg_mgr = ReorgManager::new(100);

        // Build main chain: genesis -> B1 -> B2
        let (main_hashes, _main_blocks, undos) =
            build_chain(&mut chain, &mut utxo_set, 2);

        // Store undo data from the main chain.
        for (h, u) in &undos {
            reorg_mgr.store_undo(*h, u.clone());
        }

        let old_tip = *main_hashes.last().unwrap();

        // Create a fork from B1: B1 -> F2 -> F3
        // (longer than old chain so it has more work)
        let fork_entry = chain.get_header(&main_hashes[0]).unwrap().clone();
        let (fork_hashes, fork_blocks) = build_fork(&mut chain, &fork_entry, 2, 0xCC);

        let new_tip = *fork_hashes.last().unwrap();

        let result = execute_reorg(
            &mut chain,
            &reorg_mgr,
            &mut utxo_set,
            &old_tip,
            &new_tip,
            &fork_blocks,
        )
        .expect("shallow reorg should succeed");

        assert_eq!(result.fork_point, main_hashes[0], "fork at B1");
        assert_eq!(result.fork_height, 1);
        assert_eq!(result.disconnected.len(), 1, "should disconnect B2");
        assert_eq!(result.connected.len(), 2, "should connect F2, F3");
        assert_eq!(result.depth, 1);
        assert_eq!(result.disconnected[0], main_hashes[1]);
    }

    // -----------------------------------------------------------------------
    // Test: deeper reorg (5+ blocks)
    // -----------------------------------------------------------------------

    #[test]
    fn test_deeper_reorg() {
        let mut chain = regtest_chain();
        let mut utxo_set = InMemoryUtxoSet::new();
        let mut reorg_mgr = ReorgManager::new(100);

        // Build main chain: genesis -> B1 -> B2 -> ... -> B8
        let (main_hashes, _main_blocks, undos) =
            build_chain(&mut chain, &mut utxo_set, 8);

        for (h, u) in &undos {
            reorg_mgr.store_undo(*h, u.clone());
        }

        let old_tip = *main_hashes.last().unwrap();

        // Fork from B2 (height 2), building 7 blocks: F3..F9
        let fork_entry = chain.get_header(&main_hashes[1]).unwrap().clone();
        let (fork_hashes, fork_blocks) = build_fork(&mut chain, &fork_entry, 7, 0xDD);

        let new_tip = *fork_hashes.last().unwrap();

        let result = execute_reorg(
            &mut chain,
            &reorg_mgr,
            &mut utxo_set,
            &old_tip,
            &new_tip,
            &fork_blocks,
        )
        .expect("deeper reorg should succeed");

        assert_eq!(result.fork_point, main_hashes[1], "fork at B2");
        assert_eq!(result.fork_height, 2);
        // Disconnected B3..B8 = 6 blocks
        assert_eq!(result.disconnected.len(), 6);
        // Connected F3..F9 = 7 blocks
        assert_eq!(result.connected.len(), 7);
        assert_eq!(result.depth, 6);
    }

    // -----------------------------------------------------------------------
    // Test: reorg rejected when too deep
    // -----------------------------------------------------------------------

    #[test]
    fn test_reorg_rejected_too_deep() {
        let mut chain = regtest_chain();
        let mut utxo_set = InMemoryUtxoSet::new();
        let reorg_mgr = ReorgManager::new(3); // only allow 3 blocks deep

        // Build main chain: genesis -> B1 -> ... -> B5
        let (main_hashes, _main_blocks, _undos) =
            build_chain(&mut chain, &mut utxo_set, 5);

        let old_tip = *main_hashes.last().unwrap();

        // Fork from genesis (height 0), depth = 5 which exceeds max of 3.
        let genesis_entry = chain.get_header_by_height(0).unwrap().clone();
        let (fork_hashes, fork_blocks) = build_fork(&mut chain, &genesis_entry, 6, 0xEE);
        let new_tip = *fork_hashes.last().unwrap();

        let result = execute_reorg(
            &mut chain,
            &reorg_mgr,
            &mut utxo_set,
            &old_tip,
            &new_tip,
            &fork_blocks,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            ReorgError::TooDeep { depth, max } => {
                assert_eq!(depth, 5);
                assert_eq!(max, 3);
            }
            other => panic!("expected TooDeep, got: {other}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test: UTXO set correctly updated after reorg
    // -----------------------------------------------------------------------

    #[test]
    fn test_utxo_set_updated_after_reorg() {
        let mut chain = regtest_chain();
        let mut utxo_set = InMemoryUtxoSet::new();
        let mut reorg_mgr = ReorgManager::new(100);

        // Build main chain: genesis -> B1 -> B2
        let (main_hashes, main_blocks, undos) =
            build_chain(&mut chain, &mut utxo_set, 2);

        for (h, u) in &undos {
            reorg_mgr.store_undo(*h, u.clone());
        }

        // Record the coinbase outpoint from B2 (should exist in UTXO set).
        let b2_coinbase_txid = main_blocks[1].transactions[0].txid();
        let b2_coinbase_outpoint = OutPoint::new(b2_coinbase_txid, 0);
        assert!(
            utxo_set.contains(&b2_coinbase_outpoint),
            "B2 coinbase should be in UTXO set before reorg"
        );

        let old_tip = *main_hashes.last().unwrap();

        // Fork from B1: B1 -> F2
        let fork_entry = chain.get_header(&main_hashes[0]).unwrap().clone();
        let (fork_hashes, fork_blocks) = build_fork(&mut chain, &fork_entry, 1, 0xFF);
        let new_tip = *fork_hashes.last().unwrap();

        // Record the coinbase outpoint from F2 (for checking after reorg).
        let f2_coinbase_txid = fork_blocks[0].transactions[0].txid();
        let f2_coinbase_outpoint = OutPoint::new(f2_coinbase_txid, 0);

        execute_reorg(
            &mut chain,
            &reorg_mgr,
            &mut utxo_set,
            &old_tip,
            &new_tip,
            &fork_blocks,
        )
        .expect("reorg should succeed");

        // After reorg: B2's coinbase should be gone, F2's coinbase should exist.
        assert!(
            !utxo_set.contains(&b2_coinbase_outpoint),
            "B2 coinbase should be removed after reorg"
        );
        assert!(
            utxo_set.contains(&f2_coinbase_outpoint),
            "F2 coinbase should be in UTXO set after reorg"
        );
    }

    // -----------------------------------------------------------------------
    // Test: reorg with missing undo data fails gracefully
    // -----------------------------------------------------------------------

    #[test]
    fn test_reorg_missing_undo_data() {
        let mut chain = regtest_chain();
        let mut utxo_set = InMemoryUtxoSet::new();
        // Create ReorgManager but do NOT store any undo data.
        let reorg_mgr = ReorgManager::new(100);

        // Build main chain: genesis -> B1 -> B2
        let (main_hashes, _main_blocks, _undos) =
            build_chain(&mut chain, &mut utxo_set, 2);

        let old_tip = *main_hashes.last().unwrap();

        // Fork from B1: B1 -> F2
        let fork_entry = chain.get_header(&main_hashes[0]).unwrap().clone();
        let (fork_hashes, fork_blocks) = build_fork(&mut chain, &fork_entry, 1, 0xAB);
        let new_tip = *fork_hashes.last().unwrap();

        let result = execute_reorg(
            &mut chain,
            &reorg_mgr,
            &mut utxo_set,
            &old_tip,
            &new_tip,
            &fork_blocks,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            ReorgError::MissingUndoData(h) => {
                assert_eq!(h, 2, "should be missing undo for height 2");
            }
            other => panic!("expected MissingUndoData, got: {other}"),
        }
    }
}
