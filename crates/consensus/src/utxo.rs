use btc_primitives::amount::Amount;
use btc_primitives::block::Block;
use btc_primitives::hash::TxHash;
use btc_primitives::transaction::{OutPoint, TxOut};
use std::collections::HashMap;
use thiserror::Error;

use crate::validation::{block_subsidy, ChainParams, validate_bip34_coinbase};

/// Coinbase maturity: outputs of a coinbase tx cannot be spent until
/// 100 blocks after the block containing the coinbase.
pub const COINBASE_MATURITY: u64 = 100;

// ---------------------------------------------------------------------------
// BIP68 constants
// ---------------------------------------------------------------------------

/// BIP68: If this flag is set in the sequence number, the relative lock-time
/// is disabled for that input.
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// BIP68: If this flag is set (and disable flag is not), the relative
/// lock-time is measured in 512-second units rather than blocks.
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// BIP68: Mask for the relative lock-time value (lower 16 bits).
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;

// ---------------------------------------------------------------------------
// BIP30 exempt blocks (mainnet)
// ---------------------------------------------------------------------------

/// Mainnet blocks 91842 and 91880 contain duplicate coinbase txids that
/// overwrote earlier unspent outputs. These two blocks are exempt from the
/// BIP30 duplicate-txid check.
const BIP30_EXEMPT_HEIGHTS: [u64; 2] = [91842, 91880];

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum UtxoError {
    #[error("missing UTXO for outpoint {0:?} (possible double-spend)")]
    UtxoNotFound(OutPoint),

    #[error("coinbase output at height {created_height} not mature at spending height {spend_height} (need {COINBASE_MATURITY} confirmations)")]
    CoinbaseNotMature {
        created_height: u64,
        spend_height: u64,
    },

    #[error("output value exceeds input value for non-coinbase tx: inputs={inputs}, outputs={outputs}")]
    OutputExceedsInput { inputs: Amount, outputs: Amount },

    #[error("coinbase reward too high: got {got}, max allowed {max}")]
    CoinbaseRewardTooHigh { got: Amount, max: Amount },

    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("BIP30: duplicate unspent txid {0}")]
    Bip30DuplicateTxid(TxHash),

    #[error("BIP34: {0}")]
    Bip34(#[from] crate::validation::ValidationError),

    #[error("BIP68: relative lock-time not satisfied for input spending {outpoint:?} (need {required_depth} blocks, have {actual_depth})")]
    Bip68RelativeLockTime {
        outpoint: OutPoint,
        required_depth: u64,
        actual_depth: u64,
    },
}

// ---------------------------------------------------------------------------
// Core data structures
// ---------------------------------------------------------------------------

/// A single unspent transaction output together with the metadata needed for
/// consensus validation (creation height and coinbase flag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoEntry {
    pub txout: TxOut,
    /// Block height where this UTXO was created.
    pub height: u64,
    /// Whether the creating transaction was a coinbase (maturity rules apply).
    pub is_coinbase: bool,
}

/// Abstract read-only view of the current UTXO set.
pub trait UtxoSet {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<&UtxoEntry>;

    fn contains(&self, outpoint: &OutPoint) -> bool {
        self.get_utxo(outpoint).is_some()
    }
}

/// The delta produced by connecting (or intended to disconnect) a single block.
/// Stores both the consumed UTXOs (so they can be restored on reorg) and the
/// newly created UTXOs.
#[derive(Debug, Clone)]
pub struct UtxoSetUpdate {
    /// UTXOs consumed by inputs in this block (kept for undo/reorg).
    pub spent: Vec<(OutPoint, UtxoEntry)>,
    /// UTXOs created by outputs in this block.
    pub created: Vec<(OutPoint, UtxoEntry)>,
}

// ---------------------------------------------------------------------------
// connect_block / disconnect_block
// ---------------------------------------------------------------------------

/// Apply a block to the UTXO set, returning the resulting delta.
///
/// This performs contextual validation that requires the UTXO set:
/// - Every input must reference an existing UTXO (no double-spends).
/// - Coinbase outputs must have at least `COINBASE_MATURITY` confirmations.
/// - For every non-coinbase transaction, sum(inputs) >= sum(outputs).
/// - The coinbase output value must not exceed subsidy + total fees.
pub fn connect_block(
    block: &Block,
    height: u64,
    utxo_view: &dyn UtxoSet,
) -> Result<UtxoSetUpdate, UtxoError> {
    let mut spent: Vec<(OutPoint, UtxoEntry)> = Vec::new();
    let mut created: Vec<(OutPoint, UtxoEntry)> = Vec::new();

    // We also need to be able to look up outputs created *within this block*
    // by later transactions in the same block (intra-block spends). Build an
    // auxiliary map of outputs created so far keyed by outpoint.
    let mut intra_block: HashMap<OutPoint, UtxoEntry> = HashMap::new();

    // Track total fees for coinbase reward validation.
    let mut total_fees = Amount::ZERO;

    for (_tx_idx, tx) in block.transactions.iter().enumerate() {
        let is_coinbase = tx.is_coinbase();
        let txid = tx.txid();

        // --- Process inputs (skip for coinbase) ---
        let mut input_sum = Amount::ZERO;

        if !is_coinbase {
            if tx.inputs.is_empty() {
                return Err(UtxoError::InvalidTransaction(
                    "non-coinbase transaction has no inputs".into(),
                ));
            }
            for input in &tx.inputs {
                let outpoint = &input.previous_output;

                // Look up the UTXO being spent.  First check intra-block map,
                // then fall back to the external UTXO view.
                let entry = if let Some(e) = intra_block.remove(outpoint) {
                    e
                } else if let Some(e) = utxo_view.get_utxo(outpoint) {
                    e.clone()
                } else {
                    return Err(UtxoError::UtxoNotFound(*outpoint));
                };

                // Coinbase maturity check.
                if entry.is_coinbase
                    && height.saturating_sub(entry.height) < COINBASE_MATURITY
                {
                    return Err(UtxoError::CoinbaseNotMature {
                        created_height: entry.height,
                        spend_height: height,
                    });
                }

                input_sum = input_sum + entry.txout.value;
                spent.push((*outpoint, entry));
            }
        }

        // --- Process outputs ---
        let mut output_sum = Amount::ZERO;

        for (vout, txout) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint::new(txid, vout as u32);
            let entry = UtxoEntry {
                txout: txout.clone(),
                height,
                is_coinbase,
            };

            output_sum = output_sum + txout.value;

            // Store in intra-block map so later txs in this block can spend it.
            intra_block.insert(outpoint, entry.clone());
            created.push((outpoint, entry));
        }

        // --- Value conservation for non-coinbase transactions ---
        if !is_coinbase {
            if output_sum.as_sat() > input_sum.as_sat() {
                return Err(UtxoError::OutputExceedsInput {
                    inputs: input_sum,
                    outputs: output_sum,
                });
            }
            total_fees = total_fees + (input_sum - output_sum);
        }
    }

    // --- Validate coinbase reward ---
    // The coinbase is always the first transaction.
    if !block.transactions.is_empty() {
        let coinbase_tx = &block.transactions[0];
        let coinbase_output: Amount = coinbase_tx
            .outputs
            .iter()
            .fold(Amount::ZERO, |acc, o| acc + o.value);
        let max_reward = block_subsidy(height) + total_fees;

        if coinbase_output.as_sat() > max_reward.as_sat() {
            return Err(UtxoError::CoinbaseRewardTooHigh {
                got: coinbase_output,
                max: max_reward,
            });
        }
    }

    Ok(UtxoSetUpdate { spent, created })
}

/// Apply a block to the UTXO set with full BIP30/BIP34/BIP68 validation.
///
/// This wraps `connect_block` with additional consensus checks that require
/// knowledge of the chain parameters:
///
/// - **BIP30**: Before inserting new UTXOs, verify that no existing unspent
///   UTXO shares a txid with any transaction in this block. Exception:
///   mainnet blocks 91842 and 91880 are exempt. After BIP34 activation
///   (height >= bip34_height), coinbase txids are guaranteed unique by the
///   height-in-coinbase rule, so this check is implicitly satisfied.
///
/// - **BIP34**: The coinbase scriptSig must begin with a push of the block
///   height, encoded as a minimal CScriptNum. Enforced at heights >=
///   `params.bip34_height`.
///
/// - **BIP68**: For non-coinbase transactions with version >= 2, each input
///   whose sequence number does NOT have bit 31 set is subject to a
///   relative lock-time constraint. Height-based relative lock-times (bit 22
///   not set) are fully enforced. Time-based relative lock-times (bit 22
///   set) require median-time-past access and are currently not enforced
///   (TODO).
pub fn connect_block_with_params(
    block: &Block,
    height: u64,
    utxo_view: &dyn UtxoSet,
    params: &ChainParams,
) -> Result<UtxoSetUpdate, UtxoError> {
    // --- BIP34: height in coinbase ---
    validate_bip34_coinbase(block, height, params.bip34_height)?;

    // --- BIP30: duplicate txid check ---
    // After BIP34 activation, coinbase txids include the height so they are
    // unique; we can skip the (expensive) scan in that case. The two
    // historical exception blocks are also skipped.
    let bip30_active = height < params.bip34_height
        && !BIP30_EXEMPT_HEIGHTS.contains(&height);

    if bip30_active {
        for tx in &block.transactions {
            let txid = tx.txid();
            // Check whether any output of this txid is still unspent.
            for vout in 0..tx.outputs.len() {
                let outpoint = OutPoint::new(txid, vout as u32);
                if utxo_view.contains(&outpoint) {
                    return Err(UtxoError::Bip30DuplicateTxid(txid));
                }
            }
        }
    }

    // --- Run the base connect_block (UTXO spend/create, maturity, etc.) ---
    let update = connect_block(block, height, utxo_view)?;

    // --- BIP68: relative lock-time ---
    // We need access to the spent entries that connect_block just recorded,
    // so we check BIP68 after the base validation.
    for tx in &block.transactions {
        if tx.is_coinbase() {
            continue;
        }
        // BIP68 only applies to transactions with version >= 2.
        if tx.version < 2 {
            continue;
        }

        for input in &tx.inputs {
            let seq = input.sequence;

            // If the disable flag is set, skip this input.
            if seq & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
                continue;
            }

            let masked = (seq & SEQUENCE_LOCKTIME_MASK) as u64;

            if seq & SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
                // Time-based relative lock-time (512-second granularity).
                // Requires median-time-past of the block at the UTXO
                // creation height, which we don't currently have access to.
                // TODO: implement time-based BIP68 once MTP is available.
                continue;
            }

            // Height-based relative lock-time: the input's UTXO must be
            // at least `masked` blocks old.
            //
            // Find the entry height from the spent list (connect_block
            // already validated that the UTXO exists).
            let outpoint = &input.previous_output;
            let entry_height = update
                .spent
                .iter()
                .find(|(op, _)| op == outpoint)
                .map(|(_, e)| e.height)
                .unwrap_or(0);

            // Per BIP68, the relative lock-time is satisfied when:
            //   (spending_height - utxo_height) >= required_depth
            // where required_depth = masked value from the sequence.
            // Note: the "+1" is because block N spending a UTXO created in
            // block N has depth 0 (same block), and a sequence value of 1
            // means "at least 1 block apart".
            let actual_depth = height.saturating_sub(entry_height);
            if actual_depth < masked {
                return Err(UtxoError::Bip68RelativeLockTime {
                    outpoint: *outpoint,
                    required_depth: masked,
                    actual_depth,
                });
            }
        }
    }

    Ok(update)
}

/// Reverse the effect of `connect_block` — used during chain reorganisations.
///
/// Given a mutable `InMemoryUtxoSet` and the `UtxoSetUpdate` that was produced
/// when the block was connected, this function:
/// 1. Removes every UTXO that was *created* by the block.
/// 2. Re-inserts every UTXO that was *spent* by the block.
pub fn disconnect_block(utxo_set: &mut InMemoryUtxoSet, update: &UtxoSetUpdate) {
    // Remove created UTXOs.
    for (outpoint, _) in &update.created {
        utxo_set.remove(outpoint);
    }
    // Restore spent UTXOs.
    for (outpoint, entry) in &update.spent {
        utxo_set.insert(*outpoint, entry.clone());
    }
}

// ---------------------------------------------------------------------------
// In-memory UTXO set (for testing / IBD)
// ---------------------------------------------------------------------------

/// Maximum number of entries kept in the in-memory UTXO set.
/// Beyond this limit, oldest entries (by HashMap iteration order) are evicted.
/// With a persistent redb backend, evicted entries can be re-read from disk.
const MAX_IN_MEMORY_UTXOS: usize = 50_000_000;

/// A simple `HashMap`-backed UTXO set suitable for tests and initial block
/// download (before switching to a persistent store).
#[derive(Debug, Clone, Default)]
pub struct InMemoryUtxoSet {
    map: HashMap<OutPoint, UtxoEntry>,
}

impl InMemoryUtxoSet {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn insert(&mut self, outpoint: OutPoint, entry: UtxoEntry) {
        self.map.insert(outpoint, entry);
    }

    pub fn remove(&mut self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        self.map.remove(outpoint)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Iterate over all entries in the UTXO set.
    pub fn iter(&self) -> impl Iterator<Item = (&OutPoint, &UtxoEntry)> {
        self.map.iter()
    }

    /// Apply a `UtxoSetUpdate` forward (connect): remove spent, add created.
    pub fn apply_update(&mut self, update: &UtxoSetUpdate) {
        for (outpoint, _) in &update.spent {
            self.map.remove(outpoint);
        }
        for (outpoint, entry) in &update.created {
            self.map.insert(*outpoint, entry.clone());
        }
    }

    /// Evict entries when the map exceeds `MAX_IN_MEMORY_UTXOS` to prevent OOM.
    ///
    /// Eviction uses HashMap iteration order as a rough approximation of age.
    /// With a persistent backend (redb), evicted UTXOs can be re-read from disk
    /// when needed for validation.
    pub fn enforce_limit(&mut self) {
        if self.map.len() > MAX_IN_MEMORY_UTXOS {
            let to_remove = self.map.len() - MAX_IN_MEMORY_UTXOS;
            let keys: Vec<_> = self.map.keys().take(to_remove).cloned().collect();
            for key in keys {
                self.map.remove(&key);
            }
        }
    }
}

impl UtxoSet for InMemoryUtxoSet {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<&UtxoEntry> {
        self.map.get(outpoint)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::amount::Amount;
    use btc_primitives::block::{Block, BlockHeader};
    use btc_primitives::compact::CompactTarget;
    use btc_primitives::hash::{BlockHash, TxHash};
    use btc_primitives::script::ScriptBuf;
    use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build a minimal coinbase transaction.
    fn make_coinbase_tx(value: Amount) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0x00]),
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

    /// Build a normal (non-coinbase) transaction that spends the given
    /// outpoints and produces `output_values`.
    fn make_spend_tx(
        inputs: Vec<OutPoint>,
        output_values: Vec<Amount>,
    ) -> Transaction {
        let tx_inputs = inputs
            .into_iter()
            .map(|op| TxIn {
                previous_output: op,
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: TxIn::SEQUENCE_FINAL,
            })
            .collect();

        let tx_outputs = output_values
            .into_iter()
            .map(|v| TxOut {
                value: v,
                script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14]),
            })
            .collect();

        Transaction {
            version: 1,
            inputs: tx_inputs,
            outputs: tx_outputs,
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    /// Create a block with the given transactions.  The header is a dummy that
    /// won't pass PoW checks, but that's fine for UTXO-level tests.
    fn make_block(transactions: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::ZERO,
                time: 0,
                bits: CompactTarget::MAX_TARGET,
                nonce: 0,
            },
            transactions,
        }
    }

    // -----------------------------------------------------------------------
    // Test: connecting a coinbase-only block creates UTXOs
    // -----------------------------------------------------------------------

    #[test]
    fn test_connect_coinbase_creates_utxos() {
        let utxo_set = InMemoryUtxoSet::new();
        let subsidy = crate::validation::block_subsidy(0);
        let coinbase = make_coinbase_tx(subsidy);
        let block = make_block(vec![coinbase.clone()]);

        let update = connect_block(&block, 0, &utxo_set).unwrap();

        // One output created, nothing spent.
        assert_eq!(update.created.len(), 1);
        assert!(update.spent.is_empty());

        let (outpoint, entry) = &update.created[0];
        assert_eq!(outpoint.txid, coinbase.txid());
        assert_eq!(outpoint.vout, 0);
        assert_eq!(entry.txout.value, subsidy);
        assert!(entry.is_coinbase);
        assert_eq!(entry.height, 0);
    }

    // -----------------------------------------------------------------------
    // Test: spending a UTXO removes it and creates new ones
    // -----------------------------------------------------------------------

    #[test]
    fn test_spend_utxo() {
        // Set up a UTXO set with a single entry from an earlier (non-coinbase)
        // transaction to avoid coinbase maturity issues.
        let mut utxo_set = InMemoryUtxoSet::new();
        let prev_txid = TxHash::from_bytes([0xaa; 32]);
        let prev_outpoint = OutPoint::new(prev_txid, 0);
        utxo_set.insert(
            prev_outpoint,
            UtxoEntry {
                txout: TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00]),
                },
                height: 0,
                is_coinbase: false,
            },
        );

        let subsidy = crate::validation::block_subsidy(1);
        let coinbase = make_coinbase_tx(subsidy);
        let spend = make_spend_tx(
            vec![prev_outpoint],
            vec![Amount::from_sat(8_000), Amount::from_sat(2_000)],
        );

        let block = make_block(vec![coinbase, spend]);
        let update = connect_block(&block, 1, &utxo_set).unwrap();

        // Coinbase creates 1, spend creates 2 => 3 created total.
        assert_eq!(update.created.len(), 3);
        // The spend consumes 1 UTXO.
        assert_eq!(update.spent.len(), 1);
        assert_eq!(update.spent[0].0, prev_outpoint);
    }

    // -----------------------------------------------------------------------
    // Test: double-spend detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_double_spend_detected() {
        let utxo_set = InMemoryUtxoSet::new(); // empty

        let subsidy = crate::validation::block_subsidy(1);
        let coinbase = make_coinbase_tx(subsidy);

        // Try to spend a UTXO that doesn't exist.
        let fake_outpoint = OutPoint::new(TxHash::from_bytes([0xbb; 32]), 0);
        let spend = make_spend_tx(vec![fake_outpoint], vec![Amount::from_sat(1_000)]);

        let block = make_block(vec![coinbase, spend]);
        let result = connect_block(&block, 1, &utxo_set);

        assert!(result.is_err());
        match result.unwrap_err() {
            UtxoError::UtxoNotFound(op) => assert_eq!(op, fake_outpoint),
            other => panic!("expected UtxoNotFound, got: {other}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test: coinbase maturity
    // -----------------------------------------------------------------------

    #[test]
    fn test_coinbase_maturity_too_early() {
        // Create a coinbase UTXO at height 10.
        let mut utxo_set = InMemoryUtxoSet::new();
        let cb_txid = TxHash::from_bytes([0xcc; 32]);
        let cb_outpoint = OutPoint::new(cb_txid, 0);
        utxo_set.insert(
            cb_outpoint,
            UtxoEntry {
                txout: TxOut {
                    value: Amount::from_sat(50_0000_0000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00]),
                },
                height: 10,
                is_coinbase: true,
            },
        );

        // Try to spend it at height 109 (only 99 confirmations, need 100).
        let spend_height: u64 = 109;
        let subsidy = crate::validation::block_subsidy(spend_height);
        let coinbase = make_coinbase_tx(subsidy);
        let spend = make_spend_tx(
            vec![cb_outpoint],
            vec![Amount::from_sat(49_0000_0000)],
        );

        let block = make_block(vec![coinbase, spend]);
        let result = connect_block(&block, spend_height, &utxo_set);

        assert!(result.is_err());
        match result.unwrap_err() {
            UtxoError::CoinbaseNotMature {
                created_height,
                spend_height: sh,
            } => {
                assert_eq!(created_height, 10);
                assert_eq!(sh, 109);
            }
            other => panic!("expected CoinbaseNotMature, got: {other}"),
        }
    }

    #[test]
    fn test_coinbase_maturity_exactly_100() {
        // Create a coinbase UTXO at height 10.
        let mut utxo_set = InMemoryUtxoSet::new();
        let cb_txid = TxHash::from_bytes([0xcc; 32]);
        let cb_outpoint = OutPoint::new(cb_txid, 0);
        utxo_set.insert(
            cb_outpoint,
            UtxoEntry {
                txout: TxOut {
                    value: Amount::from_sat(50_0000_0000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00]),
                },
                height: 10,
                is_coinbase: true,
            },
        );

        // Spend at height 110 (exactly 100 confirmations) -- should succeed.
        let spend_height: u64 = 110;
        let subsidy = crate::validation::block_subsidy(spend_height);
        let coinbase = make_coinbase_tx(subsidy);
        let spend = make_spend_tx(
            vec![cb_outpoint],
            vec![Amount::from_sat(49_0000_0000)],
        );

        let block = make_block(vec![coinbase, spend]);
        let result = connect_block(&block, spend_height, &utxo_set);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Test: value conservation (outputs cannot exceed inputs + subsidy)
    // -----------------------------------------------------------------------

    #[test]
    fn test_outputs_exceed_inputs() {
        let mut utxo_set = InMemoryUtxoSet::new();
        let prev_txid = TxHash::from_bytes([0xdd; 32]);
        let prev_outpoint = OutPoint::new(prev_txid, 0);
        utxo_set.insert(
            prev_outpoint,
            UtxoEntry {
                txout: TxOut {
                    value: Amount::from_sat(5_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00]),
                },
                height: 0,
                is_coinbase: false,
            },
        );

        let subsidy = crate::validation::block_subsidy(1);
        let coinbase = make_coinbase_tx(subsidy);
        // Output exceeds input.
        let spend = make_spend_tx(
            vec![prev_outpoint],
            vec![Amount::from_sat(10_000)],
        );

        let block = make_block(vec![coinbase, spend]);
        let result = connect_block(&block, 1, &utxo_set);

        assert!(result.is_err());
        match result.unwrap_err() {
            UtxoError::OutputExceedsInput { inputs, outputs } => {
                assert_eq!(inputs.as_sat(), 5_000);
                assert_eq!(outputs.as_sat(), 10_000);
            }
            other => panic!("expected OutputExceedsInput, got: {other}"),
        }
    }

    #[test]
    fn test_coinbase_reward_too_high() {
        let utxo_set = InMemoryUtxoSet::new();
        let subsidy = crate::validation::block_subsidy(0);

        // Coinbase claims more than the subsidy (no fees to justify it).
        let bad_coinbase = make_coinbase_tx(subsidy + Amount::from_sat(1));
        let block = make_block(vec![bad_coinbase]);
        let result = connect_block(&block, 0, &utxo_set);

        assert!(result.is_err());
        match result.unwrap_err() {
            UtxoError::CoinbaseRewardTooHigh { got, max } => {
                assert_eq!(got.as_sat(), subsidy.as_sat() + 1);
                assert_eq!(max.as_sat(), subsidy.as_sat());
            }
            other => panic!("expected CoinbaseRewardTooHigh, got: {other}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test: disconnect_block reverses connect_block
    // -----------------------------------------------------------------------

    #[test]
    fn test_disconnect_reverses_connect() {
        let mut utxo_set = InMemoryUtxoSet::new();

        // Pre-existing UTXO.
        let prev_txid = TxHash::from_bytes([0xee; 32]);
        let prev_outpoint = OutPoint::new(prev_txid, 0);
        utxo_set.insert(
            prev_outpoint,
            UtxoEntry {
                txout: TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00]),
                },
                height: 0,
                is_coinbase: false,
            },
        );

        // Snapshot the UTXO set size before connecting.
        let size_before = utxo_set.len();
        assert_eq!(size_before, 1);

        // Build a block that spends the existing UTXO.
        let subsidy = crate::validation::block_subsidy(1);
        let coinbase = make_coinbase_tx(subsidy);
        let spend = make_spend_tx(
            vec![prev_outpoint],
            vec![Amount::from_sat(4_000), Amount::from_sat(6_000)],
        );
        let block = make_block(vec![coinbase, spend]);

        // Connect the block.
        let update = connect_block(&block, 1, &utxo_set).unwrap();
        utxo_set.apply_update(&update);

        // After connect: the original UTXO is gone; coinbase + 2 spend
        // outputs are created => 3 UTXOs.
        assert!(!utxo_set.contains(&prev_outpoint));
        assert_eq!(utxo_set.len(), 3);

        // Now disconnect.
        disconnect_block(&mut utxo_set, &update);

        // The original UTXO should be back, created ones removed.
        assert!(utxo_set.contains(&prev_outpoint));
        assert_eq!(utxo_set.len(), size_before);
        let restored = utxo_set.get_utxo(&prev_outpoint).unwrap();
        assert_eq!(restored.txout.value.as_sat(), 10_000);
    }

    // -----------------------------------------------------------------------
    // Test: InMemoryUtxoSet basic operations
    // -----------------------------------------------------------------------

    #[test]
    fn test_in_memory_utxo_set_basics() {
        let mut set = InMemoryUtxoSet::new();
        assert!(set.is_empty());

        let op = OutPoint::new(TxHash::from_bytes([0x01; 32]), 0);
        let entry = UtxoEntry {
            txout: TxOut {
                value: Amount::from_sat(42),
                script_pubkey: ScriptBuf::from_bytes(vec![]),
            },
            height: 5,
            is_coinbase: false,
        };

        set.insert(op, entry.clone());
        assert_eq!(set.len(), 1);
        assert!(set.contains(&op));
        assert_eq!(set.get_utxo(&op).unwrap().txout.value.as_sat(), 42);

        let removed = set.remove(&op);
        assert!(removed.is_some());
        assert!(set.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test: enforce_limit caps the UTXO set size
    // -----------------------------------------------------------------------

    #[test]
    fn test_enforce_limit() {
        let mut set = InMemoryUtxoSet::new();

        // Insert more entries than the limit (use a small number to test logic).
        // We can't insert 5M entries in a unit test, so we verify the mechanism
        // works by inserting entries and checking the method runs without panic.
        let count = 100;
        for i in 0..count {
            let mut txid_bytes = [0u8; 32];
            txid_bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let op = OutPoint::new(TxHash::from_bytes(txid_bytes), 0);
            let entry = UtxoEntry {
                txout: TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![]),
                },
                height: i as u64,
                is_coinbase: false,
            };
            set.insert(op, entry);
        }

        assert_eq!(set.len(), count);

        // With MAX_IN_MEMORY_UTXOS = 5_000_000, 100 entries won't trigger eviction
        set.enforce_limit();
        assert_eq!(set.len(), count);
    }

    // -----------------------------------------------------------------------
    // Test: reject non-coinbase transaction with zero inputs
    // -----------------------------------------------------------------------

    #[test]
    fn test_reject_zero_input_non_coinbase() {
        let utxo_set = InMemoryUtxoSet::new();
        let subsidy = crate::validation::block_subsidy(0);
        let coinbase = make_coinbase_tx(subsidy);

        // A non-coinbase tx with no inputs (empty inputs vec).
        let bad_tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = make_block(vec![coinbase, bad_tx]);
        let result = connect_block(&block, 0, &utxo_set);

        assert!(result.is_err(), "should reject non-coinbase tx with no inputs");
        match result.unwrap_err() {
            UtxoError::InvalidTransaction(msg) => {
                assert!(
                    msg.contains("no inputs"),
                    "error message should mention no inputs, got: {msg}"
                );
            }
            other => panic!("expected InvalidTransaction, got: {other}"),
        }
    }

    // -----------------------------------------------------------------------
    // BIP30 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_bip30_rejects_duplicate_txid() {
        // Create a UTXO set with an existing unspent output that shares a
        // txid with a transaction in the new block.
        let mut utxo_set = InMemoryUtxoSet::new();

        // Put a coinbase at height 0 whose txid will collide.
        let coinbase_0 = make_coinbase_tx(crate::validation::block_subsidy(0));
        let txid_0 = coinbase_0.txid();
        utxo_set.insert(
            OutPoint::new(txid_0, 0),
            UtxoEntry {
                txout: coinbase_0.outputs[0].clone(),
                height: 0,
                is_coinbase: true,
            },
        );

        // Now create a block at height 1 with the SAME coinbase tx (same
        // outputs/inputs means same txid). This should be rejected by BIP30
        // because the UTXO from height 0 is still unspent.
        let duplicate_coinbase = make_coinbase_tx(crate::validation::block_subsidy(1));
        // Verify the txids actually match (they should, since make_coinbase_tx
        // produces deterministic tx structure).
        assert_eq!(
            duplicate_coinbase.txid(),
            txid_0,
            "test setup: coinbase txids must match for BIP30 test"
        );

        let block = make_block(vec![duplicate_coinbase]);

        // Use ChainParams with bip34_height far in the future so BIP30 is
        // active.
        let mut params = ChainParams::mainnet();
        params.bip34_height = 1_000_000; // disable BIP34 for this test

        let result = connect_block_with_params(&block, 1, &utxo_set, &params);
        assert!(result.is_err());
        match result.unwrap_err() {
            UtxoError::Bip30DuplicateTxid(txid) => {
                assert_eq!(txid, txid_0);
            }
            other => panic!("expected Bip30DuplicateTxid, got: {other}"),
        }
    }

    #[test]
    fn test_bip30_allows_after_utxo_spent() {
        // If all outputs of the old txid have been spent, the same txid can
        // appear again (this is what happens in the exempt blocks).
        let utxo_set = InMemoryUtxoSet::new(); // empty -- no unspent UTXOs

        let coinbase = make_coinbase_tx(crate::validation::block_subsidy(0));
        let block = make_block(vec![coinbase]);

        let mut params = ChainParams::mainnet();
        params.bip34_height = 1_000_000;

        // No collision since the UTXO set is empty.
        let result = connect_block_with_params(&block, 0, &utxo_set, &params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_bip30_exempt_blocks() {
        // Blocks 91842 and 91880 are exempt from BIP30.
        let mut utxo_set = InMemoryUtxoSet::new();

        let coinbase = make_coinbase_tx(crate::validation::block_subsidy(91842));
        let txid = coinbase.txid();
        utxo_set.insert(
            OutPoint::new(txid, 0),
            UtxoEntry {
                txout: coinbase.outputs[0].clone(),
                height: 0,
                is_coinbase: true,
            },
        );

        let duplicate_coinbase = make_coinbase_tx(crate::validation::block_subsidy(91842));
        let block = make_block(vec![duplicate_coinbase]);

        let mut params = ChainParams::mainnet();
        params.bip34_height = 1_000_000;

        // Should succeed at exempt height 91842.
        let result = connect_block_with_params(&block, 91842, &utxo_set, &params);
        assert!(result.is_ok(), "BIP30 exempt block 91842 should be accepted");
    }

    #[test]
    fn test_bip30_skipped_after_bip34() {
        // After BIP34 activation, BIP30 check is skipped because coinbase
        // txids are guaranteed unique by the height-in-coinbase rule.
        let mut utxo_set = InMemoryUtxoSet::new();

        let coinbase = make_coinbase_tx(crate::validation::block_subsidy(0));
        let txid = coinbase.txid();
        utxo_set.insert(
            OutPoint::new(txid, 0),
            UtxoEntry {
                txout: coinbase.outputs[0].clone(),
                height: 0,
                is_coinbase: true,
            },
        );

        // Build a coinbase with valid BIP34 height encoding at height 227931.
        let height = 227931u64;
        let height_push = crate::validation::encode_bip34_height(height);
        let mut script_sig = height_push;
        script_sig.push(0x00); // extra data

        let bip34_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(script_sig),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: crate::validation::block_subsidy(height),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = make_block(vec![bip34_coinbase]);
        let params = ChainParams::mainnet();

        // At height >= bip34_height, BIP30 scan is skipped. Even though
        // the old txid has unspent outputs, the new coinbase has a different
        // txid (it includes the height), so this is fine.
        let result = connect_block_with_params(&block, height, &utxo_set, &params);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // BIP68 tests
    // -----------------------------------------------------------------------

    /// Helper: build a v2 spend tx with a specific sequence number.
    fn make_v2_spend_tx(
        inputs: Vec<(OutPoint, u32)>,
        output_values: Vec<Amount>,
    ) -> Transaction {
        let tx_inputs = inputs
            .into_iter()
            .map(|(op, seq)| TxIn {
                previous_output: op,
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: seq,
            })
            .collect();

        let tx_outputs = output_values
            .into_iter()
            .map(|v| TxOut {
                value: v,
                script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14]),
            })
            .collect();

        Transaction {
            version: 2,
            inputs: tx_inputs,
            outputs: tx_outputs,
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    #[test]
    fn test_bip68_height_lock_satisfied() {
        // UTXO created at height 100; spend at height 110 with sequence
        // requiring 10 blocks.
        let mut utxo_set = InMemoryUtxoSet::new();
        let prev_txid = TxHash::from_bytes([0xaa; 32]);
        let prev_outpoint = OutPoint::new(prev_txid, 0);
        utxo_set.insert(
            prev_outpoint,
            UtxoEntry {
                txout: TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00]),
                },
                height: 100,
                is_coinbase: false,
            },
        );

        let spend_height = 110u64;
        let subsidy = crate::validation::block_subsidy(spend_height);
        let coinbase = make_coinbase_tx(subsidy);

        // Sequence: height-based lock requiring 10 blocks (no flags set).
        let sequence = 10u32;
        let spend = make_v2_spend_tx(
            vec![(prev_outpoint, sequence)],
            vec![Amount::from_sat(8_000)],
        );

        let block = make_block(vec![coinbase, spend]);

        let mut params = ChainParams::mainnet();
        params.bip34_height = 1_000_000; // disable BIP34 for simplicity

        let result = connect_block_with_params(&block, spend_height, &utxo_set, &params);
        assert!(result.is_ok(), "BIP68: lock should be satisfied (depth=10, required=10)");
    }

    #[test]
    fn test_bip68_height_lock_not_satisfied() {
        // UTXO created at height 100; spend at height 105 with sequence
        // requiring 10 blocks -- should fail.
        let mut utxo_set = InMemoryUtxoSet::new();
        let prev_txid = TxHash::from_bytes([0xbb; 32]);
        let prev_outpoint = OutPoint::new(prev_txid, 0);
        utxo_set.insert(
            prev_outpoint,
            UtxoEntry {
                txout: TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00]),
                },
                height: 100,
                is_coinbase: false,
            },
        );

        let spend_height = 105u64;
        let subsidy = crate::validation::block_subsidy(spend_height);
        let coinbase = make_coinbase_tx(subsidy);

        let sequence = 10u32; // require 10 blocks
        let spend = make_v2_spend_tx(
            vec![(prev_outpoint, sequence)],
            vec![Amount::from_sat(8_000)],
        );

        let block = make_block(vec![coinbase, spend]);

        let mut params = ChainParams::mainnet();
        params.bip34_height = 1_000_000;

        let result = connect_block_with_params(&block, spend_height, &utxo_set, &params);
        assert!(result.is_err());
        match result.unwrap_err() {
            UtxoError::Bip68RelativeLockTime {
                outpoint,
                required_depth,
                actual_depth,
            } => {
                assert_eq!(outpoint, prev_outpoint);
                assert_eq!(required_depth, 10);
                assert_eq!(actual_depth, 5);
            }
            other => panic!("expected Bip68RelativeLockTime, got: {other}"),
        }
    }

    #[test]
    fn test_bip68_disabled_flag() {
        // When bit 31 is set, BIP68 is disabled for that input.
        let mut utxo_set = InMemoryUtxoSet::new();
        let prev_txid = TxHash::from_bytes([0xcc; 32]);
        let prev_outpoint = OutPoint::new(prev_txid, 0);
        utxo_set.insert(
            prev_outpoint,
            UtxoEntry {
                txout: TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00]),
                },
                height: 100,
                is_coinbase: false,
            },
        );

        let spend_height = 101u64;
        let subsidy = crate::validation::block_subsidy(spend_height);
        let coinbase = make_coinbase_tx(subsidy);

        // Sequence with disable flag set: should bypass BIP68 even though
        // the masked value (9999) would otherwise fail.
        let sequence = SEQUENCE_LOCKTIME_DISABLE_FLAG | 9999;
        let spend = make_v2_spend_tx(
            vec![(prev_outpoint, sequence)],
            vec![Amount::from_sat(8_000)],
        );

        let block = make_block(vec![coinbase, spend]);

        let mut params = ChainParams::mainnet();
        params.bip34_height = 1_000_000;

        let result = connect_block_with_params(&block, spend_height, &utxo_set, &params);
        assert!(result.is_ok(), "BIP68 should be disabled when bit 31 is set");
    }

    #[test]
    fn test_bip68_v1_tx_not_enforced() {
        // BIP68 only applies to transactions with version >= 2.
        let mut utxo_set = InMemoryUtxoSet::new();
        let prev_txid = TxHash::from_bytes([0xdd; 32]);
        let prev_outpoint = OutPoint::new(prev_txid, 0);
        utxo_set.insert(
            prev_outpoint,
            UtxoEntry {
                txout: TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00]),
                },
                height: 100,
                is_coinbase: false,
            },
        );

        let spend_height = 101u64;
        let subsidy = crate::validation::block_subsidy(spend_height);
        let coinbase = make_coinbase_tx(subsidy);

        // Version 1 transaction with a restrictive sequence -- should NOT
        // trigger BIP68.
        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: prev_outpoint,
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 1000, // would require 1000 blocks if v2
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(8_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = make_block(vec![coinbase, spend]);

        let mut params = ChainParams::mainnet();
        params.bip34_height = 1_000_000;

        let result = connect_block_with_params(&block, spend_height, &utxo_set, &params);
        assert!(result.is_ok(), "BIP68 should not apply to v1 transactions");
    }

    #[test]
    fn test_bip68_time_based_lock_skipped() {
        // Time-based relative lock-time (bit 22 set) should be skipped
        // (not enforced) for now, with a TODO for MTP support.
        let mut utxo_set = InMemoryUtxoSet::new();
        let prev_txid = TxHash::from_bytes([0xee; 32]);
        let prev_outpoint = OutPoint::new(prev_txid, 0);
        utxo_set.insert(
            prev_outpoint,
            UtxoEntry {
                txout: TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00]),
                },
                height: 100,
                is_coinbase: false,
            },
        );

        let spend_height = 101u64;
        let subsidy = crate::validation::block_subsidy(spend_height);
        let coinbase = make_coinbase_tx(subsidy);

        // Time-based lock: bit 22 set, value = 1000 (512-second units).
        let sequence = SEQUENCE_LOCKTIME_TYPE_FLAG | 1000;
        let spend = make_v2_spend_tx(
            vec![(prev_outpoint, sequence)],
            vec![Amount::from_sat(8_000)],
        );

        let block = make_block(vec![coinbase, spend]);

        let mut params = ChainParams::mainnet();
        params.bip34_height = 1_000_000;

        // Should pass because time-based locks are not yet enforced.
        let result = connect_block_with_params(&block, spend_height, &utxo_set, &params);
        assert!(result.is_ok(), "time-based BIP68 should be skipped (not enforced yet)");
    }

    #[test]
    fn test_bip68_coinbase_exempt() {
        // Coinbase transactions are exempt from BIP68.
        let utxo_set = InMemoryUtxoSet::new();
        let subsidy = crate::validation::block_subsidy(0);

        // Coinbase with a sequence that would fail BIP68 if it were checked.
        let coinbase = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0x00]),
                sequence: 100, // would fail BIP68 if checked
            }],
            outputs: vec![TxOut {
                value: subsidy,
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = make_block(vec![coinbase]);

        let mut params = ChainParams::mainnet();
        params.bip34_height = 1_000_000;

        let result = connect_block_with_params(&block, 0, &utxo_set, &params);
        assert!(result.is_ok(), "coinbase should be exempt from BIP68");
    }

    // ---- Coverage: apply_update and enforce_limit ----

    #[test]
    fn test_utxo_set_apply_and_limit() {
        let mut utxo_set = InMemoryUtxoSet::new();

        // Add some UTXOs
        for i in 0u8..10 {
            utxo_set.insert(
                OutPoint::new(TxHash::from_bytes([i; 32]), 0),
                UtxoEntry {
                    txout: TxOut {
                        value: Amount::from_sat(1000),
                        script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
                    },
                    height: 1,
                    is_coinbase: false,
                },
            );
        }
        assert_eq!(utxo_set.len(), 10);
        assert!(!utxo_set.is_empty());

        // Test iter
        assert_eq!(utxo_set.iter().count(), 10);

        // Remove one
        let removed = utxo_set.remove(&OutPoint::new(TxHash::from_bytes([0u8; 32]), 0));
        assert!(removed.is_some());
        assert_eq!(utxo_set.len(), 9);

        // enforce_limit shouldn't do anything with only 9 entries
        utxo_set.enforce_limit();
        assert_eq!(utxo_set.len(), 9);
    }

    // ---- Coverage: apply_update forward ----

    #[test]
    fn test_apply_update() {
        let mut utxo_set = InMemoryUtxoSet::new();
        let op1 = OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0);
        let entry1 = UtxoEntry {
            txout: TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
            },
            height: 1,
            is_coinbase: false,
        };

        // Insert first
        utxo_set.insert(op1, entry1.clone());
        assert_eq!(utxo_set.len(), 1);

        // Create an update that spends op1 and creates op2
        let op2 = OutPoint::new(TxHash::from_bytes([0xbb; 32]), 0);
        let entry2 = UtxoEntry {
            txout: TxOut {
                value: Amount::from_sat(500),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
            },
            height: 2,
            is_coinbase: false,
        };

        let update = UtxoSetUpdate {
            spent: vec![(op1, entry1)],
            created: vec![(op2, entry2)],
        };

        utxo_set.apply_update(&update);
        assert!(utxo_set.get_utxo(&op1).is_none());
        assert!(utxo_set.get_utxo(&op2).is_some());
    }

    // ---- Coverage: coinbase maturity check via connect_block ----

    #[test]
    fn test_coinbase_maturity_failure() {
        let mut utxo_set = InMemoryUtxoSet::new();

        // Insert a coinbase UTXO at height 1
        let cb_outpoint = OutPoint::new(TxHash::from_bytes([0xcc; 32]), 0);
        utxo_set.insert(cb_outpoint, UtxoEntry {
            txout: TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            },
            height: 1,
            is_coinbase: true,
        });

        let subsidy = crate::validation::block_subsidy(50);
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0x32]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: subsidy + Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: cb_outpoint,
                script_sig: ScriptBuf::from_bytes(vec![0x01]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(4_999_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = make_block(vec![coinbase, spend]);

        // Try to spend at height 50 (less than COINBASE_MATURITY=100)
        let result = connect_block(&block, 50, &utxo_set);
        assert!(result.is_err());
    }
}
