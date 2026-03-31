use btc_primitives::amount::Amount;
use btc_primitives::block::Block;
use btc_primitives::transaction::{OutPoint, TxOut};
use std::collections::HashMap;
use thiserror::Error;

use crate::validation::block_subsidy;

/// Coinbase maturity: outputs of a coinbase tx cannot be spent until
/// 100 blocks after the block containing the coinbase.
pub const COINBASE_MATURITY: u64 = 100;

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
}
