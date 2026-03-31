//! Parallel script verification for block validation.
//!
//! This module provides [`ParallelValidator`], which validates transaction
//! scripts across multiple CPU cores using `std::thread::scope` (no external
//! thread-pool dependency required). During initial block download this can
//! provide a significant speed-up on multi-core machines.

use btc_primitives::block::Block;
use btc_primitives::transaction::TxOut;

use crate::script_engine::ScriptFlags;
use crate::sig_verify::Secp256k1Verifier;
use crate::utxo::UtxoSet;
use crate::validation::ChainParams;
use crate::witness::verify_input;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for parallel script verification.
#[derive(Debug, Clone)]
pub struct ParallelConfig {
    /// Number of worker threads. `0` means auto-detect from the available CPU
    /// count (`std::thread::available_parallelism`).
    pub num_threads: usize,
    /// Number of (tx_index, input_index) pairs handed to each thread in one
    /// batch. Larger batches reduce scheduling overhead but may cause uneven
    /// work distribution when individual scripts vary in cost.
    pub batch_size: usize,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            num_threads: 0,
            batch_size: 16,
        }
    }
}

// ---------------------------------------------------------------------------
// ParallelValidator
// ---------------------------------------------------------------------------

/// Validates all scripts in a block using multiple threads.
pub struct ParallelValidator {
    /// Number of worker threads (0 = auto-detect from CPU count).
    num_threads: usize,
    /// Inputs per batch handed to each thread.
    batch_size: usize,
}

impl ParallelValidator {
    /// Create a new `ParallelValidator` from a [`ParallelConfig`].
    pub fn new(config: ParallelConfig) -> Self {
        Self {
            num_threads: config.num_threads,
            batch_size: config.batch_size,
        }
    }

    /// Resolve the effective thread count (auto-detect when configured as 0).
    fn effective_threads(&self) -> usize {
        if self.num_threads == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        } else {
            self.num_threads
        }
    }

    /// Validate every script in `block` in parallel.
    ///
    /// The coinbase transaction (index 0) is always skipped because it has no
    /// real inputs to verify.
    ///
    /// # Assume-valid optimisation
    ///
    /// If the block is at or below the assume-valid height (as determined by
    /// [`ChainParams::should_verify_scripts`]), script verification is skipped
    /// entirely and `Ok(())` is returned immediately.
    ///
    /// # Errors
    ///
    /// Returns `Err` with a list of `(tx_index, input_index, error_message)`
    /// tuples describing every script that failed validation.
    pub fn validate_block_scripts(
        &self,
        block: &Block,
        utxo_set: &dyn UtxoSet,
        height: u64,
        params: &ChainParams,
    ) -> Result<(), Vec<(usize, usize, String)>> {
        // --- Assume-valid shortcut -----------------------------------------
        let block_hash = block.block_hash();
        if !params.should_verify_scripts(height, &block_hash, None) {
            return Ok(());
        }

        // --- Build the work list -------------------------------------------
        // Collect (tx_index, input_index, prev_output) for every non-coinbase
        // input. We resolve UTXO lookups on the main thread so that the worker
        // threads only need shared, immutable references.
        let flags = ScriptFlags::all();

        struct WorkItem {
            tx_idx: usize,
            input_idx: usize,
            prev_output: TxOut,
        }

        let mut work: Vec<WorkItem> = Vec::new();

        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            // Skip coinbase
            if tx_idx == 0 {
                continue;
            }

            for (input_idx, input) in tx.inputs.iter().enumerate() {
                let prev_output = match utxo_set.get_utxo(&input.previous_output) {
                    Some(entry) => entry.txout.clone(),
                    None => {
                        // Missing UTXO — record as an error immediately.
                        return Err(vec![(
                            tx_idx,
                            input_idx,
                            format!(
                                "missing UTXO for outpoint {:?}",
                                input.previous_output
                            ),
                        )]);
                    }
                };

                work.push(WorkItem {
                    tx_idx,
                    input_idx,
                    prev_output,
                });
            }
        }

        if work.is_empty() {
            return Ok(());
        }

        // --- Parallel verification -----------------------------------------
        let num_threads = self.effective_threads().min(work.len());
        let chunks: Vec<&[WorkItem]> = work.chunks(self.batch_size.max(1)).collect();

        // We split the chunk-list into `num_threads` roughly-equal slices so
        // each thread processes several batches.
        let slices = distribute(&chunks, num_threads);

        let errors: Vec<(usize, usize, String)> = std::thread::scope(|s| {
            let handles: Vec<_> = slices
                .into_iter()
                .map(|slice| {
                    let txs = &block.transactions;
                    let flags = &flags;
                    s.spawn(move || {
                        let verifier = Secp256k1Verifier;
                        let mut local_errors: Vec<(usize, usize, String)> = Vec::new();

                        for batch in slice {
                            for item in *batch {
                                let tx = &txs[item.tx_idx];
                                if let Err(e) = verify_input(
                                    tx,
                                    item.input_idx,
                                    &item.prev_output,
                                    &verifier,
                                    flags,
                                ) {
                                    local_errors.push((
                                        item.tx_idx,
                                        item.input_idx,
                                        e.to_string(),
                                    ));
                                }
                            }
                        }

                        local_errors
                    })
                })
                .collect();

            let mut all_errors = Vec::new();
            for handle in handles {
                all_errors.extend(handle.join().expect("worker thread panicked"));
            }
            all_errors
        });

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Default for ParallelValidator {
    fn default() -> Self {
        Self::new(ParallelConfig::default())
    }
}

// ---------------------------------------------------------------------------
// Helper: distribute slices evenly across N workers
// ---------------------------------------------------------------------------

/// Split `items` into `n` roughly-equal sub-slices.
fn distribute<T>(items: &[T], n: usize) -> Vec<&[T]> {
    if n == 0 || items.is_empty() {
        return vec![items];
    }
    let n = n.min(items.len());
    let base = items.len() / n;
    let remainder = items.len() % n;

    let mut result = Vec::with_capacity(n);
    let mut start = 0;
    for i in 0..n {
        let extra = if i < remainder { 1 } else { 0 };
        let end = start + base + extra;
        result.push(&items[start..end]);
        start = end;
    }
    result
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
    use crate::utxo::{InMemoryUtxoSet, UtxoEntry};
    use crate::validation::ChainParams;

    // -----------------------------------------------------------------------
    // Test helpers
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

    /// Build a non-coinbase transaction that spends given outpoints.
    fn make_spend_tx(inputs: Vec<OutPoint>, output_values: Vec<Amount>) -> Transaction {
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

    /// Create a block with the given transactions (header won't pass PoW but is
    /// sufficient for script-validation tests).
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

    /// Set up an `InMemoryUtxoSet` containing one UTXO per outpoint, each with
    /// a trivial `OP_TRUE` script so that verification will succeed for any
    /// scriptSig.
    fn utxo_set_with_entries(outpoints: &[OutPoint], value: Amount) -> InMemoryUtxoSet {
        let mut set = InMemoryUtxoSet::new();
        for op in outpoints {
            set.insert(
                *op,
                UtxoEntry {
                    txout: TxOut {
                        value,
                        // OP_TRUE (0x51) — always succeeds
                        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                    },
                    height: 0,
                    is_coinbase: false,
                },
            );
        }
        set
    }

    // -----------------------------------------------------------------------
    // Test: block with multiple transactions validates successfully
    // -----------------------------------------------------------------------

    #[test]
    fn test_parallel_validate_multiple_txs() {
        let op1 = OutPoint::new(TxHash::from_bytes([0x01; 32]), 0);
        let op2 = OutPoint::new(TxHash::from_bytes([0x02; 32]), 0);
        let op3 = OutPoint::new(TxHash::from_bytes([0x03; 32]), 0);

        let utxo_set = utxo_set_with_entries(
            &[op1, op2, op3],
            Amount::from_sat(10_000),
        );

        let coinbase = make_coinbase_tx(Amount::from_sat(50 * 100_000_000));
        let tx1 = make_spend_tx(vec![op1], vec![Amount::from_sat(9_000)]);
        let tx2 = make_spend_tx(vec![op2, op3], vec![Amount::from_sat(18_000)]);

        let block = make_block(vec![coinbase, tx1, tx2]);

        let params = ChainParams::regtest();
        let validator = ParallelValidator::default();

        let result = validator.validate_block_scripts(&block, &utxo_set, 1, &params);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    }

    // -----------------------------------------------------------------------
    // Test: single-threaded fallback (num_threads = 1)
    // -----------------------------------------------------------------------

    #[test]
    fn test_single_thread_fallback() {
        let op = OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0);
        let utxo_set = utxo_set_with_entries(&[op], Amount::from_sat(5_000));

        let coinbase = make_coinbase_tx(Amount::from_sat(50 * 100_000_000));
        let tx = make_spend_tx(vec![op], vec![Amount::from_sat(4_000)]);
        let block = make_block(vec![coinbase, tx]);

        let params = ChainParams::regtest();
        let validator = ParallelValidator::new(ParallelConfig {
            num_threads: 1,
            batch_size: 16,
        });

        let result = validator.validate_block_scripts(&block, &utxo_set, 1, &params);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    }

    // -----------------------------------------------------------------------
    // Test: assume-valid skips verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_assume_valid_skips_verification() {
        // Build a block whose hash matches assume_valid in our custom params.
        // Since we control the params, just set assume_valid to match the
        // block we construct.
        let coinbase = make_coinbase_tx(Amount::from_sat(50 * 100_000_000));

        // A spending tx referencing a UTXO that does NOT exist — this would
        // fail if scripts were actually checked. We use it to prove that
        // assume-valid causes the validator to return Ok without looking up
        // any UTXOs.
        let fake_op = OutPoint::new(TxHash::from_bytes([0xff; 32]), 0);
        let tx = make_spend_tx(vec![fake_op], vec![Amount::from_sat(1_000)]);
        let block = make_block(vec![coinbase, tx]);

        let block_hash = block.block_hash();

        // Construct params where assume_valid matches this block's hash.
        let mut params = ChainParams::regtest();
        params.assume_valid = Some(block_hash);

        let utxo_set = InMemoryUtxoSet::new(); // empty — would fail lookup
        let validator = ParallelValidator::default();

        let result = validator.validate_block_scripts(&block, &utxo_set, 100, &params);
        assert!(
            result.is_ok(),
            "assume-valid block should skip verification, got: {:?}",
            result
        );
    }

    // -----------------------------------------------------------------------
    // Test: error collection from multiple failing scripts
    // -----------------------------------------------------------------------

    #[test]
    fn test_error_collection_multiple_failures() {
        // Create UTXOs with a script that will cause verification to fail.
        // OP_RETURN (0x6a) makes the script always fail when executed.
        let op1 = OutPoint::new(TxHash::from_bytes([0x10; 32]), 0);
        let op2 = OutPoint::new(TxHash::from_bytes([0x20; 32]), 0);
        let op3 = OutPoint::new(TxHash::from_bytes([0x30; 32]), 0);

        let mut utxo_set = InMemoryUtxoSet::new();
        for op in &[op1, op2, op3] {
            utxo_set.insert(
                *op,
                UtxoEntry {
                    txout: TxOut {
                        value: Amount::from_sat(10_000),
                        // OP_RETURN — always fails
                        script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
                    },
                    height: 0,
                    is_coinbase: false,
                },
            );
        }

        let coinbase = make_coinbase_tx(Amount::from_sat(50 * 100_000_000));
        let tx1 = make_spend_tx(vec![op1], vec![Amount::from_sat(9_000)]);
        let tx2 = make_spend_tx(vec![op2, op3], vec![Amount::from_sat(18_000)]);
        let block = make_block(vec![coinbase, tx1, tx2]);

        let params = ChainParams::regtest();
        let validator = ParallelValidator::new(ParallelConfig {
            num_threads: 2,
            batch_size: 2,
        });

        let result = validator.validate_block_scripts(&block, &utxo_set, 1, &params);
        assert!(result.is_err(), "expected failures, got Ok");

        let errors = result.unwrap_err();
        // We expect exactly 3 errors: tx1/input0, tx2/input0, tx2/input1
        assert_eq!(
            errors.len(),
            3,
            "expected 3 errors, got {}: {:?}",
            errors.len(),
            errors
        );

        // Verify all three (tx_idx, input_idx) pairs are present (order may
        // vary due to threading).
        let mut pairs: Vec<(usize, usize)> = errors.iter().map(|(t, i, _)| (*t, *i)).collect();
        pairs.sort();
        assert_eq!(pairs, vec![(1, 0), (2, 0), (2, 1)]);
    }

    // -----------------------------------------------------------------------
    // Test: coinbase-only block
    // -----------------------------------------------------------------------

    #[test]
    fn test_coinbase_only_block() {
        let coinbase = make_coinbase_tx(Amount::from_sat(50 * 100_000_000));
        let block = make_block(vec![coinbase]);

        let params = ChainParams::regtest();
        let utxo_set = InMemoryUtxoSet::new();
        let validator = ParallelValidator::default();

        let result = validator.validate_block_scripts(&block, &utxo_set, 0, &params);
        assert!(result.is_ok(), "coinbase-only block should pass, got: {:?}", result);
    }

    // -----------------------------------------------------------------------
    // Test: distribute helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_distribute_evenly() {
        let items = vec![1, 2, 3, 4, 5, 6];
        let slices = distribute(&items, 3);
        assert_eq!(slices.len(), 3);
        assert_eq!(slices[0], &[1, 2]);
        assert_eq!(slices[1], &[3, 4]);
        assert_eq!(slices[2], &[5, 6]);
    }

    #[test]
    fn test_distribute_uneven() {
        let items = vec![1, 2, 3, 4, 5];
        let slices = distribute(&items, 3);
        assert_eq!(slices.len(), 3);
        // 5 / 3 = 1 remainder 2, so first two get an extra
        assert_eq!(slices[0], &[1, 2]);
        assert_eq!(slices[1], &[3, 4]);
        assert_eq!(slices[2], &[5]);
    }

    #[test]
    fn test_distribute_more_threads_than_items() {
        let items = vec![1, 2];
        let slices = distribute(&items, 10);
        // Capped to items.len() = 2
        assert_eq!(slices.len(), 2);
        assert_eq!(slices[0], &[1]);
        assert_eq!(slices[1], &[2]);
    }
}
