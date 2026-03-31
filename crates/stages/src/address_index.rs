use crate::stage::{ExecOutput, Stage, StageError, StageId, UnwindOutput, ADDRESS_INDEX};
use btc_primitives::hash::TxHash;
use std::collections::HashMap;
use tracing::info;

/// Maximum number of blocks to index in a single batch.
const ADDRESS_INDEX_BATCH_SIZE: u64 = 1000;

/// An entry in the address index, recording a transaction's effect on a script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressIndexEntry {
    /// For received (positive value): the txid of the transaction containing the output.
    /// For spent (negative value): the txid of the *original* output being consumed
    /// (i.e., the outpoint's txid), so that UTXOs can be matched.
    pub txid: TxHash,
    /// The block height containing this transaction.
    pub height: u64,
    /// Position of the transaction within the block (0 = coinbase).
    pub tx_index: u32,
    /// Positive for received (output), negative for spent (input).
    pub value: i64,
    /// For received: the vout index of the output.
    /// For spent: the vout index of the original output being consumed.
    pub output_index: u32,
}

/// Address index stage -- maps script hashes to their transaction history.
///
/// This stage builds an index from SHA256(scriptPubKey) to a list of
/// [`AddressIndexEntry`] values, following the Electrum protocol convention.
/// It enables efficient lookups for:
/// - Full transaction history for an address/script
/// - Balance computation
/// - UTXO set for a specific address/script
///
/// Depends on the Bodies stage having run first (needs the full transaction data).
pub struct AddressIndexStage {
    /// Current indexing progress -- the height up to which the index has been built.
    checkpoint: u64,
    /// Script hash -> list of (txid, block_height, value, output_index) entries.
    /// The key is SHA256(scriptPubKey), matching the Electrum protocol.
    index: HashMap<[u8; 32], Vec<AddressIndexEntry>>,
}

impl AddressIndexStage {
    pub fn new() -> Self {
        AddressIndexStage {
            checkpoint: 0,
            index: HashMap::new(),
        }
    }

    /// Return the current checkpoint height.
    pub fn checkpoint(&self) -> u64 {
        self.checkpoint
    }

    /// Return the total number of indexed script hashes.
    pub fn index_size(&self) -> usize {
        self.index.len()
    }

    /// Return the total number of index entries across all script hashes.
    pub fn total_entries(&self) -> usize {
        self.index.values().map(|v| v.len()).sum()
    }

    /// Get the full transaction history for a script hash.
    ///
    /// Returns all index entries (both receives and spends) in the order
    /// they were indexed, which corresponds to blockchain order.
    pub fn get_history(&self, script_hash: &[u8; 32]) -> Vec<AddressIndexEntry> {
        self.index.get(script_hash).cloned().unwrap_or_default()
    }

    /// Get the balance for a script hash by summing all entry values.
    ///
    /// Positive entries represent received funds, negative entries represent
    /// spent funds. The sum gives the current balance.
    pub fn get_balance(&self, script_hash: &[u8; 32]) -> i64 {
        self.index
            .get(script_hash)
            .map(|entries| entries.iter().map(|e| e.value).sum())
            .unwrap_or(0)
    }

    /// Get unspent outputs for a script hash.
    ///
    /// This works by tracking which outputs have been spent. An output at
    /// (txid, output_index) is considered spent if there is a corresponding
    /// negative-value entry with the same output_index for the same script.
    pub fn get_utxos(&self, script_hash: &[u8; 32]) -> Vec<AddressIndexEntry> {
        let entries = match self.index.get(script_hash) {
            Some(entries) => entries,
            None => return Vec::new(),
        };

        // Collect spent outputs by (output_index, absolute_value).
        // Spend entries have value < 0 and output_index matching the vout consumed.
        // The spend entry's txid is the *spending* tx, not the original output's tx,
        // so we match by (output_index, abs_value) instead.
        let mut spent: std::collections::HashSet<(u32, i64)> =
            std::collections::HashSet::new();
        for entry in entries {
            if entry.value < 0 {
                spent.insert((entry.output_index, -entry.value));
            }
        }

        entries
            .iter()
            .filter(|e| e.value > 0 && !spent.contains(&(e.output_index, e.value)))
            .cloned()
            .collect()
    }

    /// Add an entry to the index for the given script hash.
    pub fn add_entry(&mut self, script_hash: [u8; 32], entry: AddressIndexEntry) {
        self.index.entry(script_hash).or_default().push(entry);
    }

    /// Index a single block's transactions for address history.
    ///
    /// In a real implementation this would:
    /// 1. Load the block from the database
    /// 2. For each transaction:
    ///    a. For each output: compute SHA256(scriptPubKey), add positive entry
    ///    b. For each input (non-coinbase): look up the spent output's scriptPubKey,
    ///       compute SHA256(scriptPubKey), add negative entry
    fn index_block(&mut self, height: u64) -> Result<(), StageError> {
        // In a real implementation:
        //
        // let block = db.get_block(height)?;
        // for (tx_idx, tx) in block.transactions.iter().enumerate() {
        //     let txid = tx.txid();
        //
        //     // Index outputs (received funds)
        //     for (out_idx, output) in tx.outputs.iter().enumerate() {
        //         let script_hash = sha256(&output.script_pubkey);
        //         self.add_entry(script_hash, AddressIndexEntry {
        //             txid: txid.clone(),
        //             height,
        //             tx_index: tx_idx as u32,
        //             value: output.value as i64,
        //             output_index: out_idx as u32,
        //         });
        //     }
        //
        //     // Index inputs (spent funds) -- skip coinbase
        //     if !tx.is_coinbase() {
        //         for input in tx.inputs.iter() {
        //             let spent_utxo = db.get_utxo(&input.previous_output)?;
        //             let script_hash = sha256(&spent_utxo.script_pubkey);
        //             // Use the *original* outpoint txid so UTXOs can be matched
        //             self.add_entry(script_hash, AddressIndexEntry {
        //                 txid: input.previous_output.txid.clone(),
        //                 height,
        //                 tx_index: tx_idx as u32,
        //                 value: -(spent_utxo.value as i64),
        //                 output_index: input.previous_output.vout,
        //             });
        //         }
        //     }
        // }

        // Simulate: create deterministic entries based on height.
        // Each block produces one output to a script derived from the height,
        // and (for blocks > 1) one spend from the previous block's script.

        let txid = self.make_simulated_txid(height, 0);
        let script_hash = self.make_simulated_script_hash(height);

        // Coinbase output
        self.add_entry(
            script_hash,
            AddressIndexEntry {
                txid: txid.clone(),
                height,
                tx_index: 0,
                value: 50_0000_0000, // 50 BTC coinbase reward
                output_index: 0,
            },
        );

        // Simulate a second transaction that spends from a previous block
        // (only for heights > 1, to avoid spending from non-existent blocks).
        if height > 1 {
            let tx2id = self.make_simulated_txid(height, 1);
            let prev_script_hash = self.make_simulated_script_hash(height - 1);
            // The original output's txid (coinbase from the previous block).
            let prev_coinbase_txid = self.make_simulated_txid(height - 1, 0);

            // Spend from previous block's script -- use original outpoint txid
            self.add_entry(
                prev_script_hash,
                AddressIndexEntry {
                    txid: prev_coinbase_txid,
                    height,
                    tx_index: 1,
                    value: -25_0000_0000, // Spend 25 BTC
                    output_index: 0,
                },
            );

            // Output to a new script in this block
            let new_script_hash = self.make_simulated_script_hash(height * 1000);
            self.add_entry(
                new_script_hash,
                AddressIndexEntry {
                    txid: tx2id,
                    height,
                    tx_index: 1,
                    value: 25_0000_0000, // 25 BTC output
                    output_index: 0,
                },
            );
        }

        Ok(())
    }

    /// Remove index entries for a single block.
    fn deindex_block(&mut self, height: u64) -> Result<(), StageError> {
        // Remove all entries at this height from every script hash.
        self.index.retain(|_, entries| {
            entries.retain(|e| e.height != height);
            !entries.is_empty()
        });

        Ok(())
    }

    /// Create a deterministic simulated txid from height and tx position.
    fn make_simulated_txid(&self, height: u64, tx_pos: u32) -> TxHash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&height.to_le_bytes());
        bytes[8..12].copy_from_slice(&tx_pos.to_le_bytes());
        TxHash::from_bytes(bytes)
    }

    /// Create a deterministic simulated script hash from height.
    fn make_simulated_script_hash(&self, height: u64) -> [u8; 32] {
        let mut hash = [0u8; 32];
        let height_bytes = height.to_le_bytes();
        // Use a different prefix than txid to avoid collisions.
        hash[0] = 0xff;
        hash[1..9].copy_from_slice(&height_bytes);
        hash
    }
}

impl Default for AddressIndexStage {
    fn default() -> Self {
        Self::new()
    }
}

impl Stage for AddressIndexStage {
    fn id(&self) -> StageId {
        ADDRESS_INDEX
    }

    /// Execute the address indexing stage: build the address index from the
    /// current checkpoint up to `target`.
    fn execute(&mut self, target: u64) -> Result<ExecOutput, StageError> {
        if self.checkpoint >= target {
            return Ok(ExecOutput {
                checkpoint: self.checkpoint,
                done: true,
            });
        }

        let from = self.checkpoint + 1;
        let batch_end = std::cmp::min(from + ADDRESS_INDEX_BATCH_SIZE - 1, target);

        info!(from, to = batch_end, "indexing addresses");

        for height in from..=batch_end {
            self.index_block(height)?;
        }

        self.checkpoint = batch_end;
        let done = batch_end >= target;

        info!(
            checkpoint = self.checkpoint,
            scripts = self.index.len(),
            done,
            "address indexing batch complete"
        );

        Ok(ExecOutput {
            checkpoint: self.checkpoint,
            done,
        })
    }

    /// Unwind the address indexing stage: remove index entries back to `target` height.
    fn unwind(&mut self, target: u64) -> Result<UnwindOutput, StageError> {
        if target >= self.checkpoint {
            return Ok(UnwindOutput {
                checkpoint: self.checkpoint,
            });
        }

        info!(
            from = self.checkpoint,
            to = target,
            "unwinding address index stage"
        );

        for height in (target + 1..=self.checkpoint).rev() {
            self.deindex_block(height)?;
        }

        self.checkpoint = target;

        Ok(UnwindOutput {
            checkpoint: target,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_index_stage_new() {
        let stage = AddressIndexStage::new();
        assert_eq!(stage.checkpoint(), 0);
        assert_eq!(stage.index_size(), 0);
        assert_eq!(stage.total_entries(), 0);
    }

    #[test]
    fn test_address_index_stage_id() {
        let stage = AddressIndexStage::new();
        assert_eq!(stage.id(), ADDRESS_INDEX);
    }

    #[test]
    fn test_indexing_block_with_outputs_creates_entries() {
        let mut stage = AddressIndexStage::new();
        stage.execute(1).unwrap();

        // Block 1 should create a coinbase output entry.
        let script_hash = stage.make_simulated_script_hash(1);
        let history = stage.get_history(&script_hash);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].height, 1);
        assert_eq!(history[0].value, 50_0000_0000);
        assert_eq!(history[0].tx_index, 0);
        assert_eq!(history[0].output_index, 0);
    }

    #[test]
    fn test_get_history_returns_correct_entries() {
        let mut stage = AddressIndexStage::new();
        stage.execute(3).unwrap();

        // Block 1's script should have:
        // - The coinbase output from block 1 (positive)
        // - A spend entry from block 2 (negative)
        let script_hash = stage.make_simulated_script_hash(1);
        let history = stage.get_history(&script_hash);
        assert_eq!(history.len(), 2);

        // First entry: coinbase output at height 1
        assert_eq!(history[0].height, 1);
        assert_eq!(history[0].value, 50_0000_0000);

        // Second entry: spend at height 2
        assert_eq!(history[1].height, 2);
        assert_eq!(history[1].value, -25_0000_0000);
    }

    #[test]
    fn test_get_balance_sums_correctly() {
        let mut stage = AddressIndexStage::new();
        stage.execute(3).unwrap();

        // Block 1's script: received 50 BTC, spent 25 BTC -> balance = 25 BTC
        let script_hash = stage.make_simulated_script_hash(1);
        let balance = stage.get_balance(&script_hash);
        assert_eq!(balance, 50_0000_0000 - 25_0000_0000);

        // Block 3's script: only received 50 BTC coinbase -> balance = 50 BTC
        let script_hash_3 = stage.make_simulated_script_hash(3);
        let balance_3 = stage.get_balance(&script_hash_3);
        assert_eq!(balance_3, 50_0000_0000);

        // Non-existent script: balance = 0
        let missing = [0xab; 32];
        assert_eq!(stage.get_balance(&missing), 0);
    }

    #[test]
    fn test_unwind_removes_entries() {
        let mut stage = AddressIndexStage::new();
        stage.execute(5).unwrap();

        let entries_before = stage.total_entries();
        assert!(entries_before > 0);

        // Unwind back to height 2.
        let result = stage.unwind(2).unwrap();
        assert_eq!(result.checkpoint, 2);
        assert_eq!(stage.checkpoint(), 2);

        // Entries for heights 3-5 should be removed.
        let script_hash_3 = stage.make_simulated_script_hash(3);
        assert!(stage.get_history(&script_hash_3).is_empty());

        let script_hash_5 = stage.make_simulated_script_hash(5);
        assert!(stage.get_history(&script_hash_5).is_empty());

        // Entries for heights 1-2 should still exist.
        let script_hash_1 = stage.make_simulated_script_hash(1);
        assert!(!stage.get_history(&script_hash_1).is_empty());
    }

    #[test]
    fn test_multiple_transactions_in_one_block() {
        let mut stage = AddressIndexStage::new();
        stage.execute(2).unwrap();

        // Block 2 should have:
        // 1. Coinbase output (tx_index=0) -> block 2's script
        // 2. Spend from block 1's script (tx_index=1)
        // 3. Output to a new script (tx_index=1)

        // Check block 2's coinbase script has an entry
        let script_hash_2 = stage.make_simulated_script_hash(2);
        let history_2 = stage.get_history(&script_hash_2);
        assert_eq!(history_2.len(), 1);
        assert_eq!(history_2[0].tx_index, 0);
        assert_eq!(history_2[0].value, 50_0000_0000);

        // Check block 1's script has the spend entry from block 2
        let script_hash_1 = stage.make_simulated_script_hash(1);
        let history_1 = stage.get_history(&script_hash_1);
        assert_eq!(history_1.len(), 2);
        // The spend entry
        let spend_entry = &history_1[1];
        assert_eq!(spend_entry.height, 2);
        assert_eq!(spend_entry.tx_index, 1);
        assert_eq!(spend_entry.value, -25_0000_0000);

        // Check the new output script from the second tx in block 2
        let new_script = stage.make_simulated_script_hash(2 * 1000);
        let new_history = stage.get_history(&new_script);
        assert_eq!(new_history.len(), 1);
        assert_eq!(new_history[0].tx_index, 1);
        assert_eq!(new_history[0].value, 25_0000_0000);
    }

    #[test]
    fn test_get_utxos_filters_spent() {
        let mut stage = AddressIndexStage::new();
        stage.execute(3).unwrap();

        // Block 1's script received 50 BTC and had 25 BTC spent.
        // The spend entry has the same output_index (0) as the receive,
        // so the UTXO should be filtered out.
        let script_hash_1 = stage.make_simulated_script_hash(1);
        let utxos = stage.get_utxos(&script_hash_1);
        assert!(utxos.is_empty());

        // Block 3's script only has the coinbase output (no spend yet).
        let script_hash_3 = stage.make_simulated_script_hash(3);
        let utxos_3 = stage.get_utxos(&script_hash_3);
        assert_eq!(utxos_3.len(), 1);
        assert_eq!(utxos_3[0].value, 50_0000_0000);
    }

    #[test]
    fn test_execute_already_synced() {
        let mut stage = AddressIndexStage::new();
        stage.execute(100).unwrap();

        let result = stage.execute(50).unwrap();
        assert_eq!(result.checkpoint, 100);
        assert!(result.done);
    }

    #[test]
    fn test_execute_batching() {
        let mut stage = AddressIndexStage::new();
        let result = stage.execute(1500).unwrap();
        assert_eq!(result.checkpoint, ADDRESS_INDEX_BATCH_SIZE);
        assert!(!result.done);

        let result = stage.execute(1500).unwrap();
        assert_eq!(result.checkpoint, 1500);
        assert!(result.done);
    }

    #[test]
    fn test_unwind_noop_when_below() {
        let mut stage = AddressIndexStage::new();
        stage.execute(100).unwrap();

        let entries = stage.total_entries();
        let result = stage.unwind(200).unwrap();
        assert_eq!(result.checkpoint, 100);
        assert_eq!(stage.total_entries(), entries);
    }

    #[test]
    fn test_unwind_to_zero() {
        let mut stage = AddressIndexStage::new();
        stage.execute(50).unwrap();
        assert!(stage.total_entries() > 0);

        stage.unwind(0).unwrap();
        assert_eq!(stage.checkpoint(), 0);
        assert_eq!(stage.total_entries(), 0);
        assert_eq!(stage.index_size(), 0);
    }

    #[test]
    fn test_get_history_empty_for_unknown_script() {
        let stage = AddressIndexStage::new();
        let missing = [0xff; 32];
        assert!(stage.get_history(&missing).is_empty());
    }

    #[test]
    fn test_execute_then_execute_further() {
        let mut stage = AddressIndexStage::new();
        stage.execute(5).unwrap();
        let entries_at_5 = stage.total_entries();

        stage.execute(10).unwrap();
        let entries_at_10 = stage.total_entries();
        assert!(entries_at_10 > entries_at_5);
        assert_eq!(stage.checkpoint(), 10);
    }

    #[test]
    fn test_add_entry_directly() {
        let mut stage = AddressIndexStage::new();
        let script_hash = [0xaa; 32];
        let txid = TxHash::from_bytes([0xbb; 32]);

        stage.add_entry(
            script_hash,
            AddressIndexEntry {
                txid: txid.clone(),
                height: 42,
                tx_index: 0,
                value: 100_000,
                output_index: 0,
            },
        );

        let history = stage.get_history(&script_hash);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].txid, txid);
        assert_eq!(history[0].height, 42);
        assert_eq!(history[0].value, 100_000);

        assert_eq!(stage.get_balance(&script_hash), 100_000);
    }
}
