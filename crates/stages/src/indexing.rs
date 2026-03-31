use crate::stage::{ExecOutput, Stage, StageError, StageId, UnwindOutput, TX_INDEX};
use tracing::info;
use std::collections::HashMap;

/// Maximum number of blocks to index in a single batch.
const INDEXING_BATCH_SIZE: u64 = 1000;

/// A transaction index entry: maps a txid to its location in the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIndexEntry {
    /// The block height containing this transaction.
    pub block_height: u64,
    /// Position of the transaction within the block (0 = coinbase).
    pub tx_position: u32,
}

/// Indexing stage -- builds the transaction index (txid -> block location).
///
/// This is an optional stage used for RPC lookups (e.g. `getrawtransaction`).
/// It maps each transaction hash to its block height and position within that block.
///
/// Depends on the Bodies stage having run first (needs the full transaction data).
pub struct IndexingStage {
    /// Current indexing progress -- the height up to which the index has been built.
    checkpoint: u64,
    /// In-memory transaction index (simulated; a real implementation uses the database).
    tx_index: HashMap<[u8; 32], TxIndexEntry>,
}

impl IndexingStage {
    pub fn new() -> Self {
        IndexingStage {
            checkpoint: 0,
            tx_index: HashMap::new(),
        }
    }

    /// Return the current checkpoint height.
    pub fn checkpoint(&self) -> u64 {
        self.checkpoint
    }

    /// Return the number of indexed transactions (for testing/monitoring).
    pub fn index_size(&self) -> usize {
        self.tx_index.len()
    }

    /// Look up a transaction by its hash in the index.
    pub fn lookup(&self, txid: &[u8; 32]) -> Option<&TxIndexEntry> {
        self.tx_index.get(txid)
    }

    /// Index a single block's transactions.
    ///
    /// In a real implementation this would:
    /// 1. Load the block from the database
    /// 2. For each transaction, compute the txid
    /// 3. Store txid -> (block_hash, block_height, tx_position) in the index table
    fn index_block(&mut self, height: u64) -> Result<(), StageError> {
        // In a real implementation:
        //   let block = db.get_block(height)?;
        //   for (pos, tx) in block.transactions.iter().enumerate() {
        //       let txid = tx.txid();
        //       db.put_tx_index(&txid, &TxIndexEntry {
        //           block_height: height,
        //           tx_position: pos as u32,
        //       })?;
        //   }

        // Simulate: create a deterministic fake txid based on height.
        let mut fake_txid = [0u8; 32];
        let height_bytes = height.to_le_bytes();
        fake_txid[..8].copy_from_slice(&height_bytes);

        self.tx_index.insert(
            fake_txid,
            TxIndexEntry {
                block_height: height,
                tx_position: 0,
            },
        );

        Ok(())
    }

    /// Remove index entries for a single block.
    ///
    /// In a real implementation this would load the block, iterate through its
    /// transactions, and remove each txid from the index table.
    fn deindex_block(&mut self, height: u64) -> Result<(), StageError> {
        // Remove the simulated entry for this height.
        let mut fake_txid = [0u8; 32];
        let height_bytes = height.to_le_bytes();
        fake_txid[..8].copy_from_slice(&height_bytes);
        self.tx_index.remove(&fake_txid);

        Ok(())
    }
}

impl Default for IndexingStage {
    fn default() -> Self {
        Self::new()
    }
}

impl Stage for IndexingStage {
    fn id(&self) -> StageId {
        TX_INDEX
    }

    /// Execute the indexing stage: build the transaction index from the current
    /// checkpoint up to `target`.
    fn execute(&mut self, target: u64) -> Result<ExecOutput, StageError> {
        if self.checkpoint >= target {
            return Ok(ExecOutput {
                checkpoint: self.checkpoint,
                done: true,
            });
        }

        let from = self.checkpoint + 1;
        let batch_end = std::cmp::min(from + INDEXING_BATCH_SIZE - 1, target);

        info!(from, to = batch_end, "indexing transactions");

        for height in from..=batch_end {
            self.index_block(height)?;
        }

        self.checkpoint = batch_end;
        let done = batch_end >= target;

        info!(
            checkpoint = self.checkpoint,
            indexed = self.tx_index.len(),
            done,
            "indexing batch complete"
        );

        Ok(ExecOutput {
            checkpoint: self.checkpoint,
            done,
        })
    }

    /// Unwind the indexing stage: remove index entries back to `target` height.
    fn unwind(&mut self, target: u64) -> Result<UnwindOutput, StageError> {
        if target >= self.checkpoint {
            return Ok(UnwindOutput {
                checkpoint: self.checkpoint,
            });
        }

        info!(
            from = self.checkpoint,
            to = target,
            "unwinding indexing stage"
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
    fn test_indexing_stage_new() {
        let stage = IndexingStage::new();
        assert_eq!(stage.checkpoint(), 0);
        assert_eq!(stage.index_size(), 0);
    }

    #[test]
    fn test_indexing_execute_basic() {
        let mut stage = IndexingStage::new();
        let result = stage.execute(10).unwrap();
        assert_eq!(result.checkpoint, 10);
        assert!(result.done);
        assert_eq!(stage.index_size(), 10);
    }

    #[test]
    fn test_indexing_lookup() {
        let mut stage = IndexingStage::new();
        stage.execute(5).unwrap();

        // Look up the simulated txid for height 3.
        let mut txid = [0u8; 32];
        txid[..8].copy_from_slice(&3u64.to_le_bytes());

        let entry = stage.lookup(&txid).unwrap();
        assert_eq!(entry.block_height, 3);
        assert_eq!(entry.tx_position, 0);
    }

    #[test]
    fn test_indexing_execute_already_synced() {
        let mut stage = IndexingStage::new();
        stage.execute(100).unwrap();

        let result = stage.execute(50).unwrap();
        assert_eq!(result.checkpoint, 100);
        assert!(result.done);
    }

    #[test]
    fn test_indexing_execute_batching() {
        let mut stage = IndexingStage::new();
        let result = stage.execute(1500).unwrap();
        assert_eq!(result.checkpoint, INDEXING_BATCH_SIZE);
        assert!(!result.done);

        let result = stage.execute(1500).unwrap();
        assert_eq!(result.checkpoint, 1500);
        assert!(result.done);
        assert_eq!(stage.index_size(), 1500);
    }

    #[test]
    fn test_indexing_unwind() {
        let mut stage = IndexingStage::new();
        stage.execute(100).unwrap();
        assert_eq!(stage.index_size(), 100);

        let result = stage.unwind(50).unwrap();
        assert_eq!(result.checkpoint, 50);
        assert_eq!(stage.checkpoint(), 50);
        assert_eq!(stage.index_size(), 50);
    }

    #[test]
    fn test_indexing_unwind_noop_when_below() {
        let mut stage = IndexingStage::new();
        stage.execute(100).unwrap();

        let result = stage.unwind(200).unwrap();
        assert_eq!(result.checkpoint, 100);
        assert_eq!(stage.index_size(), 100);
    }

    #[test]
    fn test_indexing_unwind_to_zero() {
        let mut stage = IndexingStage::new();
        stage.execute(50).unwrap();

        stage.unwind(0).unwrap();
        assert_eq!(stage.checkpoint(), 0);
        assert_eq!(stage.index_size(), 0);
    }

    #[test]
    fn test_indexing_stage_id() {
        let stage = IndexingStage::new();
        assert_eq!(stage.id(), TX_INDEX);
    }

    #[test]
    fn test_indexing_lookup_missing() {
        let stage = IndexingStage::new();
        let missing = [0xffu8; 32];
        assert!(stage.lookup(&missing).is_none());
    }
}
