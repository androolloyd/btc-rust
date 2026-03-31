use crate::stage::{ExecOutput, Stage, StageError, StageId, UnwindOutput, VALIDATION};
use tracing::info;

/// Maximum number of blocks to validate in a single batch.
const EXECUTION_BATCH_SIZE: u64 = 500;

/// Represents a UTXO change applied during block execution.
/// Stored as undo data to allow rewinding the UTXO set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtxoChange {
    /// A UTXO was created at this height (outpoint index within the block).
    Created {
        height: u64,
        tx_index: u32,
        output_index: u32,
    },
    /// A UTXO was spent at this height (original creation info for undo).
    Spent {
        height: u64,
        tx_index: u32,
        input_index: u32,
    },
}

/// Execution stage -- validates blocks and updates the UTXO set.
///
/// This is where the core consensus validation happens:
/// - For each block from the current checkpoint to the target:
///   1. Validate all transactions (script verification would go here)
///   2. Update the UTXO set (add new outputs, remove spent outputs)
///   3. Verify the coinbase reward does not exceed the allowed subsidy + fees
///
/// Depends on both the Headers and Bodies stages having run first.
pub struct ExecutionStage {
    /// Current execution progress -- the height up to which blocks have been validated.
    checkpoint: u64,
    /// Undo data for reverting UTXO changes. Keyed by block height.
    undo_log: Vec<(u64, Vec<UtxoChange>)>,
}

impl ExecutionStage {
    pub fn new() -> Self {
        ExecutionStage {
            checkpoint: 0,
            undo_log: Vec::new(),
        }
    }

    /// Return the current checkpoint height.
    pub fn checkpoint(&self) -> u64 {
        self.checkpoint
    }

    /// Return a reference to the undo log (for testing).
    pub fn undo_log(&self) -> &[(u64, Vec<UtxoChange>)] {
        &self.undo_log
    }

    /// Simulate executing a single block.
    ///
    /// In a real implementation this would:
    /// 1. Load the block (header + body) from the database
    /// 2. For each non-coinbase transaction:
    ///    a. Look up each input's UTXO in the UTXO set
    ///    b. Verify the script (scriptSig + scriptPubKey) evaluates to true
    ///    c. Sum input values and verify they cover the output values
    ///    d. Remove spent UTXOs from the UTXO set
    /// 3. For each transaction output: add it to the UTXO set
    /// 4. Verify coinbase value <= block_subsidy(height) + total_fees
    /// 5. Store undo data for this block
    fn execute_block(&mut self, height: u64) -> Result<(), StageError> {
        // In a real implementation:
        //
        // let block = db.get_block(height)?;
        // let mut total_fees: i64 = 0;
        //
        // for (tx_idx, tx) in block.transactions.iter().enumerate() {
        //     if tx.is_coinbase() { continue; }
        //
        //     let mut input_sum = Amount::ZERO;
        //     for (in_idx, input) in tx.inputs.iter().enumerate() {
        //         let utxo = db.get_utxo(&input.previous_output)?
        //             .ok_or(StageError::Consensus("missing UTXO".into()))?;
        //         input_sum = input_sum + utxo.value;
        //
        //         // Script verification would happen here:
        //         // ScriptEngine::verify(&input.script_sig, &utxo.script_pubkey, tx, in_idx)?;
        //
        //         // Record the spend for undo
        //         undo_changes.push(UtxoChange::Spent {
        //             height, tx_index: tx_idx as u32, input_index: in_idx as u32,
        //         });
        //         db.delete_utxo(&input.previous_output)?;
        //     }
        //
        //     let output_sum: Amount = tx.outputs.iter()
        //         .map(|o| o.value)
        //         .fold(Amount::ZERO, |a, b| a + b);
        //
        //     if input_sum < output_sum {
        //         return Err(StageError::Consensus("outputs exceed inputs".into()));
        //     }
        //     total_fees += (input_sum - output_sum).as_sat();
        //
        //     for (out_idx, _output) in tx.outputs.iter().enumerate() {
        //         undo_changes.push(UtxoChange::Created {
        //             height, tx_index: tx_idx as u32, output_index: out_idx as u32,
        //         });
        //         // db.put_utxo(&OutPoint::new(tx.txid(), out_idx as u32), output)?;
        //     }
        // }
        //
        // // Verify coinbase reward
        // let coinbase = &block.transactions[0];
        // let coinbase_value: Amount = coinbase.outputs.iter()
        //     .map(|o| o.value)
        //     .fold(Amount::ZERO, |a, b| a + b);
        // let max_reward = block_subsidy(height) + Amount::from_sat(total_fees);
        // if coinbase_value > max_reward {
        //     return Err(StageError::Consensus("coinbase reward too high".into()));
        // }

        // Simulate: record undo data for this block.
        let undo_changes = vec![
            UtxoChange::Created {
                height,
                tx_index: 0,
                output_index: 0,
            },
        ];
        self.undo_log.push((height, undo_changes));

        Ok(())
    }

    /// Reverse the UTXO changes for a single block using undo data.
    ///
    /// In a real implementation this would:
    /// - For each `Created` entry: remove the UTXO from the set
    /// - For each `Spent` entry: restore the UTXO to the set
    fn undo_block(&mut self, height: u64) -> Result<(), StageError> {
        // Find undo data for this height.
        if let Some(pos) = self.undo_log.iter().position(|(h, _)| *h == height) {
            let (_h, _changes) = self.undo_log.remove(pos);

            // In a real implementation:
            // for change in changes.iter().rev() {
            //     match change {
            //         UtxoChange::Created { .. } => {
            //             // Remove the UTXO that was created
            //             // db.delete_utxo(&outpoint)?;
            //         }
            //         UtxoChange::Spent { .. } => {
            //             // Restore the UTXO that was spent
            //             // db.put_utxo(&outpoint, &txout)?;
            //         }
            //     }
            // }
        }

        Ok(())
    }
}

impl Default for ExecutionStage {
    fn default() -> Self {
        Self::new()
    }
}

impl Stage for ExecutionStage {
    fn id(&self) -> StageId {
        VALIDATION
    }

    /// Execute the validation stage: validate blocks and update the UTXO set
    /// from the current checkpoint up to `target`.
    fn execute(&mut self, target: u64) -> Result<ExecOutput, StageError> {
        if self.checkpoint >= target {
            return Ok(ExecOutput {
                checkpoint: self.checkpoint,
                done: true,
            });
        }

        let from = self.checkpoint + 1;
        let batch_end = std::cmp::min(from + EXECUTION_BATCH_SIZE - 1, target);

        info!(from, to = batch_end, "executing blocks");

        for height in from..=batch_end {
            self.execute_block(height)?;
        }

        self.checkpoint = batch_end;
        let done = batch_end >= target;

        info!(checkpoint = self.checkpoint, done, "execution batch complete");

        Ok(ExecOutput {
            checkpoint: self.checkpoint,
            done,
        })
    }

    /// Unwind the execution stage: reverse UTXO changes back to `target` height.
    fn unwind(&mut self, target: u64) -> Result<UnwindOutput, StageError> {
        if target >= self.checkpoint {
            return Ok(UnwindOutput {
                checkpoint: self.checkpoint,
            });
        }

        info!(
            from = self.checkpoint,
            to = target,
            "unwinding execution stage"
        );

        // Undo blocks in reverse order.
        for height in (target + 1..=self.checkpoint).rev() {
            self.undo_block(height)?;
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
    fn test_execution_stage_new() {
        let stage = ExecutionStage::new();
        assert_eq!(stage.checkpoint(), 0);
        assert!(stage.undo_log().is_empty());
    }

    #[test]
    fn test_execution_execute_basic() {
        let mut stage = ExecutionStage::new();
        let result = stage.execute(10).unwrap();
        assert_eq!(result.checkpoint, 10);
        assert!(result.done);
        assert_eq!(stage.checkpoint(), 10);
        // Should have undo data for each block.
        assert_eq!(stage.undo_log().len(), 10);
    }

    #[test]
    fn test_execution_execute_already_synced() {
        let mut stage = ExecutionStage::new();
        stage.execute(100).unwrap();

        let result = stage.execute(50).unwrap();
        assert_eq!(result.checkpoint, 100);
        assert!(result.done);
    }

    #[test]
    fn test_execution_execute_batching() {
        let mut stage = ExecutionStage::new();
        let result = stage.execute(1000).unwrap();
        assert_eq!(result.checkpoint, EXECUTION_BATCH_SIZE);
        assert!(!result.done);

        let result = stage.execute(1000).unwrap();
        assert_eq!(result.checkpoint, 1000);
        assert!(result.done);
    }

    #[test]
    fn test_execution_unwind() {
        let mut stage = ExecutionStage::new();
        stage.execute(100).unwrap();
        assert_eq!(stage.undo_log().len(), 100);

        let result = stage.unwind(50).unwrap();
        assert_eq!(result.checkpoint, 50);
        assert_eq!(stage.checkpoint(), 50);
        // Undo data for heights 51-100 should be removed.
        assert_eq!(stage.undo_log().len(), 50);
    }

    #[test]
    fn test_execution_unwind_noop_when_below() {
        let mut stage = ExecutionStage::new();
        stage.execute(100).unwrap();

        let result = stage.unwind(200).unwrap();
        assert_eq!(result.checkpoint, 100);
        assert_eq!(stage.undo_log().len(), 100);
    }

    #[test]
    fn test_execution_unwind_to_zero() {
        let mut stage = ExecutionStage::new();
        stage.execute(50).unwrap();

        stage.unwind(0).unwrap();
        assert_eq!(stage.checkpoint(), 0);
        assert!(stage.undo_log().is_empty());
    }

    #[test]
    fn test_execution_stage_id() {
        let stage = ExecutionStage::new();
        assert_eq!(stage.id(), VALIDATION);
    }

    #[test]
    fn test_utxo_change_variants() {
        let created = UtxoChange::Created {
            height: 100,
            tx_index: 0,
            output_index: 0,
        };
        let spent = UtxoChange::Spent {
            height: 100,
            tx_index: 1,
            input_index: 0,
        };
        // Verify they are distinct.
        assert_ne!(created, spent);
    }
}
