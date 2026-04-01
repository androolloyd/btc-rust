pub mod pipeline;
pub mod stage;
pub mod headers;
pub mod bodies;
pub mod execution;
pub mod indexing;
pub mod address_index;

pub use pipeline::Pipeline;
pub use stage::{Stage, StageId, StageError, ExecOutput, UnwindOutput};
pub use headers::{HeadersStage, HeadersSyncState};
pub use bodies::{BodiesStage, BodiesSyncState};
pub use execution::{ExecutionStage, UtxoChange};
pub use indexing::{IndexingStage, TxIndexEntry};
pub use address_index::{AddressIndexStage, AddressIndexEntry};

/// Build the default sync pipeline with all standard stages.
///
/// The pipeline stages run in order:
/// 1. **Headers** -- download and validate block headers
/// 2. **Bodies** -- download block bodies (transactions) for stored headers
/// 3. **Execution** -- validate transactions and update the UTXO set
/// 4. **Indexing** -- build the transaction index for RPC lookups
/// 5. **AddressIndex** -- build the address/script index for balance and history lookups
pub fn build_default_pipeline() -> Pipeline {
    let mut pipeline = Pipeline::new();
    pipeline.add_stage(Box::new(HeadersStage::new()));
    pipeline.add_stage(Box::new(BodiesStage::new()));
    pipeline.add_stage(Box::new(ExecutionStage::new()));
    pipeline.add_stage(Box::new(IndexingStage::new()));
    pipeline.add_stage(Box::new(AddressIndexStage::new()));
    pipeline
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stage::{HEADERS, BODIES, VALIDATION, TX_INDEX, ADDRESS_INDEX};

    #[test]
    fn test_build_default_pipeline() {
        let pipeline = build_default_pipeline();
        // Pipeline should be constructible without error.
        // Checkpoint for all stages should be None (not yet run).
        assert_eq!(pipeline.checkpoint(HEADERS), None);
        assert_eq!(pipeline.checkpoint(BODIES), None);
        assert_eq!(pipeline.checkpoint(VALIDATION), None);
        assert_eq!(pipeline.checkpoint(TX_INDEX), None);
        assert_eq!(pipeline.checkpoint(ADDRESS_INDEX), None);
    }

    #[test]
    fn test_default_pipeline_runs_to_completion() {
        let mut pipeline = build_default_pipeline();
        let result = pipeline.run(100);
        assert!(result.is_ok(), "pipeline should complete without error");

        assert_eq!(pipeline.checkpoint(HEADERS), Some(100));
        assert_eq!(pipeline.checkpoint(BODIES), Some(100));
        assert_eq!(pipeline.checkpoint(VALIDATION), Some(100));
        assert_eq!(pipeline.checkpoint(TX_INDEX), Some(100));
        assert_eq!(pipeline.checkpoint(ADDRESS_INDEX), Some(100));
    }

    #[test]
    fn test_default_pipeline_target_zero() {
        let mut pipeline = build_default_pipeline();
        let result = pipeline.run(0);
        assert!(result.is_ok());

        // All stages should report checkpoint 0 (already synced).
        assert_eq!(pipeline.checkpoint(HEADERS), Some(0));
        assert_eq!(pipeline.checkpoint(BODIES), Some(0));
        assert_eq!(pipeline.checkpoint(VALIDATION), Some(0));
        assert_eq!(pipeline.checkpoint(TX_INDEX), Some(0));
        assert_eq!(pipeline.checkpoint(ADDRESS_INDEX), Some(0));
    }

    #[test]
    fn test_pipeline_unwinds_on_failure() {
        use crate::stage::{Stage, StageId, ExecOutput, UnwindOutput, StageError};

        struct FailingStage;

        impl Stage for FailingStage {
            fn id(&self) -> StageId {
                StageId("Failing")
            }
            fn execute(&mut self, _target: u64) -> Result<ExecOutput, StageError> {
                Err(StageError::Consensus("intentional failure".into()))
            }
            fn unwind(&mut self, target: u64) -> Result<UnwindOutput, StageError> {
                Ok(UnwindOutput { checkpoint: target })
            }
        }

        let mut pipeline = Pipeline::new();
        pipeline.add_stage(Box::new(HeadersStage::new()));
        pipeline.add_stage(Box::new(BodiesStage::new()));
        pipeline.add_stage(Box::new(FailingStage)); // This will fail
        pipeline.add_stage(Box::new(IndexingStage::new()));

        let result = pipeline.run(100);
        assert!(result.is_err());

        // Headers and Bodies should be unwound to 0.
        assert_eq!(pipeline.checkpoint(HEADERS), Some(0));
        assert_eq!(pipeline.checkpoint(BODIES), Some(0));

        // The failing stage itself gets unwound too (index 2 is included).
        // Indexing and AddressIndex stages were never executed, so no checkpoint for them.
        assert_eq!(pipeline.checkpoint(TX_INDEX), None);
        assert_eq!(pipeline.checkpoint(ADDRESS_INDEX), None);
    }

    #[test]
    fn test_each_stage_independently() {
        // Headers
        let mut headers = HeadersStage::new();
        assert_eq!(headers.id(), HEADERS);
        let out = headers.execute(50).unwrap();
        assert_eq!(out.checkpoint, 50);
        assert!(out.done);
        let uw = headers.unwind(25).unwrap();
        assert_eq!(uw.checkpoint, 25);

        // Bodies
        let mut bodies = BodiesStage::new();
        assert_eq!(bodies.id(), BODIES);
        let out = bodies.execute(50).unwrap();
        assert_eq!(out.checkpoint, 50);
        assert!(out.done);
        let uw = bodies.unwind(25).unwrap();
        assert_eq!(uw.checkpoint, 25);

        // Execution
        let mut exec = ExecutionStage::new();
        assert_eq!(exec.id(), VALIDATION);
        let out = exec.execute(50).unwrap();
        assert_eq!(out.checkpoint, 50);
        assert!(out.done);
        let uw = exec.unwind(25).unwrap();
        assert_eq!(uw.checkpoint, 25);

        // Indexing
        let mut idx = IndexingStage::new();
        assert_eq!(idx.id(), TX_INDEX);
        let out = idx.execute(50).unwrap();
        assert_eq!(out.checkpoint, 50);
        assert!(out.done);
        let uw = idx.unwind(25).unwrap();
        assert_eq!(uw.checkpoint, 25);

        // Address Index
        let mut addr_idx = AddressIndexStage::new();
        assert_eq!(addr_idx.id(), ADDRESS_INDEX);
        let out = addr_idx.execute(50).unwrap();
        assert_eq!(out.checkpoint, 50);
        assert!(out.done);
        let uw = addr_idx.unwind(25).unwrap();
        assert_eq!(uw.checkpoint, 25);
    }

    #[test]
    fn test_stage_execute_then_execute_further() {
        let mut pipeline = build_default_pipeline();

        // First run to height 50.
        pipeline.run(50).unwrap();
        assert_eq!(pipeline.checkpoint(HEADERS), Some(50));

        // Run again to height 100 -- stages should pick up from 50.
        pipeline.run(100).unwrap();
        assert_eq!(pipeline.checkpoint(HEADERS), Some(100));
        assert_eq!(pipeline.checkpoint(BODIES), Some(100));
        assert_eq!(pipeline.checkpoint(VALIDATION), Some(100));
        assert_eq!(pipeline.checkpoint(TX_INDEX), Some(100));
        assert_eq!(pipeline.checkpoint(ADDRESS_INDEX), Some(100));
    }

    // ---- Additional coverage tests ----

    #[test]
    fn test_stage_id_display() {
        assert_eq!(HEADERS.to_string(), "Headers");
        assert_eq!(BODIES.to_string(), "Bodies");
        assert_eq!(VALIDATION.to_string(), "Validation");
        assert_eq!(TX_INDEX.to_string(), "TxIndex");
        assert_eq!(ADDRESS_INDEX.to_string(), "AddressIndex");
    }

    #[test]
    fn test_stage_error_display() {
        use crate::stage::StageError;
        let e1 = StageError::StageFailed(HEADERS, "reason".into());
        assert!(format!("{}", e1).contains("Headers"));
        let e2 = StageError::Database("db error".into());
        assert!(format!("{}", e2).contains("db error"));
        let e3 = StageError::Network("net error".into());
        assert!(format!("{}", e3).contains("net error"));
        let e4 = StageError::Consensus("bad".into());
        assert!(format!("{}", e4).contains("bad"));
        let e5 = StageError::Aborted;
        assert!(format!("{}", e5).contains("aborted"));
    }

    #[test]
    fn test_pipeline_default() {
        let pipeline = Pipeline::default();
        assert_eq!(pipeline.checkpoint(HEADERS), None);
    }

    #[test]
    fn test_pipeline_checkpoint_missing() {
        let pipeline = Pipeline::new();
        assert_eq!(pipeline.checkpoint(StageId("nonexistent")), None);
    }

    #[test]
    fn test_utxo_index_stage_id() {
        use crate::stage::UTXO_INDEX;
        assert_eq!(UTXO_INDEX.to_string(), "UtxoIndex");
    }

    #[test]
    fn test_exec_output_debug() {
        let out = ExecOutput { checkpoint: 42, done: true };
        let debug = format!("{:?}", out);
        assert!(debug.contains("42"));
    }

    #[test]
    fn test_unwind_output_debug() {
        let out = UnwindOutput { checkpoint: 10 };
        let debug = format!("{:?}", out);
        assert!(debug.contains("10"));
    }

    #[test]
    fn test_headers_stage_default() {
        let stage = HeadersStage::default();
        assert_eq!(stage.checkpoint(), 0);
    }

    #[test]
    fn test_bodies_stage_default() {
        let stage = BodiesStage::default();
        assert_eq!(stage.checkpoint(), 0);
    }

    #[test]
    fn test_execution_stage_default() {
        let stage = ExecutionStage::default();
        assert_eq!(stage.checkpoint(), 0);
    }

    #[test]
    fn test_indexing_stage_default() {
        let stage = IndexingStage::default();
        assert_eq!(stage.checkpoint(), 0);
    }

    #[test]
    fn test_address_index_stage_default() {
        let stage = AddressIndexStage::default();
        assert_eq!(stage.checkpoint(), 0);
    }

    #[test]
    fn test_utxo_change_debug() {
        let created = UtxoChange::Created {
            height: 1,
            tx_index: 0,
            output_index: 0,
        };
        let debug = format!("{:?}", created);
        assert!(debug.contains("Created"));

        let spent = UtxoChange::Spent {
            height: 2,
            tx_index: 1,
            input_index: 0,
        };
        let debug2 = format!("{:?}", spent);
        assert!(debug2.contains("Spent"));
    }

    #[test]
    fn test_utxo_change_clone_eq() {
        let c1 = UtxoChange::Created { height: 1, tx_index: 0, output_index: 0 };
        let c2 = c1.clone();
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_tx_index_entry_debug() {
        let entry = TxIndexEntry { block_height: 100, tx_position: 5 };
        let debug = format!("{:?}", entry);
        assert!(debug.contains("100"));
    }

    #[test]
    fn test_address_index_entry_debug() {
        let entry = AddressIndexEntry {
            txid: btc_primitives::hash::TxHash::from_bytes([0; 32]),
            height: 50,
            tx_index: 0,
            value: 1000,
            output_index: 0,
        };
        let debug = format!("{:?}", entry);
        assert!(debug.contains("50"));
    }

    #[test]
    fn test_headers_sync_state_debug() {
        let idle = HeadersSyncState::Idle;
        assert!(format!("{:?}", idle).contains("Idle"));
        let req = HeadersSyncState::Requesting { from: 1, to: 100 };
        assert!(format!("{:?}", req).contains("Requesting"));
        let proc = HeadersSyncState::Processing;
        assert!(format!("{:?}", proc).contains("Processing"));
        let done = HeadersSyncState::Done;
        assert!(format!("{:?}", done).contains("Done"));
    }

    #[test]
    fn test_bodies_sync_state_debug() {
        let idle = BodiesSyncState::Idle;
        assert!(format!("{:?}", idle).contains("Idle"));
        let dl = BodiesSyncState::Downloading { from: 1, to: 50 };
        assert!(format!("{:?}", dl).contains("Downloading"));
        let val = BodiesSyncState::Validating;
        assert!(format!("{:?}", val).contains("Validating"));
        let done = BodiesSyncState::Done;
        assert!(format!("{:?}", done).contains("Done"));
    }

    #[test]
    fn test_pipeline_with_unwind_failure() {
        use crate::stage::{Stage, StageId, ExecOutput, UnwindOutput, StageError};

        struct FailUnwindStage;

        impl Stage for FailUnwindStage {
            fn id(&self) -> StageId {
                StageId("FailUnwind")
            }
            fn execute(&mut self, _target: u64) -> Result<ExecOutput, StageError> {
                Err(StageError::Consensus("fail".into()))
            }
            fn unwind(&mut self, _target: u64) -> Result<UnwindOutput, StageError> {
                Err(StageError::Database("unwind failed".into()))
            }
        }

        let mut pipeline = Pipeline::new();
        pipeline.add_stage(Box::new(FailUnwindStage));

        let result = pipeline.run(100);
        // Unwind also fails, so the error propagates
        assert!(result.is_err());
    }

    #[test]
    fn test_execution_stage_execute_and_unwind_cycle() {
        let mut stage = ExecutionStage::new();
        stage.execute(50).unwrap();
        assert_eq!(stage.undo_log().len(), 50);

        stage.unwind(25).unwrap();
        assert_eq!(stage.undo_log().len(), 25);

        // Execute more on top
        stage.execute(75).unwrap();
        assert_eq!(stage.undo_log().len(), 75);

        // Unwind past what was re-executed
        stage.unwind(10).unwrap();
        assert_eq!(stage.undo_log().len(), 10);
    }

    #[test]
    fn test_address_index_get_utxos_empty() {
        let stage = AddressIndexStage::new();
        let missing = [0xAA; 32];
        let utxos = stage.get_utxos(&missing);
        assert!(utxos.is_empty());
    }

    #[test]
    fn test_stage_id_copy() {
        let id = HEADERS;
        let id2 = id; // Copy
        assert_eq!(id, id2);
    }

    #[test]
    fn test_stage_id_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(HEADERS);
        set.insert(BODIES);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&HEADERS));
    }

    #[test]
    fn test_headers_stored_headers_tracking() {
        let mut stage = HeadersStage::new();
        stage.execute(5).unwrap();
        // After executing to height 5, stored_headers should contain [1,2,3,4,5]

        stage.unwind(3).unwrap();
        // After unwinding to 3, only [1,2,3] should remain

        stage.execute(7).unwrap();
        // After executing to 7, should add [4,5,6,7]
        assert_eq!(stage.checkpoint(), 7);
    }

    #[test]
    fn test_bodies_range_tracking() {
        let mut stage = BodiesStage::new();
        stage.execute(50).unwrap();
        assert_eq!(stage.bodies_range(), Some((1, 50)));

        // Unwind to 0 clears range
        stage.unwind(0).unwrap();
        assert_eq!(stage.bodies_range(), None);
    }
}
