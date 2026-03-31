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
}
