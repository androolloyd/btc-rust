pub mod address_index;
pub mod bodies;
pub mod execution;
pub mod headers;
pub mod indexing;
pub mod pipeline;
pub mod stage;

pub use address_index::{AddressIndexEntry, AddressIndexStage};
pub use bodies::{BodiesStage, BodiesSyncState};
pub use execution::{ExecutionStage, UtxoChange};
pub use headers::{HeadersStage, HeadersSyncState};
pub use indexing::{IndexingStage, TxIndexEntry};
pub use pipeline::Pipeline;
pub use stage::{
    ExecOutput, Stage, StageBackend, StageCheckpoint, StageError, StageId, UnwindOutput,
};

/// Build the default sync pipeline with all standard stages.
///
/// The pipeline stages run in order:
/// 1. **Headers** -- validate actual downloaded headers and fork ancestry
/// 2. **Bodies** -- validate actual downloaded bodies against their headers
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
