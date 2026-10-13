use thiserror::Error;

/// Unique identifier for a pipeline stage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StageId(pub &'static str);

impl std::fmt::Display for StageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Well-known stage IDs
pub const HEADERS: StageId = StageId("Headers");
pub const BODIES: StageId = StageId("Bodies");
pub const VALIDATION: StageId = StageId("Validation");
pub const UTXO_INDEX: StageId = StageId("UtxoIndex");
pub const TX_INDEX: StageId = StageId("TxIndex");
pub const ADDRESS_INDEX: StageId = StageId("AddressIndex");

#[derive(Debug, Error)]
pub enum StageError {
    #[error("actual downloaded data/validated stage provider unavailable")]
    ProviderUnavailable,
    #[error("backend failure ({code}): {message}")]
    Backend { code: i32, message: String },
    #[error("stage {0} failed: {1}")]
    StageFailed(StageId, String),
    #[error("database error: {0}")]
    Database(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("consensus error: {0}")]
    Consensus(String),
    #[error("pipeline aborted")]
    Aborted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageCheckpoint {
    pub height: u64,
    pub hash: btc_primitives::BlockHash,
}

/// One actual downloaded batch. Implementations prepare against isolated state,
/// then commit every stage, coins, undo, indices and tip atomically. `abort` must
/// discard only uncommitted work; it must never erase prior validated progress.
pub trait StageBackend {
    fn execute(
        &mut self,
        stage: StageId,
        target: u64,
        limit: u64,
    ) -> Result<ExecOutput, StageError>;
    fn commit(&mut self) -> Result<StageCheckpoint, StageError>;
    fn abort(&mut self);
}

/// Output from a stage execution
#[derive(Debug)]
pub struct ExecOutput {
    /// The block number up to which this stage has progressed
    pub checkpoint: u64,
    /// Whether there is more work to do (stage should be re-run)
    pub done: bool,
}

/// Output from a stage unwind
#[derive(Debug)]
pub struct UnwindOutput {
    /// The block number to which the stage has unwound
    pub checkpoint: u64,
}

/// Stages prepare an actual input batch serially. The backend owns atomic
/// publication and validated fork undo. Unbound execution/manual unwind fail.
pub trait Stage: Send + Sync {
    /// Unique identifier for this stage
    fn id(&self) -> StageId;

    /// Execute the stage, processing blocks from the current checkpoint
    /// up to the target block number.
    fn execute(&mut self, _target: u64) -> Result<ExecOutput, StageError> {
        Err(StageError::ProviderUnavailable)
    }
    fn execute_with(
        &mut self,
        _backend: &mut dyn StageBackend,
        _target: u64,
    ) -> Result<ExecOutput, StageError> {
        Err(StageError::ProviderUnavailable)
    }

    /// Unwind the stage, reverting changes back to the given block number.
    fn unwind(&mut self, _target: u64) -> Result<UnwindOutput, StageError> {
        Err(StageError::ProviderUnavailable)
    }
}
