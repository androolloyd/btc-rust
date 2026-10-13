//! Provider-driven tx_index work. No fabricated records or height-only success.
use crate::stage::{ExecOutput, Stage, StageBackend, StageError, StageId, TX_INDEX};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIndexEntry {
    pub block_hash: btc_primitives::BlockHash,
    pub block_height: u64,
    pub tx_position: u32,
}

#[derive(Default)]
pub struct IndexingStage;
impl IndexingStage {
    pub fn new() -> Self {
        Self
    }
}
impl Stage for IndexingStage {
    fn id(&self) -> StageId {
        TX_INDEX
    }
    fn execute_with(
        &mut self,
        backend: &mut dyn StageBackend,
        target: u64,
    ) -> Result<ExecOutput, StageError> {
        backend.execute(TX_INDEX, target, 1000)
    }
}
