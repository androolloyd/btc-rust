//! Provider-driven validation work. No fabricated records or height-only success.
use crate::stage::{ExecOutput, Stage, StageBackend, StageError, StageId, VALIDATION};
pub type UtxoChange = btc_consensus::utxo::UtxoSetUpdate;

#[derive(Default)]
pub struct ExecutionStage;
impl ExecutionStage {
    pub fn new() -> Self {
        Self
    }
}
impl Stage for ExecutionStage {
    fn id(&self) -> StageId {
        VALIDATION
    }
    fn execute_with(
        &mut self,
        backend: &mut dyn StageBackend,
        target: u64,
    ) -> Result<ExecOutput, StageError> {
        backend.execute(VALIDATION, target, 500)
    }
}
