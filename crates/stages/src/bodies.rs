//! Provider-driven bodies work. No fabricated records or height-only success.
use crate::stage::{ExecOutput, Stage, StageBackend, StageError, StageId, BODIES};
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodiesSyncState {
    Idle,
    Downloading { from: u64, to: u64 },
    Validating,
    Done,
}

#[derive(Default)]
pub struct BodiesStage;
impl BodiesStage {
    pub fn new() -> Self {
        Self
    }
}
impl Stage for BodiesStage {
    fn id(&self) -> StageId {
        BODIES
    }
    fn execute_with(
        &mut self,
        backend: &mut dyn StageBackend,
        target: u64,
    ) -> Result<ExecOutput, StageError> {
        backend.execute(BODIES, target, 128)
    }
}
