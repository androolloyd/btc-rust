//! Provider-driven headers work. No fabricated records or height-only success.
use crate::stage::{ExecOutput, Stage, StageBackend, StageError, StageId, HEADERS};
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadersSyncState {
    Idle,
    Requesting { from: u64, to: u64 },
    Processing,
    Done,
}

#[derive(Default)]
pub struct HeadersStage;
impl HeadersStage {
    pub fn new() -> Self {
        Self
    }
}
impl Stage for HeadersStage {
    fn id(&self) -> StageId {
        HEADERS
    }
    fn execute_with(
        &mut self,
        backend: &mut dyn StageBackend,
        target: u64,
    ) -> Result<ExecOutput, StageError> {
        backend.execute(HEADERS, target, 2000)
    }
}
