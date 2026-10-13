//! Provider-driven address_index work. No fabricated records or height-only success.
use crate::stage::{ExecOutput, Stage, StageBackend, StageError, StageId, ADDRESS_INDEX};
pub type AddressIndexEntry = btc_storage::traits::ScriptHistoryEntry;

#[derive(Default)]
pub struct AddressIndexStage;
impl AddressIndexStage {
    pub fn new() -> Self {
        Self
    }
}
impl Stage for AddressIndexStage {
    fn id(&self) -> StageId {
        ADDRESS_INDEX
    }
    fn execute_with(
        &mut self,
        backend: &mut dyn StageBackend,
        target: u64,
    ) -> Result<ExecOutput, StageError> {
        backend.execute(ADDRESS_INDEX, target, 1000)
    }
}
