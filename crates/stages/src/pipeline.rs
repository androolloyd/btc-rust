use crate::stage::{Stage, StageBackend, StageCheckpoint, StageError, StageId};
use std::collections::HashMap;

/// Real preparation precedes one backend commit. Failed work cannot reset durable history.
#[derive(Default)]
pub struct Pipeline {
    stages: Vec<Box<dyn Stage>>,
    checkpoints: HashMap<StageId, StageCheckpoint>,
}
impl Pipeline {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_stage(&mut self, stage: Box<dyn Stage>) {
        self.stages.push(stage);
    }
    pub fn stage_ids(&self) -> Vec<StageId> {
        self.stages.iter().map(|stage| stage.id()).collect()
    }
    pub fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }
    pub fn run(&mut self, _target: u64) -> Result<(), StageError> {
        Err(StageError::ProviderUnavailable)
    }
    pub fn run_with(
        &mut self,
        backend: &mut dyn StageBackend,
        target: u64,
    ) -> Result<StageCheckpoint, StageError> {
        if self.stages.is_empty() {
            return Err(StageError::ProviderUnavailable);
        }
        let result = (|| {
            for stage in &mut self.stages {
                let output = stage.execute_with(backend, target)?;
                if !output.done || output.checkpoint != target {
                    return Err(StageError::StageFailed(
                        stage.id(),
                        "provider did not finish the actual input batch".into(),
                    ));
                }
            }
            backend.commit()
        })();
        match result {
            Ok(checkpoint) => {
                for stage in &self.stages {
                    self.checkpoints.insert(stage.id(), checkpoint);
                }
                Ok(checkpoint)
            }
            Err(error) => {
                backend.abort();
                Err(error)
            }
        }
    }
    pub fn checkpoint(&self, id: StageId) -> Option<u64> {
        self.checkpoints.get(&id).map(|cp| cp.height)
    }
    pub fn checkpoint_record(&self, id: StageId) -> Option<StageCheckpoint> {
        self.checkpoints.get(&id).copied()
    }
}

#[cfg(test)]
mod tests {
    use crate::{build_default_pipeline, Stage};
    #[test]
    fn absent_downloads_or_provider_never_publish_progress() {
        let mut pipeline = build_default_pipeline();
        for target in [0, 1, u64::MAX] {
            assert!(pipeline.run(target).is_err());
            assert!(pipeline.checkpoint(crate::stage::HEADERS).is_none());
        }
        for mut stage in [
            Box::new(crate::HeadersStage::new()) as Box<dyn Stage>,
            Box::new(crate::BodiesStage::new()),
            Box::new(crate::ExecutionStage::new()),
            Box::new(crate::IndexingStage::new()),
            Box::new(crate::AddressIndexStage::new()),
        ] {
            assert!(stage.execute(100).is_err());
            assert!(stage.unwind(0).is_err());
        }
    }
}
