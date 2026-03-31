use crate::stage::{Stage, StageId, StageError};
use tracing::{info, error};

/// Reth-style pipeline — executes stages serially, unwinds on failure
pub struct Pipeline {
    stages: Vec<Box<dyn Stage>>,
    /// Current progress per stage
    checkpoints: std::collections::HashMap<StageId, u64>,
}

impl Pipeline {
    pub fn new() -> Self {
        Pipeline {
            stages: Vec::new(),
            checkpoints: std::collections::HashMap::new(),
        }
    }

    pub fn add_stage(&mut self, stage: Box<dyn Stage>) {
        self.stages.push(stage);
    }

    /// Run the pipeline up to the target block
    pub fn run(&mut self, target: u64) -> Result<(), StageError> {
        info!(target, "pipeline starting");

        for i in 0..self.stages.len() {
            let stage = &mut self.stages[i];
            let id = stage.id();
            info!(%id, "executing stage");

            match stage.execute(target) {
                Ok(output) => {
                    info!(%id, checkpoint = output.checkpoint, done = output.done, "stage completed");
                    self.checkpoints.insert(id, output.checkpoint);
                }
                Err(e) => {
                    error!(%id, error = %e, "stage failed, unwinding");
                    // Unwind all stages that have run
                    self.unwind(i, 0)?;
                    return Err(e);
                }
            }
        }

        info!("pipeline completed successfully");
        Ok(())
    }

    /// Unwind stages from `from_stage` back to block `target`
    fn unwind(&mut self, from_stage: usize, target: u64) -> Result<(), StageError> {
        for i in (0..=from_stage).rev() {
            let stage = &mut self.stages[i];
            let id = stage.id();
            info!(%id, target, "unwinding stage");
            stage.unwind(target)?;
            self.checkpoints.insert(id, target);
        }
        Ok(())
    }

    pub fn checkpoint(&self, id: StageId) -> Option<u64> {
        self.checkpoints.get(&id).copied()
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stage::{ExecOutput, UnwindOutput};

    struct TestStage {
        id: StageId,
        should_fail: bool,
    }

    impl Stage for TestStage {
        fn id(&self) -> StageId { self.id }

        fn execute(&mut self, target: u64) -> Result<ExecOutput, StageError> {
            if self.should_fail {
                Err(StageError::StageFailed(self.id, "test failure".into()))
            } else {
                Ok(ExecOutput { checkpoint: target, done: true })
            }
        }

        fn unwind(&mut self, target: u64) -> Result<UnwindOutput, StageError> {
            Ok(UnwindOutput { checkpoint: target })
        }
    }

    #[test]
    fn test_pipeline_success() {
        let mut pipeline = Pipeline::new();
        pipeline.add_stage(Box::new(TestStage {
            id: StageId("test1"),
            should_fail: false,
        }));
        pipeline.add_stage(Box::new(TestStage {
            id: StageId("test2"),
            should_fail: false,
        }));
        assert!(pipeline.run(100).is_ok());
        assert_eq!(pipeline.checkpoint(StageId("test1")), Some(100));
        assert_eq!(pipeline.checkpoint(StageId("test2")), Some(100));
    }

    #[test]
    fn test_pipeline_failure_unwinds() {
        let mut pipeline = Pipeline::new();
        pipeline.add_stage(Box::new(TestStage {
            id: StageId("test1"),
            should_fail: false,
        }));
        pipeline.add_stage(Box::new(TestStage {
            id: StageId("test2"),
            should_fail: true,
        }));
        assert!(pipeline.run(100).is_err());
        // After unwind, checkpoints should be 0
        assert_eq!(pipeline.checkpoint(StageId("test1")), Some(0));
    }
}
