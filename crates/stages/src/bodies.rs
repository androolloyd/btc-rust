use crate::stage::{ExecOutput, Stage, StageError, StageId, UnwindOutput, BODIES};
use tracing::info;

/// Maximum number of block bodies to request in a single batch.
const BODIES_BATCH_SIZE: u64 = 128;

/// Tracks the sync state of the bodies download stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodiesSyncState {
    /// No body download in progress.
    Idle,
    /// Requesting block bodies for the given height range.
    Downloading { from: u64, to: u64 },
    /// Validating received bodies against their header commitments (merkle root, etc.).
    Validating,
    /// Body sync for the current batch is complete.
    Done,
}

/// Bodies stage -- downloads and validates block bodies (transactions) for headers
/// that have already been stored.
///
/// This stage is responsible for:
/// - Requesting block bodies from peers for headers we already have
/// - Verifying that the merkle root of the body matches the header commitment
/// - Storing validated block bodies in the database
///
/// Depends on the Headers stage having run first -- it only requests bodies for
/// heights that already have headers.
pub struct BodiesStage {
    /// Current sync progress -- the height up to which bodies have been stored.
    checkpoint: u64,
    /// Current state of the body sync.
    state: BodiesSyncState,
    /// Height range for which we have complete bodies.
    bodies_range: Option<(u64, u64)>,
}

impl BodiesStage {
    pub fn new() -> Self {
        BodiesStage {
            checkpoint: 0,
            state: BodiesSyncState::Idle,
            bodies_range: None,
        }
    }

    /// Return the current sync state.
    pub fn sync_state(&self) -> &BodiesSyncState {
        &self.state
    }

    /// Return the current checkpoint height.
    pub fn checkpoint(&self) -> u64 {
        self.checkpoint
    }

    /// Return the height range for which we have complete bodies.
    pub fn bodies_range(&self) -> Option<(u64, u64)> {
        self.bodies_range
    }

    /// Simulate downloading and validating a batch of block bodies.
    ///
    /// In a real implementation this would:
    /// 1. For each header in [from, to], send `getdata` with MSG_BLOCK to peers
    /// 2. Receive the block bodies (transaction lists)
    /// 3. Verify merkle root of transactions matches the header's merkle_root field
    /// 4. Store validated block bodies in the database
    fn download_batch(&mut self, from: u64, to: u64) -> Result<u64, StageError> {
        // Transition: Idle -> Downloading
        self.state = BodiesSyncState::Downloading { from, to };
        info!(from, to, "requesting block bodies from peers");

        // Transition: Downloading -> Validating
        self.state = BodiesSyncState::Validating;
        info!(from, to, "validating block bodies against header commitments");

        // In a real implementation we would:
        //   for height in from..=to:
        //     - Retrieve the header at this height from the database
        //     - Request the full block body from peers
        //     - Verify: block.compute_merkle_root() == header.merkle_root
        //     - Store the block body (transactions) in the database
        //     - Optionally store the block weight/size for later validation

        // Update our tracked range of complete bodies.
        let range_start = self.bodies_range.map_or(from, |(s, _)| s);
        self.bodies_range = Some((range_start, to));

        // Transition: Validating -> Done
        self.state = BodiesSyncState::Done;
        info!(to, "block bodies batch validated and stored");

        Ok(to)
    }
}

impl Default for BodiesStage {
    fn default() -> Self {
        Self::new()
    }
}

impl Stage for BodiesStage {
    fn id(&self) -> StageId {
        BODIES
    }

    /// Execute the bodies stage: download block bodies up to `target`.
    ///
    /// Block bodies are fetched in batches. If more work remains, the stage returns
    /// `done: false` so the pipeline can re-run it.
    fn execute(&mut self, target: u64) -> Result<ExecOutput, StageError> {
        if self.checkpoint >= target {
            self.state = BodiesSyncState::Done;
            return Ok(ExecOutput {
                checkpoint: self.checkpoint,
                done: true,
            });
        }

        let from = self.checkpoint + 1;
        let batch_end = std::cmp::min(from + BODIES_BATCH_SIZE - 1, target);

        self.download_batch(from, batch_end)?;
        self.checkpoint = batch_end;

        let done = batch_end >= target;
        if done {
            self.state = BodiesSyncState::Done;
        } else {
            self.state = BodiesSyncState::Idle;
        }

        Ok(ExecOutput {
            checkpoint: self.checkpoint,
            done,
        })
    }

    /// Unwind the bodies stage: remove block bodies back to `target` height.
    ///
    /// In a real implementation this would delete stored block body data
    /// for every height above `target`.
    fn unwind(&mut self, target: u64) -> Result<UnwindOutput, StageError> {
        if target >= self.checkpoint {
            return Ok(UnwindOutput {
                checkpoint: self.checkpoint,
            });
        }

        info!(
            from = self.checkpoint,
            to = target,
            "unwinding bodies stage"
        );

        // In a real implementation:
        //   for height in (target + 1)..=self.checkpoint:
        //     - Delete stored block body (transactions) at this height

        // Adjust tracked range.
        if let Some((start, _)) = self.bodies_range {
            if target < start {
                self.bodies_range = None;
            } else {
                self.bodies_range = Some((start, target));
            }
        }

        self.checkpoint = target;
        self.state = BodiesSyncState::Idle;

        Ok(UnwindOutput {
            checkpoint: target,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bodies_stage_new() {
        let stage = BodiesStage::new();
        assert_eq!(stage.checkpoint(), 0);
        assert_eq!(*stage.sync_state(), BodiesSyncState::Idle);
        assert_eq!(stage.bodies_range(), None);
    }

    #[test]
    fn test_bodies_execute_basic() {
        let mut stage = BodiesStage::new();
        let result = stage.execute(50).unwrap();
        assert_eq!(result.checkpoint, 50);
        assert!(result.done);
        assert_eq!(stage.checkpoint(), 50);
        assert_eq!(*stage.sync_state(), BodiesSyncState::Done);
        assert_eq!(stage.bodies_range(), Some((1, 50)));
    }

    #[test]
    fn test_bodies_execute_already_synced() {
        let mut stage = BodiesStage::new();
        stage.execute(100).unwrap();

        let result = stage.execute(50).unwrap();
        assert_eq!(result.checkpoint, 100);
        assert!(result.done);
    }

    #[test]
    fn test_bodies_execute_batching() {
        let mut stage = BodiesStage::new();
        let result = stage.execute(200).unwrap();
        assert_eq!(result.checkpoint, BODIES_BATCH_SIZE);
        assert!(!result.done);

        let result = stage.execute(200).unwrap();
        assert_eq!(result.checkpoint, 200);
        assert!(result.done);
    }

    #[test]
    fn test_bodies_unwind() {
        let mut stage = BodiesStage::new();
        stage.execute(100).unwrap();

        let result = stage.unwind(30).unwrap();
        assert_eq!(result.checkpoint, 30);
        assert_eq!(stage.checkpoint(), 30);
        assert_eq!(*stage.sync_state(), BodiesSyncState::Idle);
        assert_eq!(stage.bodies_range(), Some((1, 30)));
    }

    #[test]
    fn test_bodies_unwind_noop_when_below() {
        let mut stage = BodiesStage::new();
        stage.execute(100).unwrap();

        let result = stage.unwind(200).unwrap();
        assert_eq!(result.checkpoint, 100);
    }

    #[test]
    fn test_bodies_unwind_clears_range() {
        let mut stage = BodiesStage::new();
        stage.execute(100).unwrap();

        stage.unwind(0).unwrap();
        assert_eq!(stage.bodies_range(), None);
    }

    #[test]
    fn test_bodies_stage_id() {
        let stage = BodiesStage::new();
        assert_eq!(stage.id(), BODIES);
    }

    #[test]
    fn test_bodies_state_transitions() {
        let mut stage = BodiesStage::new();
        assert_eq!(*stage.sync_state(), BodiesSyncState::Idle);

        stage.execute(10).unwrap();
        assert_eq!(*stage.sync_state(), BodiesSyncState::Done);

        stage.unwind(0).unwrap();
        assert_eq!(*stage.sync_state(), BodiesSyncState::Idle);
    }
}
