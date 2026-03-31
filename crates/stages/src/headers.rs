use crate::stage::{ExecOutput, Stage, StageError, StageId, UnwindOutput, HEADERS};
use tracing::info;

/// Tracks the sync state of the headers download stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadersSyncState {
    /// No header sync in progress.
    Idle,
    /// Requesting headers from peers in the given height range.
    Requesting { from: u64, to: u64 },
    /// Processing and validating received headers.
    Processing,
    /// Header sync for the current batch is complete.
    Done,
}

/// Maximum number of headers to request in a single batch (matches Bitcoin protocol).
const HEADERS_BATCH_SIZE: u64 = 2000;

/// Headers stage -- downloads and validates block headers from peers.
///
/// This stage is responsible for:
/// - Fetching block headers from the peer-to-peer network (via getheaders messages)
/// - Validating proof-of-work and chain continuity for each header
/// - Storing validated headers in the database
///
/// The stage does not perform actual network I/O itself. Instead it describes the
/// work to be done (which height range to request, etc.) and the node runtime is
/// responsible for driving the I/O.
pub struct HeadersStage {
    /// Current sync progress -- the height up to which headers have been stored.
    checkpoint: u64,
    /// Current state of the header sync.
    state: HeadersSyncState,
    /// Accumulated list of header hashes stored during this execution (for unwind bookkeeping).
    stored_headers: Vec<u64>,
}

impl HeadersStage {
    pub fn new() -> Self {
        HeadersStage {
            checkpoint: 0,
            state: HeadersSyncState::Idle,
            stored_headers: Vec::new(),
        }
    }

    /// Return the current sync state.
    pub fn sync_state(&self) -> &HeadersSyncState {
        &self.state
    }

    /// Return the current checkpoint height.
    pub fn checkpoint(&self) -> u64 {
        self.checkpoint
    }

    /// Simulate requesting and validating a batch of headers.
    ///
    /// In a real implementation this would:
    /// 1. Send `getheaders` to peers starting from the current tip
    /// 2. Receive up to 2000 headers
    /// 3. Validate PoW and prev_blockhash chain for each header
    /// 4. Store valid headers in the database
    fn sync_batch(&mut self, from: u64, to: u64) -> Result<u64, StageError> {
        // Transition: Idle -> Requesting
        self.state = HeadersSyncState::Requesting { from, to };
        info!(from, to, "requesting headers from peers");

        // Transition: Requesting -> Processing
        self.state = HeadersSyncState::Processing;
        info!(from, to, "validating received headers");

        // In a real implementation we would:
        //   - Verify each header's PoW: header.check_proof_of_work()
        //   - Verify chain continuity: header.prev_blockhash == prev_header.block_hash()
        //   - Verify timestamps are within acceptable range
        //   - Store headers: db.put_block_header(&hash, &header)
        //   - Store height mapping: db.put_block_hash_by_height(height, &hash)

        // Track which heights were stored (for unwind)
        for h in from..=to {
            self.stored_headers.push(h);
        }

        // Transition: Processing -> Done
        self.state = HeadersSyncState::Done;
        info!(to, "header batch validated and stored");

        Ok(to)
    }
}

impl Default for HeadersStage {
    fn default() -> Self {
        Self::new()
    }
}

impl Stage for HeadersStage {
    fn id(&self) -> StageId {
        HEADERS
    }

    /// Execute the headers stage: download and validate headers up to `target`.
    ///
    /// Headers are fetched in batches of up to `HEADERS_BATCH_SIZE`. If more work
    /// remains after a batch, the stage returns `done: false` so the pipeline can
    /// re-run it.
    fn execute(&mut self, target: u64) -> Result<ExecOutput, StageError> {
        if self.checkpoint >= target {
            // Already synced to or past the target.
            self.state = HeadersSyncState::Done;
            return Ok(ExecOutput {
                checkpoint: self.checkpoint,
                done: true,
            });
        }

        let from = self.checkpoint + 1;
        let batch_end = std::cmp::min(from + HEADERS_BATCH_SIZE - 1, target);

        self.sync_batch(from, batch_end)?;
        self.checkpoint = batch_end;

        let done = batch_end >= target;
        if done {
            self.state = HeadersSyncState::Done;
        } else {
            // More batches needed -- reset to Idle so the pipeline can re-run us.
            self.state = HeadersSyncState::Idle;
        }

        Ok(ExecOutput {
            checkpoint: self.checkpoint,
            done,
        })
    }

    /// Unwind the headers stage: remove headers back to `target` height.
    ///
    /// In a real implementation this would delete header records and height
    /// mappings from the database for every height above `target`.
    fn unwind(&mut self, target: u64) -> Result<UnwindOutput, StageError> {
        if target >= self.checkpoint {
            return Ok(UnwindOutput {
                checkpoint: self.checkpoint,
            });
        }

        info!(
            from = self.checkpoint,
            to = target,
            "unwinding headers stage"
        );

        // In a real implementation:
        //   for height in (target + 1)..=self.checkpoint:
        //     - Look up the block hash at this height
        //     - Delete the header record
        //     - Delete the height -> hash mapping

        // Remove stored headers above the target.
        self.stored_headers.retain(|&h| h <= target);

        self.checkpoint = target;
        self.state = HeadersSyncState::Idle;

        Ok(UnwindOutput {
            checkpoint: target,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_headers_stage_new() {
        let stage = HeadersStage::new();
        assert_eq!(stage.checkpoint(), 0);
        assert_eq!(*stage.sync_state(), HeadersSyncState::Idle);
    }

    #[test]
    fn test_headers_execute_basic() {
        let mut stage = HeadersStage::new();
        let result = stage.execute(100).unwrap();
        assert_eq!(result.checkpoint, 100);
        assert!(result.done);
        assert_eq!(stage.checkpoint(), 100);
        assert_eq!(*stage.sync_state(), HeadersSyncState::Done);
    }

    #[test]
    fn test_headers_execute_already_synced() {
        let mut stage = HeadersStage::new();
        stage.execute(100).unwrap();

        let result = stage.execute(50).unwrap();
        assert_eq!(result.checkpoint, 100);
        assert!(result.done);
    }

    #[test]
    fn test_headers_execute_batching() {
        let mut stage = HeadersStage::new();
        // Request more than one batch worth of headers.
        let result = stage.execute(3000).unwrap();
        // Should process at most HEADERS_BATCH_SIZE in one call.
        assert_eq!(result.checkpoint, HEADERS_BATCH_SIZE);
        assert!(!result.done);
        assert_eq!(*stage.sync_state(), HeadersSyncState::Idle);

        // Second batch should finish.
        let result = stage.execute(3000).unwrap();
        assert_eq!(result.checkpoint, 3000);
        assert!(result.done);
    }

    #[test]
    fn test_headers_unwind() {
        let mut stage = HeadersStage::new();
        stage.execute(100).unwrap();

        let result = stage.unwind(50).unwrap();
        assert_eq!(result.checkpoint, 50);
        assert_eq!(stage.checkpoint(), 50);
        assert_eq!(*stage.sync_state(), HeadersSyncState::Idle);
    }

    #[test]
    fn test_headers_unwind_noop_when_below() {
        let mut stage = HeadersStage::new();
        stage.execute(100).unwrap();

        let result = stage.unwind(200).unwrap();
        assert_eq!(result.checkpoint, 100);
    }

    #[test]
    fn test_headers_state_transitions() {
        let mut stage = HeadersStage::new();
        assert_eq!(*stage.sync_state(), HeadersSyncState::Idle);

        stage.execute(10).unwrap();
        assert_eq!(*stage.sync_state(), HeadersSyncState::Done);

        stage.unwind(0).unwrap();
        assert_eq!(*stage.sync_state(), HeadersSyncState::Idle);
    }

    #[test]
    fn test_headers_stage_id() {
        let stage = HeadersStage::new();
        assert_eq!(stage.id(), HEADERS);
    }
}
