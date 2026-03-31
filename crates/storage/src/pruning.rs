use std::collections::HashSet;

/// BIP159 service flags for network advertisement.
/// A pruned node advertises NODE_NETWORK_LIMITED instead of NODE_NETWORK,
/// indicating it can only serve recent blocks (last 288).
pub const NODE_NETWORK: u64 = 1 << 0;
pub const NODE_NETWORK_LIMITED: u64 = 1 << 10;

/// Minimum number of recent blocks a pruned node must serve to peers (BIP159).
const BIP159_MIN_BLOCKS: u64 = 288;

/// Configuration for block pruning behavior.
#[derive(Debug, Clone)]
pub struct PruneConfig {
    pub enabled: bool,
    /// Target disk usage in MB (like Bitcoin Core's -prune=N). 0 = no pruning.
    pub target_size_mb: u64,
    /// Minimum number of recent blocks to keep (default 288 = ~2 days)
    pub min_blocks_to_keep: u64,
    /// Whether to keep block undo data for reorgs
    pub keep_undo_data: bool,
}

impl Default for PruneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target_size_mb: 0,
            min_blocks_to_keep: BIP159_MIN_BLOCKS,
            keep_undo_data: true,
        }
    }
}

/// Manages block pruning state and decisions.
///
/// Tracks which block heights have been pruned and estimates current disk usage
/// to determine when additional pruning is needed.
pub struct PruneManager {
    config: PruneConfig,
    /// Tracks which block heights have been pruned
    pruned_heights: HashSet<u64>,
    /// Current estimated disk usage in bytes
    estimated_disk_usage_bytes: u64,
    /// Highest pruned height
    max_pruned_height: u64,
}

impl PruneManager {
    /// Create a new prune manager with the given configuration.
    pub fn new(config: PruneConfig) -> Self {
        Self {
            config,
            pruned_heights: HashSet::new(),
            estimated_disk_usage_bytes: 0,
            max_pruned_height: 0,
        }
    }

    /// Check if we should trigger pruning based on current disk usage vs target.
    ///
    /// Returns `false` if pruning is disabled or the target has not been exceeded.
    pub fn should_prune(&self, _current_height: u64) -> bool {
        if !self.config.enabled || self.config.target_size_mb == 0 {
            return false;
        }
        self.estimated_usage_mb() >= self.config.target_size_mb
    }

    /// Return block heights eligible for pruning, oldest first.
    ///
    /// Respects `min_blocks_to_keep` — only heights older than
    /// `current_height - min_blocks_to_keep` are returned.
    /// Already-pruned heights are excluded.
    pub fn blocks_to_prune(&self, current_height: u64) -> Vec<u64> {
        if !self.config.enabled || self.config.target_size_mb == 0 {
            return Vec::new();
        }

        // The cutoff: we keep everything from (current_height - min_blocks_to_keep + 1) onward.
        let keep_from = current_height.saturating_sub(self.config.min_blocks_to_keep - 1);

        // Collect unpruned heights below the cutoff, oldest first.
        let mut eligible: Vec<u64> = (0..keep_from)
            .filter(|h| !self.pruned_heights.contains(h))
            .collect();

        eligible.sort_unstable();
        eligible
    }

    /// Record that a block at the given height was pruned, freeing `freed_bytes`.
    pub fn mark_pruned(&mut self, height: u64, freed_bytes: u64) {
        self.pruned_heights.insert(height);
        self.estimated_disk_usage_bytes =
            self.estimated_disk_usage_bytes.saturating_sub(freed_bytes);
        if height > self.max_pruned_height {
            self.max_pruned_height = height;
        }
    }

    /// Check if a specific block height has been pruned.
    pub fn is_pruned(&self, height: u64) -> bool {
        self.pruned_heights.contains(&height)
    }

    /// Returns the highest pruned block height.
    pub fn pruned_height(&self) -> u64 {
        self.max_pruned_height
    }

    /// Track new block data being added to disk.
    pub fn add_block_size(&mut self, size: u64) {
        self.estimated_disk_usage_bytes += size;
    }

    /// Current estimated disk usage in megabytes.
    pub fn estimated_usage_mb(&self) -> u64 {
        self.estimated_disk_usage_bytes / (1024 * 1024)
    }

    /// Determine which service flag to advertise based on pruning state.
    ///
    /// A pruned node advertises `NODE_NETWORK_LIMITED` (BIP159) instead of
    /// `NODE_NETWORK`, signaling that it only serves recent blocks.
    pub fn service_flags(&self) -> u64 {
        if self.config.enabled {
            NODE_NETWORK_LIMITED
        } else {
            NODE_NETWORK
        }
    }

    /// Check whether this node can serve a block at `height` to a peer,
    /// given the current chain tip `current_height`.
    ///
    /// A pruned node can only serve blocks within the last
    /// `min_blocks_to_keep` blocks (at least 288 per BIP159).
    /// A non-pruned node can serve any block.
    pub fn can_serve_block(&self, height: u64, current_height: u64) -> bool {
        if !self.config.enabled {
            return true;
        }

        // If the block has been pruned, we definitely cannot serve it.
        if self.is_pruned(height) {
            return false;
        }

        // Even if not yet pruned, a pruned node only advertises serving
        // the last min_blocks_to_keep blocks.
        let serve_from = current_height.saturating_sub(self.config.min_blocks_to_keep - 1);
        height >= serve_from
    }

    /// Access the underlying configuration.
    pub fn config(&self) -> &PruneConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pruning_disabled_by_default() {
        let config = PruneConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.target_size_mb, 0);
        assert_eq!(config.min_blocks_to_keep, 288);

        let manager = PruneManager::new(config);
        assert!(!manager.should_prune(1000));
        assert!(manager.blocks_to_prune(1000).is_empty());
        assert_eq!(manager.service_flags(), NODE_NETWORK);
    }

    #[test]
    fn test_should_prune_triggers_at_correct_threshold() {
        let config = PruneConfig {
            enabled: true,
            target_size_mb: 550,
            min_blocks_to_keep: 288,
            keep_undo_data: true,
        };
        let mut manager = PruneManager::new(config);

        // Below threshold — should not prune
        manager.add_block_size(549 * 1024 * 1024);
        assert!(!manager.should_prune(1000));

        // At threshold — should prune
        manager.add_block_size(1024 * 1024);
        assert!(manager.should_prune(1000));

        // Well above — still should prune
        manager.add_block_size(100 * 1024 * 1024);
        assert!(manager.should_prune(1000));
    }

    #[test]
    fn test_blocks_to_prune_respects_min_blocks_to_keep() {
        let config = PruneConfig {
            enabled: true,
            target_size_mb: 550,
            min_blocks_to_keep: 288,
            keep_undo_data: true,
        };
        let manager = PruneManager::new(config);

        // With current_height=500, we keep blocks [213..=500] (288 blocks).
        // Eligible for pruning: 0..213
        let eligible = manager.blocks_to_prune(500);
        assert_eq!(eligible.len(), 213);
        assert_eq!(*eligible.first().unwrap(), 0);
        assert_eq!(*eligible.last().unwrap(), 212);

        // With current_height=100, nothing is eligible (100 < 288).
        let eligible = manager.blocks_to_prune(100);
        assert!(eligible.is_empty());
    }

    #[test]
    fn test_mark_pruned_tracking() {
        let config = PruneConfig {
            enabled: true,
            target_size_mb: 550,
            min_blocks_to_keep: 288,
            keep_undo_data: true,
        };
        let mut manager = PruneManager::new(config);

        // Add some disk usage
        manager.add_block_size(10_000);

        assert!(!manager.is_pruned(5));
        assert_eq!(manager.pruned_height(), 0);

        manager.mark_pruned(5, 2_000);
        assert!(manager.is_pruned(5));
        assert_eq!(manager.pruned_height(), 5);
        assert_eq!(manager.estimated_disk_usage_bytes, 8_000);

        manager.mark_pruned(10, 3_000);
        assert!(manager.is_pruned(10));
        assert_eq!(manager.pruned_height(), 10);
        assert_eq!(manager.estimated_disk_usage_bytes, 5_000);

        // Already-pruned heights should not appear in blocks_to_prune
        let eligible = manager.blocks_to_prune(500);
        assert!(!eligible.contains(&5));
        assert!(!eligible.contains(&10));
    }

    #[test]
    fn test_can_serve_block_with_pruned_node() {
        let config = PruneConfig {
            enabled: true,
            target_size_mb: 550,
            min_blocks_to_keep: 288,
            keep_undo_data: true,
        };
        let mut manager = PruneManager::new(config);

        let current_height = 1000;

        // Recent block — within the last 288
        assert!(manager.can_serve_block(900, current_height));
        assert!(manager.can_serve_block(current_height, current_height));

        // Block at the boundary: 1000 - 288 + 1 = 713
        assert!(manager.can_serve_block(713, current_height));

        // Block just outside the window
        assert!(!manager.can_serve_block(712, current_height));

        // Old block
        assert!(!manager.can_serve_block(100, current_height));

        // Mark a recent block as pruned — should not be serveable even if in window
        manager.mark_pruned(900, 0);
        assert!(!manager.can_serve_block(900, current_height));
    }

    #[test]
    fn test_can_serve_block_non_pruned_node() {
        let config = PruneConfig::default(); // pruning disabled
        let manager = PruneManager::new(config);

        // Non-pruned node can serve any block
        assert!(manager.can_serve_block(0, 1000));
        assert!(manager.can_serve_block(500, 1000));
        assert!(manager.can_serve_block(1000, 1000));
    }

    #[test]
    fn test_estimated_usage_tracking() {
        let config = PruneConfig::default();
        let mut manager = PruneManager::new(config);

        assert_eq!(manager.estimated_usage_mb(), 0);

        // Add 1 MB
        manager.add_block_size(1024 * 1024);
        assert_eq!(manager.estimated_usage_mb(), 1);

        // Add another 2.5 MB — integer division means 3 MB total
        manager.add_block_size(2 * 1024 * 1024 + 512 * 1024);
        assert_eq!(manager.estimated_usage_mb(), 3);

        // Pruning reduces usage
        manager.mark_pruned(0, 1024 * 1024);
        assert_eq!(manager.estimated_usage_mb(), 2);
    }

    #[test]
    fn test_node_network_limited_determination() {
        // Non-pruned node
        let config = PruneConfig::default();
        let manager = PruneManager::new(config);
        assert_eq!(manager.service_flags(), NODE_NETWORK);
        assert_eq!(manager.service_flags() & NODE_NETWORK, NODE_NETWORK);
        assert_eq!(manager.service_flags() & NODE_NETWORK_LIMITED, 0);

        // Pruned node
        let config = PruneConfig {
            enabled: true,
            target_size_mb: 550,
            min_blocks_to_keep: 288,
            keep_undo_data: true,
        };
        let manager = PruneManager::new(config);
        assert_eq!(manager.service_flags(), NODE_NETWORK_LIMITED);
        assert_eq!(manager.service_flags() & NODE_NETWORK_LIMITED, NODE_NETWORK_LIMITED);
        assert_eq!(manager.service_flags() & NODE_NETWORK, 0);
    }

    #[test]
    fn test_saturating_sub_on_freed_bytes() {
        let config = PruneConfig {
            enabled: true,
            target_size_mb: 550,
            min_blocks_to_keep: 288,
            keep_undo_data: true,
        };
        let mut manager = PruneManager::new(config);

        manager.add_block_size(100);
        // Freeing more than we have should not underflow
        manager.mark_pruned(0, 200);
        assert_eq!(manager.estimated_disk_usage_bytes, 0);
        assert_eq!(manager.estimated_usage_mb(), 0);
    }

    #[test]
    fn test_blocks_to_prune_excludes_already_pruned() {
        let config = PruneConfig {
            enabled: true,
            target_size_mb: 550,
            min_blocks_to_keep: 10,
            keep_undo_data: true,
        };
        let mut manager = PruneManager::new(config);

        // current_height=20, keep last 10 => keep [11..=20], prune [0..11]
        let eligible = manager.blocks_to_prune(20);
        assert_eq!(eligible.len(), 11);
        assert_eq!(eligible, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        // Mark some as pruned
        manager.mark_pruned(0, 0);
        manager.mark_pruned(1, 0);
        manager.mark_pruned(2, 0);

        let eligible = manager.blocks_to_prune(20);
        assert_eq!(eligible.len(), 8);
        assert_eq!(eligible, vec![3, 4, 5, 6, 7, 8, 9, 10]);
    }
}
