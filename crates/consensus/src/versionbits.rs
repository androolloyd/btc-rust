use std::collections::HashMap;

use btc_primitives::block::BlockHeader;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// BIP9 version bits top-level mask: top 3 bits must be 001.
const BIP9_TOP_BITS: i32 = 0x20000000;
/// Mask to check the top 3 bits of the version field.
const BIP9_TOP_MASK: i32 = 0xE0000000_u32 as i32;

/// Default retarget period (same as difficulty adjustment interval).
pub const DEFAULT_PERIOD: u32 = 2016;
/// Default activation threshold: 1815 out of 2016 (approximately 90%).
pub const DEFAULT_THRESHOLD: u32 = 1815;

// ---------------------------------------------------------------------------
// DeploymentState
// ---------------------------------------------------------------------------

/// BIP9 deployment state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeploymentState {
    /// The deployment is not yet active and the start time has not been reached.
    Defined,
    /// The signaling window is open; miners can signal readiness.
    Started,
    /// The activation threshold has been reached; the deployment will activate
    /// after a grace period (one full retarget period, or until
    /// `min_activation_height` for Speedy Trial deployments).
    LockedIn,
    /// The deployment is fully active.
    Active,
    /// The timeout was reached without achieving activation.
    Failed,
}

// ---------------------------------------------------------------------------
// Deployment
// ---------------------------------------------------------------------------

/// Describes a single BIP9 soft fork deployment.
#[derive(Debug, Clone)]
pub struct Deployment {
    /// Human-readable name of the deployment (e.g. "csv", "segwit", "taproot").
    pub name: &'static str,
    /// BIP9 bit position in the block version field (0-28).
    pub bit: u8,
    /// Median-time-past at which signaling begins.
    pub start_time: u64,
    /// Median-time-past at which the deployment times out if not locked in.
    pub timeout: u64,
    /// Minimum activation height (BIP341 Speedy Trial). When non-zero, the
    /// deployment stays in LOCKED_IN until this height is reached even if the
    /// threshold was met earlier.
    pub min_activation_height: u64,
    /// Number of signaling blocks required per retarget period to lock in.
    pub threshold: u32,
    /// Length of the retarget period in blocks.
    pub period: u32,
}

impl Deployment {
    /// Returns the version-bit mask for this deployment.
    pub fn mask(&self) -> i32 {
        1i32 << self.bit
    }
}

// ---------------------------------------------------------------------------
// VersionBitsManager
// ---------------------------------------------------------------------------

/// Manages BIP9 version-bits deployments and their cached states.
pub struct VersionBitsManager {
    deployments: Vec<Deployment>,
    states: HashMap<String, DeploymentState>,
}

impl VersionBitsManager {
    /// Create a new manager initialised with the well-known historical
    /// mainnet deployments (CSV, SegWit, Taproot).
    pub fn new() -> Self {
        let deployments = vec![
            // BIP68/112/113 (CSV) -- bit 0, activated at height 419328
            Deployment {
                name: "csv",
                bit: 0,
                start_time: 1462060800,  // 2016-05-01
                timeout: 1493596800,     // 2017-05-01
                min_activation_height: 0,
                threshold: DEFAULT_THRESHOLD,
                period: DEFAULT_PERIOD,
            },
            // BIP141/143/147 (SegWit) -- bit 1, activated at height 481824
            Deployment {
                name: "segwit",
                bit: 1,
                start_time: 1479168000,  // 2016-11-15
                timeout: 1510704000,     // 2017-11-15
                min_activation_height: 0,
                threshold: DEFAULT_THRESHOLD,
                period: DEFAULT_PERIOD,
            },
            // BIP341 (Taproot) -- bit 2, Speedy Trial, activated at height 709632
            Deployment {
                name: "taproot",
                bit: 2,
                start_time: 1619222400,  // 2021-04-24
                timeout: 1628640000,     // 2021-08-11
                min_activation_height: 709632,
                threshold: 1815,
                period: DEFAULT_PERIOD,
            },
        ];

        let mut states = HashMap::new();
        for d in &deployments {
            states.insert(d.name.to_string(), DeploymentState::Defined);
        }

        VersionBitsManager {
            deployments,
            states,
        }
    }

    /// Create a manager with a custom set of deployments.
    pub fn with_deployments(deployments: Vec<Deployment>) -> Self {
        let mut states = HashMap::new();
        for d in &deployments {
            states.insert(d.name.to_string(), DeploymentState::Defined);
        }
        VersionBitsManager {
            deployments,
            states,
        }
    }

    /// Return the cached state for the named deployment.
    pub fn get_state(&self, name: &str) -> DeploymentState {
        self.states
            .get(name)
            .copied()
            .unwrap_or(DeploymentState::Defined)
    }

    /// Look up a deployment by name.
    pub fn get_deployment(&self, name: &str) -> Option<&Deployment> {
        self.deployments.iter().find(|d| d.name == name)
    }

    /// Return all registered deployments.
    pub fn deployments(&self) -> &[Deployment] {
        &self.deployments
    }

    /// Compute the deployment state for a given deployment based on chain
    /// context.
    ///
    /// # Arguments
    ///
    /// * `deployment` - The deployment to evaluate.
    /// * `height` - The current best-chain height.
    /// * `median_time_past` - The MTP of the chain tip.
    /// * `period_headers` - Block headers within the current retarget period
    ///   (only needed when in the `Started` state for counting signals).
    ///
    /// This implements the BIP9 state machine:
    ///
    /// ```text
    ///   DEFINED -> STARTED -> LOCKED_IN -> ACTIVE
    ///                \-> FAILED
    /// ```
    pub fn compute_state(
        &self,
        deployment: &Deployment,
        height: u64,
        median_time_past: u64,
        period_headers: &[BlockHeader],
    ) -> DeploymentState {
        // Get the previously cached state (or DEFINED).
        let prev_state = self.get_state(deployment.name);

        match prev_state {
            DeploymentState::Active | DeploymentState::Failed => {
                // Terminal states -- no transition.
                prev_state
            }
            DeploymentState::Defined => {
                if median_time_past >= deployment.timeout {
                    DeploymentState::Failed
                } else if median_time_past >= deployment.start_time {
                    DeploymentState::Started
                } else {
                    DeploymentState::Defined
                }
            }
            DeploymentState::Started => {
                if median_time_past >= deployment.timeout {
                    DeploymentState::Failed
                } else {
                    // Count signaling blocks in the provided period headers.
                    let count = count_signaling_blocks(period_headers, deployment.bit);
                    if count >= deployment.threshold {
                        DeploymentState::LockedIn
                    } else {
                        DeploymentState::Started
                    }
                }
            }
            DeploymentState::LockedIn => {
                // Speedy Trial: remain LOCKED_IN until min_activation_height.
                if deployment.min_activation_height > 0 && height < deployment.min_activation_height
                {
                    DeploymentState::LockedIn
                } else {
                    DeploymentState::Active
                }
            }
        }
    }

    /// Compute the state for a named deployment and update the internal cache.
    ///
    /// Returns the new state.
    pub fn update_state(
        &mut self,
        name: &str,
        height: u64,
        median_time_past: u64,
        period_headers: &[BlockHeader],
    ) -> DeploymentState {
        let deployment = match self.deployments.iter().find(|d| d.name == name) {
            Some(d) => d.clone(),
            None => return DeploymentState::Defined,
        };

        let new_state = self.compute_state(&deployment, height, median_time_past, period_headers);
        self.states.insert(name.to_string(), new_state);
        new_state
    }

    /// Update all deployment states at once.
    pub fn update_all_states(
        &mut self,
        height: u64,
        median_time_past: u64,
        period_headers: &[BlockHeader],
    ) {
        let deployments: Vec<Deployment> = self.deployments.clone();
        for deployment in &deployments {
            let new_state =
                self.compute_state(deployment, height, median_time_past, period_headers);
            self.states
                .insert(deployment.name.to_string(), new_state);
        }
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Check whether a block header signals for the given BIP9 bit position.
///
/// A block signals for bit `b` when:
/// 1. The top 3 bits of `nVersion` are `001` (i.e. BIP9 signaling is active).
/// 2. Bit `b` (0-indexed) is set in the lower 29 bits.
pub fn check_version_bit(header: &BlockHeader, bit: u8) -> bool {
    assert!(bit <= 28, "BIP9 bit position must be 0..=28");
    let version = header.version;
    // Check BIP9 top bits.
    if version & BIP9_TOP_MASK != BIP9_TOP_BITS {
        return false;
    }
    // Check the specific deployment bit.
    version & (1i32 << bit) != 0
}

/// Construct a block version field for mining that signals for a set of
/// active deployment bits.
///
/// The base version has the BIP9 top bits set (`0x20000000`) and then each
/// requested bit is OR'd in.
pub fn get_block_version(active_bits: &[u8]) -> i32 {
    let mut version = BIP9_TOP_BITS;
    for &bit in active_bits {
        assert!(bit <= 28, "BIP9 bit position must be 0..=28");
        version |= 1i32 << bit;
    }
    version
}

/// Count the number of blocks in a slice that signal for the given bit.
pub fn count_signaling_blocks(headers: &[BlockHeader], bit: u8) -> u32 {
    headers
        .iter()
        .filter(|h| check_version_bit(h, bit))
        .count() as u32
}

/// Returns `true` if the version field indicates BIP9 signaling (top 3 bits
/// are `001`).
pub fn is_bip9_signaling(version: i32) -> bool {
    version & BIP9_TOP_MASK == BIP9_TOP_BITS
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::block::BlockHeader;
    use btc_primitives::compact::CompactTarget;
    use btc_primitives::hash::{BlockHash, TxHash};

    /// Helper: build a minimal block header with the given version.
    fn header_with_version(version: i32) -> BlockHeader {
        BlockHeader {
            version,
            prev_blockhash: BlockHash::ZERO,
            merkle_root: TxHash::from_bytes([0u8; 32]),
            time: 0,
            bits: CompactTarget::MAX_TARGET,
            nonce: 0,
        }
    }

    /// Helper: build a test deployment.
    fn test_deployment() -> Deployment {
        Deployment {
            name: "testdeploy",
            bit: 5,
            start_time: 1_000_000,
            timeout: 2_000_000,
            min_activation_height: 0,
            threshold: 3, // low threshold for testing
            period: 5,
        }
    }

    /// Helper: build a Speedy Trial deployment with min_activation_height.
    fn speedy_trial_deployment() -> Deployment {
        Deployment {
            name: "speedytrial",
            bit: 3,
            start_time: 1_000_000,
            timeout: 2_000_000,
            min_activation_height: 100,
            threshold: 3,
            period: 5,
        }
    }

    // ---------------------------------------------------------------
    // Version bit checking
    // ---------------------------------------------------------------

    #[test]
    fn test_check_version_bit_set() {
        // Version with BIP9 top bits + bit 5 set.
        let version = 0x20000000 | (1 << 5);
        let header = header_with_version(version);
        assert!(check_version_bit(&header, 5));
    }

    #[test]
    fn test_check_version_bit_not_set() {
        // Version with BIP9 top bits but bit 5 NOT set.
        let version = 0x20000000;
        let header = header_with_version(version);
        assert!(!check_version_bit(&header, 5));
    }

    #[test]
    fn test_check_version_bit_wrong_top_bits() {
        // Version 1 (old-style) -- even if bit 5 is set, no BIP9 top bits.
        let version = 1 | (1 << 5);
        let header = header_with_version(version);
        assert!(!check_version_bit(&header, 5));
    }

    #[test]
    fn test_check_version_bit_multiple_bits() {
        // Signal for bits 0, 1, and 2 simultaneously.
        let version = 0x20000000 | (1 << 0) | (1 << 1) | (1 << 2);
        let header = header_with_version(version);
        assert!(check_version_bit(&header, 0));
        assert!(check_version_bit(&header, 1));
        assert!(check_version_bit(&header, 2));
        assert!(!check_version_bit(&header, 3));
    }

    // ---------------------------------------------------------------
    // Block version construction
    // ---------------------------------------------------------------

    #[test]
    fn test_get_block_version_no_bits() {
        let version = get_block_version(&[]);
        assert_eq!(version, 0x20000000);
        assert!(is_bip9_signaling(version));
    }

    #[test]
    fn test_get_block_version_single_bit() {
        let version = get_block_version(&[1]);
        assert_eq!(version, 0x20000000 | (1 << 1));
        assert!(check_version_bit(&header_with_version(version), 1));
    }

    #[test]
    fn test_get_block_version_multiple_bits() {
        let version = get_block_version(&[0, 1, 2]);
        assert_eq!(version, 0x20000000 | 0b111);
        let header = header_with_version(version);
        assert!(check_version_bit(&header, 0));
        assert!(check_version_bit(&header, 1));
        assert!(check_version_bit(&header, 2));
    }

    // ---------------------------------------------------------------
    // BIP9 signaling detection
    // ---------------------------------------------------------------

    #[test]
    fn test_is_bip9_signaling() {
        assert!(is_bip9_signaling(0x20000000));
        assert!(is_bip9_signaling(0x20000001));
        assert!(!is_bip9_signaling(0x00000001)); // version 1
        assert!(!is_bip9_signaling(0x40000000)); // wrong top bits
    }

    // ---------------------------------------------------------------
    // Threshold counting
    // ---------------------------------------------------------------

    #[test]
    fn test_count_signaling_blocks() {
        let signaling = header_with_version(0x20000000 | (1 << 5));
        let non_signaling = header_with_version(0x20000000);
        let old_version = header_with_version(1);

        let headers = vec![
            signaling,
            non_signaling,
            signaling,
            old_version,
            signaling,
        ];

        assert_eq!(count_signaling_blocks(&headers, 5), 3);
        assert_eq!(count_signaling_blocks(&headers, 0), 0);
    }

    #[test]
    fn test_count_signaling_blocks_empty() {
        assert_eq!(count_signaling_blocks(&[], 5), 0);
    }

    // ---------------------------------------------------------------
    // Deployment state machine: DEFINED -> STARTED -> LOCKED_IN -> ACTIVE
    // ---------------------------------------------------------------

    #[test]
    fn test_state_defined_before_start() {
        let deployment = test_deployment();
        let manager = VersionBitsManager::with_deployments(vec![deployment.clone()]);

        // MTP well before start_time => stays DEFINED.
        let state = manager.compute_state(&deployment, 0, 500_000, &[]);
        assert_eq!(state, DeploymentState::Defined);
    }

    #[test]
    fn test_state_defined_to_started() {
        let deployment = test_deployment();
        let manager = VersionBitsManager::with_deployments(vec![deployment.clone()]);

        // MTP at start_time => transitions to STARTED.
        let state = manager.compute_state(&deployment, 10, 1_000_000, &[]);
        assert_eq!(state, DeploymentState::Started);
    }

    #[test]
    fn test_state_started_to_locked_in() {
        let deployment = test_deployment();
        let mut manager = VersionBitsManager::with_deployments(vec![deployment.clone()]);

        // Move to STARTED first.
        manager.update_state("testdeploy", 10, 1_000_000, &[]);
        assert_eq!(manager.get_state("testdeploy"), DeploymentState::Started);

        // Now provide enough signaling headers to meet the threshold (3 out of 5).
        let signaling = header_with_version(0x20000000 | (1 << 5));
        let non_signaling = header_with_version(0x20000000);
        let period_headers = vec![
            signaling,
            signaling,
            signaling,
            non_signaling,
            non_signaling,
        ];

        let state =
            manager.update_state("testdeploy", 15, 1_500_000, &period_headers);
        assert_eq!(state, DeploymentState::LockedIn);
    }

    #[test]
    fn test_state_locked_in_to_active() {
        let deployment = test_deployment();
        let mut manager = VersionBitsManager::with_deployments(vec![deployment.clone()]);

        // Force state to LOCKED_IN.
        manager
            .states
            .insert("testdeploy".to_string(), DeploymentState::LockedIn);

        // No min_activation_height => immediately ACTIVE.
        let state = manager.update_state("testdeploy", 20, 1_500_000, &[]);
        assert_eq!(state, DeploymentState::Active);
    }

    #[test]
    fn test_full_lifecycle_defined_to_active() {
        let deployment = test_deployment();
        let mut manager = VersionBitsManager::with_deployments(vec![deployment.clone()]);

        // Phase 1: DEFINED (before start_time).
        let state = manager.update_state("testdeploy", 0, 500_000, &[]);
        assert_eq!(state, DeploymentState::Defined);

        // Phase 2: STARTED (MTP >= start_time).
        let state = manager.update_state("testdeploy", 5, 1_000_000, &[]);
        assert_eq!(state, DeploymentState::Started);

        // Phase 3: LOCKED_IN (enough signaling in the period).
        let signaling = header_with_version(0x20000000 | (1 << 5));
        let period_headers = vec![signaling; 5]; // all signaling
        let state = manager.update_state("testdeploy", 10, 1_200_000, &period_headers);
        assert_eq!(state, DeploymentState::LockedIn);

        // Phase 4: ACTIVE (next period boundary, no min_activation_height).
        let state = manager.update_state("testdeploy", 15, 1_300_000, &[]);
        assert_eq!(state, DeploymentState::Active);

        // Phase 5: stays ACTIVE (terminal state).
        let state = manager.update_state("testdeploy", 20, 1_400_000, &[]);
        assert_eq!(state, DeploymentState::Active);
    }

    // ---------------------------------------------------------------
    // Deployment state machine: DEFINED -> STARTED -> FAILED
    // ---------------------------------------------------------------

    #[test]
    fn test_state_defined_to_failed_on_timeout() {
        let deployment = test_deployment();
        let manager = VersionBitsManager::with_deployments(vec![deployment.clone()]);

        // MTP at or past timeout while still DEFINED => FAILED.
        let state = manager.compute_state(&deployment, 50, 2_000_000, &[]);
        assert_eq!(state, DeploymentState::Failed);
    }

    #[test]
    fn test_state_started_to_failed_on_timeout() {
        let deployment = test_deployment();
        let mut manager = VersionBitsManager::with_deployments(vec![deployment.clone()]);

        // Move to STARTED.
        manager.update_state("testdeploy", 5, 1_000_000, &[]);
        assert_eq!(manager.get_state("testdeploy"), DeploymentState::Started);

        // MTP reaches timeout without enough signaling => FAILED.
        let non_signaling = header_with_version(0x20000000);
        let period_headers = vec![non_signaling; 5];
        let state =
            manager.update_state("testdeploy", 10, 2_000_000, &period_headers);
        assert_eq!(state, DeploymentState::Failed);
    }

    #[test]
    fn test_failed_is_terminal() {
        let deployment = test_deployment();
        let mut manager = VersionBitsManager::with_deployments(vec![deployment.clone()]);

        // Force to FAILED.
        manager
            .states
            .insert("testdeploy".to_string(), DeploymentState::Failed);

        // Even with valid signaling, it should stay FAILED.
        let signaling = header_with_version(0x20000000 | (1 << 5));
        let period_headers = vec![signaling; 5];
        let state =
            manager.update_state("testdeploy", 10, 1_500_000, &period_headers);
        assert_eq!(state, DeploymentState::Failed);
    }

    // ---------------------------------------------------------------
    // Speedy Trial (min_activation_height)
    // ---------------------------------------------------------------

    #[test]
    fn test_speedy_trial_locked_in_below_min_height() {
        let deployment = speedy_trial_deployment();
        let mut manager = VersionBitsManager::with_deployments(vec![deployment.clone()]);

        // Force to LOCKED_IN.
        manager
            .states
            .insert("speedytrial".to_string(), DeploymentState::LockedIn);

        // Height below min_activation_height => stays LOCKED_IN.
        let state = manager.update_state("speedytrial", 50, 1_500_000, &[]);
        assert_eq!(state, DeploymentState::LockedIn);
    }

    #[test]
    fn test_speedy_trial_locked_in_at_min_height() {
        let deployment = speedy_trial_deployment();
        let mut manager = VersionBitsManager::with_deployments(vec![deployment.clone()]);

        // Force to LOCKED_IN.
        manager
            .states
            .insert("speedytrial".to_string(), DeploymentState::LockedIn);

        // Height at min_activation_height => transitions to ACTIVE.
        let state = manager.update_state("speedytrial", 100, 1_500_000, &[]);
        assert_eq!(state, DeploymentState::Active);
    }

    #[test]
    fn test_speedy_trial_locked_in_above_min_height() {
        let deployment = speedy_trial_deployment();
        let mut manager = VersionBitsManager::with_deployments(vec![deployment.clone()]);

        // Force to LOCKED_IN.
        manager
            .states
            .insert("speedytrial".to_string(), DeploymentState::LockedIn);

        // Height above min_activation_height => transitions to ACTIVE.
        let state = manager.update_state("speedytrial", 200, 1_500_000, &[]);
        assert_eq!(state, DeploymentState::Active);
    }

    #[test]
    fn test_speedy_trial_full_lifecycle() {
        let deployment = speedy_trial_deployment();
        let mut manager = VersionBitsManager::with_deployments(vec![deployment.clone()]);

        // DEFINED -> STARTED
        let state = manager.update_state("speedytrial", 5, 1_000_000, &[]);
        assert_eq!(state, DeploymentState::Started);

        // STARTED -> LOCKED_IN (enough signaling)
        let signaling = header_with_version(0x20000000 | (1 << 3));
        let period_headers = vec![signaling; 5];
        let state =
            manager.update_state("speedytrial", 10, 1_200_000, &period_headers);
        assert_eq!(state, DeploymentState::LockedIn);

        // LOCKED_IN but below min_activation_height => stays LOCKED_IN
        let state = manager.update_state("speedytrial", 50, 1_300_000, &[]);
        assert_eq!(state, DeploymentState::LockedIn);

        // LOCKED_IN at min_activation_height => ACTIVE
        let state = manager.update_state("speedytrial", 100, 1_400_000, &[]);
        assert_eq!(state, DeploymentState::Active);
    }

    // ---------------------------------------------------------------
    // VersionBitsManager: default deployments
    // ---------------------------------------------------------------

    #[test]
    fn test_default_manager_has_known_deployments() {
        let manager = VersionBitsManager::new();
        assert!(manager.get_deployment("csv").is_some());
        assert!(manager.get_deployment("segwit").is_some());
        assert!(manager.get_deployment("taproot").is_some());
        assert!(manager.get_deployment("nonexistent").is_none());
    }

    #[test]
    fn test_default_manager_initial_states() {
        let manager = VersionBitsManager::new();
        assert_eq!(manager.get_state("csv"), DeploymentState::Defined);
        assert_eq!(manager.get_state("segwit"), DeploymentState::Defined);
        assert_eq!(manager.get_state("taproot"), DeploymentState::Defined);
    }

    #[test]
    fn test_deployment_bit_positions() {
        let manager = VersionBitsManager::new();
        assert_eq!(manager.get_deployment("csv").unwrap().bit, 0);
        assert_eq!(manager.get_deployment("segwit").unwrap().bit, 1);
        assert_eq!(manager.get_deployment("taproot").unwrap().bit, 2);
    }

    #[test]
    fn test_deployment_mask() {
        let csv = Deployment {
            name: "csv",
            bit: 0,
            start_time: 0,
            timeout: 0,
            min_activation_height: 0,
            threshold: DEFAULT_THRESHOLD,
            period: DEFAULT_PERIOD,
        };
        assert_eq!(csv.mask(), 1);

        let segwit = Deployment {
            name: "segwit",
            bit: 1,
            start_time: 0,
            timeout: 0,
            min_activation_height: 0,
            threshold: DEFAULT_THRESHOLD,
            period: DEFAULT_PERIOD,
        };
        assert_eq!(segwit.mask(), 2);

        let taproot = Deployment {
            name: "taproot",
            bit: 2,
            start_time: 0,
            timeout: 0,
            min_activation_height: 0,
            threshold: DEFAULT_THRESHOLD,
            period: DEFAULT_PERIOD,
        };
        assert_eq!(taproot.mask(), 4);
    }

    // ---------------------------------------------------------------
    // Threshold edge cases
    // ---------------------------------------------------------------

    #[test]
    fn test_threshold_exactly_met() {
        let deployment = test_deployment(); // threshold = 3, period = 5
        let mut manager = VersionBitsManager::with_deployments(vec![deployment.clone()]);

        // Move to STARTED.
        manager.update_state("testdeploy", 5, 1_000_000, &[]);

        // Exactly 3 out of 5 signaling => LOCKED_IN.
        let signaling = header_with_version(0x20000000 | (1 << 5));
        let non_signaling = header_with_version(0x20000000);
        let period_headers = vec![
            signaling,
            non_signaling,
            signaling,
            non_signaling,
            signaling,
        ];

        let state =
            manager.update_state("testdeploy", 10, 1_500_000, &period_headers);
        assert_eq!(state, DeploymentState::LockedIn);
    }

    #[test]
    fn test_threshold_not_met() {
        let deployment = test_deployment(); // threshold = 3, period = 5
        let mut manager = VersionBitsManager::with_deployments(vec![deployment.clone()]);

        // Move to STARTED.
        manager.update_state("testdeploy", 5, 1_000_000, &[]);

        // Only 2 out of 5 signaling => stays STARTED.
        let signaling = header_with_version(0x20000000 | (1 << 5));
        let non_signaling = header_with_version(0x20000000);
        let period_headers = vec![
            signaling,
            non_signaling,
            signaling,
            non_signaling,
            non_signaling,
        ];

        let state =
            manager.update_state("testdeploy", 10, 1_500_000, &period_headers);
        assert_eq!(state, DeploymentState::Started);
    }

    // ---------------------------------------------------------------
    // update_all_states
    // ---------------------------------------------------------------

    #[test]
    fn test_update_all_states() {
        let d1 = Deployment {
            name: "deploy_a",
            bit: 0,
            start_time: 1_000_000,
            timeout: 2_000_000,
            min_activation_height: 0,
            threshold: 1,
            period: 2,
        };
        let d2 = Deployment {
            name: "deploy_b",
            bit: 1,
            start_time: 3_000_000, // later start
            timeout: 4_000_000,
            min_activation_height: 0,
            threshold: 1,
            period: 2,
        };

        let mut manager = VersionBitsManager::with_deployments(vec![d1, d2]);

        // MTP = 1_500_000: deploy_a should be STARTED, deploy_b still DEFINED.
        manager.update_all_states(10, 1_500_000, &[]);

        assert_eq!(manager.get_state("deploy_a"), DeploymentState::Started);
        assert_eq!(manager.get_state("deploy_b"), DeploymentState::Defined);
    }

    // ---------------------------------------------------------------
    // Unknown deployment
    // ---------------------------------------------------------------

    #[test]
    fn test_get_state_unknown_deployment() {
        let manager = VersionBitsManager::new();
        assert_eq!(
            manager.get_state("nonexistent"),
            DeploymentState::Defined
        );
    }

    #[test]
    fn test_update_state_unknown_deployment() {
        let mut manager = VersionBitsManager::new();
        let state = manager.update_state("nonexistent", 0, 0, &[]);
        assert_eq!(state, DeploymentState::Defined);
    }
}
