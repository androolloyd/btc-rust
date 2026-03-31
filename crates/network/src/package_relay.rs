//! BIP331 Ancestor Package Relay.
//!
//! Package relay allows nodes to relay groups of related transactions as a
//! single unit, enabling child-pays-for-parent (CPFP) fee bumping to work
//! across the P2P network. Without package relay, a low-fee parent transaction
//! may be rejected by mempool policy even though a high-fee child would make
//! the package profitable to mine.
//!
//! This module provides:
//! - `PackageInfo` — metadata about a package of related transactions
//! - `PackagePolicy` — configurable limits on package size/weight
//! - `validate_package` — validates that a package meets policy requirements
//! - P2P message stubs for `ancpkginfo`, `getpkgtxns`, and `pkgtxns`

use btc_primitives::hash::TxHash;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("package is empty")]
    EmptyPackage,
    #[error("package exceeds maximum transaction count ({count} > {max})")]
    TooManyTransactions { count: usize, max: usize },
    #[error("package exceeds maximum weight ({weight} > {max})")]
    TooHeavy { weight: u64, max: u64 },
    #[error("package feerate too low ({feerate} sat/vB < {min} sat/vB)")]
    FeerateTooLow { feerate: f64, min: f64 },
    #[error("duplicate txid in package: {0}")]
    DuplicateTxid(TxHash),
    #[error("package has no child transaction")]
    NoChild,
    #[error("child transaction has no fee contribution")]
    ChildNoFee,
    #[error("negative fee in package entry")]
    NegativeFee,
}

// ---------------------------------------------------------------------------
// PackageInfo
// ---------------------------------------------------------------------------

/// Metadata about a single transaction within a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageTxInfo {
    /// Transaction ID.
    pub txid: TxHash,
    /// Witness transaction ID.
    pub wtxid: TxHash,
    /// Fee paid by this transaction in satoshis.
    pub fee: u64,
    /// Weight of this transaction in weight units.
    pub weight: u64,
}

/// An ancestor package: a set of related transactions where the last entry
/// is the child and all preceding entries are its ancestors.
///
/// The package is ordered topologically: parents appear before children.
/// The last transaction is the "child" that pays for the whole package via
/// CPFP (child-pays-for-parent).
#[derive(Debug, Clone)]
pub struct PackageInfo {
    /// The transactions in the package, ordered topologically.
    /// The last entry is the child; all others are ancestors.
    pub transactions: Vec<PackageTxInfo>,
}

impl PackageInfo {
    /// Create a new package from a list of transaction info entries.
    pub fn new(transactions: Vec<PackageTxInfo>) -> Self {
        PackageInfo { transactions }
    }

    /// The total fee of the package (sum of all individual fees).
    pub fn total_fee(&self) -> u64 {
        self.transactions.iter().map(|tx| tx.fee).sum()
    }

    /// The total weight of the package.
    pub fn total_weight(&self) -> u64 {
        self.transactions.iter().map(|tx| tx.weight).sum()
    }

    /// The package feerate in satoshis per virtual byte.
    /// Virtual bytes = weight / 4.
    pub fn feerate(&self) -> f64 {
        let weight = self.total_weight();
        if weight == 0 {
            return 0.0;
        }
        let vbytes = weight as f64 / 4.0;
        self.total_fee() as f64 / vbytes
    }

    /// Number of transactions in the package.
    pub fn count(&self) -> usize {
        self.transactions.len()
    }

    /// The child transaction (last in the topological order).
    pub fn child(&self) -> Option<&PackageTxInfo> {
        self.transactions.last()
    }
}

// ---------------------------------------------------------------------------
// PackagePolicy
// ---------------------------------------------------------------------------

/// Policy limits for package relay.
#[derive(Debug, Clone)]
pub struct PackagePolicy {
    /// Maximum number of transactions in a package (default: 25, matching
    /// Bitcoin Core's `DEFAULT_ANCESTOR_LIMIT`).
    pub max_package_count: usize,
    /// Maximum total weight of a package in weight units (default: 404,000,
    /// corresponding to ~101 kvB, matching `DEFAULT_ANCESTOR_SIZE_LIMIT_KVB`).
    pub max_package_weight: u64,
    /// Minimum package feerate in satoshis per virtual byte (default: 1.0).
    pub min_package_feerate: f64,
}

impl Default for PackagePolicy {
    fn default() -> Self {
        PackagePolicy {
            max_package_count: 25,
            max_package_weight: 404_000,
            min_package_feerate: 1.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Package result
// ---------------------------------------------------------------------------

/// Result of successful package validation.
#[derive(Debug, Clone)]
pub struct PackageResult {
    /// Total fee of the package in satoshis.
    pub total_fee: u64,
    /// Total weight of the package in weight units.
    pub total_weight: u64,
    /// Package feerate in sat/vB.
    pub feerate: f64,
    /// Number of transactions in the package.
    pub tx_count: usize,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate that a package of transactions meets policy requirements.
///
/// Checks:
/// 1. Package is not empty.
/// 2. No duplicate txids.
/// 3. Package does not exceed `max_package_count`.
/// 4. Package total weight does not exceed `max_package_weight`.
/// 5. Package feerate meets the minimum.
/// 6. No negative fees.
pub fn validate_package(
    package: &PackageInfo,
    policy: &PackagePolicy,
) -> Result<PackageResult, PackageError> {
    // 1. Must not be empty.
    if package.transactions.is_empty() {
        return Err(PackageError::EmptyPackage);
    }

    // 2. Check for duplicate txids.
    {
        let mut seen = std::collections::HashSet::new();
        for tx in &package.transactions {
            if !seen.insert(tx.txid) {
                return Err(PackageError::DuplicateTxid(tx.txid));
            }
        }
    }

    // 3. Count check.
    if package.count() > policy.max_package_count {
        return Err(PackageError::TooManyTransactions {
            count: package.count(),
            max: policy.max_package_count,
        });
    }

    // 4. Weight check.
    let total_weight = package.total_weight();
    if total_weight > policy.max_package_weight {
        return Err(PackageError::TooHeavy {
            weight: total_weight,
            max: policy.max_package_weight,
        });
    }

    // 5. Feerate check.
    let total_fee = package.total_fee();
    let feerate = package.feerate();
    if feerate < policy.min_package_feerate {
        return Err(PackageError::FeerateTooLow {
            feerate,
            min: policy.min_package_feerate,
        });
    }

    Ok(PackageResult {
        total_fee,
        total_weight,
        feerate,
        tx_count: package.count(),
    })
}

// ---------------------------------------------------------------------------
// P2P message stubs (BIP331)
// ---------------------------------------------------------------------------

/// `ancpkginfo` — Ancestor Package Info message.
///
/// Sent in response to a `getdata` for a transaction that is part of a
/// package. Contains the list of wtxids for the ancestors that form the
/// package with the requested transaction.
#[derive(Debug, Clone)]
pub struct AncPkgInfo {
    /// The wtxids of the ancestor transactions in the package,
    /// in topological order (parents first, child last).
    pub wtxids: Vec<TxHash>,
}

impl AncPkgInfo {
    pub fn new(wtxids: Vec<TxHash>) -> Self {
        AncPkgInfo { wtxids }
    }

    pub fn command() -> &'static str {
        "ancpkginfo"
    }
}

/// `getpkgtxns` — Request package transactions.
///
/// Sent after receiving `ancpkginfo` to request the actual transaction data
/// for the transactions in the package that the receiver does not already have.
#[derive(Debug, Clone)]
pub struct GetPkgTxns {
    /// The wtxids of the transactions being requested.
    pub wtxids: Vec<TxHash>,
}

impl GetPkgTxns {
    pub fn new(wtxids: Vec<TxHash>) -> Self {
        GetPkgTxns { wtxids }
    }

    pub fn command() -> &'static str {
        "getpkgtxns"
    }
}

/// `pkgtxns` — Package transactions response.
///
/// Sent in response to `getpkgtxns`. Contains the serialized transactions
/// that were requested. The transactions are in the same topological order
/// as in the `ancpkginfo` message.
#[derive(Debug, Clone)]
pub struct PkgTxns {
    /// The serialized transactions in the package.
    /// In a full implementation these would be `Transaction` objects;
    /// we use raw bytes here as a stub.
    pub transactions: Vec<Vec<u8>>,
}

impl PkgTxns {
    pub fn new(transactions: Vec<Vec<u8>>) -> Self {
        PkgTxns { transactions }
    }

    pub fn command() -> &'static str {
        "pkgtxns"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn txhash(byte: u8) -> TxHash {
        TxHash::from_bytes([byte; 32])
    }

    fn make_tx_info(byte: u8, fee: u64, weight: u64) -> PackageTxInfo {
        PackageTxInfo {
            txid: txhash(byte),
            wtxid: txhash(byte),
            fee,
            weight,
        }
    }

    // ---- Test: valid 2-tx package (parent + child CPFP) ----

    #[test]
    fn test_valid_two_tx_package() {
        // Parent: low fee (100 sat), 400 WU
        // Child: high fee (10_000 sat), 400 WU
        // Package feerate: 10100 / (800/4) = 10100 / 200 = 50.5 sat/vB
        let parent = make_tx_info(1, 100, 400);
        let child = make_tx_info(2, 10_000, 400);

        let package = PackageInfo::new(vec![parent, child]);
        let policy = PackagePolicy::default();

        let result = validate_package(&package, &policy).expect("should be valid");
        assert_eq!(result.total_fee, 10_100);
        assert_eq!(result.total_weight, 800);
        assert_eq!(result.tx_count, 2);
        assert!(result.feerate > 50.0);
    }

    // ---- Test: reject empty package ----

    #[test]
    fn test_reject_empty_package() {
        let package = PackageInfo::new(vec![]);
        let policy = PackagePolicy::default();

        let err = validate_package(&package, &policy).unwrap_err();
        assert!(matches!(err, PackageError::EmptyPackage));
    }

    // ---- Test: reject oversized package (too many transactions) ----

    #[test]
    fn test_reject_oversized_package_count() {
        let policy = PackagePolicy {
            max_package_count: 3,
            ..PackagePolicy::default()
        };

        let txs: Vec<PackageTxInfo> = (0..4u8)
            .map(|i| make_tx_info(i + 1, 1_000, 400))
            .collect();

        let package = PackageInfo::new(txs);
        let err = validate_package(&package, &policy).unwrap_err();

        match err {
            PackageError::TooManyTransactions { count, max } => {
                assert_eq!(count, 4);
                assert_eq!(max, 3);
            }
            other => panic!("expected TooManyTransactions, got: {:?}", other),
        }
    }

    // ---- Test: reject package exceeding weight limit ----

    #[test]
    fn test_reject_oversized_package_weight() {
        let policy = PackagePolicy {
            max_package_weight: 1_000,
            ..PackagePolicy::default()
        };

        let parent = make_tx_info(1, 500, 600);
        let child = make_tx_info(2, 500, 600);

        let package = PackageInfo::new(vec![parent, child]);
        let err = validate_package(&package, &policy).unwrap_err();

        match err {
            PackageError::TooHeavy { weight, max } => {
                assert_eq!(weight, 1_200);
                assert_eq!(max, 1_000);
            }
            other => panic!("expected TooHeavy, got: {:?}", other),
        }
    }

    // ---- Test: reject package with too-low feerate ----

    #[test]
    fn test_reject_low_feerate_package() {
        let policy = PackagePolicy {
            min_package_feerate: 10.0, // 10 sat/vB
            ..PackagePolicy::default()
        };

        // Package feerate: 100 / (4000/4) = 100 / 1000 = 0.1 sat/vB
        let parent = make_tx_info(1, 50, 2_000);
        let child = make_tx_info(2, 50, 2_000);

        let package = PackageInfo::new(vec![parent, child]);
        let err = validate_package(&package, &policy).unwrap_err();

        match err {
            PackageError::FeerateTooLow { .. } => {} // expected
            other => panic!("expected FeerateTooLow, got: {:?}", other),
        }
    }

    // ---- Test: reject duplicate txids ----

    #[test]
    fn test_reject_duplicate_txids() {
        let tx1 = make_tx_info(1, 1_000, 400);
        let tx2 = make_tx_info(1, 2_000, 400); // same txid as tx1

        let package = PackageInfo::new(vec![tx1, tx2]);
        let policy = PackagePolicy::default();

        let err = validate_package(&package, &policy).unwrap_err();
        assert!(matches!(err, PackageError::DuplicateTxid(_)));
    }

    // ---- Test: single tx package is valid ----

    #[test]
    fn test_single_tx_package() {
        let tx = make_tx_info(1, 5_000, 400);
        let package = PackageInfo::new(vec![tx]);
        let policy = PackagePolicy::default();

        let result = validate_package(&package, &policy).expect("should be valid");
        assert_eq!(result.tx_count, 1);
        assert_eq!(result.total_fee, 5_000);
    }

    // ---- Test: package info methods ----

    #[test]
    fn test_package_info_methods() {
        let parent = make_tx_info(1, 100, 400);
        let child = make_tx_info(2, 9_900, 600);

        let package = PackageInfo::new(vec![parent.clone(), child.clone()]);

        assert_eq!(package.total_fee(), 10_000);
        assert_eq!(package.total_weight(), 1_000);
        assert_eq!(package.count(), 2);
        assert_eq!(package.child(), Some(&child));

        // feerate = 10000 / (1000/4) = 10000 / 250 = 40.0 sat/vB
        assert!((package.feerate() - 40.0).abs() < 0.01);
    }

    // ---- Test: default policy values ----

    #[test]
    fn test_default_policy() {
        let policy = PackagePolicy::default();
        assert_eq!(policy.max_package_count, 25);
        assert_eq!(policy.max_package_weight, 404_000);
        assert!((policy.min_package_feerate - 1.0).abs() < f64::EPSILON);
    }

    // ---- Test: P2P message stubs ----

    #[test]
    fn test_p2p_message_commands() {
        assert_eq!(AncPkgInfo::command(), "ancpkginfo");
        assert_eq!(GetPkgTxns::command(), "getpkgtxns");
        assert_eq!(PkgTxns::command(), "pkgtxns");
    }

    #[test]
    fn test_ancpkginfo_creation() {
        let wtxids = vec![txhash(1), txhash(2), txhash(3)];
        let msg = AncPkgInfo::new(wtxids.clone());
        assert_eq!(msg.wtxids, wtxids);
    }

    #[test]
    fn test_getpkgtxns_creation() {
        let wtxids = vec![txhash(1), txhash(2)];
        let msg = GetPkgTxns::new(wtxids.clone());
        assert_eq!(msg.wtxids, wtxids);
    }

    #[test]
    fn test_pkgtxns_creation() {
        let txs = vec![vec![0x01, 0x00], vec![0x02, 0x00]];
        let msg = PkgTxns::new(txs.clone());
        assert_eq!(msg.transactions, txs);
    }

    // ---- Test: 25-tx package at the limit ----

    #[test]
    fn test_max_count_package_accepted() {
        let policy = PackagePolicy::default();
        let txs: Vec<PackageTxInfo> = (0..25u8)
            .map(|i| make_tx_info(i + 1, 1_000, 400))
            .collect();

        let package = PackageInfo::new(txs);
        let result = validate_package(&package, &policy);
        assert!(result.is_ok(), "25-tx package at limit should be accepted");
    }

    #[test]
    fn test_26_tx_package_rejected() {
        let policy = PackagePolicy::default();
        let txs: Vec<PackageTxInfo> = (0..26u8)
            .map(|i| make_tx_info(i + 1, 1_000, 400))
            .collect();

        let package = PackageInfo::new(txs);
        let err = validate_package(&package, &policy).unwrap_err();
        assert!(matches!(err, PackageError::TooManyTransactions { count: 26, max: 25 }));
    }
}
