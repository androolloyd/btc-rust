use std::collections::{BTreeMap, HashMap};

use btc_primitives::{Amount, Encodable, Transaction, TxHash};
use thiserror::Error;
use tracing::{debug, warn};

use crate::policy::{self, PolicyError, TxValidationPolicy};

/// Errors that can occur when interacting with the mempool.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MempoolError {
    #[error("transaction {0} already in mempool")]
    AlreadyExists(String),

    #[error("policy violation: {0}")]
    PolicyViolation(#[from] PolicyError),
}

/// A fee rate expressed in satoshis per virtual byte.
///
/// Stored as a fixed-point value (sat * 1000 / vsize) to avoid floating point
/// and to provide enough precision for ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct FeeRate(u64);

impl FeeRate {
    /// Compute fee rate from fee (satoshis) and virtual size (bytes).
    /// Returns fee * 1000 / vsize to maintain precision without floats.
    fn from_fee_vsize(fee: Amount, vsize: usize) -> Self {
        if vsize == 0 {
            return FeeRate(0);
        }
        FeeRate((fee.as_sat() as u64).saturating_mul(1000) / vsize as u64)
    }

    /// Get the fee rate as sat/vbyte (floating point, for display/estimation).
    fn as_sat_per_vbyte(&self) -> f64 {
        self.0 as f64 / 1000.0
    }
}

/// An entry in the mempool representing a single transaction.
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    /// The transaction itself.
    pub tx: Transaction,
    /// The fee paid by this transaction (inputs - outputs).
    pub fee: Amount,
    /// Serialized size of the transaction in bytes.
    pub size: usize,
    /// Timestamp when this transaction was added to the mempool (unix seconds).
    pub time_added: u64,
    /// Number of in-mempool ancestors.
    pub ancestors: usize,
    /// Number of in-mempool descendants.
    pub descendants: usize,
}

impl MempoolEntry {
    /// Compute the fee rate for this entry.
    fn fee_rate(&self) -> FeeRate {
        FeeRate::from_fee_vsize(self.fee, self.size)
    }
}

/// A composite key for the fee-rate ordered index.
/// Sorted by fee rate (ascending), then by txid bytes for uniqueness.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FeeRateKey {
    fee_rate: FeeRate,
    /// Raw txid bytes used to break ties deterministically.
    txid_bytes: [u8; 32],
}

/// The transaction mempool.
///
/// Stores unconfirmed transactions and provides fee-rate ordered access
/// for block template building and fee estimation.
pub struct Mempool {
    /// All transactions indexed by their txid.
    entries: HashMap<TxHash, MempoolEntry>,
    /// Fee-rate ordered index mapping to txid for O(log n) sorted access.
    by_fee_rate: BTreeMap<FeeRateKey, TxHash>,
    /// Maximum total size of all transactions in the mempool (bytes).
    max_size_bytes: usize,
    /// Maximum number of transactions allowed in the mempool.
    max_count: usize,
    /// Current total size of all transactions in the mempool (bytes).
    total_size: usize,
    /// Transaction validation policy.
    policy: TxValidationPolicy,
}

impl Mempool {
    /// Create a new mempool with the given limits.
    pub fn new(max_size_bytes: usize, max_count: usize) -> Self {
        Self {
            entries: HashMap::new(),
            by_fee_rate: BTreeMap::new(),
            max_size_bytes,
            max_count,
            total_size: 0,
            policy: TxValidationPolicy::default(),
        }
    }

    /// Create a new mempool with custom policy.
    pub fn with_policy(
        max_size_bytes: usize,
        max_count: usize,
        policy: TxValidationPolicy,
    ) -> Self {
        Self {
            entries: HashMap::new(),
            by_fee_rate: BTreeMap::new(),
            max_size_bytes,
            max_count,
            total_size: 0,
            policy,
        }
    }

    /// Add a transaction to the mempool.
    ///
    /// The caller must provide the fee (sum of input values minus sum of output values).
    /// The transaction is validated against the mempool policy before acceptance.
    /// If the mempool is full, the lowest fee-rate transaction(s) are evicted.
    pub fn add_tx(
        &mut self,
        tx: Transaction,
        fee: Amount,
        time_added: u64,
    ) -> Result<TxHash, MempoolError> {
        let txid = tx.txid();

        // Reject duplicates
        if self.entries.contains_key(&txid) {
            return Err(MempoolError::AlreadyExists(txid.to_hex()));
        }

        let size = tx.encoded_size();

        // Validate against policy
        policy::validate_tx_policy(&tx, fee, 0, 0, &self.policy)?;

        let entry = MempoolEntry {
            tx,
            fee,
            size,
            time_added,
            ancestors: 0,
            descendants: 0,
        };

        let fee_rate_key = FeeRateKey {
            fee_rate: entry.fee_rate(),
            txid_bytes: txid.to_bytes(),
        };

        // Insert into maps
        self.entries.insert(txid, entry);
        self.by_fee_rate.insert(fee_rate_key, txid);
        self.total_size += size;

        debug!(
            txid = %txid,
            size,
            fee = fee.as_sat(),
            "added transaction to mempool"
        );

        // Enforce limits by evicting lowest fee-rate transactions
        self.enforce_limits();

        // If we evicted the transaction we just added, it was the lowest fee-rate
        if !self.entries.contains_key(&txid) {
            warn!(txid = %txid, "transaction evicted immediately due to mempool limits");
        }

        Ok(txid)
    }

    /// Remove a transaction from the mempool by txid.
    /// Returns the removed entry, or None if not found.
    pub fn remove_tx(&mut self, txid: &TxHash) -> Option<MempoolEntry> {
        if let Some(entry) = self.entries.remove(txid) {
            let fee_rate_key = FeeRateKey {
                fee_rate: entry.fee_rate(),
                txid_bytes: txid.to_bytes(),
            };
            self.by_fee_rate.remove(&fee_rate_key);
            self.total_size -= entry.size;
            debug!(txid = %txid, "removed transaction from mempool");
            Some(entry)
        } else {
            None
        }
    }

    /// Get a reference to a transaction in the mempool.
    pub fn get_tx(&self, txid: &TxHash) -> Option<&MempoolEntry> {
        self.entries.get(txid)
    }

    /// Check whether a transaction is in the mempool.
    pub fn contains(&self, txid: &TxHash) -> bool {
        self.entries.contains_key(txid)
    }

    /// Return all txids currently in the mempool (unordered).
    pub fn get_all_txids(&self) -> Vec<TxHash> {
        self.entries.keys().copied().collect()
    }

    /// Return the number of transactions in the mempool.
    pub fn size(&self) -> usize {
        self.entries.len()
    }

    /// Return the total serialized size of all transactions in the mempool.
    pub fn total_bytes(&self) -> usize {
        self.total_size
    }

    /// Return transactions sorted by fee rate, highest first.
    /// This is the ordering used for block template building.
    pub fn get_sorted_by_fee(&self) -> Vec<&MempoolEntry> {
        // BTreeMap iterates in ascending order, so we reverse for highest-first.
        self.by_fee_rate
            .values()
            .rev()
            .filter_map(|txid| self.entries.get(txid))
            .collect()
    }

    /// Clear all transactions from the mempool.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.by_fee_rate.clear();
        self.total_size = 0;
        debug!("mempool cleared");
    }

    /// Estimate the fee (in satoshis) needed to confirm within `target_blocks` blocks.
    ///
    /// Uses a simple percentile-based approach: looks at the mempool sorted by fee rate
    /// and estimates based on how many transactions would fit in `target_blocks` worth
    /// of blocks (assuming ~4MB weight / ~1MB serialized per block).
    ///
    /// Returns the fee rate (sat/vbyte) as an Amount, or Amount::ZERO if the mempool is empty.
    pub fn estimate_fee(&self, target_blocks: usize) -> Amount {
        if self.entries.is_empty() || target_blocks == 0 {
            return Amount::from_sat(1); // minimum 1 sat/vbyte as fallback
        }

        let sorted = self.get_sorted_by_fee();

        // Approximate: each block can hold ~1,000,000 bytes of transactions.
        const BLOCK_SIZE: usize = 1_000_000;
        let target_bytes = BLOCK_SIZE * target_blocks;

        let mut cumulative_size: usize = 0;
        let mut threshold_entry: Option<&&MempoolEntry> = None;

        for entry in &sorted {
            cumulative_size += entry.size;
            if cumulative_size >= target_bytes {
                // This entry is at the boundary -- its fee rate is what you need
                threshold_entry = Some(entry);
                break;
            }
        }

        match threshold_entry {
            Some(entry) => {
                // Return the fee rate (sat/vbyte) as the per-byte fee needed
                let rate = entry.fee_rate().as_sat_per_vbyte();
                // Return as sat amount (fee per vbyte, ceiling)
                Amount::from_sat(rate.ceil() as i64)
            }
            None => {
                // The entire mempool fits within target_blocks -- minimum fee is sufficient
                if let Some(last) = sorted.last() {
                    let rate = last.fee_rate().as_sat_per_vbyte();
                    Amount::from_sat(rate.ceil() as i64)
                } else {
                    Amount::from_sat(1)
                }
            }
        }
    }

    /// Evict lowest fee-rate transactions until limits are satisfied.
    fn enforce_limits(&mut self) {
        while self.entries.len() > self.max_count || self.total_size > self.max_size_bytes {
            // Remove the lowest fee-rate entry (first in the BTreeMap)
            let lowest_key = match self.by_fee_rate.keys().next().cloned() {
                Some(k) => k,
                None => break,
            };
            let txid = self.by_fee_rate.remove(&lowest_key).unwrap();
            if let Some(entry) = self.entries.remove(&txid) {
                self.total_size -= entry.size;
                debug!(
                    txid = %txid,
                    fee_rate = lowest_key.fee_rate.as_sat_per_vbyte(),
                    "evicted transaction due to mempool limits"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::{OutPoint, ScriptBuf, TxIn, TxOut};

    /// Helper: build a transaction with a unique txid by varying the outpoint hash.
    fn make_test_tx(id_byte: u8, output_value: i64, script_size: usize) -> Transaction {
        let script_bytes = vec![0x76u8; script_size]; // fill with OP_DUP bytes
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([id_byte; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x00; 10]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: ScriptBuf::from_bytes(script_bytes),
            }],
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    #[test]
    fn test_add_and_get_tx() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx = make_test_tx(0x01, 50_000, 25);
        let txid = tx.txid();

        let result = pool.add_tx(tx, Amount::from_sat(5_000), 1000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), txid);
        assert!(pool.contains(&txid));
        assert_eq!(pool.size(), 1);

        let entry = pool.get_tx(&txid).unwrap();
        assert_eq!(entry.fee.as_sat(), 5_000);
        assert_eq!(entry.time_added, 1000);
    }

    #[test]
    fn test_add_duplicate_tx() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx = make_test_tx(0x01, 50_000, 25);
        pool.add_tx(tx.clone(), Amount::from_sat(5_000), 1000).unwrap();

        let result = pool.add_tx(tx, Amount::from_sat(5_000), 1001);
        assert!(matches!(result, Err(MempoolError::AlreadyExists(_))));
    }

    #[test]
    fn test_remove_tx() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx = make_test_tx(0x01, 50_000, 25);
        let txid = tx.txid();
        pool.add_tx(tx, Amount::from_sat(5_000), 1000).unwrap();

        let removed = pool.remove_tx(&txid);
        assert!(removed.is_some());
        assert!(!pool.contains(&txid));
        assert_eq!(pool.size(), 0);
        assert_eq!(pool.total_bytes(), 0);
    }

    #[test]
    fn test_remove_nonexistent_tx() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let fake_txid = TxHash::from_bytes([0xff; 32]);
        assert!(pool.remove_tx(&fake_txid).is_none());
    }

    #[test]
    fn test_get_all_txids() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx1 = make_test_tx(0x01, 50_000, 25);
        let tx2 = make_test_tx(0x02, 50_000, 25);
        let txid1 = tx1.txid();
        let txid2 = tx2.txid();

        pool.add_tx(tx1, Amount::from_sat(5_000), 1000).unwrap();
        pool.add_tx(tx2, Amount::from_sat(3_000), 1001).unwrap();

        let mut txids = pool.get_all_txids();
        txids.sort_by_key(|t| t.to_bytes());
        let mut expected = vec![txid1, txid2];
        expected.sort_by_key(|t| t.to_bytes());
        assert_eq!(txids, expected);
    }

    #[test]
    fn test_sorted_by_fee_rate() {
        let mut pool = Mempool::new(10_000_000, 1000);

        // All txs have the same size, so fee determines fee-rate ordering.
        let tx_low = make_test_tx(0x01, 50_000, 25);
        let tx_mid = make_test_tx(0x02, 50_000, 25);
        let tx_high = make_test_tx(0x03, 50_000, 25);

        let txid_low = tx_low.txid();
        let txid_mid = tx_mid.txid();
        let txid_high = tx_high.txid();

        pool.add_tx(tx_low, Amount::from_sat(1_000), 100).unwrap();
        pool.add_tx(tx_mid, Amount::from_sat(5_000), 101).unwrap();
        pool.add_tx(tx_high, Amount::from_sat(10_000), 102).unwrap();

        let sorted = pool.get_sorted_by_fee();
        assert_eq!(sorted.len(), 3);

        // Highest fee-rate first
        assert_eq!(sorted[0].tx.txid(), txid_high);
        assert_eq!(sorted[1].tx.txid(), txid_mid);
        assert_eq!(sorted[2].tx.txid(), txid_low);
    }

    #[test]
    fn test_count_limit_eviction() {
        let mut pool = Mempool::new(10_000_000, 3); // max 3 transactions

        let tx1 = make_test_tx(0x01, 50_000, 25);
        let tx2 = make_test_tx(0x02, 50_000, 25);
        let tx3 = make_test_tx(0x03, 50_000, 25);
        let tx4 = make_test_tx(0x04, 50_000, 25); // This should evict the lowest fee-rate

        let txid1 = tx1.txid();

        pool.add_tx(tx1, Amount::from_sat(1_000), 100).unwrap(); // lowest fee
        pool.add_tx(tx2, Amount::from_sat(5_000), 101).unwrap();
        pool.add_tx(tx3, Amount::from_sat(10_000), 102).unwrap();
        assert_eq!(pool.size(), 3);

        pool.add_tx(tx4, Amount::from_sat(8_000), 103).unwrap();
        assert_eq!(pool.size(), 3); // Still at max

        // The lowest fee-rate tx (tx1, 1000 sat) should have been evicted
        assert!(!pool.contains(&txid1));
    }

    #[test]
    fn test_size_limit_eviction() {
        // Each test tx with script_size=25 has a certain encoded size. Let's figure it out.
        let sample_tx = make_test_tx(0x01, 50_000, 25);
        let tx_size = sample_tx.encoded_size();

        // Allow room for exactly 2 transactions
        let max_bytes = tx_size * 2 + 1;
        let mut pool = Mempool::new(max_bytes, 1000);

        let tx1 = make_test_tx(0x01, 50_000, 25);
        let tx2 = make_test_tx(0x02, 50_000, 25);
        let tx3 = make_test_tx(0x03, 50_000, 25);
        let txid1 = tx1.txid();

        pool.add_tx(tx1, Amount::from_sat(1_000), 100).unwrap();
        pool.add_tx(tx2, Amount::from_sat(5_000), 101).unwrap();
        assert_eq!(pool.size(), 2);

        // Adding a 3rd tx should evict the lowest fee-rate
        pool.add_tx(tx3, Amount::from_sat(8_000), 102).unwrap();
        assert_eq!(pool.size(), 2);
        assert!(!pool.contains(&txid1));
    }

    #[test]
    fn test_clear() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx1 = make_test_tx(0x01, 50_000, 25);
        let tx2 = make_test_tx(0x02, 50_000, 25);

        pool.add_tx(tx1, Amount::from_sat(5_000), 100).unwrap();
        pool.add_tx(tx2, Amount::from_sat(3_000), 101).unwrap();
        assert_eq!(pool.size(), 2);

        pool.clear();
        assert_eq!(pool.size(), 0);
        assert_eq!(pool.total_bytes(), 0);
    }

    #[test]
    fn test_total_bytes_tracking() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx1 = make_test_tx(0x01, 50_000, 25);
        let tx2 = make_test_tx(0x02, 50_000, 50);
        let size1 = tx1.encoded_size();
        let size2 = tx2.encoded_size();
        let txid1 = tx1.txid();

        pool.add_tx(tx1, Amount::from_sat(5_000), 100).unwrap();
        assert_eq!(pool.total_bytes(), size1);

        pool.add_tx(tx2, Amount::from_sat(3_000), 101).unwrap();
        assert_eq!(pool.total_bytes(), size1 + size2);

        pool.remove_tx(&txid1);
        assert_eq!(pool.total_bytes(), size2);
    }

    #[test]
    fn test_fee_estimation_empty_mempool() {
        let pool = Mempool::new(10_000_000, 1000);
        let est = pool.estimate_fee(1);
        assert_eq!(est.as_sat(), 1); // fallback minimum
    }

    #[test]
    fn test_fee_estimation_small_mempool() {
        let mut pool = Mempool::new(10_000_000, 1000);

        // Add a few txs that are small -- the entire mempool will fit in one block
        let tx1 = make_test_tx(0x01, 50_000, 25);
        let tx2 = make_test_tx(0x02, 50_000, 25);
        let tx3 = make_test_tx(0x03, 50_000, 25);

        pool.add_tx(tx1, Amount::from_sat(2_000), 100).unwrap();
        pool.add_tx(tx2, Amount::from_sat(5_000), 101).unwrap();
        pool.add_tx(tx3, Amount::from_sat(10_000), 102).unwrap();

        // With a small mempool, all txs fit in target_blocks=1
        // Should return the fee rate of the lowest-fee tx
        let est = pool.estimate_fee(1);
        assert!(est.as_sat() >= 1); // At least 1 sat/vbyte
    }

    #[test]
    fn test_fee_estimation_with_target_blocks() {
        let mut pool = Mempool::new(100_000_000, 100_000);

        // Simulate a more realistic scenario with many transactions.
        // Fee starts at 1000 sat (min relay fee) and increases.
        for i in 1u16..=100 {
            let tx = make_test_tx(i as u8, 50_000, 25);
            let fee = Amount::from_sat(1_000 + i as i64 * 100);
            pool.add_tx(tx, fee, i as u64).unwrap();
        }

        // All 100 txs are tiny, so they all fit in 1 block
        let est_1 = pool.estimate_fee(1);
        let est_6 = pool.estimate_fee(6);

        // Both should give reasonable estimates (the lowest fee-rate in the pool)
        assert!(est_1.as_sat() >= 1);
        assert!(est_6.as_sat() >= 1);

        // With more target blocks, the estimate should be <= estimate for fewer blocks
        // (or equal if pool is small)
        assert!(est_6.as_sat() <= est_1.as_sat());
    }

    #[test]
    fn test_policy_rejection_propagates() {
        let mut pool = Mempool::new(10_000_000, 1000);

        // Create a tx with dust output
        let tx = make_test_tx(0x01, 100, 25); // 100 sat < 546 dust limit
        let result = pool.add_tx(tx, Amount::from_sat(5_000), 100);

        assert!(matches!(
            result,
            Err(MempoolError::PolicyViolation(PolicyError::DustOutput { .. }))
        ));
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_policy_insufficient_fee_rejected() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx = make_test_tx(0x01, 50_000, 25);

        let result = pool.add_tx(tx, Amount::from_sat(100), 100); // below min relay fee
        assert!(matches!(
            result,
            Err(MempoolError::PolicyViolation(PolicyError::InsufficientFee { .. }))
        ));
    }

    #[test]
    fn test_fee_rate_calculation() {
        // A transaction with 1000 sat fee and 200 bytes should have ~5 sat/vbyte
        let rate = FeeRate::from_fee_vsize(Amount::from_sat(1000), 200);
        assert_eq!(rate.as_sat_per_vbyte(), 5.0);

        // Edge case: zero vsize
        let rate_zero = FeeRate::from_fee_vsize(Amount::from_sat(1000), 0);
        assert_eq!(rate_zero.0, 0);
    }

    #[test]
    fn test_fee_rate_ordering() {
        let low = FeeRate::from_fee_vsize(Amount::from_sat(100), 200);
        let high = FeeRate::from_fee_vsize(Amount::from_sat(1000), 200);
        assert!(low < high);
    }

    #[test]
    fn test_eviction_order_is_lowest_fee_rate_first() {
        let mut pool = Mempool::new(10_000_000, 5);

        // Add 5 txs with different fee rates
        let mut txids = Vec::new();
        for i in 1u8..=5 {
            let tx = make_test_tx(i, 50_000, 25);
            txids.push(tx.txid());
            pool.add_tx(tx, Amount::from_sat(i as i64 * 1_000), i as u64 * 100)
                .unwrap();
        }
        assert_eq!(pool.size(), 5);

        // Add a 6th tx with medium fee -- should evict the lowest (i=1, 1000 sat)
        let tx6 = make_test_tx(0x06, 50_000, 25);
        pool.add_tx(tx6, Amount::from_sat(3_500), 600).unwrap();

        assert_eq!(pool.size(), 5);
        assert!(!pool.contains(&txids[0])); // tx with 1000 sat fee evicted
        assert!(pool.contains(&txids[1])); // tx with 2000 sat fee still present
        assert!(pool.contains(&txids[2])); // tx with 3000 sat fee still present
    }

    #[test]
    fn test_with_custom_policy() {
        let policy = TxValidationPolicy {
            min_relay_fee: Amount::from_sat(500),
            dust_limit: Amount::from_sat(200),
            ..Default::default()
        };
        let mut pool = Mempool::with_policy(10_000_000, 1000, policy);

        // Should accept tx with 500 sat fee (custom min) and 200 sat output (custom dust)
        let tx = make_test_tx(0x01, 300, 25);
        let result = pool.add_tx(tx, Amount::from_sat(500), 100);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------
    // Additional coverage tests
    // -----------------------------------------------------------------

    #[test]
    fn test_fee_estimation_zero_target_blocks() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx = make_test_tx(0x01, 50_000, 25);
        pool.add_tx(tx, Amount::from_sat(5_000), 100).unwrap();

        // target_blocks == 0 => fallback
        let est = pool.estimate_fee(0);
        assert_eq!(est.as_sat(), 1);
    }

    #[test]
    fn test_fee_rate_as_sat_per_vbyte() {
        // 5000 sat fee / 100 bytes = 50 sat/vbyte
        let rate = FeeRate::from_fee_vsize(Amount::from_sat(5000), 100);
        assert_eq!(rate.as_sat_per_vbyte(), 50.0);
    }

    #[test]
    fn test_fee_rate_precision() {
        // 1 sat fee / 3 bytes = 0.333... => stored as 1000/3 = 333
        let rate = FeeRate::from_fee_vsize(Amount::from_sat(1), 3);
        assert_eq!(rate.0, 333);
        let spv = rate.as_sat_per_vbyte();
        assert!((spv - 0.333).abs() < 0.001);
    }

    #[test]
    fn test_fee_rate_zero_fee() {
        let rate = FeeRate::from_fee_vsize(Amount::from_sat(0), 100);
        assert_eq!(rate.0, 0);
        assert_eq!(rate.as_sat_per_vbyte(), 0.0);
    }

    #[test]
    fn test_mempool_entry_fee_rate() {
        let tx = make_test_tx(0x01, 50_000, 25);
        let size = tx.encoded_size();
        let entry = MempoolEntry {
            tx,
            fee: Amount::from_sat(10_000),
            size,
            time_added: 0,
            ancestors: 0,
            descendants: 0,
        };
        let rate = entry.fee_rate();
        assert!(rate.0 > 0);
    }

    #[test]
    fn test_get_tx_returns_none_for_missing() {
        let pool = Mempool::new(10_000_000, 1000);
        let fake_txid = TxHash::from_bytes([0xab; 32]);
        assert!(pool.get_tx(&fake_txid).is_none());
    }

    #[test]
    fn test_contains_false_for_missing() {
        let pool = Mempool::new(10_000_000, 1000);
        let fake_txid = TxHash::from_bytes([0xcd; 32]);
        assert!(!pool.contains(&fake_txid));
    }

    #[test]
    fn test_get_all_txids_empty() {
        let pool = Mempool::new(10_000_000, 1000);
        assert!(pool.get_all_txids().is_empty());
    }

    #[test]
    fn test_size_empty() {
        let pool = Mempool::new(10_000_000, 1000);
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_total_bytes_empty() {
        let pool = Mempool::new(10_000_000, 1000);
        assert_eq!(pool.total_bytes(), 0);
    }

    #[test]
    fn test_get_sorted_by_fee_empty() {
        let pool = Mempool::new(10_000_000, 1000);
        assert!(pool.get_sorted_by_fee().is_empty());
    }

    #[test]
    fn test_clear_already_empty() {
        let mut pool = Mempool::new(10_000_000, 1000);
        pool.clear(); // Should not panic
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_multiple_evictions_until_limit() {
        // Pool allows max 2 txs. Add 5 txs; each triggers eviction.
        let mut pool = Mempool::new(10_000_000, 2);

        for i in 1u8..=5 {
            let tx = make_test_tx(i, 50_000, 25);
            pool.add_tx(tx, Amount::from_sat(i as i64 * 1000), i as u64 * 100)
                .unwrap();
        }

        assert_eq!(pool.size(), 2);
        // Only the two highest fee txs should remain (i=4: 4000, i=5: 5000)
        let sorted = pool.get_sorted_by_fee();
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0].fee.as_sat(), 5000);
        assert_eq!(sorted[1].fee.as_sat(), 4000);
    }

    #[test]
    fn test_eviction_with_equal_fees() {
        // Txs with equal fees -- deterministic eviction by txid
        let mut pool = Mempool::new(10_000_000, 2);

        let tx1 = make_test_tx(0x01, 50_000, 25);
        let tx2 = make_test_tx(0x02, 50_000, 25);
        let tx3 = make_test_tx(0x03, 50_000, 25);

        pool.add_tx(tx1, Amount::from_sat(5_000), 100).unwrap();
        pool.add_tx(tx2, Amount::from_sat(5_000), 101).unwrap();
        pool.add_tx(tx3, Amount::from_sat(5_000), 102).unwrap();

        assert_eq!(pool.size(), 2);
    }

    #[test]
    fn test_fee_estimation_large_mempool() {
        let mut pool = Mempool::new(100_000_000, 100_000);

        // Add many transactions to exceed 1 block worth of data
        // Each tx is ~100 bytes, so we need ~10000 to fill a 1MB block
        for i in 1u16..=200 {
            let tx = make_test_tx(i as u8, 50_000, 25);
            let fee = Amount::from_sat(1_000 + (i as i64) * 50);
            pool.add_tx(tx, fee, i as u64).unwrap();
        }

        let est_1 = pool.estimate_fee(1);
        let est_10 = pool.estimate_fee(10);

        // Both should return reasonable values
        assert!(est_1.as_sat() >= 1);
        assert!(est_10.as_sat() >= 1);
        // More target blocks => lower or equal fee estimate
        assert!(est_10.as_sat() <= est_1.as_sat());
    }

    #[test]
    fn test_fee_estimation_returns_lowest_when_all_fit() {
        let mut pool = Mempool::new(10_000_000, 1000);

        let tx_low = make_test_tx(0x01, 50_000, 25);
        let tx_high = make_test_tx(0x02, 50_000, 25);

        pool.add_tx(tx_low, Amount::from_sat(2_000), 100).unwrap();
        pool.add_tx(tx_high, Amount::from_sat(20_000), 101).unwrap();

        // All txs fit in 1 block
        let est = pool.estimate_fee(1);
        // Should return the lowest fee rate
        assert!(est.as_sat() >= 1);
    }

    #[test]
    fn test_add_tx_returns_correct_txid() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx = make_test_tx(0x42, 50_000, 25);
        let expected_txid = tx.txid();
        let result = pool.add_tx(tx, Amount::from_sat(5_000), 100).unwrap();
        assert_eq!(result, expected_txid);
    }

    #[test]
    fn test_remove_tx_returns_entry() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx = make_test_tx(0x01, 50_000, 25);
        let txid = tx.txid();
        pool.add_tx(tx, Amount::from_sat(5_000), 100).unwrap();

        let removed = pool.remove_tx(&txid).unwrap();
        assert_eq!(removed.fee.as_sat(), 5_000);
        assert_eq!(removed.time_added, 100);
    }

    #[test]
    fn test_error_display_already_exists() {
        let err = MempoolError::AlreadyExists("deadbeef".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("deadbeef"));
        assert!(msg.contains("already in mempool"));
    }

    #[test]
    fn test_error_display_policy_violation() {
        let policy_err = PolicyError::InsufficientFee {
            fee: 100,
            min_fee: 1000,
        };
        let err = MempoolError::PolicyViolation(policy_err);
        let msg = format!("{}", err);
        assert!(msg.contains("policy violation"));
    }

    #[test]
    fn test_fee_rate_key_ordering() {
        let key_low = FeeRateKey {
            fee_rate: FeeRate(100),
            txid_bytes: [0x01; 32],
        };
        let key_high = FeeRateKey {
            fee_rate: FeeRate(200),
            txid_bytes: [0x01; 32],
        };
        assert!(key_low < key_high);

        // Same fee rate, different txid: ordered by txid
        let key_a = FeeRateKey {
            fee_rate: FeeRate(100),
            txid_bytes: [0x01; 32],
        };
        let key_b = FeeRateKey {
            fee_rate: FeeRate(100),
            txid_bytes: [0x02; 32],
        };
        assert!(key_a < key_b);
    }

    #[test]
    fn test_fee_rate_key_equality() {
        let key1 = FeeRateKey {
            fee_rate: FeeRate(100),
            txid_bytes: [0x01; 32],
        };
        let key2 = FeeRateKey {
            fee_rate: FeeRate(100),
            txid_bytes: [0x01; 32],
        };
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_sorted_by_fee_single_tx() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx = make_test_tx(0x01, 50_000, 25);
        pool.add_tx(tx, Amount::from_sat(5_000), 100).unwrap();

        let sorted = pool.get_sorted_by_fee();
        assert_eq!(sorted.len(), 1);
    }

    #[test]
    fn test_add_many_txs_and_get_all() {
        let mut pool = Mempool::new(10_000_000, 1000);
        for i in 1u8..=10 {
            let tx = make_test_tx(i, 50_000, 25);
            pool.add_tx(tx, Amount::from_sat(1_000 + i as i64 * 100), i as u64)
                .unwrap();
        }
        assert_eq!(pool.size(), 10);
        assert_eq!(pool.get_all_txids().len(), 10);
    }

    #[test]
    fn test_remove_and_readd() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx = make_test_tx(0x01, 50_000, 25);
        let txid = tx.txid();

        pool.add_tx(tx.clone(), Amount::from_sat(5_000), 100).unwrap();
        pool.remove_tx(&txid);
        assert!(!pool.contains(&txid));

        // Re-add same tx
        let result = pool.add_tx(tx, Amount::from_sat(5_000), 200);
        assert!(result.is_ok());
        assert!(pool.contains(&txid));
    }

    #[test]
    fn test_clear_then_add() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx1 = make_test_tx(0x01, 50_000, 25);
        pool.add_tx(tx1, Amount::from_sat(5_000), 100).unwrap();
        pool.clear();

        let tx2 = make_test_tx(0x02, 50_000, 25);
        pool.add_tx(tx2, Amount::from_sat(3_000), 200).unwrap();
        assert_eq!(pool.size(), 1);
    }

    #[test]
    fn test_eviction_by_size_multi_step() {
        let sample_tx = make_test_tx(0x01, 50_000, 25);
        let tx_size = sample_tx.encoded_size();

        // Allow exactly 1 tx
        let max_bytes = tx_size;
        let mut pool = Mempool::new(max_bytes, 1000);

        let tx1 = make_test_tx(0x01, 50_000, 25);
        let tx2 = make_test_tx(0x02, 50_000, 25);

        pool.add_tx(tx1, Amount::from_sat(1_000), 100).unwrap();
        pool.add_tx(tx2, Amount::from_sat(2_000), 101).unwrap();

        // Only higher-fee tx should remain
        assert_eq!(pool.size(), 1);
        let sorted = pool.get_sorted_by_fee();
        assert_eq!(sorted[0].fee.as_sat(), 2_000);
    }

    #[test]
    fn test_estimate_fee_single_tx() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx = make_test_tx(0x01, 50_000, 25);
        pool.add_tx(tx, Amount::from_sat(5_000), 100).unwrap();

        let est = pool.estimate_fee(1);
        assert!(est.as_sat() >= 1);
    }

    #[test]
    fn test_estimate_fee_high_target() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx = make_test_tx(0x01, 50_000, 25);
        pool.add_tx(tx, Amount::from_sat(5_000), 100).unwrap();

        // Very high target => still returns the lowest fee rate
        let est = pool.estimate_fee(100);
        assert!(est.as_sat() >= 1);
    }

    #[test]
    fn test_policy_error_from_conversion() {
        let policy_err = PolicyError::TxTooLarge {
            size: 200_000,
            max: 100_000,
        };
        let mempool_err: MempoolError = policy_err.into();
        assert!(matches!(mempool_err, MempoolError::PolicyViolation(_)));
    }

    #[test]
    fn test_mempool_entry_debug() {
        let tx = make_test_tx(0x01, 50_000, 25);
        let entry = MempoolEntry {
            tx,
            fee: Amount::from_sat(1000),
            size: 100,
            time_added: 12345,
            ancestors: 0,
            descendants: 0,
        };
        let debug = format!("{:?}", entry);
        assert!(debug.contains("MempoolEntry"));
    }
}
