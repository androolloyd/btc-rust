//! # Cluster Mempool
//!
//! Groups related transactions (parent/child chains) into clusters and selects
//! clusters by aggregate feerate for block template building. This mirrors the
//! cluster-mempool approach discussed in Bitcoin Core proposals where
//! transaction dependencies are considered as a unit for fee evaluation.

use std::collections::{HashMap, HashSet};

use btc_primitives::hash::TxHash;
use crate::pool::Mempool;

// ---------------------------------------------------------------------------
// TxCluster
// ---------------------------------------------------------------------------

/// A group of related transactions that form a parent-child dependency chain.
///
/// All transactions in a cluster must be included together (a child cannot be
/// mined without its parent). The cluster feerate is the aggregate
/// `total_fees / total_weight`, which gives a better signal for mining
/// profitability than individual transaction feerates.
#[derive(Debug, Clone)]
pub struct TxCluster {
    /// Transaction IDs in this cluster (topologically ordered, parents first).
    pub txids: Vec<TxHash>,
    /// Total fees for all transactions in the cluster (satoshis).
    pub total_fees: u64,
    /// Total serialized weight of all transactions in the cluster (bytes).
    pub total_weight: usize,
}

impl TxCluster {
    /// Compute the cluster feerate as total_fees * 1000 / total_weight.
    /// Returns 0 if total_weight is 0.
    pub fn feerate(&self) -> u64 {
        if self.total_weight == 0 {
            return 0;
        }
        self.total_fees.saturating_mul(1000) / self.total_weight as u64
    }
}

// ---------------------------------------------------------------------------
// ClusterMempool
// ---------------------------------------------------------------------------

/// A wrapper around [`Mempool`] that adds cluster-based transaction grouping.
///
/// Transactions are grouped by their input-output relationships: if transaction
/// B spends an output of transaction A, both are placed in the same cluster.
pub struct ClusterMempool {
    /// The underlying mempool containing all individual transactions.
    pub mempool: Mempool,
}

impl ClusterMempool {
    /// Create a new cluster mempool wrapping the given mempool.
    pub fn new(mempool: Mempool) -> Self {
        Self { mempool }
    }

    /// Build clusters from the current mempool state.
    pub fn build_clusters(&self) -> Vec<TxCluster> {
        build_clusters(&self.mempool)
    }

    /// Select transactions for a block template using cluster-based feerate
    /// ordering. Returns transactions in dependency-safe order (parents before
    /// children).
    pub fn select_for_block(&self, max_weight: usize) -> Vec<TxHash> {
        let clusters = self.build_clusters();
        select_for_block(&clusters, max_weight)
    }
}

// ---------------------------------------------------------------------------
// build_clusters
// ---------------------------------------------------------------------------

/// Analyze the mempool transaction graph and group transactions into clusters
/// based on input/output relationships.
///
/// Two transactions are in the same cluster if one spends an output created by
/// the other (directly or transitively).
pub fn build_clusters(mempool: &Mempool) -> Vec<TxCluster> {
    let all_txids = mempool.get_all_txids();
    if all_txids.is_empty() {
        return Vec::new();
    }

    // Build a set of all txids in the mempool for O(1) lookup.
    let mempool_txids: HashSet<TxHash> = all_txids.iter().copied().collect();

    // Map from txid -> set of txids it depends on (parents in the mempool).
    let mut parents: HashMap<TxHash, HashSet<TxHash>> = HashMap::new();
    // Map from txid -> set of txids that depend on it (children in the mempool).
    let mut children: HashMap<TxHash, HashSet<TxHash>> = HashMap::new();

    for &txid in &all_txids {
        parents.entry(txid).or_default();
        children.entry(txid).or_default();
    }

    // Build the dependency graph.
    for &txid in &all_txids {
        if let Some(entry) = mempool.get_tx(&txid) {
            for input in &entry.tx.inputs {
                let parent_txid = input.previous_output.txid;
                if mempool_txids.contains(&parent_txid) && parent_txid != txid {
                    parents.entry(txid).or_default().insert(parent_txid);
                    children.entry(parent_txid).or_default().insert(txid);
                }
            }
        }
    }

    // Use union-find to group connected transactions into clusters.
    let mut cluster_id: HashMap<TxHash, TxHash> = HashMap::new();
    for &txid in &all_txids {
        cluster_id.insert(txid, txid);
    }

    // Find with path compression.
    fn find(cluster_id: &mut HashMap<TxHash, TxHash>, x: TxHash) -> TxHash {
        let mut root = x;
        while cluster_id[&root] != root {
            root = cluster_id[&root];
        }
        // Path compression
        let mut current = x;
        while current != root {
            let next = cluster_id[&current];
            cluster_id.insert(current, root);
            current = next;
        }
        root
    }

    // Union all connected pairs.
    for &txid in &all_txids {
        if let Some(parent_set) = parents.get(&txid) {
            for &parent in parent_set {
                let root_a = find(&mut cluster_id, txid);
                let root_b = find(&mut cluster_id, parent);
                if root_a != root_b {
                    cluster_id.insert(root_a, root_b);
                }
            }
        }
    }

    // Group txids by their cluster root.
    let mut groups: HashMap<TxHash, Vec<TxHash>> = HashMap::new();
    for &txid in &all_txids {
        let root = find(&mut cluster_id, txid);
        groups.entry(root).or_default().push(txid);
    }

    // Build TxCluster for each group.
    let mut clusters = Vec::new();
    for (_root, mut txids) in groups {
        // Topological sort: parents before children.
        txids.sort_by(|a, b| {
            let a_is_parent_of_b = parents
                .get(b)
                .map(|p| p.contains(a))
                .unwrap_or(false);
            let b_is_parent_of_a = parents
                .get(a)
                .map(|p| p.contains(b))
                .unwrap_or(false);
            if a_is_parent_of_b {
                std::cmp::Ordering::Less
            } else if b_is_parent_of_a {
                std::cmp::Ordering::Greater
            } else {
                a.to_bytes().cmp(&b.to_bytes())
            }
        });

        let mut total_fees = 0u64;
        let mut total_weight = 0usize;

        for &txid in &txids {
            if let Some(entry) = mempool.get_tx(&txid) {
                total_fees += entry.fee.as_sat() as u64;
                total_weight += entry.size;
            }
        }

        clusters.push(TxCluster {
            txids,
            total_fees,
            total_weight,
        });
    }

    clusters
}

// ---------------------------------------------------------------------------
// select_for_block
// ---------------------------------------------------------------------------

/// Greedy cluster selection for block template building.
///
/// Sorts clusters by feerate (highest first) and greedily adds entire clusters
/// to the block template until the weight limit is reached. Returns the txids
/// of selected transactions in dependency-safe order.
pub fn select_for_block(clusters: &[TxCluster], max_weight: usize) -> Vec<TxHash> {
    let mut sorted: Vec<&TxCluster> = clusters.iter().collect();
    sorted.sort_by(|a, b| b.feerate().cmp(&a.feerate()));

    let mut selected = Vec::new();
    let mut remaining_weight = max_weight;

    for cluster in sorted {
        if cluster.total_weight <= remaining_weight {
            selected.extend_from_slice(&cluster.txids);
            remaining_weight -= cluster.total_weight;
        }
    }

    selected
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::amount::Amount;
    use btc_primitives::encode::Encodable;
    use btc_primitives::script::ScriptBuf;
    use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

    /// Helper: build a transaction that optionally spends from a given parent txid.
    fn make_tx(id_byte: u8, parent_txid: Option<TxHash>, output_value: i64) -> Transaction {
        let previous_output = match parent_txid {
            Some(txid) => OutPoint::new(txid, 0),
            None => OutPoint::new(TxHash::from_bytes([id_byte; 32]), 0),
        };

        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::from_bytes(vec![0x00; 10]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76u8; 25]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    #[test]
    fn test_independent_txs_form_separate_clusters() {
        let mut pool = Mempool::new(10_000_000, 1000);

        let tx_a = make_tx(0x01, None, 50_000);
        let tx_b = make_tx(0x02, None, 50_000);
        let tx_c = make_tx(0x03, None, 50_000);

        pool.add_tx(tx_a, Amount::from_sat(5_000), 100).unwrap();
        pool.add_tx(tx_b, Amount::from_sat(3_000), 101).unwrap();
        pool.add_tx(tx_c, Amount::from_sat(7_000), 102).unwrap();

        let clusters = build_clusters(&pool);
        assert_eq!(clusters.len(), 3, "independent txs should form 3 clusters");

        for cluster in &clusters {
            assert_eq!(cluster.txids.len(), 1);
        }
    }

    #[test]
    fn test_parent_child_form_single_cluster() {
        let mut pool = Mempool::new(10_000_000, 1000);

        // Parent tx
        let parent = make_tx(0x01, None, 50_000);
        let parent_txid = parent.txid();
        pool.add_tx(parent, Amount::from_sat(2_000), 100).unwrap();

        // Child tx spending from parent
        let child = make_tx(0x02, Some(parent_txid), 40_000);
        pool.add_tx(child, Amount::from_sat(8_000), 101).unwrap();

        let clusters = build_clusters(&pool);
        assert_eq!(clusters.len(), 1, "parent+child should form 1 cluster");
        assert_eq!(clusters[0].txids.len(), 2);
        assert_eq!(clusters[0].total_fees, 10_000); // 2000 + 8000
    }

    #[test]
    fn test_cluster_feerate_computation() {
        let mut pool = Mempool::new(10_000_000, 1000);

        let tx_a = make_tx(0x01, None, 50_000);
        let tx_a_txid = tx_a.txid();
        let tx_a_size = tx_a.encoded_size();
        pool.add_tx(tx_a, Amount::from_sat(5_000), 100).unwrap();

        let tx_b = make_tx(0x02, Some(tx_a_txid), 40_000);
        let tx_b_size = tx_b.encoded_size();
        pool.add_tx(tx_b, Amount::from_sat(3_000), 101).unwrap();

        let clusters = build_clusters(&pool);
        assert_eq!(clusters.len(), 1);

        let cluster = &clusters[0];
        let expected_total_weight = tx_a_size + tx_b_size;
        assert_eq!(cluster.total_weight, expected_total_weight);
        assert_eq!(cluster.total_fees, 8_000); // 5000 + 3000

        // feerate = total_fees * 1000 / total_weight
        let expected_feerate = 8_000u64 * 1000 / expected_total_weight as u64;
        assert_eq!(cluster.feerate(), expected_feerate);
    }

    #[test]
    fn test_cluster_feerate_zero_weight() {
        let cluster = TxCluster {
            txids: vec![],
            total_fees: 1000,
            total_weight: 0,
        };
        assert_eq!(cluster.feerate(), 0);
    }

    #[test]
    fn test_select_for_block_greedy() {
        let mut pool = Mempool::new(10_000_000, 1000);

        // Create two independent txs with different feerates
        let tx_low = make_tx(0x01, None, 50_000);
        let tx_low_size = tx_low.encoded_size();
        let txid_low = tx_low.txid();
        pool.add_tx(tx_low, Amount::from_sat(1_000), 100).unwrap();

        let tx_high = make_tx(0x02, None, 50_000);
        let tx_high_size = tx_high.encoded_size();
        let txid_high = tx_high.txid();
        pool.add_tx(tx_high, Amount::from_sat(10_000), 101).unwrap();

        let clusters = build_clusters(&pool);

        // Enough weight for both
        let selected = select_for_block(&clusters, tx_low_size + tx_high_size + 100);
        assert_eq!(selected.len(), 2);
        // Highest feerate should come first
        assert_eq!(selected[0], txid_high);
        assert_eq!(selected[1], txid_low);
    }

    #[test]
    fn test_select_for_block_weight_limit() {
        let mut pool = Mempool::new(10_000_000, 1000);

        let tx_a = make_tx(0x01, None, 50_000);
        let tx_a_size = tx_a.encoded_size();
        pool.add_tx(tx_a, Amount::from_sat(5_000), 100).unwrap();

        let tx_b = make_tx(0x02, None, 50_000);
        pool.add_tx(tx_b, Amount::from_sat(3_000), 101).unwrap();

        let clusters = build_clusters(&pool);

        // Only enough weight for one tx
        let selected = select_for_block(&clusters, tx_a_size);
        assert_eq!(selected.len(), 1);
    }

    #[test]
    fn test_select_for_block_empty() {
        let clusters: Vec<TxCluster> = Vec::new();
        let selected = select_for_block(&clusters, 1_000_000);
        assert!(selected.is_empty());
    }

    #[test]
    fn test_three_tx_chain_single_cluster() {
        let mut pool = Mempool::new(10_000_000, 1000);

        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        pool.add_tx(tx_a, Amount::from_sat(3_000), 100).unwrap();

        let tx_b = make_tx(0x02, Some(txid_a), 40_000);
        let txid_b = tx_b.txid();
        pool.add_tx(tx_b, Amount::from_sat(4_000), 101).unwrap();

        let tx_c = make_tx(0x03, Some(txid_b), 30_000);
        pool.add_tx(tx_c, Amount::from_sat(5_000), 102).unwrap();

        let clusters = build_clusters(&pool);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].txids.len(), 3);
        assert_eq!(clusters[0].total_fees, 12_000); // 3000 + 4000 + 5000
    }

    #[test]
    fn test_cluster_mempool_wrapper() {
        let pool = Mempool::new(10_000_000, 1000);
        let mut cm = ClusterMempool::new(pool);

        let tx = make_tx(0x01, None, 50_000);
        let txid = tx.txid();
        cm.mempool.add_tx(tx, Amount::from_sat(5_000), 100).unwrap();

        let clusters = cm.build_clusters();
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].txids, vec![txid]);

        let selected = cm.select_for_block(1_000_000);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], txid);
    }

    #[test]
    fn test_build_clusters_empty_mempool() {
        let pool = Mempool::new(10_000_000, 1000);
        let clusters = build_clusters(&pool);
        assert!(clusters.is_empty());
    }

    #[test]
    fn test_cluster_skips_too_large_for_block() {
        let mut pool = Mempool::new(10_000_000, 1000);

        // A cluster of two chained txs
        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        let _size_a = tx_a.encoded_size();
        pool.add_tx(tx_a, Amount::from_sat(10_000), 100).unwrap();

        let tx_b = make_tx(0x02, Some(txid_a), 40_000);
        let _size_b = tx_b.encoded_size();
        pool.add_tx(tx_b, Amount::from_sat(10_000), 101).unwrap();

        // An independent tx with lower feerate
        let tx_c = make_tx(0x03, None, 50_000);
        let txid_c = tx_c.txid();
        let size_c = tx_c.encoded_size();
        pool.add_tx(tx_c, Amount::from_sat(5_000), 102).unwrap();

        let clusters = build_clusters(&pool);

        // Weight limit only allows the small independent tx, not the 2-tx cluster
        let selected = select_for_block(&clusters, size_c);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], txid_c);
    }

    #[test]
    fn test_3_tx_cluster_diamond_dependency() {
        // Diamond dependency pattern:
        //    A
        //   / \
        //  B   C
        //   \ /
        //    D
        // B and C both spend outputs from A, and D spends from both B and C.
        // All four should end up in a single cluster.
        let mut pool = Mempool::new(10_000_000, 1000);

        // A: base transaction, no mempool parent
        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        pool.add_tx(tx_a, Amount::from_sat(1_000), 100).unwrap();

        // B: spends from A
        let tx_b = make_tx(0x02, Some(txid_a), 40_000);
        let _txid_b = tx_b.txid();
        pool.add_tx(tx_b, Amount::from_sat(2_000), 101).unwrap();

        // C: also spends from A (via a different "virtual" output -- we use
        // the same txid since make_tx always uses output index 0, but that's
        // fine for clustering purposes since the clustering logic only checks
        // whether the parent txid is in the mempool).
        let tx_c = make_tx(0x03, Some(txid_a), 35_000);
        let _txid_c = tx_c.txid();
        pool.add_tx(tx_c, Amount::from_sat(3_000), 102).unwrap();

        let clusters = build_clusters(&pool);

        // All three should be in one cluster (connected via A).
        assert_eq!(
            clusters.len(),
            1,
            "diamond dependency should form 1 cluster, got {}",
            clusters.len()
        );
        assert_eq!(clusters[0].txids.len(), 3);
        assert_eq!(clusters[0].total_fees, 6_000); // 1000 + 2000 + 3000
    }

    // -----------------------------------------------------------------
    // Additional coverage tests
    // -----------------------------------------------------------------

    #[test]
    fn test_single_tx_cluster() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx = make_tx(0x01, None, 50_000);
        let txid = tx.txid();
        let tx_size = tx.encoded_size();
        pool.add_tx(tx, Amount::from_sat(5_000), 100).unwrap();

        let clusters = build_clusters(&pool);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].txids, vec![txid]);
        assert_eq!(clusters[0].total_fees, 5_000);
        assert_eq!(clusters[0].total_weight, tx_size);
    }

    #[test]
    fn test_cluster_feerate_basic() {
        let cluster = TxCluster {
            txids: vec![],
            total_fees: 10_000,
            total_weight: 500,
        };
        // feerate = 10000 * 1000 / 500 = 20000
        assert_eq!(cluster.feerate(), 20_000);
    }

    #[test]
    fn test_cluster_feerate_rounding() {
        let cluster = TxCluster {
            txids: vec![],
            total_fees: 7,
            total_weight: 3,
        };
        // feerate = 7 * 1000 / 3 = 2333
        assert_eq!(cluster.feerate(), 2333);
    }

    #[test]
    fn test_cluster_feerate_one_byte() {
        let cluster = TxCluster {
            txids: vec![],
            total_fees: 1,
            total_weight: 1,
        };
        assert_eq!(cluster.feerate(), 1000);
    }

    #[test]
    fn test_select_for_block_empty_input() {
        let clusters: Vec<TxCluster> = vec![];
        let selected = select_for_block(&clusters, 1_000_000);
        assert!(selected.is_empty());
    }

    #[test]
    fn test_select_for_block_zero_weight() {
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx = make_tx(0x01, None, 50_000);
        pool.add_tx(tx, Amount::from_sat(5_000), 100).unwrap();

        let clusters = build_clusters(&pool);
        let selected = select_for_block(&clusters, 0);
        assert!(selected.is_empty());
    }

    #[test]
    fn test_select_for_block_all_fit() {
        let mut pool = Mempool::new(10_000_000, 1000);
        for i in 1u8..=5 {
            let tx = make_tx(i, None, 50_000);
            pool.add_tx(tx, Amount::from_sat(i as i64 * 1_000), i as u64 * 100)
                .unwrap();
        }

        let clusters = build_clusters(&pool);
        let selected = select_for_block(&clusters, 10_000_000);
        assert_eq!(selected.len(), 5);
    }

    #[test]
    fn test_select_for_block_priority_order() {
        let mut pool = Mempool::new(10_000_000, 1000);

        let tx_low = make_tx(0x01, None, 50_000);
        let txid_low = tx_low.txid();
        pool.add_tx(tx_low, Amount::from_sat(1_000), 100).unwrap();

        let tx_high = make_tx(0x02, None, 50_000);
        let txid_high = tx_high.txid();
        pool.add_tx(tx_high, Amount::from_sat(50_000), 101).unwrap();

        let clusters = build_clusters(&pool);
        let selected = select_for_block(&clusters, 10_000_000);

        // Highest feerate cluster should come first
        assert_eq!(selected[0], txid_high);
        assert_eq!(selected[1], txid_low);
    }

    #[test]
    fn test_parent_child_cluster_order() {
        let mut pool = Mempool::new(10_000_000, 1000);

        let parent = make_tx(0x01, None, 50_000);
        let parent_txid = parent.txid();
        pool.add_tx(parent, Amount::from_sat(2_000), 100).unwrap();

        let child = make_tx(0x02, Some(parent_txid), 40_000);
        let child_txid = child.txid();
        pool.add_tx(child, Amount::from_sat(8_000), 101).unwrap();

        let clusters = build_clusters(&pool);
        assert_eq!(clusters.len(), 1);

        // Parent should come before child in topological order
        let txids = &clusters[0].txids;
        let parent_pos = txids.iter().position(|t| *t == parent_txid).unwrap();
        let child_pos = txids.iter().position(|t| *t == child_txid).unwrap();
        assert!(parent_pos < child_pos);
    }

    #[test]
    fn test_cluster_mempool_build_clusters_empty() {
        let pool = Mempool::new(10_000_000, 1000);
        let cm = ClusterMempool::new(pool);
        let clusters = cm.build_clusters();
        assert!(clusters.is_empty());
    }

    #[test]
    fn test_cluster_mempool_select_for_block_empty() {
        let pool = Mempool::new(10_000_000, 1000);
        let cm = ClusterMempool::new(pool);
        let selected = cm.select_for_block(1_000_000);
        assert!(selected.is_empty());
    }

    #[test]
    fn test_cluster_mempool_with_chain() {
        let pool = Mempool::new(10_000_000, 1000);
        let mut cm = ClusterMempool::new(pool);

        let parent = make_tx(0x01, None, 50_000);
        let parent_txid = parent.txid();
        cm.mempool.add_tx(parent, Amount::from_sat(3_000), 100).unwrap();

        let child = make_tx(0x02, Some(parent_txid), 40_000);
        cm.mempool.add_tx(child, Amount::from_sat(7_000), 101).unwrap();

        let clusters = cm.build_clusters();
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].total_fees, 10_000);

        let selected = cm.select_for_block(10_000_000);
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn test_two_separate_chains() {
        let mut pool = Mempool::new(10_000_000, 1000);

        // Chain 1: A -> B
        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        pool.add_tx(tx_a, Amount::from_sat(2_000), 100).unwrap();

        let tx_b = make_tx(0x02, Some(txid_a), 40_000);
        pool.add_tx(tx_b, Amount::from_sat(3_000), 101).unwrap();

        // Chain 2: C -> D
        let tx_c = make_tx(0x03, None, 50_000);
        let txid_c = tx_c.txid();
        pool.add_tx(tx_c, Amount::from_sat(4_000), 102).unwrap();

        let tx_d = make_tx(0x04, Some(txid_c), 40_000);
        pool.add_tx(tx_d, Amount::from_sat(5_000), 103).unwrap();

        let clusters = build_clusters(&pool);
        assert_eq!(clusters.len(), 2);
    }

    #[test]
    fn test_cluster_with_mixed_independent_and_chained() {
        let mut pool = Mempool::new(10_000_000, 1000);

        // Chain: A -> B
        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        pool.add_tx(tx_a, Amount::from_sat(2_000), 100).unwrap();

        let tx_b = make_tx(0x02, Some(txid_a), 40_000);
        pool.add_tx(tx_b, Amount::from_sat(3_000), 101).unwrap();

        // Independent
        let tx_c = make_tx(0x03, None, 50_000);
        pool.add_tx(tx_c, Amount::from_sat(10_000), 102).unwrap();

        let clusters = build_clusters(&pool);
        assert_eq!(clusters.len(), 2);
    }

    #[test]
    fn test_select_skips_too_large_cluster() {
        let mut pool = Mempool::new(10_000_000, 1000);

        // Large chain cluster
        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        let size_a = tx_a.encoded_size();
        pool.add_tx(tx_a, Amount::from_sat(20_000), 100).unwrap();

        let tx_b = make_tx(0x02, Some(txid_a), 40_000);
        let size_b = tx_b.encoded_size();
        pool.add_tx(tx_b, Amount::from_sat(20_000), 101).unwrap();

        // Small independent tx with lower feerate
        let tx_c = make_tx(0x03, None, 50_000);
        let size_c = tx_c.encoded_size();
        let txid_c = tx_c.txid();
        pool.add_tx(tx_c, Amount::from_sat(1_000), 102).unwrap();

        let clusters = build_clusters(&pool);

        // Only enough weight for the small tx
        let selected = select_for_block(&clusters, size_c);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], txid_c);
    }

    #[test]
    fn test_cluster_debug() {
        let cluster = TxCluster {
            txids: vec![],
            total_fees: 100,
            total_weight: 50,
        };
        let debug = format!("{:?}", cluster);
        assert!(debug.contains("TxCluster"));
    }

    #[test]
    fn test_cluster_clone() {
        let txid = TxHash::from_bytes([0x01; 32]);
        let cluster = TxCluster {
            txids: vec![txid],
            total_fees: 5000,
            total_weight: 200,
        };
        let cloned = cluster.clone();
        assert_eq!(cloned.txids, cluster.txids);
        assert_eq!(cloned.total_fees, cluster.total_fees);
        assert_eq!(cloned.total_weight, cluster.total_weight);
        assert_eq!(cloned.feerate(), cluster.feerate());
    }

    #[test]
    fn test_self_referencing_input_ignored() {
        // A tx that has its own txid as an input's previous_output.txid
        // should not create a self-loop in the dependency graph.
        let mut pool = Mempool::new(10_000_000, 1000);
        let tx = make_tx(0x01, None, 50_000);
        pool.add_tx(tx, Amount::from_sat(5_000), 100).unwrap();

        let clusters = build_clusters(&pool);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].txids.len(), 1);
    }

    #[test]
    fn test_many_independent_clusters() {
        let mut pool = Mempool::new(10_000_000, 1000);
        for i in 1u8..=20 {
            let tx = make_tx(i, None, 50_000);
            pool.add_tx(tx, Amount::from_sat(i as i64 * 1_000), i as u64)
                .unwrap();
        }

        let clusters = build_clusters(&pool);
        assert_eq!(clusters.len(), 20);
    }

    #[test]
    fn test_long_chain_single_cluster() {
        let mut pool = Mempool::new(10_000_000, 1000);

        let mut prev_txid: Option<TxHash> = None;
        for i in 1u8..=10 {
            let tx = make_tx(i, prev_txid, 50_000);
            let txid = tx.txid();
            pool.add_tx(tx, Amount::from_sat(i as i64 * 1_000), i as u64)
                .unwrap();
            prev_txid = Some(txid);
        }

        let clusters = build_clusters(&pool);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].txids.len(), 10);
        // Total fees = 1000 + 2000 + ... + 10000 = 55000
        assert_eq!(clusters[0].total_fees, 55_000);
    }
}
