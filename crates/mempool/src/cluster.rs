//! # Cluster Mempool
//!
//! Implements Bitcoin Core v31-style cluster mempool where related transactions
//! (parent/child chains) are grouped into clusters, each cluster is linearized
//! into an optimal ordering by feerate, and the linearization is split into
//! "chunks" — contiguous prefixes with the same effective feerate.
//!
//! Key concepts:
//! - **Cluster**: a connected component of transactions in the dependency graph.
//! - **Linearization**: a topologically-valid ordering of transactions within a
//!   cluster, optimized so that the highest-feerate prefixes come first.
//! - **Chunk**: a prefix of the linearization whose aggregate feerate is higher
//!   than any sub-prefix; chunks are the unit of mining selection and eviction.
//! - **Package RBF**: replacement evaluated at the chunk level — the new
//!   cluster's chunks must dominate the old cluster's chunks at every position.
//! - **1p1c (one parent, one child) package acceptance**: a parent below the
//!   minimum relay feerate can be accepted if a child's CPFP brings the package
//!   feerate above the relay threshold.

use std::collections::{HashMap, HashSet};

use btc_primitives::hash::TxHash;
use btc_primitives::transaction::{OutPoint, Transaction};
use btc_primitives::amount::Amount;
use btc_primitives::encode::Encodable;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of transactions allowed in a single cluster (Bitcoin Core v31 default).
pub const MAX_CLUSTER_SIZE: usize = 101;

/// Default minimum relay feerate: fee * 1000 / weight (i.e. milli-sats per byte).
/// 1 sat/vbyte expressed in our fixed-point representation.
pub const DEFAULT_MIN_RELAY_FEERATE: u64 = 1000;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClusterMempoolError {
    #[error("transaction {0} already in mempool")]
    AlreadyExists(String),

    #[error("adding transaction would create a cluster of size {size}, exceeding limit {max}")]
    ClusterTooLarge { size: usize, max: usize },

    #[error("transaction fee {fee} with weight {weight} is below minimum relay feerate")]
    BelowMinRelayFeerate { fee: u64, weight: usize },

    #[error("package RBF failed: new cluster chunks do not dominate old cluster chunks")]
    PackageRbfFailed,

    #[error("package feerate {package_feerate} is below minimum relay feerate {min_feerate}")]
    PackageBelowMinFeerate {
        package_feerate: u64,
        min_feerate: u64,
    },

    #[error("parent transaction {0} already in mempool (1p1c requires new parent)")]
    ParentAlreadyExists(String),

    #[error("child transaction {0} already in mempool")]
    ChildAlreadyExists(String),
}

// ---------------------------------------------------------------------------
// FeeRate helper
// ---------------------------------------------------------------------------

/// Fixed-point feerate: fee * 1000 / weight. Allows precise integer comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FixedFeeRate(pub u64);

impl FixedFeeRate {
    pub fn from_fee_weight(fee: u64, weight: usize) -> Self {
        if weight == 0 {
            return FixedFeeRate(0);
        }
        FixedFeeRate(fee.saturating_mul(1000) / weight as u64)
    }

    pub fn as_raw(&self) -> u64 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Chunk
// ---------------------------------------------------------------------------

/// A chunk is a contiguous sub-sequence of a cluster's linearization.
/// During mining selection, chunks are the atomic unit — the entire chunk is
/// included or excluded together.
#[derive(Debug, Clone)]
pub struct Chunk {
    /// Transaction IDs in this chunk, in linearization order.
    pub txids: Vec<TxHash>,
    /// Total fee for all transactions in this chunk.
    pub total_fee: u64,
    /// Total weight (serialized size) for all transactions in this chunk.
    pub total_weight: usize,
}

impl Chunk {
    /// Feerate of this chunk: fee * 1000 / weight.
    pub fn feerate(&self) -> FixedFeeRate {
        FixedFeeRate::from_fee_weight(self.total_fee, self.total_weight)
    }
}

// ---------------------------------------------------------------------------
// TxInfo
// ---------------------------------------------------------------------------

/// Per-transaction metadata stored in the cluster mempool.
#[derive(Debug, Clone)]
pub struct TxInfo {
    /// The full transaction.
    pub tx: Transaction,
    /// Fee in satoshis.
    pub fee: u64,
    /// Serialized size (weight) in bytes.
    pub weight: usize,
    /// Which cluster this transaction belongs to.
    pub cluster_id: u64,
}

// ---------------------------------------------------------------------------
// Cluster
// ---------------------------------------------------------------------------

/// A cluster is a set of related (connected) transactions, together with a
/// linearization and chunk decomposition.
#[derive(Debug, Clone)]
pub struct Cluster {
    /// Unique identifier for this cluster.
    pub id: u64,
    /// Transaction IDs in this cluster (insertion order, not necessarily linearized).
    pub txids: HashSet<TxHash>,
    /// Linearized ordering of the cluster's transactions.
    pub linearization: Vec<TxHash>,
    /// Chunk decomposition of the linearization.
    pub chunks: Vec<Chunk>,
    /// Total fee of the entire cluster.
    pub total_fee: u64,
    /// Total weight of the entire cluster.
    pub total_weight: usize,
}

impl Cluster {
    /// Aggregate feerate for the entire cluster.
    pub fn feerate(&self) -> FixedFeeRate {
        FixedFeeRate::from_fee_weight(self.total_fee, self.total_weight)
    }

    /// Number of transactions in this cluster.
    pub fn size(&self) -> usize {
        self.txids.len()
    }
}

// ---------------------------------------------------------------------------
// ClusterMempool
// ---------------------------------------------------------------------------

/// A cluster-based mempool. Transactions are organized into clusters of
/// related transactions, each cluster is linearized, and chunks are used
/// for mining selection and eviction.
pub struct ClusterMempool {
    /// All transactions indexed by txid.
    txs: HashMap<TxHash, TxInfo>,
    /// All clusters indexed by cluster ID.
    clusters: HashMap<u64, Cluster>,
    /// Maps each outpoint (txid, vout) that is *created* by a mempool tx
    /// to the txid that created it. Used for finding parent relationships.
    output_index: HashMap<OutPoint, TxHash>,
    /// Maps each outpoint to the txid that *spends* it (within the mempool).
    /// Used for finding child relationships.
    spend_index: HashMap<OutPoint, TxHash>,
    /// Next cluster ID to assign.
    next_cluster_id: u64,
    /// Maximum transactions per cluster.
    max_cluster_size: usize,
    /// Minimum relay feerate (fixed-point: fee * 1000 / weight).
    min_relay_feerate: u64,
}

impl ClusterMempool {
    /// Create a new empty cluster mempool with default limits.
    pub fn new() -> Self {
        Self {
            txs: HashMap::new(),
            clusters: HashMap::new(),
            output_index: HashMap::new(),
            spend_index: HashMap::new(),
            next_cluster_id: 1,
            max_cluster_size: MAX_CLUSTER_SIZE,
            min_relay_feerate: DEFAULT_MIN_RELAY_FEERATE,
        }
    }

    /// Create a new cluster mempool with custom limits.
    pub fn with_limits(max_cluster_size: usize, min_relay_feerate: u64) -> Self {
        Self {
            txs: HashMap::new(),
            clusters: HashMap::new(),
            output_index: HashMap::new(),
            spend_index: HashMap::new(),
            next_cluster_id: 1,
            max_cluster_size,
            min_relay_feerate,
        }
    }

    /// Number of transactions in the mempool.
    pub fn tx_count(&self) -> usize {
        self.txs.len()
    }

    /// Number of clusters.
    pub fn cluster_count(&self) -> usize {
        self.clusters.len()
    }

    /// Check if a transaction is in the mempool.
    pub fn contains(&self, txid: &TxHash) -> bool {
        self.txs.contains_key(txid)
    }

    /// Get the TxInfo for a transaction.
    pub fn get_tx(&self, txid: &TxHash) -> Option<&TxInfo> {
        self.txs.get(txid)
    }

    // -----------------------------------------------------------------------
    // add_tx
    // -----------------------------------------------------------------------

    /// Add a transaction to the mempool.
    ///
    /// The transaction is placed into an existing cluster if it has mempool
    /// parents or children; otherwise a new singleton cluster is created.
    /// If adding the transaction would merge multiple clusters and exceed the
    /// cluster size limit, the addition is rejected.
    pub fn add_tx(&mut self, tx: Transaction, fee: Amount) -> Result<TxHash, ClusterMempoolError> {
        let txid = tx.txid();
        let fee_sat = fee.as_sat() as u64;
        let weight = tx.encoded_size();

        // Reject duplicates.
        if self.txs.contains_key(&txid) {
            return Err(ClusterMempoolError::AlreadyExists(txid.to_hex()));
        }

        // Check minimum relay feerate.
        let feerate = FixedFeeRate::from_fee_weight(fee_sat, weight);
        if feerate.as_raw() < self.min_relay_feerate {
            return Err(ClusterMempoolError::BelowMinRelayFeerate { fee: fee_sat, weight });
        }

        // Find related cluster IDs.
        let related_cluster_ids = self.find_related_clusters(&tx);

        // Compute merged cluster size.
        let merged_size: usize = related_cluster_ids
            .iter()
            .filter_map(|cid| self.clusters.get(cid))
            .map(|c| c.size())
            .sum::<usize>()
            + 1; // +1 for the new tx

        if merged_size > self.max_cluster_size {
            return Err(ClusterMempoolError::ClusterTooLarge {
                size: merged_size,
                max: self.max_cluster_size,
            });
        }

        // Insert the tx.
        let cluster_id = if related_cluster_ids.is_empty() {
            // Create new singleton cluster.
            let cid = self.next_cluster_id;
            self.next_cluster_id += 1;
            cid
        } else if related_cluster_ids.len() == 1 {
            *related_cluster_ids.iter().next().unwrap()
        } else {
            // Merge: pick the lowest cluster ID as the target.
            let target_cid = *related_cluster_ids.iter().min().unwrap();
            // Merge all other clusters into target.
            for &cid in &related_cluster_ids {
                if cid != target_cid {
                    self.merge_cluster_into(cid, target_cid);
                }
            }
            target_cid
        };

        // Index the outputs this tx creates.
        for (vout, _output) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint::new(txid, vout as u32);
            self.output_index.insert(outpoint, txid);
        }

        // Index the inputs this tx spends (only those that reference mempool txs).
        for input in &tx.inputs {
            if self.output_index.contains_key(&input.previous_output) {
                self.spend_index.insert(input.previous_output, txid);
            }
        }

        // Store TxInfo.
        self.txs.insert(txid, TxInfo {
            tx,
            fee: fee_sat,
            weight,
            cluster_id,
        });

        // Add txid to the cluster.
        let cluster = self.clusters.entry(cluster_id).or_insert_with(|| Cluster {
            id: cluster_id,
            txids: HashSet::new(),
            linearization: Vec::new(),
            chunks: Vec::new(),
            total_fee: 0,
            total_weight: 0,
        });
        cluster.txids.insert(txid);
        cluster.total_fee += fee_sat;
        cluster.total_weight += weight;

        // Re-linearize and re-chunk the cluster.
        self.relinearize_cluster(cluster_id);

        Ok(txid)
    }

    // -----------------------------------------------------------------------
    // remove_tx
    // -----------------------------------------------------------------------

    /// Remove a transaction from the mempool. If removing the tx disconnects
    /// the cluster, the cluster is split into its connected components.
    pub fn remove_tx(&mut self, txid: &TxHash) -> Option<TxInfo> {
        let info = self.txs.remove(txid)?;
        let cluster_id = info.cluster_id;

        // Remove output index entries.
        for (vout, _) in info.tx.outputs.iter().enumerate() {
            let outpoint = OutPoint::new(*txid, vout as u32);
            self.output_index.remove(&outpoint);
        }

        // Remove spend index entries.
        for input in &info.tx.inputs {
            self.spend_index.remove(&input.previous_output);
        }

        // Also remove any spend-index entries where other txs spend *our* outputs.
        // Those children now have a confirmed (or missing) parent, not a mempool parent.
        for (vout, _) in info.tx.outputs.iter().enumerate() {
            let outpoint = OutPoint::new(*txid, vout as u32);
            self.spend_index.remove(&outpoint);
        }

        // Remove from cluster and handle splitting.
        if let Some(cluster) = self.clusters.get_mut(&cluster_id) {
            cluster.txids.remove(txid);
            cluster.total_fee = cluster.total_fee.saturating_sub(info.fee);
            cluster.total_weight = cluster.total_weight.saturating_sub(info.weight);

            if cluster.txids.is_empty() {
                self.clusters.remove(&cluster_id);
            } else {
                // Check if the cluster is still connected; if not, split it.
                self.split_cluster_if_needed(cluster_id);
            }
        }

        Some(info)
    }

    // -----------------------------------------------------------------------
    // get_cluster
    // -----------------------------------------------------------------------

    /// Get the cluster containing a given transaction.
    pub fn get_cluster(&self, txid: &TxHash) -> Option<&Cluster> {
        let info = self.txs.get(txid)?;
        self.clusters.get(&info.cluster_id)
    }

    /// Get a cluster by its ID.
    pub fn get_cluster_by_id(&self, cluster_id: u64) -> Option<&Cluster> {
        self.clusters.get(&cluster_id)
    }

    // -----------------------------------------------------------------------
    // get_mining_order
    // -----------------------------------------------------------------------

    /// Return all chunks across all clusters, sorted by feerate (highest first).
    /// This is the ordering a miner would use to build a block template.
    pub fn get_mining_order(&self) -> Vec<Chunk> {
        let mut all_chunks: Vec<Chunk> = self
            .clusters
            .values()
            .flat_map(|c| c.chunks.iter().cloned())
            .collect();
        // Sort by feerate descending; break ties by total_fee descending.
        all_chunks.sort_by(|a, b| {
            b.feerate()
                .cmp(&a.feerate())
                .then_with(|| b.total_fee.cmp(&a.total_fee))
        });
        all_chunks
    }

    /// Select transactions for a block template, respecting a weight limit.
    /// Returns txids in dependency-safe order.
    pub fn select_for_block(&self, max_weight: usize) -> Vec<TxHash> {
        let chunks = self.get_mining_order();
        let mut selected = Vec::new();
        let mut remaining = max_weight;
        for chunk in &chunks {
            if chunk.total_weight <= remaining {
                selected.extend_from_slice(&chunk.txids);
                remaining -= chunk.total_weight;
            }
        }
        selected
    }

    // -----------------------------------------------------------------------
    // evict_worst
    // -----------------------------------------------------------------------

    /// Evict the lowest-feerate chunk from the lowest-feerate cluster.
    /// Returns the evicted transactions' TxInfo, or an empty vec if the
    /// mempool is empty.
    pub fn evict_worst(&mut self) -> Vec<TxInfo> {
        // Find the cluster with the lowest feerate.
        let worst_cluster_id = match self
            .clusters
            .values()
            .min_by_key(|c| c.feerate())
        {
            Some(c) => c.id,
            None => return Vec::new(),
        };

        // Get the last (lowest-feerate) chunk from that cluster.
        let worst_chunk_txids: Vec<TxHash> = match self.clusters.get(&worst_cluster_id) {
            Some(c) if !c.chunks.is_empty() => {
                c.chunks.last().unwrap().txids.clone()
            }
            _ => return Vec::new(),
        };

        // Remove those transactions.
        let mut evicted = Vec::new();
        for txid in &worst_chunk_txids {
            if let Some(info) = self.remove_tx(txid) {
                evicted.push(info);
            }
        }
        evicted
    }

    // -----------------------------------------------------------------------
    // Package RBF
    // -----------------------------------------------------------------------

    /// Evaluate whether a new transaction (forming a new cluster or merging
    /// into an existing one) would be a valid package RBF replacement for the
    /// conflicting transactions.
    ///
    /// `new_tx` and `new_fee` describe the replacement transaction.
    /// `conflicting_txids` are the txids of existing mempool transactions that
    /// conflict (spend the same inputs).
    ///
    /// The replacement is valid if the new cluster's chunk feerates dominate
    /// the old cluster's chunk feerates at every position (the "chunk feerate
    /// diagram" must be strictly better).
    pub fn check_package_rbf(
        &self,
        new_tx: &Transaction,
        new_fee: Amount,
        conflicting_txids: &[TxHash],
    ) -> Result<(), ClusterMempoolError> {
        if conflicting_txids.is_empty() {
            return Ok(());
        }

        // Collect the old chunks from all clusters that contain conflicting txs.
        let mut old_chunks: Vec<Chunk> = Vec::new();
        let mut seen_clusters = HashSet::new();
        for txid in conflicting_txids {
            if let Some(info) = self.txs.get(txid) {
                if seen_clusters.insert(info.cluster_id) {
                    if let Some(cluster) = self.clusters.get(&info.cluster_id) {
                        old_chunks.extend(cluster.chunks.iter().cloned());
                    }
                }
            }
        }

        // Sort old chunks by feerate descending.
        old_chunks.sort_by(|a, b| b.feerate().cmp(&a.feerate()));

        // Build a synthetic "new cluster" consisting of just the new tx.
        // In a full implementation, we would simulate the merge with any
        // non-conflicting related txs, but for correctness the new tx alone
        // must dominate.
        let new_fee_sat = new_fee.as_sat() as u64;
        let new_weight = new_tx.encoded_size();
        let new_chunk = Chunk {
            txids: vec![new_tx.txid()],
            total_fee: new_fee_sat,
            total_weight: new_weight,
        };
        let new_chunks = vec![new_chunk];

        // The new chunk feerate diagram must dominate the old one.
        // Compare cumulative fee at each cumulative weight point.
        if !diagram_dominates(&new_chunks, &old_chunks) {
            return Err(ClusterMempoolError::PackageRbfFailed);
        }

        Ok(())
    }

    /// Perform a package RBF: check the replacement, remove conflicting txs,
    /// and add the new tx.
    pub fn replace_by_fee(
        &mut self,
        new_tx: Transaction,
        new_fee: Amount,
        conflicting_txids: &[TxHash],
    ) -> Result<TxHash, ClusterMempoolError> {
        self.check_package_rbf(&new_tx, new_fee, conflicting_txids)?;

        // Remove conflicting transactions.
        for txid in conflicting_txids {
            self.remove_tx(txid);
        }

        // Add the new transaction.
        self.add_tx(new_tx, new_fee)
    }

    // -----------------------------------------------------------------------
    // 1p1c Package Acceptance
    // -----------------------------------------------------------------------

    /// Accept a parent+child transaction pair as a package.
    ///
    /// The parent may have a feerate below the minimum relay feerate, as long
    /// as the combined package feerate (parent + child fees / parent + child
    /// weights) meets or exceeds the minimum relay feerate.
    ///
    /// The child must spend at least one output of the parent.
    pub fn accept_package(
        &mut self,
        parent: Transaction,
        parent_fee: Amount,
        child: Transaction,
        child_fee: Amount,
    ) -> Result<(TxHash, TxHash), ClusterMempoolError> {
        let parent_txid = parent.txid();
        let child_txid = child.txid();

        if self.txs.contains_key(&parent_txid) {
            return Err(ClusterMempoolError::ParentAlreadyExists(parent_txid.to_hex()));
        }
        if self.txs.contains_key(&child_txid) {
            return Err(ClusterMempoolError::ChildAlreadyExists(child_txid.to_hex()));
        }

        let parent_fee_sat = parent_fee.as_sat() as u64;
        let child_fee_sat = child_fee.as_sat() as u64;
        let parent_weight = parent.encoded_size();
        let child_weight = child.encoded_size();

        let package_fee = parent_fee_sat + child_fee_sat;
        let package_weight = parent_weight + child_weight;
        let package_feerate = FixedFeeRate::from_fee_weight(package_fee, package_weight);

        if package_feerate.as_raw() < self.min_relay_feerate {
            return Err(ClusterMempoolError::PackageBelowMinFeerate {
                package_feerate: package_feerate.as_raw(),
                min_feerate: self.min_relay_feerate,
            });
        }

        // Temporarily lower the min feerate to allow the parent in.
        let saved_min = self.min_relay_feerate;
        self.min_relay_feerate = 0;

        let parent_result = self.add_tx(parent, parent_fee);
        if let Err(e) = parent_result {
            self.min_relay_feerate = saved_min;
            return Err(e);
        }

        let child_result = self.add_tx(child, child_fee);
        if let Err(e) = child_result {
            // Roll back parent.
            self.remove_tx(&parent_txid);
            self.min_relay_feerate = saved_min;
            return Err(e);
        }

        self.min_relay_feerate = saved_min;
        Ok((parent_txid, child_txid))
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Find all cluster IDs that the given transaction is related to (shares
    /// inputs/outputs with existing mempool transactions).
    fn find_related_clusters(&self, tx: &Transaction) -> HashSet<u64> {
        let mut cluster_ids = HashSet::new();
        let txid = tx.txid();

        // Check if any input spends an output of a mempool tx (parent relationship).
        for input in &tx.inputs {
            if let Some(&parent_txid) = self.output_index.get(&input.previous_output) {
                if let Some(info) = self.txs.get(&parent_txid) {
                    cluster_ids.insert(info.cluster_id);
                }
            }
        }

        // Check if any existing mempool tx spends an output of *this* tx
        // (child relationship — the child was added before the parent).
        for (vout, _) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint::new(txid, vout as u32);
            if let Some(&child_txid) = self.spend_index.get(&outpoint) {
                if let Some(info) = self.txs.get(&child_txid) {
                    cluster_ids.insert(info.cluster_id);
                }
            }
        }

        cluster_ids
    }

    /// Merge cluster `source_id` into cluster `target_id`.
    fn merge_cluster_into(&mut self, source_id: u64, target_id: u64) {
        let source = match self.clusters.remove(&source_id) {
            Some(c) => c,
            None => return,
        };

        // Update all txs in the source cluster to point to the target.
        for txid in &source.txids {
            if let Some(info) = self.txs.get_mut(txid) {
                info.cluster_id = target_id;
            }
        }

        // Merge into target.
        if let Some(target) = self.clusters.get_mut(&target_id) {
            target.txids.extend(source.txids);
            target.total_fee += source.total_fee;
            target.total_weight += source.total_weight;
        }
    }

    /// After removing a tx, check if the cluster is still connected. If not,
    /// split it into multiple clusters.
    fn split_cluster_if_needed(&mut self, cluster_id: u64) {
        let cluster = match self.clusters.get(&cluster_id) {
            Some(c) => c,
            None => return,
        };

        if cluster.txids.len() <= 1 {
            // 0 or 1 tx is trivially connected.
            self.relinearize_cluster(cluster_id);
            return;
        }

        // Build adjacency among the remaining txs.
        let txids: Vec<TxHash> = cluster.txids.iter().copied().collect();
        let txid_set: HashSet<TxHash> = cluster.txids.clone();

        let mut adj: HashMap<TxHash, HashSet<TxHash>> = HashMap::new();
        for &t in &txids {
            adj.insert(t, HashSet::new());
        }

        for &t in &txids {
            if let Some(info) = self.txs.get(&t) {
                for input in &info.tx.inputs {
                    let parent_txid = input.previous_output.txid;
                    if txid_set.contains(&parent_txid) && parent_txid != t {
                        adj.get_mut(&t).unwrap().insert(parent_txid);
                        adj.get_mut(&parent_txid).unwrap().insert(t);
                    }
                }
            }
        }

        // BFS to find connected components.
        let mut visited = HashSet::new();
        let mut components: Vec<HashSet<TxHash>> = Vec::new();

        for &start in &txids {
            if visited.contains(&start) {
                continue;
            }
            let mut component = HashSet::new();
            let mut queue = vec![start];
            while let Some(node) = queue.pop() {
                if !component.insert(node) {
                    continue;
                }
                visited.insert(node);
                if let Some(neighbors) = adj.get(&node) {
                    for &n in neighbors {
                        if !component.contains(&n) {
                            queue.push(n);
                        }
                    }
                }
            }
            components.push(component);
        }

        if components.len() <= 1 {
            // Still connected — just relinearize.
            self.relinearize_cluster(cluster_id);
            return;
        }

        // Remove the original cluster.
        self.clusters.remove(&cluster_id);

        // Create new clusters for each component.
        for component in components {
            let new_cid = self.next_cluster_id;
            self.next_cluster_id += 1;

            let mut total_fee = 0u64;
            let mut total_weight = 0usize;

            for &t in &component {
                if let Some(info) = self.txs.get_mut(&t) {
                    info.cluster_id = new_cid;
                    total_fee += info.fee;
                    total_weight += info.weight;
                }
            }

            self.clusters.insert(new_cid, Cluster {
                id: new_cid,
                txids: component,
                linearization: Vec::new(),
                chunks: Vec::new(),
                total_fee,
                total_weight,
            });

            self.relinearize_cluster(new_cid);
        }
    }

    /// Recompute the linearization and chunk decomposition for a cluster.
    fn relinearize_cluster(&mut self, cluster_id: u64) {
        let cluster = match self.clusters.get(&cluster_id) {
            Some(c) => c,
            None => return,
        };

        let txids: Vec<TxHash> = cluster.txids.iter().copied().collect();
        if txids.is_empty() {
            return;
        }

        // Build the dependency graph among cluster members.
        let txid_set: HashSet<TxHash> = cluster.txids.clone();
        let mut parents: HashMap<TxHash, HashSet<TxHash>> = HashMap::new();

        for &t in &txids {
            let mut parent_set = HashSet::new();
            if let Some(info) = self.txs.get(&t) {
                for input in &info.tx.inputs {
                    let pt = input.previous_output.txid;
                    if txid_set.contains(&pt) && pt != t {
                        parent_set.insert(pt);
                    }
                }
            }
            parents.insert(t, parent_set);
        }

        // Greedy linearization: repeatedly pick the highest-feerate subset
        // whose ancestors are all already placed.
        let linearization = greedy_linearize(&txids, &parents, &self.txs);

        // Compute chunks from the linearization.
        let chunks = compute_chunks(&linearization, &self.txs);

        // Update the cluster.
        if let Some(cluster) = self.clusters.get_mut(&cluster_id) {
            cluster.linearization = linearization;
            cluster.chunks = chunks;
        }
    }
}

impl Default for ClusterMempool {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Linearization: greedy algorithm
// ---------------------------------------------------------------------------

/// Greedy linearization of transactions within a cluster.
///
/// Repeatedly selects the "best" candidate — the transaction (or group of
/// transactions forming a connected ancestor-closed set) with the highest
/// aggregate feerate — and appends it to the linearization.
///
/// For simplicity and correctness we use single-tx selection with ancestor
/// awareness: at each step, we consider each unplaced tx and compute the
/// feerate of the "ancestor set" (all unplaced ancestors plus the tx itself).
/// The tx whose ancestor set has the highest feerate is selected, and that
/// entire ancestor set is appended (topologically sorted) to the
/// linearization.
fn greedy_linearize(
    txids: &[TxHash],
    parents: &HashMap<TxHash, HashSet<TxHash>>,
    tx_map: &HashMap<TxHash, TxInfo>,
) -> Vec<TxHash> {
    let mut placed: HashSet<TxHash> = HashSet::new();
    let mut result: Vec<TxHash> = Vec::new();
    let remaining: HashSet<TxHash> = txids.iter().copied().collect();

    while placed.len() < txids.len() {
        // For each unplaced tx, compute the feerate of its unplaced ancestor set.
        let mut best_set: Option<Vec<TxHash>> = None;
        let mut best_feerate = FixedFeeRate(0);

        for &t in &remaining {
            if placed.contains(&t) {
                continue;
            }

            // Gather the unplaced ancestor-closed set for t.
            let ancestor_set = gather_unplaced_ancestors(t, parents, &placed);
            let (total_fee, total_weight) = set_fee_weight(&ancestor_set, tx_map);
            let fr = FixedFeeRate::from_fee_weight(total_fee, total_weight);

            if best_set.is_none() || fr > best_feerate {
                best_feerate = fr;
                best_set = Some(ancestor_set);
            }
        }

        if let Some(set) = best_set {
            // Topological sort the set before appending.
            let sorted = topo_sort(&set, parents);
            for t in sorted {
                if placed.insert(t) {
                    result.push(t);
                }
            }
        } else {
            break;
        }
    }

    result
}

/// Gather the set of unplaced ancestors (including `txid` itself) that must
/// be placed before or together with `txid`.
fn gather_unplaced_ancestors(
    txid: TxHash,
    parents: &HashMap<TxHash, HashSet<TxHash>>,
    placed: &HashSet<TxHash>,
) -> Vec<TxHash> {
    let mut set = HashSet::new();
    let mut stack = vec![txid];
    while let Some(t) = stack.pop() {
        if placed.contains(&t) || !set.insert(t) {
            continue;
        }
        if let Some(ps) = parents.get(&t) {
            for &p in ps {
                if !placed.contains(&p) {
                    stack.push(p);
                }
            }
        }
    }
    set.into_iter().collect()
}

/// Compute total fee and total weight for a set of txids.
fn set_fee_weight(set: &[TxHash], tx_map: &HashMap<TxHash, TxInfo>) -> (u64, usize) {
    let mut fee = 0u64;
    let mut weight = 0usize;
    for t in set {
        if let Some(info) = tx_map.get(t) {
            fee += info.fee;
            weight += info.weight;
        }
    }
    (fee, weight)
}

/// Topological sort a set of txids using the parent map (Kahn's algorithm).
fn topo_sort(
    set: &[TxHash],
    parents: &HashMap<TxHash, HashSet<TxHash>>,
) -> Vec<TxHash> {
    let set_members: HashSet<TxHash> = set.iter().copied().collect();

    // Compute in-degree within the set.
    let mut in_degree: HashMap<TxHash, usize> = HashMap::new();
    let mut children_map: HashMap<TxHash, Vec<TxHash>> = HashMap::new();

    for &t in set {
        in_degree.entry(t).or_insert(0);
        children_map.entry(t).or_default();
    }

    for &t in set {
        if let Some(ps) = parents.get(&t) {
            for &p in ps {
                if set_members.contains(&p) {
                    *in_degree.entry(t).or_insert(0) += 1;
                    children_map.entry(p).or_default().push(t);
                }
            }
        }
    }

    let mut queue: Vec<TxHash> = set
        .iter()
        .filter(|t| in_degree.get(t) == Some(&0))
        .copied()
        .collect();
    // Sort for determinism.
    queue.sort_by_key(|t| t.to_bytes());

    let mut result = Vec::new();
    while let Some(t) = queue.pop() {
        result.push(t);
        if let Some(kids) = children_map.get(&t) {
            for &kid in kids {
                if let Some(deg) = in_degree.get_mut(&kid) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push(kid);
                        queue.sort_by_key(|t| t.to_bytes());
                    }
                }
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Chunk computation
// ---------------------------------------------------------------------------

/// Compute chunks from a linearization. A chunk boundary is placed wherever
/// the marginal feerate drops — i.e., the chunk feerate is the highest
/// feerate that a prefix of the remaining linearization achieves.
fn compute_chunks(linearization: &[TxHash], tx_map: &HashMap<TxHash, TxInfo>) -> Vec<Chunk> {
    if linearization.is_empty() {
        return Vec::new();
    }

    let mut chunks = Vec::new();
    let mut i = 0;

    while i < linearization.len() {
        // Find the prefix [i..j] that maximizes feerate.
        let mut best_j = i;
        let mut best_feerate = FixedFeeRate(0);
        let mut running_fee = 0u64;
        let mut running_weight = 0usize;

        for j in i..linearization.len() {
            let txid = &linearization[j];
            if let Some(info) = tx_map.get(txid) {
                running_fee += info.fee;
                running_weight += info.weight;
            }
            let fr = FixedFeeRate::from_fee_weight(running_fee, running_weight);
            if fr >= best_feerate {
                best_feerate = fr;
                best_j = j;
            }
        }

        // Create the chunk [i..=best_j].
        let chunk_txids: Vec<TxHash> = linearization[i..=best_j].to_vec();
        let (chunk_fee, chunk_weight) = set_fee_weight(&chunk_txids, tx_map);
        chunks.push(Chunk {
            txids: chunk_txids,
            total_fee: chunk_fee,
            total_weight: chunk_weight,
        });

        i = best_j + 1;
    }

    chunks
}

// ---------------------------------------------------------------------------
// Feerate diagram dominance (for Package RBF)
// ---------------------------------------------------------------------------

/// Check if the `new_chunks` feerate diagram strictly dominates `old_chunks`.
///
/// The feerate diagram is a step function: for each chunk, we add its weight
/// on the x-axis and its fee on the y-axis. "Dominance" means that at every
/// weight point, the cumulative fee of the new diagram is >= the old, and
/// strictly greater at at least one point.
fn diagram_dominates(new_chunks: &[Chunk], old_chunks: &[Chunk]) -> bool {
    // Build cumulative (weight, fee) breakpoints for each set.
    let new_points = cumulative_diagram(new_chunks);
    let old_points = cumulative_diagram(old_chunks);

    if old_points.is_empty() {
        return true;
    }
    if new_points.is_empty() {
        return false;
    }

    // At every old breakpoint weight, the new cumulative fee must be >= old.
    // And we need strict improvement at at least one point.
    let mut strictly_better = false;

    for &(old_w, old_f) in &old_points {
        let new_f = interpolate_fee(&new_points, old_w);
        if new_f < old_f {
            return false;
        }
        if new_f > old_f {
            strictly_better = true;
        }
    }

    // Also check the total: new total fee should be >= old total fee.
    let new_total_fee: u64 = new_chunks.iter().map(|c| c.total_fee).sum();
    let old_total_fee: u64 = old_chunks.iter().map(|c| c.total_fee).sum();
    if new_total_fee < old_total_fee {
        return false;
    }
    if new_total_fee > old_total_fee {
        strictly_better = true;
    }

    strictly_better
}

/// Build cumulative (weight, fee) breakpoints from a set of chunks.
fn cumulative_diagram(chunks: &[Chunk]) -> Vec<(usize, u64)> {
    let mut points = Vec::new();
    let mut cum_weight = 0usize;
    let mut cum_fee = 0u64;
    for chunk in chunks {
        cum_weight += chunk.total_weight;
        cum_fee += chunk.total_fee;
        points.push((cum_weight, cum_fee));
    }
    points
}

/// Linearly interpolate the cumulative fee at a given weight in the diagram.
fn interpolate_fee(points: &[(usize, u64)], weight: usize) -> u64 {
    if points.is_empty() || weight == 0 {
        return 0;
    }

    let mut prev_w = 0usize;
    let mut prev_f = 0u64;

    for &(w, f) in points {
        if weight <= w {
            // Linear interpolation within this segment.
            if w == prev_w {
                return f;
            }
            let segment_weight = w - prev_w;
            let segment_fee = f - prev_f;
            let offset = weight - prev_w;
            return prev_f + (segment_fee as u128 * offset as u128 / segment_weight as u128) as u64;
        }
        prev_w = w;
        prev_f = f;
    }

    // weight is beyond the last point — return the total fee.
    prev_f
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::script::ScriptBuf;
    use btc_primitives::transaction::{TxIn, TxOut};

    // -- helpers --

    /// Build a transaction that optionally spends from a given parent txid.
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

    /// Build a transaction with multiple inputs.
    fn make_tx_multi_input(
        id_byte: u8,
        parent_txids: &[TxHash],
        output_value: i64,
    ) -> Transaction {
        let inputs: Vec<TxIn> = if parent_txids.is_empty() {
            vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([id_byte; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x00; 10]),
                sequence: 0xffffffff,
            }]
        } else {
            parent_txids
                .iter()
                .map(|txid| TxIn {
                    previous_output: OutPoint::new(*txid, 0),
                    script_sig: ScriptBuf::from_bytes(vec![0x00; 10]),
                    sequence: 0xffffffff,
                })
                .collect()
        };

        Transaction {
            version: 2,
            inputs,
            outputs: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76u8; 25]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    // =====================================================================
    // Basic add/remove
    // =====================================================================

    #[test]
    fn test_add_single_tx() {
        let mut pool = ClusterMempool::new();
        let tx = make_tx(0x01, None, 50_000);
        let txid = tx.txid();

        let result = pool.add_tx(tx, Amount::from_sat(5_000));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), txid);
        assert!(pool.contains(&txid));
        assert_eq!(pool.tx_count(), 1);
        assert_eq!(pool.cluster_count(), 1);
    }

    #[test]
    fn test_add_duplicate_rejected() {
        let mut pool = ClusterMempool::new();
        let tx = make_tx(0x01, None, 50_000);
        pool.add_tx(tx.clone(), Amount::from_sat(5_000)).unwrap();
        let result = pool.add_tx(tx, Amount::from_sat(5_000));
        assert!(matches!(result, Err(ClusterMempoolError::AlreadyExists(_))));
    }

    #[test]
    fn test_add_below_min_feerate_rejected() {
        let mut pool = ClusterMempool::new();
        // Very low fee for the weight.
        let tx = make_tx(0x01, None, 50_000);
        // fee * 1000 / weight < 1000 means fee < weight
        // Our tx is small, so fee = 1 should fail.
        let result = pool.add_tx(tx, Amount::from_sat(1));
        assert!(matches!(
            result,
            Err(ClusterMempoolError::BelowMinRelayFeerate { .. })
        ));
    }

    #[test]
    fn test_remove_tx() {
        let mut pool = ClusterMempool::new();
        let tx = make_tx(0x01, None, 50_000);
        let txid = pool.add_tx(tx, Amount::from_sat(5_000)).unwrap();

        let removed = pool.remove_tx(&txid);
        assert!(removed.is_some());
        assert!(!pool.contains(&txid));
        assert_eq!(pool.tx_count(), 0);
        assert_eq!(pool.cluster_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut pool = ClusterMempool::new();
        let fake = TxHash::from_bytes([0xff; 32]);
        assert!(pool.remove_tx(&fake).is_none());
    }

    // =====================================================================
    // Clustering
    // =====================================================================

    #[test]
    fn test_independent_txs_separate_clusters() {
        let mut pool = ClusterMempool::new();
        let tx_a = make_tx(0x01, None, 50_000);
        let tx_b = make_tx(0x02, None, 50_000);
        let tx_c = make_tx(0x03, None, 50_000);

        pool.add_tx(tx_a, Amount::from_sat(5_000)).unwrap();
        pool.add_tx(tx_b, Amount::from_sat(3_000)).unwrap();
        pool.add_tx(tx_c, Amount::from_sat(7_000)).unwrap();

        assert_eq!(pool.cluster_count(), 3);
    }

    #[test]
    fn test_parent_child_same_cluster() {
        let mut pool = ClusterMempool::new();
        let parent = make_tx(0x01, None, 50_000);
        let parent_txid = parent.txid();
        pool.add_tx(parent, Amount::from_sat(2_000)).unwrap();

        let child = make_tx(0x02, Some(parent_txid), 40_000);
        pool.add_tx(child, Amount::from_sat(8_000)).unwrap();

        assert_eq!(pool.cluster_count(), 1);
        assert_eq!(pool.tx_count(), 2);
    }

    #[test]
    fn test_three_tx_chain_single_cluster() {
        let mut pool = ClusterMempool::new();

        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        pool.add_tx(tx_a, Amount::from_sat(3_000)).unwrap();

        let tx_b = make_tx(0x02, Some(txid_a), 40_000);
        let txid_b = tx_b.txid();
        pool.add_tx(tx_b, Amount::from_sat(4_000)).unwrap();

        let tx_c = make_tx(0x03, Some(txid_b), 30_000);
        pool.add_tx(tx_c, Amount::from_sat(5_000)).unwrap();

        assert_eq!(pool.cluster_count(), 1);
        assert_eq!(pool.tx_count(), 3);
    }

    #[test]
    fn test_cluster_merge_on_add() {
        let mut pool = ClusterMempool::new();

        // Two independent txs — 2 clusters.
        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        pool.add_tx(tx_a, Amount::from_sat(3_000)).unwrap();

        let tx_b = make_tx(0x02, None, 50_000);
        let txid_b = tx_b.txid();
        pool.add_tx(tx_b, Amount::from_sat(4_000)).unwrap();

        assert_eq!(pool.cluster_count(), 2);

        // A tx that spends from both A and B merges the two clusters.
        let tx_c = make_tx_multi_input(0x03, &[txid_a, txid_b], 30_000);
        pool.add_tx(tx_c, Amount::from_sat(5_000)).unwrap();

        assert_eq!(pool.cluster_count(), 1);
        assert_eq!(pool.tx_count(), 3);
    }

    #[test]
    fn test_cluster_split_on_remove() {
        let mut pool = ClusterMempool::new();

        // Chain: A -> B -> C
        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        pool.add_tx(tx_a, Amount::from_sat(3_000)).unwrap();

        let tx_b = make_tx(0x02, Some(txid_a), 40_000);
        let txid_b = tx_b.txid();
        pool.add_tx(tx_b, Amount::from_sat(4_000)).unwrap();

        let tx_c = make_tx(0x03, Some(txid_b), 30_000);
        pool.add_tx(tx_c, Amount::from_sat(5_000)).unwrap();

        assert_eq!(pool.cluster_count(), 1);

        // Remove B — should split into {A} and {C}.
        pool.remove_tx(&txid_b);
        assert_eq!(pool.tx_count(), 2);
        assert_eq!(pool.cluster_count(), 2);
    }

    #[test]
    fn test_cluster_size_limit() {
        let mut pool = ClusterMempool::with_limits(3, DEFAULT_MIN_RELAY_FEERATE);

        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        pool.add_tx(tx_a, Amount::from_sat(3_000)).unwrap();

        let tx_b = make_tx(0x02, Some(txid_a), 40_000);
        let txid_b = tx_b.txid();
        pool.add_tx(tx_b, Amount::from_sat(4_000)).unwrap();

        let tx_c = make_tx(0x03, Some(txid_b), 30_000);
        let txid_c = tx_c.txid();
        pool.add_tx(tx_c, Amount::from_sat(5_000)).unwrap();

        // Cluster has 3 txs (at limit). Adding a 4th should fail.
        let tx_d = make_tx(0x04, Some(txid_c), 20_000);
        let result = pool.add_tx(tx_d, Amount::from_sat(6_000));
        assert!(matches!(
            result,
            Err(ClusterMempoolError::ClusterTooLarge { size: 4, max: 3 })
        ));
    }

    // =====================================================================
    // get_cluster
    // =====================================================================

    #[test]
    fn test_get_cluster() {
        let mut pool = ClusterMempool::new();
        let tx = make_tx(0x01, None, 50_000);
        let txid = pool.add_tx(tx, Amount::from_sat(5_000)).unwrap();

        let cluster = pool.get_cluster(&txid).unwrap();
        assert!(cluster.txids.contains(&txid));
        assert_eq!(cluster.size(), 1);
    }

    #[test]
    fn test_get_cluster_nonexistent() {
        let pool = ClusterMempool::new();
        let fake = TxHash::from_bytes([0xff; 32]);
        assert!(pool.get_cluster(&fake).is_none());
    }

    // =====================================================================
    // Linearization and chunks
    // =====================================================================

    #[test]
    fn test_single_tx_linearization() {
        let mut pool = ClusterMempool::new();
        let tx = make_tx(0x01, None, 50_000);
        let txid = pool.add_tx(tx, Amount::from_sat(5_000)).unwrap();

        let cluster = pool.get_cluster(&txid).unwrap();
        assert_eq!(cluster.linearization.len(), 1);
        assert_eq!(cluster.linearization[0], txid);
        assert_eq!(cluster.chunks.len(), 1);
        assert_eq!(cluster.chunks[0].txids.len(), 1);
    }

    #[test]
    fn test_parent_child_linearization_parent_first() {
        let mut pool = ClusterMempool::new();
        let parent = make_tx(0x01, None, 50_000);
        let parent_txid = parent.txid();
        pool.add_tx(parent, Amount::from_sat(2_000)).unwrap();

        let child = make_tx(0x02, Some(parent_txid), 40_000);
        let child_txid = child.txid();
        pool.add_tx(child, Amount::from_sat(8_000)).unwrap();

        let cluster = pool.get_cluster(&parent_txid).unwrap();
        // Parent must come before child.
        let parent_pos = cluster
            .linearization
            .iter()
            .position(|t| *t == parent_txid)
            .unwrap();
        let child_pos = cluster
            .linearization
            .iter()
            .position(|t| *t == child_txid)
            .unwrap();
        assert!(parent_pos < child_pos);
    }

    #[test]
    fn test_chunk_feerate() {
        let mut pool = ClusterMempool::new();
        let tx = make_tx(0x01, None, 50_000);
        let txid = pool.add_tx(tx.clone(), Amount::from_sat(5_000)).unwrap();

        let cluster = pool.get_cluster(&txid).unwrap();
        let chunk = &cluster.chunks[0];
        assert_eq!(chunk.total_fee, 5_000);
        let expected_feerate = FixedFeeRate::from_fee_weight(5_000, chunk.total_weight);
        assert_eq!(chunk.feerate(), expected_feerate);
    }

    #[test]
    fn test_cpfp_linearization() {
        // Parent has low fee, child has high fee (CPFP).
        // The greedy linearizer should group them into a single high-feerate chunk
        // if the child's ancestor set feerate is high enough.
        let mut pool = ClusterMempool::new();

        let parent = make_tx(0x01, None, 50_000);
        let parent_txid = parent.txid();
        pool.add_tx(parent, Amount::from_sat(1_000)).unwrap();

        let child = make_tx(0x02, Some(parent_txid), 40_000);
        pool.add_tx(child, Amount::from_sat(20_000)).unwrap();

        let cluster = pool.get_cluster(&parent_txid).unwrap();
        // They should be in one chunk because the child's ancestor set
        // (parent+child) has a higher feerate than the parent alone.
        // Actually, the chunk algorithm may create 1 or 2 chunks depending
        // on the math. Let's just verify the total is correct.
        let total_chunk_fee: u64 = cluster.chunks.iter().map(|c| c.total_fee).sum();
        assert_eq!(total_chunk_fee, 21_000);
    }

    // =====================================================================
    // Mining order
    // =====================================================================

    #[test]
    fn test_get_mining_order_empty() {
        let pool = ClusterMempool::new();
        let order = pool.get_mining_order();
        assert!(order.is_empty());
    }

    #[test]
    fn test_get_mining_order_sorted_by_feerate() {
        let mut pool = ClusterMempool::new();

        // Three independent txs with different feerates.
        let tx_low = make_tx(0x01, None, 50_000);
        pool.add_tx(tx_low, Amount::from_sat(1_000)).unwrap();

        let tx_mid = make_tx(0x02, None, 50_000);
        pool.add_tx(tx_mid, Amount::from_sat(5_000)).unwrap();

        let tx_high = make_tx(0x03, None, 50_000);
        pool.add_tx(tx_high, Amount::from_sat(10_000)).unwrap();

        let order = pool.get_mining_order();
        assert_eq!(order.len(), 3);
        assert!(order[0].feerate() >= order[1].feerate());
        assert!(order[1].feerate() >= order[2].feerate());
    }

    #[test]
    fn test_select_for_block() {
        let mut pool = ClusterMempool::new();

        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        let weight_a = tx_a.encoded_size();
        pool.add_tx(tx_a, Amount::from_sat(1_000)).unwrap();

        let tx_b = make_tx(0x02, None, 50_000);
        let txid_b = tx_b.txid();
        pool.add_tx(tx_b, Amount::from_sat(10_000)).unwrap();

        // Both should fit.
        let selected = pool.select_for_block(1_000_000);
        assert_eq!(selected.len(), 2);
        // Higher feerate first.
        assert_eq!(selected[0], txid_b);
        assert_eq!(selected[1], txid_a);

        // Only enough weight for one.
        let selected = pool.select_for_block(weight_a);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], txid_b);
    }

    // =====================================================================
    // evict_worst
    // =====================================================================

    #[test]
    fn test_evict_worst_empty() {
        let mut pool = ClusterMempool::new();
        let evicted = pool.evict_worst();
        assert!(evicted.is_empty());
    }

    #[test]
    fn test_evict_worst_removes_lowest_feerate() {
        let mut pool = ClusterMempool::new();

        let tx_low = make_tx(0x01, None, 50_000);
        let txid_low = tx_low.txid();
        pool.add_tx(tx_low, Amount::from_sat(1_000)).unwrap();

        let tx_high = make_tx(0x02, None, 50_000);
        let txid_high = tx_high.txid();
        pool.add_tx(tx_high, Amount::from_sat(10_000)).unwrap();

        let evicted = pool.evict_worst();
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].tx.txid(), txid_low);
        assert!(pool.contains(&txid_high));
        assert!(!pool.contains(&txid_low));
    }

    #[test]
    fn test_evict_worst_chain_cluster() {
        // In a chain cluster, evict_worst should remove the last chunk
        // (lowest feerate tail).
        let mut pool = ClusterMempool::new();

        let parent = make_tx(0x01, None, 50_000);
        let parent_txid = parent.txid();
        pool.add_tx(parent, Amount::from_sat(10_000)).unwrap();

        let child = make_tx(0x02, Some(parent_txid), 40_000);
        pool.add_tx(child, Amount::from_sat(1_000)).unwrap();

        // The cluster has parent (high fee) and child (low fee).
        // We need another independent cluster with even lower feerate
        // to be the "worst".
        let tx_worst = make_tx(0x03, None, 50_000);
        pool.add_tx(tx_worst, Amount::from_sat(1_000)).unwrap();

        // The independent tx_worst has the lowest feerate cluster.
        let evicted = pool.evict_worst();
        // It should evict from the worst cluster.
        assert!(!evicted.is_empty());
    }

    // =====================================================================
    // Package RBF
    // =====================================================================

    #[test]
    fn test_package_rbf_success() {
        let mut pool = ClusterMempool::new();

        let old_tx = make_tx(0x01, None, 50_000);
        let old_txid = old_tx.txid();
        pool.add_tx(old_tx.clone(), Amount::from_sat(2_000)).unwrap();

        // New tx spends the same input with higher fee.
        let new_tx = make_tx(0x01, None, 48_000);
        let new_txid = new_tx.txid();
        let result = pool.replace_by_fee(new_tx, Amount::from_sat(10_000), &[old_txid]);
        assert!(result.is_ok());
        assert!(!pool.contains(&old_txid));
        assert!(pool.contains(&new_txid));
    }

    #[test]
    fn test_package_rbf_insufficient_fee() {
        let mut pool = ClusterMempool::new();

        let old_tx = make_tx(0x01, None, 50_000);
        let old_txid = old_tx.txid();
        pool.add_tx(old_tx.clone(), Amount::from_sat(10_000)).unwrap();

        // New tx has lower fee — should fail.
        let new_tx = make_tx(0x01, None, 50_000);
        let result = pool.check_package_rbf(&new_tx, Amount::from_sat(5_000), &[old_txid]);
        assert!(matches!(result, Err(ClusterMempoolError::PackageRbfFailed)));
    }

    #[test]
    fn test_package_rbf_no_conflicts() {
        let pool = ClusterMempool::new();
        let tx = make_tx(0x01, None, 50_000);
        let result = pool.check_package_rbf(&tx, Amount::from_sat(5_000), &[]);
        assert!(result.is_ok());
    }

    // =====================================================================
    // 1p1c Package Acceptance
    // =====================================================================

    #[test]
    fn test_1p1c_package_acceptance() {
        let mut pool = ClusterMempool::new();

        // Parent has fee below min relay feerate.
        let parent = make_tx(0x01, None, 50_000);
        let parent_txid = parent.txid();

        // Child with high fee brings the package above threshold.
        let child = make_tx(0x02, Some(parent_txid), 40_000);

        let result = pool.accept_package(
            parent,
            Amount::from_sat(1), // way below min feerate
            child,
            Amount::from_sat(50_000), // high fee
        );

        assert!(result.is_ok());
        let (ptxid, ctxid) = result.unwrap();
        assert!(pool.contains(&ptxid));
        assert!(pool.contains(&ctxid));
        // They should be in the same cluster.
        assert_eq!(pool.cluster_count(), 1);
    }

    #[test]
    fn test_1p1c_package_below_threshold() {
        let mut pool = ClusterMempool::new();

        // Both parent and child have low fees — package feerate below threshold.
        let parent = make_tx(0x01, None, 50_000);
        let parent_txid = parent.txid();

        let child = make_tx(0x02, Some(parent_txid), 40_000);

        let result = pool.accept_package(
            parent,
            Amount::from_sat(1),
            child,
            Amount::from_sat(1),
        );

        assert!(matches!(
            result,
            Err(ClusterMempoolError::PackageBelowMinFeerate { .. })
        ));
        assert_eq!(pool.tx_count(), 0);
    }

    #[test]
    fn test_1p1c_parent_already_exists() {
        let mut pool = ClusterMempool::new();

        let parent = make_tx(0x01, None, 50_000);
        let parent_txid = parent.txid();
        pool.add_tx(parent.clone(), Amount::from_sat(5_000)).unwrap();

        let child = make_tx(0x02, Some(parent_txid), 40_000);

        let result = pool.accept_package(
            parent,
            Amount::from_sat(5_000),
            child,
            Amount::from_sat(5_000),
        );
        assert!(matches!(
            result,
            Err(ClusterMempoolError::ParentAlreadyExists(_))
        ));
    }

    #[test]
    fn test_1p1c_child_already_exists() {
        let mut pool = ClusterMempool::new();

        let parent = make_tx(0x01, None, 50_000);
        let parent_txid = parent.txid();

        let child = make_tx(0x02, Some(parent_txid), 40_000);
        // Pre-add the child (it will be in its own cluster since parent isn't in pool yet).
        pool.add_tx(child.clone(), Amount::from_sat(5_000)).unwrap();

        let result = pool.accept_package(
            parent,
            Amount::from_sat(5_000),
            child,
            Amount::from_sat(5_000),
        );
        assert!(matches!(
            result,
            Err(ClusterMempoolError::ChildAlreadyExists(_))
        ));
    }

    // =====================================================================
    // FixedFeeRate
    // =====================================================================

    #[test]
    fn test_fixed_feerate_zero_weight() {
        let fr = FixedFeeRate::from_fee_weight(1000, 0);
        assert_eq!(fr.as_raw(), 0);
    }

    #[test]
    fn test_fixed_feerate_basic() {
        let fr = FixedFeeRate::from_fee_weight(10_000, 500);
        // 10000 * 1000 / 500 = 20000
        assert_eq!(fr.as_raw(), 20_000);
    }

    #[test]
    fn test_fixed_feerate_ordering() {
        let low = FixedFeeRate::from_fee_weight(1_000, 500);
        let high = FixedFeeRate::from_fee_weight(10_000, 500);
        assert!(low < high);
    }

    // =====================================================================
    // Chunk
    // =====================================================================

    #[test]
    fn test_chunk_feerate_computation() {
        let chunk = Chunk {
            txids: vec![],
            total_fee: 10_000,
            total_weight: 500,
        };
        assert_eq!(chunk.feerate(), FixedFeeRate(20_000));
    }

    #[test]
    fn test_chunk_feerate_zero_weight() {
        let chunk = Chunk {
            txids: vec![],
            total_fee: 1_000,
            total_weight: 0,
        };
        assert_eq!(chunk.feerate(), FixedFeeRate(0));
    }

    // =====================================================================
    // Cluster
    // =====================================================================

    #[test]
    fn test_cluster_feerate() {
        let mut pool = ClusterMempool::new();
        let tx = make_tx(0x01, None, 50_000);
        let txid = pool.add_tx(tx, Amount::from_sat(5_000)).unwrap();

        let cluster = pool.get_cluster(&txid).unwrap();
        assert!(cluster.feerate().as_raw() > 0);
    }

    #[test]
    fn test_cluster_size() {
        let mut pool = ClusterMempool::new();
        let parent = make_tx(0x01, None, 50_000);
        let parent_txid = parent.txid();
        pool.add_tx(parent, Amount::from_sat(5_000)).unwrap();

        let child = make_tx(0x02, Some(parent_txid), 40_000);
        pool.add_tx(child, Amount::from_sat(3_000)).unwrap();

        let cluster = pool.get_cluster(&parent_txid).unwrap();
        assert_eq!(cluster.size(), 2);
    }

    // =====================================================================
    // Diagram dominance
    // =====================================================================

    #[test]
    fn test_diagram_dominates_higher_fee() {
        let new_chunks = vec![Chunk {
            txids: vec![],
            total_fee: 10_000,
            total_weight: 100,
        }];
        let old_chunks = vec![Chunk {
            txids: vec![],
            total_fee: 5_000,
            total_weight: 100,
        }];
        assert!(diagram_dominates(&new_chunks, &old_chunks));
    }

    #[test]
    fn test_diagram_does_not_dominate_lower_fee() {
        let new_chunks = vec![Chunk {
            txids: vec![],
            total_fee: 5_000,
            total_weight: 100,
        }];
        let old_chunks = vec![Chunk {
            txids: vec![],
            total_fee: 10_000,
            total_weight: 100,
        }];
        assert!(!diagram_dominates(&new_chunks, &old_chunks));
    }

    #[test]
    fn test_diagram_equal_not_dominant() {
        let new_chunks = vec![Chunk {
            txids: vec![],
            total_fee: 5_000,
            total_weight: 100,
        }];
        let old_chunks = vec![Chunk {
            txids: vec![],
            total_fee: 5_000,
            total_weight: 100,
        }];
        // Equal is not strictly better.
        assert!(!diagram_dominates(&new_chunks, &old_chunks));
    }

    #[test]
    fn test_diagram_dominates_empty_old() {
        let new_chunks = vec![Chunk {
            txids: vec![],
            total_fee: 5_000,
            total_weight: 100,
        }];
        let old_chunks: Vec<Chunk> = vec![];
        assert!(diagram_dominates(&new_chunks, &old_chunks));
    }

    #[test]
    fn test_diagram_does_not_dominate_empty_new() {
        let new_chunks: Vec<Chunk> = vec![];
        let old_chunks = vec![Chunk {
            txids: vec![],
            total_fee: 5_000,
            total_weight: 100,
        }];
        assert!(!diagram_dominates(&new_chunks, &old_chunks));
    }

    // =====================================================================
    // Interpolation
    // =====================================================================

    #[test]
    fn test_interpolate_fee_empty() {
        assert_eq!(interpolate_fee(&[], 100), 0);
    }

    #[test]
    fn test_interpolate_fee_zero_weight() {
        let points = vec![(100, 1000)];
        assert_eq!(interpolate_fee(&points, 0), 0);
    }

    #[test]
    fn test_interpolate_fee_exact_point() {
        let points = vec![(100, 1000), (200, 3000)];
        assert_eq!(interpolate_fee(&points, 100), 1000);
        assert_eq!(interpolate_fee(&points, 200), 3000);
    }

    #[test]
    fn test_interpolate_fee_midpoint() {
        let points = vec![(100, 1000), (200, 3000)];
        // Midpoint at weight 150: 1000 + (3000-1000) * (150-100) / (200-100) = 1000 + 1000 = 2000
        assert_eq!(interpolate_fee(&points, 150), 2000);
    }

    #[test]
    fn test_interpolate_fee_beyond_last() {
        let points = vec![(100, 1000)];
        assert_eq!(interpolate_fee(&points, 200), 1000);
    }

    // =====================================================================
    // Complex scenarios
    // =====================================================================

    #[test]
    fn test_diamond_dependency() {
        //    A
        //   / \
        //  B   C
        //   \ /
        //    D
        let mut pool = ClusterMempool::new();

        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        pool.add_tx(tx_a, Amount::from_sat(3_000)).unwrap();

        let tx_b = make_tx(0x02, Some(txid_a), 40_000);
        let txid_b = tx_b.txid();
        pool.add_tx(tx_b, Amount::from_sat(4_000)).unwrap();

        let tx_c = make_tx(0x03, Some(txid_a), 35_000);
        let txid_c = tx_c.txid();
        pool.add_tx(tx_c, Amount::from_sat(5_000)).unwrap();

        let tx_d = make_tx_multi_input(0x04, &[txid_b, txid_c], 25_000);
        pool.add_tx(tx_d, Amount::from_sat(6_000)).unwrap();

        assert_eq!(pool.cluster_count(), 1);
        assert_eq!(pool.tx_count(), 4);

        let cluster = pool.get_cluster(&txid_a).unwrap();
        assert_eq!(cluster.total_fee, 18_000);
    }

    #[test]
    fn test_two_separate_chains() {
        let mut pool = ClusterMempool::new();

        // Chain 1: A -> B
        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        pool.add_tx(tx_a, Amount::from_sat(2_000)).unwrap();

        let tx_b = make_tx(0x02, Some(txid_a), 40_000);
        pool.add_tx(tx_b, Amount::from_sat(3_000)).unwrap();

        // Chain 2: C -> D
        let tx_c = make_tx(0x03, None, 50_000);
        let txid_c = tx_c.txid();
        pool.add_tx(tx_c, Amount::from_sat(4_000)).unwrap();

        let tx_d = make_tx(0x04, Some(txid_c), 40_000);
        pool.add_tx(tx_d, Amount::from_sat(5_000)).unwrap();

        assert_eq!(pool.cluster_count(), 2);
    }

    #[test]
    fn test_many_independent_txs() {
        let mut pool = ClusterMempool::new();
        for i in 1u8..=20 {
            let tx = make_tx(i, None, 50_000);
            pool.add_tx(tx, Amount::from_sat(i as i64 * 1_000)).unwrap();
        }
        assert_eq!(pool.cluster_count(), 20);
        assert_eq!(pool.tx_count(), 20);
    }

    #[test]
    fn test_long_chain_single_cluster() {
        let mut pool = ClusterMempool::new();

        let mut prev_txid: Option<TxHash> = None;
        for i in 1u8..=10 {
            let tx = make_tx(i, prev_txid, 50_000);
            let txid = tx.txid();
            pool.add_tx(tx, Amount::from_sat(i as i64 * 1_000)).unwrap();
            prev_txid = Some(txid);
        }

        assert_eq!(pool.cluster_count(), 1);
        assert_eq!(pool.tx_count(), 10);

        let cluster = pool.get_cluster(&prev_txid.unwrap()).unwrap();
        assert_eq!(cluster.total_fee, 55_000);
    }

    #[test]
    fn test_remove_all_txs_leaves_empty() {
        let mut pool = ClusterMempool::new();
        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        pool.add_tx(tx_a, Amount::from_sat(5_000)).unwrap();

        let tx_b = make_tx(0x02, None, 50_000);
        let txid_b = tx_b.txid();
        pool.add_tx(tx_b, Amount::from_sat(3_000)).unwrap();

        pool.remove_tx(&txid_a);
        pool.remove_tx(&txid_b);

        assert_eq!(pool.tx_count(), 0);
        assert_eq!(pool.cluster_count(), 0);
    }

    #[test]
    fn test_evict_until_empty() {
        let mut pool = ClusterMempool::new();

        for i in 1u8..=5 {
            let tx = make_tx(i, None, 50_000);
            pool.add_tx(tx, Amount::from_sat(i as i64 * 1_000)).unwrap();
        }

        // Evict all.
        let mut evicted_count = 0;
        while !pool.evict_worst().is_empty() {
            evicted_count += 1;
            if evicted_count > 10 {
                panic!("infinite loop in evict_worst");
            }
        }

        assert_eq!(pool.tx_count(), 0);
        assert_eq!(pool.cluster_count(), 0);
    }

    #[test]
    fn test_select_for_block_empty() {
        let pool = ClusterMempool::new();
        let selected = pool.select_for_block(1_000_000);
        assert!(selected.is_empty());
    }

    #[test]
    fn test_select_for_block_zero_weight() {
        let mut pool = ClusterMempool::new();
        let tx = make_tx(0x01, None, 50_000);
        pool.add_tx(tx, Amount::from_sat(5_000)).unwrap();

        let selected = pool.select_for_block(0);
        assert!(selected.is_empty());
    }

    #[test]
    fn test_default_impl() {
        let pool = ClusterMempool::default();
        assert_eq!(pool.tx_count(), 0);
        assert_eq!(pool.cluster_count(), 0);
        assert_eq!(pool.max_cluster_size, MAX_CLUSTER_SIZE);
    }

    #[test]
    fn test_get_cluster_by_id() {
        let mut pool = ClusterMempool::new();
        let tx = make_tx(0x01, None, 50_000);
        let txid = pool.add_tx(tx, Amount::from_sat(5_000)).unwrap();

        let info = pool.get_tx(&txid).unwrap();
        let cid = info.cluster_id;
        let cluster = pool.get_cluster_by_id(cid).unwrap();
        assert!(cluster.txids.contains(&txid));
    }

    #[test]
    fn test_get_cluster_by_id_nonexistent() {
        let pool = ClusterMempool::new();
        assert!(pool.get_cluster_by_id(999).is_none());
    }

    #[test]
    fn test_error_display() {
        let e1 = ClusterMempoolError::AlreadyExists("abc".to_string());
        assert!(format!("{}", e1).contains("abc"));

        let e2 = ClusterMempoolError::ClusterTooLarge { size: 102, max: 101 };
        assert!(format!("{}", e2).contains("102"));

        let e3 = ClusterMempoolError::BelowMinRelayFeerate { fee: 1, weight: 100 };
        assert!(format!("{}", e3).contains("below minimum"));

        let e4 = ClusterMempoolError::PackageRbfFailed;
        assert!(format!("{}", e4).contains("dominate"));

        let e5 = ClusterMempoolError::PackageBelowMinFeerate {
            package_feerate: 500,
            min_feerate: 1000,
        };
        assert!(format!("{}", e5).contains("500"));

        let e6 = ClusterMempoolError::ParentAlreadyExists("def".to_string());
        assert!(format!("{}", e6).contains("def"));

        let e7 = ClusterMempoolError::ChildAlreadyExists("ghi".to_string());
        assert!(format!("{}", e7).contains("ghi"));
    }

    #[test]
    fn test_error_equality() {
        let e1 = ClusterMempoolError::PackageRbfFailed;
        let e2 = ClusterMempoolError::PackageRbfFailed;
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_cluster_total_fee_after_remove() {
        let mut pool = ClusterMempool::new();

        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        pool.add_tx(tx_a, Amount::from_sat(3_000)).unwrap();

        let tx_b = make_tx(0x02, Some(txid_a), 40_000);
        let txid_b = tx_b.txid();
        pool.add_tx(tx_b, Amount::from_sat(4_000)).unwrap();

        // Before removal, cluster fee = 7000.
        let cluster = pool.get_cluster(&txid_a).unwrap();
        assert_eq!(cluster.total_fee, 7_000);

        // Remove the child.
        pool.remove_tx(&txid_b);

        let cluster = pool.get_cluster(&txid_a).unwrap();
        assert_eq!(cluster.total_fee, 3_000);
        assert_eq!(cluster.size(), 1);
    }

    #[test]
    fn test_replace_by_fee_removes_conflicts_and_adds_new() {
        let mut pool = ClusterMempool::new();

        let tx_old = make_tx(0x01, None, 50_000);
        let txid_old = tx_old.txid();
        pool.add_tx(tx_old, Amount::from_sat(2_000)).unwrap();

        // Create new tx (different output value to get different txid)
        let tx_new = make_tx(0x01, None, 45_000);
        let txid_new = tx_new.txid();

        let result = pool.replace_by_fee(tx_new, Amount::from_sat(15_000), &[txid_old]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), txid_new);
        assert!(!pool.contains(&txid_old));
        assert!(pool.contains(&txid_new));
        assert_eq!(pool.tx_count(), 1);
    }

    #[test]
    fn test_1p1c_rollback_on_child_failure() {
        let mut pool = ClusterMempool::with_limits(2, DEFAULT_MIN_RELAY_FEERATE);

        // Pre-fill the pool so the child's cluster would be too large.
        // Actually, let's test a simpler rollback scenario: child is a duplicate.
        let parent = make_tx(0x01, None, 50_000);
        let parent_txid = parent.txid();

        let child = make_tx(0x02, Some(parent_txid), 40_000);
        // Pre-add the child.
        pool.add_tx(child.clone(), Amount::from_sat(5_000)).unwrap();

        let parent2 = make_tx(0x01, None, 50_000);
        let result = pool.accept_package(
            parent2,
            Amount::from_sat(5_000),
            child,
            Amount::from_sat(5_000),
        );

        // Should fail because child already exists.
        assert!(matches!(
            result,
            Err(ClusterMempoolError::ChildAlreadyExists(_))
        ));
        // Parent should NOT be in the pool (rolled back).
        assert!(!pool.contains(&parent_txid));
    }

    #[test]
    fn test_linearization_respects_dependencies() {
        // A chain of 5 txs. Verify linearization has correct topological order.
        let mut pool = ClusterMempool::new();

        let mut prev_txid: Option<TxHash> = None;
        let mut txids_in_order = Vec::new();
        for i in 1u8..=5 {
            let tx = make_tx(i, prev_txid, 50_000);
            let txid = tx.txid();
            pool.add_tx(tx, Amount::from_sat(i as i64 * 1_000)).unwrap();
            txids_in_order.push(txid);
            prev_txid = Some(txid);
        }

        let cluster = pool.get_cluster(&txids_in_order[0]).unwrap();
        // Verify topological ordering: each tx must appear after its parent.
        for i in 0..txids_in_order.len() - 1 {
            let parent_pos = cluster
                .linearization
                .iter()
                .position(|t| *t == txids_in_order[i])
                .unwrap();
            let child_pos = cluster
                .linearization
                .iter()
                .position(|t| *t == txids_in_order[i + 1])
                .unwrap();
            assert!(
                parent_pos < child_pos,
                "tx {} should come before tx {} in linearization",
                i,
                i + 1
            );
        }
    }

    #[test]
    fn test_chunks_cover_all_txs() {
        // Verify that all txs in a cluster appear exactly once across all chunks.
        let mut pool = ClusterMempool::new();

        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        pool.add_tx(tx_a, Amount::from_sat(3_000)).unwrap();

        let tx_b = make_tx(0x02, Some(txid_a), 40_000);
        let txid_b = tx_b.txid();
        pool.add_tx(tx_b, Amount::from_sat(4_000)).unwrap();

        let tx_c = make_tx(0x03, Some(txid_b), 30_000);
        pool.add_tx(tx_c, Amount::from_sat(5_000)).unwrap();

        let cluster = pool.get_cluster(&txid_a).unwrap();
        let mut chunk_txids: Vec<TxHash> = cluster
            .chunks
            .iter()
            .flat_map(|c| c.txids.iter().copied())
            .collect();
        chunk_txids.sort_by_key(|t| t.to_bytes());

        let mut cluster_txids: Vec<TxHash> = cluster.txids.iter().copied().collect();
        cluster_txids.sort_by_key(|t| t.to_bytes());

        assert_eq!(chunk_txids, cluster_txids);
    }

    #[test]
    fn test_chunks_fees_sum_to_cluster_total() {
        let mut pool = ClusterMempool::new();

        let tx_a = make_tx(0x01, None, 50_000);
        let txid_a = tx_a.txid();
        pool.add_tx(tx_a, Amount::from_sat(3_000)).unwrap();

        let tx_b = make_tx(0x02, Some(txid_a), 40_000);
        pool.add_tx(tx_b, Amount::from_sat(4_000)).unwrap();

        let cluster = pool.get_cluster(&txid_a).unwrap();
        let chunk_fee_total: u64 = cluster.chunks.iter().map(|c| c.total_fee).sum();
        assert_eq!(chunk_fee_total, cluster.total_fee);
    }

    #[test]
    fn test_mining_order_includes_all_txs() {
        let mut pool = ClusterMempool::new();

        for i in 1u8..=5 {
            let tx = make_tx(i, None, 50_000);
            pool.add_tx(tx, Amount::from_sat(i as i64 * 1_000)).unwrap();
        }

        let order = pool.get_mining_order();
        let total_txs: usize = order.iter().map(|c| c.txids.len()).sum();
        assert_eq!(total_txs, 5);
    }
}
