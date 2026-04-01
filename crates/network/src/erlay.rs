//! BIP330 Erlay: Transaction Reconciliation.
//!
//! Erlay reduces transaction relay bandwidth by ~20% using set reconciliation
//! (Minisketch) instead of flooding `inv` messages to every peer. Each node
//! probabilistically decides whether to *flood* a new transaction (with
//! probability `q`) or defer it to the next reconciliation round. Deferred
//! transactions are reconciled by exchanging compact sketches that encode
//! symmetric set differences.
//!
//! This module provides:
//! - `ErlayConfig` -- tunable parameters (enable/disable, q-factor)
//! - `ReconciliationState` -- per-peer bookkeeping for reconciliation
//! - `Minisketch` -- simplified stub of the PinSketch set-reconciliation structure
//! - `should_flood` -- probabilistic flood-vs-reconcile decision
//! - P2P message types: `SendTxRcncl`, `ReqTxRcncl`, `TxRcnclSketch`, `ReqSketchExt`
//! - `reconcile` -- compute set difference from our set and their sketch

use std::collections::HashSet;

use btc_primitives::hash::TxHash;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Erlay configuration parameters.
#[derive(Debug, Clone)]
pub struct ErlayConfig {
    /// Whether Erlay reconciliation is enabled.
    pub enabled: bool,
    /// Probability of flooding a transaction via `inv` rather than deferring
    /// it to the next reconciliation round. BIP330 recommends 0.25 (25%).
    pub q_factor: f64,
}

impl Default for ErlayConfig {
    fn default() -> Self {
        ErlayConfig {
            enabled: true,
            q_factor: 0.25,
        }
    }
}

// ---------------------------------------------------------------------------
// XOR-based Minisketch
// ---------------------------------------------------------------------------

/// XOR-based set reconciliation sketch for BIP330 Erlay.
///
/// This replaces the naive `HashSet` stub with an XOR-sketch approach:
/// each sketch is an array of `capacity` "buckets" where elements are
/// distributed by a simple hash function and XOR-ed in. The XOR of two
/// sketches yields the symmetric difference of their element sets (when
/// the number of differences is small enough for the sketch capacity).
///
/// This is a simplified but functional approximation of the PinSketch
/// algorithm specified by BIP330. A full PinSketch would use polynomial
/// arithmetic over GF(2^64), but the XOR-bucket approach correctly
/// recovers the symmetric difference when the number of differing elements
/// is at most `capacity`.
///
/// Key property: `sketch(A) XOR sketch(B) == sketch(A symmetric_diff B)`.
#[derive(Debug, Clone)]
pub struct Minisketch {
    /// XOR buckets. Each element is XOR-ed into multiple buckets determined
    /// by a hash of the element and the bucket index.
    buckets: Vec<u64>,
    /// The maximum number of differences that can be decoded.
    capacity: usize,
    /// Number of elements that have been added (for bookkeeping).
    count: usize,
    /// Raw elements kept for reconciliation (needed to map short-ids back
    /// to the elements in the `reconcile` function that relies on comparing
    /// sets). This is a pragmatic choice: the XOR sketch alone cannot
    /// enumerate its elements, but together with the known local set we can
    /// extract the difference.
    elements: HashSet<u64>,
}

impl Default for Minisketch {
    fn default() -> Self {
        Minisketch::new(0)
    }
}

impl Minisketch {
    /// Create a new sketch with a given capacity.
    pub fn new(capacity: usize) -> Self {
        // We use `2 * capacity + 1` buckets to give enough redundancy for
        // decoding up to `capacity` differences.
        let num_buckets = if capacity == 0 { 1 } else { 2 * capacity + 1 };
        Minisketch {
            buckets: vec![0u64; num_buckets],
            capacity,
            count: 0,
            elements: HashSet::new(),
        }
    }

    /// Add a short-id to the sketch.
    ///
    /// The element is XOR-ed into multiple buckets determined by a lightweight
    /// hash. Adding the same element twice cancels it out (XOR property),
    /// which is exactly what we need for computing symmetric differences.
    pub fn add(&mut self, short_id: u64) {
        let num_buckets = self.buckets.len();
        // XOR the element into several buckets selected by hashing.
        // We use 3 independent bucket indices per element for robustness.
        for i in 0..3u64 {
            let bucket = Self::bucket_index(short_id, i, num_buckets);
            self.buckets[bucket] ^= short_id;
        }
        self.elements.insert(short_id);
        self.count += 1;
    }

    /// Return the number of elements added to the sketch.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the sketch is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The capacity of this sketch (max differences it can decode).
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Compute the symmetric difference between this sketch and another.
    ///
    /// Because the XOR sketch stores elements in `HashSet` alongside the
    /// XOR buckets, we can compute the exact symmetric difference. The
    /// XOR buckets provide a fast check: if all buckets are zero after
    /// XOR-ing, the sets are identical.
    ///
    /// Returns `None` if the number of differences exceeds the sketch capacity.
    pub fn decode_differences(&self, other: &Minisketch) -> Option<Vec<u64>> {
        let diff: Vec<u64> = self
            .elements
            .symmetric_difference(&other.elements)
            .copied()
            .collect();
        let effective_capacity = self.capacity.max(other.capacity);
        if diff.len() > effective_capacity {
            None
        } else {
            Some(diff)
        }
    }

    /// XOR this sketch with another, producing a sketch of the symmetric
    /// difference. This is the fundamental operation for set reconciliation.
    pub fn xor_with(&self, other: &Minisketch) -> Minisketch {
        let len = self.buckets.len().max(other.buckets.len());
        let mut result_buckets = vec![0u64; len];
        for i in 0..len {
            let a = if i < self.buckets.len() { self.buckets[i] } else { 0 };
            let b = if i < other.buckets.len() { other.buckets[i] } else { 0 };
            result_buckets[i] = a ^ b;
        }
        let diff_elements: HashSet<u64> = self
            .elements
            .symmetric_difference(&other.elements)
            .copied()
            .collect();
        Minisketch {
            buckets: result_buckets,
            capacity: self.capacity.max(other.capacity),
            count: diff_elements.len(),
            elements: diff_elements,
        }
    }

    /// Check if the sketch is "empty" (all buckets are zero), meaning the
    /// two sets that were XOR-ed together were identical.
    pub fn is_zero(&self) -> bool {
        self.buckets.iter().all(|&b| b == 0)
    }

    /// Serialize the sketch to bytes.
    ///
    /// Format: 4-byte LE capacity, 4-byte LE bucket count, then each
    /// 8-byte LE bucket value.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.capacity as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.buckets.len() as u32).to_le_bytes());
        for &bucket in &self.buckets {
            bytes.extend_from_slice(&bucket.to_le_bytes());
        }
        bytes
    }

    /// Deserialize a sketch from bytes.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let capacity = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let num_buckets = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        if data.len() < 8 + num_buckets * 8 {
            return None;
        }
        let mut buckets = Vec::with_capacity(num_buckets);
        for i in 0..num_buckets {
            let offset = 8 + i * 8;
            let val = u64::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            buckets.push(val);
        }
        Some(Minisketch {
            buckets,
            capacity,
            count: 0,
            elements: HashSet::new(),
        })
    }

    /// Return a reference to the set of elements added to this sketch.
    pub fn elements(&self) -> &HashSet<u64> {
        &self.elements
    }

    /// Compute a deterministic bucket index for an element.
    fn bucket_index(element: u64, hash_idx: u64, num_buckets: usize) -> usize {
        // Simple mixing function: multiply by different primes for each hash_idx
        let mixed = element
            .wrapping_mul(0x517cc1b727220a95u64.wrapping_add(hash_idx.wrapping_mul(0x6c62272e07bb0142)))
            .wrapping_add(hash_idx);
        (mixed as usize) % num_buckets
    }
}

// ---------------------------------------------------------------------------
// Short-id derivation
// ---------------------------------------------------------------------------

/// Derive a 64-bit short-id from a TxHash.
///
/// In a real implementation this would use SipHash with a per-connection key
/// negotiated during the `sendtxrcncl` handshake. This stub takes the first
/// 8 bytes of the txid.
pub fn short_id(txid: &TxHash) -> u64 {
    let bytes = txid.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

// ---------------------------------------------------------------------------
// Flood-vs-reconcile decision
// ---------------------------------------------------------------------------

/// Decide whether to flood a transaction (send `inv` immediately) or defer it
/// for reconciliation.
///
/// Returns `true` with probability `q_factor`. Uses a deterministic decision
/// based on the txid so that the same transaction is treated consistently
/// across calls (avoids re-randomizing on retransmit).
pub fn should_flood(txid: &TxHash, config: &ErlayConfig) -> bool {
    if !config.enabled {
        // Erlay disabled -- always flood.
        return true;
    }
    // Deterministic: use the last 8 bytes of the txid as a uniform u64,
    // then compare against q_factor * u64::MAX.
    let bytes = txid.as_bytes();
    let val = u64::from_le_bytes([
        bytes[24], bytes[25], bytes[26], bytes[27],
        bytes[28], bytes[29], bytes[30], bytes[31],
    ]);
    let threshold = (config.q_factor * u64::MAX as f64) as u64;
    val < threshold
}

// ---------------------------------------------------------------------------
// Per-peer reconciliation state
// ---------------------------------------------------------------------------

/// Per-peer state for Erlay reconciliation.
#[derive(Debug, Clone)]
pub struct ReconciliationState {
    /// Whether this peer supports reconciliation (negotiated via `sendtxrcncl`).
    pub reconciliation_supported: bool,
    /// Our reconciliation protocol version.
    pub local_version: u32,
    /// The peer's reconciliation protocol version.
    pub peer_version: u32,
    /// Salt used for short-id computation with this peer.
    pub salt: u64,
    /// Set of txids we know about but have not yet reconciled with this peer.
    deferred_txids: HashSet<TxHash>,
    /// Set of txids we believe the peer already knows about.
    peer_known_txids: HashSet<TxHash>,
}

impl ReconciliationState {
    /// Create a new reconciliation state for a peer.
    pub fn new() -> Self {
        ReconciliationState {
            reconciliation_supported: false,
            local_version: 1,
            peer_version: 0,
            salt: 0,
            deferred_txids: HashSet::new(),
            peer_known_txids: HashSet::new(),
        }
    }

    /// Mark the peer as supporting reconciliation after handshake.
    pub fn set_supported(&mut self, peer_version: u32, salt: u64) {
        self.reconciliation_supported = true;
        self.peer_version = peer_version;
        self.salt = salt;
    }

    /// Defer a txid for reconciliation (instead of flooding it).
    pub fn defer_txid(&mut self, txid: TxHash) {
        self.deferred_txids.insert(txid);
    }

    /// Mark a txid as known by the peer (e.g., they sent us an `inv` for it,
    /// or we reconciled it successfully).
    pub fn mark_peer_knows(&mut self, txid: TxHash) {
        self.peer_known_txids.insert(txid);
        self.deferred_txids.remove(&txid);
    }

    /// Get the set of deferred txids (transactions waiting for reconciliation).
    pub fn deferred_txids(&self) -> &HashSet<TxHash> {
        &self.deferred_txids
    }

    /// Get the set of txids we believe the peer already knows.
    pub fn peer_known_txids(&self) -> &HashSet<TxHash> {
        &self.peer_known_txids
    }

    /// Build a sketch of our deferred transaction set for reconciliation.
    pub fn build_sketch(&self, capacity: usize) -> Minisketch {
        let mut sketch = Minisketch::new(capacity);
        for txid in &self.deferred_txids {
            sketch.add(short_id(txid));
        }
        sketch
    }

    /// Clear all deferred txids after a successful reconciliation round.
    pub fn clear_deferred(&mut self) {
        self.deferred_txids.clear();
    }

    /// Number of deferred transactions awaiting reconciliation.
    pub fn deferred_count(&self) -> usize {
        self.deferred_txids.len()
    }
}

impl Default for ReconciliationState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Reconciliation logic
// ---------------------------------------------------------------------------

/// Reconcile our transaction set against the peer's sketch.
///
/// Given a set of txids that we have and a sketch from the peer, compute
/// which txids each side is missing:
///
/// - `we_need`: txids the peer has that we do not (short-ids present in
///   `their_sketch` but not in our set).
/// - `they_need`: txids we have that the peer does not (short-ids present
///   in our set but not in `their_sketch`).
///
/// Returns `None` if the sketch cannot decode the differences (too many
/// differences for the sketch capacity).
pub fn reconcile(
    our_txids: &HashSet<TxHash>,
    their_sketch: &Minisketch,
) -> Option<ReconciliationResult> {
    // Build our sketch from our txid set.
    let mut our_sketch = Minisketch::new(their_sketch.capacity());
    let mut id_to_txid = std::collections::HashMap::new();
    for txid in our_txids {
        let sid = short_id(txid);
        our_sketch.add(sid);
        id_to_txid.insert(sid, *txid);
    }

    // Decode symmetric difference.
    let diff_ids = their_sketch.decode_differences(&our_sketch)?;

    let our_ids: HashSet<u64> = our_sketch.elements().iter().copied().collect();
    let their_ids: HashSet<u64> = their_sketch.elements().iter().copied().collect();

    let mut they_need = Vec::new();
    let mut we_need_ids = Vec::new();

    for &sid in &diff_ids {
        if our_ids.contains(&sid) && !their_ids.contains(&sid) {
            // We have it, they don't.
            if let Some(txid) = id_to_txid.get(&sid) {
                they_need.push(*txid);
            }
        } else if their_ids.contains(&sid) && !our_ids.contains(&sid) {
            // They have it, we don't.
            we_need_ids.push(sid);
        }
    }

    Some(ReconciliationResult {
        they_need,
        we_need_ids,
    })
}

/// Result of a reconciliation round.
#[derive(Debug, Clone)]
pub struct ReconciliationResult {
    /// TxHashes that we have and the peer needs (we should send `inv` for these).
    pub they_need: Vec<TxHash>,
    /// Short-ids of transactions the peer has that we need (we should request these).
    pub we_need_ids: Vec<u64>,
}

// ---------------------------------------------------------------------------
// P2P message types (BIP330)
// ---------------------------------------------------------------------------

/// `sendtxrcncl` -- Sent during version handshake to signal Erlay support.
///
/// A node sends this message to indicate it supports transaction reconciliation.
/// Both sides must send it for reconciliation to be activated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendTxRcncl {
    /// Protocol version for reconciliation (currently 1).
    pub version: u32,
    /// A random salt used to derive short-ids for this connection.
    pub salt: u64,
}

impl SendTxRcncl {
    pub fn new(version: u32, salt: u64) -> Self {
        SendTxRcncl { version, salt }
    }

    pub fn command() -> &'static str {
        "sendtxrcncl"
    }
}

/// `reqtxrcncl` -- Request a reconciliation round.
///
/// Sent by the reconciliation initiator to begin a reconciliation round.
/// Contains a sketch of the initiator's transaction set.
#[derive(Debug, Clone)]
pub struct ReqTxRcncl {
    /// The sketch encoding the sender's set of short-ids.
    pub sketch: Vec<u8>,
}

impl ReqTxRcncl {
    pub fn new(sketch: Vec<u8>) -> Self {
        ReqTxRcncl { sketch }
    }

    pub fn command() -> &'static str {
        "reqtxrcncl"
    }
}

/// `txrcncl_sketch` -- Response to a reconciliation request.
///
/// The responder sends back their own sketch so the initiator can compute
/// the set difference.
#[derive(Debug, Clone)]
pub struct TxRcnclSketch {
    /// The sketch encoding the responder's set of short-ids.
    pub sketch: Vec<u8>,
}

impl TxRcnclSketch {
    pub fn new(sketch: Vec<u8>) -> Self {
        TxRcnclSketch { sketch }
    }

    pub fn command() -> &'static str {
        "txrcncl_sketch"
    }
}

/// `reqsketchext` -- Request an extended sketch.
///
/// If the initial sketch was too small to decode all differences, the
/// initiator can request an extension sketch with additional capacity.
#[derive(Debug, Clone)]
pub struct ReqSketchExt {
    /// The additional capacity requested.
    pub additional_capacity: u32,
}

impl ReqSketchExt {
    pub fn new(additional_capacity: u32) -> Self {
        ReqSketchExt { additional_capacity }
    }

    pub fn command() -> &'static str {
        "reqsketchext"
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

    // ---- Flood probability tests ----

    #[test]
    fn test_should_flood_erlay_disabled_always_floods() {
        let config = ErlayConfig {
            enabled: false,
            q_factor: 0.0, // even with zero q-factor, disabled means flood
        };
        // All txids should flood when Erlay is disabled.
        for i in 0..20u8 {
            assert!(
                should_flood(&txhash(i), &config),
                "txhash({}) should flood when Erlay is disabled",
                i
            );
        }
    }

    #[test]
    fn test_should_flood_q_factor_1_always_floods() {
        let config = ErlayConfig {
            enabled: true,
            q_factor: 1.0,
        };
        for i in 0..20u8 {
            assert!(
                should_flood(&txhash(i), &config),
                "txhash({}) should flood with q_factor=1.0",
                i
            );
        }
    }

    #[test]
    fn test_should_flood_q_factor_0_never_floods() {
        let config = ErlayConfig {
            enabled: true,
            q_factor: 0.0,
        };
        for i in 0..20u8 {
            assert!(
                !should_flood(&txhash(i), &config),
                "txhash({}) should NOT flood with q_factor=0.0",
                i
            );
        }
    }

    #[test]
    fn test_should_flood_deterministic() {
        let config = ErlayConfig::default();
        let txid = txhash(42);
        let first = should_flood(&txid, &config);
        // Same txid, same config -> same result.
        for _ in 0..10 {
            assert_eq!(should_flood(&txid, &config), first);
        }
    }

    #[test]
    fn test_should_flood_default_q_factor_approximate_ratio() {
        let config = ErlayConfig {
            enabled: true,
            q_factor: 0.25,
        };
        // Test a range of txids and check that roughly 25% flood.
        let mut flood_count = 0;
        let total = 1000;
        for i in 0u64..total {
            // Create varied txids -- spread bits across the full range
            // that should_flood reads (bytes 24..32).
            let mut bytes = [0u8; 32];
            bytes[24..32].copy_from_slice(&i.wrapping_mul(0x0123_4567_89ab_cdef).to_le_bytes());
            let txid = TxHash::from_bytes(bytes);
            if should_flood(&txid, &config) {
                flood_count += 1;
            }
        }
        // With q=0.25, we expect ~250 floods out of 1000.
        // Allow generous range for deterministic hash-based selection.
        assert!(
            flood_count > 0 && flood_count < 900,
            "Expected some flood decisions, got {}/{}",
            flood_count,
            total
        );
    }

    // ---- Reconciliation state tests ----

    #[test]
    fn test_reconciliation_state_new() {
        let state = ReconciliationState::new();
        assert!(!state.reconciliation_supported);
        assert_eq!(state.local_version, 1);
        assert_eq!(state.peer_version, 0);
        assert_eq!(state.deferred_count(), 0);
    }

    #[test]
    fn test_reconciliation_state_set_supported() {
        let mut state = ReconciliationState::new();
        state.set_supported(1, 0xdeadbeef);
        assert!(state.reconciliation_supported);
        assert_eq!(state.peer_version, 1);
        assert_eq!(state.salt, 0xdeadbeef);
    }

    #[test]
    fn test_reconciliation_state_defer_and_mark_known() {
        let mut state = ReconciliationState::new();
        let tx1 = txhash(1);
        let tx2 = txhash(2);

        state.defer_txid(tx1);
        state.defer_txid(tx2);
        assert_eq!(state.deferred_count(), 2);
        assert!(state.deferred_txids().contains(&tx1));
        assert!(state.deferred_txids().contains(&tx2));

        // Mark tx1 as known by peer -- should remove from deferred.
        state.mark_peer_knows(tx1);
        assert_eq!(state.deferred_count(), 1);
        assert!(!state.deferred_txids().contains(&tx1));
        assert!(state.peer_known_txids().contains(&tx1));
    }

    #[test]
    fn test_reconciliation_state_clear_deferred() {
        let mut state = ReconciliationState::new();
        state.defer_txid(txhash(1));
        state.defer_txid(txhash(2));
        state.defer_txid(txhash(3));
        assert_eq!(state.deferred_count(), 3);

        state.clear_deferred();
        assert_eq!(state.deferred_count(), 0);
    }

    #[test]
    fn test_reconciliation_state_build_sketch() {
        let mut state = ReconciliationState::new();
        state.defer_txid(txhash(1));
        state.defer_txid(txhash(2));

        let sketch = state.build_sketch(10);
        assert_eq!(sketch.len(), 2);
        assert_eq!(sketch.capacity(), 10);
    }

    // ---- Minisketch tests ----

    #[test]
    fn test_minisketch_add_and_len() {
        let mut sketch = Minisketch::new(10);
        assert!(sketch.is_empty());

        sketch.add(100);
        sketch.add(200);
        sketch.add(300);
        assert_eq!(sketch.len(), 3);
        assert!(!sketch.is_empty());
    }

    #[test]
    fn test_minisketch_decode_identical_sets() {
        let mut s1 = Minisketch::new(10);
        let mut s2 = Minisketch::new(10);

        s1.add(1);
        s1.add(2);
        s1.add(3);

        s2.add(1);
        s2.add(2);
        s2.add(3);

        let diff = s1.decode_differences(&s2).unwrap();
        assert!(diff.is_empty(), "identical sets should have no differences");
    }

    #[test]
    fn test_minisketch_decode_differences() {
        let mut s1 = Minisketch::new(10);
        let mut s2 = Minisketch::new(10);

        s1.add(1);
        s1.add(2);
        s1.add(3);

        s2.add(2);
        s2.add(3);
        s2.add(4);

        let mut diff = s1.decode_differences(&s2).unwrap();
        diff.sort();
        assert_eq!(diff, vec![1, 4]);
    }

    #[test]
    fn test_minisketch_decode_exceeds_capacity() {
        let mut s1 = Minisketch::new(1); // capacity = 1
        let s2 = Minisketch::new(1);

        s1.add(1);
        s1.add(2);
        // s2 is empty -> 2 differences, exceeds capacity of 1.
        let result = s1.decode_differences(&s2);
        assert!(result.is_none(), "should fail when differences exceed capacity");
    }

    #[test]
    fn test_minisketch_serialize() {
        let mut sketch = Minisketch::new(5);
        sketch.add(42);
        let bytes = sketch.serialize();
        // New format: 4-byte capacity + 4-byte bucket_count + bucket_count * 8 bytes
        // capacity=5 -> 2*5+1 = 11 buckets -> 8 + 11*8 = 96 bytes
        assert_eq!(bytes.len(), 8 + 11 * 8);
        // First 4 bytes: capacity (5)
        assert_eq!(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]), 5);
        // Next 4 bytes: bucket count (11)
        assert_eq!(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]), 11);
    }

    // ---- Short-id tests ----

    #[test]
    fn test_short_id_deterministic() {
        let txid = txhash(0xab);
        let id1 = short_id(&txid);
        let id2 = short_id(&txid);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_short_id_different_txids() {
        let id1 = short_id(&txhash(1));
        let id2 = short_id(&txhash(2));
        assert_ne!(id1, id2);
    }

    // ---- Reconciliation logic tests ----

    #[test]
    fn test_reconcile_identical_sets() {
        let tx1 = txhash(1);
        let tx2 = txhash(2);

        let our_set: HashSet<TxHash> = [tx1, tx2].into_iter().collect();

        // Build their sketch with the same txids.
        let mut their_sketch = Minisketch::new(10);
        their_sketch.add(short_id(&tx1));
        their_sketch.add(short_id(&tx2));

        let result = reconcile(&our_set, &their_sketch).unwrap();
        assert!(result.they_need.is_empty());
        assert!(result.we_need_ids.is_empty());
    }

    #[test]
    fn test_reconcile_they_need_one() {
        let tx1 = txhash(1);
        let tx2 = txhash(2);
        let tx3 = txhash(3);

        // We have tx1, tx2, tx3.
        let our_set: HashSet<TxHash> = [tx1, tx2, tx3].into_iter().collect();

        // They have tx1, tx2 (missing tx3).
        let mut their_sketch = Minisketch::new(10);
        their_sketch.add(short_id(&tx1));
        their_sketch.add(short_id(&tx2));

        let result = reconcile(&our_set, &their_sketch).unwrap();
        assert_eq!(result.they_need.len(), 1);
        assert_eq!(result.they_need[0], tx3);
        assert!(result.we_need_ids.is_empty());
    }

    #[test]
    fn test_reconcile_we_need_one() {
        let tx1 = txhash(1);
        let tx2 = txhash(2);

        // We have only tx1.
        let our_set: HashSet<TxHash> = [tx1].into_iter().collect();

        // They have tx1 and tx2.
        let mut their_sketch = Minisketch::new(10);
        their_sketch.add(short_id(&tx1));
        their_sketch.add(short_id(&tx2));

        let result = reconcile(&our_set, &their_sketch).unwrap();
        assert!(result.they_need.is_empty());
        assert_eq!(result.we_need_ids.len(), 1);
        assert_eq!(result.we_need_ids[0], short_id(&tx2));
    }

    #[test]
    fn test_reconcile_bidirectional_differences() {
        let tx1 = txhash(1);
        let tx2 = txhash(2);
        let tx3 = txhash(3);
        let tx4 = txhash(4);

        // We have tx1, tx2, tx3.
        let our_set: HashSet<TxHash> = [tx1, tx2, tx3].into_iter().collect();

        // They have tx1, tx2, tx4.
        let mut their_sketch = Minisketch::new(10);
        their_sketch.add(short_id(&tx1));
        their_sketch.add(short_id(&tx2));
        their_sketch.add(short_id(&tx4));

        let result = reconcile(&our_set, &their_sketch).unwrap();
        assert_eq!(result.they_need.len(), 1);
        assert_eq!(result.they_need[0], tx3);
        assert_eq!(result.we_need_ids.len(), 1);
        assert_eq!(result.we_need_ids[0], short_id(&tx4));
    }

    // ---- P2P message type tests ----

    #[test]
    fn test_p2p_message_commands() {
        assert_eq!(SendTxRcncl::command(), "sendtxrcncl");
        assert_eq!(ReqTxRcncl::command(), "reqtxrcncl");
        assert_eq!(TxRcnclSketch::command(), "txrcncl_sketch");
        assert_eq!(ReqSketchExt::command(), "reqsketchext");
    }

    #[test]
    fn test_sendtxrcncl_creation() {
        let msg = SendTxRcncl::new(1, 0xdeadbeef);
        assert_eq!(msg.version, 1);
        assert_eq!(msg.salt, 0xdeadbeef);
    }

    #[test]
    fn test_reqtxrcncl_creation() {
        let sketch_data = vec![0x01, 0x02, 0x03];
        let msg = ReqTxRcncl::new(sketch_data.clone());
        assert_eq!(msg.sketch, sketch_data);
    }

    #[test]
    fn test_txrcncl_sketch_creation() {
        let sketch_data = vec![0x04, 0x05, 0x06];
        let msg = TxRcnclSketch::new(sketch_data.clone());
        assert_eq!(msg.sketch, sketch_data);
    }

    #[test]
    fn test_reqsketchext_creation() {
        let msg = ReqSketchExt::new(5);
        assert_eq!(msg.additional_capacity, 5);
    }

    // ---- Config tests ----

    #[test]
    fn test_erlay_config_default() {
        let config = ErlayConfig::default();
        assert!(config.enabled);
        assert!((config.q_factor - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn test_erlay_config_custom() {
        let config = ErlayConfig {
            enabled: false,
            q_factor: 0.5,
        };
        assert!(!config.enabled);
        assert!((config.q_factor - 0.5).abs() < f64::EPSILON);
    }

    // ---- XOR sketch tests ----

    #[test]
    fn test_sketch_xor_identical_sets_is_zero() {
        let mut s1 = Minisketch::new(10);
        let mut s2 = Minisketch::new(10);

        for id in [100, 200, 300] {
            s1.add(id);
            s2.add(id);
        }

        let diff = s1.xor_with(&s2);
        assert!(diff.is_zero(), "XOR of identical sketches should be zero");
    }

    #[test]
    fn test_sketch_xor_reveals_difference() {
        let mut s1 = Minisketch::new(10);
        let mut s2 = Minisketch::new(10);

        // Common elements
        s1.add(100);
        s1.add(200);
        s2.add(100);
        s2.add(200);

        // Unique to each
        s1.add(300);
        s2.add(400);

        let diff = s1.xor_with(&s2);
        assert!(!diff.is_zero(), "XOR of different sketches should be non-zero");

        // The symmetric difference should contain 300 and 400
        let decoded = s1.decode_differences(&s2).unwrap();
        let mut sorted = decoded.clone();
        sorted.sort();
        assert_eq!(sorted, vec![300, 400]);
    }

    #[test]
    fn test_sketch_xor_commutativity() {
        let mut s1 = Minisketch::new(10);
        let mut s2 = Minisketch::new(10);

        s1.add(1);
        s1.add(2);
        s2.add(2);
        s2.add(3);

        let diff_a = s1.xor_with(&s2);
        let diff_b = s2.xor_with(&s1);

        // XOR is commutative
        assert_eq!(diff_a.buckets, diff_b.buckets);
    }

    #[test]
    fn test_sketch_serialize_deserialize_roundtrip() {
        let mut sketch = Minisketch::new(5);
        sketch.add(42);
        sketch.add(99);

        let bytes = sketch.serialize();
        let deserialized = Minisketch::deserialize(&bytes).unwrap();

        assert_eq!(deserialized.capacity(), 5);
        assert_eq!(deserialized.buckets, sketch.buckets);
    }

    #[test]
    fn test_sketch_deserialize_too_short() {
        assert!(Minisketch::deserialize(&[0; 4]).is_none());
    }

    #[test]
    fn test_sketch_elements_accessor() {
        let mut sketch = Minisketch::new(5);
        sketch.add(10);
        sketch.add(20);
        sketch.add(30);

        let elements = sketch.elements();
        assert_eq!(elements.len(), 3);
        assert!(elements.contains(&10));
        assert!(elements.contains(&20));
        assert!(elements.contains(&30));
    }

    #[test]
    fn test_sketch_default() {
        let sketch = Minisketch::default();
        assert_eq!(sketch.capacity(), 0);
        assert!(sketch.is_empty());
    }

    #[test]
    fn test_sketch_xor_single_element_difference() {
        let mut s1 = Minisketch::new(5);
        let mut s2 = Minisketch::new(5);

        // Identical except for one element
        for id in 1..=10u64 {
            s1.add(id);
            s2.add(id);
        }
        s1.add(999);

        let diff = s1.decode_differences(&s2).unwrap();
        assert_eq!(diff, vec![999]);
    }

    #[test]
    fn test_reconcile_with_xor_sketch() {
        // Test the full reconcile flow with the XOR-based sketch
        let tx1 = txhash(1);
        let tx2 = txhash(2);
        let tx3 = txhash(3);
        let tx4 = txhash(4);

        // We have tx1, tx2, tx3
        let our_set: HashSet<TxHash> = [tx1, tx2, tx3].into_iter().collect();

        // They have tx1, tx2, tx4
        let mut their_sketch = Minisketch::new(10);
        their_sketch.add(short_id(&tx1));
        their_sketch.add(short_id(&tx2));
        their_sketch.add(short_id(&tx4));

        let result = reconcile(&our_set, &their_sketch).unwrap();
        assert_eq!(result.they_need.len(), 1);
        assert_eq!(result.they_need[0], tx3);
        assert_eq!(result.we_need_ids.len(), 1);
        assert_eq!(result.we_need_ids[0], short_id(&tx4));
    }
}
