//! Persistent UTXO set backed by a [`Database`] implementation.
//!
//! This module bridges the consensus-layer [`UtxoSet`] trait with the storage-layer
//! [`Database`] trait, providing a UTXO set that survives node restarts.
//!
//! A write-through cache of recently-created UTXOs is maintained in memory.
//! Cache misses on reads are served from the underlying database via
//! [`DbTx::get_utxo`] and transparently inserted into the cache so that
//! subsequent lookups for the same outpoint are fast.

use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::sync::Arc;

use btc_consensus::utxo::{UtxoEntry, UtxoSet, UtxoSetUpdate};
use btc_primitives::amount::Amount;
use btc_primitives::script::ScriptBuf;
use btc_primitives::transaction::{OutPoint, TxOut};

use crate::traits::{Database, DbTx, DbTxMut, StorageError};

/// Default maximum number of entries in the hot UTXO cache.
const DEFAULT_CACHE_SIZE_LIMIT: usize = 100_000;

/// A UTXO set persisted to a [`Database`] backend with an in-memory write-through
/// cache for recently-created (hot) UTXOs.
///
/// # Cache behaviour
///
/// * **Writes** (`apply_update`): created UTXOs are inserted into both the cache
///   and the database; spent UTXOs are removed from both.
/// * **Reads** (`get_utxo` / `contains`): the cache is checked first.  On a miss
///   the entry is loaded from the database and promoted into the cache so that
///   repeated lookups are cheap.
/// * **Eviction**: when the cache exceeds `cache_size_limit` after an
///   `apply_update`, the oldest entries (by insertion order approximation) are
///   evicted.  Evicted entries are *not* deleted from the database — they can
///   always be reloaded on the next cache miss.
pub struct PersistentUtxoSet<DB: Database> {
    db: Arc<DB>,
    /// Read-through cache for hot UTXOs.
    ///
    /// # Safety
    ///
    /// Wrapped in `UnsafeCell` to allow interior mutation during `get_utxo`
    /// (`&self`).  This is sound because:
    ///
    /// 1. During `&self` borrows (reads), entries are only *added* to the map —
    ///    never removed — so outstanding `&UtxoEntry` references remain valid.
    /// 2. Methods that remove entries (`apply_update`, `flush_cache`) require
    ///    `&mut self`, which the borrow checker guarantees is exclusive (no
    ///    `&self` borrows can coexist).
    /// 3. `PersistentUtxoSet` is `!Sync` (due to `UnsafeCell`) so no concurrent
    ///    `&self` access can occur across threads.
    cache: UnsafeCell<HashMap<OutPoint, UtxoEntry>>,
    cache_size_limit: usize,
    /// Outpoints that were spent via `apply_update_cached` and need to be
    /// deleted from the DB on the next `flush_cache()`.
    pending_deletes: Vec<OutPoint>,
}

// PersistentUtxoSet is Send if DB is Send (UnsafeCell is Send when inner is Send).
// It is intentionally !Sync due to UnsafeCell, which is correct for our use case.
unsafe impl<DB: Database> Send for PersistentUtxoSet<DB> {}

impl<DB: Database> PersistentUtxoSet<DB> {
    /// Create a new `PersistentUtxoSet` wrapping the given database.
    pub fn new(db: Arc<DB>) -> Self {
        Self {
            db,
            cache: UnsafeCell::new(HashMap::new()),
            cache_size_limit: DEFAULT_CACHE_SIZE_LIMIT,
            pending_deletes: Vec::new(),
        }
    }

    /// Create a new `PersistentUtxoSet` with a custom cache size limit.
    pub fn with_cache_limit(db: Arc<DB>, cache_size_limit: usize) -> Self {
        Self {
            db,
            cache: UnsafeCell::new(HashMap::new()),
            cache_size_limit,
            pending_deletes: Vec::new(),
        }
    }

    /// Apply a [`UtxoSetUpdate`] — persist created UTXOs and delete spent ones.
    ///
    /// This writes through to the database in a single transaction and updates
    /// the in-memory cache accordingly.
    pub fn apply_update(&mut self, update: &UtxoSetUpdate) -> Result<(), StorageError> {
        let tx = self.db.tx_mut()?;

        // Remove spent UTXOs from DB and cache.
        for (outpoint, _entry) in &update.spent {
            tx.delete_utxo(outpoint)?;
            self.delete_utxo_meta(&tx, outpoint)?;
            self.cache.get_mut().remove(outpoint);
        }

        // Insert created UTXOs into DB and cache.
        for (outpoint, entry) in &update.created {
            tx.put_utxo(outpoint, &entry.txout)?;
            // We also need to persist height + is_coinbase metadata.
            // Encode as: height(8 LE) || is_coinbase(1)
            self.put_utxo_meta(&tx, outpoint, entry)?;
            self.cache.get_mut().insert(*outpoint, entry.clone());
        }

        tx.commit()?;

        // Evict if cache is over the limit.
        self.evict_cache();

        Ok(())
    }

    /// Apply a UTXO update to the in-memory cache only (no DB write).
    /// Call `flush_cache()` periodically to persist to disk.
    /// Tracks spent outpoints in `pending_deletes` so `flush_cache()`
    /// can delete them from the DB.
    pub fn apply_update_cached(&mut self, update: &UtxoSetUpdate) {
        for (outpoint, _) in &update.spent {
            self.cache.get_mut().remove(outpoint);
            self.pending_deletes.push(*outpoint);
        }
        for (outpoint, entry) in &update.created {
            self.cache.get_mut().insert(*outpoint, entry.clone());
        }
        self.evict_cache();
    }

    /// Write all cached entries to the database, delete spent UTXOs, and clear.
    pub fn flush_cache(&mut self) -> Result<(), StorageError> {
        let cache = self.cache.get_mut();
        if cache.is_empty() && self.pending_deletes.is_empty() {
            return Ok(());
        }

        let tx = self.db.tx_mut()?;

        // Delete spent UTXOs from DB (only if they exist in DB)
        for outpoint in &self.pending_deletes {
            // Check if the UTXO exists in DB before deleting — QMDB panics on
            // deleting non-existent keys. UTXOs created and spent within the same
            // batch were never persisted, so skip those.
            if tx.get_utxo(outpoint)?.is_some() {
                tx.delete_utxo(outpoint)?;
                let meta_outpoint = OutPoint::new(outpoint.txid, outpoint.vout | 0x8000_0000);
                if tx.get_utxo(&meta_outpoint)?.is_some() {
                    tx.delete_utxo(&meta_outpoint)?;
                }
            }
        }

        // Write created/cached UTXOs to DB
        for (outpoint, entry) in cache.iter() {
            tx.put_utxo(outpoint, &entry.txout)?;
            let meta_outpoint = OutPoint::new(outpoint.txid, outpoint.vout | 0x8000_0000);
            let meta_txout = TxOut {
                value: Amount::from_sat(entry.height as i64),
                script_pubkey: ScriptBuf::from_bytes(vec![entry.is_coinbase as u8]),
            };
            tx.put_utxo(&meta_outpoint, &meta_txout)?;
        }
        tx.commit()?;

        cache.clear();
        self.pending_deletes.clear();
        Ok(())
    }

    /// Return the number of entries currently in the cache.
    pub fn cache_len(&self) -> usize {
        // SAFETY: only reading the length, no mutation.
        unsafe { (*self.cache.get()).len() }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Load a full `UtxoEntry` from the database for the given outpoint.
    ///
    /// The DB stores `TxOut` via `DbTx::get_utxo` and the metadata (height,
    /// is_coinbase) under a separate metadata key.  Both are needed to
    /// reconstruct a `UtxoEntry`.
    fn load_from_db(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        let tx = self.db.tx().ok()?;
        let txout = tx.get_utxo(outpoint).ok()??;

        // Read the metadata (height + is_coinbase).
        let meta = self.get_utxo_meta(&tx, outpoint)?;

        Some(UtxoEntry {
            txout,
            height: meta.0,
            is_coinbase: meta.1,
        })
    }

    /// Write UTXO metadata (height + is_coinbase) alongside the TxOut.
    ///
    /// We store this as an additional UTXO entry whose value encodes the
    /// metadata in a compact format.  The key is the outpoint key with a
    /// `"um:"` (utxo-meta) prefix to avoid colliding with the TxOut entry.
    fn put_utxo_meta<T: DbTxMut>(
        &self,
        tx: &T,
        outpoint: &OutPoint,
        entry: &UtxoEntry,
    ) -> Result<(), StorageError> {
        // Encode metadata as a TxOut with value packing:
        //   value = height
        //   script_pubkey = [is_coinbase as u8]
        //
        // This reuses the existing put_utxo mechanism with a modified outpoint
        // (vout with high bit set) to store metadata without adding a new
        // DB trait method.
        let meta_outpoint = OutPoint::new(outpoint.txid, outpoint.vout | 0x8000_0000);
        let meta_txout = TxOut {
            value: Amount::from_sat(entry.height as i64),
            script_pubkey: ScriptBuf::from_bytes(vec![entry.is_coinbase as u8]),
        };
        tx.put_utxo(&meta_outpoint, &meta_txout)
    }

    /// Read UTXO metadata from the database.  Returns `(height, is_coinbase)`.
    fn get_utxo_meta<T: DbTx>(&self, tx: &T, outpoint: &OutPoint) -> Option<(u64, bool)> {
        let meta_outpoint = OutPoint::new(outpoint.txid, outpoint.vout | 0x8000_0000);
        let meta_txout = tx.get_utxo(&meta_outpoint).ok()??;
        let height = meta_txout.value.as_sat() as u64;
        let is_coinbase = meta_txout
            .script_pubkey
            .as_bytes()
            .first()
            .map(|&b| b != 0)
            .unwrap_or(false);
        Some((height, is_coinbase))
    }

    /// Delete UTXO metadata from the database.
    fn delete_utxo_meta<T: DbTxMut>(
        &self,
        tx: &T,
        outpoint: &OutPoint,
    ) -> Result<(), StorageError> {
        let meta_outpoint = OutPoint::new(outpoint.txid, outpoint.vout | 0x8000_0000);
        tx.delete_utxo(&meta_outpoint)
    }

    /// Evict cache entries when the cache size exceeds the limit.
    ///
    /// This is a simple strategy that removes arbitrary entries (HashMap
    /// iteration order) until the cache is within bounds.  A production
    /// implementation might use an LRU or generation-based policy.
    fn evict_cache(&mut self) {
        let cache = self.cache.get_mut();
        if cache.len() <= self.cache_size_limit {
            return;
        }
        let to_remove = cache.len() - self.cache_size_limit;
        let keys_to_remove: Vec<OutPoint> = cache.keys().take(to_remove).copied().collect();
        for key in keys_to_remove {
            cache.remove(&key);
        }
    }
}

impl<DB: Database> UtxoSet for PersistentUtxoSet<DB> {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<&UtxoEntry> {
        let cache_ptr = self.cache.get();

        // SAFETY: We only read from the map here.  If we find the entry, we
        // return a reference whose lifetime is tied to `&self`.  The entry will
        // not be removed until `&mut self` is taken (apply_update / flush_cache),
        // which cannot happen while `&self` is borrowed.
        if let Some(entry) = unsafe { (*cache_ptr).get(outpoint) } {
            return Some(entry);
        }

        // Cache miss — load from DB and promote into cache.
        let entry = self.load_from_db(outpoint)?;

        // SAFETY: No outstanding references into the map exist (the `get` above
        // returned `None`).  We insert a new entry and immediately obtain a
        // reference to it.  The reference is valid for `&self`'s lifetime because
        // entries are never removed while `&self` is borrowed (removal requires
        // `&mut self`).
        unsafe {
            (*cache_ptr).insert(*outpoint, entry);
            (*cache_ptr).get(outpoint)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redb_backend::RedbDatabase;
    use btc_consensus::utxo::{UtxoEntry, UtxoSetUpdate};
    use btc_primitives::amount::Amount;
    use btc_primitives::hash::TxHash;
    use btc_primitives::script::ScriptBuf;
    use btc_primitives::transaction::{OutPoint, TxOut};

    /// Helper: create a temporary RedbDatabase.
    fn temp_db() -> (Arc<RedbDatabase>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let db_path = dir.path().join("test_utxo.redb");
        let db = RedbDatabase::new(&db_path).expect("failed to create db");
        db.init_tables().expect("failed to init tables");
        (Arc::new(db), dir)
    }

    /// Helper: build a test UtxoEntry.
    fn make_entry(value: u64, height: u64, is_coinbase: bool) -> UtxoEntry {
        UtxoEntry {
            txout: TxOut {
                value: Amount::from_sat(value as i64),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            },
            height,
            is_coinbase,
        }
    }

    /// Helper: build an outpoint with a distinct txid.
    fn make_outpoint(id_byte: u8, vout: u32) -> OutPoint {
        OutPoint::new(TxHash::from_bytes([id_byte; 32]), vout)
    }

    // -----------------------------------------------------------------------
    // Basic insert and lookup
    // -----------------------------------------------------------------------

    #[test]
    fn test_insert_and_get() {
        let (db, _dir) = temp_db();
        let mut utxo_set = PersistentUtxoSet::new(Arc::clone(&db));

        let op = make_outpoint(0x01, 0);
        let entry = make_entry(50_000, 100, false);

        let update = UtxoSetUpdate {
            spent: vec![],
            created: vec![(op, entry.clone())],
        };
        utxo_set.apply_update(&update).unwrap();

        // Should be retrievable.
        let got = utxo_set.get_utxo(&op);
        assert!(got.is_some());
        let got = got.unwrap();
        assert_eq!(got.txout.value.as_sat(), 50_000);
        assert_eq!(got.height, 100);
        assert!(!got.is_coinbase);
    }

    // -----------------------------------------------------------------------
    // Contains
    // -----------------------------------------------------------------------

    #[test]
    fn test_contains() {
        let (db, _dir) = temp_db();
        let mut utxo_set = PersistentUtxoSet::new(Arc::clone(&db));

        let op = make_outpoint(0x02, 0);
        let entry = make_entry(1_000, 5, true);

        assert!(!utxo_set.contains(&op));

        let update = UtxoSetUpdate {
            spent: vec![],
            created: vec![(op, entry)],
        };
        utxo_set.apply_update(&update).unwrap();

        assert!(utxo_set.contains(&op));
    }

    // -----------------------------------------------------------------------
    // Spend removes UTXO
    // -----------------------------------------------------------------------

    #[test]
    fn test_spend_removes_utxo() {
        let (db, _dir) = temp_db();
        let mut utxo_set = PersistentUtxoSet::new(Arc::clone(&db));

        let op = make_outpoint(0x03, 0);
        let entry = make_entry(25_000, 10, false);

        // Create.
        let update = UtxoSetUpdate {
            spent: vec![],
            created: vec![(op, entry.clone())],
        };
        utxo_set.apply_update(&update).unwrap();
        assert!(utxo_set.contains(&op));

        // Spend.
        let update = UtxoSetUpdate {
            spent: vec![(op, entry)],
            created: vec![],
        };
        utxo_set.apply_update(&update).unwrap();
        assert!(!utxo_set.contains(&op));
    }

    // -----------------------------------------------------------------------
    // Persistence: data survives a new PersistentUtxoSet instance on same DB
    // -----------------------------------------------------------------------

    #[test]
    fn test_persistence_across_instances() {
        let (db, _dir) = temp_db();

        let op1 = make_outpoint(0x10, 0);
        let entry1 = make_entry(100_000, 200, false);
        let op2 = make_outpoint(0x11, 1);
        let entry2 = make_entry(50_000_000, 300, true);

        // Write with first instance.
        {
            let mut utxo_set = PersistentUtxoSet::new(Arc::clone(&db));
            let update = UtxoSetUpdate {
                spent: vec![],
                created: vec![(op1, entry1.clone()), (op2, entry2.clone())],
            };
            utxo_set.apply_update(&update).unwrap();
        }

        // Read with a fresh instance (empty cache).
        {
            let utxo_set = PersistentUtxoSet::new(Arc::clone(&db));
            assert_eq!(utxo_set.cache_len(), 0);

            let got1 = utxo_set.get_utxo(&op1).expect("op1 should be in DB");
            assert_eq!(got1.txout.value.as_sat(), 100_000);
            assert_eq!(got1.height, 200);
            assert!(!got1.is_coinbase);

            let got2 = utxo_set.get_utxo(&op2).expect("op2 should be in DB");
            assert_eq!(got2.txout.value.as_sat(), 50_000_000);
            assert_eq!(got2.height, 300);
            assert!(got2.is_coinbase);

            // Both should now be in the cache after loading.
            assert_eq!(utxo_set.cache_len(), 2);
        }
    }

    // -----------------------------------------------------------------------
    // Persistence: spent UTXO is gone from DB after reopen
    // -----------------------------------------------------------------------

    #[test]
    fn test_spend_persists_across_instances() {
        let (db, _dir) = temp_db();

        let op = make_outpoint(0x20, 0);
        let entry = make_entry(42_000, 50, false);

        // Create in first instance.
        {
            let mut utxo_set = PersistentUtxoSet::new(Arc::clone(&db));
            let update = UtxoSetUpdate {
                spent: vec![],
                created: vec![(op, entry.clone())],
            };
            utxo_set.apply_update(&update).unwrap();
        }

        // Spend in second instance.
        {
            let mut utxo_set = PersistentUtxoSet::new(Arc::clone(&db));
            let update = UtxoSetUpdate {
                spent: vec![(op, entry.clone())],
                created: vec![],
            };
            utxo_set.apply_update(&update).unwrap();
        }

        // Verify gone in third instance.
        {
            let utxo_set = PersistentUtxoSet::new(Arc::clone(&db));
            assert!(utxo_set.get_utxo(&op).is_none());
        }
    }

    // -----------------------------------------------------------------------
    // Cache eviction
    // -----------------------------------------------------------------------

    #[test]
    fn test_cache_eviction() {
        let (db, _dir) = temp_db();
        let mut utxo_set = PersistentUtxoSet::with_cache_limit(Arc::clone(&db), 5);

        // Insert 10 UTXOs — cache should be capped at 5 after eviction.
        let entries: Vec<(OutPoint, UtxoEntry)> = (0u8..10)
            .map(|i| (make_outpoint(i, 0), make_entry(1_000 * i as u64, i as u64, false)))
            .collect();

        let update = UtxoSetUpdate {
            spent: vec![],
            created: entries.clone(),
        };
        utxo_set.apply_update(&update).unwrap();

        // Cache should be at most the limit.
        assert!(utxo_set.cache_len() <= 5);

        // All 10 entries should still be accessible (cache miss -> DB load).
        for (op, expected) in &entries {
            let got = utxo_set.get_utxo(op).expect("entry should be in DB");
            assert_eq!(got.txout.value.as_sat(), expected.txout.value.as_sat());
            assert_eq!(got.height, expected.height);
        }
    }

    // -----------------------------------------------------------------------
    // Flush cache
    // -----------------------------------------------------------------------

    #[test]
    fn test_flush_cache() {
        let (db, _dir) = temp_db();
        let mut utxo_set = PersistentUtxoSet::new(Arc::clone(&db));

        let op = make_outpoint(0x30, 0);
        let entry = make_entry(99_000, 42, true);

        let update = UtxoSetUpdate {
            spent: vec![],
            created: vec![(op, entry.clone())],
        };
        utxo_set.apply_update(&update).unwrap();
        assert_eq!(utxo_set.cache_len(), 1);

        utxo_set.flush_cache().unwrap();
        assert_eq!(utxo_set.cache_len(), 0);

        // Entry should still be accessible from DB.
        let got = utxo_set.get_utxo(&op).expect("entry should still be in DB");
        assert_eq!(got.txout.value.as_sat(), 99_000);
        assert_eq!(got.height, 42);
        assert!(got.is_coinbase);
    }

    // -----------------------------------------------------------------------
    // Missing UTXO returns None
    // -----------------------------------------------------------------------

    #[test]
    fn test_missing_utxo_returns_none() {
        let (db, _dir) = temp_db();
        let utxo_set = PersistentUtxoSet::new(Arc::clone(&db));

        let op = make_outpoint(0xff, 99);
        assert!(utxo_set.get_utxo(&op).is_none());
        assert!(!utxo_set.contains(&op));
    }

    // -----------------------------------------------------------------------
    // Coinbase metadata roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_coinbase_metadata_persists() {
        let (db, _dir) = temp_db();

        let op = make_outpoint(0x40, 0);
        let entry = make_entry(50_0000_0000, 0, true);

        {
            let mut utxo_set = PersistentUtxoSet::new(Arc::clone(&db));
            let update = UtxoSetUpdate {
                spent: vec![],
                created: vec![(op, entry.clone())],
            };
            utxo_set.apply_update(&update).unwrap();
        }

        // Fresh instance — must recover coinbase flag and height from DB.
        {
            let utxo_set = PersistentUtxoSet::new(Arc::clone(&db));
            let got = utxo_set.get_utxo(&op).expect("should find coinbase UTXO");
            assert!(got.is_coinbase, "coinbase flag should be true");
            assert_eq!(got.height, 0, "height should be 0 (genesis)");
            assert_eq!(got.txout.value.as_sat(), 50_0000_0000);
        }
    }

    // -----------------------------------------------------------------------
    // Multiple updates in sequence
    // -----------------------------------------------------------------------

    #[test]
    fn test_multiple_updates() {
        let (db, _dir) = temp_db();
        let mut utxo_set = PersistentUtxoSet::new(Arc::clone(&db));

        let op1 = make_outpoint(0x50, 0);
        let entry1 = make_entry(10_000, 1, false);

        let op2 = make_outpoint(0x51, 0);
        let entry2 = make_entry(20_000, 2, false);

        let op3 = make_outpoint(0x52, 0);
        let entry3 = make_entry(30_000, 2, false);

        // Block 1: create op1.
        utxo_set
            .apply_update(&UtxoSetUpdate {
                spent: vec![],
                created: vec![(op1, entry1.clone())],
            })
            .unwrap();

        // Block 2: spend op1, create op2 and op3.
        utxo_set
            .apply_update(&UtxoSetUpdate {
                spent: vec![(op1, entry1)],
                created: vec![(op2, entry2.clone()), (op3, entry3.clone())],
            })
            .unwrap();

        assert!(utxo_set.get_utxo(&op1).is_none());
        assert_eq!(utxo_set.get_utxo(&op2).unwrap().txout.value.as_sat(), 20_000);
        assert_eq!(utxo_set.get_utxo(&op3).unwrap().txout.value.as_sat(), 30_000);
    }
}
