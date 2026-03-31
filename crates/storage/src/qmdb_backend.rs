use std::path::Path;
use std::sync::{Arc, Mutex};

use parking_lot::RwLock;

use qmdb::config::Config;
use qmdb::def::{DEFAULT_ENTRY_SIZE, IN_BLOCK_IDX_BITS, OP_CREATE, OP_DELETE, OP_WRITE};
use qmdb::entryfile::entry::EntryBz;
use qmdb::tasks::TasksManager;
use qmdb::test_helper::SimpleTask;
use qmdb::utils::changeset::ChangeSet;
use qmdb::utils::{byte0_to_shard_id, hasher};
use qmdb::{AdsCore, AdsWrap, SharedAdsWrap, ADS};

use btc_primitives::block::BlockHeader;
use btc_primitives::encode;
use btc_primitives::hash::{BlockHash, TxHash};
use btc_primitives::transaction::{OutPoint, Transaction, TxOut};

use crate::traits::{Database, DbTx, DbTxMut, StorageError};

// Key namespace prefixes — separate logical tables within QMDB's flat keyspace
const NS_BLOCK_HEADER: &[u8] = b"bh:";
const NS_BLOCK_HEIGHT: &[u8] = b"ht:";
const NS_TRANSACTION: &[u8] = b"tx:";
const NS_UTXO: &[u8] = b"ut:";

// Metadata keys
const META_BEST_HEIGHT: &[u8] = b"mt:best_height";
const META_BEST_HASH: &[u8] = b"mt:best_hash";

/// Build a namespaced key from prefix + suffix, capped at 255 bytes (QMDB limit)
fn make_key(ns: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(ns.len() + suffix.len());
    k.extend_from_slice(ns);
    k.extend_from_slice(suffix);
    k
}

/// Build an OutPoint key: namespace + txid(32) + vout(4 LE)
fn outpoint_key(outpoint: &OutPoint) -> Vec<u8> {
    let mut key = Vec::with_capacity(NS_UTXO.len() + 36);
    key.extend_from_slice(NS_UTXO);
    key.extend_from_slice(outpoint.txid.as_bytes());
    key.extend_from_slice(&outpoint.vout.to_le_bytes());
    key
}

/// Build a block height key: namespace + height(8 BE for lexicographic order)
fn height_key(height: u64) -> Vec<u8> {
    make_key(NS_BLOCK_HEIGHT, &height.to_be_bytes())
}

/// Read an entry from SharedAdsWrap, returning the value bytes if found
fn read_value_from_shared(shared: &SharedAdsWrap, key: &[u8]) -> Option<Vec<u8>> {
    let key_hash = hasher::hash(key);
    let mut buf = vec![0u8; DEFAULT_ENTRY_SIZE];

    // height -1 = latest committed state
    let (n, found) = shared.read_entry(-1, &key_hash, key, &mut buf);
    if !found {
        return None;
    }

    if n > buf.len() {
        // Entry larger than default buffer — resize and retry
        buf.resize(n, 0);
        let (n2, found2) = shared.read_entry(-1, &key_hash, key, &mut buf);
        if !found2 {
            return None;
        }
        let entry = EntryBz { bz: &buf[..n2] };
        Some(entry.value().to_vec())
    } else {
        let entry = EntryBz { bz: &buf[..n] };
        Some(entry.value().to_vec())
    }
}

/// QMDB-backed database for Bitcoin block/tx/UTXO storage.
///
/// QMDB's block-oriented write model maps naturally to Bitcoin's block-by-block
/// processing. Writes are buffered in `QmdbTxMut` and flushed as a QMDB block
/// on `commit()`.
pub struct QmdbDatabase {
    /// AdsWrap is not Sync, so we wrap in Mutex for thread safety
    ads: Arc<Mutex<AdsWrap<SimpleTask>>>,
    /// Current QMDB block height (incremented on each commit)
    next_height: Arc<Mutex<i64>>,
}

// AdsWrap contains non-Sync fields (mpsc::Receiver), but we guard with Mutex
unsafe impl Send for QmdbDatabase {}
unsafe impl Sync for QmdbDatabase {}

impl QmdbDatabase {
    /// Create or open a QMDB database at the given path
    pub fn new(path: &Path) -> Result<Self, StorageError> {
        let dir = path.to_str().ok_or_else(|| {
            StorageError::Database("path is not valid UTF-8".into())
        })?;

        let config = Config::from_dir(dir);
        AdsCore::init_dir(&config);
        let ads = AdsWrap::new(&config);

        Ok(QmdbDatabase {
            ads: Arc::new(Mutex::new(ads)),
            next_height: Arc::new(Mutex::new(1)),
        })
    }
}

impl Database for QmdbDatabase {
    type TX = QmdbTx;
    type TXMut = QmdbTxMut;

    fn tx(&self) -> Result<Self::TX, StorageError> {
        Ok(QmdbTx {
            db: Arc::clone(&self.ads),
        })
    }

    fn tx_mut(&self) -> Result<Self::TXMut, StorageError> {
        Ok(QmdbTxMut {
            db: Arc::clone(&self.ads),
            next_height: Arc::clone(&self.next_height),
            ops: Mutex::new(Vec::new()),
        })
    }
}

/// Read-only transaction backed by QMDB's shared state
pub struct QmdbTx {
    db: Arc<Mutex<AdsWrap<SimpleTask>>>,
}

unsafe impl Send for QmdbTx {}
unsafe impl Sync for QmdbTx {}

impl QmdbTx {
    fn read_value(&self, key: &[u8]) -> Option<Vec<u8>> {
        let ads = self.db.lock().unwrap();
        let shared = ads.get_shared();
        read_value_from_shared(&shared, key)
    }
}

impl DbTx for QmdbTx {
    fn get_block_header(&self, hash: &BlockHash) -> Result<Option<BlockHeader>, StorageError> {
        let key = make_key(NS_BLOCK_HEADER, hash.as_bytes());
        match self.read_value(&key) {
            Some(bytes) => {
                let header: BlockHeader = encode::decode(&bytes)
                    .map_err(|e| StorageError::Corruption(e.to_string()))?;
                Ok(Some(header))
            }
            None => Ok(None),
        }
    }

    fn get_block_hash_by_height(&self, height: u64) -> Result<Option<BlockHash>, StorageError> {
        let key = height_key(height);
        match self.read_value(&key) {
            Some(bytes) if bytes.len() == 32 => Ok(Some(BlockHash::from_slice(&bytes))),
            Some(_) => Err(StorageError::Corruption("invalid block hash length".into())),
            None => Ok(None),
        }
    }

    fn get_transaction(&self, txid: &TxHash) -> Result<Option<Transaction>, StorageError> {
        let key = make_key(NS_TRANSACTION, txid.as_bytes());
        match self.read_value(&key) {
            Some(bytes) => {
                let tx: Transaction = encode::decode(&bytes)
                    .map_err(|e| StorageError::Corruption(e.to_string()))?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>, StorageError> {
        let key = outpoint_key(outpoint);
        match self.read_value(&key) {
            Some(bytes) => {
                let txout: TxOut = encode::decode(&bytes)
                    .map_err(|e| StorageError::Corruption(e.to_string()))?;
                Ok(Some(txout))
            }
            None => Ok(None),
        }
    }

    fn get_best_block_height(&self) -> Result<u64, StorageError> {
        match self.read_value(META_BEST_HEIGHT) {
            Some(bytes) if bytes.len() == 8 => {
                Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
            }
            None => Ok(0),
            _ => Err(StorageError::Corruption("invalid best height".into())),
        }
    }

    fn get_best_block_hash(&self) -> Result<BlockHash, StorageError> {
        match self.read_value(META_BEST_HASH) {
            Some(bytes) if bytes.len() == 32 => Ok(BlockHash::from_slice(&bytes)),
            None => Ok(BlockHash::ZERO),
            _ => Err(StorageError::Corruption("invalid best hash".into())),
        }
    }
}

/// Buffered write operation
struct WriteOp {
    op_type: u8,
    key: Vec<u8>,
    value: Vec<u8>,
}

/// Read-write transaction that buffers mutations and flushes as a QMDB block on commit.
///
/// QMDB's write model is block-oriented: all mutations in a `commit()` are
/// submitted as a single QMDB block, mirroring Bitcoin's block-by-block processing.
pub struct QmdbTxMut {
    db: Arc<Mutex<AdsWrap<SimpleTask>>>,
    next_height: Arc<Mutex<i64>>,
    /// Interior mutability for write buffer — trait methods take `&self`
    ops: Mutex<Vec<WriteOp>>,
}

unsafe impl Send for QmdbTxMut {}
unsafe impl Sync for QmdbTxMut {}

impl QmdbTxMut {
    fn read_value(&self, key: &[u8]) -> Option<Vec<u8>> {
        // Check local buffer first (most recent write wins)
        let ops = self.ops.lock().unwrap();
        for op in ops.iter().rev() {
            if op.key == key {
                return match op.op_type {
                    OP_DELETE => None,
                    _ => Some(op.value.clone()),
                };
            }
        }
        drop(ops);
        // Fall back to committed state
        let ads = self.db.lock().unwrap();
        let shared = ads.get_shared();
        read_value_from_shared(&shared, key)
    }

    fn buffer_upsert(&self, key: Vec<u8>, value: Vec<u8>) {
        // Determine OP_CREATE vs OP_WRITE based on whether key already exists
        let exists = {
            let ads = self.db.lock().unwrap();
            let shared = ads.get_shared();
            let key_hash = hasher::hash(&key);
            let mut buf = vec![0u8; DEFAULT_ENTRY_SIZE];
            let (_, found) = shared.read_entry(-1, &key_hash, &key, &mut buf);
            found
        };
        let mut ops = self.ops.lock().unwrap();
        let created_in_batch = ops.iter().any(|op| op.key == key && op.op_type == OP_CREATE);

        let op_type = if exists || created_in_batch { OP_WRITE } else { OP_CREATE };
        ops.push(WriteOp { op_type, key, value });
    }

    fn buffer_delete(&self, key: Vec<u8>, value: Vec<u8>) {
        self.ops.lock().unwrap().push(WriteOp {
            op_type: OP_DELETE,
            key,
            value,
        });
    }
}

impl DbTx for QmdbTxMut {
    fn get_block_header(&self, hash: &BlockHash) -> Result<Option<BlockHeader>, StorageError> {
        let key = make_key(NS_BLOCK_HEADER, hash.as_bytes());
        match self.read_value(&key) {
            Some(bytes) => Ok(Some(encode::decode(&bytes).map_err(|e| StorageError::Corruption(e.to_string()))?)),
            None => Ok(None),
        }
    }

    fn get_block_hash_by_height(&self, height: u64) -> Result<Option<BlockHash>, StorageError> {
        let key = height_key(height);
        match self.read_value(&key) {
            Some(bytes) if bytes.len() == 32 => Ok(Some(BlockHash::from_slice(&bytes))),
            Some(_) => Err(StorageError::Corruption("invalid block hash length".into())),
            None => Ok(None),
        }
    }

    fn get_transaction(&self, txid: &TxHash) -> Result<Option<Transaction>, StorageError> {
        let key = make_key(NS_TRANSACTION, txid.as_bytes());
        match self.read_value(&key) {
            Some(bytes) => Ok(Some(encode::decode(&bytes).map_err(|e| StorageError::Corruption(e.to_string()))?)),
            None => Ok(None),
        }
    }

    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>, StorageError> {
        let key = outpoint_key(outpoint);
        match self.read_value(&key) {
            Some(bytes) => Ok(Some(encode::decode(&bytes).map_err(|e| StorageError::Corruption(e.to_string()))?)),
            None => Ok(None),
        }
    }

    fn get_best_block_height(&self) -> Result<u64, StorageError> {
        match self.read_value(META_BEST_HEIGHT) {
            Some(bytes) if bytes.len() == 8 => Ok(u64::from_be_bytes(bytes.try_into().unwrap())),
            None => Ok(0),
            _ => Err(StorageError::Corruption("invalid best height".into())),
        }
    }

    fn get_best_block_hash(&self) -> Result<BlockHash, StorageError> {
        match self.read_value(META_BEST_HASH) {
            Some(bytes) if bytes.len() == 32 => Ok(BlockHash::from_slice(&bytes)),
            None => Ok(BlockHash::ZERO),
            _ => Err(StorageError::Corruption("invalid best hash".into())),
        }
    }
}

impl DbTxMut for QmdbTxMut {
    fn put_block_header(&self, hash: &BlockHash, header: &BlockHeader) -> Result<(), StorageError> {
        self.buffer_upsert(make_key(NS_BLOCK_HEADER, hash.as_bytes()), encode::encode(header));
        Ok(())
    }

    fn put_block_hash_by_height(&self, height: u64, hash: &BlockHash) -> Result<(), StorageError> {
        self.buffer_upsert(height_key(height), hash.as_bytes().to_vec());
        Ok(())
    }

    fn put_transaction(&self, txid: &TxHash, tx: &Transaction) -> Result<(), StorageError> {
        self.buffer_upsert(make_key(NS_TRANSACTION, txid.as_bytes()), encode::encode(tx));
        Ok(())
    }

    fn put_utxo(&self, outpoint: &OutPoint, txout: &TxOut) -> Result<(), StorageError> {
        self.buffer_upsert(outpoint_key(outpoint), encode::encode(txout));
        Ok(())
    }

    fn delete_utxo(&self, outpoint: &OutPoint) -> Result<(), StorageError> {
        let key = outpoint_key(outpoint);
        let current_value = self.read_value(&key).unwrap_or_default();
        self.buffer_delete(key, current_value);
        Ok(())
    }

    fn set_best_block(&self, height: u64, hash: &BlockHash) -> Result<(), StorageError> {
        self.buffer_upsert(META_BEST_HEIGHT.to_vec(), height.to_be_bytes().to_vec());
        self.buffer_upsert(META_BEST_HASH.to_vec(), hash.as_bytes().to_vec());
        Ok(())
    }

    fn commit(self) -> Result<(), StorageError> {
        let ops = self.ops.into_inner().unwrap();
        if ops.is_empty() {
            return Ok(());
        }

        // Build QMDB changeset from buffered operations
        let mut cset = ChangeSet::new();
        for op in &ops {
            let kh = hasher::hash(&op.key);
            let shard_id = byte0_to_shard_id(kh[0]) as u8;
            cset.add_op(op.op_type, shard_id, &kh, &op.key, &op.value, None);
        }
        cset.sort();

        // Submit as a single QMDB block
        let mut ads = self.db.lock().unwrap();
        let height = {
            let mut h = self.next_height.lock().unwrap();
            let current = *h;
            *h += 1;
            current
        };

        let task = SimpleTask::new(vec![cset]);
        let task_list = vec![RwLock::new(Some(task))];
        let last_task_id = (height << IN_BLOCK_IDX_BITS) | 0;

        ads.start_block(
            height,
            Arc::new(TasksManager::new(task_list, last_task_id)),
        );

        let shared = ads.get_shared();
        shared.insert_extra_data(height, String::new());
        shared.add_task(height << IN_BLOCK_IDX_BITS);

        ads.flush();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::amount::Amount;
    use btc_primitives::compact::CompactTarget;
    use btc_primitives::script::ScriptBuf;

    fn temp_db() -> (tempfile::TempDir, QmdbDatabase) {
        let dir = tempfile::tempdir().unwrap();
        let db = QmdbDatabase::new(dir.path()).unwrap();
        (dir, db)
    }

    fn sample_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::ZERO,
            merkle_root: TxHash::from_bytes([0xab; 32]),
            time: 1231006505,
            bits: CompactTarget::MAX_TARGET,
            nonce: 2083236893,
        }
    }

    #[test]
    fn test_qmdb_block_header_roundtrip() {
        let (_dir, db) = temp_db();
        let header = sample_header();
        let hash = header.block_hash();

        let tx = db.tx_mut().unwrap();
        tx.put_block_header(&hash, &header).unwrap();
        tx.commit().unwrap();

        let tx = db.tx().unwrap();
        let retrieved = tx.get_block_header(&hash).unwrap();
        assert_eq!(retrieved, Some(header));
    }

    #[test]
    fn test_qmdb_missing_key_returns_none() {
        let (_dir, db) = temp_db();
        let tx = db.tx().unwrap();
        let result = tx.get_block_header(&BlockHash::from_bytes([0xff; 32])).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_qmdb_utxo_insert_delete() {
        let (_dir, db) = temp_db();
        let outpoint = OutPoint::new(TxHash::from_bytes([0x01; 32]), 0);
        let txout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
        };

        let tx = db.tx_mut().unwrap();
        tx.put_utxo(&outpoint, &txout).unwrap();
        tx.commit().unwrap();

        let tx = db.tx().unwrap();
        assert_eq!(tx.get_utxo(&outpoint).unwrap(), Some(txout));

        let tx = db.tx_mut().unwrap();
        tx.delete_utxo(&outpoint).unwrap();
        tx.commit().unwrap();

        let tx = db.tx().unwrap();
        assert_eq!(tx.get_utxo(&outpoint).unwrap(), None);
    }

    #[test]
    fn test_qmdb_best_block() {
        let (_dir, db) = temp_db();

        let tx = db.tx().unwrap();
        assert_eq!(tx.get_best_block_height().unwrap(), 0);
        assert_eq!(tx.get_best_block_hash().unwrap(), BlockHash::ZERO);
        drop(tx);

        let hash = BlockHash::from_bytes([0xcc; 32]);
        let tx = db.tx_mut().unwrap();
        tx.set_best_block(100, &hash).unwrap();
        tx.commit().unwrap();

        let tx = db.tx().unwrap();
        assert_eq!(tx.get_best_block_height().unwrap(), 100);
        assert_eq!(tx.get_best_block_hash().unwrap(), hash);
    }

    #[test]
    fn test_qmdb_height_index() {
        let (_dir, db) = temp_db();
        let hash = BlockHash::from_bytes([0xdd; 32]);

        let tx = db.tx_mut().unwrap();
        tx.put_block_hash_by_height(42, &hash).unwrap();
        tx.commit().unwrap();

        let tx = db.tx().unwrap();
        assert_eq!(tx.get_block_hash_by_height(42).unwrap(), Some(hash));
        assert_eq!(tx.get_block_hash_by_height(43).unwrap(), None);
    }
}
