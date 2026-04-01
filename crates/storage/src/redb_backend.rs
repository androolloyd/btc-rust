use std::path::Path;
use std::sync::Arc;

use redb::{ReadableTable, TableDefinition};

use btc_primitives::block::BlockHeader;
use btc_primitives::encode::{decode, encode};
use btc_primitives::hash::{BlockHash, TxHash};
use btc_primitives::transaction::{OutPoint, Transaction, TxOut};

use crate::tables::{
    META_BEST_HASH, META_BEST_HEIGHT, TABLE_BLOCK_INDEX, TABLE_HEADERS, TABLE_META,
    TABLE_TRANSACTIONS, TABLE_UTXOS,
};
use crate::traits::{Database, DbTx, DbTxMut, StorageError};

/// Table definitions for redb.
/// All tables use `&[u8]` keys and `&[u8]` values — serialization is handled
/// in the trait implementations using btc_primitives::encode.
const HEADERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new(TABLE_HEADERS);
const BLOCK_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new(TABLE_BLOCK_INDEX);
const TRANSACTIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new(TABLE_TRANSACTIONS);
const UTXOS: TableDefinition<&[u8], &[u8]> = TableDefinition::new(TABLE_UTXOS);
const META: TableDefinition<&str, &[u8]> = TableDefinition::new(TABLE_META);

/// Concrete redb-backed database implementing the `Database` trait.
pub struct RedbDatabase {
    db: Arc<redb::Database>,
}

impl RedbDatabase {
    /// Open (or create) a database at the given filesystem path.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let db = redb::Database::create(path).map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Create all required tables so that later read-only transactions can open them.
    pub fn init_tables(&self) -> Result<(), StorageError> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        // Opening a table inside a write-transaction creates it if missing.
        write_txn
            .open_table(HEADERS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        write_txn
            .open_table(BLOCK_INDEX)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        write_txn
            .open_table(TRANSACTIONS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        write_txn
            .open_table(UTXOS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        write_txn
            .open_table(META)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        write_txn
            .commit()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }
}

impl Database for RedbDatabase {
    type TX = RedbTx;
    type TXMut = RedbTxMut;

    fn tx(&self) -> Result<Self::TX, StorageError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(RedbTx { inner: read_txn })
    }

    fn tx_mut(&self) -> Result<Self::TXMut, StorageError> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(RedbTxMut { inner: write_txn })
    }
}

// ---------------------------------------------------------------------------
// Key-encoding helpers
// ---------------------------------------------------------------------------

/// Encode a block hash as a 32-byte key.
fn hash_key(hash: &BlockHash) -> [u8; 32] {
    *hash.as_bytes()
}

/// Encode a TxHash as a 32-byte key.
fn txhash_key(hash: &TxHash) -> [u8; 32] {
    *hash.as_bytes()
}

/// Encode a block height as big-endian bytes (for lexicographic ordering).
fn height_key(height: u64) -> [u8; 8] {
    height.to_be_bytes()
}

/// Encode an OutPoint as txid(32) + vout(4 LE) = 36 bytes.
fn outpoint_key(outpoint: &OutPoint) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[..32].copy_from_slice(outpoint.txid.as_bytes());
    key[32..].copy_from_slice(&outpoint.vout.to_le_bytes());
    key
}

// ---------------------------------------------------------------------------
// Read-only transaction
// ---------------------------------------------------------------------------

/// Read-only transaction backed by `redb::ReadTransaction`.
pub struct RedbTx {
    inner: redb::ReadTransaction,
}

// SAFETY: redb::ReadTransaction is Send but not marked Sync in redb's API.
// Our DbTx trait requires Send + Sync.  A ReadTransaction holds an immutable
// snapshot — concurrent `&self` reads are safe because each table-open
// produces its own `ReadOnlyTable` value (not a shared mutable reference).
unsafe impl Sync for RedbTx {}

impl DbTx for RedbTx {
    fn get_block_header(&self, hash: &BlockHash) -> Result<Option<BlockHeader>, StorageError> {
        let table = self
            .inner
            .open_table(HEADERS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let key = hash_key(hash);
        match table
            .get(key.as_slice())
            .map_err(|e| StorageError::Database(e.to_string()))?
        {
            Some(val) => {
                let header: BlockHeader =
                    decode(val.value()).map_err(|e| StorageError::Corruption(e.to_string()))?;
                Ok(Some(header))
            }
            None => Ok(None),
        }
    }

    fn get_block_hash_by_height(&self, height: u64) -> Result<Option<BlockHash>, StorageError> {
        let table = self
            .inner
            .open_table(BLOCK_INDEX)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let key = height_key(height);
        match table
            .get(key.as_slice())
            .map_err(|e| StorageError::Database(e.to_string()))?
        {
            Some(val) => {
                let bytes = val.value();
                if bytes.len() != 32 {
                    return Err(StorageError::Corruption(format!(
                        "block hash has invalid length: {}",
                        bytes.len()
                    )));
                }
                Ok(Some(BlockHash::from_slice(bytes)))
            }
            None => Ok(None),
        }
    }

    fn get_transaction(&self, txid: &TxHash) -> Result<Option<Transaction>, StorageError> {
        let table = self
            .inner
            .open_table(TRANSACTIONS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let key = txhash_key(txid);
        match table
            .get(key.as_slice())
            .map_err(|e| StorageError::Database(e.to_string()))?
        {
            Some(val) => {
                let tx: Transaction =
                    decode(val.value()).map_err(|e| StorageError::Corruption(e.to_string()))?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>, StorageError> {
        let table = self
            .inner
            .open_table(UTXOS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let key = outpoint_key(outpoint);
        match table
            .get(key.as_slice())
            .map_err(|e| StorageError::Database(e.to_string()))?
        {
            Some(val) => {
                let txout: TxOut =
                    decode(val.value()).map_err(|e| StorageError::Corruption(e.to_string()))?;
                Ok(Some(txout))
            }
            None => Ok(None),
        }
    }

    fn get_best_block_height(&self) -> Result<u64, StorageError> {
        let table = self
            .inner
            .open_table(META)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        match table
            .get(META_BEST_HEIGHT)
            .map_err(|e| StorageError::Database(e.to_string()))?
        {
            Some(val) => {
                let bytes = val.value();
                if bytes.len() != 8 {
                    return Err(StorageError::Corruption(format!(
                        "best_height has invalid length: {}",
                        bytes.len()
                    )));
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(bytes);
                Ok(u64::from_be_bytes(buf))
            }
            None => Ok(0),
        }
    }

    fn get_best_block_hash(&self) -> Result<BlockHash, StorageError> {
        let table = self
            .inner
            .open_table(META)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        match table
            .get(META_BEST_HASH)
            .map_err(|e| StorageError::Database(e.to_string()))?
        {
            Some(val) => {
                let bytes = val.value();
                if bytes.len() != 32 {
                    return Err(StorageError::Corruption(format!(
                        "best_hash has invalid length: {}",
                        bytes.len()
                    )));
                }
                Ok(BlockHash::from_slice(bytes))
            }
            None => Ok(BlockHash::ZERO),
        }
    }
}

// ---------------------------------------------------------------------------
// Read-write transaction
// ---------------------------------------------------------------------------

/// Read-write transaction backed by `redb::WriteTransaction`.
pub struct RedbTxMut {
    inner: redb::WriteTransaction,
}

// SAFETY: Same rationale as RedbTx — each table-open produces its own handle.
unsafe impl Sync for RedbTxMut {}

impl DbTx for RedbTxMut {
    fn get_block_header(&self, hash: &BlockHash) -> Result<Option<BlockHeader>, StorageError> {
        let table = self
            .inner
            .open_table(HEADERS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let key = hash_key(hash);
        let guard = table
            .get(key.as_slice())
            .map_err(|e| StorageError::Database(e.to_string()))?;
        match guard {
            Some(val) => {
                let header: BlockHeader =
                    decode(val.value()).map_err(|e| StorageError::Corruption(e.to_string()))?;
                Ok(Some(header))
            }
            None => Ok(None),
        }
    }

    fn get_block_hash_by_height(&self, height: u64) -> Result<Option<BlockHash>, StorageError> {
        let table = self
            .inner
            .open_table(BLOCK_INDEX)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let key = height_key(height);
        let guard = table
            .get(key.as_slice())
            .map_err(|e| StorageError::Database(e.to_string()))?;
        match guard {
            Some(val) => {
                let bytes = val.value();
                if bytes.len() != 32 {
                    return Err(StorageError::Corruption(format!(
                        "block hash has invalid length: {}",
                        bytes.len()
                    )));
                }
                Ok(Some(BlockHash::from_slice(bytes)))
            }
            None => Ok(None),
        }
    }

    fn get_transaction(&self, txid: &TxHash) -> Result<Option<Transaction>, StorageError> {
        let table = self
            .inner
            .open_table(TRANSACTIONS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let key = txhash_key(txid);
        let guard = table
            .get(key.as_slice())
            .map_err(|e| StorageError::Database(e.to_string()))?;
        match guard {
            Some(val) => {
                let tx: Transaction =
                    decode(val.value()).map_err(|e| StorageError::Corruption(e.to_string()))?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>, StorageError> {
        let table = self
            .inner
            .open_table(UTXOS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let key = outpoint_key(outpoint);
        let guard = table
            .get(key.as_slice())
            .map_err(|e| StorageError::Database(e.to_string()))?;
        match guard {
            Some(val) => {
                let txout: TxOut =
                    decode(val.value()).map_err(|e| StorageError::Corruption(e.to_string()))?;
                Ok(Some(txout))
            }
            None => Ok(None),
        }
    }

    fn get_best_block_height(&self) -> Result<u64, StorageError> {
        let table = self
            .inner
            .open_table(META)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let guard = table
            .get(META_BEST_HEIGHT)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        match guard {
            Some(val) => {
                let bytes = val.value();
                if bytes.len() != 8 {
                    return Err(StorageError::Corruption(format!(
                        "best_height has invalid length: {}",
                        bytes.len()
                    )));
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(bytes);
                Ok(u64::from_be_bytes(buf))
            }
            None => Ok(0),
        }
    }

    fn get_best_block_hash(&self) -> Result<BlockHash, StorageError> {
        let table = self
            .inner
            .open_table(META)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let guard = table
            .get(META_BEST_HASH)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        match guard {
            Some(val) => {
                let bytes = val.value();
                if bytes.len() != 32 {
                    return Err(StorageError::Corruption(format!(
                        "best_hash has invalid length: {}",
                        bytes.len()
                    )));
                }
                Ok(BlockHash::from_slice(bytes))
            }
            None => Ok(BlockHash::ZERO),
        }
    }
}

impl DbTxMut for RedbTxMut {
    fn put_block_header(
        &self,
        hash: &BlockHash,
        header: &BlockHeader,
    ) -> Result<(), StorageError> {
        let mut table = self
            .inner
            .open_table(HEADERS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let key = hash_key(hash);
        let value = encode(header);
        table
            .insert(key.as_slice(), value.as_slice())
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    fn put_block_hash_by_height(
        &self,
        height: u64,
        hash: &BlockHash,
    ) -> Result<(), StorageError> {
        let mut table = self
            .inner
            .open_table(BLOCK_INDEX)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let key = height_key(height);
        table
            .insert(key.as_slice(), hash.as_bytes().as_slice())
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    fn put_transaction(&self, txid: &TxHash, tx: &Transaction) -> Result<(), StorageError> {
        let mut table = self
            .inner
            .open_table(TRANSACTIONS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let key = txhash_key(txid);
        let value = encode(tx);
        table
            .insert(key.as_slice(), value.as_slice())
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    fn put_utxo(&self, outpoint: &OutPoint, txout: &TxOut) -> Result<(), StorageError> {
        let mut table = self
            .inner
            .open_table(UTXOS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let key = outpoint_key(outpoint);
        let value = encode(txout);
        table
            .insert(key.as_slice(), value.as_slice())
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    fn delete_utxo(&self, outpoint: &OutPoint) -> Result<(), StorageError> {
        let mut table = self
            .inner
            .open_table(UTXOS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let key = outpoint_key(outpoint);
        table
            .remove(key.as_slice())
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    fn set_best_block(&self, height: u64, hash: &BlockHash) -> Result<(), StorageError> {
        let mut table = self
            .inner
            .open_table(META)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        table
            .insert(META_BEST_HEIGHT, height.to_be_bytes().as_slice())
            .map_err(|e| StorageError::Database(e.to_string()))?;
        table
            .insert(META_BEST_HASH, hash.as_bytes().as_slice())
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    fn commit(self) -> Result<(), StorageError> {
        self.inner
            .commit()
            .map_err(|e| StorageError::Database(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::amount::Amount;
    use btc_primitives::compact::CompactTarget;
    use btc_primitives::script::ScriptBuf;

    /// Helper: create a temporary database, with tables initialized.
    fn temp_db() -> (RedbDatabase, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let db_path = dir.path().join("test.redb");
        let db = RedbDatabase::new(&db_path).expect("failed to create db");
        db.init_tables().expect("failed to init tables");
        (db, dir)
    }

    /// Helper: build a simple test block header.
    fn test_header() -> BlockHeader {
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
    fn test_block_header_roundtrip() {
        let (db, _dir) = temp_db();
        let header = test_header();
        let hash = header.block_hash();

        // Write
        {
            let tx = db.tx_mut().unwrap();
            tx.put_block_header(&hash, &header).unwrap();
            tx.commit().unwrap();
        }

        // Read back
        {
            let tx = db.tx().unwrap();
            let loaded = tx.get_block_header(&hash).unwrap();
            assert_eq!(loaded, Some(header));
        }
    }

    #[test]
    fn test_block_header_missing() {
        let (db, _dir) = temp_db();
        let tx = db.tx().unwrap();
        let missing = tx
            .get_block_header(&BlockHash::from_bytes([0xff; 32]))
            .unwrap();
        assert_eq!(missing, None);
    }

    #[test]
    fn test_utxo_insert_and_delete() {
        let (db, _dir) = temp_db();

        let outpoint = OutPoint::new(TxHash::from_bytes([0x01; 32]), 0);
        let txout = TxOut {
            value: Amount::from_sat(50_000_000),
            script_pubkey: ScriptBuf::p2pkh(&[0xaa; 20]),
        };

        // Insert
        {
            let tx = db.tx_mut().unwrap();
            tx.put_utxo(&outpoint, &txout).unwrap();
            tx.commit().unwrap();
        }

        // Verify present
        {
            let tx = db.tx().unwrap();
            let loaded = tx.get_utxo(&outpoint).unwrap();
            assert_eq!(loaded, Some(txout.clone()));
        }

        // Delete
        {
            let tx = db.tx_mut().unwrap();
            tx.delete_utxo(&outpoint).unwrap();
            tx.commit().unwrap();
        }

        // Verify gone
        {
            let tx = db.tx().unwrap();
            let loaded = tx.get_utxo(&outpoint).unwrap();
            assert_eq!(loaded, None);
        }
    }

    #[test]
    fn test_best_block_set_and_get() {
        let (db, _dir) = temp_db();

        // Defaults before anything is set
        {
            let tx = db.tx().unwrap();
            assert_eq!(tx.get_best_block_height().unwrap(), 0);
            assert_eq!(tx.get_best_block_hash().unwrap(), BlockHash::ZERO);
        }

        let height = 840_000u64;
        let hash = BlockHash::from_bytes([0x42; 32]);

        {
            let tx = db.tx_mut().unwrap();
            tx.set_best_block(height, &hash).unwrap();
            tx.commit().unwrap();
        }

        {
            let tx = db.tx().unwrap();
            assert_eq!(tx.get_best_block_height().unwrap(), height);
            assert_eq!(tx.get_best_block_hash().unwrap(), hash);
        }
    }

    #[test]
    fn test_block_hash_by_height() {
        let (db, _dir) = temp_db();

        let height = 100u64;
        let hash = BlockHash::from_bytes([0xde; 32]);

        {
            let tx = db.tx_mut().unwrap();
            tx.put_block_hash_by_height(height, &hash).unwrap();
            tx.commit().unwrap();
        }

        {
            let tx = db.tx().unwrap();
            assert_eq!(tx.get_block_hash_by_height(height).unwrap(), Some(hash));
            assert_eq!(tx.get_block_hash_by_height(999).unwrap(), None);
        }
    }

    #[test]
    fn test_transaction_roundtrip() {
        let (db, _dir) = temp_db();

        let transaction = Transaction {
            version: 1,
            inputs: vec![btc_primitives::transaction::TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0xff, 0xff, 0x00, 0x1d]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::p2pkh(&[0xaa; 20]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        let txid = transaction.txid();

        {
            let tx = db.tx_mut().unwrap();
            tx.put_transaction(&txid, &transaction).unwrap();
            tx.commit().unwrap();
        }

        {
            let tx = db.tx().unwrap();
            let loaded = tx.get_transaction(&txid).unwrap();
            assert_eq!(loaded, Some(transaction));
        }
    }

    #[test]
    fn test_provider_integration() {
        use crate::provider::BlockchainProvider;

        let (db, _dir) = temp_db();
        let header = test_header();
        let hash = header.block_hash();

        // Store header + index
        {
            let tx = db.tx_mut().unwrap();
            tx.put_block_header(&hash, &header).unwrap();
            tx.put_block_hash_by_height(0, &hash).unwrap();
            tx.set_best_block(0, &hash).unwrap();
            tx.commit().unwrap();
        }

        let provider = BlockchainProvider::new(db);
        assert_eq!(provider.header_by_hash(&hash).unwrap(), Some(header));
        assert_eq!(provider.header_by_height(0).unwrap(), Some(header));
        assert_eq!(provider.best_block_height().unwrap(), 0);
        assert_eq!(provider.best_block_hash().unwrap(), hash);
    }

    // -----------------------------------------------------------------------
    // RedbTxMut also implements DbTx — test read-through-write-tx
    // -----------------------------------------------------------------------

    #[test]
    fn test_read_through_write_tx_block_header() {
        let (db, _dir) = temp_db();
        let header = test_header();
        let hash = header.block_hash();

        let tx = db.tx_mut().unwrap();
        tx.put_block_header(&hash, &header).unwrap();

        // Read back via the same write transaction (DbTx on RedbTxMut).
        let loaded = tx.get_block_header(&hash).unwrap();
        assert_eq!(loaded, Some(header));

        // Missing header via write tx.
        let missing = tx
            .get_block_header(&BlockHash::from_bytes([0xee; 32]))
            .unwrap();
        assert_eq!(missing, None);

        tx.commit().unwrap();
    }

    #[test]
    fn test_read_through_write_tx_utxo() {
        let (db, _dir) = temp_db();
        let outpoint = OutPoint::new(TxHash::from_bytes([0x02; 32]), 1);
        let txout = TxOut {
            value: Amount::from_sat(1_000_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };

        let tx = db.tx_mut().unwrap();
        tx.put_utxo(&outpoint, &txout).unwrap();

        // Read via same write tx.
        let loaded = tx.get_utxo(&outpoint).unwrap();
        assert_eq!(loaded, Some(txout.clone()));

        // Missing UTXO.
        let missing_op = OutPoint::new(TxHash::from_bytes([0xff; 32]), 99);
        assert_eq!(tx.get_utxo(&missing_op).unwrap(), None);

        tx.commit().unwrap();
    }

    #[test]
    fn test_read_through_write_tx_transaction() {
        let (db, _dir) = temp_db();
        let transaction = Transaction {
            version: 2,
            inputs: vec![btc_primitives::transaction::TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x00]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        let txid = transaction.txid();

        let tx = db.tx_mut().unwrap();
        tx.put_transaction(&txid, &transaction).unwrap();

        // Read via same write tx.
        let loaded = tx.get_transaction(&txid).unwrap();
        assert_eq!(loaded, Some(transaction));

        // Missing txid.
        let missing = tx
            .get_transaction(&TxHash::from_bytes([0xee; 32]))
            .unwrap();
        assert_eq!(missing, None);

        tx.commit().unwrap();
    }

    #[test]
    fn test_read_through_write_tx_block_hash_by_height() {
        let (db, _dir) = temp_db();
        let hash = BlockHash::from_bytes([0xab; 32]);

        let tx = db.tx_mut().unwrap();
        tx.put_block_hash_by_height(42, &hash).unwrap();

        // Read via same write tx.
        assert_eq!(tx.get_block_hash_by_height(42).unwrap(), Some(hash));
        assert_eq!(tx.get_block_hash_by_height(999).unwrap(), None);

        tx.commit().unwrap();
    }

    #[test]
    fn test_read_through_write_tx_best_block() {
        let (db, _dir) = temp_db();
        let hash = BlockHash::from_bytes([0xcc; 32]);

        let tx = db.tx_mut().unwrap();

        // Defaults before anything is set.
        assert_eq!(tx.get_best_block_height().unwrap(), 0);
        assert_eq!(tx.get_best_block_hash().unwrap(), BlockHash::ZERO);

        tx.set_best_block(500, &hash).unwrap();

        // Read via same write tx after set.
        assert_eq!(tx.get_best_block_height().unwrap(), 500);
        assert_eq!(tx.get_best_block_hash().unwrap(), hash);

        tx.commit().unwrap();
    }

    // -----------------------------------------------------------------------
    // Delete UTXO via write tx
    // -----------------------------------------------------------------------

    #[test]
    fn test_delete_utxo_via_write_tx() {
        let (db, _dir) = temp_db();
        let outpoint = OutPoint::new(TxHash::from_bytes([0x05; 32]), 0);
        let txout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
        };

        // Insert.
        {
            let tx = db.tx_mut().unwrap();
            tx.put_utxo(&outpoint, &txout).unwrap();
            tx.commit().unwrap();
        }

        // Delete and verify within same write tx.
        {
            let tx = db.tx_mut().unwrap();
            let before = tx.get_utxo(&outpoint).unwrap();
            assert!(before.is_some());
            tx.delete_utxo(&outpoint).unwrap();
            // After delete, redb write tx should not find it.
            let after = tx.get_utxo(&outpoint).unwrap();
            assert!(after.is_none());
            tx.commit().unwrap();
        }

        // Verify via read tx.
        {
            let tx = db.tx().unwrap();
            assert!(tx.get_utxo(&outpoint).unwrap().is_none());
        }
    }

    // -----------------------------------------------------------------------
    // Transaction missing returns None
    // -----------------------------------------------------------------------

    #[test]
    fn test_transaction_missing() {
        let (db, _dir) = temp_db();
        let tx = db.tx().unwrap();
        let missing = tx
            .get_transaction(&TxHash::from_bytes([0xfe; 32]))
            .unwrap();
        assert_eq!(missing, None);
    }

    // -----------------------------------------------------------------------
    // UTXO missing returns None
    // -----------------------------------------------------------------------

    #[test]
    fn test_utxo_missing() {
        let (db, _dir) = temp_db();
        let tx = db.tx().unwrap();
        let outpoint = OutPoint::new(TxHash::from_bytes([0xfe; 32]), 0);
        assert_eq!(tx.get_utxo(&outpoint).unwrap(), None);
    }

    // -----------------------------------------------------------------------
    // Key encoding helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_hash_key_encoding() {
        let hash = BlockHash::from_bytes([0xab; 32]);
        let key = hash_key(&hash);
        assert_eq!(key, [0xab; 32]);
    }

    #[test]
    fn test_txhash_key_encoding() {
        let hash = TxHash::from_bytes([0xcd; 32]);
        let key = txhash_key(&hash);
        assert_eq!(key, [0xcd; 32]);
    }

    #[test]
    fn test_height_key_encoding() {
        let key = height_key(256);
        assert_eq!(key, 256u64.to_be_bytes());
        // Big-endian: 0 should sort before 1.
        assert!(height_key(0) < height_key(1));
        assert!(height_key(100) < height_key(200));
    }

    #[test]
    fn test_outpoint_key_encoding() {
        let outpoint = OutPoint::new(TxHash::from_bytes([0x11; 32]), 42);
        let key = outpoint_key(&outpoint);
        assert_eq!(key.len(), 36);
        assert_eq!(&key[..32], &[0x11; 32]);
        assert_eq!(&key[32..], &42u32.to_le_bytes());
    }

    // -----------------------------------------------------------------------
    // Multiple block headers
    // -----------------------------------------------------------------------

    #[test]
    fn test_multiple_headers() {
        let (db, _dir) = temp_db();
        let header1 = test_header();
        let hash1 = header1.block_hash();

        let header2 = BlockHeader {
            version: 2,
            prev_blockhash: hash1,
            merkle_root: TxHash::from_bytes([0xcd; 32]),
            time: 1231006506,
            bits: CompactTarget::MAX_TARGET,
            nonce: 12345,
        };
        let hash2 = header2.block_hash();

        {
            let tx = db.tx_mut().unwrap();
            tx.put_block_header(&hash1, &header1).unwrap();
            tx.put_block_header(&hash2, &header2).unwrap();
            tx.commit().unwrap();
        }

        {
            let tx = db.tx().unwrap();
            assert_eq!(tx.get_block_header(&hash1).unwrap(), Some(header1));
            assert_eq!(tx.get_block_header(&hash2).unwrap(), Some(header2));
        }
    }

    // -----------------------------------------------------------------------
    // Overwrite existing entry
    // -----------------------------------------------------------------------

    #[test]
    fn test_overwrite_utxo() {
        let (db, _dir) = temp_db();
        let outpoint = OutPoint::new(TxHash::from_bytes([0x07; 32]), 0);
        let txout1 = TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        let txout2 = TxOut {
            value: Amount::from_sat(2_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
        };

        {
            let tx = db.tx_mut().unwrap();
            tx.put_utxo(&outpoint, &txout1).unwrap();
            tx.commit().unwrap();
        }
        {
            let tx = db.tx_mut().unwrap();
            tx.put_utxo(&outpoint, &txout2).unwrap();
            tx.commit().unwrap();
        }
        {
            let tx = db.tx().unwrap();
            let loaded = tx.get_utxo(&outpoint).unwrap().unwrap();
            assert_eq!(loaded.value.as_sat(), 2_000);
        }
    }

    // -----------------------------------------------------------------------
    // Overwrite best block
    // -----------------------------------------------------------------------

    #[test]
    fn test_overwrite_best_block() {
        let (db, _dir) = temp_db();
        let hash1 = BlockHash::from_bytes([0x11; 32]);
        let hash2 = BlockHash::from_bytes([0x22; 32]);

        {
            let tx = db.tx_mut().unwrap();
            tx.set_best_block(1, &hash1).unwrap();
            tx.commit().unwrap();
        }
        {
            let tx = db.tx_mut().unwrap();
            tx.set_best_block(2, &hash2).unwrap();
            tx.commit().unwrap();
        }
        {
            let tx = db.tx().unwrap();
            assert_eq!(tx.get_best_block_height().unwrap(), 2);
            assert_eq!(tx.get_best_block_hash().unwrap(), hash2);
        }
    }

    // -----------------------------------------------------------------------
    // Provider: missing entries
    // -----------------------------------------------------------------------

    #[test]
    fn test_provider_missing_entries() {
        use crate::provider::BlockchainProvider;

        let (db, _dir) = temp_db();
        let provider = BlockchainProvider::new(db);

        assert_eq!(
            provider
                .header_by_hash(&BlockHash::from_bytes([0xff; 32]))
                .unwrap(),
            None
        );
        assert_eq!(provider.header_by_height(999).unwrap(), None);
        assert_eq!(
            provider
                .transaction_by_hash(&TxHash::from_bytes([0xff; 32]))
                .unwrap(),
            None
        );
        let op = OutPoint::new(TxHash::from_bytes([0xff; 32]), 0);
        assert_eq!(provider.utxo(&op).unwrap(), None);
        assert_eq!(provider.best_block_height().unwrap(), 0);
        assert_eq!(provider.best_block_hash().unwrap(), BlockHash::ZERO);
    }

    // -----------------------------------------------------------------------
    // Provider: db() accessor
    // -----------------------------------------------------------------------

    #[test]
    fn test_provider_db_accessor() {
        use crate::provider::BlockchainProvider;

        let (db, _dir) = temp_db();
        let provider = BlockchainProvider::new(db);

        // Just verify we can call db() and use it.
        let _tx = provider.db().tx().unwrap();
    }

    // -----------------------------------------------------------------------
    // Provider: transaction by hash
    // -----------------------------------------------------------------------

    #[test]
    fn test_provider_transaction_by_hash() {
        use crate::provider::BlockchainProvider;

        let (db, _dir) = temp_db();
        let transaction = Transaction {
            version: 1,
            inputs: vec![btc_primitives::transaction::TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        let txid = transaction.txid();

        {
            let tx = db.tx_mut().unwrap();
            tx.put_transaction(&txid, &transaction).unwrap();
            tx.commit().unwrap();
        }

        let provider = BlockchainProvider::new(db);
        assert_eq!(
            provider.transaction_by_hash(&txid).unwrap(),
            Some(transaction)
        );
    }

    // -----------------------------------------------------------------------
    // Provider: utxo lookup
    // -----------------------------------------------------------------------

    #[test]
    fn test_provider_utxo_lookup() {
        use crate::provider::BlockchainProvider;

        let (db, _dir) = temp_db();
        let outpoint = OutPoint::new(TxHash::from_bytes([0x09; 32]), 0);
        let txout = TxOut {
            value: Amount::from_sat(500),
            script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
        };

        {
            let tx = db.tx_mut().unwrap();
            tx.put_utxo(&outpoint, &txout).unwrap();
            tx.commit().unwrap();
        }

        let provider = BlockchainProvider::new(db);
        assert_eq!(provider.utxo(&outpoint).unwrap(), Some(txout));
    }
}
