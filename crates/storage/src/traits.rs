use btc_primitives::block::BlockHeader;
use btc_primitives::hash::{BlockHash, TxHash};
use btc_primitives::transaction::{Transaction, TxOut, OutPoint};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(String),
    #[error("key not found")]
    NotFound,
    #[error("corruption detected: {0}")]
    Corruption(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Reth-style Database trait — abstraction over storage backends
pub trait Database: Send + Sync + 'static {
    /// Read-only transaction type
    type TX: DbTx;
    /// Read-write transaction type
    type TXMut: DbTxMut;

    /// Create a read-only transaction
    fn tx(&self) -> Result<Self::TX, StorageError>;

    /// Create a read-write transaction
    fn tx_mut(&self) -> Result<Self::TXMut, StorageError>;
}

/// Read-only database transaction
pub trait DbTx: Send + Sync {
    fn get_block_header(&self, hash: &BlockHash) -> Result<Option<BlockHeader>, StorageError>;
    fn get_block_hash_by_height(&self, height: u64) -> Result<Option<BlockHash>, StorageError>;
    fn get_transaction(&self, txid: &TxHash) -> Result<Option<Transaction>, StorageError>;
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>, StorageError>;
    fn get_best_block_height(&self) -> Result<u64, StorageError>;
    fn get_best_block_hash(&self) -> Result<BlockHash, StorageError>;
}

/// Read-write database transaction
pub trait DbTxMut: DbTx {
    fn put_block_header(&self, hash: &BlockHash, header: &BlockHeader) -> Result<(), StorageError>;
    fn put_block_hash_by_height(&self, height: u64, hash: &BlockHash) -> Result<(), StorageError>;
    fn put_transaction(&self, txid: &TxHash, tx: &Transaction) -> Result<(), StorageError>;
    fn put_utxo(&self, outpoint: &OutPoint, txout: &TxOut) -> Result<(), StorageError>;
    fn delete_utxo(&self, outpoint: &OutPoint) -> Result<(), StorageError>;
    fn set_best_block(&self, height: u64, hash: &BlockHash) -> Result<(), StorageError>;
    fn commit(self) -> Result<(), StorageError>;
}
