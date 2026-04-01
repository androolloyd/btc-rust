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

/// A transaction's location within the blockchain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxBlockLocation {
    /// The hash of the block containing this transaction.
    pub block_hash: BlockHash,
    /// The position of the transaction within the block (0 = coinbase).
    pub tx_position: u32,
}

/// An entry in the per-address (per-script) index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressIndexValue {
    /// The txid that affected this script.
    pub txid: TxHash,
    /// The block height.
    pub height: u64,
    /// Position of the tx within the block.
    pub tx_position: u32,
    /// Satoshi value: positive for received outputs, negative for spends.
    pub value: i64,
    /// Output index (vout) for receives, or the original output index for spends.
    pub output_index: u32,
}

/// Read-only database transaction
pub trait DbTx: Send + Sync {
    fn get_block_header(&self, hash: &BlockHash) -> Result<Option<BlockHeader>, StorageError>;
    fn get_block_hash_by_height(&self, height: u64) -> Result<Option<BlockHash>, StorageError>;
    fn get_transaction(&self, txid: &TxHash) -> Result<Option<Transaction>, StorageError>;
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>, StorageError>;
    fn get_best_block_height(&self) -> Result<u64, StorageError>;
    fn get_best_block_hash(&self) -> Result<BlockHash, StorageError>;

    /// Look up which block contains a transaction.
    fn get_tx_block_index(&self, txid: &TxHash) -> Result<Option<TxBlockLocation>, StorageError>;

    /// Get all transaction entries for a given script hash (address index).
    fn get_address_txs(&self, script_hash: &[u8; 32]) -> Result<Vec<AddressIndexValue>, StorageError>;
}

/// Read-write database transaction
pub trait DbTxMut: DbTx {
    fn put_block_header(&self, hash: &BlockHash, header: &BlockHeader) -> Result<(), StorageError>;
    fn put_block_hash_by_height(&self, height: u64, hash: &BlockHash) -> Result<(), StorageError>;
    fn put_transaction(&self, txid: &TxHash, tx: &Transaction) -> Result<(), StorageError>;
    fn put_utxo(&self, outpoint: &OutPoint, txout: &TxOut) -> Result<(), StorageError>;
    fn delete_utxo(&self, outpoint: &OutPoint) -> Result<(), StorageError>;
    fn set_best_block(&self, height: u64, hash: &BlockHash) -> Result<(), StorageError>;

    /// Store which block contains a transaction.
    fn put_tx_block_index(
        &self,
        txid: &TxHash,
        block_hash: &BlockHash,
        tx_position: u32,
    ) -> Result<(), StorageError>;

    /// Index a transaction's effect on a script (address).
    fn put_address_tx(
        &self,
        script_hash: &[u8; 32],
        entry: &AddressIndexValue,
    ) -> Result<(), StorageError>;

    fn commit(self) -> Result<(), StorageError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_error_display() {
        let err = StorageError::Database("test db error".into());
        assert_eq!(err.to_string(), "database error: test db error");

        let err = StorageError::NotFound;
        assert_eq!(err.to_string(), "key not found");

        let err = StorageError::Corruption("bad data".into());
        assert_eq!(err.to_string(), "corruption detected: bad data");

        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err = StorageError::Io(io_err);
        assert!(err.to_string().contains("file missing"));
    }

    #[test]
    fn test_storage_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let storage_err: StorageError = io_err.into();
        match storage_err {
            StorageError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
            _ => panic!("expected Io variant"),
        }
    }

    #[test]
    fn test_storage_error_debug() {
        let err = StorageError::Database("debug test".into());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Database"));
        assert!(debug_str.contains("debug test"));
    }
}
