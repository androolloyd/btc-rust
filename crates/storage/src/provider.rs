use btc_primitives::block::BlockHeader;
use btc_primitives::hash::{BlockHash, TxHash};
use btc_primitives::transaction::{Transaction, TxOut, OutPoint};
use crate::traits::{Database, DbTx, StorageError};

/// High-level provider over raw database operations (reth-style two-tier pattern)
pub struct BlockchainProvider<DB: Database> {
    db: DB,
}

impl<DB: Database> BlockchainProvider<DB> {
    pub fn new(db: DB) -> Self {
        BlockchainProvider { db }
    }

    pub fn header_by_hash(&self, hash: &BlockHash) -> Result<Option<BlockHeader>, StorageError> {
        let tx = self.db.tx()?;
        tx.get_block_header(hash)
    }

    pub fn header_by_height(&self, height: u64) -> Result<Option<BlockHeader>, StorageError> {
        let tx = self.db.tx()?;
        let hash = tx.get_block_hash_by_height(height)?;
        match hash {
            Some(h) => tx.get_block_header(&h),
            None => Ok(None),
        }
    }

    pub fn transaction_by_hash(&self, txid: &TxHash) -> Result<Option<Transaction>, StorageError> {
        let tx = self.db.tx()?;
        tx.get_transaction(txid)
    }

    pub fn utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>, StorageError> {
        let tx = self.db.tx()?;
        tx.get_utxo(outpoint)
    }

    pub fn best_block_height(&self) -> Result<u64, StorageError> {
        let tx = self.db.tx()?;
        tx.get_best_block_height()
    }

    pub fn best_block_hash(&self) -> Result<BlockHash, StorageError> {
        let tx = self.db.tx()?;
        tx.get_best_block_hash()
    }

    pub fn db(&self) -> &DB {
        &self.db
    }
}
