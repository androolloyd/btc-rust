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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redb_backend::RedbDatabase;
    use btc_primitives::amount::Amount;
    use btc_primitives::block::BlockHeader;
    use btc_primitives::compact::CompactTarget;
    use btc_primitives::script::ScriptBuf;
    use btc_primitives::transaction::{OutPoint, TxOut, Transaction, TxIn};
    use crate::traits::DbTxMut;

    fn temp_provider() -> (BlockchainProvider<RedbDatabase>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("provider_test.redb");
        let db = RedbDatabase::new(&db_path).unwrap();
        db.init_tables().unwrap();
        (BlockchainProvider::new(db), dir)
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
    fn test_provider_header_by_hash() {
        let (provider, _dir) = temp_provider();
        let header = sample_header();
        let hash = header.block_hash();

        {
            let tx = provider.db().tx_mut().unwrap();
            tx.put_block_header(&hash, &header).unwrap();
            tx.commit().unwrap();
        }

        assert_eq!(provider.header_by_hash(&hash).unwrap(), Some(header));
        assert_eq!(
            provider
                .header_by_hash(&BlockHash::from_bytes([0xff; 32]))
                .unwrap(),
            None
        );
    }

    #[test]
    fn test_provider_header_by_height_found() {
        let (provider, _dir) = temp_provider();
        let header = sample_header();
        let hash = header.block_hash();

        {
            let tx = provider.db().tx_mut().unwrap();
            tx.put_block_header(&hash, &header).unwrap();
            tx.put_block_hash_by_height(0, &hash).unwrap();
            tx.commit().unwrap();
        }

        assert_eq!(provider.header_by_height(0).unwrap(), Some(header));
    }

    #[test]
    fn test_provider_header_by_height_not_found() {
        let (provider, _dir) = temp_provider();
        assert_eq!(provider.header_by_height(999).unwrap(), None);
    }

    #[test]
    fn test_provider_transaction_by_hash() {
        let (provider, _dir) = temp_provider();
        let transaction = Transaction {
            version: 1,
            inputs: vec![TxIn {
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
            let tx = provider.db().tx_mut().unwrap();
            tx.put_transaction(&txid, &transaction).unwrap();
            tx.commit().unwrap();
        }

        assert_eq!(
            provider.transaction_by_hash(&txid).unwrap(),
            Some(transaction)
        );
    }

    #[test]
    fn test_provider_utxo() {
        let (provider, _dir) = temp_provider();
        let outpoint = OutPoint::new(TxHash::from_bytes([0x01; 32]), 0);
        let txout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
        };

        {
            let tx = provider.db().tx_mut().unwrap();
            tx.put_utxo(&outpoint, &txout).unwrap();
            tx.commit().unwrap();
        }

        assert_eq!(provider.utxo(&outpoint).unwrap(), Some(txout));
    }

    #[test]
    fn test_provider_best_block() {
        let (provider, _dir) = temp_provider();
        let hash = BlockHash::from_bytes([0xcc; 32]);

        // Defaults.
        assert_eq!(provider.best_block_height().unwrap(), 0);
        assert_eq!(provider.best_block_hash().unwrap(), BlockHash::ZERO);

        {
            let tx = provider.db().tx_mut().unwrap();
            tx.set_best_block(100, &hash).unwrap();
            tx.commit().unwrap();
        }

        assert_eq!(provider.best_block_height().unwrap(), 100);
        assert_eq!(provider.best_block_hash().unwrap(), hash);
    }

    #[test]
    fn test_provider_db_returns_ref() {
        let (provider, _dir) = temp_provider();
        let db = provider.db();
        let tx = db.tx().unwrap();
        assert_eq!(tx.get_best_block_height().unwrap(), 0);
    }
}
