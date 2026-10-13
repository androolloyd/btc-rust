//! Preserve unverified tip-only databases before ordinary genesis-based resync.
//! Table renames and fresh genesis initialization share one durable transaction;
//! no coin, index, pool entry or height from the archive becomes authoritative.

use super::*;
use redb::{ReadableTableMetadata, TableHandle};

const PREFIX: &str = "LegacyCheckpointV1.";
const RECORD: TableDefinition<&str, &[u8]> = TableDefinition::new("LegacyCheckpointResyncV1");
const BYTE_TABLES: [TableDefinition<&[u8], &[u8]>; 13] = [
    UNDO,
    MEMPOOL,
    HEADERS,
    BLOCKS,
    BLOCK_INDEX,
    TRANSACTIONS,
    UTXOS,
    TX_BLOCK_INDEX,
    ADDRESS_INDEX,
    script_index::HISTORY,
    script_index::MANIFEST,
    exex_journal::EVENTS,
    exex_journal::STATES,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyCheckpointArchive {
    /// Unverified original checkpoint; never used to select or validate a tip.
    pub height: u64,
    pub hash: BlockHash,
    /// The selected network's genesis at which fresh validation began.
    pub genesis: BlockHash,
}

fn error(e: impl std::fmt::Display) -> StorageError {
    StorageError::Database(e.to_string())
}

impl RedbDatabase {
    /// Read the durable recovery receipt. Original raw tables remain in this DB.
    pub fn legacy_checkpoint_archive(
        &self,
    ) -> Result<Option<LegacyCheckpointArchive>, StorageError> {
        let reader = self.db.begin_read().map_err(error)?;
        if !reader
            .list_tables()
            .map_err(error)?
            .any(|t| t.name() == RECORD.name())
        {
            return Ok(None);
        }
        let record = reader.open_table(RECORD).map_err(error)?;
        let genesis = record
            .get("genesis")
            .map_err(error)?
            .ok_or_else(|| StorageError::Corruption("missing resync genesis".into()))?;
        if genesis.value().len() != 32 {
            return Err(StorageError::Corruption("invalid resync genesis".into()));
        }
        let name = format!("{PREFIX}{}", META.name());
        let meta = reader
            .open_table(TableDefinition::<&str, &[u8]>::new(&name))
            .map_err(error)?;
        let height = meta
            .get(META_BEST_HEIGHT)
            .map_err(error)?
            .ok_or_else(|| StorageError::Corruption("missing archived height".into()))?;
        let hash = meta
            .get(META_BEST_HASH)
            .map_err(error)?
            .ok_or_else(|| StorageError::Corruption("missing archived hash".into()))?;
        let height: [u8; 8] = height
            .value()
            .try_into()
            .map_err(|_| StorageError::Corruption("invalid archived height".into()))?;
        if hash.value().len() != 32 {
            return Err(StorageError::Corruption("invalid archived hash".into()));
        }
        Ok(Some(LegacyCheckpointArchive {
            height: u64::from_be_bytes(height),
            hash: BlockHash::from_slice(hash.value()),
            genesis: BlockHash::from_slice(genesis.value()),
        }))
    }

    /// Explicit recovery of a tip-only checkpoint. Healthy history databases
    /// and already recovered databases are left alone. Partial histories are
    /// not classified as legacy checkpoints and still fail ordinary startup.
    /// This must run before any UTXO caches or runtime readers are created.
    pub fn resync_legacy_checkpoint(
        &self,
        genesis: &BlockHeader,
    ) -> Result<Option<LegacyCheckpointArchive>, StorageError> {
        self.resync_legacy_checkpoint_inner(genesis, || Ok(()))
    }

    fn resync_legacy_checkpoint_inner(
        &self,
        genesis: &BlockHeader,
        mut checkpoint: impl FnMut() -> Result<(), StorageError>,
    ) -> Result<Option<LegacyCheckpointArchive>, StorageError> {
        if let Some(archive) = self.legacy_checkpoint_archive()? {
            if archive.genesis != genesis.block_hash() {
                return Err(StorageError::Corruption(
                    "resync archive belongs to another network".into(),
                ));
            }
            return Ok(None);
        }
        let write = self.tx_mut()?;
        let height = write.get_best_block_height()?;
        let hash = write.get_best_block_hash()?;
        if height == 0 || hash == BlockHash::ZERO {
            return Ok(None);
        }
        // Any non-genesis history belongs to the normal verifier, even if it
        // is incomplete/corrupt. Never silently turn a damaged chain into resync.
        {
            let headers = write.inner.open_table(HEADERS).map_err(error)?;
            for row in headers.iter().map_err(error)? {
                let (key, value) = row.map_err(error)?;
                if key.value() != genesis.block_hash().as_bytes()
                    || value.value() != encode(genesis)
                {
                    return Ok(None);
                }
            }
            let index = write.inner.open_table(BLOCK_INDEX).map_err(error)?;
            for row in index.iter().map_err(error)? {
                let (key, value) = row.map_err(error)?;
                if key.value() != height_key(0) || value.value() != genesis.block_hash().as_bytes()
                {
                    return Ok(None);
                }
            }
            for table in [BLOCKS, UNDO] {
                if !write
                    .inner
                    .open_table(table)
                    .map_err(error)?
                    .is_empty()
                    .map_err(error)?
                {
                    return Ok(None);
                }
            }
        }
        // Protect even an incomplete pre-existing archive from overwriting.
        if write
            .inner
            .list_tables()
            .map_err(error)?
            .any(|table| table.name().starts_with(PREFIX))
        {
            return Err(StorageError::Corruption(
                "existing legacy checkpoint archive without receipt".into(),
            ));
        }
        let archive = LegacyCheckpointArchive {
            height,
            hash,
            genesis: genesis.block_hash(),
        };
        checkpoint()?;
        for table in BYTE_TABLES {
            let name = format!("{PREFIX}{}", table.name());
            write
                .inner
                .rename_table(table, TableDefinition::<&[u8], &[u8]>::new(&name))
                .map_err(error)?;
            checkpoint()?;
            write.inner.open_table(table).map_err(error)?;
            checkpoint()?;
        }
        let name = format!("{PREFIX}{}", META.name());
        write
            .inner
            .rename_table(META, TableDefinition::<&str, &[u8]>::new(&name))
            .map_err(error)?;
        checkpoint()?;
        write.inner.open_table(META).map_err(error)?;
        checkpoint()?;
        write.put_block_header(&genesis.block_hash(), genesis)?;
        write.put_block_hash_by_height(0, &genesis.block_hash())?;
        write.set_best_block(0, &genesis.block_hash())?;
        {
            let mut receipt = write.inner.open_table(RECORD).map_err(error)?;
            receipt
                .insert("genesis", genesis.block_hash().as_bytes().as_slice())
                .map_err(error)?;
        }
        checkpoint()?;
        write.commit()?;
        Ok(Some(archive))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::{amount::Amount, network::Network, script::ScriptBuf};

    fn genesis() -> BlockHeader {
        btc_consensus::ChainState::new(btc_consensus::validation::ChainParams::from_network(
            Network::Regtest,
        ))
        .best_header()
        .header
    }

    fn fixture(path: &Path) -> RedbDatabase {
        let db = RedbDatabase::new(path).unwrap();
        db.init_tables().unwrap();
        let write = db.tx_mut().unwrap();
        write
            .set_best_block(42, &BlockHash::from_bytes([42; 32]))
            .unwrap();
        // Preserve raw coins, companion metadata, obsolete indices and unknown
        // values without interpreting or inventing a validation claim for them.
        for table in BYTE_TABLES {
            write.inner.open_table(table).unwrap();
        }
        write
            .put_utxo(
                &OutPoint {
                    txid: TxHash::from_bytes([7; 32]),
                    vout: 0,
                },
                &TxOut {
                    value: Amount::from_sat(123),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
            )
            .unwrap();
        write
            .inner
            .open_table(UTXOS)
            .unwrap()
            .insert([3; 36].as_slice(), [0xff, 0xfe].as_slice())
            .unwrap();
        write
            .inner
            .open_table(MEMPOOL)
            .unwrap()
            .insert([4; 32].as_slice(), [0xff].as_slice())
            .unwrap();
        write
            .inner
            .open_table(TRANSACTIONS)
            .unwrap()
            .insert([5; 32].as_slice(), [0xaa].as_slice())
            .unwrap();
        write
            .inner
            .open_table(TX_BLOCK_INDEX)
            .unwrap()
            .insert([6; 32].as_slice(), [0xbb].as_slice())
            .unwrap();
        write
            .inner
            .open_table(ADDRESS_INDEX)
            .unwrap()
            .insert([8; 48].as_slice(), [0xcc].as_slice())
            .unwrap();
        // Unverified journal/state bytes must also survive archival unchanged,
        // without being decoded or becoming fresh validated consumer progress.
        for table in [exex_journal::EVENTS, exex_journal::STATES] {
            write
                .inner
                .open_table(table)
                .unwrap()
                .insert(b"unverified-exex".as_slice(), [0xdd, 0xee].as_slice())
                .unwrap();
        }
        write
            .put_block_header(&genesis().block_hash(), &genesis())
            .unwrap();
        write
            .put_block_hash_by_height(0, &genesis().block_hash())
            .unwrap();
        write.commit().unwrap();
        db
    }

    fn raw_tables(db: &RedbDatabase, prefix: &str) -> Vec<Vec<(Vec<u8>, Vec<u8>)>> {
        let read = db.db.begin_read().unwrap();
        let mut rows = Vec::new();
        for table in BYTE_TABLES {
            let name = format!("{prefix}{}", table.name());
            rows.push(
                read.open_table(TableDefinition::<&[u8], &[u8]>::new(&name))
                    .unwrap()
                    .iter()
                    .unwrap()
                    .map(|row| {
                        let (key, value) = row.unwrap();
                        (key.value().to_vec(), value.value().to_vec())
                    })
                    .collect(),
            );
        }
        let name = format!("{prefix}{}", META.name());
        rows.push(
            read.open_table(TableDefinition::<&str, &[u8]>::new(&name))
                .unwrap()
                .iter()
                .unwrap()
                .map(|row| {
                    let (key, value) = row.unwrap();
                    (key.value().as_bytes().to_vec(), value.value().to_vec())
                })
                .collect(),
        );
        rows
    }

    #[test]
    fn every_staged_recovery_failure_preserves_all_raw_tables_on_restart() {
        // before renames, each rename/recreation, and before the single commit.
        for fail_at in 0..(2 * BYTE_TABLES.len() + 4) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("legacy.redb");
            let db = fixture(&path);
            let original = raw_tables(&db, "");
            let mut stage = 0;
            assert!(db
                .resync_legacy_checkpoint_inner(&genesis(), || {
                    let fail = stage == fail_at;
                    stage += 1;
                    if fail {
                        Err(error("injected migration failure"))
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            assert_eq!(raw_tables(&db, ""), original);
            drop(db);
            let db = RedbDatabase::new(&path).unwrap();
            assert_eq!(raw_tables(&db, ""), original);
            assert!(db.legacy_checkpoint_archive().unwrap().is_none());
            let receipt = db.resync_legacy_checkpoint(&genesis()).unwrap().unwrap();
            assert_eq!(receipt.height, 42);
            assert_eq!(raw_tables(&db, PREFIX), original);
            assert_eq!(db.coin_count().unwrap(), 0);
            assert!(db.mempool_transactions().unwrap().is_empty());
            assert_eq!(
                db.tx().unwrap().get_best_block_hash().unwrap(),
                genesis().block_hash()
            );
            drop(db);
            let db = RedbDatabase::new(&path).unwrap();
            assert_eq!(db.legacy_checkpoint_archive().unwrap(), Some(receipt));
            assert!(db.resync_legacy_checkpoint(&genesis()).unwrap().is_none());
            assert_eq!(raw_tables(&db, PREFIX), original);
        }
    }

    #[test]
    fn history_and_archive_collisions_are_never_reset() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(&dir.path().join("legacy.redb"));
        let write = db.tx_mut().unwrap();
        write
            .put_block_hash_by_height(1, &BlockHash::from_bytes([1; 32]))
            .unwrap();
        write.commit().unwrap();
        let original = raw_tables(&db, "");
        assert!(db.resync_legacy_checkpoint(&genesis()).unwrap().is_none());
        assert_eq!(raw_tables(&db, ""), original);
        let write = db.tx_mut().unwrap();
        write.delete_block_hash_by_height(1).unwrap();
        write
            .inner
            .open_table(TableDefinition::<&[u8], &[u8]>::new(
                "LegacyCheckpointV1.UTXO",
            ))
            .unwrap();
        write.commit().unwrap();
        let original = raw_tables(&db, "");
        assert!(db.resync_legacy_checkpoint(&genesis()).is_err());
        assert_eq!(raw_tables(&db, ""), original);
    }
}
