//! Validated active-chain script history. Independent of the stage address table.
//! Per-block manifests detect missing/extra/corrupt rows on reopen. Publication,
//! reorg unwind and the tip receipt share the coin/index/mempool transaction.
use super::*;
use crate::traits::ScriptHistoryEntry;
use btc_consensus::utxo::UtxoSetUpdate;
use btc_primitives::hash::sha256;
use redb::ReadableTable;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

pub(super) const HISTORY: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("ValidatedScriptHistoryV1");
pub(super) const MANIFEST: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("ValidatedScriptBlocksV1");
pub(super) const RECEIPT: &str = "validated_script_tip_v1";
pub(super) fn error(e: impl std::fmt::Display) -> StorageError {
    StorageError::Database(e.to_string())
}
fn bad(s: &str) -> StorageError {
    StorageError::Corruption(s.into())
}

pub(super) fn read_tip(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<Option<(u64, BlockHash)>, StorageError> {
    table
        .get(RECEIPT)
        .map_err(error)?
        .map(|v| {
            let v = v.value();
            if v.len() != 40 {
                return Err(bad("invalid validated script index receipt"));
            }
            Ok((
                u64::from_be_bytes(v[..8].try_into().unwrap()),
                BlockHash::from_slice(&v[8..]),
            ))
        })
        .transpose()
}
fn key(hash: &[u8; 32], height: u64, position: u32) -> [u8; 44] {
    let mut key = [0; 44];
    key[..32].copy_from_slice(hash);
    key[32..40].copy_from_slice(&height.to_be_bytes());
    key[40..].copy_from_slice(&position.to_be_bytes());
    key
}
fn entry(k: &[u8], v: &[u8]) -> Result<ScriptHistoryEntry, StorageError> {
    if k.len() != 44 || v.len() != 32 {
        return Err(bad("invalid validated script history row"));
    }
    Ok(ScriptHistoryEntry {
        txid: TxHash::from_slice(v),
        height: u64::from_be_bytes(k[32..40].try_into().unwrap()),
        tx_position: u32::from_be_bytes(k[40..].try_into().unwrap()),
    })
}
pub(super) fn history(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    hash: &[u8; 32],
    limit: usize,
) -> Result<Vec<ScriptHistoryEntry>, StorageError> {
    let start = key(hash, 0, 0);
    let end = key(hash, u64::MAX, u32::MAX);
    let mut rows = Vec::new();
    for row in table
        .range(start.as_slice()..=end.as_slice())
        .map_err(error)?
    {
        let (k, v) = row.map_err(error)?;
        if rows.len() == limit {
            return Err(StorageError::Database(
                "script history exceeds query limit".into(),
            ));
        }
        rows.push(entry(k.value(), v.value())?);
    }
    Ok(rows)
}

// One row per touched script/transaction, regardless of input/output multiplicity.
// Consumed coins include same-block spends and come from the validated undo.
fn rows(
    height: u64,
    block: &Block,
    undo: &UtxoSetUpdate,
) -> Result<BTreeMap<[u8; 44], TxHash>, StorageError> {
    let spent: HashMap<_, _> = undo.spent.iter().map(|(op, coin)| (*op, coin)).collect();
    if spent.len() != undo.spent.len() {
        return Err(bad("duplicate spent script-index undo coin"));
    }
    let mut rows = BTreeMap::new();
    let mut consumed = HashSet::new();
    for (position, tx) in block.transactions.iter().enumerate() {
        let position =
            u32::try_from(position).map_err(|_| bad("script-index position overflow"))?;
        let mut scripts = HashSet::new();
        for output in &tx.outputs {
            // Provably unspendable outputs are not coins. Genesis is excluded by
            // the caller, matching Electrum's explicitly unindexed coinbase.
            if !output.script_pubkey.is_op_return() && output.script_pubkey.len() <= 10_000 {
                scripts.insert(sha256(output.script_pubkey.as_bytes()));
            }
        }
        if !tx.is_coinbase() {
            for input in &tx.inputs {
                let op = input.previous_output;
                if !consumed.insert(op) {
                    return Err(bad("duplicate consumed script-index coin"));
                }
                let coin = spent
                    .get(&op)
                    .ok_or_else(|| bad("missing spent script-index coin"))?;
                scripts.insert(sha256(coin.txout.script_pubkey.as_bytes()));
            }
        }
        for script in scripts {
            rows.insert(key(&script, height, position), tx.txid());
        }
    }
    if spent.len() != consumed.len() {
        return Err(bad("extra spent script-index undo coin"));
    }
    Ok(rows)
}
pub(super) fn index_block(
    tx: &RedbTxMut,
    height: u64,
    block: &Block,
    undo: &UtxoSetUpdate,
    remove: bool,
) -> Result<(), StorageError> {
    if height == 0 {
        return Err(bad("genesis must not enter script index"));
    }
    let rows = rows(height, block, undo)?;
    let mut digest = Sha256::new();
    let mut history = tx.inner.open_table(HISTORY).map_err(error)?;
    for (k, id) in &rows {
        digest.update(k);
        digest.update(id.as_bytes());
        if remove {
            if history
                .remove(k.as_slice())
                .map_err(error)?
                .is_none_or(|value| value.value() != id.as_bytes())
            {
                return Err(bad("missing/mismatched script row during unwind"));
            }
        } else if history
            .insert(k.as_slice(), id.as_bytes().as_slice())
            .map_err(error)?
            .is_some()
        {
            return Err(bad("script index already contains attached row"));
        }
    }
    let mut manifest = block.block_hash().as_bytes().to_vec();
    manifest.extend_from_slice(&(rows.len() as u64).to_be_bytes());
    manifest.extend_from_slice(&digest.finalize());
    let mut table = tx.inner.open_table(MANIFEST).map_err(error)?;
    if remove {
        if table
            .remove(height_key(height).as_slice())
            .map_err(error)?
            .is_none_or(|v| v.value() != manifest)
        {
            return Err(bad("script block manifest mismatch during unwind"));
        }
    } else if table
        .insert(height_key(height).as_slice(), manifest.as_slice())
        .map_err(error)?
        .is_some()
    {
        return Err(bad("script block manifest already exists"));
    }
    Ok(())
}
impl RedbDatabase {
    /// Verify all rows against per-block manifests and the current active chain.
    /// Returns false only for a never-initialized index; corruption always errors.
    pub fn verify_script_index(&self) -> Result<bool, StorageError> {
        let tx = self.tx()?;
        let Some((height, hash)) = tx.script_index_tip()? else {
            return Ok(false);
        };
        if tx.get_best_block_height()? != height || tx.get_best_block_hash()? != hash {
            return Err(bad("validated script index tip mismatch"));
        }
        let history = tx.inner.open_table(HISTORY).map_err(error)?;
        let mut digests: HashMap<u64, (u64, Sha256)> = HashMap::new();
        for row in history.iter().map_err(error)? {
            let (k, v) = row.map_err(error)?;
            let entry = entry(k.value(), v.value())?;
            if entry.height == 0 || entry.height > height {
                return Err(bad("script row outside active history"));
            }
            let (count, digest) = digests
                .entry(entry.height)
                .or_insert_with(|| (0, Sha256::new()));
            *count += 1;
            digest.update(k.value());
            digest.update(v.value());
        }
        let manifests = tx.inner.open_table(MANIFEST).map_err(error)?;
        let mut count = 0;
        for row in manifests.iter().map_err(error)? {
            let (k, v) = row.map_err(error)?;
            let (k, v) = (k.value(), v.value());
            if k.len() != 8 || v.len() != 72 {
                return Err(bad("invalid script block manifest"));
            }
            count += 1;
            let h = u64::from_be_bytes(k.try_into().unwrap());
            if h != count
                || tx
                    .get_block_hash_by_height(h)?
                    .as_ref()
                    .map(BlockHash::as_bytes)
                    .map(|b| b.as_slice())
                    != Some(&v[..32])
            {
                return Err(bad("script block manifest not on active chain"));
            }
            let (rows, digest) = digests.remove(&h).unwrap_or_else(|| (0, Sha256::new()));
            if rows != u64::from_be_bytes(v[32..40].try_into().unwrap())
                || digest.finalize().as_slice() != &v[40..]
            {
                return Err(bad("script block manifest checksum/count mismatch"));
            }
        }
        if count != height || !digests.is_empty() {
            return Err(bad("incomplete validated script index"));
        }
        Ok(true)
    }
}
impl RedbTxMut {
    /// Reset only unpublished rows, in the same transaction as verified replay.
    pub fn reset_uninitialized_script_index(&self) -> Result<(), StorageError> {
        if self.script_index_tip()?.is_some() {
            return Err(bad("cannot clear initialized script index"));
        }
        self.inner
            .open_table(HISTORY)
            .map_err(error)?
            .retain(|_, _| false)
            .map_err(error)?;
        self.inner
            .open_table(MANIFEST)
            .map_err(error)?
            .retain(|_, _| false)
            .map_err(error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::{Amount, CompactTarget, ScriptBuf, TxIn, TxOut};
    fn fixture() -> (RedbDatabase, tempfile::TempDir, Block, UtxoSetUpdate) {
        let dir = tempfile::tempdir().unwrap();
        let db = RedbDatabase::new(dir.path().join("index.redb")).unwrap();
        db.init_tables().unwrap();
        let coinbase = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![1, 1]),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
            witness: vec![],
            lock_time: 0,
        };
        let op = OutPoint::new(coinbase.txid(), 0);
        let child = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![coinbase.outputs[0].clone(), coinbase.outputs[0].clone()],
            witness: vec![],
            lock_time: 0,
        };
        let undo = UtxoSetUpdate {
            spent: vec![(
                op,
                btc_consensus::utxo::UtxoEntry {
                    txout: coinbase.outputs[0].clone(),
                    height: 1,
                    is_coinbase: true,
                },
            )],
            created: vec![],
        };
        let block = Block {
            header: BlockHeader {
                version: 4,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::ZERO,
                time: 1,
                bits: CompactTarget(0x207fffff),
                nonce: 0,
            },
            transactions: vec![coinbase, child],
        };
        (db, dir, block, undo)
    }
    #[test]
    fn indexed_same_script_inputs_and_outputs_are_deduplicated_and_atomic() {
        let (db, _dir, block, undo) = fixture();
        let hash = sha256(&[0x51]);
        {
            let tx = db.tx_mut().unwrap();
            tx.index_script_block(1, &block, &undo, false).unwrap();
            tx.set_script_index_tip(1, &block.block_hash()).unwrap();
            // Dropped transaction simulates a failed final commit.
        }
        assert!(db
            .tx()
            .unwrap()
            .script_history(&hash, 10)
            .unwrap()
            .is_empty());
        assert!(!db.verify_script_index().unwrap());
        let tx = db.tx_mut().unwrap();
        tx.index_script_block(1, &block, &undo, false).unwrap();
        tx.put_block_hash_by_height(1, &block.block_hash()).unwrap();
        tx.set_best_block(1, &block.block_hash()).unwrap();
        tx.set_script_index_tip(1, &block.block_hash()).unwrap();
        tx.commit().unwrap();
        let rows = db.tx().unwrap().script_history(&hash, 10).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].tx_position, 1);
        assert!(db.tx().unwrap().script_history(&hash, 1).is_err());
        assert!(db.verify_script_index().unwrap());
        // A failed unwind leaves the complete old index, then retry succeeds.
        {
            let tx = db.tx_mut().unwrap();
            tx.index_script_block(1, &block, &undo, true).unwrap();
        }
        assert!(db.verify_script_index().unwrap());
        let tx = db.tx_mut().unwrap();
        tx.index_script_block(1, &block, &undo, true).unwrap();
        tx.set_best_block(0, &BlockHash::ZERO).unwrap();
        tx.set_script_index_tip(0, &BlockHash::ZERO).unwrap();
        tx.commit().unwrap();
        assert!(db.verify_script_index().unwrap());
    }
    #[test]
    fn missing_corrupt_rows_and_receipts_cannot_look_like_empty_history() {
        for damage in 0..4 {
            let (db, _dir, block, undo) = fixture();
            let tx = db.tx_mut().unwrap();
            tx.index_script_block(1, &block, &undo, false).unwrap();
            tx.put_block_hash_by_height(1, &block.block_hash()).unwrap();
            tx.set_best_block(1, &block.block_hash()).unwrap();
            tx.set_script_index_tip(1, &block.block_hash()).unwrap();
            tx.commit().unwrap();
            let tx = db.tx_mut().unwrap();
            match damage {
                0 => {
                    tx.inner
                        .open_table(HISTORY)
                        .unwrap()
                        .remove(key(&sha256(&[0x51]), 1, 1).as_slice())
                        .unwrap();
                }
                1 => {
                    tx.inner
                        .open_table(HISTORY)
                        .unwrap()
                        .insert(key(&sha256(&[0x51]), 1, 1).as_slice(), &[3u8][..])
                        .unwrap();
                }
                2 => {
                    tx.inner
                        .open_table(MANIFEST)
                        .unwrap()
                        .remove(height_key(1).as_slice())
                        .unwrap();
                }
                _ => {
                    tx.inner
                        .open_table(META)
                        .unwrap()
                        .insert(RECEIPT, &[0u8][..])
                        .unwrap();
                }
            }
            tx.commit().unwrap();
            assert!(db.verify_script_index().is_err());
        }
    }
    #[test]
    fn malformed_undo_and_maximum_script_hash_queries_are_explicit() {
        let (db, _dir, block, mut undo) = fixture();
        undo.spent.clear();
        let tx = db.tx_mut().unwrap();
        assert!(tx.index_script_block(1, &block, &undo, false).is_err());
        assert!(tx.index_script_block(0, &block, &undo, false).is_err());
        assert!(tx.script_history(&[0xff; 32], 5).unwrap().is_empty());
    }
}
