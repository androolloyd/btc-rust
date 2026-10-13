//! redb implementation: journal publication and consumer acknowledgements are transactional.
use super::*;
use crate::exex::{bad, ExtensionState, JournalEntry, JournalTip};
pub(super) const EVENTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("ExExJournalV1");
pub(super) const STATES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("ExExStatesV1");
const RECEIPT: &str = "validated_exex_v1";
pub(super) fn read_tip(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<Option<JournalTip>, StorageError> {
    table
        .get(RECEIPT)
        .map_err(script_index::error)?
        .map(|v| JournalTip::decode(v.value()))
        .transpose()
}
pub(super) fn read_entry(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    sequence: u64,
) -> Result<Option<JournalEntry>, StorageError> {
    table
        .get(sequence.to_be_bytes().as_slice())
        .map_err(script_index::error)?
        .map(|v| JournalEntry::decode(v.value(), sequence))
        .transpose()
}
pub(super) fn read_state(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    name: &str,
) -> Result<Option<ExtensionState>, StorageError> {
    crate::exex::validate_name(name)?;
    table
        .get(name.as_bytes())
        .map_err(script_index::error)?
        .map(|v| ExtensionState::decode(name, v.value()))
        .transpose()
}
pub(super) fn initialize(tx: &RedbTxMut, genesis: BlockHash) -> Result<(), StorageError> {
    if tx.exex_journal_tip()?.is_some() {
        return Err(bad("ExEx journal already initialized"));
    }
    for definition in [EVENTS, STATES] {
        let table = tx
            .inner
            .open_table(definition)
            .map_err(script_index::error)?;
        if table.iter().map_err(script_index::error)?.next().is_some() {
            return Err(bad("unbound ExEx rows cannot authorize a new journal"));
        }
    }
    let mut initial = JournalTip::initial(genesis);
    initial.bootstrap_height = tx.get_best_block_height()?;
    tx.inner
        .open_table(META)
        .map_err(script_index::error)?
        .insert(RECEIPT, initial.encode().as_slice())
        .map_err(script_index::error)?;
    Ok(())
}
pub(super) fn append(
    tx: &RedbTxMut,
    connected: bool,
    height: u64,
    block: &Block,
) -> Result<(), StorageError> {
    let tip = tx
        .exex_journal_tip()?
        .ok_or_else(|| bad("ExEx journal unavailable"))?;
    if height == 0 {
        return Err(bad("genesis cannot produce an ExEx coin event"));
    }
    let entry = JournalEntry {
        sequence: tip
            .sequence
            .checked_add(1)
            .ok_or_else(|| bad("ExEx sequence overflow"))?,
        connected,
        height,
        hash: block.block_hash(),
        parent: block.header.prev_blockhash,
    };
    if entry.before() != (tip.height, tip.hash) {
        return Err(bad("ExEx event does not connect to prior receipt"));
    }
    entry.resolve(tx)?;
    let mut table = tx.inner.open_table(EVENTS).map_err(script_index::error)?;
    if table
        .insert(
            entry.sequence.to_be_bytes().as_slice(),
            entry.encode().as_slice(),
        )
        .map_err(script_index::error)?
        .is_some()
    {
        return Err(bad("ExEx sequence already exists"));
    }
    drop(table);
    let (height, hash) = entry.after();
    let next = JournalTip {
        sequence: entry.sequence,
        height,
        hash,
        ..tip
    };
    tx.inner
        .open_table(META)
        .map_err(script_index::error)?
        .insert(RECEIPT, next.encode().as_slice())
        .map_err(script_index::error)?;
    Ok(())
}
pub(super) fn set_state(
    tx: &RedbTxMut,
    name: &str,
    state: &ExtensionState,
) -> Result<(), StorageError> {
    let tip = tx
        .exex_journal_tip()?
        .ok_or_else(|| bad("ExEx journal unavailable"))?;
    let previous = tx
        .exex_state(name)?
        .map(|s| s.cursor)
        .unwrap_or(JournalTip::initial(tip.genesis));
    if previous.genesis != tip.genesis
        || previous.sequence.checked_add(1) != Some(state.cursor.sequence)
        || state.cursor.genesis != tip.genesis
        || state.cursor.bootstrap_height != tip.bootstrap_height
        || state.cursor.sequence > tip.sequence
    {
        return Err(bad("invalid extension cursor advancement"));
    }
    let entry = tx
        .exex_journal_entry(state.cursor.sequence)?
        .ok_or_else(|| bad("missing extension cursor event"))?;
    if entry.before() != (previous.height, previous.hash)
        || entry.after() != (state.cursor.height, state.cursor.hash)
    {
        return Err(bad("extension cursor does not follow actual journal"));
    }
    tx.inner
        .open_table(STATES)
        .map_err(script_index::error)?
        .insert(name.as_bytes(), state.encode(name)?.as_slice())
        .map_err(script_index::error)?;
    Ok(())
}
impl RedbDatabase {
    pub fn verify_exex_journal(
        &self,
        genesis: BlockHash,
    ) -> Result<Option<JournalTip>, StorageError> {
        let reader = self.tx()?;
        let Some(tip) = reader.exex_journal_tip()? else {
            return Ok(None);
        };
        if tip.genesis != genesis || tip.bootstrap_height > tip.sequence {
            return Err(bad("ExEx journal network anchor mismatch"));
        }
        let mut previous = JournalTip {
            bootstrap_height: tip.bootstrap_height,
            ..JournalTip::initial(genesis)
        };
        let table = reader
            .inner
            .open_table(EVENTS)
            .map_err(script_index::error)?;
        for row in table.iter().map_err(script_index::error)? {
            let (key, value) = row.map_err(script_index::error)?;
            if key.value().len() != 8 {
                return Err(bad("invalid ExEx sequence key"));
            }
            let sequence = u64::from_be_bytes(key.value().try_into().unwrap());
            let entry = JournalEntry::decode(value.value(), sequence)?;
            if previous.sequence.checked_add(1) != Some(sequence)
                || entry.before() != (previous.height, previous.hash)
            {
                return Err(bad("ExEx journal sequence/ancestry gap"));
            }
            entry.resolve(&reader)?;
            let (height, hash) = entry.after();
            previous = JournalTip {
                sequence,
                height,
                hash,
                ..previous
            };
        }
        if previous != tip {
            return Err(bad("ExEx journal receipt/history mismatch"));
        }
        let states = reader
            .inner
            .open_table(STATES)
            .map_err(script_index::error)?;
        for row in states.iter().map_err(script_index::error)? {
            let (key, value) = row.map_err(script_index::error)?;
            let name = std::str::from_utf8(key.value())
                .map_err(|_| bad("invalid extension state name"))?;
            let state = ExtensionState::decode(name, value.value())?;
            let event = reader
                .exex_journal_entry(state.cursor.sequence)?
                .ok_or_else(|| bad("extension cursor event missing"))?;
            if state.cursor.genesis != genesis
                || state.cursor.bootstrap_height != tip.bootstrap_height
                || state.cursor.sequence > tip.sequence
                || event.after() != (state.cursor.height, state.cursor.hash)
            {
                return Err(bad("extension checkpoint/journal mismatch"));
            }
        }
        Ok(Some(tip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn actual_fixture() -> (RedbDatabase, tempfile::TempDir, Block) {
        let dir = tempfile::tempdir().unwrap();
        let db = RedbDatabase::new(dir.path().join("journal.redb")).unwrap();
        db.init_tables().unwrap();
        let params = btc_consensus::validation::ChainParams::regtest();
        let genesis = btc_consensus::chain::genesis_block(&params);
        let mut body = genesis.clone();
        body.header.version = 4;
        body.header.prev_blockhash = genesis.block_hash();
        body.header.time += 1;
        body.transactions[0].inputs[0].script_sig =
            btc_primitives::ScriptBuf::from_bytes(vec![0x51, 0x00]);
        body.header.merkle_root = body.compute_merkle_root();
        while !body.header.check_proof_of_work() {
            body.header.nonce += 1;
        }
        let undo = btc_consensus::utxo::connect_block_with_params(
            &body,
            1,
            &btc_consensus::utxo::InMemoryUtxoSet::new(),
            &params,
        )
        .unwrap();
        let write = db.tx_mut().unwrap();
        write.set_best_block(0, &genesis.block_hash()).unwrap();
        write.initialize_exex_journal(genesis.block_hash()).unwrap();
        write.put_block(&body.block_hash(), &body).unwrap();
        write
            .put_block_undo(
                &body.block_hash(),
                &crate::undo::encode_undo(body.block_hash(), &undo),
            )
            .unwrap();
        write.append_exex_event(true, 1, &body).unwrap();
        write.set_best_block(1, &body.block_hash()).unwrap();
        write.commit().unwrap();
        (db, dir, body)
    }
    #[test]
    fn journal_gaps_corruption_and_future_or_rebound_cursors_are_not_acknowledged() {
        let (db, _dir, body) = actual_fixture();
        let genesis = body.header.prev_blockhash;
        let tip = db.verify_exex_journal(genesis).unwrap().unwrap();
        let state = ExtensionState {
            cursor: tip,
            state: vec![1, 2, 3],
        };
        {
            let write = db.tx_mut().unwrap();
            let future = ExtensionState {
                cursor: JournalTip { sequence: 2, ..tip },
                state: vec![],
            };
            assert!(write.set_exex_state("metrics", &future).is_err());
            write.set_exex_state("metrics", &state).unwrap();
        }
        assert!(db.tx().unwrap().exex_state("metrics").unwrap().is_none());
        let write = db.tx_mut().unwrap();
        write.set_exex_state("metrics", &state).unwrap();
        write.commit().unwrap();
        assert_eq!(db.tx().unwrap().exex_state("metrics").unwrap(), Some(state));
        let write = db.tx_mut().unwrap();
        {
            let mut table = write.inner.open_table(STATES).unwrap();
            let bytes = table
                .get(b"metrics".as_slice())
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            table
                .insert(b"renamed".as_slice(), bytes.as_slice())
                .unwrap();
        }
        write.commit().unwrap();
        assert!(db.verify_exex_journal(genesis).is_err());
        let write = db.tx_mut().unwrap();
        {
            let mut table = write.inner.open_table(STATES).unwrap();
            table.remove(b"renamed".as_slice()).unwrap();
        }
        write.commit().unwrap();
        let write = db.tx_mut().unwrap();
        {
            let mut table = write.inner.open_table(EVENTS).unwrap();
            let key = 1u64.to_be_bytes();
            let mut bytes = table.get(key.as_slice()).unwrap().unwrap().value().to_vec();
            bytes[21] ^= 1;
            table.insert(key.as_slice(), bytes.as_slice()).unwrap();
        }
        write.commit().unwrap();
        assert!(db.verify_exex_journal(genesis).is_err());
        let (gap, _gap_dir, gap_body) = actual_fixture();
        let write = gap.tx_mut().unwrap();
        {
            let mut table = write.inner.open_table(EVENTS).unwrap();
            table.remove(1u64.to_be_bytes().as_slice()).unwrap();
        }
        write.commit().unwrap();
        assert!(gap
            .verify_exex_journal(gap_body.header.prev_blockhash)
            .is_err());
    }
}
