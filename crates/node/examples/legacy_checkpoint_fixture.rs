//! Acceptance fixture tool only. Imports real Core coin records into the old
//! tip-only layout, and hashes raw active/archive tables for preservation checks.
//! It never participates in ordinary node startup or validates imported coins.
use btc_consensus::utxo::{UtxoEntry, UtxoSetUpdate};
use btc_primitives::{
    amount::Amount,
    encode::decode,
    hash::BlockHash,
    transaction::{OutPoint, Transaction},
};
use btc_storage::{
    redb_backend::RedbDatabase,
    traits::{Database, DbTxMut},
    utxo_store::PersistentUtxoSet,
};
use redb::{ReadableTable, TableDefinition};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};

fn digest(path: &Path, prefix: &str) -> eyre::Result<String> {
    let db = redb::Database::create(path)?;
    let read = db.begin_read()?;
    let mut digest = Sha256::new();
    for table in [
        "BlockUndoV1",
        "Mempool",
        "Headers",
        "Blocks",
        "BlockIndex",
        "Transactions",
        "UTXOs",
        "TxBlockIndex",
        "AddressIndex",
    ] {
        let name = format!("{prefix}{table}");
        digest.update(table.as_bytes());
        for row in read
            .open_table(TableDefinition::<&[u8], &[u8]>::new(&name))?
            .iter()?
        {
            let (key, value) = row?;
            for part in [key.value(), value.value()] {
                digest.update((part.len() as u64).to_be_bytes());
                digest.update(part);
            }
        }
    }
    let name = format!("{prefix}Meta");
    digest.update(b"Meta");
    for row in read
        .open_table(TableDefinition::<&str, &[u8]>::new(&name))?
        .iter()?
    {
        let (key, value) = row?;
        for part in [key.value().as_bytes(), value.value()] {
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part);
        }
    }
    Ok(hex::encode(digest.finalize()))
}

fn main() -> eyre::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    eyre::ensure!(
        args.len() == 4,
        "create MANIFEST DATABASE | digest active/archive DATABASE"
    );
    let path = Path::new(&args[3]);
    match args[1].as_str() {
        "create" => {
            eyre::ensure!(!path.exists(), "fixture database already exists");
            let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&args[2])?)?;
            let tip =
                BlockHash::from_hex(json["hash"].as_str().ok_or_else(|| eyre::eyre!("hash"))?)?;
            let height = json["height"]
                .as_u64()
                .ok_or_else(|| eyre::eyre!("height"))?;
            let db = Arc::new(RedbDatabase::new(path)?);
            db.init_tables()?;
            let mut coins = PersistentUtxoSet::new(db.clone());
            let mut update = UtxoSetUpdate {
                created: Vec::new(),
                spent: Vec::new(),
            };
            for item in json["coins"]
                .as_array()
                .ok_or_else(|| eyre::eyre!("coins"))?
            {
                let tx: Transaction = decode(&hex::decode(item["transaction"].as_str().unwrap())?)?;
                let vout = item["vout"].as_u64().unwrap() as u32;
                update.created.push((
                    OutPoint::new(tx.txid(), vout),
                    UtxoEntry {
                        txout: tx.outputs[vout as usize].clone(),
                        height: item["height"].as_u64().unwrap(),
                        is_coinbase: item["coinbase"].as_bool().unwrap(),
                    },
                ));
                let write = db.tx_mut()?;
                write.put_transaction(&tx.txid(), &tx)?;
                // Deliberately stale indexes/pool test that these archived rows
                // never authorize transactions in the fresh runtime.
                write.put_tx_block_index(&tx.txid(), &tip, 0)?;
                write.replace_mempool(&[tx])?;
                write.commit()?;
            }
            // Verify the actual supplied coin amounts before writing the layout.
            eyre::ensure!(
                update
                    .created
                    .iter()
                    .all(|(_, e)| e.txout.value > Amount::ZERO),
                "fixture coins must be positive"
            );
            coins.apply_update(&update)?;
            coins.flush_cache_with_tip(height, tip)?;
        }
        "digest" => {
            let prefix = match args[2].as_str() {
                "active" => "",
                "archive" => "LegacyCheckpointV1.",
                _ => eyre::bail!("unknown table scope"),
            };
            println!("{}", digest(path, prefix)?);
        }
        _ => eyre::bail!("unknown fixture action"),
    }
    Ok(())
}
