//! Replay the actual durable journal of a stopped btc-node database.
//! Usage: cargo run --example exex_plugin -- /path/to/utxo.redb
use btc_exex::durable::{DatabaseStore, DurableManager, MetricsState, ValidatedMetrics};
use btc_storage::{
    traits::{Database, DbTx},
    RedbDatabase,
};
use std::{path::PathBuf, sync::Arc};
#[tokio::main]
async fn main() -> eyre::Result<()> {
    let path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| eyre::eyre!("provide an existing stopped node database"))?;
    eyre::ensure!(path.is_file(), "node database does not exist");
    let db = Arc::new(RedbDatabase::new(path)?);
    let genesis = db
        .tx()?
        .get_block_hash_by_height(0)?
        .ok_or_else(|| eyre::eyre!("validated genesis unavailable"))?;
    let tip = db
        .verify_exex_journal(genesis)?
        .ok_or_else(|| eyre::eyre!("durable journal unavailable"))?;
    let (_sender, wakeup) = tokio::sync::watch::channel(0);
    let mut manager = DurableManager::new(Arc::new(DatabaseStore::new(db.clone())), wakeup);
    manager.register(ValidatedMetrics)?;
    let result = tokio::select! {
        error=manager.wait_failed()=>Err(error),
        result=async {
            loop {
                if let Some(state)=db.tx()?.exex_state("validated-metrics-v1")? {
                    if state.cursor==tip {let metrics=MetricsState::decode(&state.state)?;println!("sequence {} height {} hash {} transactions {} spendable coins {}",tip.sequence,tip.height,tip.hash,metrics.transactions,metrics.spendable_coins);break;}
                } else if tip.sequence==0 {println!("validated genesis {}: no block events",genesis);break;}
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Ok::<(),eyre::Error>(())
        }=>result,
    };
    manager.shutdown().await;
    result
}
