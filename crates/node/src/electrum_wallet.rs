//! Wallet query snapshots from validated script history and the real mempool.
//! No separate wallet balance cache or stage index is authoritative here.
use super::chain_backend::{internal, NodeChainBackend, ValidatedChain};
use btc_electrum::methods::*;
use btc_primitives::{hash::sha256, OutPoint, TxOut};
use btc_rpc::handler::RpcError;
use btc_storage::redb_backend::RedbTx;
use btc_storage::traits::{Database, DbTx};
use serde_json::{json, Value};

const MAX_HISTORY: usize = 10_000;
const MAX_QUERY_WORK: usize = 1_000_000;
#[derive(Default)]
struct QueryBudget {
    work: usize,
    block_weight: usize,
    script_bytes: usize,
    history: usize,
}
fn inspect(output: &TxOut, script: &[u8; 32], budget: &mut QueryBudget) -> Result<bool, RpcError> {
    budget.script_bytes = budget
        .script_bytes
        .checked_add(output.script_pubkey.len())
        .filter(|n| *n <= 64 * 1024 * 1024)
        .ok_or_else(|| internal("Electrum script byte limit exceeded"))?;
    Ok(relevant(output, script))
}
fn relevant(output: &TxOut, script: &[u8; 32]) -> bool {
    !output.script_pubkey.is_op_return()
        && output.script_pubkey.len() <= 10_000
        && sha256(output.script_pubkey.as_bytes()) == *script
}
fn charge(work: &mut usize, count: usize) -> Result<(), RpcError> {
    *work = work
        .checked_add(count)
        .filter(|n| *n <= MAX_QUERY_WORK)
        .ok_or_else(|| internal("Electrum script query work limit exceeded"))?;
    Ok(())
}
fn add(balance: &mut i64, value: i64) -> Result<(), RpcError> {
    *balance = balance
        .checked_add(value)
        .ok_or_else(|| internal("Electrum balance overflow"))?;
    Ok(())
}

impl NodeChainBackend {
    pub(super) fn electrum_wallet(
        &self,
        data: &ValidatedChain,
        method: &str,
        hash: &[u8; 32],
    ) -> Result<Value, RpcError> {
        let read = self.db.tx().map_err(internal)?;
        Self::wallet_snapshot(data, &read, method, hash, &mut QueryBudget::default())
    }

    fn wallet_snapshot(
        data: &ValidatedChain,
        read: &RedbTx,
        method: &str,
        hash: &[u8; 32],
        budget: &mut QueryBudget,
    ) -> Result<Value, RpcError> {
        if read.script_index_tip().map_err(internal)?
            != Some((
                data.headers.best_height(),
                data.headers.best_header().header.block_hash(),
            ))
        {
            return Err(internal(
                "validated script index unavailable or behind chain",
            ));
        }
        let mut history = Vec::new();
        let mut unspent = Vec::new();
        let mut confirmed = 0i64;
        let mut delta = 0i64;
        let pool_only = method == METHOD_SCRIPTHASH_GET_MEMPOOL;
        if !pool_only {
            let rows = read.script_history(hash, MAX_HISTORY).map_err(internal)?;
            budget.history = budget
                .history
                .checked_add(rows.len())
                .filter(|n| *n <= MAX_HISTORY)
                .ok_or_else(|| internal("Electrum subscription history budget exceeded"))?;
            let mut cached_block = None;
            for row in rows {
                let active = data
                    .headers
                    .get_header_by_height(row.height)
                    .ok_or_else(|| internal("script history height unavailable"))?
                    .header
                    .block_hash();
                if cached_block
                    .as_ref()
                    .is_none_or(|(hash, _)| *hash != active)
                {
                    let block = read
                        .get_block(&active)
                        .map_err(internal)?
                        .ok_or_else(|| internal("script history body unavailable"))?;
                    budget.block_weight = budget
                        .block_weight
                        .checked_add(block.weight())
                        .filter(|n| *n <= 64 * 1024 * 1024)
                        .ok_or_else(|| {
                            internal("Electrum script query block-read limit exceeded")
                        })?;
                    if block.block_hash() != active
                        || block.compute_merkle_root() != block.header.merkle_root
                    {
                        return Err(internal("script history body corrupt"));
                    }
                    cached_block = Some((active, block));
                }
                let tx = cached_block
                    .as_ref()
                    .unwrap()
                    .1
                    .transactions
                    .get(row.tx_position as usize)
                    .filter(|tx| tx.txid() == row.txid)
                    .ok_or_else(|| internal("script history transaction mismatch"))?;
                history.push(json!({"tx_hash":row.txid.to_string(),"height":row.height}));
                if method == METHOD_SCRIPTHASH_GET_HISTORY {
                    continue;
                }
                charge(&mut budget.work, tx.outputs.len())?;
                for (position, output) in tx.outputs.iter().enumerate() {
                    if !inspect(output, hash, budget)? {
                        continue;
                    }
                    let op = OutPoint::new(row.txid, position as u32);
                    // Query the DB snapshot directly: a storage error must not
                    // turn into the UtxoSet trait's absent-coin representation.
                    if let Some(coin) = read.get_utxo(&op).map_err(internal)? {
                        let meta = read
                            .get_utxo(&OutPoint::new(row.txid, op.vout | 0x8000_0000))
                            .map_err(internal)?
                            .ok_or_else(|| internal("script coin metadata missing"))?;
                        if meta.value.as_sat() < 0
                            || !matches!(meta.script_pubkey.as_bytes(), [0] | [1])
                        {
                            return Err(internal("script coin metadata corrupt"));
                        }
                        // Duplicate pre-BIP30 txids can have two history rows;
                        // the durable coin belongs only to its actual height.
                        if meta.value.as_sat() as u64 != row.height {
                            continue;
                        }
                        if coin != *output {
                            return Err(internal("script history/coin mismatch"));
                        }
                        add(&mut confirmed, coin.value.as_sat())?;
                        if !data.mempool.spent.contains_key(&op) {
                            if unspent.len() >= MAX_HISTORY {
                                return Err(internal(
                                    "Electrum unspent result exceeds query limit",
                                ));
                            }
                            unspent.push(json!({"tx_hash":row.txid.to_string(),"tx_pos":position,"height":row.height,"value":coin.value.as_sat()}));
                        }
                    }
                }
            }
        }
        let mut pool_history = Vec::new();
        for id in &data.mempool.order {
            let entry = &data.mempool.entries[id];
            let tx = &entry.tx;
            charge(&mut budget.work, tx.inputs.len() + tx.outputs.len())?;
            let mut touched = false;
            let mut unconfirmed_parent = false;
            for input in &tx.inputs {
                let op = input.previous_output;
                let prevout = if let Some(parent) = data.mempool.entries.get(&op.txid) {
                    unconfirmed_parent = true;
                    parent
                        .tx
                        .outputs
                        .get(op.vout as usize)
                        .cloned()
                        .ok_or_else(|| internal("mempool script query parent output missing"))?
                } else {
                    read.get_utxo(&op)
                        .map_err(internal)?
                        .ok_or_else(|| internal("mempool script query spent coin missing"))?
                };
                if inspect(&prevout, hash, budget)? {
                    touched = true;
                    add(&mut delta, -prevout.value.as_sat())?;
                }
            }
            for (position, output) in tx.outputs.iter().enumerate() {
                if inspect(output, hash, budget)? {
                    touched = true;
                    add(&mut delta, output.value.as_sat())?;
                    if method == METHOD_SCRIPTHASH_LISTUNSPENT
                        && !data
                            .mempool
                            .spent
                            .contains_key(&OutPoint::new(*id, position as u32))
                    {
                        if unspent.len() >= MAX_HISTORY {
                            return Err(internal("Electrum unspent result exceeds query limit"));
                        }
                        unspent.push(json!({"tx_hash":id.to_string(),"tx_pos":position,"height":0,"value":output.value.as_sat()}));
                    }
                }
            }
            if touched {
                if history.len() + pool_history.len() >= MAX_HISTORY {
                    return Err(internal("Electrum script history exceeds query limit"));
                }
                budget.history = budget
                    .history
                    .checked_add(1)
                    .filter(|n| *n <= MAX_HISTORY)
                    .ok_or_else(|| internal("Electrum subscription history budget exceeded"))?;
                pool_history.push(json!({"tx_hash":id.to_string(),"height":if unconfirmed_parent {-1} else {0},"fee":entry.fee}));
            }
        }
        if unspent.len() > MAX_HISTORY {
            return Err(internal("Electrum unspent result exceeds query limit"));
        }
        // Electrum permits arbitrary pool ordering. Stable display-txid order
        // keeps history and status identical across pool rebuild/restart.
        pool_history.sort_by_cached_key(|row| row["tx_hash"].as_str().unwrap().to_owned());
        match method {
            METHOD_SCRIPTHASH_GET_HISTORY => {
                history.extend(pool_history);
                Ok(json!(history))
            }
            METHOD_SCRIPTHASH_GET_MEMPOOL => Ok(json!(pool_history)),
            METHOD_SCRIPTHASH_GET_BALANCE => Ok(json!({"confirmed":confirmed,"unconfirmed":delta})),
            METHOD_SCRIPTHASH_LISTUNSPENT => Ok(json!(unspent)),
            _ => Err(internal("unsupported Electrum script query")),
        }
    }
    pub(super) fn electrum_statuses(
        &self,
        data: &ValidatedChain,
        scripts: &[String],
    ) -> Result<Vec<Value>, RpcError> {
        if scripts.len() > btc_electrum::handler::MAX_SCRIPT_SUBSCRIPTIONS {
            return Err(internal("too many script statuses"));
        }
        let read = self.db.tx().map_err(internal)?;
        let mut budget = QueryBudget::default();
        scripts
            .iter()
            .map(|script| {
                let mut hash: [u8; 32] = hex::decode(script)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| internal("invalid script status hash"))?;
                hash.reverse();
                let history = Self::wallet_snapshot(
                    data,
                    &read,
                    METHOD_SCRIPTHASH_GET_HISTORY,
                    &hash,
                    &mut budget,
                )?;
                let mut text = String::new();
                for row in history
                    .as_array()
                    .ok_or_else(|| internal("invalid script status history"))?
                {
                    let id = row["tx_hash"]
                        .as_str()
                        .ok_or_else(|| internal("invalid script status transaction"))?;
                    let height = row["height"]
                        .as_i64()
                        .ok_or_else(|| internal("invalid script status height"))?;
                    use std::fmt::Write;
                    write!(text, "{id}:{height}:").map_err(internal)?;
                }
                Ok(if text.is_empty() {
                    Value::Null
                } else {
                    json!(hex::encode(sha256(text.as_bytes())))
                })
            })
            .collect()
    }
}
