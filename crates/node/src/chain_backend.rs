//! The validated chain shared by RPC and block download.
//! Header-only download never advances this chain's UTXOs or published tip.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use btc_consensus::parallel::{ParallelConfig, ParallelValidator};
use btc_consensus::utxo::{connect_block_with_context, LockTimeContext, UtxoSet, UtxoSetUpdate};
use btc_consensus::validation::{
    block_subsidy_with_params, encode_bip34_height, BlockValidator, ChainParams,
};
use btc_consensus::ChainState;
use btc_primitives::address::Address;
use btc_primitives::block::{Block, BlockHeader};
use btc_primitives::encode::{decode, encode};
use btc_primitives::hash::{BlockHash, TxHash};
use btc_primitives::network::Network;
use btc_primitives::script::ScriptBuf;
use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use btc_rpc::handler::{
    compact_bits_to_difficulty, compact_bits_to_target_hex, ChainBackend, RpcError, INTERNAL_ERROR,
    INVALID_PARAMS,
};
use btc_storage::redb_backend::RedbDatabase;
use btc_storage::traits::{Database, DbTx, DbTxMut};
use btc_storage::utxo_store::PersistentUtxoSet;
use serde_json::{json, Value};

use crate::state::NodeState;

struct ValidatedChain {
    headers: ChainState,
    utxos: PersistentUtxoSet<RedbDatabase>,
}

pub struct NodeChainBackend {
    data: Mutex<ValidatedChain>,
    db: Arc<RedbDatabase>,
    state: NodeState,
}

pub struct AcceptedBlock {
    pub height: u64,
    pub hash: BlockHash,
    pub update: UtxoSetUpdate,
}

impl NodeChainBackend {
    pub fn open(path: &Path, state: NodeState) -> eyre::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = Arc::new(RedbDatabase::new(path)?);
        db.init_tables()?;
        let utxos = PersistentUtxoSet::new(Arc::clone(&db));
        let mut params = ChainParams::from_network(state.network);
        // RPC submissions always run scripts; an assume-valid shortcut cannot
        // be inferred merely from a matching incoming block hash.
        params.assume_valid = None;
        let mut headers = ChainState::new(params);
        if let Some((height, expected)) = utxos.validated_tip()? {
            let tx = db.tx()?;
            for h in 1..=height {
                let hash = tx.get_block_hash_by_height(h)?.ok_or_else(|| eyre::eyre!(
                    "committed chain lacks header history at height {h}; legacy checkpoint migration requires a resync in a separate data directory"
                ))?;
                let header = tx
                    .get_block_header(&hash)?
                    .ok_or_else(|| eyre::eyre!("missing committed header {hash}"))?;
                if header.block_hash() != hash {
                    return Err(eyre::eyre!("corrupt header index at height {h}"));
                }
                headers.accept_header(header)?;
            }
            if headers.best_header().header.block_hash() != expected {
                return Err(eyre::eyre!(
                    "committed tip does not match stored header history"
                ));
            }
        } else {
            let genesis = headers.best_header().header.clone();
            let hash = genesis.block_hash();
            let tx = db.tx_mut()?;
            tx.put_block_header(&hash, &genesis)?;
            tx.put_block_hash_by_height(0, &hash)?;
            tx.set_best_block(0, &hash)?;
            tx.commit()?;
        }
        state.update_chain_tip(
            headers.best_height(),
            &headers.best_header().header.block_hash().to_string(),
        );
        Ok(Self {
            data: Mutex::new(ValidatedChain { headers, utxos }),
            db,
            state,
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, ValidatedChain>, RpcError> {
        self.data
            .lock()
            .map_err(|_| RpcError::new(INTERNAL_ERROR, "validated chain lock poisoned"))
    }

    pub fn header_chain(&self) -> eyre::Result<ChainState> {
        Ok(self
            .lock()
            .map_err(|e| eyre::eyre!(e.message))?
            .headers
            .clone())
    }

    pub fn tip(&self) -> eyre::Result<(u64, BlockHash)> {
        let data = self.lock().map_err(|e| eyre::eyre!(e.message))?;
        Ok((
            data.headers.best_height(),
            data.headers.best_header().header.block_hash(),
        ))
    }

    /// Validate against the current UTXOs, commit all durable data, then publish.
    pub fn submit_block(&self, block: &Block) -> Result<AcceptedBlock, RpcError> {
        let mut data = self.lock()?;
        let hash = block.block_hash();
        if data.headers.get_header(&hash).is_some() {
            return Err(RpcError::new(-27, "duplicate"));
        }
        if block.header.prev_blockhash != data.headers.best_header().header.block_hash() {
            return Err(RpcError::new(
                -25,
                "block does not extend the validated tip; persistent reorg support is required",
            ));
        }
        let height = data.headers.best_height() + 1;
        let params = data.headers.params().clone();
        BlockValidator::validate_block(block).map_err(rejection)?;
        let min_version = if height >= params.bip65_height {
            4
        } else if height >= params.bip66_height {
            3
        } else if height >= params.bip34_height {
            2
        } else {
            1
        };
        if block.header.version < min_version {
            return Err(rejection("obsolete block version"));
        }
        let coinbase_size = block.transactions[0].inputs[0].script_sig.len();
        if !(2..=100).contains(&coinbase_size) {
            return Err(rejection("coinbase scriptSig length must be 2..100"));
        }
        if block.transactions.iter().any(|tx| tx.inputs.is_empty()) {
            return Err(rejection("transaction has no inputs"));
        }
        if height >= params.segwit_height {
            BlockValidator::verify_witness_commitment(block).map_err(rejection)?;
        } else if block.transactions.iter().any(Transaction::is_segwit) {
            return Err(rejection("unexpected witness before activation"));
        }
        if let Some(challenge) = &params.signet_challenge {
            btc_consensus::signet::validate_signet_block(
                block,
                &btc_consensus::signet::SignetChallenge::new(challenge.clone()),
            )
            .map_err(rejection)?;
        }
        let prev = data.headers.best_header();
        let ancestor_mtp = |h| {
            data.headers
                .get_header_by_height(h)
                .map(|e| data.headers.median_time_past(e))
        };
        let context = LockTimeContext {
            median_time_past: data.headers.median_time_past(prev),
            ancestor_mtp: &ancestor_mtp,
        };
        let update =
            connect_block_with_context(block, height, &data.utxos, &params, Some(&context))
                .map_err(rejection)?;
        ParallelValidator::new(ParallelConfig::default())
            .validate_block_scripts(block, &data.utxos, height, &params)
            .map_err(|errors| rejection(format!("script verification failed: {errors:?}")))?;
        let ValidatedChain { headers, utxos } = &mut *data;
        headers
            .accept_header_with_commit(block.header.clone(), || {
                utxos
                    .apply_block_update(block, height, &update)
                    .map_err(|e| e.to_string())
            })
            .map_err(|e| match e {
                btc_consensus::chain::ChainError::CommitFailed(message) => {
                    RpcError::new(INTERNAL_ERROR, message)
                }
                other => rejection(other),
            })?;
        self.state.update_chain_tip(height, &hash.to_string());
        Ok(AcceptedBlock {
            height,
            hash,
            update,
        })
    }

    fn candidate(&self, output_script: ScriptBuf) -> Result<Block, RpcError> {
        let data = self.lock()?;
        let height = data.headers.best_height() + 1;
        let prev = data.headers.best_header();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(internal)?
            .as_secs();
        let time = (now as u32).max(data.headers.median_time_past(prev) + 1);
        let mut script = encode_bip34_height(height);
        // A coinbase scriptSig is at least two bytes, including small heights.
        script.push(0);
        let coinbase = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(script),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: block_subsidy_with_params(height, data.headers.params()),
                script_pubkey: output_script,
            }],
            witness: vec![],
            lock_time: 0,
        };
        let mut block = Block {
            header: BlockHeader {
                version: 0x2000_0000,
                prev_blockhash: prev.header.block_hash(),
                merkle_root: TxHash::ZERO,
                time,
                bits: data.headers.next_work_required(time),
                nonce: 0,
            },
            transactions: vec![coinbase],
        };
        block.header.merkle_root = block.compute_merkle_root();
        Ok(block)
    }

    fn network_hashps(headers: &ChainState, count: i64, height: i64) -> Result<f64, RpcError> {
        let end = if height < 0 {
            headers.best_height()
        } else {
            height as u64
        };
        if end > headers.best_height() {
            return Err(RpcError::new(-8, "height out of range"));
        }
        if end == 0 {
            return Ok(0.0);
        }
        let count = if count <= 0 {
            end % 2016 + 1
        } else {
            (count as u64).min(end)
        };
        let start = end.saturating_sub(count);
        let mut min_time = u32::MAX;
        let mut max_time = 0;
        for h in start..=end {
            let entry = headers
                .get_header_by_height(h)
                .ok_or_else(|| internal("missing header"))?;
            min_time = min_time.min(entry.header.time);
            max_time = max_time.max(entry.header.time);
        }
        if max_time == min_time {
            return Ok(0.0);
        }
        let work = |h| {
            headers
                .get_header_by_height(h)
                .unwrap()
                .cumulative_work
                .iter()
                .fold(0.0, |v, b| v * 256.0 + *b as f64)
        };
        Ok((work(end) - work(start)) / (max_time - min_time) as f64)
    }

    fn header_json(&self, headers: &ChainState, hash: BlockHash) -> Result<Value, RpcError> {
        let entry = headers
            .get_header(&hash)
            .ok_or_else(|| RpcError::new(-5, "block not found"))?;
        let header = &entry.header;
        let block = self
            .db
            .tx()
            .map_err(internal)?
            .get_block(&hash)
            .map_err(internal)?;
        let mut result = json!({
            "hash": hash.to_string(), "confirmations": headers.best_height() - entry.height + 1,
            "height": entry.height, "version": header.version, "versionHex": format!("{:08x}", header.version),
            "merkleroot": header.merkle_root.to_string(), "time": header.time,
            "mediantime": headers.median_time_past(entry), "nonce": header.nonce,
            "bits": format!("{:08x}", header.bits.to_u32()), "difficulty": compact_bits_to_difficulty(header.bits.to_u32()),
            "chainwork": hex::encode(entry.cumulative_work),
            "nTx": if entry.height == 0 { 1 } else { block.as_ref().ok_or_else(|| internal("committed block body missing"))?.transactions.len() },
        });
        if entry.height > 0 {
            result["previousblockhash"] = json!(header.prev_blockhash.to_string());
        }
        if let Some(next) = headers.get_header_by_height(entry.height + 1) {
            result["nextblockhash"] = json!(next.header.block_hash().to_string());
        }
        Ok(result)
    }
}

impl ChainBackend for NodeChainBackend {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        match method {
            "submitblock" => {
                let raw = hex::decode(string_param(&params, 0)?)
                    .map_err(|e| RpcError::new(-22, e.to_string()))?;
                let block: Block = decode(&raw).map_err(|e| RpcError::new(-22, e.to_string()))?;
                match self.submit_block(&block) {
                    Ok(_) => Ok(Value::Null),
                    Err(error) if matches!(error.code, -25 | -26 | -27) => Ok(json!(error.message)),
                    Err(error) => Err(error),
                }
            }
            "generatetoaddress" => {
                if self.state.network != Network::Regtest {
                    return Err(RpcError::new(-8, "generation is only supported on regtest"));
                }
                let count = unsigned_param(&params, 0)?;
                if count > 1000 {
                    return Err(RpcError::new(-8, "at most 1000 blocks per request"));
                }
                let address = string_param(&params, 1)?;
                let address = Address::from_bech32(address, self.state.network)
                    .or_else(|_| Address::from_base58(address, self.state.network))
                    .map_err(|e| RpcError::new(-5, e.to_string()))?;
                let mut tries = match params.get(2) {
                    Some(_) => unsigned_param(&params, 2)?,
                    None => 1_000_000,
                };
                if tries > 10_000_000 {
                    return Err(RpcError::new(-8, "maxtries exceeds request limit"));
                }
                let mut hashes = Vec::new();
                for _ in 0..count {
                    let mut block = self.candidate(address.script_pubkey())?;
                    let mut found = false;
                    while tries > 0 {
                        tries -= 1;
                        if block.header.check_proof_of_work() {
                            found = true;
                            break;
                        }
                        block.header.nonce = block.header.nonce.wrapping_add(1);
                    }
                    if !found {
                        break;
                    }
                    hashes.push(self.submit_block(&block)?.hash.to_string());
                }
                Ok(json!(hashes))
            }
            "getblocktemplate" => {
                if self.state.network == Network::Signet {
                    return Err(internal("signet template signing is unavailable"));
                }
                let block = self.candidate(ScriptBuf::from_bytes(vec![0x51]))?;
                let data = self.lock()?;
                let previous = data
                    .headers
                    .get_header(&block.header.prev_blockhash)
                    .ok_or_else(|| internal("template parent unavailable"))?;
                Ok(
                    json!({ "version": block.header.version, "previousblockhash": block.header.prev_blockhash.to_string(),
                    "transactions": [], "coinbasevalue": block.transactions[0].outputs[0].value.as_sat(),
                    "target": compact_bits_to_target_hex(block.header.bits.to_u32()), "mintime": data.headers.median_time_past(previous) + 1,
                    "curtime": block.header.time, "height": previous.height + 1, "bits": format!("{:08x}", block.header.bits.to_u32()),
                    "noncerange": "00000000ffffffff", "sizelimit": 1000000, "weightlimit": 4000000, "sigoplimit": 80000,
                    "rules": ["csv", "segwit"], "capabilities": [], "mutable": ["time", "transactions", "prevblock"] }),
                )
            }
            _ => {
                let data = self.lock()?;
                let headers = &data.headers;
                let tip = headers.best_header();
                match method {
                    "getblockcount" => Ok(json!(tip.height)),
                    "getbestblockhash" => Ok(json!(tip.header.block_hash().to_string())),
                    "getblockhash" => {
                        let entry = headers
                            .get_header_by_height(unsigned_param(&params, 0)?)
                            .ok_or_else(|| RpcError::new(-8, "height out of range"))?;
                        Ok(json!(entry.header.block_hash().to_string()))
                    }
                    "getblockheader" => {
                        let hash = block_hash_param(&params)?;
                        if params.get(1) == Some(&Value::Bool(false)) {
                            let entry = headers
                                .get_header(&hash)
                                .ok_or_else(|| RpcError::new(-5, "block not found"))?;
                            Ok(json!(hex::encode(encode(&entry.header))))
                        } else {
                            self.header_json(headers, hash)
                        }
                    }
                    "getblock" => {
                        let hash = block_hash_param(&params)?;
                        let block = self
                            .db
                            .tx()
                            .map_err(internal)?
                            .get_block(&hash)
                            .map_err(internal)?
                            .ok_or_else(|| RpcError::new(-5, "block body unavailable"))?;
                        let verbosity = params.get(1).and_then(Value::as_u64).unwrap_or(1);
                        if verbosity == 0 {
                            return Ok(json!(hex::encode(encode(&block))));
                        }
                        if verbosity != 1 {
                            return Err(RpcError::new(
                                -8,
                                "only block verbosity 0 and 1 are supported",
                            ));
                        }
                        let mut result = self.header_json(headers, hash)?;
                        result["tx"] = json!(block
                            .transactions
                            .iter()
                            .map(|t| t.txid().to_string())
                            .collect::<Vec<_>>());
                        result["size"] = json!(encode(&block).len());
                        result["weight"] = json!(block.weight());
                        Ok(result)
                    }
                    "getrawtransaction" => {
                        let txid = TxHash::from_hex(string_param(&params, 0)?)
                            .map_err(|e| RpcError::new(-8, e.to_string()))?;
                        if params
                            .get(1)
                            .is_some_and(|v| *v != Value::Bool(false) && *v != json!(0))
                        {
                            return Err(RpcError::new(
                                -8,
                                "verbose transaction output is unavailable",
                            ));
                        }
                        let tx = self
                            .db
                            .tx()
                            .map_err(internal)?
                            .get_transaction(&txid)
                            .map_err(internal)?
                            .ok_or_else(|| RpcError::new(-5, "transaction not found"))?;
                        Ok(json!(hex::encode(encode(&tx))))
                    }
                    "gettxout" => {
                        let txid = TxHash::from_hex(string_param(&params, 0)?)
                            .map_err(|e| RpcError::new(-8, e.to_string()))?;
                        let vout = u32::try_from(unsigned_param(&params, 1)?)
                            .map_err(|_| RpcError::new(-8, "output index out of range"))?;
                        let Some(entry) = data.utxos.get_utxo(&OutPoint::new(txid, vout)) else {
                            return Ok(Value::Null);
                        };
                        Ok(
                            json!({ "bestblock": tip.header.block_hash().to_string(), "confirmations": tip.height - entry.height + 1,
                            "value": entry.txout.value.as_sat() as f64 / 100_000_000.0, "coinbase": entry.is_coinbase,
                            "scriptPubKey": { "hex": hex::encode(entry.txout.script_pubkey.as_bytes()) } }),
                        )
                    }
                    "getnetworkhashps" => Ok(json!(Self::network_hashps(
                        headers,
                        params.get(0).and_then(Value::as_i64).unwrap_or(120),
                        params.get(1).and_then(Value::as_i64).unwrap_or(-1)
                    )?)),
                    "getmininginfo" => Ok(
                        json!({ "blocks": tip.height, "difficulty": compact_bits_to_difficulty(tip.header.bits.to_u32()),
                        "networkhashps": Self::network_hashps(headers, 120, -1)?, "chain": self.state.rpc_network_name() }),
                    ),
                    "getblockchaininfo" => Ok(
                        json!({ "chain": self.state.rpc_network_name(), "blocks": tip.height, "headers": tip.height,
                        "bestblockhash": tip.header.block_hash().to_string(), "difficulty": compact_bits_to_difficulty(tip.header.bits.to_u32()),
                        "mediantime": headers.median_time_past(tip), "chainwork": hex::encode(tip.cumulative_work),
                        "initialblockdownload": self.state.syncing.load(std::sync::atomic::Ordering::SeqCst), "pruned": false, "warnings": "experimental node: full Core consensus parity remains unverified" }),
                    ),
                    _ => Err(RpcError::new(-32601, "method not found")),
                }
            }
        }
    }
}

fn string_param(params: &Value, index: usize) -> Result<&str, RpcError> {
    params.get(index).and_then(Value::as_str).ok_or_else(|| {
        RpcError::new(
            INVALID_PARAMS,
            format!("parameter {index} must be a string"),
        )
    })
}
fn unsigned_param(params: &Value, index: usize) -> Result<u64, RpcError> {
    params.get(index).and_then(Value::as_u64).ok_or_else(|| {
        RpcError::new(
            INVALID_PARAMS,
            format!("parameter {index} must be an unsigned integer"),
        )
    })
}
fn block_hash_param(params: &Value) -> Result<BlockHash, RpcError> {
    BlockHash::from_hex(string_param(params, 0)?).map_err(|e| RpcError::new(-8, e.to_string()))
}
fn rejection(error: impl std::fmt::Display) -> RpcError {
    RpcError::new(-26, error.to_string())
}
fn internal(error: impl std::fmt::Display) -> RpcError {
    RpcError::new(INTERNAL_ERROR, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::amount::Amount;
    use btc_rpc::handler::{RpcHandler, RpcRequest};
    use btc_test::TestKeyPair;

    fn handler(backend: &Arc<NodeChainBackend>) -> RpcHandler {
        let state = &backend.state;
        RpcHandler::new_with_state(
            state.chain_height.clone(),
            state.best_hash.clone(),
            state.rpc_network_name(),
            state.peer_count.clone(),
            state.mempool_size.clone(),
            state.mempool_bytes.clone(),
        )
        .with_chain_backend(backend.clone())
    }
    fn rpc(handler: &RpcHandler, method: &str, params: Value) -> Value {
        let response = handler.handle(&RpcRequest {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
            id: json!(17),
        });
        assert!(response.error.is_none(), "{method}: {:?}", response.error);
        assert_eq!(response.id, json!(17));
        response.result.unwrap()
    }
    fn mine(block: &mut Block) {
        block.header.merkle_root = block.compute_merkle_root();
        block.header.nonce = 0;
        while !block.header.check_proof_of_work() {
            block.header.nonce += 1;
        }
    }

    #[test]
    fn rpc_mining_mature_spend_rejection_and_restart_share_durable_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.redb");
        let state = NodeState::new(Network::Regtest);
        let backend = Arc::new(NodeChainBackend::open(&path, state.clone()).unwrap());
        let rpc_handler = handler(&backend);
        let key = TestKeyPair::from_secret(secp256k1::SecretKey::from_slice(&[7; 32]).unwrap());
        let address = Address::p2pkh_from_pubkey(&key.pubkey_bytes(), Network::Regtest).to_string();
        let hashes = rpc(&rpc_handler, "generatetoaddress", json!([100, address]));
        assert_eq!(hashes.as_array().unwrap().len(), 100);
        let first: Block = decode(
            &hex::decode(
                rpc(&rpc_handler, "getblock", json!([hashes[0], 0]))
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let previous = &first.transactions[0].outputs[0];
        let outpoint = OutPoint::new(first.transactions[0].txid(), 0);
        assert_eq!(
            rpc(
                &rpc_handler,
                "gettxout",
                json!([outpoint.txid.to_string(), 0])
            )["confirmations"],
            100
        );
        let mut spend = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(previous.value.as_sat() - 1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
            witness: vec![],
            lock_time: 0,
        };
        spend.inputs[0].script_sig = key.build_p2pkh_script_sig(&spend, 0, previous);
        let mut block = backend.candidate(key.p2pkh_script()).unwrap();
        block.transactions.push(spend.clone());
        mine(&mut block);
        let tip_before = rpc(&rpc_handler, "getbestblockhash", json!([]));

        let mut bad_pow = block.clone();
        while bad_pow.header.check_proof_of_work() {
            bad_pow.header.nonce += 1;
        }
        assert!(rpc(
            &rpc_handler,
            "submitblock",
            json!([hex::encode(encode(&bad_pow))])
        )
        .as_str()
        .unwrap()
        .contains("target"));
        let mut bad_script = block.clone();
        bad_script.transactions[1].inputs[0].script_sig = ScriptBuf::from_bytes(vec![0]);
        mine(&mut bad_script);
        assert!(rpc(
            &rpc_handler,
            "submitblock",
            json!([hex::encode(encode(&bad_script))])
        )
        .as_str()
        .unwrap()
        .contains("script"));
        assert_eq!(rpc(&rpc_handler, "getbestblockhash", json!([])), tip_before);
        assert!(!rpc(
            &rpc_handler,
            "gettxout",
            json!([outpoint.txid.to_string(), 0])
        )
        .is_null());

        assert!(rpc(
            &rpc_handler,
            "submitblock",
            json!([hex::encode(encode(&block))])
        )
        .is_null());
        assert_eq!(rpc(&rpc_handler, "getblockcount", json!([])), 101);
        assert_eq!(
            state.chain_height.load(std::sync::atomic::Ordering::SeqCst),
            101
        );
        assert!(rpc(
            &rpc_handler,
            "gettxout",
            json!([outpoint.txid.to_string(), 0])
        )
        .is_null());
        assert_eq!(
            rpc(&rpc_handler, "getblockhash", json!([101])),
            block.block_hash().to_string()
        );
        assert_eq!(
            rpc(
                &rpc_handler,
                "getrawtransaction",
                json!([spend.txid().to_string()])
            ),
            hex::encode(encode(&spend))
        );
        let header: BlockHeader = decode(
            &hex::decode(
                rpc(
                    &rpc_handler,
                    "getblockheader",
                    json!([block.block_hash().to_string(), false]),
                )
                .as_str()
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(header, block.header);
        drop(rpc_handler);
        drop(backend);

        let backend =
            Arc::new(NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).unwrap());
        let rpc_handler = handler(&backend);
        assert_eq!(rpc(&rpc_handler, "getblockcount", json!([])), 101);
        assert_eq!(
            rpc(&rpc_handler, "getbestblockhash", json!([])),
            block.block_hash().to_string()
        );
        assert!(rpc(
            &rpc_handler,
            "gettxout",
            json!([outpoint.txid.to_string(), 0])
        )
        .is_null());
        assert_eq!(
            rpc(
                &rpc_handler,
                "gettxout",
                json!([spend.txid().to_string(), 0])
            )["value"],
            previous.value.as_sat() as f64 / 100_000_000.0 - 0.00001
        );
    }

    #[test]
    fn regtest_coinbase_matches_core_height_encoding_and_halving() {
        let dir = tempfile::tempdir().unwrap();
        let backend = Arc::new(
            NodeChainBackend::open(
                &dir.path().join("chain.redb"),
                NodeState::new(Network::Regtest),
            )
            .unwrap(),
        );
        let rpc_handler = handler(&backend);
        let address = Address::P2wpkh {
            hash: [8; 20],
            network: Network::Regtest,
        }
        .to_string();
        let hashes = rpc(&rpc_handler, "generatetoaddress", json!([150, address]));
        for (height, prefix) in [
            (1, vec![0x51]),
            (16, vec![0x60]),
            (17, vec![1, 17]),
            (128, vec![2, 128, 0]),
        ] {
            let block: Block = decode(
                &hex::decode(
                    rpc(&rpc_handler, "getblock", json!([hashes[height - 1], 0]))
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
            assert!(block.transactions[0].inputs[0]
                .script_sig
                .as_bytes()
                .starts_with(&prefix));
        }
        let last: Block = decode(
            &hex::decode(
                rpc(&rpc_handler, "getblock", json!([hashes[149], 0]))
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            last.transactions[0].outputs[0].value.as_sat(),
            2_500_000_000
        );
        assert_eq!(
            rpc(&rpc_handler, "getblocktemplate", json!([]))["coinbasevalue"],
            2_500_000_000i64
        );
        assert_eq!(
            rpc(&rpc_handler, "getblocktemplate", json!([]))["bits"],
            "207fffff"
        );
    }

    #[test]
    fn unavailable_data_and_legacy_checkpoints_fail_explicitly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.redb");
        let backend =
            Arc::new(NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).unwrap());
        let rpc_handler = handler(&backend);
        for (method, params, code) in [
            ("getblockheader", json!(["aa".repeat(32)]), -5),
            ("getblockhash", json!([1]), -8),
            ("generatetoaddress", json!([1, "invalid address"]), -5),
            ("getblockhash", json!([-1]), INVALID_PARAMS),
            ("submitblock", json!(["ff"]), -22),
        ] {
            let response = rpc_handler.handle(&RpcRequest {
                jsonrpc: "2.0".into(),
                method: method.into(),
                params,
                id: json!(9),
            });
            assert_eq!(response.error.unwrap().code, code);
            assert!(response.result.is_none());
        }
        let mut block = backend
            .candidate(ScriptBuf::from_bytes(vec![0x51]))
            .unwrap();
        mine(&mut block);
        let mut raw = encode(&block);
        raw.push(0);
        let response = rpc_handler.handle(&RpcRequest {
            jsonrpc: "2.0".into(),
            method: "submitblock".into(),
            params: json!([hex::encode(raw)]),
            id: json!(1),
        });
        assert_eq!(response.error.unwrap().code, -22);
        assert_eq!(backend.tip().unwrap().0, 0);
        drop(rpc_handler);
        drop(backend);
        let db = RedbDatabase::new(&path).unwrap();
        let tx = db.tx_mut().unwrap();
        tx.set_best_block(42, &BlockHash::from_bytes([42; 32]))
            .unwrap();
        tx.commit().unwrap();
        drop(db);
        let error = NodeChainBackend::open(&path, NodeState::new(Network::Regtest))
            .err()
            .unwrap();
        assert!(error.to_string().contains("legacy checkpoint migration"));
        let db = RedbDatabase::new(&path).unwrap();
        assert_eq!(db.tx().unwrap().get_best_block_height().unwrap(), 42);
    }
}
