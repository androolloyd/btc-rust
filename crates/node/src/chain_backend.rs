//! The validated chain shared by RPC and block download.
//! Header-only download never advances this chain's UTXOs or published tip.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use btc_consensus::parallel::{ParallelConfig, ParallelValidator};
use btc_consensus::utxo::{
    connect_block_with_context, InMemoryUtxoSet, LockTimeContext, UtxoEntry, UtxoSet, UtxoSetUpdate,
};
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

pub(super) struct ValidatedChain {
    pub(super) headers: ChainState,
    utxos: PersistentUtxoSet<RedbDatabase>,
    pub(super) mempool: crate::mempool::RuntimeMempool,
    exex: Option<tokio::sync::broadcast::Sender<btc_exex::ExExNotification>>,
}

pub struct NodeChainBackend {
    data: Mutex<ValidatedChain>,
    pub(super) db: Arc<RedbDatabase>,
    state: NodeState,
    block_events: tokio::sync::broadcast::Sender<BlockHash>,
    tx_events: tokio::sync::broadcast::Sender<TxHash>,
    wallet_events: tokio::sync::watch::Sender<u64>,
    pub(super) header_proofs: Mutex<crate::header_proofs::HeaderProofCache>,
    legacy_checkpoint: Option<btc_storage::redb_backend::LegacyCheckpointArchive>,
}

#[derive(Debug)]
pub struct AcceptedBlock {
    pub height: u64,
    pub hash: BlockHash,
    pub update: UtxoSetUpdate,
    pub active: bool,
}

struct CoinOverlay<'a> {
    base: &'a dyn UtxoSet,
    changes: HashMap<OutPoint, Option<UtxoEntry>>,
}
impl UtxoSet for CoinOverlay<'_> {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        match self.changes.get(outpoint) {
            Some(value) => value.clone(),
            None => self.base.get_utxo(outpoint),
        }
    }
}
impl CoinOverlay<'_> {
    fn connect(&mut self, update: &UtxoSetUpdate) {
        let spent: HashSet<_> = update.spent.iter().map(|(op, _)| *op).collect();
        for (op, _) in &update.spent {
            self.changes.insert(*op, None);
        }
        for (op, entry) in &update.created {
            if !spent.contains(op) {
                self.changes.insert(*op, Some(entry.clone()));
            }
        }
    }
    fn disconnect(&mut self, update: &UtxoSetUpdate) {
        let created: HashSet<_> = update.created.iter().map(|(op, _)| *op).collect();
        for (op, _) in &update.created {
            self.changes.insert(*op, None);
        }
        for (op, entry) in &update.spent {
            if !created.contains(op) {
                self.changes.insert(*op, Some(entry.clone()));
            }
        }
    }
}

impl NodeChainBackend {
    pub fn open(path: &Path, state: NodeState) -> eyre::Result<Self> {
        Self::open_with_legacy_resync(path, state, false)
    }

    pub fn open_with_legacy_resync(
        path: &Path,
        state: NodeState,
        resync: bool,
    ) -> eyre::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = Arc::new(RedbDatabase::new(path)?);
        db.init_tables()?;
        let mut params = ChainParams::from_network(state.network);
        // RPC submissions always run scripts; an assume-valid shortcut cannot
        // be inferred merely from a matching incoming block hash.
        params.assume_valid = None;
        let mut headers = ChainState::new(params);
        let genesis = headers.best_header().header;
        if resync {
            if let Some(archive) = db.resync_legacy_checkpoint(&genesis)? {
                tracing::warn!(height = archive.height, hash = %archive.hash,
                    "preserved unverified legacy checkpoint tables; validation resuming from genesis");
            }
        }
        let legacy_checkpoint = db.legacy_checkpoint_archive()?;
        if legacy_checkpoint
            .as_ref()
            .is_some_and(|archive| archive.genesis != genesis.block_hash())
        {
            return Err(eyre::eyre!(
                "legacy checkpoint archive belongs to another network"
            ));
        }
        let utxos = PersistentUtxoSet::new(Arc::clone(&db));
        if let Some((height, expected)) = utxos.validated_tip()? {
            if height == 0 && db.coin_count()? != 0 {
                return Err(eyre::eyre!("genesis checkpoint contains unvalidated coins"));
            }
            let tx = db.tx()?;
            for h in 1..=height {
                let hash = tx.get_block_hash_by_height(h)?.ok_or_else(|| eyre::eyre!(
                    "committed chain lacks header history at height {h}; legacy checkpoint migration requires run --resync-legacy-checkpoint (archives tip-only tables), or a separate data directory for partial histories"
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
            if db.tx()?.get_best_block_height()? != 0
                || db.coin_count()? != 0
                || !db.stored_headers()?.is_empty()
            {
                return Err(eyre::eyre!(
                    "database has coins/history or a height without a committed tip"
                ));
            }
            let genesis = headers.best_header().header.clone();
            let hash = genesis.block_hash();
            let tx = db.tx_mut()?;
            tx.put_block_header(&hash, &genesis)?;
            tx.put_block_hash_by_height(0, &hash)?;
            tx.set_best_block(0, &hash)?;
            tx.commit()?;
        }
        // Restore side branches after the active path so equal-work ties retain
        // the persisted selection. Every stored side header has a validated body.
        let mut pending: Vec<_> = db
            .stored_headers()?
            .into_iter()
            .filter(|header| headers.get_header(&header.block_hash()).is_none())
            .collect();
        while !pending.is_empty() {
            let old_len = pending.len();
            let mut retry = Vec::new();
            for header in pending {
                if headers.get_header(&header.prev_blockhash).is_some() {
                    headers.accept_header(header)?;
                } else {
                    retry.push(header);
                }
            }
            if retry.len() == old_len {
                return Err(eyre::eyre!("stored branch has missing ancestry"));
            }
            pending = retry;
        }
        if utxos
            .validated_tip()?
            .is_some_and(|(_, hash)| hash != headers.best_header().header.block_hash())
        {
            return Err(eyre::eyre!(
                "stored branch work disagrees with committed tip"
            ));
        }
        Self::backfill_undo(&db, &headers, &utxos).map_err(|e| eyre::eyre!(e.message))?;
        Self::initialize_script_index(&db, &headers, &utxos).map_err(|e| eyre::eyre!(e.message))?;
        let persisted_pool = db.mempool_transactions()?;
        let reader = db.tx()?;
        let mut confirmed = HashSet::new();
        for transaction in &persisted_pool {
            if reader.get_tx_block_index(&transaction.txid())?.is_some() {
                confirmed.insert(transaction.txid());
            }
        }
        drop(reader);
        let mempool = crate::mempool::RuntimeMempool::rebuild(
            persisted_pool,
            &confirmed,
            &utxos,
            &headers,
            None,
            None,
        );
        state.update_mempool(mempool.entries.len() as u64, mempool.bytes as u64);
        state.update_chain_tip(
            headers.best_height(),
            &headers.best_header().header.block_hash().to_string(),
        );
        Ok(Self {
            data: Mutex::new(ValidatedChain {
                headers,
                utxos,
                mempool,
                exex: None,
            }),
            db,
            state,
            block_events: tokio::sync::broadcast::channel(256).0,
            tx_events: tokio::sync::broadcast::channel(1024).0,
            wallet_events: tokio::sync::watch::channel(0).0,
            header_proofs: Mutex::new(crate::header_proofs::HeaderProofCache::default()),
            legacy_checkpoint,
        })
    }

    pub fn subscribe_blocks(&self) -> tokio::sync::broadcast::Receiver<BlockHash> {
        self.block_events.subscribe()
    }
    pub fn locator_hashes(&self) -> Result<Vec<BlockHash>, RpcError> {
        Ok(self.lock()?.headers.get_locator_hashes())
    }

    pub fn header(&self, hash: &BlockHash) -> Result<Option<BlockHeader>, RpcError> {
        Ok(self
            .lock()?
            .headers
            .get_header(hash)
            .map(|entry| entry.header))
    }

    pub fn header_height(&self, hash: &BlockHash) -> Result<Option<u64>, RpcError> {
        Ok(self
            .lock()?
            .headers
            .get_header(hash)
            .map(|entry| entry.height))
    }

    pub fn headers_after(
        &self,
        locator: &[BlockHash],
        stop: BlockHash,
        limit: usize,
    ) -> Result<Vec<BlockHeader>, RpcError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let data = self.lock()?;
        let headers = &data.headers;
        if locator.is_empty() {
            return Ok(headers
                .get_header(&stop)
                .map(|e| vec![e.header])
                .unwrap_or_default());
        }
        let start = locator
            .iter()
            .find_map(|hash| {
                headers
                    .get_header(hash)
                    .filter(|e| {
                        headers
                            .get_header_by_height(e.height)
                            .is_some_and(|active| active.header.block_hash() == *hash)
                    })
                    .map(|e| e.height)
            })
            .unwrap_or(0);
        let mut result = Vec::new();
        for height in start + 1..=headers.best_height() {
            let header = headers
                .get_header_by_height(height)
                .ok_or_else(|| internal("header index incomplete"))?
                .header;
            result.push(header);
            if result.len() >= limit.min(2000) || header.block_hash() == stop {
                break;
            }
        }
        Ok(result)
    }

    pub fn block(&self, hash: &BlockHash) -> Result<Option<Block>, RpcError> {
        self.db
            .tx()
            .map_err(internal)?
            .get_block(hash)
            .map_err(internal)
    }

    pub fn transaction(&self, hash: &TxHash) -> Result<Option<Transaction>, RpcError> {
        if let Some(entry) = self.lock()?.mempool.entries.get(hash) {
            return Ok(Some(entry.tx.clone()));
        }
        self.db
            .tx()
            .map_err(internal)?
            .get_transaction(hash)
            .map_err(internal)
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

    fn validate_block_against(
        block: &Block,
        height: u64,
        headers: &ChainState,
        coins: &dyn UtxoSet,
    ) -> Result<UtxoSetUpdate, RpcError> {
        let params = headers.params();
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
        let prev = headers
            .get_header(&block.header.prev_blockhash)
            .ok_or_else(|| rejection("unknown parent"))?;
        let ancestor_mtp = |h| {
            headers
                .get_header_by_height(h)
                .map(|e| headers.median_time_past(e))
        };
        let context = LockTimeContext {
            median_time_past: headers.median_time_past(prev),
            ancestor_mtp: &ancestor_mtp,
        };
        let update = connect_block_with_context(block, height, coins, params, Some(&context))
            .map_err(rejection)?;
        ParallelValidator::new(ParallelConfig::default())
            .validate_block_scripts(block, coins, height, params)
            .map_err(|errors| rejection(format!("script verification failed: {errors:?}")))?;
        Ok(update)
    }

    fn undo(&self, hash: BlockHash) -> Result<UtxoSetUpdate, RpcError> {
        let raw = self
            .db
            .tx()
            .map_err(internal)?
            .get_block_undo(&hash)
            .map_err(internal)?
            .ok_or_else(|| internal(format!("missing undo for {hash}")))?;
        btc_storage::undo::decode_undo(hash, &raw).map_err(internal)
    }

    /// Validate side branches with fork-specific coins and MTP. Publish the
    /// winning chain only after the entire disconnect/reconnect commits.
    pub fn submit_block(&self, block: &Block) -> Result<AcceptedBlock, RpcError> {
        let mut data = self.lock()?;
        let hash = block.block_hash();
        if data.headers.get_header(&hash).is_some() {
            return Err(RpcError::new(-27, "duplicate"));
        }
        let parent = data
            .headers
            .get_header(&block.header.prev_blockhash)
            .ok_or_else(|| RpcError::new(-25, "unknown block parent"))?
            .clone();
        let height = parent.height + 1;
        let old_tip = data.headers.best_header().header.block_hash();
        let old_height = data.headers.best_height();
        let extension = block.header.prev_blockhash == old_tip;
        let mut branch = None;
        let mut detached = Vec::new();
        let mut attached = Vec::new();
        let mut attached_updates = HashMap::new();
        let mut overlay = CoinOverlay {
            base: &data.utxos,
            changes: HashMap::new(),
        };
        let mut fork_hash = old_tip;
        if !extension {
            let mut cursor = block.header.prev_blockhash;
            let mut reconnect = Vec::new();
            loop {
                let entry = data
                    .headers
                    .get_header(&cursor)
                    .ok_or_else(|| internal("fork ancestry missing"))?;
                if data
                    .headers
                    .get_header_by_height(entry.height)
                    .is_some_and(|active| active.header.block_hash() == cursor)
                {
                    fork_hash = cursor;
                    break;
                }
                reconnect.push((entry.height, cursor));
                cursor = entry.header.prev_blockhash;
            }
            let mut cursor = old_tip;
            while cursor != fork_hash {
                let entry = data
                    .headers
                    .get_header(&cursor)
                    .ok_or_else(|| internal("active ancestry missing"))?;
                let body = self
                    .block(&cursor)?
                    .ok_or_else(|| internal("active body missing"))?;
                overlay.disconnect(&self.undo(cursor)?);
                detached.push((entry.height, body));
                cursor = entry.header.prev_blockhash;
            }
            for (height, hash) in reconnect.into_iter().rev() {
                let undo = self.undo(hash)?;
                overlay.connect(&undo);
                attached_updates.insert(hash, undo);
                attached.push((
                    height,
                    self.block(&hash)?
                        .ok_or_else(|| internal("branch body missing"))?,
                ));
            }
            let mut context = data.headers.clone();
            context
                .select_tip(block.header.prev_blockhash)
                .map_err(rejection)?;
            context.accept_header(block.header).map_err(rejection)?;
            branch = Some(context);
        }
        let context = branch.as_ref().unwrap_or(&data.headers);
        let update = Self::validate_block_against(block, height, context, &overlay)?;
        overlay.connect(&update);
        let active = extension
            || context.best_header().cumulative_work > data.headers.best_header().cumulative_work;
        let (pool, changes) = if active {
            attached.push((height, block.clone()));
            attached_updates.insert(hash, update.clone());
            let mut candidates = data.mempool.transactions();
            for (_, body) in detached.iter().rev() {
                candidates.extend(body.transactions.iter().skip(1).cloned());
            }
            let confirmed: HashSet<_> = attached
                .iter()
                .flat_map(|(_, b)| b.transactions.iter().map(Transaction::txid))
                .collect();
            // Evaluate new lock points from the actual candidate header without
            // cloning the complete chain on every linear extension.
            let next_pool = {
                crate::mempool::RuntimeMempool::rebuild(
                    candidates,
                    &confirmed,
                    &overlay,
                    context,
                    Some(&data.mempool),
                    extension.then_some(&block.header),
                )
            };
            (next_pool, overlay.changes)
        } else {
            (data.mempool.empty_like(), HashMap::new())
        };
        let pool_transactions = pool.transactions();
        let ValidatedChain { headers, utxos, .. } = &mut *data;
        headers
            .accept_header_with_commit(block.header, || {
                utxos
                    .commit_chain_transition(btc_storage::utxo_store::ChainTransition {
                        incoming: block,
                        height,
                        undo: &update,
                        detached: if active { &detached } else { &[] },
                        attached: if active { &attached } else { &[] },
                        coins: &changes,
                        tip: active.then_some((height, hash)),
                        old_height,
                        mempool: &pool_transactions,
                    })
                    .map_err(|e| e.to_string())
            })
            .map_err(|error| match error {
                btc_consensus::chain::ChainError::CommitFailed(message) => internal(message),
                other => rejection(other),
            })?;
        if active {
            data.mempool = pool;
            self.state
                .update_mempool(data.mempool.entries.len() as u64, data.mempool.bytes as u64);
            self.state.update_chain_tip(height, &hash.to_string());
            if let Some(sender) = &data.exex {
                for (height, body) in &detached {
                    let _ = sender.send(btc_exex::ExExNotification::BlockReverted {
                        height: *height,
                        hash: body.block_hash(),
                    });
                }
                for (height, body) in &attached {
                    let undo = attached_updates[&body.block_hash()].clone();
                    let _ = sender.send(btc_exex::ExExNotification::BlockCommitted {
                        height: *height,
                        hash: body.block_hash(),
                        block: body.clone(),
                        utxo_changes: undo,
                    });
                }
                if !detached.is_empty() {
                    let _ = sender.send(btc_exex::ExExNotification::ChainReorged {
                        old_tip,
                        new_tip: hash,
                        fork_height: data.headers.get_header(&fork_hash).unwrap().height,
                        reverted: detached.iter().map(|(_, b)| b.block_hash()).collect(),
                        committed: attached.iter().map(|(h, b)| (*h, b.block_hash())).collect(),
                    });
                }
            }
            self.wallet_events
                .send_modify(|revision| *revision = revision.wrapping_add(1));
            let _ = self.block_events.send(hash);
            // Reaccepted disconnected transactions must be announced again.
            for txid in &data.mempool.order {
                let _ = self.tx_events.send(*txid);
            }
        }
        Ok(AcceptedBlock {
            height,
            hash,
            update,
            active,
        })
    }

    pub fn configure_mempool(
        &self,
        full_rbf: bool,
        policy: btc_mempool::policy::TxValidationPolicy,
        flags: btc_consensus::script_engine::ScriptFlags,
    ) -> Result<(), RpcError> {
        let mut data = self.lock()?;
        let mut settings = data.mempool.empty_like();
        settings.full_rbf = full_rbf;
        settings.policy = policy;
        settings.flags = flags;
        let pool = crate::mempool::RuntimeMempool::rebuild(
            data.mempool.transactions(),
            &HashSet::new(),
            &data.utxos,
            &data.headers,
            Some(&settings),
            None,
        );
        let write = self.db.tx_mut().map_err(internal)?;
        write
            .replace_mempool(&pool.transactions())
            .map_err(internal)?;
        write.commit().map_err(internal)?;
        data.mempool = pool;
        self.state
            .update_mempool(data.mempool.entries.len() as u64, data.mempool.bytes as u64);
        self.wallet_events
            .send_modify(|revision| *revision = revision.wrapping_add(1));
        Ok(())
    }
    pub fn set_exex_sender(
        &self,
        sender: tokio::sync::broadcast::Sender<btc_exex::ExExNotification>,
    ) -> Result<(), RpcError> {
        self.lock()?.exex = Some(sender);
        Ok(())
    }
    pub fn subscribe_transactions(&self) -> tokio::sync::broadcast::Receiver<TxHash> {
        self.tx_events.subscribe()
    }
    pub fn submit_transaction(&self, tx: Transaction) -> Result<TxHash, RpcError> {
        self.submit_transaction_capped(tx, None)
    }
    fn submit_transaction_capped(
        &self,
        tx: Transaction,
        limits: Option<RpcFeeLimits>,
    ) -> Result<TxHash, RpcError> {
        let mut data = self.lock()?;
        let id = tx.txid();
        if self
            .db
            .tx()
            .map_err(internal)?
            .get_tx_block_index(&id)
            .map_err(internal)?
            .is_some()
        {
            return Err(RpcError::new(-27, "transaction already in active chain"));
        }
        let mut pool = data.mempool.clone();
        pool.admit(tx.clone(), &data.utxos, &data.headers)?;
        if let Some(limits) = limits {
            limits.check(&tx, pool.entries[&id].fee)?;
        }
        let write = self.db.tx_mut().map_err(internal)?;
        write
            .replace_mempool(&pool.transactions())
            .map_err(internal)?;
        write.commit().map_err(internal)?;
        data.mempool = pool;
        self.state
            .update_mempool(data.mempool.entries.len() as u64, data.mempool.bytes as u64);
        self.wallet_events
            .send_modify(|revision| *revision = revision.wrapping_add(1));
        let _ = self.tx_events.send(id);
        Ok(id)
    }
    pub fn mempool_transaction(
        &self,
        hash: TxHash,
        witness_id: bool,
    ) -> Result<Option<Transaction>, RpcError> {
        let data = self.lock()?;
        Ok(if witness_id {
            data.mempool.entries.values().find(|e| e.tx.wtxid() == hash)
        } else {
            data.mempool.entries.get(&hash)
        }
        .map(|e| e.tx.clone()))
    }
    pub fn mempool_transactions(&self) -> Result<Vec<Transaction>, RpcError> {
        Ok(self.lock()?.mempool.transactions())
    }

    fn backfill_undo(
        db: &RedbDatabase,
        headers: &ChainState,
        coins: &dyn UtxoSet,
    ) -> Result<(), RpcError> {
        let reader = db.tx().map_err(internal)?;
        let missing = (1..=headers.best_height()).any(|height| {
            let hash = headers
                .get_header_by_height(height)
                .unwrap()
                .header
                .block_hash();
            !matches!(reader.get_block_undo(&hash), Ok(Some(_)))
        });
        if !missing {
            return Ok(());
        }
        // Older body/history databases can gain undo only by a verified replay.
        let mut replay = InMemoryUtxoSet::new();
        let mut records = Vec::new();
        for height in 1..=headers.best_height() {
            let hash = headers
                .get_header_by_height(height)
                .unwrap()
                .header
                .block_hash();
            let body = reader
                .get_block(&hash)
                .map_err(internal)?
                .ok_or_else(|| internal("undo migration requires stored bodies"))?;
            let update = Self::validate_block_against(&body, height, headers, &replay)?;
            replay.apply_update(&update);
            records.push((hash, btc_storage::undo::encode_undo(hash, &update)));
        }
        if db.coin_count().map_err(internal)? != replay.len()
            || replay
                .iter()
                .any(|(op, entry)| coins.get_utxo(op).as_ref() != Some(entry))
        {
            return Err(internal(
                "undo migration replay does not match committed coins",
            ));
        }
        drop(reader);
        let write = db.tx_mut().map_err(internal)?;
        for (hash, raw) in records {
            write.put_block_undo(&hash, &raw).map_err(internal)?;
        }
        write.commit().map_err(internal)
    }

    /// Existing bodies become script history only after script-verified replay
    /// produces exactly the durable coins. A single commit publishes all rows.
    fn initialize_script_index(
        db: &RedbDatabase,
        headers: &ChainState,
        coins: &dyn UtxoSet,
    ) -> Result<(), RpcError> {
        if db.verify_script_index().map_err(internal)? {
            return Ok(());
        }
        let mut replay = InMemoryUtxoSet::new();
        let write = db.tx_mut().map_err(internal)?;
        write.reset_uninitialized_script_index().map_err(internal)?;
        for height in 1..=headers.best_height() {
            let header = &headers
                .get_header_by_height(height)
                .ok_or_else(|| internal("script index migration header missing"))?
                .header;
            let hash = header.block_hash();
            let body = write
                .get_block(&hash)
                .map_err(internal)?
                .ok_or_else(|| internal("script index migration requires validated bodies"))?;
            if body.header != *header {
                return Err(internal("script index migration body/header mismatch"));
            }
            let update = Self::validate_block_against(&body, height, headers, &replay)?;
            let raw = write
                .get_block_undo(&hash)
                .map_err(internal)?
                .ok_or_else(|| internal("script index migration requires undo"))?;
            if raw != btc_storage::undo::encode_undo(hash, &update) {
                return Err(internal(
                    "script index migration undo does not match verified replay",
                ));
            }
            write
                .index_script_block(height, &body, &update, false)
                .map_err(internal)?;
            replay.apply_update(&update);
        }
        if db.coin_count().map_err(internal)? != replay.len()
            || replay
                .iter()
                .any(|(op, entry)| coins.get_utxo(op).as_ref() != Some(entry))
        {
            return Err(internal(
                "script index migration replay does not match committed coins",
            ));
        }
        write
            .set_script_index_tip(
                headers.best_height(),
                &headers.best_header().header.block_hash(),
            )
            .map_err(internal)?;
        write.commit().map_err(internal)
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
        let mut selected = HashSet::new();
        let mut fees = 0i64;
        let mut sigops = btc_consensus::sigops::legacy_sigop_cost(&block.transactions[0]);
        for id in &data.mempool.order {
            let entry = &data.mempool.entries[id];
            if entry.tx.inputs.iter().any(|input| {
                data.mempool
                    .entries
                    .contains_key(&input.previous_output.txid)
                    && !selected.contains(&input.previous_output.txid)
            }) {
                continue;
            }
            if block.weight() + entry.tx.weight() + 1000 > 4_000_000 {
                continue;
            }
            if sigops.saturating_add(entry.sigop_cost)
                > btc_consensus::sigops::MAX_BLOCK_SIGOPS_COST
            {
                continue;
            }
            sigops += entry.sigop_cost;
            fees = fees
                .checked_add(entry.fee)
                .ok_or_else(|| internal("template fee overflow"))?;
            selected.insert(*id);
            block.transactions.push(entry.tx.clone());
        }
        block.transactions[0].outputs[0].value = btc_primitives::Amount::from_sat(
            block.transactions[0].outputs[0].value.as_sat() + fees,
        );
        if block
            .transactions
            .iter()
            .skip(1)
            .any(Transaction::is_segwit)
        {
            let mut wtxids = vec![[0u8; 32]];
            wtxids.extend(
                block
                    .transactions
                    .iter()
                    .skip(1)
                    .map(|tx| tx.wtxid().to_bytes()),
            );
            let mut preimage = btc_primitives::block::merkle_root(&wtxids).to_vec();
            preimage.extend_from_slice(&[0u8; 32]);
            let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
            script.extend_from_slice(&btc_primitives::hash::sha256d(&preimage));
            block.transactions[0].outputs.push(TxOut {
                value: btc_primitives::Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(script),
            });
            block.transactions[0].witness =
                vec![btc_primitives::transaction::Witness::from_items(vec![
                    vec![0u8; 32],
                ])];
        }
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
        let active = headers
            .get_header_by_height(entry.height)
            .is_some_and(|e| e.header.block_hash() == hash);
        let confirmations = if active {
            (headers.best_height() - entry.height + 1) as i64
        } else {
            -1
        };
        let mut result = json!({
            "hash": hash.to_string(), "confirmations": confirmations,
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
        if active {
            if let Some(next) = headers.get_header_by_height(entry.height + 1) {
                result["nextblockhash"] = json!(next.header.block_hash().to_string());
            }
        }
        Ok(result)
    }

    fn rpc_undo(&self, hash: BlockHash) -> Result<HashMap<OutPoint, UtxoEntry>, RpcError> {
        let mut coins = HashMap::new();
        for (outpoint, coin) in self.undo(hash)?.spent {
            if coins.insert(outpoint, coin).is_some() {
                return Err(internal("duplicate input in block undo"));
            }
        }
        Ok(coins)
    }

    fn raw_transaction_json(
        &self,
        data: &ValidatedChain,
        params: &Value,
    ) -> Result<Value, RpcError> {
        use crate::rpc_transaction::{transaction_json, verbosity};
        let txid = TxHash::from_hex(string_param(params, 0)?)
            .map_err(|e| RpcError::new(-8, e.to_string()))?;
        if txid
            == data
                .headers
                .get_header_by_height(0)
                .unwrap()
                .header
                .merkle_root
        {
            return Err(RpcError::new(
                -5,
                "the genesis coinbase cannot be retrieved as an ordinary transaction",
            ));
        }
        let level = verbosity(params, 0)?;
        let explicit = match params.get(2) {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                BlockHash::from_hex(
                    value
                        .as_str()
                        .ok_or_else(|| RpcError::new(-3, "blockhash must be a string"))?,
                )
                .map_err(|e| RpcError::new(-8, e.to_string()))?,
            ),
        };
        let reader = self.db.tx().map_err(internal)?;
        let (tx, block_hash) = if let Some(hash) = explicit {
            if data.headers.get_header(&hash).is_none() {
                return Err(RpcError::new(-5, "block hash not found"));
            }
            let block = reader
                .get_block(&hash)
                .map_err(internal)?
                .ok_or_else(|| RpcError::new(-1, "block body unavailable"))?;
            let tx = block
                .transactions
                .into_iter()
                .find(|tx| tx.txid() == txid)
                .ok_or_else(|| RpcError::new(-5, "transaction not found in the provided block"))?;
            (tx, Some(hash))
        } else if let Some(entry) = data.mempool.entries.get(&txid) {
            (entry.tx.clone(), None)
        } else {
            // The persistent index describes the active chain. Retained side
            // bodies must be queried with their explicit block hash; a detached
            // transaction record alone cannot supply confirmation context.
            let location = reader.get_tx_block_index(&txid).map_err(internal)?
                .ok_or_else(|| RpcError::new(-5, "transaction not found in mempool or active chain; provide a block hash for retained branches"))?;
            let entry = data
                .headers
                .get_header(&location.block_hash)
                .ok_or_else(|| internal("indexed transaction block header missing"))?;
            if !data
                .headers
                .get_header_by_height(entry.height)
                .is_some_and(|header| header.header.block_hash() == location.block_hash)
            {
                return Err(internal(
                    "transaction index points outside the active chain",
                ));
            }
            let block = reader
                .get_block(&location.block_hash)
                .map_err(internal)?
                .ok_or_else(|| internal("indexed transaction block body missing"))?;
            let tx = block
                .transactions
                .get(location.tx_position as usize)
                .filter(|tx| tx.txid() == txid)
                .cloned()
                .ok_or_else(|| internal("transaction location disagrees with block body"))?;
            (tx, Some(location.block_hash))
        };
        drop(reader);
        if level <= 0 {
            return Ok(json!(hex::encode(encode(&tx))));
        }
        let undo = if level >= 2 && !tx.is_coinbase() {
            block_hash.map(|hash| self.rpc_undo(hash)).transpose()?
        } else {
            None
        };
        let mut result = transaction_json(&tx, self.state.network, undo.as_ref(), level >= 2)?;
        if let Some(hash) = block_hash {
            let entry = data
                .headers
                .get_header(&hash)
                .ok_or_else(|| internal("transaction block header missing"))?;
            let active = data
                .headers
                .get_header_by_height(entry.height)
                .is_some_and(|entry| entry.header.block_hash() == hash);
            if explicit.is_none() && !active {
                return Err(internal(
                    "transaction index points outside the active chain",
                ));
            }
            result["blockhash"] = json!(hash.to_string());
            result["confirmations"] = json!(if active {
                data.headers.best_height() - entry.height + 1
            } else {
                0
            });
            if active {
                result["time"] = json!(entry.header.time);
                result["blocktime"] = json!(entry.header.time);
            }
            if explicit.is_some() {
                result["in_active_chain"] = json!(active);
            }
        }
        Ok(result)
    }
}

impl btc_electrum::ElectrumBackend for NodeChainBackend {
    fn subscribe_scripts(&self) -> Option<tokio::sync::watch::Receiver<u64>> {
        Some(self.wallet_events.subscribe())
    }
    fn script_statuses(
        &self,
        scripts: &[String],
    ) -> Result<Vec<Value>, btc_electrum::ElectrumRpcError> {
        let fail = |error: RpcError| btc_electrum::ElectrumRpcError {
            code: error.code,
            message: error.message,
        };
        let data = self.lock().map_err(fail)?;
        self.electrum_statuses(&data, scripts).map_err(fail)
    }

    fn subscribe_headers(&self) -> tokio::sync::broadcast::Receiver<BlockHash> {
        self.subscribe_blocks()
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, btc_electrum::ElectrumRpcError> {
        use btc_electrum::methods::*;
        let fail = |code, message: &str| btc_electrum::ElectrumRpcError {
            code,
            message: message.into(),
        };
        let map_error = |error: RpcError| btc_electrum::ElectrumRpcError {
            code: if error.code == INTERNAL_ERROR {
                INTERNAL_ERROR
            } else {
                1
            },
            message: error.message,
        };
        let number = |index: usize| {
            params
                .get(index)
                .and_then(Value::as_u64)
                .ok_or_else(|| fail(INVALID_PARAMS, "expected nonnegative integer"))
        };
        let string = |index: usize| {
            params
                .get(index)
                .and_then(Value::as_str)
                .ok_or_else(|| fail(INVALID_PARAMS, "expected string"))
        };
        if method == METHOD_TRANSACTION_BROADCAST {
            return ChainBackend::call(self, "sendrawtransaction", json!([string(0)?]))
                .map_err(map_error);
        }
        if method == METHOD_TRANSACTION_GET {
            let verbose = match params.get(1) {
                None | Some(Value::Null) => false,
                Some(value) => value
                    .as_bool()
                    .ok_or_else(|| fail(INVALID_PARAMS, "verbose must be boolean"))?,
            };
            return ChainBackend::call(self, "getrawtransaction", json!([string(0)?, verbose]))
                .map_err(map_error);
        }
        let data = self.lock().map_err(map_error)?;
        if matches!(
            method,
            METHOD_SCRIPTHASH_GET_HISTORY
                | METHOD_SCRIPTHASH_GET_MEMPOOL
                | METHOD_SCRIPTHASH_GET_BALANCE
                | METHOD_SCRIPTHASH_LISTUNSPENT
        ) {
            let script = string(0)?;
            if script.len() != 64 {
                return Err(fail(
                    INVALID_PARAMS,
                    "scripthash must be 32-byte hexadecimal",
                ));
            }
            let mut hash: [u8; 32] = hex::decode(script)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| fail(INVALID_PARAMS, "scripthash must be 32-byte hexadecimal"))?;
            hash.reverse();
            return self
                .electrum_wallet(&data, method, &hash)
                .map_err(map_error);
        }
        let header = |height| {
            data.headers
                .get_header_by_height(height)
                .ok_or_else(|| fail(1, "header height unavailable"))
        };
        match method {
            METHOD_HEADERS_SUBSCRIBE => Ok(
                json!({"height":data.headers.best_height(), "hex":hex::encode(encode(&data.headers.best_header().header))}),
            ),
            METHOD_BLOCK_HEADER | METHOD_BLOCK_HEADERS => {
                let cp_index = if method == METHOD_BLOCK_HEADER { 1 } else { 2 };
                let checkpoint = match params.get(cp_index) {
                    None | Some(Value::Null) => 0,
                    Some(_) => number(cp_index)?,
                };
                let start = number(0)?;
                if method == METHOD_BLOCK_HEADER {
                    let bytes = hex::encode(encode(&header(start)?.header));
                    if checkpoint == 0 {
                        return Ok(json!(bytes));
                    }
                    let mut proof = self
                        .header_checkpoint_proof(&data, start, checkpoint)
                        .map_err(map_error)?;
                    proof["header"] = json!(bytes);
                    return Ok(proof);
                }
                let count = number(1)?.min(2016);
                let available = if start > data.headers.best_height() {
                    0
                } else {
                    data.headers.best_height() - start + 1
                };
                let count = count.min(available);
                let mut bytes = Vec::with_capacity(count as usize * 80);
                for offset in 0..count {
                    bytes.extend(encode(&header(start + offset)?.header));
                }
                let mut result = json!({"count":count, "hex":hex::encode(bytes), "max":2016});
                // ElectrumX attaches a proof only for nonempty actual output,
                // using the last returned header after chunk/tip truncation.
                if count != 0 && checkpoint != 0 {
                    let last = start
                        .checked_add(count - 1)
                        .ok_or_else(|| fail(INVALID_PARAMS, "header range overflow"))?;
                    let proof = self
                        .header_checkpoint_proof(&data, last, checkpoint)
                        .map_err(map_error)?;
                    result["branch"] = proof["branch"].clone();
                    result["root"] = proof["root"].clone();
                }
                Ok(result)
            }
            METHOD_TRANSACTION_GET_MERKLE => {
                let txid = TxHash::from_hex(string(0)?)
                    .map_err(|_| fail(INVALID_PARAMS, "invalid transaction hash"))?;
                let height = number(1)?;
                let hash = header(height)?.header.block_hash();
                let block = self
                    .db
                    .tx()
                    .map_err(|e| fail(INTERNAL_ERROR, &e.to_string()))?
                    .get_block(&hash)
                    .map_err(|e| fail(INTERNAL_ERROR, &e.to_string()))?
                    .ok_or_else(|| fail(1, "block body unavailable"))?;
                if block.block_hash() != hash || !block.check_merkle_root() {
                    return Err(fail(
                        INTERNAL_ERROR,
                        "stored block body disagrees with header",
                    ));
                }
                let position = block
                    .transactions
                    .iter()
                    .position(|tx| tx.txid() == txid)
                    .ok_or_else(|| {
                        fail(1, "transaction is not in the active block at that height")
                    })?;
                let mut index = position;
                let mut hashes: Vec<_> = block
                    .transactions
                    .iter()
                    .map(|tx| tx.txid().to_bytes())
                    .collect();
                let mut branch = Vec::new();
                while hashes.len() > 1 {
                    branch.push(
                        TxHash::from_bytes(hashes[(index ^ 1).min(hashes.len() - 1)]).to_string(),
                    );
                    hashes = hashes
                        .chunks(2)
                        .map(|pair| {
                            let mut bytes = [0; 64];
                            bytes[..32].copy_from_slice(&pair[0]);
                            bytes[32..].copy_from_slice(pair.get(1).unwrap_or(&pair[0]));
                            btc_primitives::hash::sha256d(&bytes)
                        })
                        .collect();
                    index >>= 1;
                }
                Ok(json!({"block_height":height, "pos":position, "merkle":branch}))
            }
            _ => Err(fail(
                btc_electrum::protocol::METHOD_NOT_FOUND,
                "unsupported Electrum provider method",
            )),
        }
    }
}

impl ChainBackend for NodeChainBackend {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        match method {
            "sendrawtransaction" => {
                let raw = hex::decode(string_param(&params, 0)?)
                    .map_err(|e| RpcError::new(-22, e.to_string()))?;
                let tx: Transaction =
                    decode(&raw).map_err(|e| RpcError::new(-22, e.to_string()))?;
                let limits = RpcFeeLimits::parse(&params, true)?;
                Ok(json!(self
                    .submit_transaction_capped(tx, Some(limits))?
                    .to_string()))
            }
            "testmempoolaccept" => {
                let raws = params.get(0).and_then(Value::as_array).ok_or_else(|| {
                    RpcError::new(INVALID_PARAMS, "expected transaction hex array")
                })?;
                if raws.len() != 1 {
                    return Err(RpcError::new(
                        -8,
                        "single-transaction admission only; package acceptance is unavailable",
                    ));
                }
                let raw = raws[0]
                    .as_str()
                    .ok_or_else(|| RpcError::new(INVALID_PARAMS, "expected transaction hex"))?;
                let tx: Transaction =
                    decode(&hex::decode(raw).map_err(|e| RpcError::new(-22, e.to_string()))?)
                        .map_err(|e| RpcError::new(-22, e.to_string()))?;
                let data = self.lock()?;
                let mut pool = data.mempool.clone();
                let id = tx.txid();
                let limits = RpcFeeLimits::parse(&params, false)?;
                let accepted = pool
                    .admit(tx.clone(), &data.utxos, &data.headers)
                    .and_then(|id| {
                        limits.check_with_size(
                            &tx,
                            pool.entries[&id].fee,
                            pool.entries[&id].vsize,
                        )?;
                        Ok(id)
                    });
                match accepted {
                    Ok(_) => Ok(
                        json!([{ "txid": id.to_string(), "wtxid": tx.wtxid().to_string(), "allowed": true,
                        "vsize": pool.entries[&id].vsize, "fees": { "base": pool.entries[&id].fee as f64 / 100_000_000.0 } }]),
                    ),
                    Err(error) => Ok(
                        json!([{ "txid": id.to_string(), "wtxid": tx.wtxid().to_string(), "allowed": false, "reject-reason": error.message }]),
                    ),
                }
            }
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
                let transactions: Vec<_> = block.transactions.iter().skip(1).enumerate().map(|(index, tx)| {
                    let depends: Vec<_> = block.transactions.iter().skip(1).take(index).enumerate()
                        .filter(|(_, parent)| tx.inputs.iter().any(|input| input.previous_output.txid == parent.txid()))
                        .map(|(position, _)| position + 1).collect();
                    Ok(json!({ "data": hex::encode(encode(tx)), "txid": tx.txid().to_string(), "hash": tx.wtxid().to_string(),
                        "depends": depends, "fee": data.mempool.entries.get(&tx.txid()).map(|e| e.fee).ok_or_else(|| internal("template changed while reading metadata"))?, "sigops": data.mempool.entries.get(&tx.txid()).map(|e| e.sigop_cost).ok_or_else(|| internal("template changed while reading metadata"))?, "weight": tx.weight() }))
                }).collect::<Result<Vec<_>, RpcError>>()?;
                let mut result = json!({ "version": block.header.version, "previousblockhash": block.header.prev_blockhash.to_string(),
                    "transactions": transactions, "coinbasevalue": block.transactions[0].outputs[0].value.as_sat(),
                    "target": compact_bits_to_target_hex(block.header.bits.to_u32()), "mintime": data.headers.median_time_past(previous) + 1,
                    "curtime": block.header.time, "height": previous.height + 1, "bits": format!("{:08x}", block.header.bits.to_u32()),
                    "noncerange": "00000000ffffffff", "sizelimit": 1000000, "weightlimit": 4000000, "sigoplimit": 80000,
                    "rules": ["csv", "segwit"], "capabilities": [], "mutable": ["time", "transactions", "prevblock"] });
                if block.transactions[0].outputs.len() > 1 {
                    result["default_witness_commitment"] = json!(hex::encode(
                        block.transactions[0]
                            .outputs
                            .last()
                            .unwrap()
                            .script_pubkey
                            .as_bytes()
                    ));
                }
                Ok(result)
            }
            _ => {
                let data = self.lock()?;
                let headers = &data.headers;
                let tip = headers.best_header();
                match method {
                    "getmempoolinfo" => Ok(
                        json!({ "loaded": true, "size": data.mempool.entries.len(), "bytes": data.mempool.bytes,
                        "maxmempool": crate::mempool::MAX_BYTES, "mempoolminfee": 0.00001, "minrelaytxfee": 0.00001 }),
                    ),
                    "getrawmempool" => {
                        if params.get(0).and_then(Value::as_bool).unwrap_or(false) {
                            let mut entries = serde_json::Map::new();
                            for id in &data.mempool.order {
                                entries.insert(
                                    id.to_string(),
                                    mempool_entry_json(&data.mempool, *id)?,
                                );
                            }
                            Ok(Value::Object(entries))
                        } else {
                            Ok(json!(data
                                .mempool
                                .order
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()))
                        }
                    }
                    "getmempoolentry" => {
                        let id = TxHash::from_hex(string_param(&params, 0)?)
                            .map_err(|e| RpcError::new(-8, e.to_string()))?;
                        mempool_entry_json(&data.mempool, id)
                    }
                    "getblockcount" => Ok(json!(tip.height)),
                    "getbestblockhash" => Ok(json!(tip.header.block_hash().to_string())),
                    "getblockhash" => {
                        if params
                            .get(0)
                            .and_then(Value::as_i64)
                            .is_some_and(|height| height < 0)
                        {
                            return Err(RpcError::new(-8, "height out of range"));
                        }
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
                        use crate::rpc_transaction::{transaction_json, verbosity};
                        let hash = block_hash_param(&params)?;
                        let block = self
                            .db
                            .tx()
                            .map_err(internal)?
                            .get_block(&hash)
                            .map_err(internal)?
                            .ok_or_else(|| RpcError::new(-5, "block body unavailable"))?;
                        let level = verbosity(&params, 1)?;
                        if level <= 0 {
                            return Ok(json!(hex::encode(encode(&block))));
                        }
                        let mut result = self.header_json(headers, hash)?;
                        result["tx"] = if level == 1 {
                            json!(block
                                .transactions
                                .iter()
                                .map(|t| t.txid().to_string())
                                .collect::<Vec<_>>())
                        } else {
                            let undo = self.rpc_undo(hash)?;
                            json!(block
                                .transactions
                                .iter()
                                .map(|tx| transaction_json(
                                    tx,
                                    self.state.network,
                                    Some(&undo),
                                    level >= 3
                                ))
                                .collect::<Result<Vec<_>, _>>()?)
                        };
                        let size = encode(&block).len();
                        result["size"] = json!(size);
                        result["strippedsize"] = json!((block.weight() - size) / 3);
                        result["weight"] = json!(block.weight());
                        Ok(result)
                    }
                    "getrawtransaction" => self.raw_transaction_json(&data, &params),
                    "gettxout" => {
                        let txid = TxHash::from_hex(string_param(&params, 0)?)
                            .map_err(|e| RpcError::new(-8, e.to_string()))?;
                        let vout = u32::try_from(unsigned_param(&params, 1)?)
                            .map_err(|_| RpcError::new(-8, "output index out of range"))?;
                        let include_mempool = match params.get(2) {
                            None => true,
                            Some(value) => value.as_bool().ok_or_else(|| {
                                RpcError::new(INVALID_PARAMS, "include_mempool must be boolean")
                            })?,
                        };
                        let op = OutPoint::new(txid, vout);
                        let entry = if include_mempool {
                            data.mempool.coin(&op, &data.utxos, tip.height + 1)
                        } else {
                            data.utxos.get_utxo(&op)
                        };
                        let Some(entry) = entry else {
                            return Ok(Value::Null);
                        };
                        // Older local databases retain provably unspendable
                        // outputs. They are never spendable coins in Core's RPC
                        // view, including when supplied by a mempool overlay.
                        if entry.txout.script_pubkey.is_op_return()
                            || entry.txout.script_pubkey.len() > 10_000
                        {
                            return Ok(Value::Null);
                        }
                        Ok(
                            json!({ "bestblock": tip.header.block_hash().to_string(), "confirmations": tip.height.saturating_add(1).saturating_sub(entry.height),
                            "value": entry.txout.value.as_sat() as f64 / 100_000_000.0, "coinbase": entry.is_coinbase,
                            "scriptPubKey": crate::rpc_transaction::script_pubkey_json(&entry.txout.script_pubkey, self.state.network) }),
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
                        "legacy_checkpoint_archive": self.legacy_checkpoint.as_ref().map(|archive| json!({
                            "height": archive.height, "hash": archive.hash.to_string(), "genesis": archive.genesis.to_string(),
                            "used_for_validation": false })),
                        "initialblockdownload": self.state.syncing.load(std::sync::atomic::Ordering::SeqCst), "pruned": false, "warnings": "experimental node: full Core consensus parity remains unverified" }),
                    ),
                    _ => Err(RpcError::new(-32601, "method not found")),
                }
            }
        }
    }
}

struct RpcFeeLimits {
    rate_sat_per_kvb: i64,
    burn_sat: Option<i64>,
}
impl RpcFeeLimits {
    fn parse(params: &Value, burn: bool) -> Result<Self, RpcError> {
        let amount = |index: usize, default: f64| -> Result<i64, RpcError> {
            let number = match params.get(index) {
                None => default,
                Some(value) => value
                    .as_f64()
                    .ok_or_else(|| RpcError::new(INVALID_PARAMS, "fee limit must be a number"))?,
            };
            if !number.is_finite() || !(0.0..=21_000_000.0).contains(&number) {
                return Err(RpcError::new(-8, "fee limit out of range"));
            }
            Ok((number * 100_000_000.0).round() as i64)
        };
        Ok(Self {
            rate_sat_per_kvb: amount(1, 0.1)?,
            burn_sat: if burn { Some(amount(2, 0.0)?) } else { None },
        })
    }
    fn check(&self, tx: &Transaction, fee: i64) -> Result<(), RpcError> {
        self.check_with_size(tx, fee, tx.weight().div_ceil(4))
    }
    fn check_with_size(&self, tx: &Transaction, fee: i64, vsize: usize) -> Result<(), RpcError> {
        // Core CFeeRate::GetFee rounds upward to a whole satoshi.
        let maximum = (self.rate_sat_per_kvb as i128 * vsize as i128 + 999) / 1000;
        if self.rate_sat_per_kvb != 0 && fee as i128 > maximum {
            return Err(RpcError::new(-25, "max feerate exceeded"));
        }
        if let Some(limit) = self.burn_sat {
            let burned: i64 = tx
                .outputs
                .iter()
                .filter(|output| {
                    output.script_pubkey.is_op_return() || output.script_pubkey.len() > 10_000
                })
                .map(|output| output.value.as_sat())
                .sum();
            if burned > limit {
                return Err(RpcError::new(-25, "max burn amount exceeded"));
            }
        }
        Ok(())
    }
}

fn mempool_entry_json(
    pool: &crate::mempool::RuntimeMempool,
    id: TxHash,
) -> Result<Value, RpcError> {
    let entry = pool
        .entries
        .get(&id)
        .ok_or_else(|| RpcError::new(-5, "transaction not in mempool"))?;
    let depends: Vec<_> = entry
        .tx
        .inputs
        .iter()
        .filter_map(|input| {
            pool.entries
                .contains_key(&input.previous_output.txid)
                .then(|| input.previous_output.txid.to_string())
        })
        .collect();
    let spent_by: Vec<_> = pool
        .entries
        .values()
        .filter(|child| {
            child
                .tx
                .inputs
                .iter()
                .any(|input| input.previous_output.txid == id)
        })
        .map(|child| child.tx.txid().to_string())
        .collect();
    Ok(
        json!({ "vsize": entry.vsize, "weight": entry.tx.weight(), "time": entry.time,
        "fees": { "base": entry.fee as f64 / 100_000_000.0 }, "depends": depends, "spentby": spent_by, "wtxid": entry.tx.wtxid().to_string() }),
    )
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
pub(super) fn internal(error: impl std::fmt::Display) -> RpcError {
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
    fn script_revisions_follow_successful_publication_and_not_rejected_writes() {
        use btc_electrum::ElectrumBackend;
        let dir = tempfile::tempdir().unwrap();
        let backend = NodeChainBackend::open(
            &dir.path().join("chain.redb"),
            NodeState::new(Network::Regtest),
        )
        .unwrap();
        let mut events = backend.subscribe_scripts().unwrap();
        let key = TestKeyPair::from_secret(secp256k1::SecretKey::from_slice(&[12; 32]).unwrap());
        let address = Address::p2pkh_from_pubkey(&key.pubkey_bytes(), Network::Regtest).to_string();
        let block = ChainBackend::call(&backend, "generatetoaddress", json!([1, address])).unwrap();
        assert!(events.has_changed().unwrap());
        let first = *events.borrow_and_update();
        assert_eq!(first, 1);
        let hash = block_hash_param(&json!([block[0]])).unwrap();
        let body = backend.block(&hash).unwrap().unwrap();
        assert!(backend.submit_block(&body).is_err());
        assert!(!events.has_changed().unwrap());
        let mut invalid = body.transactions[0].clone();
        invalid.inputs[0].previous_output = OutPoint::new(TxHash::ZERO, 0);
        assert!(backend.submit_transaction(invalid).is_err());
        assert!(!events.has_changed().unwrap());
        backend
            .configure_mempool(
                true,
                btc_mempool::policy::TxValidationPolicy::default(),
                btc_consensus::script_engine::ScriptFlags::core_compliant(),
            )
            .unwrap();
        assert!(events.has_changed().unwrap());
        assert_eq!(*events.borrow_and_update(), first + 1);
        // Snapshot failures are errors; subscribing cannot invent a status.
        assert!(backend
            .script_statuses(&vec![
                "00".repeat(32);
                btc_electrum::handler::MAX_SCRIPT_SUBSCRIPTIONS + 1
            ])
            .is_err());
    }

    #[test]
    fn validated_script_index_upgrades_real_body_history_and_ignores_stage_rows() {
        let dir = tempfile::tempdir().unwrap();
        let source = NodeChainBackend::open(
            &dir.path().join("source.redb"),
            NodeState::new(Network::Regtest),
        )
        .unwrap();
        let key = TestKeyPair::from_secret(secp256k1::SecretKey::from_slice(&[11; 32]).unwrap());
        let address = Address::p2pkh_from_pubkey(&key.pubkey_bytes(), Network::Regtest).to_string();
        ChainBackend::call(&source, "generatetoaddress", json!([3, address])).unwrap();
        let path = dir.path().join("old.redb");
        {
            let db = Arc::new(RedbDatabase::new(&path).unwrap());
            db.init_tables().unwrap();
            let mut coins = PersistentUtxoSet::new(db.clone());
            let source_read = source.db.tx().unwrap();
            for height in 1..=3 {
                let hash = source_read
                    .get_block_hash_by_height(height)
                    .unwrap()
                    .unwrap();
                let block = source_read.get_block(&hash).unwrap().unwrap();
                let raw = source_read.get_block_undo(&hash).unwrap().unwrap();
                coins
                    .apply_block_update(
                        &block,
                        height,
                        &btc_storage::undo::decode_undo(hash, &raw).unwrap(),
                    )
                    .unwrap();
            }
            let write = db.tx_mut().unwrap();
            write
                .put_address_tx(
                    &[0; 32],
                    &btc_storage::AddressIndexValue {
                        txid: TxHash::ZERO,
                        height: 2,
                        tx_position: 0,
                        value: 100,
                        output_index: 0,
                    },
                )
                .unwrap();
            write.commit().unwrap();
            assert!(!db.verify_script_index().unwrap());
        }
        let upgraded = NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).unwrap();
        let hash = btc_primitives::hash::sha256(key.p2pkh_script().as_bytes());
        assert_eq!(
            upgraded.db.tx().unwrap().script_history(&hash, 10).unwrap(),
            source.db.tx().unwrap().script_history(&hash, 10).unwrap()
        );
        assert!(upgraded
            .db
            .tx()
            .unwrap()
            .script_history(&[0; 32], 10)
            .unwrap()
            .is_empty());
        assert!(upgraded.db.verify_script_index().unwrap());
        drop(upgraded);
        assert!(
            NodeChainBackend::open(&path, NodeState::new(Network::Regtest))
                .unwrap()
                .db
                .verify_script_index()
                .unwrap()
        );
    }

    #[test]
    fn txout_view_excludes_retained_unspendable_outputs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc-coins.redb");
        let backend = NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).unwrap();
        let mut block = backend
            .candidate(ScriptBuf::from_bytes(vec![0x51]))
            .unwrap();
        for script in [vec![0x6a, 0x4c], vec![0; 10_001]] {
            block.transactions[0].outputs.push(TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(script),
            });
        }
        mine(&mut block);
        backend.submit_block(&block).unwrap();
        let txid = block.transactions[0].txid().to_string();
        for pool in [false, true] {
            assert!(backend
                .call("gettxout", json!([txid, 0, pool]))
                .unwrap()
                .is_object());
            for n in 1..block.transactions[0].outputs.len() {
                assert!(backend
                    .call("gettxout", json!([txid, n, pool]))
                    .unwrap()
                    .is_null());
            }
        }
        drop(backend);
        let backend = NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).unwrap();
        for n in 1..block.transactions[0].outputs.len() {
            assert!(backend
                .call("gettxout", json!([txid, n]))
                .unwrap()
                .is_null());
        }
    }

    #[test]
    fn sigop_budget_controls_admission_mining_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sigops.redb");
        let backend =
            Arc::new(NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).unwrap());
        let mut funding = Vec::new();
        for _ in 0..106 {
            let mut block = backend
                .candidate(ScriptBuf::from_bytes(vec![0x51]))
                .unwrap();
            mine(&mut block);
            funding.push(block.transactions[0].clone());
            backend.submit_block(&block).unwrap();
        }
        let spend = |index: usize, count: usize| {
            let mut operations = vec![0x6a];
            operations.extend(vec![0xae; count]);
            Transaction {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(funding[index].txid(), 0),
                    script_sig: ScriptBuf::new(),
                    sequence: u32::MAX,
                }],
                outputs: vec![
                    TxOut {
                        value: Amount::from_sat(funding[index].outputs[0].value.as_sat() - 100_000),
                        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                    },
                    TxOut {
                        value: Amount::ZERO,
                        script_pubkey: ScriptBuf::from_bytes(operations),
                    },
                ],
                witness: vec![],
                lock_time: 0,
            }
        };
        let rejected = spend(6, 201);
        assert!(backend
            .submit_transaction(rejected)
            .unwrap_err()
            .message
            .contains("too-many-sigops"));
        let mut ids = Vec::new();
        for index in 0..6 {
            ids.push(backend.submit_transaction(spend(index, 200)).unwrap());
        }
        let mut child = spend(7, 0);
        child.inputs[0].previous_output = OutPoint::new(ids[5], 0);
        child.outputs[0].value =
            Amount::from_sat(spend(5, 200).outputs[0].value.as_sat() - 100_000);
        let child_id = backend.submit_transaction(child).unwrap();
        let rpc_handler = handler(&backend);
        assert_eq!(
            rpc(&rpc_handler, "getmempoolentry", json!([ids[0].to_string()]))["vsize"],
            80_000
        );
        let template = rpc(&rpc_handler, "getblocktemplate", json!([]));
        assert_eq!(template["transactions"].as_array().unwrap().len(), 5);
        assert!(template["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|tx| tx["sigops"] == 16_000));
        let mut block = backend
            .candidate(ScriptBuf::from_bytes(vec![0x51]))
            .unwrap();
        assert_eq!(block.transactions.len(), 6);
        let tip = backend.tip().unwrap();
        let mut invalid = block.clone();
        invalid.transactions.push(spend(5, 200));
        mine(&mut invalid);
        assert!(backend
            .submit_block(&invalid)
            .unwrap_err()
            .message
            .contains("bad-blk-sigops"));
        assert_eq!(backend.tip().unwrap(), tip);
        assert_eq!(backend.mempool_transactions().unwrap().len(), 7);
        drop(rpc_handler);
        drop(backend);
        let backend =
            Arc::new(NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).unwrap());
        assert_eq!(backend.mempool_transactions().unwrap().len(), 7);
        assert_eq!(
            backend.lock().unwrap().mempool.entries[&ids[0]].sigop_cost,
            16_000
        );
        mine(&mut block);
        backend.submit_block(&block).unwrap();
        assert_eq!(backend.mempool_transactions().unwrap().len(), 2);
        let mut next = backend
            .candidate(ScriptBuf::from_bytes(vec![0x51]))
            .unwrap();
        assert_eq!(
            next.transactions
                .iter()
                .skip(1)
                .map(Transaction::txid)
                .collect::<Vec<_>>(),
            vec![ids[5], child_id]
        );
        mine(&mut next);
        backend.submit_block(&next).unwrap();
        assert!(backend.mempool_transactions().unwrap().is_empty());
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
            (
                "generatetoaddress",
                json!([1, "ԱmipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"]),
                -5,
            ),
            (
                "generatetoaddress",
                json!([1, "m\u{169}pcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"]),
                -5,
            ),
            ("generatetoaddress", json!([1, "3".repeat(100_000)]), -5),
            ("getblockhash", json!([-1]), -8),
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
        assert_eq!(rpc(&rpc_handler, "getblockcount", json!([])), 0);
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

    #[test]
    fn legacy_resync_revalidates_history_and_cannot_reuse_archived_coins() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("original.redb");
        let path = dir.path().join("legacy.redb");
        let backend = NodeChainBackend::open(&original, NodeState::new(Network::Regtest)).unwrap();
        let key = TestKeyPair::from_secret(secp256k1::SecretKey::from_slice(&[1; 32]).unwrap());
        let mut blocks = Vec::new();
        for _ in 0..101 {
            let mut block = backend.candidate(key.p2pkh_script()).unwrap();
            mine(&mut block);
            backend.submit_block(&block).unwrap();
            blocks.push(block);
        }
        let op = OutPoint::new(blocks[0].transactions[0].txid(), 0);
        let prev = blocks[0].transactions[0].outputs[0].clone();
        let spend = signed_spend(&key, op, &prev, 10_000);
        backend.submit_transaction(spend.clone()).unwrap();
        let mut spent_block = backend.candidate(key.p2pkh_script()).unwrap();
        mine(&mut spent_block);
        backend.submit_block(&spent_block).unwrap();
        blocks.push(spent_block);
        let tip = backend.tip().unwrap();
        drop(backend);
        let db = Arc::new(RedbDatabase::new(&path).unwrap());
        db.init_tables().unwrap();
        let mut coins = PersistentUtxoSet::new(db.clone());
        // A stale legacy checkpoint falsely retains a now-spent, mature coin.
        coins
            .apply_update(&UtxoSetUpdate {
                created: vec![(
                    op,
                    UtxoEntry {
                        txout: prev,
                        height: 1,
                        is_coinbase: true,
                    },
                )],
                spent: vec![],
            })
            .unwrap();
        coins.flush_cache_with_tip(tip.0, tip.1).unwrap();
        drop(coins);
        drop(db);
        assert!(NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).is_err());
        let backend = NodeChainBackend::open_with_legacy_resync(
            &path,
            NodeState::new(Network::Regtest),
            true,
        )
        .unwrap();
        assert_eq!(backend.tip().unwrap().0, 0);
        assert!(backend.lock().unwrap().utxos.get_utxo(&op).is_none());
        assert!(backend.submit_transaction(spend.clone()).is_err());
        for block in &blocks[..50] {
            backend.submit_block(block).unwrap();
        }
        drop(backend);
        let backend = NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).unwrap();
        assert_eq!(backend.tip().unwrap().0, 50);
        for block in &blocks[50..] {
            backend.submit_block(block).unwrap();
        }
        assert_eq!(backend.tip().unwrap(), tip);
        assert!(backend.lock().unwrap().utxos.get_utxo(&op).is_none());
        assert!(backend.submit_transaction(spend).is_err());
        drop(backend);
        let backend = NodeChainBackend::open_with_legacy_resync(
            &path,
            NodeState::new(Network::Regtest),
            true,
        )
        .unwrap();
        assert_eq!(backend.tip().unwrap(), tip);
        assert!(backend.lock().unwrap().utxos.get_utxo(&op).is_none());
        assert_eq!(backend.legacy_checkpoint.unwrap().height, tip.0);
    }

    #[test]
    fn coins_without_a_validated_tip_cannot_become_genesis_state() {
        for committed_genesis in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("orphan.redb");
            let db = RedbDatabase::new(&path).unwrap();
            db.init_tables().unwrap();
            let write = db.tx_mut().unwrap();
            write
                .put_utxo(
                    &OutPoint::new(TxHash::from_bytes([1; 32]), 0),
                    &TxOut {
                        value: Amount::from_sat(10_000),
                        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                    },
                )
                .unwrap();
            if committed_genesis {
                let genesis = ChainState::new(ChainParams::from_network(Network::Regtest))
                    .best_header()
                    .header;
                write.set_best_block(0, &genesis.block_hash()).unwrap();
            }
            write.commit().unwrap();
            drop(db);
            assert!(NodeChainBackend::open_with_legacy_resync(
                &path,
                NodeState::new(Network::Regtest),
                true
            )
            .is_err());
            let db = RedbDatabase::new(&path).unwrap();
            assert_eq!(db.coin_count().unwrap(), 1);
            assert!(db.legacy_checkpoint_archive().unwrap().is_none());
        }
    }
    fn signed_spend(key: &TestKeyPair, op: OutPoint, prev: &TxOut, fee: i64) -> Transaction {
        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(prev.value.as_sat() - fee),
                script_pubkey: key.p2pkh_script(),
            }],
            witness: vec![],
            lock_time: 0,
        };
        tx.inputs[0].script_sig = key.build_p2pkh_script_sig(&tx, 0, prev);
        tx
    }

    #[test]
    fn invalid_witness_results_preserve_pool_coins_and_durable_tip() {
        use btc_primitives::{
            hash::{sha256, sha256d},
            transaction::Witness,
        };
        let dir = tempfile::tempdir().unwrap();
        let key = TestKeyPair::from_secret(secp256k1::SecretKey::from_slice(&[18; 32]).unwrap());
        let script = vec![0x75, 0x51]; // DROP TRUE
        for taproot in [false, true] {
            let path = dir.path().join(format!("witness-{taproot}.redb"));
            let backend = NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).unwrap();
            let (address, tail) = if taproot {
                use btc_consensus::taproot::{compute_taprootoutput_key, tap_leaf_hash};
                let internal =
                    hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                        .unwrap()
                        .try_into()
                        .unwrap();
                let (output, parity) =
                    compute_taprootoutput_key(&internal, Some(&tap_leaf_hash(0xc0, &script)))
                        .unwrap();
                (
                    Address::P2tr {
                        output_key: output,
                        network: Network::Regtest,
                    },
                    vec![
                        script.clone(),
                        [vec![0xc0 | parity], internal.to_vec()].concat(),
                    ],
                )
            } else {
                (
                    Address::P2wsh {
                        hash: sha256(&script),
                        network: Network::Regtest,
                    },
                    vec![script.clone()],
                )
            };
            let hashes = backend
                .call("generatetoaddress", json!([100, address.to_string()]))
                .unwrap();
            let first = backend
                .block(&BlockHash::from_hex(hashes[0].as_str().unwrap()).unwrap())
                .unwrap()
                .unwrap();
            let op = OutPoint::new(first.transactions[0].txid(), 0);
            let mut valid = signed_spend(&key, op, &first.transactions[0].outputs[0], 1000);
            valid.inputs[0].script_sig = ScriptBuf::new();
            valid.witness = vec![Witness::from_items([vec![vec![1]], tail.clone()].concat())];
            let tip = backend.tip().unwrap();
            let coin = backend
                .call("gettxout", json!([op.txid.to_hex(), 0, false]))
                .unwrap();
            for arguments in [vec![vec![1], vec![1]], vec![vec![0; 521]]] {
                let mut bad = valid.clone();
                bad.witness[0] = Witness::from_items([arguments, tail.clone()].concat());
                assert!(backend.submit_transaction(bad.clone()).is_err());
                let mut block = backend.candidate(key.p2pkh_script()).unwrap();
                block.transactions.push(bad);
                // Give the invalid block a correct independent witness
                // commitment and real PoW so it reaches script validation.
                let root = sha256d(&[[0u8; 32], block.transactions[1].wtxid().to_bytes()].concat());
                let commitment = sha256d(&[root, [0u8; 32]].concat());
                block.transactions[0].outputs.push(TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::from_bytes(
                        [
                            vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed],
                            commitment.to_vec(),
                        ]
                        .concat(),
                    ),
                });
                block.transactions[0].witness = vec![Witness::from_items(vec![vec![0; 32]])];
                mine(&mut block);
                assert!(backend
                    .submit_block(&block)
                    .unwrap_err()
                    .message
                    .contains("script"));
                assert_eq!(backend.tip().unwrap(), tip);
                assert_eq!(
                    backend
                        .call("gettxout", json!([op.txid.to_hex(), 0, false]))
                        .unwrap(),
                    coin
                );
                assert!(backend.mempool_transactions().unwrap().is_empty());
                assert!(backend.block(&block.block_hash()).unwrap().is_none());
            }
            drop(backend);
            let backend = NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).unwrap();
            assert_eq!(backend.tip().unwrap(), tip);
            assert_eq!(
                backend
                    .call("gettxout", json!([op.txid.to_hex(), 0, false]))
                    .unwrap(),
                coin
            );
            backend.submit_transaction(valid.clone()).unwrap();
            let mut block = backend.candidate(key.p2pkh_script()).unwrap();
            mine(&mut block);
            assert_eq!(block.transactions[1], valid);
            assert!(backend.submit_block(&block).unwrap().active);
            assert!(backend.mempool_transactions().unwrap().is_empty());
            assert!(backend
                .call("gettxout", json!([op.txid.to_hex(), 0, false]))
                .unwrap()
                .is_null());
        }
    }

    #[test]
    fn p2sh_invalid_signatures_cannot_enter_pool_or_commit_block_coins() {
        use btc_primitives::hash::hash160;
        use btc_primitives::script::Opcode;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p2sh.redb");
        let backend = NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).unwrap();
        let key = TestKeyPair::from_secret(secp256k1::SecretKey::from_slice(&[16; 32]).unwrap());
        let mut redeem = ScriptBuf::new();
        redeem.push_slice(&key.pubkey_bytes());
        redeem.push_opcode(Opcode::OP_CHECKSIG);
        let address = Address::P2sh {
            hash: hash160(redeem.as_bytes()),
            network: Network::Regtest,
        }
        .to_string();
        let hashes = backend
            .call("generatetoaddress", json!([100, address]))
            .unwrap();
        let first = backend
            .block(&BlockHash::from_hex(hashes[0].as_str().unwrap()).unwrap())
            .unwrap()
            .unwrap();
        let op = OutPoint::new(first.transactions[0].txid(), 0);
        let previous = &first.transactions[0].outputs[0];
        let mut valid = signed_spend(&key, op, previous, 1000);
        let sig = key.sign_input(
            &valid,
            0,
            &TxOut {
                value: previous.value,
                script_pubkey: redeem.clone(),
            },
        );
        valid.inputs[0].script_sig = {
            let mut s = ScriptBuf::new();
            s.push_slice(&sig);
            s.push_slice(redeem.as_bytes());
            s
        };
        let tip = backend.tip().unwrap();
        let coin = backend
            .call("gettxout", json!([op.txid.to_hex(), 0, false]))
            .unwrap();
        let mut broken = sig.clone();
        let last = broken.len() - 2;
        broken[last] ^= 1;
        for signature in [broken, vec![]] {
            let mut bad = valid.clone();
            bad.inputs[0].script_sig = {
                let mut s = ScriptBuf::new();
                s.push_slice(&signature);
                s.push_slice(redeem.as_bytes());
                s
            };
            assert!(backend.submit_transaction(bad.clone()).is_err());
            let mut block = backend.candidate(key.p2pkh_script()).unwrap();
            block.transactions.push(bad);
            mine(&mut block);
            assert!(backend
                .submit_block(&block)
                .unwrap_err()
                .message
                .contains("script"));
            assert_eq!(backend.tip().unwrap(), tip);
            assert_eq!(
                backend
                    .call("gettxout", json!([op.txid.to_hex(), 0, false]))
                    .unwrap(),
                coin
            );
            assert!(backend.block(&block.block_hash()).unwrap().is_none());
            assert!(backend.mempool_transactions().unwrap().is_empty());
        }
        let mut nonpush = valid.clone();
        nonpush.inputs[0].script_sig = ScriptBuf::from_bytes(
            [vec![0x61], valid.inputs[0].script_sig.as_bytes().to_vec()].concat(),
        );
        let mut block = backend.candidate(key.p2pkh_script()).unwrap();
        block.transactions.push(nonpush);
        mine(&mut block);
        assert!(backend.submit_block(&block).is_err());
        assert_eq!(backend.tip().unwrap(), tip);
        drop(backend);
        let backend = NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).unwrap();
        assert_eq!(backend.tip().unwrap(), tip);
        assert_eq!(
            backend
                .call("gettxout", json!([op.txid.to_hex(), 0, false]))
                .unwrap(),
            coin
        );
        assert!(backend.mempool_transactions().unwrap().is_empty());
        backend.submit_transaction(valid.clone()).unwrap();
        let mut block = backend.candidate(key.p2pkh_script()).unwrap();
        mine(&mut block);
        assert_eq!(block.transactions[1], valid);
        assert!(backend.submit_block(&block).unwrap().active);
        assert!(backend
            .call("gettxout", json!([op.txid.to_hex(), 0, false]))
            .unwrap()
            .is_null());
        assert!(backend.mempool_transactions().unwrap().is_empty());
    }
    #[test]
    fn durable_forks_restore_spends_revalidate_pool_and_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.redb");
        let a = Arc::new(NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).unwrap());
        let b =
            NodeChainBackend::open(&dir.path().join("b.redb"), NodeState::new(Network::Regtest))
                .unwrap();
        let key = TestKeyPair::from_secret(secp256k1::SecretKey::from_slice(&[11; 32]).unwrap());
        let other = TestKeyPair::from_secret(secp256k1::SecretKey::from_slice(&[12; 32]).unwrap());
        let address = Address::p2pkh_from_pubkey(&key.pubkey_bytes(), Network::Regtest).to_string();
        let hashes = a.call("generatetoaddress", json!([100, address])).unwrap();
        for hash in hashes.as_array().unwrap() {
            let body = a
                .block(&BlockHash::from_hex(hash.as_str().unwrap()).unwrap())
                .unwrap()
                .unwrap();
            b.submit_block(&body).unwrap();
        }
        let first = a
            .block(&BlockHash::from_hex(hashes[0].as_str().unwrap()).unwrap())
            .unwrap()
            .unwrap();
        let op = OutPoint::new(first.transactions[0].txid(), 0);
        let parent = signed_spend(&key, op, &first.transactions[0].outputs[0], 1000);
        let child = signed_spend(
            &key,
            OutPoint::new(parent.txid(), 0),
            &parent.outputs[0],
            1000,
        );
        let mut invalid = parent.clone();
        invalid.inputs[0].script_sig = ScriptBuf::from_bytes(vec![0]);
        assert_eq!(a.submit_transaction(invalid).unwrap_err().code, -26);
        let dry = a
            .call("testmempoolaccept", json!([[hex::encode(encode(&parent))]]))
            .unwrap();
        assert_eq!(dry[0]["allowed"], true);
        assert!(a.mempool_transactions().unwrap().is_empty());
        a.submit_transaction(parent.clone()).unwrap();
        a.submit_transaction(child.clone()).unwrap();
        let mempool_view = a
            .call("getrawtransaction", json!([parent.txid().to_string(), 2]))
            .unwrap();
        for field in ["blockhash", "confirmations", "time", "fee"] {
            assert!(mempool_view.get(field).is_none(), "mempool {field}");
        }
        assert_eq!(
            a.call(
                "getrawtransaction",
                json!([parent.txid().to_string(), true, hashes[0]])
            )
            .unwrap_err()
            .code,
            -5
        );
        assert!(a
            .call("gettxout", json!([op.txid.to_string(), 0]))
            .unwrap()
            .is_null());
        assert!(!a
            .call("gettxout", json!([op.txid.to_string(), 0, false]))
            .unwrap()
            .is_null());
        assert_eq!(
            a.submit_transaction(signed_spend(
                &key,
                op,
                &first.transactions[0].outputs[0],
                2000
            ))
            .unwrap_err()
            .code,
            -26
        );
        let mut block_a = a.candidate(key.p2pkh_script()).unwrap();
        mine(&mut block_a);
        assert_eq!(block_a.transactions.len(), 3);
        assert_eq!(
            block_a.transactions[0].outputs[0].value.as_sat(),
            5_000_002_000
        );
        a.submit_block(&block_a).unwrap();
        assert!(a.mempool_transactions().unwrap().is_empty());
        let block_a_hash = block_a.block_hash().to_string();
        let confirmed_view = a
            .call("getrawtransaction", json!([parent.txid().to_string(), 2]))
            .unwrap();
        assert_eq!(confirmed_view["confirmations"], 1);
        assert_eq!(confirmed_view["fee"], json!(0.00001));
        assert_eq!(confirmed_view["vin"][0]["prevout"]["height"], 1);
        assert_eq!(confirmed_view["vin"][0]["prevout"]["generated"], true);
        assert!(confirmed_view.get("in_active_chain").is_none());
        let full_block = a.call("getblock", json!([block_a_hash, 3])).unwrap();
        assert_eq!(full_block["tx"][2]["vin"][0]["prevout"]["height"], 101);
        assert_eq!(full_block["tx"][2]["vin"][0]["prevout"]["generated"], false);
        assert_eq!(full_block["tx"][2]["fee"], json!(0.00001));
        assert!(full_block["tx"][0].get("fee").is_none());
        assert!(full_block["tx"][1].get("blockhash").is_none());
        let details = a.call("getblock", json!([block_a_hash, 2])).unwrap();
        assert!(details["tx"][2]["vin"][0].get("prevout").is_none());
        assert_eq!(details["tx"][2]["fee"], json!(0.00001));
        let raw_undo =
            a.db.tx()
                .unwrap()
                .get_block_undo(&block_a.block_hash())
                .unwrap()
                .unwrap();
        let write = a.db.tx_mut().unwrap();
        write
            .put_block_undo(&block_a.block_hash(), b"corrupt")
            .unwrap();
        write.commit().unwrap();
        assert_eq!(
            a.call("getrawtransaction", json!([parent.txid().to_string(), 2]))
                .unwrap_err()
                .code,
            INTERNAL_ERROR
        );
        assert_eq!(
            a.call("getblock", json!([block_a_hash, 3]))
                .unwrap_err()
                .code,
            INTERNAL_ERROR
        );
        assert_eq!(
            a.call("getrawtransaction", json!([parent.txid().to_string(), 1]))
                .unwrap()["confirmations"],
            1
        );
        // Even a checksummed undo cannot silently substitute missing inputs.
        let empty_undo = btc_storage::undo::encode_undo(
            block_a.block_hash(),
            &UtxoSetUpdate {
                spent: vec![],
                created: vec![],
            },
        );
        let write = a.db.tx_mut().unwrap();
        write
            .put_block_undo(&block_a.block_hash(), &empty_undo)
            .unwrap();
        write.commit().unwrap();
        assert_eq!(
            a.call("getrawtransaction", json!([parent.txid().to_string(), 2]))
                .unwrap_err()
                .code,
            INTERNAL_ERROR
        );
        let write = a.db.tx_mut().unwrap();
        write
            .put_block_undo(&block_a.block_hash(), &raw_undo)
            .unwrap();
        write.commit().unwrap();
        let mut block_b = b.candidate(other.p2pkh_script()).unwrap();
        mine(&mut block_b);
        b.submit_block(&block_b).unwrap();
        assert!(
            !a.submit_block(&block_b).unwrap().active,
            "equal work must retain the active tip"
        );
        assert_eq!(
            a.call("getblockheader", json!([block_b.block_hash().to_string()]))
                .unwrap()["confirmations"],
            -1
        );
        // A malformed winning body cannot persist or disconnect valid coins.
        let mut b2 = b.candidate(other.p2pkh_script()).unwrap();
        mine(&mut b2);
        let mut bad = b2.clone();
        bad.transactions[0].outputs[0].value = Amount::from_sat(5_000_000_001);
        mine(&mut bad);
        assert!(a.submit_block(&bad).is_err());
        assert_eq!(a.tip().unwrap().1, block_a.block_hash());
        assert!(a.block(&bad.block_hash()).unwrap().is_none());
        b.submit_block(&b2).unwrap();
        a.submit_block(&b2).unwrap();
        assert_eq!(a.tip().unwrap(), b.tip().unwrap());
        let stale_view = a
            .call(
                "getrawtransaction",
                json!([parent.txid().to_string(), 2, block_a_hash]),
            )
            .unwrap();
        assert_eq!(stale_view["confirmations"], 0);
        assert_eq!(stale_view["in_active_chain"], false);
        assert!(stale_view.get("time").is_none() && stale_view.get("blocktime").is_none());
        assert_eq!(stale_view["fee"], confirmed_view["fee"]);
        assert_eq!(
            a.call("getrawtransaction", json!([parent.txid().to_string(), 2]))
                .unwrap(),
            mempool_view
        );
        assert_eq!(
            a.call("getblockheader", json!([block_a.block_hash().to_string()]))
                .unwrap()["confirmations"],
            -1
        );
        assert_eq!(
            a.mempool_transactions().unwrap(),
            vec![parent.clone(), child.clone()]
        );
        assert_eq!(
            a.call("gettxout", json!([child.txid().to_string(), 0]))
                .unwrap()["confirmations"],
            0
        );
        assert!(!a
            .call("gettxout", json!([op.txid.to_string(), 0, false]))
            .unwrap()
            .is_null());
        drop(a);
        let a = Arc::new(NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).unwrap());
        assert_eq!(
            a.mempool_transactions().unwrap(),
            vec![parent.clone(), child.clone()]
        );
        assert!(
            a.header(&block_a.block_hash()).unwrap().is_some(),
            "side branch survives restart"
        );
        assert_eq!(
            a.call(
                "getrawtransaction",
                json!([parent.txid().to_string(), 2, block_a_hash])
            )
            .unwrap(),
            stale_view
        );
        assert_eq!(
            a.call("getblock", json!([block_a_hash, 3])).unwrap()["tx"],
            full_block["tx"]
        );
        let mut a3 = a.candidate(key.p2pkh_script()).unwrap();
        mine(&mut a3);
        a.submit_block(&a3).unwrap();
        let conflict = signed_spend(&key, op, &first.transactions[0].outputs[0], 4000);
        b.submit_transaction(conflict.clone()).unwrap();
        let mut b3 = b.candidate(other.p2pkh_script()).unwrap();
        mine(&mut b3);
        b.submit_block(&b3).unwrap();
        a.submit_block(&b3).unwrap();
        let mut b4 = b.candidate(other.p2pkh_script()).unwrap();
        mine(&mut b4);
        b.submit_block(&b4).unwrap();
        a.submit_block(&b4).unwrap();
        assert_eq!(a.tip().unwrap(), b.tip().unwrap());
        assert!(
            a.mempool_transactions().unwrap().is_empty(),
            "conflicting resurrected parent and descendant are removed"
        );
        assert_eq!(
            a.call("getrawtransaction", json!([parent.txid().to_string(), 1]))
                .unwrap_err()
                .code,
            -5
        );
        assert_eq!(
            a.call(
                "getrawtransaction",
                json!([parent.txid().to_string(), 2, block_a_hash])
            )
            .unwrap(),
            stale_view
        );
        assert!(a
            .db
            .tx()
            .unwrap()
            .get_tx_block_index(&parent.txid())
            .unwrap()
            .is_none());
        assert!(a
            .db
            .tx()
            .unwrap()
            .get_tx_block_index(&child.txid())
            .unwrap()
            .is_none());
        assert_eq!(
            a.db.tx()
                .unwrap()
                .get_tx_block_index(&conflict.txid())
                .unwrap()
                .unwrap()
                .block_hash,
            b3.block_hash()
        );
        assert!(a
            .call("gettxout", json!([parent.txid().to_string(), 0, false]))
            .unwrap()
            .is_null());
        assert!(!a
            .call("gettxout", json!([conflict.txid().to_string(), 0, false]))
            .unwrap()
            .is_null());
        let tip = a.tip().unwrap();
        // Undo corruption is detected before any replacement state is committed.
        let raw = a.db.tx().unwrap().get_block_undo(&tip.1).unwrap().unwrap();
        let mut corrupt = raw.clone();
        corrupt[40] ^= 1;
        let write = a.db.tx_mut().unwrap();
        write.put_block_undo(&tip.1, &corrupt).unwrap();
        write.commit().unwrap();
        let mut side = a.candidate(other.p2pkh_script()).unwrap();
        side.header.prev_blockhash = a3.block_hash();
        side.transactions[0].inputs[0].script_sig = ScriptBuf::from_bytes({
            let mut script = encode_bip34_height(104);
            script.push(0);
            script
        });
        mine(&mut side);
        assert!(a
            .submit_block(&side)
            .unwrap_err()
            .message
            .contains("checksum"));
        assert_eq!(a.tip().unwrap(), tip);
        let write = a.db.tx_mut().unwrap();
        write.put_block_undo(&tip.1, &raw).unwrap();
        write.commit().unwrap();
        assert!(!a.submit_block(&side).unwrap().active);
        drop(a);
        let reopened = NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).unwrap();
        assert_eq!(reopened.tip().unwrap(), tip);
        assert!(reopened.header(&side.block_hash()).unwrap().is_some());
        assert!(reopened.mempool_transactions().unwrap().is_empty());
    }

    #[test]
    fn mempool_rejects_immature_missing_duplicate_nonfinal_and_relative_locked_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let backend = NodeChainBackend::open(
            &dir.path().join("chain.redb"),
            NodeState::new(Network::Regtest),
        )
        .unwrap();
        let key = TestKeyPair::from_secret(secp256k1::SecretKey::from_slice(&[13; 32]).unwrap());
        let address = Address::p2pkh_from_pubkey(&key.pubkey_bytes(), Network::Regtest).to_string();
        let hashes = backend
            .call("generatetoaddress", json!([1, address]))
            .unwrap();
        let first = backend
            .block(&BlockHash::from_hex(hashes[0].as_str().unwrap()).unwrap())
            .unwrap()
            .unwrap();
        let op = OutPoint::new(first.transactions[0].txid(), 0);
        let valid = signed_spend(&key, op, &first.transactions[0].outputs[0], 1000);
        assert!(backend
            .submit_transaction(valid.clone())
            .unwrap_err()
            .message
            .contains("premature"));
        backend
            .call("generatetoaddress", json!([99, address]))
            .unwrap();
        let mut bad = valid.clone();
        bad.inputs.push(bad.inputs[0].clone());
        assert!(backend
            .submit_transaction(bad)
            .unwrap_err()
            .message
            .contains("duplicate"));
        let mut missing = valid.clone();
        missing.inputs[0].previous_output.txid = TxHash::from_bytes([99; 32]);
        assert_eq!(backend.submit_transaction(missing).unwrap_err().code, -25);
        let mut nonfinal = valid.clone();
        nonfinal.lock_time = 101;
        nonfinal.inputs[0].sequence = 0xfffffffe;
        nonfinal.inputs[0].script_sig =
            key.build_p2pkh_script_sig(&nonfinal, 0, &first.transactions[0].outputs[0]);
        assert!(backend
            .submit_transaction(nonfinal)
            .unwrap_err()
            .message
            .contains("non-final"));
        backend.submit_transaction(valid.clone()).unwrap();
        let mut child = signed_spend(
            &key,
            OutPoint::new(valid.txid(), 0),
            &valid.outputs[0],
            1000,
        );
        child.inputs[0].sequence = 1;
        child.inputs[0].script_sig = key.build_p2pkh_script_sig(&child, 0, &valid.outputs[0]);
        assert!(backend
            .submit_transaction(child.clone())
            .unwrap_err()
            .message
            .contains("BIP68"));
        child.inputs[0].sequence = (1 << 22) | 1;
        child.inputs[0].script_sig = key.build_p2pkh_script_sig(&child, 0, &valid.outputs[0]);
        assert!(backend
            .submit_transaction(child)
            .unwrap_err()
            .message
            .contains("BIP68"));
        assert_eq!(backend.mempool_transactions().unwrap(), vec![valid]);
    }

    #[test]
    fn undo_backfill_replays_old_body_history_and_checks_committed_coins() {
        let dir = tempfile::tempdir().unwrap();
        let source = NodeChainBackend::open(
            &dir.path().join("source.redb"),
            NodeState::new(Network::Regtest),
        )
        .unwrap();
        let mut block = source.candidate(ScriptBuf::from_bytes(vec![0x51])).unwrap();
        mine(&mut block);
        let accepted = source.submit_block(&block).unwrap();
        let path = dir.path().join("legacy.redb");
        let db = RedbDatabase::new(&path).unwrap();
        db.init_tables().unwrap();
        let write = db.tx_mut().unwrap();
        write
            .put_block_header(&block.block_hash(), &block.header)
            .unwrap();
        write.put_block(&block.block_hash(), &block).unwrap();
        write
            .put_block_hash_by_height(1, &block.block_hash())
            .unwrap();
        for (op, entry) in &accepted.update.created {
            write.put_utxo(op, &entry.txout).unwrap();
            write
                .put_utxo(
                    &OutPoint::new(op.txid, op.vout | 0x8000_0000),
                    &TxOut {
                        value: Amount::from_sat(entry.height as i64),
                        script_pubkey: ScriptBuf::from_bytes(vec![entry.is_coinbase as u8]),
                    },
                )
                .unwrap();
        }
        write.set_best_block(1, &block.block_hash()).unwrap();
        write.commit().unwrap();
        assert!(db
            .tx()
            .unwrap()
            .get_block_undo(&block.block_hash())
            .unwrap()
            .is_none());
        drop(db);
        let reopened = NodeChainBackend::open(&path, NodeState::new(Network::Regtest)).unwrap();
        assert_eq!(reopened.tip().unwrap(), (1, block.block_hash()));
        assert_eq!(
            reopened.undo(block.block_hash()).unwrap().created,
            accepted.update.created
        );
        drop(reopened);
        // A coin mismatch must not be repaired by trusting a stored checkpoint.
        let bad_path = dir.path().join("bad.redb");
        let db = RedbDatabase::new(&bad_path).unwrap();
        db.init_tables().unwrap();
        let write = db.tx_mut().unwrap();
        write
            .put_block_header(&block.block_hash(), &block.header)
            .unwrap();
        write.put_block(&block.block_hash(), &block).unwrap();
        write
            .put_block_hash_by_height(1, &block.block_hash())
            .unwrap();
        write.set_best_block(1, &block.block_hash()).unwrap();
        write.commit().unwrap();
        drop(db);
        assert!(
            NodeChainBackend::open(&bad_path, NodeState::new(Network::Regtest))
                .err()
                .unwrap()
                .to_string()
                .contains("does not match committed coins")
        );
        let db = RedbDatabase::new(&bad_path).unwrap();
        assert!(db
            .tx()
            .unwrap()
            .get_block_undo(&block.block_hash())
            .unwrap()
            .is_none());
    }
    #[test]
    fn replacement_checks_are_atomic_and_honor_full_rbf_and_opt_in_policy() {
        let dir = tempfile::tempdir().unwrap();
        let backend = NodeChainBackend::open(
            &dir.path().join("chain.redb"),
            NodeState::new(Network::Regtest),
        )
        .unwrap();
        let key = TestKeyPair::from_secret(secp256k1::SecretKey::from_slice(&[14; 32]).unwrap());
        let address = Address::p2pkh_from_pubkey(&key.pubkey_bytes(), Network::Regtest).to_string();
        let hashes = backend
            .call("generatetoaddress", json!([100, address]))
            .unwrap();
        let first = backend
            .block(&BlockHash::from_hex(hashes[0].as_str().unwrap()).unwrap())
            .unwrap()
            .unwrap();
        let op = OutPoint::new(first.transactions[0].txid(), 0);
        let parent = signed_spend(&key, op, &first.transactions[0].outputs[0], 1000);
        let child = signed_spend(
            &key,
            OutPoint::new(parent.txid(), 0),
            &parent.outputs[0],
            1000,
        );
        let raw = hex::encode(encode(&parent));
        let capped = backend
            .call("testmempoolaccept", json!([[raw], 0.00001]))
            .unwrap();
        assert_eq!(capped[0]["allowed"], false);
        assert!(backend
            .call("sendrawtransaction", json!([raw, 0.00001]))
            .unwrap_err()
            .message
            .contains("max feerate"));
        assert!(backend.mempool_transactions().unwrap().is_empty());
        backend.submit_transaction(parent.clone()).unwrap();
        backend.submit_transaction(child.clone()).unwrap();
        let low_fee = signed_spend(&key, op, &first.transactions[0].outputs[0], 2001);
        assert!(backend
            .submit_transaction(low_fee)
            .unwrap_err()
            .message
            .contains("increment"));
        let replacement = signed_spend(&key, op, &first.transactions[0].outputs[0], 5000);
        let mut bad_signature = replacement.clone();
        bad_signature.inputs[0].script_sig = ScriptBuf::from_bytes(vec![0]);
        assert!(backend.submit_transaction(bad_signature).is_err());
        assert_eq!(
            backend.mempool_transactions().unwrap(),
            vec![parent.clone(), child]
        );
        backend
            .configure_mempool(
                false,
                btc_mempool::policy::TxValidationPolicy::default(),
                btc_consensus::script_engine::ScriptFlags::all(),
            )
            .unwrap();
        assert!(backend
            .submit_transaction(replacement.clone())
            .unwrap_err()
            .message
            .contains("opt-in"));
        backend
            .configure_mempool(
                true,
                btc_mempool::policy::TxValidationPolicy::default(),
                btc_consensus::script_engine::ScriptFlags::all(),
            )
            .unwrap();
        backend.submit_transaction(replacement.clone()).unwrap();
        assert_eq!(backend.mempool_transactions().unwrap(), vec![replacement]);
        let mut block = backend.candidate(key.p2pkh_script()).unwrap();
        mine(&mut block);
        backend.submit_block(&block).unwrap();
        let second = backend
            .block(&BlockHash::from_hex(hashes[1].as_str().unwrap()).unwrap())
            .unwrap()
            .unwrap();
        let op = OutPoint::new(second.transactions[0].txid(), 0);
        let mut opt_in = signed_spend(&key, op, &second.transactions[0].outputs[0], 1000);
        opt_in.inputs[0].sequence = u32::MAX - 2;
        opt_in.inputs[0].script_sig =
            key.build_p2pkh_script_sig(&opt_in, 0, &second.transactions[0].outputs[0]);
        backend
            .configure_mempool(
                false,
                btc_mempool::policy::TxValidationPolicy::default(),
                btc_consensus::script_engine::ScriptFlags::all(),
            )
            .unwrap();
        backend.submit_transaction(opt_in).unwrap();
        let replacement = signed_spend(&key, op, &second.transactions[0].outputs[0], 4000);
        backend.submit_transaction(replacement.clone()).unwrap();
        assert_eq!(backend.mempool_transactions().unwrap(), vec![replacement]);
        let mut block = backend.candidate(key.p2pkh_script()).unwrap();
        mine(&mut block);
        backend.submit_block(&block).unwrap();
        assert!(
            !backend.lock().unwrap().mempool.full_rbf,
            "block commits preserve configured policy"
        );
    }
}
