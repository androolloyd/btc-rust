//! Node-owned stage backend: borrowed validated state and one actual downloaded body.
use super::*;
use btc_stages::stage::{
    ExecOutput, StageBackend, StageCheckpoint, StageError, StageId, ADDRESS_INDEX, BODIES, HEADERS,
    TX_INDEX, VALIDATION,
};
use btc_storage::index_plan::BlockIndexPlan;
fn backend(error: RpcError) -> StageError {
    StageError::Backend {
        code: error.code,
        message: error.message,
    }
}

pub(super) struct Batch<'a> {
    node: &'a NodeChainBackend,
    data: &'a mut ValidatedChain,
    block: &'a Block,
    pub(super) height: u64,
    hash: BlockHash,
    old_tip: BlockHash,
    old_height: u64,
    extension: bool,
    branch: Option<ChainState>,
    detached: Vec<(u64, Block)>,
    attached: Vec<(u64, Block)>,
    attached_updates: HashMap<BlockHash, UtxoSetUpdate>,
    changes: HashMap<OutPoint, Option<UtxoEntry>>,
    fork_hash: BlockHash,
    update: Option<UtxoSetUpdate>,
    transactions: Option<Vec<(TxHash, btc_storage::traits::TxBlockLocation)>>,
    plan: Option<BlockIndexPlan>,
    phase: usize,
    pub(super) accepted: Option<AcceptedBlock>,
}
impl<'a> Batch<'a> {
    pub(super) fn new(
        node: &'a NodeChainBackend,
        data: &'a mut ValidatedChain,
        block: &'a Block,
    ) -> Result<Self, RpcError> {
        let hash = block.block_hash();
        if data.headers.get_header(&hash).is_some() {
            return Err(RpcError::new(-27, "duplicate"));
        }
        let parent = data
            .headers
            .get_header(&block.header.prev_blockhash)
            .ok_or_else(|| RpcError::new(-25, "unknown block parent"))?;
        let height = parent
            .height
            .checked_add(1)
            .ok_or_else(|| rejection("block height overflow"))?;
        let old_tip = data.headers.best_header().header.block_hash();
        let old_height = data.headers.best_height();
        Ok(Self {
            node,
            data,
            block,
            height,
            hash,
            old_tip,
            old_height,
            extension: block.header.prev_blockhash == old_tip,
            branch: None,
            detached: vec![],
            attached: vec![],
            attached_updates: HashMap::new(),
            changes: HashMap::new(),
            fork_hash: old_tip,
            update: None,
            transactions: None,
            plan: None,
            phase: 0,
            accepted: None,
        })
    }
    fn headers(&mut self) -> Result<(), RpcError> {
        let data = &*self.data;
        let block = self.block;
        let old_tip = self.old_tip;
        let extension = self.extension;
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
                    .node
                    .block(&cursor)?
                    .ok_or_else(|| internal("active body missing"))?;
                overlay.disconnect(&self.node.undo(cursor)?);
                detached.push((entry.height, body));
                cursor = entry.header.prev_blockhash;
            }
            for (height, hash) in reconnect.into_iter().rev() {
                let undo = self.node.undo(hash)?;
                overlay.connect(&undo);
                attached_updates.insert(hash, undo);
                attached.push((
                    height,
                    self.node
                        .block(&hash)?
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

        if extension {
            data.headers
                .validate_header(block.header)
                .map_err(rejection)?;
        }
        self.branch = branch;
        self.detached = detached;
        self.attached = attached;
        self.attached_updates = attached_updates;
        self.changes = overlay.changes;
        self.fork_hash = fork_hash;
        Ok(())
    }
    fn execute_block(&mut self) -> Result<(), RpcError> {
        let context = self.branch.as_ref().unwrap_or(&self.data.headers);
        let mut overlay = CoinOverlay {
            base: &self.data.utxos,
            changes: std::mem::take(&mut self.changes),
        };
        let update =
            NodeChainBackend::validate_block_against(self.block, self.height, context, &overlay)?;
        overlay.connect(&update);
        self.changes = overlay.changes;
        self.update = Some(update);
        Ok(())
    }
    fn publish(&mut self) -> Result<StageCheckpoint, RpcError> {
        let block = self.block;
        let height = self.height;
        let hash = self.hash;
        let old_tip = self.old_tip;
        let old_height = self.old_height;
        let extension = self.extension;
        let fork_hash = self.fork_hash;
        let data = &mut *self.data;
        let context = self.branch.as_ref().unwrap_or(&data.headers);
        let detached = std::mem::take(&mut self.detached);
        let mut attached = std::mem::take(&mut self.attached);
        let mut attached_updates = std::mem::take(&mut self.attached_updates);
        let update = self
            .update
            .take()
            .ok_or_else(|| internal("execution stage did not produce coins"))?;
        let overlay = CoinOverlay {
            base: &data.utxos,
            changes: std::mem::take(&mut self.changes),
        };
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
        let mut fees = data.fees.clone();
        let fee_bytes = if active {
            let mined = attached
                .iter()
                .flat_map(|(_, b)| b.transactions.iter().skip(1).map(Transaction::txid))
                .collect();
            fees.update(height, hash, &pool, &mined, !extension);
            Some(fees.encode()?)
        } else {
            None
        };
        let pool_transactions = pool.transactions();
        let ValidatedChain { headers, utxos, .. } = &mut *data;
        headers
            .accept_header_with_commit(block.header, || {
                utxos
                    .commit_chain_transition_with_stage_plan(
                        btc_storage::utxo_store::ChainTransition {
                            incoming: block,
                            height,
                            undo: &update,
                            detached: if active { &detached } else { &[] },
                            attached: if active { &attached } else { &[] },
                            coins: &changes,
                            tip: active.then_some((height, hash)),
                            old_height,
                            mempool: &pool_transactions,
                        },
                        fee_bytes.as_deref(),
                        Some(
                            self.plan
                                .as_ref()
                                .ok_or_else(|| "stage index plan missing".to_string())?,
                        ),
                    )
                    .map_err(|e| e.to_string())
            })
            .map_err(|error| match error {
                btc_consensus::chain::ChainError::CommitFailed(message) => internal(message),
                other => rejection(other),
            })?;
        if active {
            data.fees = fees;
            data.mempool = pool;
            self.node
                .state
                .update_mempool(data.mempool.entries.len() as u64, data.mempool.bytes as u64);
            self.node.state.update_chain_tip(height, &hash.to_string());
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
            self.node
                .wallet_events
                .send_modify(|revision| *revision = revision.wrapping_add(1));
            let _ = self.node.block_events.send(hash);
            // Reaccepted disconnected transactions must be announced again.
            for txid in &data.mempool.order {
                let _ = self.node.tx_events.send(*txid);
            }
        }

        self.accepted = Some(AcceptedBlock {
            height,
            hash,
            update,
            active,
        });
        Ok(StageCheckpoint {
            height: data.headers.best_height(),
            hash: data.headers.best_header().header.block_hash(),
        })
    }
}
impl StageBackend for Batch<'_> {
    fn execute(
        &mut self,
        stage: StageId,
        target: u64,
        limit: u64,
    ) -> Result<ExecOutput, StageError> {
        let order = [HEADERS, BODIES, VALIDATION, TX_INDEX, ADDRESS_INDEX];
        if target != self.height || limit == 0 || order.get(self.phase) != Some(&stage) {
            return Err(StageError::StageFailed(
                stage,
                "stage order or actual downloaded target mismatch".into(),
            ));
        }
        match stage {
            HEADERS => self.headers().map_err(backend)?,
            BODIES => {
                BlockValidator::validate_block(self.block).map_err(|e| backend(rejection(e)))?
            }
            VALIDATION => self.execute_block().map_err(backend)?,
            TX_INDEX => {
                self.transactions = Some(
                    BlockIndexPlan::transaction_rows(self.block)
                        .map_err(|e| backend(internal(e)))?,
                )
            }
            ADDRESS_INDEX => {
                self.plan = Some(
                    BlockIndexPlan::new(
                        self.height,
                        self.block,
                        self.update
                            .as_ref()
                            .ok_or_else(|| backend(internal("missing execution undo")))?,
                        self.transactions
                            .take()
                            .ok_or_else(|| backend(internal("missing transaction rows")))?,
                    )
                    .map_err(|e| backend(internal(e)))?,
                )
            }
            _ => return Err(StageError::ProviderUnavailable),
        }
        self.phase += 1;
        Ok(ExecOutput {
            checkpoint: self.height,
            done: true,
        })
    }
    fn commit(&mut self) -> Result<StageCheckpoint, StageError> {
        if self.phase != 5 || self.plan.is_none() {
            return Err(StageError::ProviderUnavailable);
        }
        self.publish().map_err(backend)
    }
    fn abort(&mut self) {
        self.changes.clear();
        self.update = None;
        self.plan = None;
        self.transactions = None;
    }
}
