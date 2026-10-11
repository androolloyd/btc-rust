//! Bounded, dependency-aware admission against the active chain and pool coins.
use btc_consensus::{
    script_engine::ScriptFlags,
    sig_verify::Secp256k1Verifier,
    utxo::{UtxoEntry, UtxoSet, COINBASE_MATURITY},
    witness::verify_input_with_prevouts,
    ChainState,
};
use btc_primitives::encode::Encodable;
use btc_primitives::{OutPoint, Transaction, TxHash};
use btc_rpc::handler::RpcError;
use std::collections::{HashMap, HashSet};

pub const MAX_BYTES: usize = 300_000_000;
#[derive(Clone)]
pub struct Entry {
    pub tx: Transaction,
    pub fee: i64,
    pub time: u64,
}
#[derive(Clone)]
pub struct RuntimeMempool {
    pub entries: HashMap<TxHash, Entry>,
    pub order: Vec<TxHash>,
    pub spent: HashMap<OutPoint, TxHash>,
    pub bytes: usize,
    pub full_rbf: bool,
    pub policy: btc_mempool::policy::TxValidationPolicy,
    pub flags: ScriptFlags,
}
impl Default for RuntimeMempool {
    fn default() -> Self {
        let mut flags = ScriptFlags::core_compliant();
        flags.verify_discourage_upgradable_nops = true;
        flags.verify_discourage_upgradable_witness_program = true;
        Self {
            entries: HashMap::new(),
            order: Vec::new(),
            spent: HashMap::new(),
            bytes: 0,
            full_rbf: true,
            policy: btc_mempool::policy::TxValidationPolicy::default(),
            flags,
        }
    }
}
struct PoolCoins<'a> {
    pool: &'a RuntimeMempool,
    base: &'a dyn UtxoSet,
    height: u64,
}
impl UtxoSet for PoolCoins<'_> {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        if self.pool.spent.contains_key(outpoint) {
            return None;
        }
        if let Some(entry) = self.pool.entries.get(&outpoint.txid) {
            return entry
                .tx
                .outputs
                .get(outpoint.vout as usize)
                .map(|txout| UtxoEntry {
                    txout: txout.clone(),
                    height: self.height,
                    is_coinbase: false,
                });
        }
        self.base.get_utxo(outpoint)
    }
}
fn reject(message: impl Into<String>) -> RpcError {
    RpcError::new(-26, message)
}
impl RuntimeMempool {
    pub fn empty_like(&self) -> Self {
        Self {
            full_rbf: self.full_rbf,
            policy: self.policy.clone(),
            flags: self.flags,
            ..Self::default()
        }
    }
    pub fn transactions(&self) -> Vec<Transaction> {
        self.order
            .iter()
            .filter_map(|id| self.entries.get(id).map(|e| e.tx.clone()))
            .collect()
    }
    pub fn coin(&self, outpoint: &OutPoint, base: &dyn UtxoSet, height: u64) -> Option<UtxoEntry> {
        PoolCoins {
            pool: self,
            base,
            height,
        }
        .get_utxo(outpoint)
    }
    fn remove_set(&mut self, removed: &HashSet<TxHash>) {
        for id in removed {
            if let Some(entry) = self.entries.remove(id) {
                self.bytes -= entry.tx.encoded_size();
                for input in entry.tx.inputs {
                    self.spent.remove(&input.previous_output);
                }
            }
        }
        self.order.retain(|id| !removed.contains(id));
    }
    /// Evaluate replacement on an isolated candidate pool. Failed signatures,
    /// fees or dependency rules leave every original transaction intact.
    pub fn admit(
        &mut self,
        tx: Transaction,
        base: &dyn UtxoSet,
        chain: &ChainState,
    ) -> Result<TxHash, RpcError> {
        self.admit_with_tip(tx, base, chain, None)
    }
    fn admit_with_tip(
        &mut self,
        tx: Transaction,
        base: &dyn UtxoSet,
        chain: &ChainState,
        tip: Option<&btc_primitives::BlockHeader>,
    ) -> Result<TxHash, RpcError> {
        if self.entries.contains_key(&tx.txid()) {
            return Err(RpcError::new(-27, "transaction already in mempool"));
        }
        let direct: HashSet<_> = tx
            .inputs
            .iter()
            .filter_map(|input| self.spent.get(&input.previous_output).copied())
            .collect();
        if direct.is_empty() {
            return self.admit_unconflicted(tx, base, chain, tip);
        }
        if !self.full_rbf {
            for id in &direct {
                let mut ancestors = HashSet::new();
                self.collect_ancestors(*id, &mut ancestors);
                if !ancestors.iter().any(|id| {
                    self.entries[id]
                        .tx
                        .inputs
                        .iter()
                        .any(|input| input.sequence < u32::MAX - 1)
                }) {
                    return Err(reject("conflict does not signal opt-in RBF"));
                }
            }
        }
        let mut removed = direct.clone();
        loop {
            let old_len = removed.len();
            for (id, entry) in &self.entries {
                if entry
                    .tx
                    .inputs
                    .iter()
                    .any(|input| removed.contains(&input.previous_output.txid))
                {
                    removed.insert(*id);
                }
            }
            if removed.len() > 100 {
                return Err(reject("too many replacements"));
            }
            if removed.len() == old_len {
                break;
            }
        }
        let old_parents: HashSet<_> = removed
            .iter()
            .flat_map(|id| {
                self.entries[id]
                    .tx
                    .inputs
                    .iter()
                    .map(|input| input.previous_output.txid)
            })
            .collect();
        for input in &tx.inputs {
            if self.entries.contains_key(&input.previous_output.txid)
                && !old_parents.contains(&input.previous_output.txid)
            {
                return Err(reject("replacement adds an unconfirmed input"));
            }
        }
        let old_fees: i64 = removed.iter().map(|id| self.entries[id].fee).sum();
        let mut candidate = self.clone();
        candidate.remove_set(&removed);
        let id = candidate.admit_unconflicted(tx, base, chain, tip)?;
        let new = &candidate.entries[&id];
        let new_size = new.tx.weight().div_ceil(4) as i64;
        if new.fee < old_fees + new_size {
            return Err(reject("insufficient replacement fee increment"));
        }
        for conflict in direct {
            let old = &self.entries[&conflict];
            if (new.fee as i128) * 1000 / new_size as i128
                <= (old.fee as i128) * 1000 / old.tx.weight().div_ceil(4) as i128
            {
                return Err(reject(
                    "replacement feerate is not higher than its direct conflict",
                ));
            }
        }
        *self = candidate;
        Ok(id)
    }

    fn admit_unconflicted(
        &mut self,
        tx: Transaction,
        base: &dyn UtxoSet,
        chain: &ChainState,
        tip: Option<&btc_primitives::BlockHeader>,
    ) -> Result<TxHash, RpcError> {
        let id = tx.txid();
        if self.entries.contains_key(&id) {
            return Err(RpcError::new(-27, "transaction already in mempool"));
        }
        if tx.is_coinbase() || tx.inputs.is_empty() || tx.outputs.is_empty() {
            return Err(reject(
                "coinbase or empty transaction cannot enter the mempool",
            ));
        }
        if tx.version < 1 || tx.version > 2 {
            return Err(reject("unsupported transaction version"));
        }
        if tx.weight() > 400_000 {
            return Err(reject("transaction exceeds standard weight"));
        }
        let size = tx.encoded_size();
        if self.bytes + size > MAX_BYTES || self.entries.len() >= 100_000 {
            return Err(reject("mempool full"));
        }
        let height = if let Some(tip) = tip {
            chain
                .get_header(&tip.prev_blockhash)
                .ok_or_else(|| reject("missing candidate parent"))?
                .height
                + 2
        } else {
            chain.best_height() + 1
        };
        let mtp = if let Some(tip) = tip {
            chain
                .median_time_past_with_header(tip)
                .ok_or_else(|| reject("missing candidate MTP"))?
        } else {
            chain.median_time_past(chain.best_header())
        };
        if tx.lock_time != 0 && tx.inputs.iter().any(|input| input.sequence != u32::MAX) {
            let endpoint = if tx.lock_time < 500_000_000 {
                height
            } else {
                mtp as u64
            };
            if tx.lock_time as u64 >= endpoint {
                return Err(reject("non-final transaction"));
            }
        }
        let view = PoolCoins {
            pool: self,
            base,
            height,
        };
        let mut seen = HashSet::new();
        let mut prevouts = Vec::new();
        let mut input_value = 0i64;
        let mut ancestors = HashSet::new();
        for input in &tx.inputs {
            let op = input.previous_output;
            if !seen.insert(op) || op.is_coinbase() {
                return Err(reject("duplicate or null input"));
            }
            if input.script_sig.len() > 1650 {
                return Err(reject("nonstandard scriptSig size"));
            }
            if self.spent.contains_key(&op) {
                return Err(reject("mempool conflict"));
            }
            let coin = view
                .get_utxo(&op)
                .ok_or_else(|| RpcError::new(-25, "missing inputs"))?;
            if coin.is_coinbase && height < coin.height + COINBASE_MATURITY {
                return Err(reject("premature coinbase spend"));
            }
            input_value = input_value
                .checked_add(coin.txout.value.as_sat())
                .filter(|v| (0..=2_100_000_000_000_000).contains(v))
                .ok_or_else(|| reject("input value out of range"))?;
            if tx.version >= 2 && input.sequence & (1 << 31) == 0 {
                let delay = (input.sequence & 0xffff) as u64;
                if input.sequence & (1 << 22) == 0 {
                    if height < coin.height + delay {
                        return Err(reject("non-BIP68-final"));
                    }
                } else {
                    let creation_mtp = if coin.height == height {
                        mtp
                    } else {
                        chain
                            .get_header_by_height(coin.height.saturating_sub(1))
                            .map(|entry| chain.median_time_past(entry))
                            .ok_or_else(|| reject("missing lock-time ancestor"))?
                    };
                    if (mtp as u64) < creation_mtp as u64 + (delay << 9) {
                        return Err(reject("non-BIP68-final"));
                    }
                }
            }
            self.collect_ancestors(op.txid, &mut ancestors);
            prevouts.push(coin.txout);
        }
        if ancestors.len() + 1 > 25 {
            return Err(reject("too many mempool ancestors"));
        }
        for ancestor in &ancestors {
            let descendants = self
                .entries
                .values()
                .filter(|entry| {
                    let mut parents = HashSet::new();
                    for input in &entry.tx.inputs {
                        self.collect_ancestors(input.previous_output.txid, &mut parents);
                    }
                    parents.contains(ancestor)
                })
                .count();
            if descendants + 2 > 25 {
                return Err(reject("too many mempool descendants"));
            }
        }
        let mut output_value = 0i64;
        for output in &tx.outputs {
            let value = output.value.as_sat();
            if !(0..=2_100_000_000_000_000).contains(&value) {
                return Err(reject("output value out of range"));
            }
            output_value = output_value
                .checked_add(value)
                .filter(|v| *v <= 2_100_000_000_000_000)
                .ok_or_else(|| reject("output total out of range"))?;
        }
        let fee = input_value
            .checked_sub(output_value)
            .filter(|v| *v >= 0)
            .ok_or_else(|| reject("inputs below outputs"))?;
        // Rate is 1000 sat/kvB (one sat/vB), using witness virtual size.
        let mut policy = self.policy.clone();
        let relay_fee =
            (tx.weight().div_ceil(4) as i128 * policy.min_relay_fee.as_sat() as i128 + 999) / 1000;
        policy.min_relay_fee = btc_primitives::Amount::from_sat(
            i64::try_from(relay_fee).map_err(|_| reject("relay fee out of range"))?,
        );
        btc_mempool::policy::validate_tx_policy(
            &tx,
            btc_primitives::Amount::from_sat(fee),
            ancestors.len() + 1,
            1,
            &policy,
        )
        .map_err(|e| reject(e.to_string()))?;
        let flags = self.flags;
        for index in 0..tx.inputs.len() {
            verify_input_with_prevouts(&tx, index, &prevouts, &Secp256k1Verifier, &flags)
                .map_err(|e| reject(format!("script verification failed: {e}")))?;
        }
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| reject(e.to_string()))?
            .as_secs();
        for input in &tx.inputs {
            self.spent.insert(input.previous_output, id);
        }
        self.bytes += size;
        self.order.push(id);
        self.entries.insert(id, Entry { tx, fee, time });
        Ok(id)
    }
    fn collect_ancestors(&self, id: TxHash, seen: &mut HashSet<TxHash>) {
        if let Some(entry) = self.entries.get(&id) {
            if seen.insert(id) {
                for input in &entry.tx.inputs {
                    self.collect_ancestors(input.previous_output.txid, seen);
                }
            }
        }
    }
    /// Recheck all survivors and disconnected transactions against the new tip.
    /// Retry missing parents so disk/table order cannot drop valid descendants.
    pub fn rebuild(
        transactions: Vec<Transaction>,
        confirmed: &HashSet<TxHash>,
        base: &dyn UtxoSet,
        chain: &ChainState,
        settings: Option<&Self>,
        tip: Option<&btc_primitives::BlockHeader>,
    ) -> Self {
        let mut pool = Self::default();
        if let Some(settings) = settings {
            pool.full_rbf = settings.full_rbf;
            pool.policy = settings.policy.clone();
            pool.flags = settings.flags;
        }
        let mut pending: Vec<_> = transactions
            .into_iter()
            .filter(|tx| !confirmed.contains(&tx.txid()))
            .collect();
        loop {
            let old_count = pending.len();
            let mut retry = Vec::new();
            for tx in pending {
                if let Err(error) = pool.admit_with_tip(tx.clone(), base, chain, tip) {
                    if error.code == -25 {
                        retry.push(tx);
                    }
                }
            }
            if retry.len() == old_count {
                break;
            }
            pending = retry;
            if pending.is_empty() {
                break;
            }
        }
        pool
    }
}
