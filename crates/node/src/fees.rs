//! Bounded empirical confirmation estimates from actual post-commit pool events.
//! This is not Bitcoin Core's decaying multi-horizon estimator. Unknown history,
//! stale/reorganized observations and inadequate samples never produce a quote.
use crate::chain_backend::internal;
use crate::mempool::RuntimeMempool;
use btc_primitives::{hash::sha256, BlockHash, TxHash};
use btc_rpc::handler::RpcError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};

const WINDOW: u64 = 144;
const MIN_SAMPLES: usize = 20;
const MAX_RECORDS: usize = 20_000;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    entered: u64,
    rate: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    recorded: u64,
    rate: u64,
    delay: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FeeObservations {
    version: u8,
    height: u64,
    hash: String,
    pending: BTreeMap<String, Pending>,
    samples: Vec<Sample>,
}

fn rate(fee: i64, vsize: usize) -> u64 {
    // Admission already proves a nonnegative money-bounded fee and positive size.
    ((fee as u128 * 1000).div_ceil(vsize as u128)) as u64
}
impl FeeObservations {
    pub(super) fn new(height: u64, hash: BlockHash) -> Self {
        Self {
            version: 1,
            height,
            hash: hash.to_string(),
            pending: BTreeMap::new(),
            samples: Vec::new(),
        }
    }
    pub(super) fn decode(bytes: &[u8], height: u64, hash: BlockHash) -> Result<Self, RpcError> {
        if bytes.len() < 32 || bytes.len() > btc_storage::traits::MAX_FEE_STATE_BYTES {
            return Err(internal("invalid fee observation receipt size"));
        }
        if sha256(&bytes[32..]).as_slice() != &bytes[..32] {
            return Err(internal("fee observation checksum mismatch"));
        }
        let state: Self = serde_json::from_slice(&bytes[32..])
            .map_err(|_| internal("invalid fee observation receipt"))?;
        if state.version != 1
            || (state.height, state.hash.as_str()) != (height, hash.to_string().as_str())
            || state.pending.len() > MAX_RECORDS
            || state.samples.len() > MAX_RECORDS
            || state
                .pending
                .keys()
                .any(|id| TxHash::from_hex(id).is_err() || id.to_ascii_lowercase() != *id)
            || state.pending.values().any(|p| p.entered > height)
            || state.samples.iter().any(|s| {
                s.recorded > height
                    || s.recorded < height.saturating_sub(WINDOW)
                    || s.delay.is_some_and(|d| d == 0 || d > s.recorded)
            })
        {
            return Err(internal(
                "fee observation receipt inconsistent with validated tip",
            ));
        }
        Ok(state)
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, RpcError> {
        let payload = serde_json::to_vec(self).map_err(internal)?;
        let mut bytes = sha256(&payload).to_vec();
        bytes.extend(payload);
        if bytes.len() > btc_storage::traits::MAX_FEE_STATE_BYTES {
            return Err(internal("fee observation receipt exceeds limit"));
        }
        Ok(bytes)
    }
    /// Evaluate on an isolated candidate; publish only after the corresponding
    /// pool/chain transaction commits. A reorg discards all learned outcomes.
    pub(super) fn update(
        &mut self,
        height: u64,
        hash: BlockHash,
        pool: &RuntimeMempool,
        mined: &HashSet<TxHash>,
        reorg: bool,
    ) {
        if reorg {
            *self = Self::new(height, hash);
        }
        self.height = height;
        self.hash = hash.to_string();
        self.samples
            .retain(|s| s.recorded >= height.saturating_sub(WINDOW));
        let mut resolved = Vec::new();
        for (id, p) in &self.pending {
            let txid = TxHash::from_hex(id).expect("validated observation txid");
            if mined.contains(&txid) || !pool.entries.contains_key(&txid) {
                self.samples.push(Sample {
                    recorded: height,
                    rate: p.rate,
                    delay: mined.contains(&txid).then(|| height - p.entered),
                });
                resolved.push(id.clone());
            }
        }
        for id in resolved {
            self.pending.remove(&id);
        }
        // Refuse to learn from a truncated sample. Capacity exhaustion clears
        // learning rather than preventing an otherwise valid block/admission.
        if pool.entries.len() > MAX_RECORDS || self.samples.len() > MAX_RECORDS {
            self.pending.clear();
            self.samples.clear();
            return;
        }
        for (&id, e) in &pool.entries {
            if !e
                .tx
                .inputs
                .iter()
                .any(|i| pool.entries.contains_key(&i.previous_output.txid))
            {
                self.pending.entry(id.to_string()).or_insert(Pending {
                    entered: height,
                    rate: rate(e.fee, e.vsize),
                });
            }
        }
    }
    /// Lowest observed rate whose entire higher-rate tail meets the success
    /// threshold, with at least twenty resolved/aged observations. Young pending
    /// entries are censored; aged pending and removed/replaced entries fail.
    pub(super) fn estimate(&self, target: u64, economical: bool, floor: i64) -> Option<u64> {
        if target == 0 || target > WINDOW {
            return None;
        }
        let mut buckets: BTreeMap<u64, (usize, usize)> = BTreeMap::new();
        for s in &self.samples {
            let bucket = buckets.entry(s.rate).or_default();
            bucket.0 += 1;
            bucket.1 += usize::from(s.delay.is_some_and(|d| d <= target));
        }
        for p in self
            .pending
            .values()
            .filter(|p| self.height - p.entered >= target)
        {
            buckets.entry(p.rate).or_default().0 += 1;
        }
        let (mut count, mut success, mut quote) = (0usize, 0usize, None);
        for (rate, (n, ok)) in buckets.into_iter().rev() {
            count += n;
            success += ok;
            if count >= MIN_SAMPLES && success * 100 >= count * if economical { 85 } else { 95 } {
                quote = Some(rate.max(floor.max(0) as u64));
            }
        }
        quote
    }
}

/// Exact released ElectrumX compact-histogram rules. Rates are rounded down to
/// 0.1 sat/vbyte and bins grow from 100,000 vbytes; the final small tail is omitted.
pub(super) fn histogram(pool: &RuntimeMempool) -> Result<Value, RpcError> {
    if pool.entries.len() > MAX_RECORDS {
        return Err(internal("fee histogram transaction work limit exceeded"));
    }
    let mut buckets = BTreeMap::<u64, u64>::new();
    for e in pool.entries.values() {
        let rate = (e.fee as u128 * 10 / e.vsize as u128) as u64;
        *buckets.entry(rate).or_default() += e.vsize as u64;
    }
    let (mut size, mut cumulative, mut previous) = (100_000.0, 0u64, None);
    let mut result = Vec::new();
    for (rate, bytes) in buckets.into_iter().rev() {
        if bytes as f64 > 2.0 * size && previous.is_some() && cumulative > 0 {
            result.push(json!([previous.unwrap() as f64 / 10.0, cumulative]));
            cumulative = 0;
            size *= 1.1;
        }
        cumulative += bytes;
        if cumulative as f64 > size {
            result.push(json!([rate as f64 / 10.0, cumulative]));
            cumulative = 0;
            size *= 1.1;
        }
        previous = Some(rate);
    }
    Ok(json!(result))
}
