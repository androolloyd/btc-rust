//! BIP152 compact-block wire data and bounded partial reconstruction.
//! Live sessions negotiate only witness-inclusive version 2. Explicit version
//! 1 primitive operations are available for independent protocol comparisons.

use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};

use btc_primitives::block::{Block, BlockHeader};
use btc_primitives::encode::{Decodable, Encodable, EncodeError, ReadExt, VarInt, WriteExt};
use btc_primitives::hash::{sha256, BlockHash, TxHash};
use btc_primitives::transaction::Transaction;

use crate::siphash::siphash_2_4;

pub const MAX_COMPACT_TRANSACTIONS: usize = u16::MAX as usize;
pub const MAX_COMPACT_PAYLOAD: usize = 4_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactVersion {
    V1,
    V2,
}

impl CompactVersion {
    fn hash(self, tx: &Transaction) -> TxHash {
        match self {
            Self::V1 => tx.txid(),
            Self::V2 => tx.wtxid(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ShortIdKey {
    pub k0: u64,
    pub k1: u64,
}

impl ShortIdKey {
    /// Single SHA256 of the SERIALIZED HEADER and little-endian nonce.
    pub fn new(header: &BlockHeader, nonce: u64) -> Self {
        let mut preimage = [0; 88];
        header
            .encode(&mut &mut preimage[..80])
            .expect("fixed header encoding");
        preimage[80..].copy_from_slice(&nonce.to_le_bytes());
        let hash = sha256(&preimage);
        Self {
            k0: u64::from_le_bytes(hash[..8].try_into().expect("eight bytes")),
            k1: u64::from_le_bytes(hash[8..16].try_into().expect("eight bytes")),
        }
    }
    pub fn short_id(&self, hash: &TxHash) -> u64 {
        siphash_2_4(self.k0, self.k1, hash.as_bytes()) & 0x0000_ffff_ffff_ffff
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CompactError {
    #[error("invalid compact-block layout or transaction count")]
    Layout,
    #[error("duplicate compact-block short IDs; request the full block")]
    Collision,
    #[error("compact-block resource bound exceeded")]
    Resource,
    #[error("blocktxn does not match the pending request")]
    Response,
    #[error("reconstructed block fails transaction or merkle checks; request the full block")]
    Completion,
}

#[derive(Debug, Clone)]
pub struct CompactBlock {
    pub header: BlockHeader,
    pub nonce: u64,
    pub short_ids: Vec<u64>,
    pub prefilled_txs: Vec<PrefilledTx>,
}

#[derive(Debug, Clone)]
pub struct PrefilledTx {
    /// Absolute index in memory; differential CompactSize only on the wire.
    pub index: u16,
    pub tx: Transaction,
}

#[derive(Debug, Clone)]
pub struct BlockTxnRequest {
    pub block_hash: BlockHash,
    pub indices: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct BlockTxnResponse {
    pub block_hash: BlockHash,
    pub transactions: Vec<Transaction>,
}

fn invalid(error: impl std::fmt::Display) -> EncodeError {
    EncodeError::InvalidData(error.to_string())
}

fn count(cursor: &mut Cursor<&[u8]>, minimum_size: usize) -> Result<usize, EncodeError> {
    let n = VarInt::decode(cursor)?.0;
    let remaining = cursor.get_ref().len() as u64 - cursor.position();
    if n > MAX_COMPACT_TRANSACTIONS as u64 || n > remaining / minimum_size as u64 {
        return Err(invalid("compact vector exceeds count or remaining payload"));
    }
    Ok(n as usize)
}

fn complete(cursor: &Cursor<&[u8]>) -> Result<(), EncodeError> {
    if cursor.position() != cursor.get_ref().len() as u64 {
        return Err(invalid("trailing compact-message bytes"));
    }
    Ok(())
}

fn cursor(bytes: &[u8]) -> Result<Cursor<&[u8]>, EncodeError> {
    if bytes.len() > MAX_COMPACT_PAYLOAD {
        return Err(invalid(CompactError::Resource));
    }
    Ok(Cursor::new(bytes))
}

fn write_tx(
    tx: &Transaction,
    version: CompactVersion,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    if version == CompactVersion::V1 && tx.is_segwit() {
        let mut legacy = tx.clone();
        legacy.witness.clear();
        legacy.encode(out)?;
    } else {
        tx.encode(out)?;
    }
    Ok(())
}

fn read_tx(
    cursor: &mut Cursor<&[u8]>,
    version: CompactVersion,
) -> Result<Transaction, EncodeError> {
    let tx = Transaction::decode(cursor)?;
    if version == CompactVersion::V1 && tx.is_segwit() {
        return Err(invalid("witness serialization in compact version 1"));
    }
    Ok(tx)
}

fn differential(next: u64, delta: u64) -> Result<u16, EncodeError> {
    next.checked_add(delta)
        .and_then(|index| u16::try_from(index).ok())
        .ok_or_else(|| invalid("differential transaction index overflow"))
}

impl CompactBlock {
    pub fn for_relay(block: &Block) -> Result<Self, CompactError> {
        Self::from_block(block, rand::random(), CompactVersion::V2)
    }
    fn validate(&self) -> Result<usize, CompactError> {
        let total = self
            .short_ids
            .len()
            .checked_add(self.prefilled_txs.len())
            .ok_or(CompactError::Layout)?;
        if total == 0
            || total > MAX_COMPACT_TRANSACTIONS
            || self.short_ids.iter().any(|id| *id > 0x0000_ffff_ffff_ffff)
        {
            return Err(CompactError::Layout);
        }
        let mut previous = None;
        let mut weight = 0usize;
        for prefilled in &self.prefilled_txs {
            if prefilled.index as usize >= total
                || previous.is_some_and(|index| index >= prefilled.index)
            {
                return Err(CompactError::Layout);
            }
            previous = Some(prefilled.index);
            weight = weight
                .checked_add(prefilled.tx.weight())
                .ok_or(CompactError::Resource)?;
            if weight > MAX_COMPACT_PAYLOAD {
                return Err(CompactError::Resource);
            }
        }
        Ok(total)
    }

    pub fn from_block(
        block: &Block,
        nonce: u64,
        version: CompactVersion,
    ) -> Result<Self, CompactError> {
        if block.transactions.is_empty()
            || block.transactions.len() > MAX_COMPACT_TRANSACTIONS
            || block.weight() > MAX_COMPACT_PAYLOAD
        {
            return Err(CompactError::Resource);
        }
        let key = ShortIdKey::new(&block.header, nonce);
        let mut coinbase = block.transactions[0].clone();
        if version == CompactVersion::V1 {
            coinbase.witness.clear();
        }
        Ok(Self {
            header: block.header,
            nonce,
            short_ids: block
                .transactions
                .iter()
                .skip(1)
                .map(|tx| key.short_id(&version.hash(tx)))
                .collect(),
            prefilled_txs: vec![PrefilledTx {
                index: 0,
                tx: coinbase,
            }],
        })
    }

    pub fn serialize(&self, version: CompactVersion) -> Result<Vec<u8>, EncodeError> {
        self.validate().map_err(invalid)?;
        let mut out = Vec::new();
        self.header.encode(&mut out)?;
        out.write_u64_le(self.nonce)?;
        VarInt(self.short_ids.len() as u64).encode(&mut out)?;
        for id in &self.short_ids {
            out.extend_from_slice(&id.to_le_bytes()[..6]);
        }
        VarInt(self.prefilled_txs.len() as u64).encode(&mut out)?;
        let mut next = 0u64;
        for prefilled in &self.prefilled_txs {
            VarInt(prefilled.index as u64 - next).encode(&mut out)?;
            next = prefilled.index as u64 + 1;
            write_tx(&prefilled.tx, version, &mut out)?;
        }
        if out.len() > MAX_COMPACT_PAYLOAD {
            return Err(invalid(CompactError::Resource));
        }
        Ok(out)
    }

    pub fn deserialize(bytes: &[u8], version: CompactVersion) -> Result<Self, EncodeError> {
        let mut input = cursor(bytes)?;
        let header = BlockHeader::decode(&mut input)?;
        let nonce = input.read_u64_le()?;
        let n = count(&mut input, 6)?;
        let mut short_ids = Vec::with_capacity(n);
        for _ in 0..n {
            let mut bytes = [0; 8];
            input.read_exact(&mut bytes[..6])?;
            short_ids.push(u64::from_le_bytes(bytes));
        }
        let n = count(&mut input, 11)?;
        if short_ids.len() + n > MAX_COMPACT_TRANSACTIONS {
            return Err(invalid(CompactError::Layout));
        }
        let mut prefilled_txs = Vec::with_capacity(n);
        let mut next = 0u64;
        let mut weight = 0usize;
        for _ in 0..n {
            let delta = VarInt::decode(&mut input)?.0;
            let index = differential(next, delta)?;
            next = index as u64 + 1;
            let tx = read_tx(&mut input, version)?;
            weight = weight
                .checked_add(tx.weight())
                .ok_or_else(|| invalid(CompactError::Resource))?;
            if weight > MAX_COMPACT_PAYLOAD {
                return Err(invalid(CompactError::Resource));
            }
            prefilled_txs.push(PrefilledTx { index, tx });
        }
        complete(&input)?;
        let compact = Self {
            header,
            nonce,
            short_ids,
            prefilled_txs,
        };
        compact.validate().map_err(invalid)?;
        Ok(compact)
    }

    pub fn prepare(
        &self,
        transactions: &[Transaction],
        version: CompactVersion,
    ) -> Result<PartialBlock, CompactError> {
        let key = ShortIdKey::new(&self.header, self.nonce);
        self.prepare_with_ids(transactions, version, |tx| key.short_id(&version.hash(tx)))
    }

    fn prepare_with_ids(
        &self,
        transactions: &[Transaction],
        version: CompactVersion,
        id: impl Fn(&Transaction) -> u64,
    ) -> Result<PartialBlock, CompactError> {
        let total = self.validate()?;
        let wanted: HashSet<_> = self.short_ids.iter().copied().collect();
        if wanted.len() != self.short_ids.len() {
            return Err(CompactError::Collision);
        }
        let mut matches = HashMap::<u64, Option<&Transaction>>::new();
        for tx in transactions {
            let short = id(tx);
            if !wanted.contains(&short) {
                continue;
            }
            matches
                .entry(short)
                .and_modify(|existing| {
                    if existing.is_some_and(|previous| version.hash(previous) != version.hash(tx)) {
                        *existing = None;
                    }
                })
                .or_insert(Some(tx));
        }
        let mut available = vec![None; total];
        for prefilled in &self.prefilled_txs {
            available[prefilled.index as usize] = Some(prefilled.tx.clone());
        }
        let mut expected = vec![None; total];
        let mut ids = self.short_ids.iter();
        for (position, slot) in available.iter_mut().enumerate() {
            if slot.is_some() {
                continue;
            }
            let short = *ids.next().ok_or(CompactError::Layout)?;
            expected[position] = Some(short);
            if let Some(Some(tx)) = matches.get(&short) {
                let mut tx = (*tx).clone();
                if version == CompactVersion::V1 {
                    tx.witness.clear();
                }
                *slot = Some(tx);
            }
        }
        let partial = PartialBlock {
            header: self.header,
            nonce: self.nonce,
            version,
            available,
            expected,
        };
        if partial.buffered_size() > 16_000_000 {
            return Err(CompactError::Resource);
        }
        Ok(partial)
    }
}

/// One immutable snapshot of local matches. Completion consumes it exactly once.
#[derive(Debug)]
pub struct PartialBlock {
    header: BlockHeader,
    nonce: u64,
    version: CompactVersion,
    available: Vec<Option<Transaction>>,
    expected: Vec<Option<u64>>,
}

impl PartialBlock {
    pub fn request(&self) -> BlockTxnRequest {
        BlockTxnRequest {
            block_hash: self.header.block_hash(),
            indices: self
                .available
                .iter()
                .enumerate()
                .filter_map(|(i, tx)| tx.is_none().then_some(i as u16))
                .collect(),
        }
    }
    pub fn buffered_size(&self) -> usize {
        self.available.len()
            * (std::mem::size_of::<Option<Transaction>>() + std::mem::size_of::<Option<u64>>())
            + self
                .available
                .iter()
                .flatten()
                .map(Transaction::weight)
                .sum::<usize>()
    }
    pub fn finish(mut self, response: BlockTxnResponse) -> Result<Block, CompactError> {
        let request = self.request();
        if response.block_hash != request.block_hash
            || response.transactions.len() != request.indices.len()
        {
            return Err(CompactError::Response);
        }
        let key = ShortIdKey::new(&self.header, self.nonce);
        for (index, tx) in request.indices.into_iter().zip(response.transactions) {
            if self.expected[index as usize]
                .is_some_and(|expected| key.short_id(&self.version.hash(&tx)) != expected)
            {
                return Err(CompactError::Response);
            }
            if self.version == CompactVersion::V1 && tx.is_segwit() {
                return Err(CompactError::Response);
            }
            self.available[index as usize] = Some(tx);
        }
        let block = Block {
            header: self.header,
            transactions: self
                .available
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .ok_or(CompactError::Response)?,
        };
        let mut unique = HashSet::new();
        if block.weight() > MAX_COMPACT_PAYLOAD
            || !block.check_merkle_root()
            || !block.transactions[0].is_coinbase()
            || block
                .transactions
                .iter()
                .skip(1)
                .any(Transaction::is_coinbase)
            || block
                .transactions
                .iter()
                .any(|tx| !unique.insert(tx.txid()))
        {
            return Err(CompactError::Completion);
        }
        // Structural reconstruction is NOT script, UTXO, witness-commitment or
        // context validation. Runtime submits through the ordinary chain backend.
        Ok(block)
    }
}

impl BlockTxnRequest {
    pub fn serialize(&self) -> Result<Vec<u8>, EncodeError> {
        if self.indices.len() > MAX_COMPACT_TRANSACTIONS {
            return Err(invalid(CompactError::Resource));
        }
        let mut out = self.block_hash.to_bytes().to_vec();
        VarInt(self.indices.len() as u64).encode(&mut out)?;
        let mut next = 0u64;
        for &index in &self.indices {
            let delta = (index as u64)
                .checked_sub(next)
                .ok_or_else(|| invalid(CompactError::Layout))?;
            VarInt(delta).encode(&mut out)?;
            next = index as u64 + 1;
        }
        Ok(out)
    }
    pub fn deserialize(bytes: &[u8]) -> Result<Self, EncodeError> {
        let mut input = cursor(bytes)?;
        let block_hash = BlockHash::from_bytes(input.read_hash256()?);
        let n = count(&mut input, 1)?;
        let mut indices = Vec::with_capacity(n);
        let mut next = 0;
        for _ in 0..n {
            let delta = VarInt::decode(&mut input)?.0;
            let index = differential(next, delta)?;
            next = index as u64 + 1;
            indices.push(index);
        }
        complete(&input)?;
        Ok(Self {
            block_hash,
            indices,
        })
    }
}

impl BlockTxnResponse {
    pub fn serialize(&self, version: CompactVersion) -> Result<Vec<u8>, EncodeError> {
        if self.transactions.len() > MAX_COMPACT_TRANSACTIONS {
            return Err(invalid(CompactError::Resource));
        }
        let weight: usize = self.transactions.iter().map(Transaction::weight).sum();
        if weight > MAX_COMPACT_PAYLOAD {
            return Err(invalid(CompactError::Resource));
        }
        let mut out = self.block_hash.to_bytes().to_vec();
        VarInt(self.transactions.len() as u64).encode(&mut out)?;
        for tx in &self.transactions {
            write_tx(tx, version, &mut out)?;
        }
        if out.len() > MAX_COMPACT_PAYLOAD {
            return Err(invalid(CompactError::Resource));
        }
        Ok(out)
    }
    pub fn deserialize(bytes: &[u8], version: CompactVersion) -> Result<Self, EncodeError> {
        let mut input = cursor(bytes)?;
        let block_hash = BlockHash::from_bytes(input.read_hash256()?);
        let n = count(&mut input, 10)?;
        let mut transactions = Vec::with_capacity(n);
        let mut weight = 0usize;
        for _ in 0..n {
            let tx = read_tx(&mut input, version)?;
            weight = weight
                .checked_add(tx.weight())
                .ok_or_else(|| invalid(CompactError::Resource))?;
            if weight > MAX_COMPACT_PAYLOAD {
                return Err(invalid(CompactError::Resource));
            }
            transactions.push(tx);
        }
        complete(&input)?;
        Ok(Self {
            block_hash,
            transactions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::encode::{decode, encode};
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/data/bip152.json")).unwrap()
    }
    fn bytes(value: &Value) -> Vec<u8> {
        hex::decode(value.as_str().unwrap()).unwrap()
    }
    fn version(case: &Value) -> CompactVersion {
        if case["version"] == 1 {
            CompactVersion::V1
        } else {
            CompactVersion::V2
        }
    }
    fn indices(value: &Value) -> Vec<u16> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u16)
            .collect()
    }
    fn base() -> (Block, CompactBlock) {
        let data = vectors();
        let case = &data["cases"][4];
        (
            decode(&bytes(&case["block"])).unwrap(),
            CompactBlock::deserialize(&bytes(&case["compact"]), CompactVersion::V2).unwrap(),
        )
    }

    #[test]
    fn unchanged_core_keys_short_ids_and_all_wire_bytes() {
        for case in vectors()["cases"].as_array().unwrap() {
            let v = version(case);
            let block: Block = decode(&bytes(&case["block"])).unwrap();
            let compact = CompactBlock::deserialize(&bytes(&case["compact"]), v).unwrap();
            let key = ShortIdKey::new(&compact.header, compact.nonce);
            assert_eq!(key.k0, case["k0"].as_u64().unwrap());
            assert_eq!(key.k1, case["k1"].as_u64().unwrap());
            assert_eq!(
                compact.short_ids,
                case["short_ids"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| id.as_u64().unwrap())
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                compact
                    .prefilled_txs
                    .iter()
                    .map(|tx| tx.index)
                    .collect::<Vec<_>>(),
                indices(&case["prefilled"])
            );
            assert_eq!(compact.serialize(v).unwrap(), bytes(&case["compact"]));
            if indices(&case["prefilled"]) == [0] {
                let generated = CompactBlock::from_block(&block, compact.nonce, v).unwrap();
                assert_eq!(generated.serialize(v).unwrap(), bytes(&case["compact"]));
            }
            let request = BlockTxnRequest::deserialize(&bytes(&case["request"])).unwrap();
            assert_eq!(request.indices, indices(&case["request_indices"]));
            assert_eq!(request.serialize().unwrap(), bytes(&case["request"]));
            let response = BlockTxnResponse::deserialize(&bytes(&case["response"]), v).unwrap();
            assert_eq!(response.serialize(v).unwrap(), bytes(&case["response"]));
        }
        for case in vectors()["requests"].as_array().unwrap() {
            let received = BlockTxnRequest::deserialize(&bytes(&case["hex"])).unwrap();
            assert_eq!(received.indices, indices(&case["indices"]));
            assert_eq!(received.serialize().unwrap(), bytes(&case["hex"]));
        }
    }

    #[test]
    fn independent_missing_indices_and_full_reconstruction() {
        for case in vectors()["cases"].as_array().unwrap() {
            let v = version(case);
            let block: Block = decode(&bytes(&case["block"])).unwrap();
            let compact = CompactBlock::deserialize(&bytes(&case["compact"]), v).unwrap();
            let local = block
                .transactions
                .iter()
                .enumerate()
                .filter(|(i, _)| i % 2 == 0)
                .map(|(_, tx)| tx.clone())
                .collect::<Vec<_>>();
            let prepared = compact.prepare(&local, v).unwrap();
            assert_eq!(
                prepared.request().serialize().unwrap(),
                bytes(&case["request"])
            );
            let response = BlockTxnResponse::deserialize(&bytes(&case["response"]), v).unwrap();
            let reconstructed = prepared.finish(response).unwrap();
            assert_eq!(encode(&reconstructed), bytes(&case["block"]));
        }
    }

    #[test]
    fn versions_use_txid_or_wtxid_and_never_trust_a_supplied_lookup_key() {
        let (block, _) = base();
        let mut local = block.transactions.clone();
        let mut items = local[1].witness[0].iter().cloned().collect::<Vec<_>>();
        items[0][0] ^= 1;
        local[1].witness[0] = btc_primitives::transaction::Witness::from_items(items);
        assert_eq!(local[1].txid(), block.transactions[1].txid());
        assert_ne!(local[1].wtxid(), block.transactions[1].wtxid());
        let legacy = CompactBlock::from_block(&block, 42, CompactVersion::V1).unwrap();
        assert!(legacy
            .prepare(&local, CompactVersion::V1)
            .unwrap()
            .request()
            .indices
            .is_empty());
        let witness = CompactBlock::from_block(&block, 42, CompactVersion::V2).unwrap();
        assert_eq!(
            witness
                .prepare(&local, CompactVersion::V2)
                .unwrap()
                .request()
                .indices,
            vec![1]
        );
        assert!(CompactBlock::deserialize(
            &witness.serialize(CompactVersion::V2).unwrap(),
            CompactVersion::V1
        )
        .is_err());
    }

    #[test]
    fn injected_candidate_collision_requests_the_transaction_without_overwrite() {
        // Inject the short-ID lookup only in this private classification test;
        // production always hashes actual txid/wtxid with the real header key.
        let (block, mut compact) = base();
        compact.short_ids = vec![1];
        let candidates = vec![
            block.transactions[1].clone(),
            block.transactions[2].clone(),
            block.transactions[1].clone(),
        ];
        let partial = compact
            .prepare_with_ids(&candidates, CompactVersion::V2, |_| 1)
            .unwrap();
        assert_eq!(partial.request().indices, vec![1]);
        compact.short_ids = vec![1, 1];
        assert!(matches!(
            compact.prepare(&[], CompactVersion::V2),
            Err(CompactError::Collision)
        ));
    }

    #[test]
    fn malformed_layouts_counts_and_differential_indices_cannot_panic_or_allocate_from_claims() {
        let (block, compact) = base();
        for prefilled in [
            vec![
                PrefilledTx {
                    index: 0,
                    tx: block.transactions[0].clone(),
                },
                PrefilledTx {
                    index: 0,
                    tx: block.transactions[1].clone(),
                },
            ],
            vec![PrefilledTx {
                index: u16::MAX,
                tx: block.transactions[0].clone(),
            }],
        ] {
            let mut bad = compact.clone();
            bad.prefilled_txs = prefilled;
            assert!(bad.prepare(&[], CompactVersion::V2).is_err());
            assert!(bad.serialize(CompactVersion::V2).is_err());
        }
        let mut bad = compact.clone();
        bad.short_ids.clear();
        bad.prefilled_txs.clear();
        assert!(bad.prepare(&[], CompactVersion::V2).is_err());
        for count in [65536, u64::MAX] {
            let mut payload = encode(&block.header);
            payload.extend_from_slice(&0u64.to_le_bytes());
            VarInt(count).encode(&mut payload).unwrap();
            assert!(CompactBlock::deserialize(&payload, CompactVersion::V2).is_err());
            let mut request = block.block_hash().to_bytes().to_vec();
            VarInt(count).encode(&mut request).unwrap();
            assert!(BlockTxnRequest::deserialize(&request).is_err());
            assert!(BlockTxnResponse::deserialize(&request, CompactVersion::V2).is_err());
        }
        for values in [vec![65536], vec![65535, 0], vec![u64::MAX]] {
            let mut request = block.block_hash().to_bytes().to_vec();
            VarInt(values.len() as u64).encode(&mut request).unwrap();
            for value in values {
                VarInt(value).encode(&mut request).unwrap();
            }
            assert!(BlockTxnRequest::deserialize(&request).is_err());
        }
        let request = BlockTxnRequest {
            block_hash: block.block_hash(),
            indices: vec![1, 1],
        };
        assert!(request.serialize().is_err());
        let mut request = block.block_hash().to_bytes().to_vec();
        request.extend_from_slice(&[0xfd, 0, 0]);
        assert!(BlockTxnRequest::deserialize(&request).is_err());
        let mut payload = compact.serialize(CompactVersion::V2).unwrap();
        payload.push(0);
        assert!(CompactBlock::deserialize(&payload, CompactVersion::V2).is_err());
        assert!(
            CompactBlock::deserialize(&vec![0; MAX_COMPACT_PAYLOAD + 1], CompactVersion::V2)
                .is_err()
        );
    }

    #[test]
    fn completion_requires_exact_response_hash_count_ids_and_real_merkle_root() {
        let (block, compact) = base();
        let response = BlockTxnResponse {
            block_hash: block.block_hash(),
            transactions: block.transactions[1..].to_vec(),
        };
        let prepare = || compact.prepare(&[], CompactVersion::V2).unwrap();
        let mut bad = response.clone();
        bad.block_hash = BlockHash::ZERO;
        assert!(prepare().finish(bad).is_err());
        let mut bad = response.clone();
        bad.transactions.pop();
        assert!(prepare().finish(bad).is_err());
        let mut bad = response.clone();
        bad.transactions.swap(0, 1);
        assert!(prepare().finish(bad).is_err());
        assert_eq!(prepare().finish(response.clone()).unwrap(), block);
        let mut wrong_root = compact.clone();
        wrong_root.header.merkle_root = TxHash::ZERO;
        let response = BlockTxnResponse {
            block_hash: wrong_root.header.block_hash(),
            transactions: block.transactions[1..].to_vec(),
        };
        assert!(wrong_root
            .prepare(&[], CompactVersion::V2)
            .unwrap()
            .finish(response)
            .is_err());
        let mut duplicate = block.clone();
        duplicate.transactions[2] = duplicate.transactions[1].clone();
        duplicate.header.merkle_root = duplicate.compute_merkle_root();
        let full = CompactBlock {
            header: duplicate.header,
            nonce: 0,
            short_ids: Vec::new(),
            prefilled_txs: duplicate
                .transactions
                .iter()
                .enumerate()
                .map(|(i, tx)| PrefilledTx {
                    index: i as u16,
                    tx: tx.clone(),
                })
                .collect(),
        };
        let response = BlockTxnResponse {
            block_hash: duplicate.block_hash(),
            transactions: Vec::new(),
        };
        assert!(full
            .prepare(&[], CompactVersion::V2)
            .unwrap()
            .finish(response)
            .is_err());
    }

    #[test]
    fn actual_payload_codec_preserves_core_messages_and_rejects_bad_sendcmpct() {
        use crate::codec::{decode_payload, encode_payload};
        for case in vectors()["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| version(case) == CompactVersion::V2)
        {
            for (command, field) in [
                ("cmpctblock", "compact"),
                ("getblocktxn", "request"),
                ("blocktxn", "response"),
            ] {
                let payload = bytes(&case[field]);
                let message = decode_payload(command, &payload).unwrap();
                assert_eq!(message.command(), command);
                assert_eq!(encode_payload(&message).unwrap(), payload);
            }
        }
        for payload in [vec![2, 2, 0, 0, 0, 0, 0, 0, 0], vec![0; 8], vec![0; 10]] {
            assert!(decode_payload("sendcmpct", &payload).is_err());
        }
    }
}
