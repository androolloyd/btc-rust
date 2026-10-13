//! Electrum 1.4 header checkpoint trees over the actual active validated prefix.
//! Leaves are serialized-header SHA256d hashes, including genesis. Pair hashing
//! and odd-width duplication match ElectrumX. A response root is not a trust
//! anchor: clients must independently pin the expected checkpoint commitment.
use crate::chain_backend::{internal, NodeChainBackend, ValidatedChain};
use btc_primitives::{hash::sha256d, BlockHash};
use btc_rpc::handler::RpcError;
use serde_json::{json, Value};

/// At most roughly 64 MiB of hash payload across one cached prefix's levels.
/// This bounds proof construction, not block acceptance or chain length.
const MAX_CHECKPOINT_HEADERS: u64 = 1 << 20;

#[derive(Default)]
pub(super) struct HeaderProofCache {
    prefix: Option<(u64, BlockHash)>,
    levels: Vec<Vec<BlockHash>>,
}
fn pair(left: BlockHash, right: BlockHash) -> BlockHash {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(left.as_bytes());
    bytes[32..].copy_from_slice(right.as_bytes());
    BlockHash::from_bytes(sha256d(&bytes))
}
impl HeaderProofCache {
    fn proof(
        &mut self,
        height: u64,
        checkpoint: u64,
        mut hash_at: impl FnMut(u64) -> Result<BlockHash, RpcError>,
    ) -> Result<Value, RpcError> {
        let count = checkpoint
            .checked_add(1)
            .filter(|n| *n <= MAX_CHECKPOINT_HEADERS)
            .ok_or_else(|| RpcError::new(1, "header checkpoint prefix exceeds proof limit"))?;
        if height >= count {
            return Err(RpcError::new(
                1,
                "checkpoint does not cover requested header",
            ));
        }
        // The checkpoint hash commits to its ancestry. Later extensions can
        // retain this prefix; a reorg changing it cannot reuse the old tree.
        let end = hash_at(checkpoint)?;
        if self.prefix != Some((count, end)) {
            // Release the previous prefix before allocating the new one. Only
            // a complete successfully read tree gains an identity/cache hit.
            self.prefix = None;
            self.levels.clear();
            let mut leaves = Vec::with_capacity(count as usize);
            for h in 0..count {
                leaves.push(hash_at(h)?);
            }
            if leaves.last().copied() != Some(end) {
                return Err(internal("checkpoint prefix changed while reading"));
            }
            self.levels.push(leaves);
            while self.levels.last().unwrap().len() > 1 {
                let previous = self.levels.last().unwrap();
                let mut parents = Vec::with_capacity(previous.len().div_ceil(2));
                for chunk in previous.chunks(2) {
                    parents.push(pair(chunk[0], *chunk.get(1).unwrap_or(&chunk[0])));
                }
                self.levels.push(parents);
            }
            self.prefix = Some((count, end));
        }
        let mut index = height as usize;
        let mut branch = Vec::with_capacity(self.levels.len() - 1);
        for level in self.levels.iter().take(self.levels.len() - 1) {
            branch.push(level[(index ^ 1).min(level.len() - 1)].to_string());
            index >>= 1;
        }
        let root = self
            .levels
            .last()
            .and_then(|row| row.first())
            .ok_or_else(|| internal("header checkpoint cache incomplete"))?;
        Ok(json!({"branch":branch,"root":root.to_string()}))
    }
}

impl NodeChainBackend {
    pub(super) fn header_checkpoint_proof(
        &self,
        data: &ValidatedChain,
        height: u64,
        checkpoint: u64,
    ) -> Result<Value, RpcError> {
        if height > checkpoint || checkpoint > data.headers.best_height() {
            return Err(RpcError::new(
                1,
                "require header height <= cp_height <= validated chain height",
            ));
        }
        let mut cache = self
            .header_proofs
            .lock()
            .map_err(|_| internal("header checkpoint cache lock poisoned"))?;
        cache.proof(height, checkpoint, |h| {
            data.headers
                .get_header_by_height(h)
                .map(|entry| entry.header.block_hash())
                .ok_or_else(|| internal("validated checkpoint header prefix incomplete"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::{block::BlockHeader, encode::decode};

    #[test]
    fn unchanged_published_electrum_checkpoint_branch_reaches_root() {
        // ElectrumX protocol-methods example: Bitcoin/BCH height 5, cp_height 8.
        // These are unchanged published header/branch/root bytes, not a tree
        // self-roundtrip or a fabricated chain accepted by the runtime.
        let bytes = hex::decode("0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477").unwrap();
        let header: BlockHeader = decode(&bytes).unwrap();
        assert!(header.check_proof_of_work());
        let branch = [
            "000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485",
            "96cbbc84783888e4cc971ae8acf86dd3c1a419370336bb3c634c97695a8c5ac9",
            "965ac94082cebbcffe458075651e9cc33ce703ab0115c72d9e8b1a9906b2b636",
            "89e5daa6950b895190716dd26054432b564ccdc2868188ba1da76de8e1dc7591",
        ];
        let mut hash = header.block_hash();
        let mut index = 5;
        for sibling in branch {
            let sibling = BlockHash::from_hex(sibling).unwrap();
            hash = if index & 1 == 1 {
                pair(sibling, hash)
            } else {
                pair(hash, sibling)
            };
            index >>= 1;
        }
        assert_eq!(
            hash.to_string(),
            "e347b1c43fd9b5415bf0d92708db8284b78daf4d0e24f9c3405f45feb85e25db"
        );
    }
    #[test]
    fn limits_are_checked_before_source_reads_or_allocation() {
        let mut cache = HeaderProofCache::default();
        for (height, checkpoint) in [(0, u64::MAX), (0, MAX_CHECKPOINT_HEADERS), (2, 1)] {
            assert_eq!(
                cache
                    .proof(height, checkpoint, |_| panic!(
                        "invalid request must not query source"
                    ))
                    .unwrap_err()
                    .code,
                1
            );
            assert!(cache.levels.is_empty());
            assert!(cache.prefix.is_none());
        }
    }
    #[test]
    fn failed_prefix_read_does_not_publish_partial_cache() {
        let genesis = btc_consensus::chain::genesis_header(
            &btc_consensus::validation::ChainParams::from_network(btc_primitives::Network::Mainnet),
        )
        .block_hash();
        let header: BlockHeader = decode(&hex::decode("0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477").unwrap()).unwrap();
        let mut cache = HeaderProofCache::default();
        // The real public endpoint hash and genesis are available, but an
        // intermediate source row is missing. No partial prefix becomes a hit.
        assert!(cache
            .proof(0, 5, |h| match h {
                0 => Ok(genesis),
                5 => Ok(header.block_hash()),
                _ => Err(internal("header missing")),
            })
            .is_err());
        assert!(cache.prefix.is_none());
        assert_eq!(
            cache.proof(0, 0, |_| Ok(genesis)).unwrap(),
            json!({"branch":[],"root":genesis.to_string()})
        );
    }
}
