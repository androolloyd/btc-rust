//! Experimental BIP330 reconciliation primitives, not a negotiated P2P session.
//!
//! Real 32-bit PinSketch bytes and salted witness-transaction short IDs replace
//! the former retained-set/XOR-bucket shortcut. Live round scheduling, handshake
//! negotiation, snapshot/extension messages and INV fallback remain unsupported.
//! Ordinary peers continue using the existing transaction relay protocol.

use std::collections::{HashMap, HashSet};

use btc_primitives::hash::{sha256, TxHash};

pub use crate::minisketch::{Minisketch, SketchError, MAX_CAPACITY};
use crate::siphash::siphash_2_4;

/// A BIP330 request's set size is uint16. This is also our local input bound.
pub const MAX_SET_SIZE: usize = u16::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReconciliationError {
    #[error(transparent)]
    Sketch(#[from] SketchError),
    #[error("reconciliation set exceeds 65535 witness transaction IDs")]
    SetSize,
    #[error("distinct witness transaction IDs collide at short ID {0}; use INV fallback")]
    Collision(u32),
}

/// Derived from both peers' salts, with the exact BIP330 tagged-hash domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShortIdKey {
    k0: u64,
    k1: u64,
}

impl ShortIdKey {
    pub fn new(salt_a: u64, salt_b: u64) -> Self {
        let tag = sha256(b"Tx Relay Salting");
        let mut preimage = [0; 80];
        preimage[..32].copy_from_slice(&tag);
        preimage[32..64].copy_from_slice(&tag);
        preimage[64..72].copy_from_slice(&salt_a.min(salt_b).to_le_bytes());
        preimage[72..80].copy_from_slice(&salt_a.max(salt_b).to_le_bytes());
        let hash = sha256(&preimage);
        Self {
            k0: u64::from_le_bytes(hash[..8].try_into().expect("eight-byte key")),
            k1: u64::from_le_bytes(hash[8..16].try_into().expect("eight-byte key")),
        }
    }

    /// Takes the INTERNAL-order witness hash, not the legacy txid/display hex.
    /// The shared hash type cannot distinguish txid from wtxid; callers must.
    pub fn short_id(&self, wtxid: &TxHash) -> u32 {
        (1 + siphash_2_4(self.k0, self.k1, wtxid.as_bytes()) % u32::MAX as u64) as u32
    }
}

/// Local snapshot used to build a sketch and classify decoded differences.
/// Only this local map is retained; peer sets are never needed by the decoder.
#[derive(Debug, Clone)]
pub struct ReconciliationSet {
    ids: HashMap<u32, TxHash>,
}

impl ReconciliationSet {
    pub fn new(key: ShortIdKey, wtxids: &HashSet<TxHash>) -> Result<Self, ReconciliationError> {
        if wtxids.len() > MAX_SET_SIZE {
            return Err(ReconciliationError::SetSize);
        }
        let mut ids = HashMap::with_capacity(wtxids.len());
        for &wtxid in wtxids {
            let id = key.short_id(&wtxid);
            if ids.insert(id, wtxid).is_some() {
                return Err(ReconciliationError::Collision(id));
            }
        }
        Ok(Self { ids })
    }

    pub fn build_sketch(&self, capacity: usize) -> Result<Minisketch, SketchError> {
        let mut sketch = Minisketch::new(capacity)?;
        for &id in self.ids.keys() {
            sketch.add(id)?;
        }
        Ok(sketch)
    }

    /// Compare only our local snapshot with a sketch decoded from peer bytes.
    /// Local short-ID collisions fail construction. Collisions between the two
    /// peers' sets and oversized-difference aliases cannot be excluded here.
    pub fn reconcile(&self, peer: &Minisketch) -> Result<ReconciliationResult, SketchError> {
        let local = self.build_sketch(peer.capacity())?;
        let difference = peer.decode_differences(&local)?;
        let mut they_need = Vec::new();
        let mut we_need_ids = Vec::new();
        for id in difference {
            if let Some(&wtxid) = self.ids.get(&id) {
                they_need.push(wtxid);
            } else {
                we_need_ids.push(id);
            }
        }
        they_need.sort_unstable_by_key(|hash| hash.to_bytes());
        Ok(ReconciliationResult {
            they_need,
            we_need_ids,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationResult {
    /// Actual local witness hashes to announce through normal INV handling.
    pub they_need: Vec<TxHash>,
    /// Peer short IDs to request; these are not invented transaction hashes.
    pub we_need_ids: Vec<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/data/bip330-sketches.json")).unwrap()
    }

    fn numbers(value: &Value) -> Vec<u32> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u32)
            .collect()
    }

    fn sketch(elements: &[u32], capacity: usize) -> Minisketch {
        let mut sketch = Minisketch::new(capacity).unwrap();
        for &element in elements {
            sketch.add(element).unwrap();
        }
        sketch
    }

    #[test]
    fn upstream_minisketch_serializations_and_received_decodes() {
        for case in vectors()["sketches"].as_array().unwrap() {
            let encoded = hex::decode(case["hex"].as_str().unwrap()).unwrap();
            let capacity = case["capacity"].as_u64().unwrap() as usize;
            let local = sketch(&numbers(&case["elements"]), capacity);
            assert_eq!(local.serialize(), encoded, "{}", case["name"]);
            let received = Minisketch::deserialize(&encoded).unwrap();
            assert_eq!(received.capacity(), capacity);
            if case["decoded"].is_null() {
                assert!(received.decode().is_err(), "{}", case["name"]);
            } else {
                assert_eq!(
                    received.decode().unwrap(),
                    numbers(&case["decoded"]),
                    "{}",
                    case["name"]
                );
            }
        }
        for case in vectors()["raw_decodes"].as_array().unwrap() {
            let received =
                Minisketch::deserialize(&hex::decode(case["hex"].as_str().unwrap()).unwrap())
                    .unwrap();
            if case["decoded"].is_null() {
                assert!(received.decode().is_err(), "{}", case["name"]);
            } else {
                assert_eq!(
                    received.decode().unwrap(),
                    numbers(&case["decoded"]),
                    "{}",
                    case["name"]
                );
            }
        }
    }

    #[test]
    fn upstream_short_ids_use_both_salts_and_full_witness_hash() {
        for case in vectors()["short_ids"].as_array().unwrap() {
            let a = case["salt_a"].as_u64().unwrap();
            let b = case["salt_b"].as_u64().unwrap();
            let hash = TxHash::from_hex_internal(case["wtxid_internal"].as_str().unwrap()).unwrap();
            let key = ShortIdKey::new(a, b);
            assert_eq!(key, ShortIdKey::new(b, a));
            assert_eq!(
                key.short_id(&hash),
                case["short_id"].as_u64().unwrap() as u32
            );
            assert_ne!(key.short_id(&hash), 0);
        }
    }

    #[test]
    fn independent_bidirectional_reconciliation_without_peer_set() {
        let fixture = vectors();
        let case = &fixture["reconciliation"];
        let key = ShortIdKey::new(
            case["salt_a"].as_u64().unwrap(),
            case["salt_b"].as_u64().unwrap(),
        );
        let hashes = |value: &Value| {
            value
                .as_array()
                .unwrap()
                .iter()
                .map(|v| TxHash::from_hex_internal(v.as_str().unwrap()).unwrap())
                .collect::<HashSet<_>>()
        };
        let local = ReconciliationSet::new(key, &hashes(&case["local_wtxids_internal"])).unwrap();
        let peer =
            Minisketch::deserialize(&hex::decode(case["peer_sketch"].as_str().unwrap()).unwrap())
                .unwrap();
        let result = local.reconcile(&peer).unwrap();
        assert_eq!(
            result.they_need.into_iter().collect::<HashSet<_>>(),
            hashes(&case["they_need_internal"])
        );
        assert_eq!(result.we_need_ids, numbers(&case["we_need_ids"]));
    }

    #[test]
    fn short_id_collision_and_set_bound_fail_explicitly() {
        let fixture = vectors();
        let case = &fixture["collision"];
        let key = ShortIdKey::new(
            case["salt_a"].as_u64().unwrap(),
            case["salt_b"].as_u64().unwrap(),
        );
        let hashes = case["wtxids_internal"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| TxHash::from_hex_internal(v.as_str().unwrap()).unwrap())
            .collect();
        assert!(matches!(
            ReconciliationSet::new(key, &hashes),
            Err(ReconciliationError::Collision(_))
        ));
        let hashes = (0..=MAX_SET_SIZE)
            .map(|i| {
                let mut hash = [0; 32];
                hash[..8].copy_from_slice(&(i as u64).to_le_bytes());
                TxHash::from_bytes(hash)
            })
            .collect();
        assert!(matches!(
            ReconciliationSet::new(key, &hashes),
            Err(ReconciliationError::SetSize)
        ));
    }

    #[test]
    fn capacities_and_invalid_elements_are_bounded_and_atomic() {
        assert_eq!(Minisketch::new(usize::MAX), Err(SketchError::Capacity));
        assert_eq!(
            Minisketch::deserialize(&[0; 4 * (MAX_CAPACITY + 1)]),
            Err(SketchError::Capacity)
        );
        for length in [1, 2, 3, 5, 7, 255] {
            assert_eq!(
                Minisketch::deserialize(&vec![0; length]),
                Err(SketchError::Encoding)
            );
        }
        let mut one = sketch(&[1], 3);
        let original = one.clone();
        assert_eq!(one.add(0), Err(SketchError::ZeroElement));
        assert_eq!(one, original);
        assert_eq!(
            one.merge(&sketch(&[1], 4)),
            Err(SketchError::CapacityMismatch)
        );
        assert_eq!(one, original);
        one.add(1).unwrap();
        assert!(one.is_zero());
        assert_eq!(one.decode().unwrap(), Vec::<u32>::new());
        assert_eq!(Minisketch::default().decode().unwrap(), Vec::<u32>::new());
    }

    #[test]
    fn extension_is_concatenation_and_short_capacity_may_alias() {
        let elements = [1, 3, 5, 7, u32::MAX, 0x8000_0000];
        let full = sketch(&elements, 12).serialize();
        let initial = sketch(&elements, 3).serialize();
        assert_eq!(&full[..initial.len()], initial);
        let joined = [initial, full[12..].to_vec()].concat();
        assert_eq!(
            Minisketch::deserialize(&joined).unwrap().decode().unwrap(),
            {
                let mut sorted = elements.to_vec();
                sorted.sort_unstable();
                sorted
            }
        );
        // A one-slot sketch only communicates XOR. Capacity overflow cannot be
        // universally detected, and must never be reported as authenticated.
        assert_eq!(sketch(&[1, 2], 1).decode().unwrap(), vec![3]);
        assert_eq!(sketch(&[1, 2, 3], 1).decode().unwrap(), Vec::<u32>::new());
    }
}
