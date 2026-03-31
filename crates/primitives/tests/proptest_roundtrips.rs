//! Property-based tests for btc-primitives using proptest.
//!
//! These tests verify that invariants hold for ALL inputs, not just hand-picked examples.
//! Every encodable type must survive encode -> decode -> re-encode without data loss.

use proptest::prelude::*;

use btc_primitives::amount::Amount;
use btc_primitives::block::BlockHeader;
use btc_primitives::compact::CompactTarget;
use btc_primitives::encode::{self, Encodable, VarInt};
use btc_primitives::hash::{BlockHash, TxHash, hash160, sha256, sha256d};
use btc_primitives::script::ScriptBuf;
use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness};

// ---------------------------------------------------------------------------
// Arbitrary generators (strategies)
// ---------------------------------------------------------------------------

fn arb_outpoint() -> impl Strategy<Value = OutPoint> {
    (any::<[u8; 32]>(), any::<u32>()).prop_map(|(hash, vout)| {
        OutPoint::new(TxHash::from_bytes(hash), vout)
    })
}

fn arb_script(max_len: usize) -> impl Strategy<Value = ScriptBuf> {
    prop::collection::vec(any::<u8>(), 0..=max_len).prop_map(ScriptBuf::from_bytes)
}

fn arb_txin() -> impl Strategy<Value = TxIn> {
    (arb_outpoint(), arb_script(100), any::<u32>()).prop_map(|(previous_output, script_sig, sequence)| {
        TxIn {
            previous_output,
            script_sig,
            sequence,
        }
    })
}

fn arb_txout() -> impl Strategy<Value = TxOut> {
    // Only generate valid (non-negative, <= MAX_MONEY) output values
    (0i64..=2_100_000_000_000_000i64, arb_script(100)).prop_map(|(value, script_pubkey)| {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        }
    })
}

/// Generate a legacy (non-segwit) transaction with 1-3 inputs and 1-3 outputs.
fn arb_legacy_transaction() -> impl Strategy<Value = Transaction> {
    (
        any::<i32>(),
        prop::collection::vec(arb_txin(), 1..=3),
        prop::collection::vec(arb_txout(), 1..=3),
        any::<u32>(),
    )
        .prop_map(|(version, inputs, outputs, lock_time)| {
            Transaction {
                version,
                inputs,
                outputs,
                witness: Vec::new(),
                lock_time,
            }
        })
}

fn arb_witness_item() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=72)
}

fn arb_witness() -> impl Strategy<Value = Witness> {
    prop::collection::vec(arb_witness_item(), 1..=3)
        .prop_map(Witness::from_items)
}

/// Generate a segwit transaction with 1-3 inputs, 1-3 outputs, and matching witness data.
fn arb_segwit_transaction() -> impl Strategy<Value = Transaction> {
    (
        any::<i32>(),
        prop::collection::vec(arb_txin(), 1..=3usize),
        prop::collection::vec(arb_txout(), 1..=3),
        any::<u32>(),
    )
        .prop_flat_map(|(version, inputs, outputs, lock_time)| {
            let n_inputs = inputs.len();
            // Generate exactly one witness per input, at least one must be non-empty
            let witnesses = prop::collection::vec(arb_witness(), n_inputs..=n_inputs);
            (Just(version), Just(inputs), Just(outputs), witnesses, Just(lock_time))
        })
        .prop_map(|(version, inputs, outputs, witness, lock_time)| {
            Transaction {
                version,
                inputs,
                outputs,
                witness,
                lock_time,
            }
        })
}

/// Strategy that produces either legacy or segwit transactions.
fn arb_transaction() -> impl Strategy<Value = Transaction> {
    prop_oneof![
        arb_legacy_transaction(),
        arb_segwit_transaction(),
    ]
}

fn arb_block_header() -> impl Strategy<Value = BlockHeader> {
    (
        any::<i32>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
    )
        .prop_map(|(version, prev, merkle, time, bits, nonce)| {
            BlockHeader {
                version,
                prev_blockhash: BlockHash::from_bytes(prev),
                merkle_root: TxHash::from_bytes(merkle),
                time,
                bits: CompactTarget::from_u32(bits),
                nonce,
            }
        })
}

// ---------------------------------------------------------------------------
// 1. Transaction roundtrip
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn transaction_roundtrip(tx in arb_transaction()) {
        let encoded = encode::encode(&tx);
        let decoded: Transaction = encode::decode(&encoded).unwrap();
        let re_encoded = encode::encode(&decoded);
        prop_assert_eq!(&encoded, &re_encoded, "transaction roundtrip failed: encode -> decode -> encode produced different bytes");
        prop_assert_eq!(tx, decoded, "decoded transaction differs from original");
    }
}

// ---------------------------------------------------------------------------
// 2. BlockHeader roundtrip (always 80 bytes)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn block_header_roundtrip(header in arb_block_header()) {
        let encoded = encode::encode(&header);
        prop_assert_eq!(encoded.len(), 80, "block header encoding must always be 80 bytes");
        let decoded: BlockHeader = encode::decode(&encoded).unwrap();
        let re_encoded = encode::encode(&decoded);
        prop_assert_eq!(&encoded, &re_encoded);
        prop_assert_eq!(header, decoded);
    }
}

// ---------------------------------------------------------------------------
// 3. VarInt roundtrip
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn varint_roundtrip(value: u64) {
        let vi = VarInt(value);
        let encoded = encode::encode(&vi);
        let decoded: VarInt = encode::decode(&encoded).unwrap();
        prop_assert_eq!(decoded, vi, "VarInt roundtrip failed for value {}", value);
    }

    #[test]
    fn varint_encoded_size_is_correct(value: u64) {
        let vi = VarInt(value);
        let encoded = encode::encode(&vi);
        prop_assert_eq!(encoded.len(), vi.encoded_size(), "VarInt::encoded_size() disagrees with actual encoding length for {}", value);
    }
}

// ---------------------------------------------------------------------------
// 4. ScriptBuf roundtrip
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn script_roundtrip(data in prop::collection::vec(any::<u8>(), 0..=500)) {
        let script = ScriptBuf::from_bytes(data.clone());
        let encoded = encode::encode(&script);
        let decoded: ScriptBuf = encode::decode(&encoded).unwrap();
        prop_assert_eq!(decoded.as_bytes(), script.as_bytes(), "ScriptBuf roundtrip failed");
    }
}

// ---------------------------------------------------------------------------
// 5. OutPoint roundtrip
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn outpoint_roundtrip(outpoint in arb_outpoint()) {
        let encoded = encode::encode(&outpoint);
        prop_assert_eq!(encoded.len(), 36, "OutPoint encoding must always be 36 bytes");
        let decoded: OutPoint = encode::decode(&encoded).unwrap();
        prop_assert_eq!(decoded, outpoint, "OutPoint roundtrip failed");
    }
}

// ---------------------------------------------------------------------------
// 6. Amount properties
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn amount_from_sat_roundtrip(x: i64) {
        let amount = Amount::from_sat(x);
        prop_assert_eq!(amount.as_sat(), x, "from_sat({}).as_sat() should equal {}", x, x);
    }

    #[test]
    fn amount_add_zero_identity(x: i64) {
        let amount = Amount::from_sat(x);
        let result = amount + Amount::ZERO;
        prop_assert_eq!(result.as_sat(), x, "amount + ZERO should equal amount");
    }

    #[test]
    fn amount_sub_zero_identity(x: i64) {
        let amount = Amount::from_sat(x);
        let result = amount - Amount::ZERO;
        prop_assert_eq!(result.as_sat(), x, "amount - ZERO should equal amount");
    }
}

#[test]
fn amount_btc_sat_relationship() {
    assert_eq!(Amount::from_btc(1), Amount::from_sat(100_000_000));
    assert_eq!(Amount::from_btc(21_000_000), Amount::MAX_MONEY);
}

// ---------------------------------------------------------------------------
// 7. Hash properties
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn sha256d_is_deterministic(data in prop::collection::vec(any::<u8>(), 0..=1000)) {
        let h1 = sha256d(&data);
        let h2 = sha256d(&data);
        prop_assert_eq!(h1, h2, "sha256d must be deterministic");
    }

    #[test]
    fn sha256d_different_inputs_different_outputs(
        x in prop::collection::vec(any::<u8>(), 1..=200),
        y in prop::collection::vec(any::<u8>(), 1..=200),
    ) {
        // When x != y, sha256d(x) should almost certainly differ from sha256d(y).
        // This is probabilistic: collision probability is negligible (2^-256).
        prop_assume!(x != y);
        let hx = sha256d(&x);
        let hy = sha256d(&y);
        prop_assert_ne!(hx, hy, "sha256d collision detected (astronomically unlikely)");
    }

    #[test]
    fn sha256_produces_32_bytes(data in prop::collection::vec(any::<u8>(), 0..=1000)) {
        let hash = sha256(&data);
        prop_assert_eq!(hash.len(), 32);
    }

    #[test]
    fn hash160_produces_20_bytes(data in prop::collection::vec(any::<u8>(), 0..=1000)) {
        let hash = hash160(&data);
        prop_assert_eq!(hash.len(), 20);
    }
}

// ---------------------------------------------------------------------------
// 8. Base58 roundtrip (through Address API)
// ---------------------------------------------------------------------------

proptest! {
    /// Test P2PKH address base58 roundtrip: any 20-byte hash survives
    /// Address construction -> to_base58 -> from_base58 -> hash comparison.
    #[test]
    fn base58_p2pkh_roundtrip(hash in any::<[u8; 20]>()) {
        use btc_primitives::address::Address;
        use btc_primitives::network::Network;

        let addr = Address::P2pkh { hash, network: Network::Mainnet };
        let encoded = addr.to_base58().expect("P2PKH should produce base58");
        let decoded = Address::from_base58(&encoded, Network::Mainnet).unwrap();
        match decoded {
            Address::P2pkh { hash: decoded_hash, .. } => {
                prop_assert_eq!(hash, decoded_hash, "base58 P2PKH roundtrip hash mismatch");
            }
            other => {
                prop_assert!(false, "expected P2PKH, got {:?}", other);
            }
        }
    }

    /// Test P2SH address base58 roundtrip.
    #[test]
    fn base58_p2sh_roundtrip(hash in any::<[u8; 20]>()) {
        use btc_primitives::address::Address;
        use btc_primitives::network::Network;

        let addr = Address::P2sh { hash, network: Network::Mainnet };
        let encoded = addr.to_base58().expect("P2SH should produce base58");
        let decoded = Address::from_base58(&encoded, Network::Mainnet).unwrap();
        match decoded {
            Address::P2sh { hash: decoded_hash, .. } => {
                prop_assert_eq!(hash, decoded_hash, "base58 P2SH roundtrip hash mismatch");
            }
            other => {
                prop_assert!(false, "expected P2SH, got {:?}", other);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Additional integer encoding roundtrips
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn u32_roundtrip(val: u32) {
        let encoded = encode::encode(&val);
        prop_assert_eq!(encoded.len(), 4);
        let decoded: u32 = encode::decode(&encoded).unwrap();
        prop_assert_eq!(decoded, val);
    }

    #[test]
    fn i32_roundtrip(val: i32) {
        let encoded = encode::encode(&val);
        prop_assert_eq!(encoded.len(), 4);
        let decoded: i32 = encode::decode(&encoded).unwrap();
        prop_assert_eq!(decoded, val);
    }

    #[test]
    fn u64_roundtrip(val: u64) {
        let encoded = encode::encode(&val);
        prop_assert_eq!(encoded.len(), 8);
        let decoded: u64 = encode::decode(&encoded).unwrap();
        prop_assert_eq!(decoded, val);
    }

    #[test]
    fn i64_roundtrip(val: i64) {
        let encoded = encode::encode(&val);
        prop_assert_eq!(encoded.len(), 8);
        let decoded: i64 = encode::decode(&encoded).unwrap();
        prop_assert_eq!(decoded, val);
    }

    #[test]
    fn vec_u8_roundtrip(data in prop::collection::vec(any::<u8>(), 0..=500)) {
        let encoded = encode::encode(&data);
        let decoded: Vec<u8> = encode::decode(&encoded).unwrap();
        prop_assert_eq!(decoded, data);
    }
}

// ---------------------------------------------------------------------------
// Transaction-specific invariants
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn legacy_transaction_is_not_segwit(tx in arb_legacy_transaction()) {
        prop_assert!(!tx.is_segwit(), "a transaction with empty witness should not be segwit");
    }

    #[test]
    fn segwit_transaction_is_segwit(tx in arb_segwit_transaction()) {
        prop_assert!(tx.is_segwit(), "a transaction with non-empty witness should be segwit");
    }

    #[test]
    fn txid_is_deterministic(tx in arb_transaction()) {
        let id1 = tx.txid();
        let id2 = tx.txid();
        prop_assert_eq!(id1, id2, "txid must be deterministic");
    }

    #[test]
    fn encoded_size_matches_encode_length(tx in arb_transaction()) {
        let encoded = encode::encode(&tx);
        let reported = tx.encoded_size();
        prop_assert_eq!(encoded.len(), reported, "encoded_size() should match actual encoding length");
    }
}

// ---------------------------------------------------------------------------
// BlockHeader invariants
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn block_hash_is_deterministic(header in arb_block_header()) {
        let h1 = header.block_hash();
        let h2 = header.block_hash();
        prop_assert_eq!(h1, h2, "block_hash must be deterministic");
    }
}
