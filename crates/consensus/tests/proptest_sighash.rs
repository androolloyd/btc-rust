//! Property-based tests for btc-consensus sighash and script number encoding.
//!
//! These tests verify that cryptographic and encoding invariants hold for all inputs.

use proptest::prelude::*;

use btc_consensus::script_engine::{encode_num, decode_num};
use btc_consensus::sighash::{sighash_legacy, SighashType};
use btc_primitives::amount::Amount;
use btc_primitives::hash::TxHash;
use btc_primitives::script::ScriptBuf;
use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

// ---------------------------------------------------------------------------
// Arbitrary generators
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
    (arb_outpoint(), arb_script(50), any::<u32>()).prop_map(|(previous_output, script_sig, sequence)| {
        TxIn {
            previous_output,
            script_sig,
            sequence,
        }
    })
}

fn arb_txout() -> impl Strategy<Value = TxOut> {
    (any::<i64>(), arb_script(50)).prop_map(|(value, script_pubkey)| {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        }
    })
}

/// Generate a legacy transaction suitable for sighash testing (1-3 inputs, 1-3 outputs).
fn arb_sighash_tx() -> impl Strategy<Value = Transaction> {
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

// ---------------------------------------------------------------------------
// 1. sighash_legacy is deterministic
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn sighash_legacy_is_deterministic(
        tx in arb_sighash_tx(),
        script_code in prop::collection::vec(any::<u8>(), 0..=100),
    ) {
        // Always use input_index 0, which is guaranteed to exist (1..=3 inputs).
        let h1 = sighash_legacy(&tx, 0, &script_code, SighashType::ALL).unwrap();
        let h2 = sighash_legacy(&tx, 0, &script_code, SighashType::ALL).unwrap();
        prop_assert_eq!(h1, h2, "sighash_legacy must be deterministic for the same inputs");
    }
}

// ---------------------------------------------------------------------------
// 2. Different hash types produce different sighashes (overwhelmingly likely)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn sighash_different_hash_types(
        tx in arb_sighash_tx(),
        script_code in prop::collection::vec(any::<u8>(), 1..=100),
    ) {
        let hash_all = sighash_legacy(&tx, 0, &script_code, SighashType::ALL).unwrap();
        let hash_none = sighash_legacy(&tx, 0, &script_code, SighashType::NONE).unwrap();

        // SIGHASH_ALL and SIGHASH_NONE commit to different sets of outputs,
        // so they should produce different digests unless the tx has extremely
        // degenerate structure. The probability of collision is 2^-256.
        prop_assert_ne!(
            hash_all, hash_none,
            "SIGHASH_ALL and SIGHASH_NONE should produce different hashes"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. encode_num / decode_num roundtrip for all i32 values
// ---------------------------------------------------------------------------

proptest! {
    /// Script numbers are limited to 4 bytes (MAX_SCRIPT_NUM_LENGTH = 4),
    /// which constrains the representable range. All i32 values are within range.
    #[test]
    fn encode_decode_num_roundtrip_i32(n: i32) {
        let encoded = encode_num(n as i64);
        let decoded = decode_num(&encoded).unwrap();
        prop_assert_eq!(decoded, n as i64, "encode_num/decode_num roundtrip failed for {}", n);
    }

    /// Zero encodes as empty bytes and decodes back to zero.
    #[test]
    fn encode_num_zero_is_empty(_dummy in 0..1u8) {
        let encoded = encode_num(0);
        prop_assert!(encoded.is_empty(), "encode_num(0) should produce empty vec");
        let decoded = decode_num(&encoded).unwrap();
        prop_assert_eq!(decoded, 0, "decode_num of empty should be 0");
    }

    /// Positive numbers produce encodings with the sign bit clear.
    #[test]
    fn encode_num_positive_sign_bit(n in 1i32..=i32::MAX) {
        let encoded = encode_num(n as i64);
        prop_assert!(!encoded.is_empty());
        // The sign bit of the last byte should be 0 for positive numbers
        let last = *encoded.last().unwrap();
        prop_assert_eq!(last & 0x80, 0, "positive number {} should have sign bit clear, got encoded {:?}", n, encoded);
    }

    /// Negative numbers produce encodings with the sign bit set.
    #[test]
    fn encode_num_negative_sign_bit(n in i32::MIN..=-1i32) {
        let encoded = encode_num(n as i64);
        prop_assert!(!encoded.is_empty());
        // The sign bit of the last byte should be 1 for negative numbers
        let last = *encoded.last().unwrap();
        prop_assert_ne!(last & 0x80, 0, "negative number {} should have sign bit set, got encoded {:?}", n, encoded);
    }
}

// ---------------------------------------------------------------------------
// 4. sighash_legacy with out-of-range input index returns error
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn sighash_legacy_oob_input_errors(
        tx in arb_sighash_tx(),
        extra in 1u32..=100u32,
    ) {
        let bad_index = tx.inputs.len() + extra as usize;
        let result = sighash_legacy(&tx, bad_index, &[], SighashType::ALL);
        prop_assert!(result.is_err(), "sighash with out-of-range input_index should error");
    }
}

// ---------------------------------------------------------------------------
// 5. SIGHASH_SINGLE bug: input_index >= outputs.len() returns the known constant
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn sighash_single_bug_constant(
        version: i32,
        lock_time: u32,
        script_code in prop::collection::vec(any::<u8>(), 0..=50),
    ) {
        // Create a tx with 2 inputs but 0 outputs -- triggers the SIGHASH_SINGLE bug
        let tx = Transaction {
            version,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0x01; 32]), 0),
                    script_sig: ScriptBuf::new(),
                    sequence: 0xffffffff,
                },
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0x02; 32]), 0),
                    script_sig: ScriptBuf::new(),
                    sequence: 0xffffffff,
                },
            ],
            outputs: vec![],
            witness: Vec::new(),
            lock_time,
        };

        let hash = sighash_legacy(&tx, 1, &script_code, SighashType::SINGLE).unwrap();
        let mut expected = [0u8; 32];
        expected[0] = 1;
        prop_assert_eq!(hash, expected, "SIGHASH_SINGLE bug should return 0x0100...00");
    }
}

// ---------------------------------------------------------------------------
// 6. sighash_legacy produces non-zero 32-byte hash for valid SIGHASH_ALL
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn sighash_legacy_produces_nonzero(
        tx in arb_sighash_tx(),
        script_code in prop::collection::vec(any::<u8>(), 0..=100),
    ) {
        let hash = sighash_legacy(&tx, 0, &script_code, SighashType::ALL).unwrap();
        prop_assert_eq!(hash.len(), 32);
        // The hash is sha256d output, so all-zeros is astronomically unlikely
        prop_assert_ne!(hash, [0u8; 32], "sighash should not be all zeros");
    }
}
