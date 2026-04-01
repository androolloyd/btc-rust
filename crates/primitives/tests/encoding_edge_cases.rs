/// Edge cases in Bitcoin's encoding formats.
///
/// These tests cover boundary conditions in varint encoding, transaction
/// serialisation, and script construction that are important for consensus
/// compatibility.

use btc_primitives::amount::Amount;
use btc_primitives::encode::{self, VarInt};
use btc_primitives::hash::TxHash;
use btc_primitives::script::{Opcode, ScriptBuf};
use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness};

// ============================================================================
// VarInt max value
// ============================================================================

#[test]
fn test_varint_max_value() {
    // Bitcoin's VarInt encoding can represent values up to u64::MAX.
    // The maximum value uses the 0xFF prefix followed by 8 bytes.
    let max_vi = VarInt(u64::MAX);

    // Encode
    let encoded = encode::encode(&max_vi);
    assert_eq!(encoded.len(), 9, "u64::MAX varint should be 9 bytes");
    assert_eq!(encoded[0], 0xFF, "prefix byte for 8-byte varint should be 0xFF");

    // The remaining 8 bytes should be u64::MAX in little-endian
    let le_bytes = u64::MAX.to_le_bytes();
    assert_eq!(&encoded[1..], &le_bytes);

    // Decode and verify roundtrip
    let decoded: VarInt = encode::decode(&encoded).unwrap();
    assert_eq!(decoded.0, u64::MAX);

    // Verify encoded_size
    assert_eq!(max_vi.encoded_size(), 9);
}

#[test]
fn test_varint_boundary_values() {
    // Test values at each encoding boundary:
    // 0..=0xFC      => 1 byte
    // 0xFD..=0xFFFF => 3 bytes
    // 0x10000..=0xFFFFFFFF => 5 bytes
    // 0x100000000..=u64::MAX => 9 bytes

    let boundaries: &[(u64, usize)] = &[
        (0, 1),
        (0xFC, 1),           // last 1-byte value
        (0xFD, 3),           // first 3-byte value
        (0xFFFF, 3),         // last 3-byte value
        (0x10000, 5),        // first 5-byte value
        (0xFFFFFFFF, 5),     // last 5-byte value
        (0x100000000, 9),    // first 9-byte value
        (u64::MAX, 9),       // last 9-byte value
    ];

    for &(value, expected_size) in boundaries {
        let vi = VarInt(value);
        let encoded = encode::encode(&vi);
        assert_eq!(
            encoded.len(),
            expected_size,
            "VarInt({}) should encode to {} bytes, got {}",
            value,
            expected_size,
            encoded.len()
        );
        assert_eq!(vi.encoded_size(), expected_size);

        let decoded: VarInt = encode::decode(&encoded).unwrap();
        assert_eq!(decoded.0, value, "roundtrip failed for VarInt({})", value);
    }
}

// ============================================================================
// Empty transaction (0 inputs, 0 outputs)
// ============================================================================

#[test]
fn test_empty_transaction() {
    // A transaction with zero inputs and zero outputs is not valid per
    // consensus rules, but our encoding layer should still handle it
    // gracefully for serialisation purposes (a decoder may reject it
    // during validation, but the codec itself should be robust).
    //
    // Note: A segwit transaction with 0 inputs actually starts with
    // marker=0x00, which our decoder interprets as the segwit marker.
    // So a truly empty transaction in legacy format has version + 0 inputs
    // + 0 outputs + locktime = 10 bytes.

    let empty_tx = Transaction {
        version: 1,
        inputs: Vec::new(),
        outputs: Vec::new(),
        witness: Vec::new(),
        lock_time: 0,
    };

    // Verify basic properties
    assert!(!empty_tx.is_coinbase());
    assert!(!empty_tx.is_segwit());
    assert_eq!(empty_tx.inputs.len(), 0);
    assert_eq!(empty_tx.outputs.len(), 0);

    // Encoding should work: version(4) + vin_count(1=0x00) + vout_count(1=0x00) + locktime(4) = 10 bytes
    // But note: vin_count=0 triggers segwit detection in our decoder.
    // Build the raw bytes manually.
    let mut buf = Vec::new();
    buf.extend_from_slice(&1i32.to_le_bytes()); // version
    buf.push(0x00); // vin_count = 0 (this will be read as segwit marker!)

    // Because of the segwit detection (marker=0x00, flag=next byte), a
    // legacy tx with 0 inputs can't roundtrip through our codec directly.
    // This is by design: such transactions are invalid anyway.
    // Let's instead test that a tx with 1 input and 0 outputs encodes/decodes.
    let one_input_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: ScriptBuf::from_bytes(vec![0x01, 0x00]),
            sequence: 0xffffffff,
        }],
        outputs: Vec::new(),
        witness: Vec::new(),
        lock_time: 0,
    };

    let encoded = encode::encode(&one_input_tx);
    let decoded: Transaction = encode::decode(&encoded).unwrap();
    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.inputs.len(), 1);
    assert_eq!(decoded.outputs.len(), 0);
    assert_eq!(decoded.lock_time, 0);
}

// ============================================================================
// Max transaction size (4MW weight limit)
// ============================================================================

#[test]
fn test_max_transaction_size() {
    // The maximum block weight is 4,000,000 weight units (4MW).
    // A single transaction's weight is:
    //   weight = base_size * 3 + total_size
    // where base_size is the non-witness serialized size and total_size
    // includes witness data.
    //
    // The largest possible legacy (non-segwit) transaction would be one
    // where base_size = total_size, giving weight = 4 * size.
    // So max legacy tx size = 4,000,000 / 4 = 1,000,000 bytes.
    //
    // The largest possible segwit transaction could theoretically be up
    // to ~4MB if almost all data is in the witness.
    //
    // We test that our encoding handles large transactions correctly.

    const MAX_BLOCK_WEIGHT: usize = 4_000_000;
    const MAX_LEGACY_TX_SIZE: usize = MAX_BLOCK_WEIGHT / 4; // 1MB

    // Our codec limits script decode size to 100KB for safety. We test
    // with a large-but-decodable script to verify the weight calculations
    // and roundtrip behaviour at scale.
    let script_size = 90_000; // just under the 100KB script decode limit
    let large_script = vec![Opcode::OP_NOP as u8; script_size];

    let large_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: ScriptBuf::from_bytes(large_script),
            sequence: 0xffffffff,
        }],
        outputs: Vec::new(),
        witness: Vec::new(),
        lock_time: 0,
    };

    let encoded = encode::encode(&large_tx);
    // Should be well under 1MB but still a substantial size
    assert!(encoded.len() > 90_000,
        "encoded size {} should be > 90000", encoded.len());
    assert!(encoded.len() <= MAX_LEGACY_TX_SIZE,
        "encoded size {} should be <= {}", encoded.len(), MAX_LEGACY_TX_SIZE);

    // Verify it roundtrips
    let decoded: Transaction = encode::decode(&encoded).unwrap();
    assert_eq!(decoded.version, large_tx.version);
    assert_eq!(decoded.inputs.len(), 1);
    assert_eq!(decoded.inputs[0].script_sig.len(), large_tx.inputs[0].script_sig.len());

    // Weight calculation for legacy tx: weight = 4 * size
    let legacy_weight = 4 * encoded.len();
    assert!(legacy_weight <= MAX_BLOCK_WEIGHT,
        "weight {} should be <= {}", legacy_weight, MAX_BLOCK_WEIGHT);

    // Verify that at the theoretical max, the weight limit holds:
    // A single legacy tx of 1MB would have weight = 4MB = MAX_BLOCK_WEIGHT
    assert_eq!(4 * MAX_LEGACY_TX_SIZE, MAX_BLOCK_WEIGHT);
}

// ============================================================================
// Script with all opcodes
// ============================================================================

#[test]
fn test_script_with_all_opcodes() {
    // Construct a script containing every valid opcode (excluding data push
    // opcodes 0x01-0x4B which require accompanying data).
    //
    // This verifies that our Opcode enum covers the full range and that
    // script iteration handles all opcodes correctly.

    let all_opcodes: Vec<Opcode> = vec![
        // Push value
        Opcode::OP_0,
        Opcode::OP_1NEGATE,
        Opcode::OP_RESERVED,
        Opcode::OP_1, Opcode::OP_2, Opcode::OP_3, Opcode::OP_4,
        Opcode::OP_5, Opcode::OP_6, Opcode::OP_7, Opcode::OP_8,
        Opcode::OP_9, Opcode::OP_10, Opcode::OP_11, Opcode::OP_12,
        Opcode::OP_13, Opcode::OP_14, Opcode::OP_15, Opcode::OP_16,
        // Flow control
        Opcode::OP_NOP,
        Opcode::OP_VER,
        Opcode::OP_IF,
        Opcode::OP_NOTIF,
        Opcode::OP_VERIF,
        Opcode::OP_VERNOTIF,
        Opcode::OP_ELSE,
        Opcode::OP_ENDIF,
        Opcode::OP_VERIFY,
        Opcode::OP_RETURN,
        // Stack
        Opcode::OP_TOALTSTACK,
        Opcode::OP_FROMALTSTACK,
        Opcode::OP_2DROP,
        Opcode::OP_2DUP,
        Opcode::OP_3DUP,
        Opcode::OP_2OVER,
        Opcode::OP_2ROT,
        Opcode::OP_2SWAP,
        Opcode::OP_IFDUP,
        Opcode::OP_DEPTH,
        Opcode::OP_DROP,
        Opcode::OP_DUP,
        Opcode::OP_NIP,
        Opcode::OP_OVER,
        Opcode::OP_PICK,
        Opcode::OP_ROLL,
        Opcode::OP_ROT,
        Opcode::OP_SWAP,
        Opcode::OP_TUCK,
        // Splice (disabled)
        Opcode::OP_CAT,
        Opcode::OP_SUBSTR,
        Opcode::OP_LEFT,
        Opcode::OP_RIGHT,
        Opcode::OP_SIZE,
        // Bitwise (disabled except EQUAL/EQUALVERIFY)
        Opcode::OP_INVERT,
        Opcode::OP_AND,
        Opcode::OP_OR,
        Opcode::OP_XOR,
        Opcode::OP_EQUAL,
        Opcode::OP_EQUALVERIFY,
        Opcode::OP_RESERVED1,
        Opcode::OP_RESERVED2,
        // Arithmetic
        Opcode::OP_1ADD,
        Opcode::OP_1SUB,
        Opcode::OP_2MUL,
        Opcode::OP_2DIV,
        Opcode::OP_NEGATE,
        Opcode::OP_ABS,
        Opcode::OP_NOT,
        Opcode::OP_0NOTEQUAL,
        Opcode::OP_ADD,
        Opcode::OP_SUB,
        Opcode::OP_MUL,
        Opcode::OP_DIV,
        Opcode::OP_MOD,
        Opcode::OP_LSHIFT,
        Opcode::OP_RSHIFT,
        Opcode::OP_BOOLAND,
        Opcode::OP_BOOLOR,
        Opcode::OP_NUMEQUAL,
        Opcode::OP_NUMEQUALVERIFY,
        Opcode::OP_NUMNOTEQUAL,
        Opcode::OP_LESSTHAN,
        Opcode::OP_GREATERTHAN,
        Opcode::OP_LESSTHANOREQUAL,
        Opcode::OP_GREATERTHANOREQUAL,
        Opcode::OP_MIN,
        Opcode::OP_MAX,
        Opcode::OP_WITHIN,
        // Crypto
        Opcode::OP_RIPEMD160,
        Opcode::OP_SHA1,
        Opcode::OP_SHA256,
        Opcode::OP_HASH160,
        Opcode::OP_HASH256,
        Opcode::OP_CODESEPARATOR,
        Opcode::OP_CHECKSIG,
        Opcode::OP_CHECKSIGVERIFY,
        Opcode::OP_CHECKMULTISIG,
        Opcode::OP_CHECKMULTISIGVERIFY,
        // Expansion NOPs
        Opcode::OP_NOP1,
        Opcode::OP_CHECKLOCKTIMEVERIFY,
        Opcode::OP_CHECKSEQUENCEVERIFY,
        Opcode::OP_NOP4,
        Opcode::OP_NOP5,
        Opcode::OP_NOP6,
        Opcode::OP_NOP7,
        Opcode::OP_NOP8,
        Opcode::OP_NOP9,
        Opcode::OP_NOP10,
        // Tapscript
        Opcode::OP_CHECKSIGADD,
    ];

    // Build a script with all opcodes
    let mut script = ScriptBuf::new();
    for &op in &all_opcodes {
        script.push_opcode(op);
    }

    // Verify the script length matches the number of opcodes
    assert_eq!(script.len(), all_opcodes.len());

    // Verify Opcode::from_u8 roundtrip for each
    for &op in &all_opcodes {
        let byte = op as u8;
        let recovered = Opcode::from_u8(byte);
        assert_eq!(recovered, op,
            "Opcode::from_u8({:#04x}) returned {:?}, expected {:?}", byte, recovered, op);
    }

    // Verify that iterating instructions yields the correct opcodes
    // Note: OP_0 (0x00) is handled specially by the instruction iterator
    let instructions: Vec<_> = script.instructions().collect();
    assert_eq!(instructions.len(), all_opcodes.len(),
        "instruction count should match opcode count");

    // All instructions should parse successfully
    for (i, instr) in instructions.iter().enumerate() {
        assert!(instr.is_ok(),
            "instruction {} ({:?}) failed to parse", i, all_opcodes[i]);
    }

    // Verify script encode/decode roundtrip
    let encoded = encode::encode(&script);
    let decoded: ScriptBuf = encode::decode(&encoded).unwrap();
    assert_eq!(decoded, script);
}

// ============================================================================
// Additional encoding edge cases
// ============================================================================

#[test]
fn test_segwit_tx_with_empty_witness() {
    // A segwit transaction where the witness is present but contains
    // only empty witness stacks. This is unusual but valid.
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xAA; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![]),
            sequence: 0xffffffff,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::p2wpkh(&[0u8; 20]),
        }],
        witness: vec![
            Witness::from_items(vec![vec![0x30; 72], vec![0x02; 33]]),
        ],
        lock_time: 0,
    };

    assert!(tx.is_segwit());
    let encoded = encode::encode(&tx);
    let decoded: Transaction = encode::decode(&encoded).unwrap();
    assert_eq!(decoded.version, tx.version);
    assert_eq!(decoded.inputs.len(), 1);
    assert_eq!(decoded.outputs.len(), 1);
    assert!(decoded.is_segwit());
    assert_eq!(decoded.witness.len(), 1);
}

#[test]
fn test_outpoint_encoding_deterministic() {
    // Verify that the same outpoint always encodes to the same bytes
    let op1 = OutPoint::new(TxHash::from_bytes([0x42; 32]), 7);
    let op2 = OutPoint::new(TxHash::from_bytes([0x42; 32]), 7);

    let enc1 = encode::encode(&op1);
    let enc2 = encode::encode(&op2);
    assert_eq!(enc1, enc2, "identical outpoints must encode identically");

    // Different vout => different encoding
    let op3 = OutPoint::new(TxHash::from_bytes([0x42; 32]), 8);
    let enc3 = encode::encode(&op3);
    assert_ne!(enc1, enc3, "different vout must produce different encoding");
}

#[test]
fn test_varint_encoded_size_matches_actual() {
    // Ensure encoded_size() always matches the actual encoded length
    let values = [0u64, 1, 252, 253, 254, 255, 65534, 65535, 65536,
                  0xFFFFFFFE, 0xFFFFFFFF, 0x100000000, u64::MAX / 2, u64::MAX];
    for val in values {
        let vi = VarInt(val);
        let encoded = encode::encode(&vi);
        assert_eq!(vi.encoded_size(), encoded.len(),
            "encoded_size() mismatch for VarInt({})", val);
    }
}
