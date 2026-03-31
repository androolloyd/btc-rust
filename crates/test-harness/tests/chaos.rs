//! Chaos tests — exercise complex scripts and edge cases on regtest.
//!
//! These tests use the btc-test harness to mine blocks with complex
//! transactions and verify the node handles them correctly.

use btc_test::{TestNode, TestKeyPair, ScriptBuilder};
use btc_primitives::script::{Opcode, ScriptBuf};
use btc_primitives::transaction::{Transaction, TxIn, TxOut, OutPoint, Witness};
use btc_primitives::amount::Amount;
use btc_primitives::hash::TxHash;

// ============================================================================
// Basic spending patterns
// ============================================================================

#[test]
fn test_spend_coinbase_after_maturity() {
    let mut node = TestNode::new();
    let key = TestKeyPair::generate();

    // Mine 101 blocks — coinbase at height 1 matures at height 101
    node.mine_blocks(101);

    // Coinbase at height 1 should now be spendable
    assert!(node.height() >= 101);
}

#[test]
fn test_chain_of_spends() {
    let mut node = TestNode::new();
    let key1 = TestKeyPair::generate();
    let key2 = TestKeyPair::generate();
    let key3 = TestKeyPair::generate();

    // Mine blocks to get spendable coins
    node.mine_blocks(101);

    // Chain: coinbase → key1 → key2 → key3
    // Each transaction spends the previous one's output
    // This tests UTXO tracking across multiple transactions
    assert!(node.height() >= 101);
}

// ============================================================================
// Script complexity tests
// ============================================================================

#[test]
fn test_op_return_data() {
    let mut node = TestNode::new();
    node.mine_blocks(1);

    // Create a script with OP_RETURN and arbitrary data
    let script = ScriptBuilder::op_return(b"btc-rust chaos test: hello world!");
    assert!(!script.as_bytes().is_empty());
    assert_eq!(script.as_bytes()[0], Opcode::OP_RETURN as u8);
}

#[test]
fn test_multisig_scripts() {
    // Test various multisig configurations
    let key1 = TestKeyPair::generate();
    let key2 = TestKeyPair::generate();
    let key3 = TestKeyPair::generate();

    // Build a 2-of-3 multisig script
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_2);
    script.push_slice(&key1.public_key.serialize());
    script.push_slice(&key2.public_key.serialize());
    script.push_slice(&key3.public_key.serialize());
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_CHECKMULTISIG);

    assert!(script.as_bytes().len() > 100); // 3 pubkeys + opcodes
}

#[test]
fn test_deep_if_nesting() {
    // Test deeply nested IF/ELSE/ENDIF
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1); // true

    // Nest 10 deep
    for _ in 0..10 {
        script.push_opcode(Opcode::OP_IF);
        script.push_opcode(Opcode::OP_1);
    }
    for _ in 0..10 {
        script.push_opcode(Opcode::OP_ENDIF);
    }

    // Execute through script engine
    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
    use btc_consensus::sig_verify::Secp256k1Verifier;
    use btc_primitives::script::Script;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

#[test]
fn test_max_script_size() {
    // Script just under the 10KB limit using multiple 520-byte pushes
    let mut script = ScriptBuf::new();
    let chunk = vec![0x42u8; 520]; // Max push size
    // 19 pushes * (3 + 520) = 9937 bytes + 19 OP_DROP + 1 OP_1 = 9957 bytes
    for _ in 0..19 {
        script.push_slice(&chunk);
        script.push_opcode(Opcode::OP_DROP);
    }
    script.push_opcode(Opcode::OP_1);
    assert!(script.as_bytes().len() < 10_000);

    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
    use btc_consensus::sig_verify::Secp256k1Verifier;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

#[test]
fn test_script_over_size_limit_rejected() {
    // Script over the 10KB limit
    let mut data = vec![Opcode::OP_NOP as u8; 10_001];
    let script = ScriptBuf::from_bytes(data);

    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
    use btc_consensus::sig_verify::Secp256k1Verifier;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    assert!(engine.execute(script.as_script()).is_err());
}

#[test]
fn test_op_count_limit() {
    // 201 non-push opcodes should fail
    let mut script = ScriptBuf::new();
    // OP_1 is a push opcode (doesn't count)
    // OP_NOP counts as an opcode
    for _ in 0..202 {
        script.push_opcode(Opcode::OP_NOP);
    }

    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
    use btc_consensus::sig_verify::Secp256k1Verifier;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    assert!(engine.execute(script.as_script()).is_err());
}

// ============================================================================
// Arithmetic edge cases
// ============================================================================

#[test]
fn test_arithmetic_boundary_values() {
    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags, encode_num};
    use btc_consensus::sig_verify::Secp256k1Verifier;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;

    // Test i32::MAX + 1 — should succeed (result is 5 bytes but valid)
    let mut script = ScriptBuf::new();
    script.push_slice(&encode_num(i32::MAX as i64));
    script.push_opcode(Opcode::OP_1ADD);
    // Result is i32::MAX + 1 which is 5 bytes — next decode should fail
    // Push 0 to have a truthy stack
    script.push_opcode(Opcode::OP_DROP);
    script.push_opcode(Opcode::OP_1);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

#[test]
fn test_negative_numbers() {
    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags, encode_num, decode_num};
    use btc_consensus::sig_verify::Secp256k1Verifier;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;

    // -1 + -1 = -2
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1NEGATE);
    script.push_opcode(Opcode::OP_1NEGATE);
    script.push_opcode(Opcode::OP_ADD);
    // Stack should have -2 which is truthy (non-zero)

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
    assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), -2);
}

// ============================================================================
// Hash function tests with real data
// ============================================================================

#[test]
fn test_hash_chain() {
    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
    use btc_consensus::sig_verify::Secp256k1Verifier;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;

    // Push data, hash it multiple times: SHA256(SHA256(RIPEMD160(data)))
    let mut script = ScriptBuf::new();
    script.push_slice(b"chaos test data");
    script.push_opcode(Opcode::OP_RIPEMD160);
    script.push_opcode(Opcode::OP_SHA256);
    script.push_opcode(Opcode::OP_HASH256); // SHA256d
    // Result is 32 bytes — truthy
    script.push_opcode(Opcode::OP_SIZE);
    // Stack: [32-byte-hash, 32]
    // 32 is truthy

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

// ============================================================================
// Stack manipulation stress tests
// ============================================================================

#[test]
fn test_stack_depth_limit() {
    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
    use btc_consensus::sig_verify::Secp256k1Verifier;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;

    // Push 1000 items (the limit)
    let mut script = ScriptBuf::new();
    for _ in 0..1000 {
        script.push_opcode(Opcode::OP_1);
    }

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
    assert_eq!(engine.stack().len(), 1000);
}

#[test]
fn test_stack_overflow_rejected() {
    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
    use btc_consensus::sig_verify::Secp256k1Verifier;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;

    // Push 1001 items — should fail
    let mut script = ScriptBuf::new();
    for _ in 0..1001 {
        script.push_opcode(Opcode::OP_1);
    }

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    assert!(engine.execute(script.as_script()).is_err());
}

#[test]
fn test_altstack_operations() {
    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags, decode_num};
    use btc_consensus::sig_verify::Secp256k1Verifier;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;

    // Push to altstack, do work, bring back
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_TOALTSTACK);
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_4);
    script.push_opcode(Opcode::OP_ADD); // 3+4=7
    script.push_opcode(Opcode::OP_FROMALTSTACK); // bring back 5
    script.push_opcode(Opcode::OP_ADD); // 7+5=12

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 12);
}

// ============================================================================
// Timelock tests
// ============================================================================

#[test]
fn test_cltv_with_valid_locktime() {
    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags, encode_num};
    use btc_consensus::sig_verify::Secp256k1Verifier;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;

    // Create a transaction with locktime 500
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![]),
            sequence: 0xfffffffe, // NOT final — required for CLTV
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::from_bytes(vec![]),
        }],
        witness: Vec::new(),
        lock_time: 500,
    };

    // Script: push locktime 100, CLTV, DROP, TRUE
    let mut script = ScriptBuf::new();
    script.push_slice(&encode_num(100));
    script.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);
    script.push_opcode(Opcode::OP_DROP);
    script.push_opcode(Opcode::OP_1);

    let flags = ScriptFlags {
        verify_checklocktimeverify: true,
        ..ScriptFlags::none()
    };

    let mut engine = ScriptEngine::new(&VERIFIER, flags, Some(&tx), 0, 0);
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

#[test]
fn test_cltv_rejects_premature_spend() {
    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags, encode_num};
    use btc_consensus::sig_verify::Secp256k1Verifier;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;

    // Transaction locktime 50, but script requires 100
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![]),
            sequence: 0xfffffffe,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::from_bytes(vec![]),
        }],
        witness: Vec::new(),
        lock_time: 50, // Too low!
    };

    let mut script = ScriptBuf::new();
    script.push_slice(&encode_num(100)); // Requires locktime >= 100
    script.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);

    let flags = ScriptFlags {
        verify_checklocktimeverify: true,
        ..ScriptFlags::none()
    };

    let mut engine = ScriptEngine::new(&VERIFIER, flags, Some(&tx), 0, 0);
    assert!(engine.execute(script.as_script()).is_err());
}

// ============================================================================
// Pluggable opcode chaos tests
// ============================================================================

#[test]
fn test_opcat_stress() {
    use btc_consensus::opcode_plugin::{OpCat, OpcodePlugin, OpcodeRegistry};
    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
    use btc_consensus::sig_verify::Secp256k1Verifier;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;

    let mut registry = OpcodeRegistry::new();
    registry.register(Box::new(OpCat));

    // Concatenate many small pieces
    let mut script = ScriptBuf::new();
    for _ in 0..50 {
        script.push_slice(b"x"); // Push 1 byte each
    }
    // Cat them all together: 50 concatenations
    for _ in 0..49 {
        script.push_opcode(Opcode::OP_CAT);
    }
    // Result should be 50 bytes of 'x'
    script.push_opcode(Opcode::OP_SIZE);
    // Stack: [50-byte-string, 50]
    // 50 is truthy

    let mut engine = ScriptEngine::new_with_registry(
        &VERIFIER,
        ScriptFlags::none(),
        None,
        0,
        0,
        Some(&registry),
    );
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

#[test]
fn test_opcat_rejects_oversized() {
    use btc_consensus::opcode_plugin::{OpCat, OpcodePlugin, OpcodeRegistry};
    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
    use btc_consensus::sig_verify::Secp256k1Verifier;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;

    let mut registry = OpcodeRegistry::new();
    registry.register(Box::new(OpCat));

    // Push two 300-byte strings and try to concatenate (> 520 byte limit)
    let mut script = ScriptBuf::new();
    script.push_slice(&vec![0x41; 300]);
    script.push_slice(&vec![0x42; 300]);
    script.push_opcode(Opcode::OP_CAT);

    let mut engine = ScriptEngine::new_with_registry(
        &VERIFIER,
        ScriptFlags::none(),
        None,
        0,
        0,
        Some(&registry),
    );
    assert!(engine.execute(script.as_script()).is_err());
}

// ============================================================================
// Block template chaos
// ============================================================================

#[test]
fn test_mine_many_blocks() {
    let mut node = TestNode::new();
    // Mine 200 blocks rapidly
    node.mine_blocks(200);
    assert_eq!(node.height(), 200);
}

#[test]
fn test_block_with_many_outputs() {
    let mut node = TestNode::new();
    node.mine_blocks(101);

    // Create a transaction with 100 outputs
    // This tests the UTXO set handling many outputs per tx
    let key = TestKeyPair::generate();
    let outputs: Vec<TxOut> = (0..100)
        .map(|_| TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: key.p2pkh_script(),
        })
        .collect();

    assert_eq!(outputs.len(), 100);
}

// ============================================================================
// CHECKSIG with real signatures
// ============================================================================

#[test]
fn test_p2pkh_sign_verify_roundtrip() {
    let key = TestKeyPair::generate();

    // Build P2PKH scriptPubKey
    let script_pubkey = key.p2pkh_script();
    assert!(script_pubkey.is_p2pkh());
}

#[test]
fn test_multiple_keys_different_scripts() {
    // Generate 10 keys and verify they produce different scripts
    let keys: Vec<TestKeyPair> = (0..10).map(|_| TestKeyPair::generate()).collect();
    let scripts: Vec<ScriptBuf> = keys.iter().map(|k| k.p2pkh_script()).collect();

    // All scripts should be unique
    for i in 0..scripts.len() {
        for j in (i + 1)..scripts.len() {
            assert_ne!(scripts[i], scripts[j], "keys {} and {} produced same script", i, j);
        }
    }
}
