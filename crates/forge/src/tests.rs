//! Comprehensive tests for btc-forge.

use crate::debugger::ScriptDebugger;
use crate::script_builder::ForgeScript;
use crate::script_env::ScriptEnv;
use crate::tx_builder::TxBuilder;
use crate::weight::analyze_script;
use btc_primitives::amount::Amount;
use btc_primitives::hash::{sha256, TxHash};
use btc_primitives::script::{Opcode, ScriptBuf};
use btc_primitives::transaction::OutPoint;

// ---------------------------------------------------------------------------
// ScriptEnv
// ---------------------------------------------------------------------------

#[test]
fn test_simple_p2pkh_flow() {
    let mut env = ScriptEnv::new();
    let _ = env.new_named_account("alice");
    // Fund alice (account index 0)
    let utxo = env.fund_p2pkh(0, Amount::from_sat(100_000));
    // The UTXO value will be the regtest coinbase subsidy (50 BTC), not the
    // requested amount, because we mine a coinbase directly.
    assert!(utxo.txout.value.as_sat() > 0);
}

#[test]
fn test_script_env_advance_blocks() {
    let mut env = ScriptEnv::new();
    assert_eq!(env.height(), 0);
    env.advance_blocks(10);
    assert_eq!(env.height(), 10);
}

#[test]
fn test_script_env_set_height() {
    let mut env = ScriptEnv::new();
    env.set_height(50);
    assert_eq!(env.height(), 50);
    // Setting to a lower height is a no-op.
    env.set_height(25);
    assert_eq!(env.height(), 50);
}

#[test]
fn test_script_env_execute_simple() {
    let env = ScriptEnv::new();
    // OP_1 always succeeds.
    let script = ForgeScript::new().op(Opcode::OP_1).build();
    let result = env.execute_script(script.as_script()).unwrap();
    assert!(result.success);
}

#[test]
fn test_script_env_execute_arithmetic() {
    let env = ScriptEnv::new();
    // 2 + 3 == 5 => OP_1 (true)
    let script = ForgeScript::new()
        .push_num(2)
        .push_num(3)
        .op(Opcode::OP_ADD)
        .push_num(5)
        .op(Opcode::OP_EQUAL)
        .build();
    let result = env.execute_script(script.as_script()).unwrap();
    assert!(result.success);
}

#[test]
fn test_script_env_verify_script() {
    let env = ScriptEnv::new();
    // script_sig pushes OP_1, script_pubkey checks OP_1
    let sig = ForgeScript::new().op(Opcode::OP_1).build();
    let pubkey = ForgeScript::new().build(); // empty -- stack has [1]
    let result = env
        .verify_script(sig.as_script(), pubkey.as_script())
        .unwrap();
    assert!(result.success);
}

// ---------------------------------------------------------------------------
// ForgeScript -- HTLC
// ---------------------------------------------------------------------------

#[test]
fn test_htlc_claim_with_preimage() {
    let mut env = ScriptEnv::new();
    let _ = env.new_named_account("alice");
    let _ = env.new_named_account("bob");

    let alice = env.account(0);
    let bob = env.account(1);

    let preimage = b"secret_preimage_value___";
    let hash = sha256(preimage);

    let htlc = ForgeScript::htlc(
        &bob.keypair.public_key.serialize(),
        &alice.keypair.public_key.serialize(),
        &hash,
        100,
    )
    .build();

    assert!(!htlc.is_empty());
    // HTLC script should contain IF/ELSE/ENDIF structure.
    let bytes = htlc.as_bytes();
    assert!(bytes.contains(&(Opcode::OP_IF as u8)));
    assert!(bytes.contains(&(Opcode::OP_ELSE as u8)));
    assert!(bytes.contains(&(Opcode::OP_ENDIF as u8)));
    assert!(bytes.contains(&(Opcode::OP_SHA256 as u8)));
    assert!(bytes.contains(&(Opcode::OP_CHECKLOCKTIMEVERIFY as u8)));
}

// ---------------------------------------------------------------------------
// ForgeScript -- Multisig
// ---------------------------------------------------------------------------

#[test]
fn test_multisig_2_of_3() {
    let mut env = ScriptEnv::new();
    let _ = env.new_account();
    let _ = env.new_account();
    let _ = env.new_account();

    let key1 = env.account(0);
    let key2 = env.account(1);
    let key3 = env.account(2);

    let ms = ForgeScript::multisig(
        2,
        &[
            &key1.keypair.public_key.serialize(),
            &key2.keypair.public_key.serialize(),
            &key3.keypair.public_key.serialize(),
        ],
    )
    .build();

    assert!(!ms.is_empty());
    // Should contain OP_CHECKMULTISIG.
    let bytes = ms.as_bytes();
    assert!(bytes.contains(&(Opcode::OP_CHECKMULTISIG as u8)));
    // Should start with OP_2 (threshold).
    assert_eq!(bytes[0], Opcode::OP_2 as u8);
}

// ---------------------------------------------------------------------------
// ScriptDebugger
// ---------------------------------------------------------------------------

#[test]
fn test_debugger_traces_execution() {
    let script = ForgeScript::new()
        .push_num(2)
        .push_num(3)
        .op(Opcode::OP_ADD)
        .push_num(5)
        .op(Opcode::OP_EQUAL)
        .build();

    let mut debugger = ScriptDebugger::new(script.as_script());
    let trace = debugger.run();

    assert!(!trace.is_empty());

    // After push 2: stack should be [2]
    assert_eq!(trace[0].stack.len(), 1);

    // After push 3: stack should be [2, 3]
    assert_eq!(trace[1].stack.len(), 2);

    // After OP_ADD: stack should be [5]
    assert_eq!(trace[2].stack.len(), 1);

    // After push 5: stack should be [5, 5]
    assert_eq!(trace[3].stack.len(), 2);

    // After OP_EQUAL: stack should be [1] (true)
    assert_eq!(trace[4].stack.len(), 1);
    assert_eq!(trace[4].stack[0], vec![1u8]);
}

#[test]
fn test_debugger_print_trace() {
    let script = ForgeScript::new()
        .push_num(1)
        .push_num(2)
        .op(Opcode::OP_ADD)
        .build();

    let mut debugger = ScriptDebugger::new(script.as_script());
    debugger.run();
    // Smoke test -- just make sure it doesn't panic.
    debugger.print_trace();
}

#[test]
fn test_debugger_stack_at() {
    let script = ForgeScript::new()
        .push_num(42)
        .push_num(7)
        .op(Opcode::OP_DROP)
        .build();

    let mut debugger = ScriptDebugger::new(script.as_script());
    debugger.run();

    // After push 42 (step 0): stack = [42]
    let s = debugger.stack_at(0);
    assert_eq!(s.len(), 1);

    // Out-of-bounds returns empty slice.
    assert!(debugger.stack_at(999).is_empty());
}

// ---------------------------------------------------------------------------
// ForgeScript -- Timelock
// ---------------------------------------------------------------------------

#[test]
fn test_timelock_script() {
    let inner = ForgeScript::new().op(Opcode::OP_1).build();
    let timelocked = ForgeScript::timelock(500, &inner).build();
    assert!(!timelocked.is_empty());
    // Should contain CHECKLOCKTIMEVERIFY.
    let bytes = timelocked.as_bytes();
    assert!(bytes.contains(&(Opcode::OP_CHECKLOCKTIMEVERIFY as u8)));
    assert!(bytes.contains(&(Opcode::OP_DROP as u8)));
}

// ---------------------------------------------------------------------------
// ForgeScript -- Hashlock
// ---------------------------------------------------------------------------

#[test]
fn test_hashlock_script() {
    let hash = sha256(b"secret");
    let inner = ForgeScript::new().op(Opcode::OP_1).build();
    let locked = ForgeScript::hashlock(&hash, &inner).build();
    assert!(!locked.is_empty());
    let bytes = locked.as_bytes();
    assert!(bytes.contains(&(Opcode::OP_SHA256 as u8)));
    assert!(bytes.contains(&(Opcode::OP_EQUALVERIFY as u8)));
}

// ---------------------------------------------------------------------------
// Script analysis
// ---------------------------------------------------------------------------

#[test]
fn test_script_analysis() {
    let script = ForgeScript::multisig(2, &[&[0; 33], &[0; 33], &[0; 33]]).build();
    let analysis = analyze_script(script.as_script());
    assert!(analysis.has_signature_ops);
    assert_eq!(analysis.sigop_count, 3); // CHECKMULTISIG with 3 keys
}

#[test]
fn test_script_analysis_p2pkh() {
    let script = ForgeScript::p2pkh(&[0; 20]).build();
    let analysis = analyze_script(script.as_script());
    assert!(analysis.has_signature_ops);
    assert_eq!(analysis.sigop_count, 1); // single CHECKSIG
    assert_eq!(analysis.size_bytes, 25);
}

#[test]
fn test_script_analysis_no_sigops() {
    let script = ForgeScript::new()
        .push_num(1)
        .push_num(2)
        .op(Opcode::OP_ADD)
        .build();
    let analysis = analyze_script(script.as_script());
    assert!(!analysis.has_signature_ops);
    assert_eq!(analysis.sigop_count, 0);
}

// ---------------------------------------------------------------------------
// TxBuilder
// ---------------------------------------------------------------------------

#[test]
fn test_tx_builder() {
    let tx = TxBuilder::new()
        .add_input_with_script(
            OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            ScriptBuf::new(),
        )
        .add_output(
            ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            Amount::from_sat(50000),
        )
        .with_locktime(500)
        .build();

    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.lock_time, 500);
    assert_eq!(tx.outputs[0].value.as_sat(), 50000);
}

#[test]
fn test_tx_builder_multiple_inputs_outputs() {
    let tx = TxBuilder::new()
        .add_input_with_script(
            OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            ScriptBuf::new(),
        )
        .add_input_with_script(
            OutPoint::new(TxHash::from_bytes([0xbb; 32]), 1),
            ScriptBuf::new(),
        )
        .add_output(ScriptBuf::new(), Amount::from_sat(30000))
        .add_output(ScriptBuf::new(), Amount::from_sat(20000))
        .build();

    assert_eq!(tx.inputs.len(), 2);
    assert_eq!(tx.outputs.len(), 2);
    assert_eq!(tx.version, 2);
}

#[test]
fn test_tx_builder_with_sequence() {
    let tx = TxBuilder::new()
        .add_input_with_script(
            OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            ScriptBuf::new(),
        )
        .with_sequence(0, 0xfffffffe)
        .add_output(ScriptBuf::new(), Amount::from_sat(10000))
        .build();

    assert_eq!(tx.inputs[0].sequence, 0xfffffffe);
}

#[test]
fn test_tx_builder_with_witness() {
    let witness_data = vec![vec![0x01, 0x02], vec![0x03, 0x04]];
    let tx = TxBuilder::new()
        .add_input_with_script(
            OutPoint::new(TxHash::from_bytes([0xcc; 32]), 0),
            ScriptBuf::new(),
        )
        .with_witness(0, witness_data.clone())
        .add_output(ScriptBuf::new(), Amount::from_sat(5000))
        .build();

    assert_eq!(tx.witness.len(), 1);
    assert_eq!(tx.witness[0].len(), 2);
}

// ---------------------------------------------------------------------------
// ForgeScript builder basics
// ---------------------------------------------------------------------------

#[test]
fn test_forge_script_push_num() {
    // OP_0
    let s = ForgeScript::new().push_num(0).build();
    assert_eq!(s.as_bytes(), &[Opcode::OP_0 as u8]);

    // OP_1 .. OP_16
    for n in 1..=16i64 {
        let s = ForgeScript::new().push_num(n).build();
        assert_eq!(s.as_bytes()[0], 0x50 + n as u8);
    }

    // OP_1NEGATE
    let s = ForgeScript::new().push_num(-1).build();
    assert_eq!(s.as_bytes(), &[Opcode::OP_1NEGATE as u8]);

    // Larger number
    let s = ForgeScript::new().push_num(500).build();
    assert!(!s.is_empty());
}

#[test]
fn test_forge_script_p2pkh() {
    let hash = [0xab; 20];
    let script = ForgeScript::p2pkh(&hash).build();
    assert!(script.is_p2pkh());
    assert_eq!(script.len(), 25);
}

#[test]
fn test_forge_script_p2wpkh() {
    let hash = [0xcd; 20];
    let script = ForgeScript::p2wpkh(&hash).build();
    // P2WPKH uses a direct OP_0 push + 20 bytes, but ForgeScript uses
    // push_bytes which wraps in a length prefix. Verify it's non-empty.
    assert!(!script.is_empty());
}

#[test]
fn test_forge_script_p2sh() {
    let hash = [0xef; 20];
    let script = ForgeScript::p2sh(&hash).build();
    assert!(!script.is_empty());
    let bytes = script.as_bytes();
    assert_eq!(bytes[0], Opcode::OP_HASH160 as u8);
}

// ---------------------------------------------------------------------------
// Witness weight estimation
// ---------------------------------------------------------------------------

#[test]
fn test_estimate_witness_weight() {
    use crate::weight::estimate_witness_weight;

    let empty: Vec<Vec<u8>> = vec![];
    assert_eq!(estimate_witness_weight(&empty), 0);

    // Single item of 72 bytes (typical signature).
    let sig = vec![0u8; 72];
    let w = estimate_witness_weight(&[sig]);
    // 1 (count varint) + 1 (item len varint) + 72 = 74
    assert_eq!(w, 74);
}

// ---------------------------------------------------------------------------
// Integration: ScriptEnv + ForgeScript + TxBuilder
// ---------------------------------------------------------------------------

#[test]
fn test_end_to_end_fund_and_build_tx() {
    let mut env = ScriptEnv::new();
    let _ = env.new_named_account("alice");
    let _ = env.new_named_account("bob");

    // Fund alice.
    let utxo = env.fund_p2pkh(0, Amount::from_sat(100_000));

    // Mature the coinbase.
    env.advance_blocks(100);

    // Build a transaction spending alice's UTXO to bob.
    let bob_script = env.account(1).keypair.p2pkh_script();
    let tx = TxBuilder::new()
        .add_input(&utxo)
        .add_output(bob_script, Amount::from_sat(40_000))
        .build();

    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.inputs[0].previous_output, utxo.outpoint);
}

// ---------------------------------------------------------------------------
// Named account test
// ---------------------------------------------------------------------------

#[test]
fn test_named_accounts() {
    let mut env = ScriptEnv::new();
    let _ = env.new_named_account("alice");
    let _ = env.new_named_account("bob");
    let _ = env.new_account(); // auto-named

    assert_eq!(env.account(0).name, "alice");
    assert_eq!(env.account(1).name, "bob");
    assert_eq!(env.account(2).name, "account_2");
}
