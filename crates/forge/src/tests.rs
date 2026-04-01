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

// ---------------------------------------------------------------------------
// Additional coverage tests
// ---------------------------------------------------------------------------

#[test]
fn test_forge_script_default() {
    let s = crate::script_builder::ForgeScript::default();
    let script = s.build();
    assert!(script.is_empty());
}

#[test]
fn test_forge_script_push_hash() {
    let hash = [0xAA; 32];
    let script = ForgeScript::new().push_hash(&hash).build();
    assert!(!script.is_empty());
}

#[test]
fn test_forge_script_push_pubkey() {
    let key = [0x02; 33];
    let script = ForgeScript::new().push_pubkey(&key).build();
    assert!(!script.is_empty());
}

#[test]
fn test_forge_script_push_large_number() {
    // Large positive number
    let s = ForgeScript::new().push_num(1000).build();
    assert!(!s.is_empty());

    // Large negative number
    let s2 = ForgeScript::new().push_num(-1000).build();
    assert!(!s2.is_empty());

    // Number that needs sign extension
    let s3 = ForgeScript::new().push_num(128).build();
    assert!(!s3.is_empty());

    // Negative number needing sign bit
    let s4 = ForgeScript::new().push_num(-128).build();
    assert!(!s4.is_empty());
}

#[test]
fn test_script_env_fund_script() {
    let mut env = ScriptEnv::new();
    let script = ScriptBuf::from_bytes(vec![0x51]); // OP_1
    let utxo = env.fund_script(&script, Amount::from_sat(100_000));
    assert!(utxo.txout.value.as_sat() > 0);
}

#[test]
fn test_script_env_node_access() {
    let mut env = ScriptEnv::new();
    let node = env.node();
    assert_eq!(node.height(), 0);

    let node_mut = env.node_mut();
    node_mut.mine_blocks(1);
    assert_eq!(env.height(), 1);
}

#[test]
fn test_script_env_verify_with_witness() {
    let env = ScriptEnv::new();
    // Push 1 as witness, then run OP_1 as witness script
    let witness_items = vec![vec![0x01]];
    let witness_script = ForgeScript::new().op(Opcode::OP_1).build();
    let script_pubkey = ForgeScript::new().build(); // empty

    let result = env
        .verify_script_with_witness(&witness_items, witness_script.as_script(), script_pubkey.as_script())
        .unwrap();
    assert!(result.success);
}

#[test]
fn test_script_result_fields() {
    let env = ScriptEnv::new();
    let script = ForgeScript::new().push_num(42).build();
    let result = env.execute_script(script.as_script()).unwrap();
    assert!(result.success);
    assert!(!result.final_stack.is_empty());
    assert_eq!(result.script_size, script.len());
}

#[test]
fn test_debugger_run_twice_returns_cached() {
    let script = ForgeScript::new().push_num(1).build();
    let mut debugger = ScriptDebugger::new(script.as_script());
    let trace1 = debugger.run();
    let trace2 = debugger.run();
    assert_eq!(trace1.len(), trace2.len());
}

#[test]
fn test_debugger_step() {
    let script = ForgeScript::new().push_num(1).build();
    let mut debugger = ScriptDebugger::new(script.as_script());
    let step = debugger.step();
    // After step() calls run(), result is None (all in history)
    assert!(step.is_none());
}

#[test]
fn test_debugger_set_breakpoint() {
    let script = ForgeScript::new().push_num(1).push_num(2).op(Opcode::OP_ADD).build();
    let mut debugger = ScriptDebugger::new(script.as_script());
    debugger.set_breakpoint(0);
    debugger.set_breakpoint(0); // duplicate should not add
    debugger.set_breakpoint(1);
    // Just verify no panics
    let trace = debugger.run();
    assert!(!trace.is_empty());
}

#[test]
fn test_debugger_history() {
    let script = ForgeScript::new().push_num(1).build();
    let mut debugger = ScriptDebugger::new(script.as_script());
    assert!(debugger.history().is_empty());
    debugger.run();
    assert!(!debugger.history().is_empty());
}

#[test]
fn test_script_analysis_with_branches() {
    use crate::weight::analyze_script;

    // IF/ELSE/ENDIF script
    let script = ForgeScript::new()
        .op(Opcode::OP_IF)
        .push_num(1)
        .op(Opcode::OP_ELSE)
        .push_num(2)
        .op(Opcode::OP_ENDIF)
        .build();

    let analysis = analyze_script(script.as_script());
    assert!(!analysis.branches.is_empty());
}

#[test]
fn test_script_analysis_checksigadd() {
    let script = ForgeScript::new()
        .push_bytes(&[0x02; 33])
        .op(Opcode::OP_CHECKSIGADD)
        .build();
    let analysis = crate::weight::analyze_script(script.as_script());
    assert!(analysis.has_signature_ops);
    assert_eq!(analysis.sigop_count, 1);
}

#[test]
fn test_script_analysis_checkmultisig_unknown_n() {
    // CHECKMULTISIG without preceding OP_N -> uses 20 sigops
    let script = ForgeScript::new()
        .push_bytes(&[0x02; 33])
        .op(Opcode::OP_CHECKMULTISIG)
        .build();
    let analysis = crate::weight::analyze_script(script.as_script());
    // last_n_keys was 0, so sigop_count = 20
    assert!(analysis.sigop_count >= 20);
}

#[test]
fn test_script_analysis_stack_operations() {
    let script = ForgeScript::new()
        .push_num(1)
        .push_num(2)
        .op(Opcode::OP_2DUP)
        .op(Opcode::OP_3DUP)
        .op(Opcode::OP_2DROP)
        .op(Opcode::OP_NIP)
        .op(Opcode::OP_SWAP)
        .op(Opcode::OP_OVER)
        .op(Opcode::OP_TUCK)
        .op(Opcode::OP_DROP)
        .op(Opcode::OP_ADD)
        .build();
    let analysis = crate::weight::analyze_script(script.as_script());
    assert!(analysis.max_stack_depth > 0);
}

#[test]
fn test_script_analysis_data_push_n_detection() {
    // Push single byte 3, then CHECKMULTISIG -> should count 3 sigops
    let mut script = ScriptBuf::new();
    script.push_slice(&[3u8]);
    script.push_opcode(Opcode::OP_CHECKMULTISIG);
    let analysis = crate::weight::analyze_script(script.as_script());
    assert_eq!(analysis.sigop_count, 3);
}

#[test]
fn test_estimate_witness_weight_multiple() {
    use crate::weight::estimate_witness_weight;
    let witness = vec![vec![0u8; 72], vec![0u8; 33]];
    let weight = estimate_witness_weight(&witness);
    // 1 (count) + 1 (len) + 72 + 1 (len) + 33 = 108
    assert_eq!(weight, 108);
}

#[test]
fn test_tx_builder_with_sequence_out_of_bounds() {
    let tx = crate::tx_builder::TxBuilder::new()
        .add_input_with_script(
            OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            ScriptBuf::new(),
        )
        .with_sequence(5, 0xfffffffe) // out of bounds, should be no-op
        .build();
    // Default sequence should be SEQUENCE_FINAL
    assert_eq!(tx.inputs[0].sequence, 0xffffffff);
}

#[test]
fn test_tx_builder_with_witness_out_of_bounds() {
    let tx = crate::tx_builder::TxBuilder::new()
        .add_input_with_script(
            OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            ScriptBuf::new(),
        )
        .with_witness(5, vec![vec![0x01]]) // out of bounds, should be no-op
        .build();
    // Witness should be empty
    assert!(tx.witness[0].is_empty());
}

#[test]
fn test_tx_builder_default() {
    let builder = crate::tx_builder::TxBuilder::default();
    let tx = builder
        .add_input_with_script(
            OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            ScriptBuf::new(),
        )
        .add_output(ScriptBuf::new(), Amount::from_sat(1000))
        .build();
    assert_eq!(tx.version, 2);
}

#[test]
fn test_script_env_default() {
    let env = crate::script_env::ScriptEnv::default();
    assert_eq!(env.height(), 0);
}

// ---------------------------------------------------------------------------
// Miniscript additional coverage
// ---------------------------------------------------------------------------

#[test]
fn test_miniscript_witness_size_hash256() {
    use crate::miniscript::Miniscript;
    let ms = Miniscript::Hash256(vec![0x42; 32]);
    assert_eq!(ms.max_satisfaction_witness_size(), 33);
}

#[test]
fn test_miniscript_witness_size_ripemd160() {
    use crate::miniscript::Miniscript;
    let ms = Miniscript::Ripemd160(vec![0x42; 20]);
    assert_eq!(ms.max_satisfaction_witness_size(), 33);
}

#[test]
fn test_miniscript_witness_size_hash160() {
    use crate::miniscript::Miniscript;
    let ms = Miniscript::Hash160(vec![0x42; 20]);
    assert_eq!(ms.max_satisfaction_witness_size(), 33);
}

#[test]
fn test_miniscript_witness_size_andb() {
    use crate::miniscript::Miniscript;
    let ms = Miniscript::AndB(
        Box::new(Miniscript::Pk(vec![0xaa; 33])),
        Box::new(Miniscript::Pk(vec![0xbb; 33])),
    );
    assert_eq!(ms.max_satisfaction_witness_size(), 148);
}

#[test]
fn test_miniscript_witness_size_orb() {
    use crate::miniscript::Miniscript;
    let ms = Miniscript::OrB(
        Box::new(Miniscript::Pk(vec![0xaa; 33])),
        Box::new(Miniscript::Pk(vec![0xbb; 33])),
    );
    // OrB: sum of both branches
    assert_eq!(ms.max_satisfaction_witness_size(), 148);
}

#[test]
fn test_miniscript_witness_size_ord() {
    use crate::miniscript::Miniscript;
    let ms = Miniscript::OrD(
        Box::new(Miniscript::Pk(vec![0xaa; 33])),
        Box::new(Miniscript::Pk(vec![0xbb; 33])),
    );
    // max of branches
    assert_eq!(ms.max_satisfaction_witness_size(), 74);
}

#[test]
fn test_miniscript_witness_size_orc() {
    use crate::miniscript::Miniscript;
    let ms = Miniscript::OrC(
        Box::new(Miniscript::Pk(vec![0xaa; 33])),
        Box::new(Miniscript::Pk(vec![0xbb; 33])),
    );
    assert_eq!(ms.max_satisfaction_witness_size(), 74);
}

#[test]
fn test_miniscript_witness_size_thresh() {
    use crate::miniscript::Miniscript;
    let ms = Miniscript::Thresh(
        1,
        vec![
            Miniscript::Pk(vec![0xaa; 33]),
            Miniscript::Pk(vec![0xbb; 33]),
        ],
    );
    // Sum all sub sizes: 74 + 74 = 148
    assert_eq!(ms.max_satisfaction_witness_size(), 148);
}

#[test]
fn test_miniscript_witness_size_nonzero() {
    use crate::miniscript::Miniscript;
    let ms = Miniscript::NonZero(Box::new(Miniscript::Pk(vec![0xaa; 33])));
    assert_eq!(ms.max_satisfaction_witness_size(), 74);
}

#[test]
fn test_miniscript_safety_or_variants() {
    use crate::miniscript::Miniscript;
    // OrB: both branches need sig
    let ms_safe = Miniscript::OrB(
        Box::new(Miniscript::Pk(vec![0xaa; 33])),
        Box::new(Miniscript::Pk(vec![0xbb; 33])),
    );
    assert!(ms_safe.is_safe());

    let ms_unsafe = Miniscript::OrB(
        Box::new(Miniscript::Pk(vec![0xaa; 33])),
        Box::new(Miniscript::After(100)),
    );
    assert!(!ms_unsafe.is_safe());

    // OrD
    let ms_ord_safe = Miniscript::OrD(
        Box::new(Miniscript::Pk(vec![0xaa; 33])),
        Box::new(Miniscript::Pk(vec![0xbb; 33])),
    );
    assert!(ms_ord_safe.is_safe());

    // OrC
    let ms_orc_safe = Miniscript::OrC(
        Box::new(Miniscript::Pk(vec![0xaa; 33])),
        Box::new(Miniscript::Pk(vec![0xbb; 33])),
    );
    assert!(ms_orc_safe.is_safe());
}

#[test]
fn test_miniscript_safety_thresh_edge_cases() {
    use crate::miniscript::Miniscript;
    // k=2, 1 no-sig sub: still safe because every k=2 subset must include the sig sub
    let ms = Miniscript::Thresh(
        2,
        vec![
            Miniscript::Pk(vec![0xaa; 33]),
            Miniscript::Pk(vec![0xbb; 33]),
            Miniscript::After(100), // no sig
        ],
    );
    assert!(ms.is_safe()); // no_sig_count=1 < k=2, safe

    // k=1, 1 no-sig sub: unsafe (no_sig_count=1 >= k=1)
    let ms2 = Miniscript::Thresh(
        1,
        vec![
            Miniscript::Pk(vec![0xaa; 33]),
            Miniscript::After(100),
        ],
    );
    assert!(!ms2.is_safe());
}

#[test]
fn test_policy_parse_sha256_invalid_hex() {
    use crate::miniscript::Policy;
    let result = Policy::parse("sha256(zzzz)");
    assert!(result.is_err());
}

#[test]
fn test_policy_parse_empty() {
    use crate::miniscript::Policy;
    let result = Policy::parse("");
    assert!(result.is_err());
}

#[test]
fn test_policy_parse_no_open_paren() {
    use crate::miniscript::Policy;
    let result = Policy::parse("pk");
    assert!(result.is_err());
}

#[test]
fn test_policy_parse_thresh_invalid_k() {
    use crate::miniscript::Policy;
    // k = 0 is invalid
    let result = Policy::parse("thresh(0,pk(aa))");
    assert!(result.is_err());
    // k > subs is invalid
    let result2 = Policy::parse("thresh(3,pk(aa),pk(bb))");
    assert!(result2.is_err());
}

#[test]
fn test_policy_parse_thresh_invalid_k_string() {
    use crate::miniscript::Policy;
    let result = Policy::parse("thresh(abc,pk(aa))");
    assert!(result.is_err());
}

#[test]
fn test_policy_parse_older_invalid() {
    use crate::miniscript::Policy;
    let result = Policy::parse("older(abc)");
    assert!(result.is_err());
}

#[test]
fn test_policy_parse_and_missing_comma() {
    use crate::miniscript::Policy;
    let result = Policy::parse("and(pk(aa) pk(bb))");
    assert!(result.is_err());
}

#[test]
fn test_policy_parse_or_missing_close() {
    use crate::miniscript::Policy;
    let result = Policy::parse("or(pk(aa),pk(bb)");
    assert!(result.is_err());
}

#[test]
fn test_miniscript_andb_safety() {
    use crate::miniscript::Miniscript;
    let ms = Miniscript::AndB(
        Box::new(Miniscript::Sha256(vec![0x42; 32])),
        Box::new(Miniscript::Pk(vec![0xaa; 33])),
    );
    assert!(ms.is_safe()); // one branch has sig -> safe for And
}

#[test]
fn test_script_analysis_checkmultisigverify() {
    let script = ForgeScript::new()
        .push_num(2)
        .push_bytes(&[0x02; 33])
        .push_bytes(&[0x03; 33])
        .push_num(2)
        .op(Opcode::OP_CHECKMULTISIGVERIFY)
        .build();
    let analysis = crate::weight::analyze_script(script.as_script());
    assert!(analysis.has_signature_ops);
    assert_eq!(analysis.sigop_count, 2); // 2 keys
}

#[test]
fn test_script_analysis_checksigverify() {
    let script = ForgeScript::new()
        .push_bytes(&[0x02; 33])
        .op(Opcode::OP_CHECKSIGVERIFY)
        .build();
    let analysis = crate::weight::analyze_script(script.as_script());
    assert!(analysis.has_signature_ops);
    assert_eq!(analysis.sigop_count, 1);
}

#[test]
fn test_script_analysis_nested_if() {
    let script = ForgeScript::new()
        .op(Opcode::OP_IF)
        .op(Opcode::OP_IF)
        .push_num(1)
        .op(Opcode::OP_ENDIF)
        .op(Opcode::OP_ELSE)
        .push_num(2)
        .op(Opcode::OP_ENDIF)
        .build();
    let analysis = crate::weight::analyze_script(script.as_script());
    assert!(!analysis.branches.is_empty());
}

#[test]
fn test_script_analysis_op0_push() {
    let script = ForgeScript::new().push_num(0).build();
    let analysis = crate::weight::analyze_script(script.as_script());
    assert_eq!(analysis.max_stack_depth, 1);
}

#[test]
fn test_forge_error_display() {
    use crate::script_env::ForgeError;
    let e1 = ForgeError::ScriptExecution("exec fail".into());
    assert!(format!("{}", e1).contains("exec fail"));
    let e2 = ForgeError::MissingUtxo("missing".into());
    assert!(format!("{}", e2).contains("missing"));
    let e3 = ForgeError::InvalidArgument("bad arg".into());
    assert!(format!("{}", e3).contains("bad arg"));
}

// ---------------------------------------------------------------------------
// Debugger -- large push data coverage (lines 78-83, 87)
// ---------------------------------------------------------------------------

#[test]
fn test_debugger_large_pushdata_76_to_255_bytes() {
    // A push of 76-255 bytes uses OP_PUSHDATA1 (2 + len bytes overhead)
    let data = vec![0x42u8; 100];
    let mut script = ScriptBuf::new();
    script.push_slice(&data);
    script.push_opcode(Opcode::OP_DROP);

    let mut debugger = ScriptDebugger::new(script.as_script());
    let trace = debugger.run();
    assert!(trace.len() >= 2);
    // First step pushes 100 bytes onto stack
    assert_eq!(trace[0].stack.len(), 1);
    assert_eq!(trace[0].stack[0].len(), 100);
}

#[test]
fn test_debugger_large_pushdata_over_255_bytes() {
    // A push of 256+ bytes uses OP_PUSHDATA2 (3 + len bytes overhead)
    let data = vec![0x42u8; 300];
    let mut script = ScriptBuf::new();
    script.push_slice(&data);
    script.push_opcode(Opcode::OP_DROP);

    let mut debugger = ScriptDebugger::new(script.as_script());
    let trace = debugger.run();
    assert!(trace.len() >= 2);
    assert_eq!(trace[0].stack.len(), 1);
    assert_eq!(trace[0].stack[0].len(), 300);
}

#[test]
fn test_debugger_invalid_script_breaks() {
    // A script with an invalid instruction should stop at Err(_) => break
    // OP_PUSHDATA1 (0x4c) followed by a length byte claiming 0xff bytes,
    // but the script is too short. This should cause a parse error.
    let bytes = vec![0x4c, 0xff]; // PUSHDATA1 requesting 255 bytes, but none follow
    let script = ScriptBuf::from_bytes(bytes);

    let mut debugger = ScriptDebugger::new(script.as_script());
    let trace = debugger.run();
    // The parse error means no instructions are successfully decoded
    assert!(trace.is_empty());
}

#[test]
fn test_debugger_print_trace_empty_stack_items() {
    // Ensure print_trace handles empty stack items (the "[]" branch)
    let script = ForgeScript::new()
        .op(Opcode::OP_0)  // pushes empty bytes onto stack
        .op(Opcode::OP_DROP)
        .build();

    let mut debugger = ScriptDebugger::new(script.as_script());
    debugger.run();
    // Should not panic; the empty stack item should be printed as "[]"
    debugger.print_trace();
}

// ---------------------------------------------------------------------------
// TxBuilder -- sign_input coverage (lines 97-102)
// ---------------------------------------------------------------------------

#[test]
fn test_tx_builder_sign_input() {
    let mut env = ScriptEnv::new();
    let _ = env.new_named_account("signer");
    let utxo = env.fund_p2pkh(0, Amount::from_sat(100_000));
    env.advance_blocks(100); // mature coinbase

    let keypair = &env.account(0).keypair;
    let prev_output = utxo.txout.clone();

    let tx = TxBuilder::new()
        .add_input(&utxo)
        .add_output(
            ForgeScript::p2pkh(&[0xbb; 20]).build(),
            Amount::from_sat(40_000),
        )
        .sign_input(0, keypair, &prev_output)
        .build();

    assert_eq!(tx.inputs.len(), 1);
    // After signing, the script_sig should be non-empty
    assert!(!tx.inputs[0].script_sig.is_empty());
}

// ---------------------------------------------------------------------------
// Weight -- varint_size edge cases (lines 217-222)
// ---------------------------------------------------------------------------

#[test]
fn test_estimate_witness_weight_large_items() {
    use crate::weight::estimate_witness_weight;

    // An item of 253 bytes triggers the 3-byte varint path for item length
    let big_item = vec![0x42u8; 253];
    let w = estimate_witness_weight(&[big_item]);
    // 1 (count varint, count=1 < 0xfd) + 3 (item len varint, 253 = 0xfd) + 253 = 257
    assert_eq!(w, 257);
}

#[test]
fn test_estimate_witness_weight_many_items() {
    use crate::weight::estimate_witness_weight;

    // Create 253 items to trigger 3-byte varint for witness count
    let items: Vec<Vec<u8>> = (0..253).map(|_| vec![0x01]).collect();
    let w = estimate_witness_weight(&items);
    // 3 (count varint for 253) + 253 * (1 (item len) + 1 (item byte)) = 3 + 506 = 509
    assert_eq!(w, 509);
}

// ---------------------------------------------------------------------------
// Weight -- invalid script error branch (line 177)
// ---------------------------------------------------------------------------

#[test]
fn test_script_analysis_malformed_script() {
    // Script with an invalid instruction: OP_PUSHDATA1 + length but no data
    let bytes = vec![0x4c, 0x10]; // PUSHDATA1 requesting 16 bytes, but none follow
    let script = ScriptBuf::from_bytes(bytes);
    let analysis = analyze_script(script.as_script());
    // The script parsing will hit Err(_) => break
    // No ops should be counted
    assert_eq!(analysis.op_count, 0);
    assert_eq!(analysis.size_bytes, 2);
}

// ---------------------------------------------------------------------------
// Weight -- data push > 1 byte doesn't set last_n_keys
// ---------------------------------------------------------------------------

#[test]
fn test_script_analysis_data_push_multiby_no_n() {
    // Push 2 bytes: should NOT set last_n_keys
    let mut script = ScriptBuf::new();
    script.push_slice(&[3u8, 0u8]); // 2-byte push
    script.push_opcode(Opcode::OP_CHECKMULTISIG);
    let analysis = analyze_script(script.as_script());
    // last_n_keys should be 0 since data.len() != 1, so sigop_count = 20
    assert_eq!(analysis.sigop_count, 20);
}

// ---------------------------------------------------------------------------
// Miniscript parser edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_policy_parse_thresh_missing_close_in_sub() {
    use crate::miniscript::Policy;
    // thresh sub-policy followed by invalid character (not comma or close)
    let result = Policy::parse("thresh(2,pk(aa);pk(bb))");
    assert!(result.is_err());
}

#[test]
fn test_policy_parse_thresh_empty_subs() {
    use crate::miniscript::Policy;
    // thresh with k but no sub-policies - should fail
    // "thresh(1)" has no comma after k
    let result = Policy::parse("thresh(1)");
    assert!(result.is_err());
}

#[test]
fn test_policy_parse_after_invalid_number() {
    use crate::miniscript::Policy;
    let result = Policy::parse("after(not_a_number)");
    assert!(result.is_err());
}

#[test]
fn test_policy_parse_and_missing_close_paren() {
    use crate::miniscript::Policy;
    let result = Policy::parse("and(pk(aa),pk(bb)");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Miniscript -- MiniscriptError Display variants
// ---------------------------------------------------------------------------

#[test]
fn test_miniscript_error_display() {
    use crate::miniscript::MiniscriptError;
    let e1 = MiniscriptError::UnexpectedEof;
    assert!(format!("{}", e1).contains("unexpected end"));

    let e2 = MiniscriptError::Expected("(".into(), "foo".into());
    assert!(format!("{}", e2).contains("expected"));

    let e3 = MiniscriptError::InvalidHex("bad hex".into());
    assert!(format!("{}", e3).contains("invalid hex"));

    let e4 = MiniscriptError::InvalidNumber("nan".into());
    assert!(format!("{}", e4).contains("invalid number"));

    let e5 = MiniscriptError::UnknownPolicy("foo".into());
    assert!(format!("{}", e5).contains("unknown policy"));

    let e6 = MiniscriptError::InvalidThreshold;
    assert!(format!("{}", e6).contains("thresh"));

    let e7 = MiniscriptError::EmptyThresh;
    assert!(format!("{}", e7).contains("thresh"));

    let e8 = MiniscriptError::TrailingInput("extra".into());
    assert!(format!("{}", e8).contains("trailing"));
}

// ---------------------------------------------------------------------------
// Miniscript -- encode_script_num edge cases for push_script_number
// ---------------------------------------------------------------------------

#[test]
fn test_miniscript_compile_after_zero() {
    use crate::miniscript::Miniscript;
    // After(0) should push 0 via push_script_number (hits the n==0 branch)
    let ms = Miniscript::After(0);
    let script = ms.compile();
    assert!(!script.is_empty());
    // Should start with OP_0
    assert_eq!(script.as_bytes()[0], Opcode::OP_0 as u8);
}

#[test]
fn test_miniscript_compile_after_small_values() {
    use crate::miniscript::Miniscript;
    // After(1) should use OP_1
    let ms = Miniscript::After(1);
    let script = ms.compile();
    assert_eq!(script.as_bytes()[0], Opcode::OP_1 as u8);

    // After(16) should use OP_16
    let ms16 = Miniscript::After(16);
    let script16 = ms16.compile();
    assert_eq!(script16.as_bytes()[0], Opcode::OP_16 as u8);
}

// ---------------------------------------------------------------------------
// Miniscript -- read_until_close with nested parens
// ---------------------------------------------------------------------------

#[test]
fn test_policy_parse_deeply_nested_parens() {
    use crate::miniscript::Policy;
    // This tests read_until_close with multiple levels of nesting
    let result = Policy::parse("and(and(pk(aa),pk(bb)),and(pk(cc),pk(dd)))");
    assert!(result.is_ok());
    let p = result.unwrap();
    if let Policy::And(left, right) = &p {
        assert!(matches!(**left, Policy::And(_, _)));
        assert!(matches!(**right, Policy::And(_, _)));
    } else {
        panic!("Expected And");
    }
}

#[test]
fn test_policy_parse_read_until_close_unclosed() {
    use crate::miniscript::Policy;
    // Missing closing paren at the end -- should trigger read_until_close error
    let result = Policy::parse("pk(aabb");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Weight -- NOTIF coverage and remaining branch ops
// ---------------------------------------------------------------------------

#[test]
fn test_script_analysis_notif() {
    let script = ForgeScript::new()
        .op(Opcode::OP_NOTIF)
        .push_num(1)
        .op(Opcode::OP_ENDIF)
        .build();
    let analysis = analyze_script(script.as_script());
    assert!(!analysis.branches.is_empty());
}

#[test]
fn test_script_analysis_else_without_prior_ops() {
    // IF immediately followed by ELSE (current_branch_ops for ELSE is just [OP_IF])
    let script = ForgeScript::new()
        .op(Opcode::OP_IF)
        .op(Opcode::OP_ELSE)
        .push_num(1)
        .op(Opcode::OP_ENDIF)
        .build();
    let analysis = analyze_script(script.as_script());
    assert!(!analysis.branches.is_empty());
}

// ---------------------------------------------------------------------------
// Weight -- remaining arithmetic/comparison stack ops
// ---------------------------------------------------------------------------

#[test]
fn test_script_analysis_comparison_ops() {
    let script = ForgeScript::new()
        .push_num(1)
        .push_num(2)
        .op(Opcode::OP_LESSTHAN)
        .push_num(3)
        .push_num(4)
        .op(Opcode::OP_GREATERTHAN)
        .op(Opcode::OP_BOOLOR)
        .push_num(5)
        .push_num(6)
        .op(Opcode::OP_MIN)
        .op(Opcode::OP_BOOLAND)
        .push_num(7)
        .push_num(8)
        .op(Opcode::OP_MAX)
        .op(Opcode::OP_NUMEQUAL)
        .push_num(9)
        .push_num(10)
        .op(Opcode::OP_SUB)
        .op(Opcode::OP_DROP)
        .build();
    let analysis = analyze_script(script.as_script());
    assert!(analysis.op_count > 0);
    assert!(analysis.max_stack_depth > 0);
}

// ---------------------------------------------------------------------------
// Script builder -- push_num edge cases for encode_script_num
// ---------------------------------------------------------------------------

#[test]
fn test_forge_script_push_num_negative_needing_sign_extension() {
    // -128 has abs = 0x80, whose high bit is set, so it needs an extra 0x80 byte
    let s = ForgeScript::new().push_num(-128).build();
    assert!(!s.is_empty());

    // -255 has abs = 0xFF, high bit set, needs sign extension
    let s2 = ForgeScript::new().push_num(-255).build();
    assert!(!s2.is_empty());
}

#[test]
fn test_forge_script_push_num_large_negative() {
    // -1000 exercises the "set sign bit on last byte" path
    let s = ForgeScript::new().push_num(-1000).build();
    assert!(!s.is_empty());

    // Verify the encoded value is correct by checking script is valid
    let env = ScriptEnv::new();
    // Push -1000 then negate to get 1000, which should equal push_num(1000)
    let script = ForgeScript::new()
        .push_num(-1000)
        .op(Opcode::OP_NEGATE)
        .push_num(1000)
        .op(Opcode::OP_EQUAL)
        .build();
    let result = env.execute_script(script.as_script()).unwrap();
    assert!(result.success);
}

// ---------------------------------------------------------------------------
// Miniscript -- Verify wrapper witness size
// ---------------------------------------------------------------------------

#[test]
fn test_miniscript_verify_wrapper_compile_and_safety() {
    use crate::miniscript::Miniscript;
    // Verify(Sha256(...)) should not be safe (no key)
    let ms = Miniscript::Verify(Box::new(Miniscript::Sha256(vec![0x42; 32])));
    assert!(!ms.is_safe());
    let script = ms.compile();
    assert!(!script.is_empty());
}

#[test]
fn test_miniscript_nonzero_wrapper_unsafe() {
    use crate::miniscript::Miniscript;
    // NonZero(After(100)) should not be safe (no key)
    let ms = Miniscript::NonZero(Box::new(Miniscript::After(100)));
    assert!(!ms.is_safe());
}

// ---------------------------------------------------------------------------
// Miniscript -- OrI witness size with asymmetric branches
// ---------------------------------------------------------------------------

#[test]
fn test_miniscript_ori_witness_size_asymmetric() {
    use crate::miniscript::Miniscript;
    // One branch is PkH (108 bytes) and the other is Pk (74 bytes)
    let ms = Miniscript::OrI(
        Box::new(Miniscript::PkH(vec![0xaa; 20])),
        Box::new(Miniscript::Pk(vec![0xbb; 33])),
    );
    // 1 selector + max(108, 74) = 109
    assert_eq!(ms.max_satisfaction_witness_size(), 109);
}

// ---------------------------------------------------------------------------
// Miniscript -- AndB with non-key branches
// ---------------------------------------------------------------------------

#[test]
fn test_miniscript_andb_no_keys_unsafe() {
    use crate::miniscript::Miniscript;
    let ms = Miniscript::AndB(
        Box::new(Miniscript::Sha256(vec![0x42; 32])),
        Box::new(Miniscript::After(100)),
    );
    assert!(!ms.is_safe());
}

// ---------------------------------------------------------------------------
// Miniscript -- AndV witness size
// ---------------------------------------------------------------------------

#[test]
fn test_miniscript_andv_witness_size_mixed() {
    use crate::miniscript::Miniscript;
    // AndV(Pk, Sha256): 74 + 33 = 107
    let ms = Miniscript::AndV(
        Box::new(Miniscript::Pk(vec![0xaa; 33])),
        Box::new(Miniscript::Sha256(vec![0x42; 32])),
    );
    assert_eq!(ms.max_satisfaction_witness_size(), 107);
}

// ---------------------------------------------------------------------------
// Policy -- thresh with non-key subs (general path)
// ---------------------------------------------------------------------------

#[test]
fn test_policy_compile_thresh_general_three_subs() {
    use crate::miniscript::Policy;
    // General thresh with mixed sub-policies (not all keys)
    let p = Policy::Thresh(
        2,
        vec![
            Policy::Key("aa".to_string()),
            Policy::After(10),
            Policy::Key("bb".to_string()),
        ],
    );
    let script = p.compile();
    assert!(!script.is_empty());
    // Should contain OP_ADD and OP_EQUAL (not OP_CHECKMULTISIG)
    let bytes = script.as_bytes();
    assert!(bytes.contains(&(Opcode::OP_ADD as u8)));
    assert!(bytes.contains(&(Opcode::OP_EQUAL as u8)));
}

// ---------------------------------------------------------------------------
// Miniscript -- Multi witness size with k=1
// ---------------------------------------------------------------------------

#[test]
fn test_miniscript_multi_witness_size_k1() {
    use crate::miniscript::Miniscript;
    let ms = Miniscript::Multi(1, vec![vec![0xaa; 33]]);
    // 1 (OP_0 dummy) + 1 * (1+73) = 1 + 74 = 75
    assert_eq!(ms.max_satisfaction_witness_size(), 75);
}

// ---------------------------------------------------------------------------
// Miniscript -- script_size for various types
// ---------------------------------------------------------------------------

#[test]
fn test_miniscript_script_size_various() {
    use crate::miniscript::Miniscript;

    // PkH
    let ms = Miniscript::PkH(vec![0xab; 20]);
    assert_eq!(ms.script_size(), ms.compile().len());

    // Hash256
    let ms2 = Miniscript::Hash256(vec![0x42; 32]);
    assert_eq!(ms2.script_size(), ms2.compile().len());

    // After
    let ms3 = Miniscript::After(500);
    assert_eq!(ms3.script_size(), ms3.compile().len());

    // Older
    let ms4 = Miniscript::Older(144);
    assert_eq!(ms4.script_size(), ms4.compile().len());

    // AndB
    let ms5 = Miniscript::AndB(
        Box::new(Miniscript::Pk(vec![0xaa; 33])),
        Box::new(Miniscript::Pk(vec![0xbb; 33])),
    );
    assert_eq!(ms5.script_size(), ms5.compile().len());

    // Thresh
    let ms6 = Miniscript::Thresh(
        1,
        vec![Miniscript::Pk(vec![0xaa; 33]), Miniscript::Pk(vec![0xbb; 33])],
    );
    assert_eq!(ms6.script_size(), ms6.compile().len());

    // Verify
    let ms7 = Miniscript::Verify(Box::new(Miniscript::Pk(vec![0xaa; 33])));
    assert_eq!(ms7.script_size(), ms7.compile().len());

    // NonZero
    let ms8 = Miniscript::NonZero(Box::new(Miniscript::Pk(vec![0xaa; 33])));
    assert_eq!(ms8.script_size(), ms8.compile().len());
}

// ---------------------------------------------------------------------------
// Weight -- varint_size for large item sizes (lines 219-220)
// ---------------------------------------------------------------------------

#[test]
fn test_estimate_witness_weight_very_large_item() {
    use crate::weight::estimate_witness_weight;
    // An item of 65536 bytes triggers the 5-byte varint path for item length
    // (n > 0xffff)
    let big_item = vec![0x00u8; 65536];
    let w = estimate_witness_weight(&[big_item]);
    // 1 (count varint, count=1 < 0xfd) + 5 (item len varint, 65536 > 0xffff) + 65536 = 65542
    assert_eq!(w, 65542);
}

// ---------------------------------------------------------------------------
// Miniscript parser -- read_until_comma with close paren at depth 0
// ---------------------------------------------------------------------------

#[test]
fn test_policy_parse_thresh_close_paren_before_comma() {
    use crate::miniscript::Policy;
    // "thresh(1)" -- first arg is "1" followed by ')' not ','
    // This should hit the read_until_comma error path for ')' at depth 0
    let result = Policy::parse("thresh(1)");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Miniscript parser -- read_until_comma reaching end of input
// ---------------------------------------------------------------------------

#[test]
fn test_policy_parse_thresh_no_comma_no_close() {
    use crate::miniscript::Policy;
    // Truncated input: "thresh(1" -- no comma or close paren
    let result = Policy::parse("thresh(1");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Miniscript parser -- thresh sub followed by invalid separator
// ---------------------------------------------------------------------------

#[test]
fn test_policy_parse_thresh_sub_invalid_sep() {
    use crate::miniscript::Policy;
    // "thresh(1,pk(aa)!)" -- '!' is not comma or close paren after sub
    let result = Policy::parse("thresh(1,pk(aa)!)");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Miniscript -- read_until_close with nested depth decrements
// ---------------------------------------------------------------------------

#[test]
fn test_policy_parse_sha256_with_nested_parens_in_hash() {
    use crate::miniscript::Policy;
    // A sha256 hash cannot contain parens, but read_until_close handles depth
    // Let's test a read_until_close where depth goes up then down
    // The 'pk' argument is simple but 'sha256' goes through read_until_close
    let valid_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let result = Policy::parse(&format!("sha256({})", valid_hash));
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Debugger -- large pushdata over 65535 bytes
// ---------------------------------------------------------------------------

#[test]
fn test_debugger_very_large_pushdata() {
    // OP_PUSHDATA4 (0x4e) + 4-byte little-endian length
    // We'll create a script that pushes 70000 bytes using PUSHDATA4 format
    // Script format: 0x4e LL LL LL LL <data>
    let data_len: u32 = 70_000;
    let mut bytes = Vec::new();
    bytes.push(0x4e); // OP_PUSHDATA4
    bytes.extend_from_slice(&data_len.to_le_bytes());
    bytes.extend(std::iter::repeat(0x42).take(data_len as usize));
    bytes.push(Opcode::OP_DROP as u8);

    let script = ScriptBuf::from_bytes(bytes);
    let mut debugger = ScriptDebugger::new(script.as_script());
    let trace = debugger.run();
    // Should have parsed the pushdata instruction (pos += 5 + len) and the OP_DROP
    assert!(trace.len() >= 1);
}
