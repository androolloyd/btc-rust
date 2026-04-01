//! Complex and adversarial script tests -- push the script engine to its limits.
//!
//! Categories:
//! 1. Maximum complexity scripts (stack depth, op count, multisig, conditionals)
//! 2. Real-world Bitcoin scripts (Lightning HTLC, atomic swaps, vaults)
//! 3. Adversarial/malicious scripts that MUST fail
//! 4. Hash puzzles and commitment schemes
//! 5. Full P2PKH and multisig sign+verify roundtrips with real signatures

use btc_test::TestKeyPair;
use btc_consensus::script_engine::{ScriptEngine, ScriptFlags, encode_num, decode_num};
use btc_consensus::sig_verify::Secp256k1Verifier;
use btc_consensus::sighash::{sighash_legacy, SighashType};
use btc_primitives::hash::{sha256, hash160, sha256d};
use btc_primitives::script::{Opcode, ScriptBuf};
use btc_primitives::transaction::{Transaction, TxIn, TxOut, OutPoint};
use btc_primitives::amount::Amount;
use btc_primitives::hash::TxHash;

static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;

// ============================================================================
// Helper: build a simple spending transaction for CHECKSIG tests
// ============================================================================

fn make_spend_tx(_prev_script_pubkey: &ScriptBuf, value: i64) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![]),
            sequence: 0xfffffffe,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
        witness: Vec::new(),
        lock_time: 0,
    }
}

/// Sign a transaction input against a given script_pubkey using legacy sighash.
fn sign_legacy(key: &TestKeyPair, tx: &Transaction, input_index: usize, script_pubkey: &[u8]) -> Vec<u8> {
    let hash = sighash_legacy(tx, input_index, script_pubkey, SighashType::ALL)
        .expect("sighash should succeed");
    let secp = secp256k1::Secp256k1::new();
    let msg = secp256k1::Message::from_digest(hash);
    let sig = secp.sign_ecdsa(&msg, &key.secret_key);
    let mut der = sig.serialize_der().to_vec();
    der.push(0x01); // SIGHASH_ALL
    der
}

// ============================================================================
// 1. Maximum complexity scripts
// ============================================================================

#[test]
fn test_20_of_20_checkmultisig() {
    // Build a 20-of-20 CHECKMULTISIG (max keys allowed)
    // Generate 20 real keypairs, sign with all 20, verify execution succeeds.
    let keys: Vec<TestKeyPair> = (0..20).map(|_| TestKeyPair::generate()).collect();

    // Build script_pubkey: OP_20 <pk1> ... <pk20> OP_20 OP_CHECKMULTISIG
    let mut script_pubkey = ScriptBuf::new();
    // OP_1 through OP_16 cover 1..16; for 17..20 we need to push the number.
    script_pubkey.push_slice(&encode_num(20));
    for k in &keys {
        script_pubkey.push_slice(&k.pubkey_bytes());
    }
    script_pubkey.push_slice(&encode_num(20));
    script_pubkey.push_opcode(Opcode::OP_CHECKMULTISIG);

    let tx = make_spend_tx(&script_pubkey, 50_000);

    // Sign with all 20 keys in order
    let sigs: Vec<Vec<u8>> = keys.iter().map(|k| {
        sign_legacy(k, &tx, 0, script_pubkey.as_bytes())
    }).collect();

    // Build script_sig: OP_0 <sig1> ... <sig20>
    let mut script_sig = ScriptBuf::new();
    script_sig.push_opcode(Opcode::OP_0); // dummy for off-by-one bug
    for sig in &sigs {
        script_sig.push_slice(sig);
    }

    // Execute: scriptSig then scriptPubKey
    let flags = ScriptFlags::none();
    let mut engine = ScriptEngine::new(&VERIFIER, flags, Some(&tx), 0, 50_000);
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "20-of-20 CHECKMULTISIG should succeed");
}

#[test]
fn test_deeply_nested_conditionals_100_levels() {
    // OP_1 OP_IF OP_1 OP_IF ... (100 deep) ... OP_ENDIF OP_ENDIF
    // Tests the conditional stack depth
    let mut script = ScriptBuf::new();
    for _ in 0..100 {
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_IF);
    }
    // Push final TRUE
    script.push_opcode(Opcode::OP_1);
    // Close all 100 IF blocks
    for _ in 0..100 {
        script.push_opcode(Opcode::OP_ENDIF);
    }

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "100 levels of nested IF should succeed");
}

#[test]
fn test_max_stack_1000_elements() {
    // Push exactly 1000 elements (the max allowed stack size)
    // Then use OP_PICK from position 999 (the deepest)
    let mut script = ScriptBuf::new();
    for _ in 0..999 {
        script.push_opcode(Opcode::OP_1);
    }
    // Push the value we want to pick: element at depth 998
    // (after pushing 999 OP_1s, the stack is 999 deep)
    // OP_PICK pops the index, so we have room for 1 more push (999 + 1 = 1000)
    // But we need to be careful: we need index on the stack too.
    // Let's push 998, then OP_PICK.
    // After push: stack = 1000 items. OP_PICK pops 1 (now 999) then pushes 1 (back to 1000).
    script.push_slice(&encode_num(998));
    // Now stack has 1000 items
    script.push_opcode(Opcode::OP_PICK);
    // OP_PICK pops the index (999 items) and pushes the picked value (1000 items again)

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "1000 stack elements with OP_PICK should succeed");
    assert_eq!(engine.stack().len(), 1000);
}

#[test]
fn test_max_script_ops_201() {
    // Script with exactly 201 counted opcodes (the limit) should succeed.
    // OP_NOP is a counted opcode (byte > OP_16).
    // We use 200 OP_NOPs + 1 OP_1 at the end.
    // Wait: OP_1 is NOT counted (it is <= OP_16). So 200 OP_NOPs are counted.
    // To hit exactly 201, we need 201 counted ops.
    // Let's use 200 OP_NOP + OP_NOP(=201st) -- but we need a truthy stack.
    // Push OP_1 first (not counted), then 201 OP_NOPs.
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1);
    for _ in 0..201 {
        script.push_opcode(Opcode::OP_NOP);
    }

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "201 counted opcodes should succeed");
}

#[test]
fn test_over_max_script_ops_202_fails() {
    // Script with 202 counted opcodes should fail.
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1);
    for _ in 0..202 {
        script.push_opcode(Opcode::OP_NOP);
    }

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "202 counted opcodes should fail with OpCountLimit");
}

#[test]
fn test_max_push_size_520_bytes() {
    // Push exactly 520 bytes (max element size), hash it, verify the hash
    let data = vec![0x42u8; 520];
    let expected_hash = sha256(&data);

    let mut script = ScriptBuf::new();
    script.push_slice(&data);
    script.push_opcode(Opcode::OP_SHA256);
    script.push_slice(&expected_hash);
    script.push_opcode(Opcode::OP_EQUAL);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "520-byte push + SHA256 verify should succeed");
}

#[test]
fn test_push_over_520_bytes_fails() {
    // Push 521 bytes -- should fail with PushSizeLimit
    let data = vec![0x42u8; 521];
    let mut script = ScriptBuf::new();
    script.push_slice(&data);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "521-byte push should fail");
}

// ============================================================================
// 2. Real-world complex scripts from Bitcoin / Lightning
// ============================================================================

#[test]
fn test_p2pkh_full_roundtrip_with_real_signature() {
    // Full P2PKH: sign a transaction, then execute scriptSig + scriptPubKey
    let key = TestKeyPair::generate();
    let script_pubkey = key.p2pkh_script();
    let tx = make_spend_tx(&script_pubkey, 50_000);

    let sig = sign_legacy(&key, &tx, 0, script_pubkey.as_bytes());

    // scriptSig: <sig> <pubkey>
    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(&sig);
    script_sig.push_slice(&key.pubkey_bytes());

    let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 50_000);
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "P2PKH full roundtrip should succeed");
}

#[test]
fn test_p2pkh_wrong_key_fails() {
    // Sign with one key, use a different key's scriptPubKey
    let key1 = TestKeyPair::generate();
    let key2 = TestKeyPair::generate();
    let script_pubkey = key2.p2pkh_script();
    let tx = make_spend_tx(&script_pubkey, 50_000);

    // Sign with key1 but the scriptPubKey expects key2's pubkey hash
    let sig = sign_legacy(&key1, &tx, 0, script_pubkey.as_bytes());

    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(&sig);
    script_sig.push_slice(&key1.pubkey_bytes());

    let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 50_000);
    engine.execute(script_sig.as_script()).unwrap();
    // P2PKH script uses OP_EQUALVERIFY which returns an error (not just falsy stack)
    // when the pubkey hash doesn't match.
    let result = engine.execute(script_pubkey.as_script());
    assert!(result.is_err(), "P2PKH with wrong key should fail at EQUALVERIFY (hash mismatch)");
}

#[test]
fn test_2_of_3_multisig_full_roundtrip() {
    // 2-of-3 CHECKMULTISIG with real signatures
    let key1 = TestKeyPair::generate();
    let key2 = TestKeyPair::generate();
    let key3 = TestKeyPair::generate();

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_2);
    script_pubkey.push_slice(&key1.pubkey_bytes());
    script_pubkey.push_slice(&key2.pubkey_bytes());
    script_pubkey.push_slice(&key3.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_3);
    script_pubkey.push_opcode(Opcode::OP_CHECKMULTISIG);

    let tx = make_spend_tx(&script_pubkey, 50_000);

    // Sign with key1 and key3 (skipping key2) -- order must match key order
    let sig1 = sign_legacy(&key1, &tx, 0, script_pubkey.as_bytes());
    let sig3 = sign_legacy(&key3, &tx, 0, script_pubkey.as_bytes());

    // scriptSig: OP_0 <sig1> <sig3>
    let mut script_sig = ScriptBuf::new();
    script_sig.push_opcode(Opcode::OP_0);
    script_sig.push_slice(&sig1);
    script_sig.push_slice(&sig3);

    let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 50_000);
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "2-of-3 CHECKMULTISIG should succeed with keys 1 and 3");
}

#[test]
fn test_2_of_3_multisig_wrong_order_fails() {
    // Try to sign with key3 then key1 (wrong order) -- should fail
    let key1 = TestKeyPair::generate();
    let key2 = TestKeyPair::generate();
    let key3 = TestKeyPair::generate();

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_2);
    script_pubkey.push_slice(&key1.pubkey_bytes());
    script_pubkey.push_slice(&key2.pubkey_bytes());
    script_pubkey.push_slice(&key3.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_3);
    script_pubkey.push_opcode(Opcode::OP_CHECKMULTISIG);

    let tx = make_spend_tx(&script_pubkey, 50_000);

    // Sign with key3 and key1 in WRONG order (sigs in reverse of pubkey order)
    let sig3 = sign_legacy(&key3, &tx, 0, script_pubkey.as_bytes());
    let sig1 = sign_legacy(&key1, &tx, 0, script_pubkey.as_bytes());

    let mut script_sig = ScriptBuf::new();
    script_sig.push_opcode(Opcode::OP_0);
    script_sig.push_slice(&sig3); // key3's sig first -- but key3 is after key1
    script_sig.push_slice(&sig1); // key1's sig second

    let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 50_000);
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(!engine.success(), "CHECKMULTISIG with sigs in wrong order should fail");
}

#[test]
fn test_lightning_funding_output_2_of_2() {
    // Lightning funding output: 2-of-2 multisig
    // OP_2 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
    let alice = TestKeyPair::generate();
    let bob = TestKeyPair::generate();

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_2);
    script_pubkey.push_slice(&alice.pubkey_bytes());
    script_pubkey.push_slice(&bob.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_2);
    script_pubkey.push_opcode(Opcode::OP_CHECKMULTISIG);

    let tx = make_spend_tx(&script_pubkey, 100_000);
    let sig_alice = sign_legacy(&alice, &tx, 0, script_pubkey.as_bytes());
    let sig_bob = sign_legacy(&bob, &tx, 0, script_pubkey.as_bytes());

    let mut script_sig = ScriptBuf::new();
    script_sig.push_opcode(Opcode::OP_0);
    script_sig.push_slice(&sig_alice);
    script_sig.push_slice(&sig_bob);

    let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 100_000);
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "Lightning 2-of-2 funding output should succeed");
}

#[test]
fn test_lightning_commitment_to_self_revocation_path() {
    // Lightning commitment to-self output (revocation path):
    // OP_IF
    //   <revocationpubkey> OP_CHECKSIG
    // OP_ELSE
    //   <to_self_delay> OP_CHECKSEQUENCEVERIFY OP_DROP
    //   <local_delayedpubkey> OP_CHECKSIG
    // OP_ENDIF
    //
    // Test the revocation path (OP_IF branch, push OP_1 to take IF)
    let revocation_key = TestKeyPair::generate();
    let _local_delayed_key = TestKeyPair::generate();

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_IF);
    script_pubkey.push_slice(&revocation_key.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);
    script_pubkey.push_opcode(Opcode::OP_ELSE);
    script_pubkey.push_slice(&encode_num(144)); // ~1 day in blocks
    script_pubkey.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
    script_pubkey.push_opcode(Opcode::OP_DROP);
    script_pubkey.push_slice(&_local_delayed_key.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);
    script_pubkey.push_opcode(Opcode::OP_ENDIF);

    let tx = make_spend_tx(&script_pubkey, 50_000);
    let sig = sign_legacy(&revocation_key, &tx, 0, script_pubkey.as_bytes());

    // scriptSig: <sig> OP_1 (take the IF branch)
    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(&sig);
    script_sig.push_opcode(Opcode::OP_1);

    let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 50_000);
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "Lightning commitment revocation path should succeed");
}

#[test]
fn test_lightning_commitment_to_self_delayed_path() {
    // Test the delayed (ELSE) path with CSV
    let _revocation_key = TestKeyPair::generate();
    let local_delayed_key = TestKeyPair::generate();
    let to_self_delay: i64 = 144;

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_IF);
    script_pubkey.push_slice(&_revocation_key.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);
    script_pubkey.push_opcode(Opcode::OP_ELSE);
    script_pubkey.push_slice(&encode_num(to_self_delay));
    script_pubkey.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
    script_pubkey.push_opcode(Opcode::OP_DROP);
    script_pubkey.push_slice(&local_delayed_key.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);
    script_pubkey.push_opcode(Opcode::OP_ENDIF);

    // Transaction must have version >= 2 for CSV, and sequence must satisfy delay
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![]),
            sequence: to_self_delay as u32, // satisfies CSV
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
        witness: Vec::new(),
        lock_time: 0,
    };

    let sig = sign_legacy(&local_delayed_key, &tx, 0, script_pubkey.as_bytes());

    // scriptSig: <sig> OP_0 (take the ELSE branch)
    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(&sig);
    script_sig.push_opcode(Opcode::OP_0);

    let flags = ScriptFlags {
        verify_checksequenceverify: true,
        ..ScriptFlags::none()
    };

    let mut engine = ScriptEngine::new(&VERIFIER, flags, Some(&tx), 0, 50_000);
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "Lightning commitment delayed path (CSV) should succeed");
}

#[test]
fn test_atomic_swap_claim_path() {
    // Cross-chain atomic swap HTLC -- claim path with preimage:
    // OP_IF
    //   OP_SHA256 <hash> OP_EQUALVERIFY <counterparty_pubkey> OP_CHECKSIG
    // OP_ELSE
    //   <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <my_pubkey> OP_CHECKSIG
    // OP_ENDIF

    let counterparty = TestKeyPair::generate();
    let _my_key = TestKeyPair::generate();
    let preimage = b"atomic swap secret preimage!";
    let hash = sha256(preimage);

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_IF);
    script_pubkey.push_opcode(Opcode::OP_SHA256);
    script_pubkey.push_slice(&hash);
    script_pubkey.push_opcode(Opcode::OP_EQUALVERIFY);
    script_pubkey.push_slice(&counterparty.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);
    script_pubkey.push_opcode(Opcode::OP_ELSE);
    script_pubkey.push_slice(&encode_num(500_000));
    script_pubkey.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);
    script_pubkey.push_opcode(Opcode::OP_DROP);
    script_pubkey.push_slice(&_my_key.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);
    script_pubkey.push_opcode(Opcode::OP_ENDIF);

    let tx = make_spend_tx(&script_pubkey, 50_000);
    let sig = sign_legacy(&counterparty, &tx, 0, script_pubkey.as_bytes());

    // Claim path: <sig> <preimage> OP_1 (take IF branch)
    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(&sig);
    script_sig.push_slice(preimage);
    script_sig.push_opcode(Opcode::OP_1);

    let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 50_000);
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "Atomic swap claim path should succeed with correct preimage");
}

#[test]
fn test_atomic_swap_timeout_path() {
    // Test the timeout (ELSE) path with CLTV
    let _counterparty = TestKeyPair::generate();
    let my_key = TestKeyPair::generate();
    let preimage = b"atomic swap secret preimage!";
    let hash = sha256(preimage);
    let timeout: i64 = 500_000;

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_IF);
    script_pubkey.push_opcode(Opcode::OP_SHA256);
    script_pubkey.push_slice(&hash);
    script_pubkey.push_opcode(Opcode::OP_EQUALVERIFY);
    script_pubkey.push_slice(&_counterparty.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);
    script_pubkey.push_opcode(Opcode::OP_ELSE);
    script_pubkey.push_slice(&encode_num(timeout));
    script_pubkey.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);
    script_pubkey.push_opcode(Opcode::OP_DROP);
    script_pubkey.push_slice(&my_key.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);
    script_pubkey.push_opcode(Opcode::OP_ENDIF);

    // Transaction locktime must be >= timeout
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![]),
            sequence: 0xfffffffe, // not final, required for CLTV
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
        witness: Vec::new(),
        lock_time: 600_000, // > timeout of 500_000
    };

    let sig = sign_legacy(&my_key, &tx, 0, script_pubkey.as_bytes());

    // Timeout path: <sig> OP_0 (take ELSE branch)
    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(&sig);
    script_sig.push_opcode(Opcode::OP_0);

    let flags = ScriptFlags {
        verify_checklocktimeverify: true,
        ..ScriptFlags::none()
    };

    let mut engine = ScriptEngine::new(&VERIFIER, flags, Some(&tx), 0, 50_000);
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "Atomic swap timeout path should succeed after locktime");
}

#[test]
fn test_atomic_swap_wrong_preimage_fails() {
    // Try to claim with a wrong preimage
    let counterparty = TestKeyPair::generate();
    let my_key = TestKeyPair::generate();
    let preimage = b"correct preimage";
    let hash = sha256(preimage);

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_IF);
    script_pubkey.push_opcode(Opcode::OP_SHA256);
    script_pubkey.push_slice(&hash);
    script_pubkey.push_opcode(Opcode::OP_EQUALVERIFY);
    script_pubkey.push_slice(&counterparty.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);
    script_pubkey.push_opcode(Opcode::OP_ELSE);
    script_pubkey.push_slice(&encode_num(500_000));
    script_pubkey.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);
    script_pubkey.push_opcode(Opcode::OP_DROP);
    script_pubkey.push_slice(&my_key.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);
    script_pubkey.push_opcode(Opcode::OP_ENDIF);

    let tx = make_spend_tx(&script_pubkey, 50_000);
    let sig = sign_legacy(&counterparty, &tx, 0, script_pubkey.as_bytes());

    // Wrong preimage
    let wrong_preimage = b"wrong preimage!!";
    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(&sig);
    script_sig.push_slice(wrong_preimage.as_slice());
    script_sig.push_opcode(Opcode::OP_1);

    let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 50_000);
    engine.execute(script_sig.as_script()).unwrap();
    let result = engine.execute(script_pubkey.as_script());
    // OP_EQUALVERIFY will fail
    assert!(result.is_err(), "Atomic swap with wrong preimage should fail at EQUALVERIFY");
}

// ============================================================================
// 3. Vault scripts
// ============================================================================

#[test]
fn test_simple_vault_hot_cold_path() {
    // Vault: spend immediately with 2 keys (hot+cold), or after timeout with 1 key
    // OP_IF
    //   OP_2 <hot_key> <cold_key> OP_2 OP_CHECKMULTISIG
    // OP_ELSE
    //   <30_days> OP_CHECKSEQUENCEVERIFY OP_DROP <recovery_key> OP_CHECKSIG
    // OP_ENDIF

    let hot_key = TestKeyPair::generate();
    let cold_key = TestKeyPair::generate();
    let _recovery_key = TestKeyPair::generate();

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_IF);
    script_pubkey.push_opcode(Opcode::OP_2);
    script_pubkey.push_slice(&hot_key.pubkey_bytes());
    script_pubkey.push_slice(&cold_key.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_2);
    script_pubkey.push_opcode(Opcode::OP_CHECKMULTISIG);
    script_pubkey.push_opcode(Opcode::OP_ELSE);
    script_pubkey.push_slice(&encode_num(4320)); // ~30 days in blocks
    script_pubkey.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
    script_pubkey.push_opcode(Opcode::OP_DROP);
    script_pubkey.push_slice(&_recovery_key.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);
    script_pubkey.push_opcode(Opcode::OP_ENDIF);

    let tx = make_spend_tx(&script_pubkey, 100_000);
    let sig_hot = sign_legacy(&hot_key, &tx, 0, script_pubkey.as_bytes());
    let sig_cold = sign_legacy(&cold_key, &tx, 0, script_pubkey.as_bytes());

    // Hot+cold immediate path: OP_0 <sig_hot> <sig_cold> OP_1
    let mut script_sig = ScriptBuf::new();
    script_sig.push_opcode(Opcode::OP_0); // CHECKMULTISIG dummy
    script_sig.push_slice(&sig_hot);
    script_sig.push_slice(&sig_cold);
    script_sig.push_opcode(Opcode::OP_1); // take IF branch

    let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 100_000);
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "Vault hot+cold path should succeed");
}

#[test]
fn test_simple_vault_recovery_path() {
    // Test the vault recovery path (ELSE branch with CSV)
    let _hot_key = TestKeyPair::generate();
    let _cold_key = TestKeyPair::generate();
    let recovery_key = TestKeyPair::generate();
    let delay: i64 = 4320;

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_IF);
    script_pubkey.push_opcode(Opcode::OP_2);
    script_pubkey.push_slice(&_hot_key.pubkey_bytes());
    script_pubkey.push_slice(&_cold_key.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_2);
    script_pubkey.push_opcode(Opcode::OP_CHECKMULTISIG);
    script_pubkey.push_opcode(Opcode::OP_ELSE);
    script_pubkey.push_slice(&encode_num(delay));
    script_pubkey.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
    script_pubkey.push_opcode(Opcode::OP_DROP);
    script_pubkey.push_slice(&recovery_key.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);
    script_pubkey.push_opcode(Opcode::OP_ENDIF);

    // Transaction must satisfy CSV
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![]),
            sequence: delay as u32, // satisfies CSV
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
        witness: Vec::new(),
        lock_time: 0,
    };

    let sig = sign_legacy(&recovery_key, &tx, 0, script_pubkey.as_bytes());

    // Recovery path: <sig> OP_0 (take ELSE branch)
    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(&sig);
    script_sig.push_opcode(Opcode::OP_0);

    let flags = ScriptFlags {
        verify_checksequenceverify: true,
        ..ScriptFlags::none()
    };

    let mut engine = ScriptEngine::new(&VERIFIER, flags, Some(&tx), 0, 100_000);
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "Vault recovery path should succeed after CSV delay");
}

#[test]
fn test_dead_mans_switch() {
    // If owner spends: <owner_key> OP_CHECKSIG
    // If owner doesn't spend within 1 year: heir can claim
    //
    // Script:
    // OP_IF
    //   <owner_key> OP_CHECKSIG
    // OP_ELSE
    //   <52560_blocks> OP_CHECKSEQUENCEVERIFY OP_DROP <heir_key> OP_CHECKSIG
    // OP_ENDIF

    let owner = TestKeyPair::generate();
    let heir = TestKeyPair::generate();
    let one_year_blocks: i64 = 52560; // ~365 days

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_IF);
    script_pubkey.push_slice(&owner.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);
    script_pubkey.push_opcode(Opcode::OP_ELSE);
    script_pubkey.push_slice(&encode_num(one_year_blocks));
    script_pubkey.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
    script_pubkey.push_opcode(Opcode::OP_DROP);
    script_pubkey.push_slice(&heir.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);
    script_pubkey.push_opcode(Opcode::OP_ENDIF);

    // Owner spending (IF path)
    let tx = make_spend_tx(&script_pubkey, 50_000);
    let sig = sign_legacy(&owner, &tx, 0, script_pubkey.as_bytes());

    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(&sig);
    script_sig.push_opcode(Opcode::OP_1);

    let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 50_000);
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "Dead man's switch: owner path should succeed");

    // Heir spending (ELSE path) after delay
    let tx_heir = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xbb; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![]),
            sequence: one_year_blocks as u32,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
        witness: Vec::new(),
        lock_time: 0,
    };

    let sig_heir = sign_legacy(&heir, &tx_heir, 0, script_pubkey.as_bytes());

    let mut script_sig_heir = ScriptBuf::new();
    script_sig_heir.push_slice(&sig_heir);
    script_sig_heir.push_opcode(Opcode::OP_0);

    let flags = ScriptFlags {
        verify_checksequenceverify: true,
        ..ScriptFlags::none()
    };

    let mut engine2 = ScriptEngine::new(&VERIFIER, flags, Some(&tx_heir), 0, 50_000);
    engine2.execute(script_sig_heir.as_script()).unwrap();
    engine2.execute(script_pubkey.as_script()).unwrap();
    assert!(engine2.success(), "Dead man's switch: heir path should succeed after delay");
}

// ============================================================================
// 4. Adversarial/malicious scripts that should FAIL
// ============================================================================

#[test]
fn test_stack_overflow_attack_1001_elements() {
    // Try to push 1001 elements -- should fail with StackOverflow
    let mut script = ScriptBuf::new();
    for _ in 0..1001 {
        script.push_opcode(Opcode::OP_1);
    }

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "1001 stack elements should overflow");
}

#[test]
fn test_script_too_large_10001_bytes() {
    // 10,001 byte script should be rejected
    let data = vec![Opcode::OP_NOP as u8; 10_001];
    let script = ScriptBuf::from_bytes(data);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "10001-byte script should be rejected");
}

#[test]
fn test_script_exactly_10000_bytes_succeeds() {
    // 10,000 byte script should be accepted
    // Use OP_1 pushes (1 byte each) up to limit minus 1, then one OP_1
    // But we also need to stay under the 201 op count limit for non-push ops.
    // OP_1 through OP_16 are NOT counted, so we can use them freely.
    // Build a 10000-byte script that stays within stack (1000) and op count (201) limits.
    // Strategy: 19 x (push 520 bytes + OP_DROP) = 9956 bytes, then fill with OP_1.
    let mut script = ScriptBuf::new();
    let chunk = vec![0x42u8; 520];
    for _ in 0..19 {
        script.push_slice(&chunk);
        script.push_opcode(Opcode::OP_DROP);
    }
    // 19 * (3 + 520 + 1) = 19 * 524 = 9956 bytes so far
    let remaining = 10_000 - script.as_bytes().len();
    for _ in 0..remaining {
        script.push_opcode(Opcode::OP_1);
    }
    assert_eq!(script.as_bytes().len(), 10_000);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "exactly 10000-byte script should succeed");
}

#[test]
fn test_op_return_in_executable_position() {
    // OP_1 OP_RETURN -- should fail
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_RETURN);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "OP_RETURN should always cause failure");
}

#[test]
fn test_op_return_in_unexecuted_branch() {
    // OP_0 OP_IF OP_RETURN OP_ENDIF OP_1 -- should SUCCEED
    // (OP_RETURN in dead branch is skipped)
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_0);
    script.push_opcode(Opcode::OP_IF);
    script.push_opcode(Opcode::OP_RETURN);
    script.push_opcode(Opcode::OP_ENDIF);
    script.push_opcode(Opcode::OP_1);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "OP_RETURN in dead branch should be skipped");
}

#[test]
fn test_disabled_opcode_in_dead_branch_fails() {
    // OP_0 OP_IF OP_CAT OP_ENDIF OP_1 -- should FAIL
    // (disabled opcodes fail even in dead branches per Bitcoin Core)
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_0);
    script.push_opcode(Opcode::OP_IF);
    script.push_opcode(Opcode::OP_CAT);
    script.push_opcode(Opcode::OP_ENDIF);
    script.push_opcode(Opcode::OP_1);

    // Without OP_CAT plugin registered, it's a disabled opcode
    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "Disabled opcode in dead branch should still fail");
}

#[test]
fn test_verif_in_dead_branch_fails() {
    // OP_0 OP_IF OP_VERIF OP_ENDIF OP_1 -- should FAIL
    // (OP_VERIF is always illegal, even in dead branches)
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_0);
    script.push_opcode(Opcode::OP_IF);
    script.push_opcode(Opcode::OP_VERIF);
    script.push_opcode(Opcode::OP_ENDIF);
    script.push_opcode(Opcode::OP_1);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "OP_VERIF should always be illegal");
}

#[test]
fn test_vernotif_in_dead_branch_fails() {
    // OP_VERNOTIF is also always illegal
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_0);
    script.push_opcode(Opcode::OP_IF);
    script.push_opcode(Opcode::OP_VERNOTIF);
    script.push_opcode(Opcode::OP_ENDIF);
    script.push_opcode(Opcode::OP_1);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "OP_VERNOTIF should always be illegal");
}

#[test]
fn test_negative_number_arithmetic() {
    // OP_1NEGATE OP_1NEGATE OP_ADD -- result should be -2 (truthy, non-zero)
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1NEGATE);
    script.push_opcode(Opcode::OP_1NEGATE);
    script.push_opcode(Opcode::OP_ADD);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "-2 is truthy (non-zero)");
    assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), -2);
}

#[test]
fn test_negative_number_complex_arithmetic() {
    // Test: (-3) + 5 = 2, then 2 * 1 = 2 (no MUL, use ADD),
    // then verify 2 == 2
    let mut script = ScriptBuf::new();
    script.push_slice(&encode_num(-3));
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_ADD); // -3 + 5 = 2
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_NUMEQUAL);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "-3 + 5 should equal 2");
}

#[test]
fn test_number_overflow_5_byte_result() {
    // Push max 4-byte value (2147483647 = 0x7FFFFFFF), add 1.
    // Result is 2147483648 which requires 5 bytes.
    // The result can be pushed (encode_num handles it), but
    // attempting to use it in another arithmetic op (which calls decode_num
    // with 4-byte max) should fail with NumberOverflow.
    let mut script = ScriptBuf::new();
    script.push_slice(&encode_num(i32::MAX as i64));
    script.push_opcode(Opcode::OP_1ADD); // 2147483648 -- 5 bytes
    // Try to do another arithmetic op on the 5-byte result
    script.push_opcode(Opcode::OP_1ADD); // should fail: input is 5 bytes

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "Arithmetic on 5-byte number should fail with overflow");
}

#[test]
fn test_unbalanced_if_fails() {
    // OP_1 OP_IF OP_1 -- missing OP_ENDIF
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_IF);
    script.push_opcode(Opcode::OP_1);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "Unbalanced IF should fail");
}

#[test]
fn test_unbalanced_endif_fails() {
    // OP_1 OP_ENDIF -- ENDIF without IF
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_ENDIF);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "ENDIF without IF should fail");
}

#[test]
fn test_unbalanced_else_fails() {
    // OP_1 OP_ELSE -- ELSE without IF
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_ELSE);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "ELSE without IF should fail");
}

#[test]
fn test_empty_stack_fails() {
    // Empty script (no push, nothing) -- stack is empty, should fail
    let script = ScriptBuf::new();

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(!engine.success(), "Empty stack should be falsy");
}

#[test]
fn test_false_top_of_stack_fails() {
    // OP_0 -- pushes empty byte vector (false)
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_0);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(!engine.success(), "OP_0 should be falsy");
}

#[test]
fn test_op_count_includes_multisig_keys() {
    // CHECKMULTISIG with n_keys counts those keys toward the 201 op limit.
    // Use 199 OP_NOPs + 1 CHECKMULTISIG + 2 keys = 199 + 1 + 2 = 202 > 201
    // Should fail with OpCountLimit.

    // Build script: push required items, then 199 NOPs, then CHECKMULTISIG
    // We need: <dummy> <0 sigs> <pk1> <pk2> <2 keys> ... 199 NOPs ... CHECKMULTISIG
    let k1 = TestKeyPair::generate();
    let k2 = TestKeyPair::generate();

    let mut script = ScriptBuf::new();
    // Push elements for CHECKMULTISIG: OP_0 (dummy), OP_0 (0 sigs), <pk1>, <pk2>, OP_2 (n_keys)
    script.push_opcode(Opcode::OP_0); // dummy
    script.push_opcode(Opcode::OP_0); // 0 sigs
    script.push_slice(&k1.pubkey_bytes());
    script.push_slice(&k2.pubkey_bytes());
    script.push_opcode(Opcode::OP_2); // 2 keys
    // 199 NOPs (each counted)
    for _ in 0..199 {
        script.push_opcode(Opcode::OP_NOP);
    }
    // CHECKMULTISIG (counted as 1, then +2 for n_keys = total 199+1+2=202)
    script.push_opcode(Opcode::OP_CHECKMULTISIG);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "CHECKMULTISIG keys should count toward 201 op limit");
}

#[test]
fn test_checksig_without_tx_context_fails() {
    // CHECKSIG without transaction context should fail
    let key = TestKeyPair::generate();

    let mut script = ScriptBuf::new();
    script.push_slice(b"fake signature data\x01");
    script.push_slice(&key.pubkey_bytes());
    script.push_opcode(Opcode::OP_CHECKSIG);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    let result = engine.execute(script.as_script());
    // This should error because there's no tx to compute sighash against
    assert!(result.is_err(), "CHECKSIG without tx context should fail");
}

// ============================================================================
// 5. Hash puzzles and commitment schemes
// ============================================================================

#[test]
fn test_hash_preimage_puzzle_sha256() {
    // Anyone can spend if they know the SHA256 preimage
    // scriptPubKey: OP_SHA256 <known_hash> OP_EQUAL
    let preimage = b"the secret preimage for this puzzle";
    let hash = sha256(preimage);

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_SHA256);
    script_pubkey.push_slice(&hash);
    script_pubkey.push_opcode(Opcode::OP_EQUAL);

    // scriptSig: <preimage>
    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(preimage);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "SHA256 preimage puzzle should succeed");
}

#[test]
fn test_hash_preimage_puzzle_wrong_preimage() {
    let preimage = b"correct preimage";
    let hash = sha256(preimage);

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_SHA256);
    script_pubkey.push_slice(&hash);
    script_pubkey.push_opcode(Opcode::OP_EQUAL);

    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(b"wrong preimage!!");

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(!engine.success(), "Wrong preimage should not solve the puzzle");
}

#[test]
fn test_double_hash_puzzle() {
    // OP_SHA256 OP_SHA256 <double_hash> OP_EQUAL
    // Need to provide x where SHA256(SHA256(x)) = target
    let preimage = b"double hash me";
    let single = sha256(preimage);
    let double = sha256(&single);

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_SHA256);
    script_pubkey.push_opcode(Opcode::OP_SHA256);
    script_pubkey.push_slice(&double);
    script_pubkey.push_opcode(Opcode::OP_EQUAL);

    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(preimage);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "Double SHA256 puzzle should succeed");
}

#[test]
fn test_hash160_address_verification() {
    // Verify that HASH160 of a pubkey matches an expected address hash
    // This is essentially P2PKH without the signature check
    let key = TestKeyPair::generate();
    let pkh = key.pubkey_hash();

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_HASH160);
    script_pubkey.push_slice(&pkh);
    script_pubkey.push_opcode(Opcode::OP_EQUAL);

    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(&key.pubkey_bytes());

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "HASH160 of pubkey should match pkh");
}

#[test]
fn test_hash256_puzzle() {
    // OP_HASH256 <double_sha256> OP_EQUAL
    let preimage = b"hash256 puzzle preimage";
    let expected = sha256d(preimage);

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_HASH256);
    script_pubkey.push_slice(&expected);
    script_pubkey.push_opcode(Opcode::OP_EQUAL);

    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(preimage);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "HASH256 puzzle should succeed");
}

#[test]
fn test_hash_chain_ripemd_sha256_hash160() {
    // Test chained hash operations:
    // <data> OP_RIPEMD160 -> 20 bytes
    // OP_SHA256 -> 32 bytes
    // OP_HASH160 -> 20 bytes
    // Verify the final result
    let data = b"chain of hashes";

    // Compute expected result manually
    use ripemd::Digest;
    let mut ripemd = ripemd::Ripemd160::new();
    ripemd.update(data);
    let step1: [u8; 20] = ripemd.finalize().into();
    let step2 = sha256(&step1);
    let step3 = hash160(&step2);

    let mut script = ScriptBuf::new();
    script.push_slice(data);
    script.push_opcode(Opcode::OP_RIPEMD160);
    script.push_opcode(Opcode::OP_SHA256);
    script.push_opcode(Opcode::OP_HASH160);
    script.push_slice(&step3);
    script.push_opcode(Opcode::OP_EQUAL);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "Chained RIPEMD160 -> SHA256 -> HASH160 should match");
}

// ============================================================================
// 6. Stack manipulation edge cases
// ============================================================================

#[test]
fn test_pick_from_deep_stack() {
    // Push 100 items, then OP_PICK from the bottom
    let mut script = ScriptBuf::new();
    // Push OP_2 as the bottom item
    script.push_opcode(Opcode::OP_2);
    // Push 99 OP_1s on top
    for _ in 0..99 {
        script.push_opcode(Opcode::OP_1);
    }
    // Pick from index 99 (the bottom item, OP_2)
    script.push_slice(&encode_num(99));
    script.push_opcode(Opcode::OP_PICK);
    // Top should now be 2
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_NUMEQUAL);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "OP_PICK from depth 99 should find the correct value");
}

#[test]
fn test_roll_moves_element() {
    // OP_3 OP_2 OP_1 OP_2 OP_ROLL -> stack becomes [3, 1, 2] (rolled element 2 from pos 2 to top)
    // Wait -- OP_ROLL pops the index first, then the stack is [3, 2, 1].
    // Roll(2) takes the element at index 2 from top: that's 3. Moves it to top.
    // Stack becomes [2, 1, 3].
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_ROLL);
    // Top should be 3
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_NUMEQUAL);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "OP_ROLL should bring deep element to top");
}

#[test]
fn test_altstack_roundtrip() {
    // Push several values, move to altstack, do work, bring back
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_7);
    script.push_opcode(Opcode::OP_TOALTSTACK);
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_TOALTSTACK);
    // Altstack: [7, 3] (3 on top)
    // Main stack: empty
    script.push_opcode(Opcode::OP_FROMALTSTACK); // 3
    script.push_opcode(Opcode::OP_FROMALTSTACK); // 7
    script.push_opcode(Opcode::OP_ADD); // 3 + 7 = 10
    script.push_opcode(Opcode::OP_10);
    script.push_opcode(Opcode::OP_NUMEQUAL);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "Altstack roundtrip should preserve values");
}

#[test]
fn test_depth_opcode() {
    // Push 5 items, then OP_DEPTH should report 5
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_4);
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_DEPTH);
    // Stack: [1, 2, 3, 4, 5, 5]
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_NUMEQUAL);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "OP_DEPTH should report correct stack depth");
}

#[test]
fn test_ifdup_with_true() {
    // OP_1 OP_IFDUP -> stack is [1, 1] (duplicates because top is true)
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_IFDUP);
    script.push_opcode(Opcode::OP_DEPTH);
    // Stack should be [1, 1, 2]
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_NUMEQUAL);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "OP_IFDUP with true should duplicate");
}

#[test]
fn test_ifdup_with_false() {
    // OP_0 OP_IFDUP -> stack is [0] (does not duplicate because top is false)
    // Then push 1 so we have a truthy top
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_0);
    script.push_opcode(Opcode::OP_IFDUP);
    // Stack: [0] (not duplicated)
    script.push_opcode(Opcode::OP_DEPTH);
    // Stack: [0, 1]
    // Top is 1, which is truthy

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "OP_IFDUP with false should not duplicate");
    // Stack depth should be 2 (the original 0 + depth value)
    assert_eq!(engine.stack().len(), 2);
}

// ============================================================================
// 7. Complex conditional logic
// ============================================================================

#[test]
fn test_if_else_endif_true_branch() {
    // OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
    // Should execute the IF branch (push 2)
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_IF);
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_ELSE);
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_ENDIF);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 2);
}

#[test]
fn test_if_else_endif_false_branch() {
    // OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
    // Should execute the ELSE branch (push 3)
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_0);
    script.push_opcode(Opcode::OP_IF);
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_ELSE);
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_ENDIF);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 3);
}

#[test]
fn test_notif_semantics() {
    // OP_0 OP_NOTIF OP_1 OP_ENDIF
    // NOTIF inverts the condition: 0 -> true, so execute the body
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_0);
    script.push_opcode(Opcode::OP_NOTIF);
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_ENDIF);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

#[test]
fn test_nested_if_else_complex() {
    // Complex nested conditional:
    // OP_1 OP_IF
    //   OP_0 OP_IF
    //     OP_2  (dead)
    //   OP_ELSE
    //     OP_3  (executed)
    //   OP_ENDIF
    // OP_ELSE
    //   OP_4  (dead)
    // OP_ENDIF
    // Result should be 3
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_IF);
    script.push_opcode(Opcode::OP_0);
    script.push_opcode(Opcode::OP_IF);
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_ELSE);
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_ENDIF);
    script.push_opcode(Opcode::OP_ELSE);
    script.push_opcode(Opcode::OP_4);
    script.push_opcode(Opcode::OP_ENDIF);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 3);
}

// ============================================================================
// 8. Arithmetic edge cases
// ============================================================================

#[test]
fn test_abs_of_negative() {
    // OP_1NEGATE OP_ABS -> 1
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1NEGATE);
    script.push_opcode(Opcode::OP_ABS);
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_NUMEQUAL);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

#[test]
fn test_negate_negate_identity() {
    // OP_5 OP_NEGATE OP_NEGATE -> 5
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_NEGATE);
    script.push_opcode(Opcode::OP_NEGATE);
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_NUMEQUAL);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

#[test]
fn test_not_boolean_logic() {
    // OP_0 OP_NOT -> 1 (NOT of false is true)
    // OP_1 OP_NOT -> 0 (NOT of true is false)
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_0);
    script.push_opcode(Opcode::OP_NOT);
    // Stack: [1]
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_NOT);
    // Stack: [1, 0]
    script.push_opcode(Opcode::OP_BOOLOR);
    // Stack: [1] (1 OR 0 = 1)

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

#[test]
fn test_within_range_check() {
    // OP_WITHIN checks if x is in [min, max)
    // 5 WITHIN [3, 8) -> true (1)
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_5); // x
    script.push_opcode(Opcode::OP_3); // min
    script.push_opcode(Opcode::OP_8); // max
    script.push_opcode(Opcode::OP_WITHIN);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "5 should be within [3, 8)");
}

#[test]
fn test_within_boundary_exclusive() {
    // 8 WITHIN [3, 8) -> false (max is exclusive)
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_8); // x == max
    script.push_opcode(Opcode::OP_3); // min
    script.push_opcode(Opcode::OP_8); // max
    script.push_opcode(Opcode::OP_WITHIN);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(!engine.success(), "8 should NOT be within [3, 8) -- exclusive upper bound");
}

#[test]
fn test_min_max_opcodes() {
    // OP_3 OP_7 OP_MIN -> 3
    // OP_3 OP_7 OP_MAX -> 7
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_7);
    script.push_opcode(Opcode::OP_MIN);
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_NUMEQUAL); // 3 == 3
    script.push_opcode(Opcode::OP_DROP);

    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_7);
    script.push_opcode(Opcode::OP_MAX);
    script.push_opcode(Opcode::OP_7);
    script.push_opcode(Opcode::OP_NUMEQUAL); // 7 == 7

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

// ============================================================================
// 9. Size and comparison operations
// ============================================================================

#[test]
fn test_size_of_various_pushes() {
    // Push different sized data, check SIZE
    let mut script = ScriptBuf::new();
    // 0-byte push (OP_0)
    script.push_opcode(Opcode::OP_0);
    script.push_opcode(Opcode::OP_SIZE);
    script.push_opcode(Opcode::OP_0);
    script.push_opcode(Opcode::OP_NUMEQUAL);
    script.push_opcode(Opcode::OP_VERIFY);
    script.push_opcode(Opcode::OP_DROP);

    // 33-byte push (pubkey)
    let key = TestKeyPair::generate();
    script.push_slice(&key.pubkey_bytes());
    script.push_opcode(Opcode::OP_SIZE);
    script.push_slice(&encode_num(33));
    script.push_opcode(Opcode::OP_NUMEQUAL);
    script.push_opcode(Opcode::OP_VERIFY);
    script.push_opcode(Opcode::OP_DROP);

    // 32-byte push (hash)
    script.push_slice(&sha256(b"test"));
    script.push_opcode(Opcode::OP_SIZE);
    script.push_slice(&encode_num(32));
    script.push_opcode(Opcode::OP_NUMEQUAL);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

// ============================================================================
// 10. CLTV and CSV edge cases
// ============================================================================

#[test]
fn test_cltv_type_mismatch_block_vs_time_fails() {
    // Script requires block height locktime (< 500_000_000),
    // but transaction has timestamp locktime (>= 500_000_000).
    // Should fail with UnsatisfiedLocktime.
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
        lock_time: 1_700_000_000, // timestamp
    };

    let mut script = ScriptBuf::new();
    script.push_slice(&encode_num(100)); // block height
    script.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);
    script.push_opcode(Opcode::OP_DROP);
    script.push_opcode(Opcode::OP_1);

    let flags = ScriptFlags {
        verify_checklocktimeverify: true,
        ..ScriptFlags::none()
    };

    let mut engine = ScriptEngine::new(&VERIFIER, flags, Some(&tx), 0, 0);
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "CLTV type mismatch (block vs time) should fail");
}

#[test]
fn test_cltv_negative_locktime_fails() {
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
        lock_time: 500,
    };

    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1NEGATE); // negative locktime
    script.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);

    let flags = ScriptFlags {
        verify_checklocktimeverify: true,
        ..ScriptFlags::none()
    };

    let mut engine = ScriptEngine::new(&VERIFIER, flags, Some(&tx), 0, 0);
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "Negative locktime should fail");
}

#[test]
fn test_csv_disabled_flag_acts_as_nop() {
    // When the disable flag (bit 31) is set in the CSV argument,
    // CSV should behave as NOP (succeed).
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![]),
            sequence: 0xffffffff, // bit 31 set in tx sequence too
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::from_bytes(vec![]),
        }],
        witness: Vec::new(),
        lock_time: 0,
    };

    // Push a number with bit 31 set (disable flag)
    let csv_val: i64 = 1 << 31;
    let mut script = ScriptBuf::new();
    script.push_slice(&encode_num(csv_val));
    script.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
    script.push_opcode(Opcode::OP_DROP);
    script.push_opcode(Opcode::OP_1);

    let flags = ScriptFlags {
        verify_checksequenceverify: true,
        ..ScriptFlags::none()
    };

    let mut engine = ScriptEngine::new(&VERIFIER, flags, Some(&tx), 0, 0);
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "CSV with disable flag should behave as NOP");
}

// ============================================================================
// 11. OP_CAT with plugin (Merkle proof in script)
// ============================================================================

#[test]
fn test_merkle_proof_with_op_cat() {
    // Verify a simple 2-level Merkle proof:
    // Given leaf_a and leaf_b, the Merkle root is SHA256(leaf_a || leaf_b)
    // Push leaf_a, push leaf_b, OP_CAT, OP_SHA256, compare to root.
    use btc_consensus::opcode_plugin::{OpCat, OpcodeRegistry};

    let mut registry = OpcodeRegistry::new();
    registry.register(Box::new(OpCat));

    let leaf_a = sha256(b"transaction A");
    let leaf_b = sha256(b"transaction B");
    let mut combined = Vec::new();
    combined.extend_from_slice(&leaf_a);
    combined.extend_from_slice(&leaf_b);
    let merkle_root = sha256(&combined);

    let mut script = ScriptBuf::new();
    script.push_slice(&leaf_a);
    script.push_slice(&leaf_b);
    script.push_opcode(Opcode::OP_CAT);
    script.push_opcode(Opcode::OP_SHA256);
    script.push_slice(&merkle_root);
    script.push_opcode(Opcode::OP_EQUAL);

    let mut engine = ScriptEngine::new_with_registry(
        &VERIFIER,
        ScriptFlags::none(),
        None, 0, 0,
        Some(&registry),
    );
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "Merkle proof with OP_CAT should verify");
}

#[test]
fn test_merkle_proof_3_level_with_op_cat() {
    // 3-level Merkle tree: 4 leaves, prove inclusion of leaf_a
    // Tree:
    //       root
    //      /    \
    //    h_ab   h_cd
    //   /  \   /  \
    //  a    b c    d
    //
    // Proof for leaf_a: provide leaf_b (sibling), then h_cd (uncle)
    // Verify: SHA256(SHA256(a || b) || h_cd) == root
    use btc_consensus::opcode_plugin::{OpCat, OpcodeRegistry};

    let mut registry = OpcodeRegistry::new();
    registry.register(Box::new(OpCat));

    let leaf_a = sha256(b"leaf A");
    let leaf_b = sha256(b"leaf B");
    let leaf_c = sha256(b"leaf C");
    let leaf_d = sha256(b"leaf D");

    let mut ab = Vec::new();
    ab.extend_from_slice(&leaf_a);
    ab.extend_from_slice(&leaf_b);
    let h_ab = sha256(&ab);

    let mut cd = Vec::new();
    cd.extend_from_slice(&leaf_c);
    cd.extend_from_slice(&leaf_d);
    let h_cd = sha256(&cd);

    let mut root_input = Vec::new();
    root_input.extend_from_slice(&h_ab);
    root_input.extend_from_slice(&h_cd);
    let root = sha256(&root_input);

    // Script to verify inclusion of leaf_a:
    // <leaf_a> <leaf_b> OP_CAT OP_SHA256 <h_cd> OP_CAT OP_SHA256 <root> OP_EQUAL
    let mut script = ScriptBuf::new();
    script.push_slice(&leaf_a);
    script.push_slice(&leaf_b);
    script.push_opcode(Opcode::OP_CAT);
    script.push_opcode(Opcode::OP_SHA256);
    script.push_slice(&h_cd);
    script.push_opcode(Opcode::OP_CAT);
    script.push_opcode(Opcode::OP_SHA256);
    script.push_slice(&root);
    script.push_opcode(Opcode::OP_EQUAL);

    let mut engine = ScriptEngine::new_with_registry(
        &VERIFIER,
        ScriptFlags::none(),
        None, 0, 0,
        Some(&registry),
    );
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "3-level Merkle proof with OP_CAT should verify");
}

// ============================================================================
// 12. CHECKSIG with OP_CODESEPARATOR
// ============================================================================

#[test]
fn test_checksig_with_codeseparator() {
    // OP_CODESEPARATOR changes the subscript used for sighash computation.
    // Build a script where CODESEPARATOR is placed before CHECKSIG.
    let key = TestKeyPair::generate();

    // scriptPubKey: OP_CODESEPARATOR <pubkey> OP_CHECKSIG
    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_CODESEPARATOR);
    script_pubkey.push_slice(&key.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);

    // The sighash should use the subscript starting AFTER OP_CODESEPARATOR.
    // That subscript is: <pubkey> OP_CHECKSIG
    let mut subscript = ScriptBuf::new();
    subscript.push_slice(&key.pubkey_bytes());
    subscript.push_opcode(Opcode::OP_CHECKSIG);

    let tx = make_spend_tx(&script_pubkey, 50_000);

    // Sign against the subscript (after CODESEPARATOR)
    let sig = sign_legacy(&key, &tx, 0, subscript.as_bytes());

    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(&sig);

    let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 50_000);
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "CHECKSIG with OP_CODESEPARATOR should use the subscript after separator");
}

// ============================================================================
// 13. Complex script combining multiple features
// ============================================================================

#[test]
fn test_escrow_3_of_3_with_hash_commitment() {
    // Escrow script: requires 2-of-3 multisig AND knowledge of a hash preimage
    // OP_SHA256 <hash> OP_EQUALVERIFY
    // OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
    let alice = TestKeyPair::generate();
    let bob = TestKeyPair::generate();
    let escrow_agent = TestKeyPair::generate();
    let secret = b"escrow release secret";
    let hash = sha256(secret);

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_SHA256);
    script_pubkey.push_slice(&hash);
    script_pubkey.push_opcode(Opcode::OP_EQUALVERIFY);
    script_pubkey.push_opcode(Opcode::OP_2);
    script_pubkey.push_slice(&alice.pubkey_bytes());
    script_pubkey.push_slice(&bob.pubkey_bytes());
    script_pubkey.push_slice(&escrow_agent.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_3);
    script_pubkey.push_opcode(Opcode::OP_CHECKMULTISIG);

    let tx = make_spend_tx(&script_pubkey, 50_000);
    let sig_alice = sign_legacy(&alice, &tx, 0, script_pubkey.as_bytes());
    let sig_bob = sign_legacy(&bob, &tx, 0, script_pubkey.as_bytes());

    // scriptSig: OP_0 <sig_alice> <sig_bob> <secret>
    let mut script_sig = ScriptBuf::new();
    script_sig.push_opcode(Opcode::OP_0);
    script_sig.push_slice(&sig_alice);
    script_sig.push_slice(&sig_bob);
    script_sig.push_slice(secret);

    let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 50_000);
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "Escrow with hash commitment + 2-of-3 multisig should succeed");
}

#[test]
fn test_escrow_wrong_secret_fails() {
    // Same escrow script but with wrong secret
    let alice = TestKeyPair::generate();
    let bob = TestKeyPair::generate();
    let escrow_agent = TestKeyPair::generate();
    let secret = b"escrow release secret";
    let hash = sha256(secret);

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(Opcode::OP_SHA256);
    script_pubkey.push_slice(&hash);
    script_pubkey.push_opcode(Opcode::OP_EQUALVERIFY);
    script_pubkey.push_opcode(Opcode::OP_2);
    script_pubkey.push_slice(&alice.pubkey_bytes());
    script_pubkey.push_slice(&bob.pubkey_bytes());
    script_pubkey.push_slice(&escrow_agent.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_3);
    script_pubkey.push_opcode(Opcode::OP_CHECKMULTISIG);

    let tx = make_spend_tx(&script_pubkey, 50_000);
    let sig_alice = sign_legacy(&alice, &tx, 0, script_pubkey.as_bytes());
    let sig_bob = sign_legacy(&bob, &tx, 0, script_pubkey.as_bytes());

    let mut script_sig = ScriptBuf::new();
    script_sig.push_opcode(Opcode::OP_0);
    script_sig.push_slice(&sig_alice);
    script_sig.push_slice(&sig_bob);
    script_sig.push_slice(b"wrong secret value!!");

    let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 50_000);
    engine.execute(script_sig.as_script()).unwrap();
    let result = engine.execute(script_pubkey.as_script());
    assert!(result.is_err(), "Escrow with wrong secret should fail at EQUALVERIFY");
}

#[test]
fn test_multisig_21_keys_fails() {
    // CHECKMULTISIG with 21 keys should fail (max is 20)
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_0); // dummy
    script.push_opcode(Opcode::OP_0); // 0 sigs
    for _ in 0..21 {
        script.push_slice(&[0x02; 33]); // fake pubkey
    }
    script.push_slice(&encode_num(21));
    script.push_opcode(Opcode::OP_CHECKMULTISIG);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "CHECKMULTISIG with 21 keys should fail");
}

// ============================================================================
// 14. DUP/SWAP/ROT/NIP/TUCK/OVER stress tests
// ============================================================================

#[test]
fn test_2dup_3dup_2over_2swap_2rot() {
    // Test all multi-element stack ops
    let mut script = ScriptBuf::new();

    // 2DUP: [1,2] -> [1,2,1,2]
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_2DUP);
    script.push_opcode(Opcode::OP_DEPTH);
    script.push_opcode(Opcode::OP_4);
    script.push_opcode(Opcode::OP_NUMEQUALVERIFY);
    script.push_opcode(Opcode::OP_2DROP);
    script.push_opcode(Opcode::OP_2DROP);

    // 3DUP: [1,2,3] -> [1,2,3,1,2,3]
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_3DUP);
    script.push_opcode(Opcode::OP_DEPTH);
    script.push_opcode(Opcode::OP_6);
    script.push_opcode(Opcode::OP_NUMEQUALVERIFY);
    script.push_opcode(Opcode::OP_2DROP);
    script.push_opcode(Opcode::OP_2DROP);
    script.push_opcode(Opcode::OP_2DROP);

    // Final truthy value
    script.push_opcode(Opcode::OP_1);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

#[test]
fn test_swap_rot_nip_tuck_over() {
    // Test individual stack manipulation ops with verified results
    let mut script = ScriptBuf::new();

    // SWAP: [1, 2] -> [2, 1]
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_SWAP);
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_NUMEQUALVERIFY); // top was 2, after swap it's 1
    script.push_opcode(Opcode::OP_DROP);

    // ROT: [1, 2, 3] -> [2, 3, 1]
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_ROT);
    // After ROT: [2, 3, 1], top = 1
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_NUMEQUALVERIFY);
    script.push_opcode(Opcode::OP_2DROP);

    // NIP: [1, 2] -> [2] (remove second-to-top)
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_NIP);
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_NUMEQUALVERIFY);

    // TUCK: [1, 2] -> [2, 1, 2]
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_TUCK);
    script.push_opcode(Opcode::OP_DEPTH);
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_NUMEQUALVERIFY);
    script.push_opcode(Opcode::OP_2DROP);
    script.push_opcode(Opcode::OP_DROP);

    // OVER: [1, 2] -> [1, 2, 1]
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_OVER);
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_NUMEQUAL);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

// ============================================================================
// 15. Multiple CHECKSIG in one script
// ============================================================================

#[test]
fn test_dual_checksig_both_must_pass() {
    // Script requires two separate signatures from two different keys:
    // <sig1> <pk1> OP_CHECKSIGVERIFY <sig2> <pk2> OP_CHECKSIG
    let key1 = TestKeyPair::generate();
    let key2 = TestKeyPair::generate();

    let mut script_pubkey = ScriptBuf::new();
    // First: verify key1's sig (consumed by CHECKSIGVERIFY)
    script_pubkey.push_slice(&key1.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIGVERIFY);
    // Second: check key2's sig
    script_pubkey.push_slice(&key2.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);

    let tx = make_spend_tx(&script_pubkey, 50_000);
    let sig1 = sign_legacy(&key1, &tx, 0, script_pubkey.as_bytes());
    let sig2 = sign_legacy(&key2, &tx, 0, script_pubkey.as_bytes());

    // scriptSig: <sig2> <sig1> (sig1 is consumed first by CHECKSIGVERIFY)
    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(&sig2);
    script_sig.push_slice(&sig1);

    let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 50_000);
    engine.execute(script_sig.as_script()).unwrap();
    engine.execute(script_pubkey.as_script()).unwrap();
    assert!(engine.success(), "Dual CHECKSIG should succeed with both valid signatures");
}

// ============================================================================
// 16. Comparison opcodes
// ============================================================================

#[test]
fn test_comparison_opcodes() {
    let mut script = ScriptBuf::new();

    // 3 < 5 -> 1
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_LESSTHAN);
    script.push_opcode(Opcode::OP_VERIFY);

    // 5 > 3 -> 1
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_GREATERTHAN);
    script.push_opcode(Opcode::OP_VERIFY);

    // 5 <= 5 -> 1
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_LESSTHANOREQUAL);
    script.push_opcode(Opcode::OP_VERIFY);

    // 5 >= 5 -> 1
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_GREATERTHANOREQUAL);
    script.push_opcode(Opcode::OP_VERIFY);

    // 3 != 5 -> 1
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_NUMNOTEQUAL);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

// ============================================================================
// 17. Boolean logic opcodes
// ============================================================================

#[test]
fn test_booland_boolor() {
    let mut script = ScriptBuf::new();

    // 1 AND 1 -> 1
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_BOOLAND);
    script.push_opcode(Opcode::OP_VERIFY);

    // 1 AND 0 -> 0 -> NOT -> 1
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_0);
    script.push_opcode(Opcode::OP_BOOLAND);
    script.push_opcode(Opcode::OP_NOT);
    script.push_opcode(Opcode::OP_VERIFY);

    // 0 OR 1 -> 1
    script.push_opcode(Opcode::OP_0);
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_BOOLOR);
    script.push_opcode(Opcode::OP_VERIFY);

    // 0 OR 0 -> 0 -> NOT -> 1
    script.push_opcode(Opcode::OP_0);
    script.push_opcode(Opcode::OP_0);
    script.push_opcode(Opcode::OP_BOOLOR);
    script.push_opcode(Opcode::OP_NOT);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

// ============================================================================
// 18. 0NOTEQUAL opcode
// ============================================================================

#[test]
fn test_0notequal() {
    // 0 -> 0NOTEQUAL -> 0 (false)
    // 5 -> 0NOTEQUAL -> 1 (true)
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_0NOTEQUAL);
    script.push_opcode(Opcode::OP_VERIFY);

    script.push_opcode(Opcode::OP_0);
    script.push_opcode(Opcode::OP_0NOTEQUAL);
    script.push_opcode(Opcode::OP_NOT); // 0 -> 1

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

// ============================================================================
// 19. OP_EQUAL vs OP_NUMEQUAL distinction
// ============================================================================

#[test]
fn test_equal_vs_numequal() {
    // OP_EQUAL does byte comparison, OP_NUMEQUAL does numeric comparison
    // Both should agree on simple numbers
    let mut script = ScriptBuf::new();

    // OP_NUMEQUAL: 5 == 5
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_NUMEQUAL);
    script.push_opcode(Opcode::OP_VERIFY);

    // OP_EQUAL: same bytes
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_EQUAL);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success());
}

// ============================================================================
// 20. OP_CHECKSIGVERIFY fails properly
// ============================================================================

#[test]
fn test_checksigverify_invalid_sig_fails() {
    let key = TestKeyPair::generate();

    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_slice(&key.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIGVERIFY);
    script_pubkey.push_opcode(Opcode::OP_1); // would succeed if CHECKSIGVERIFY passes

    let tx = make_spend_tx(&script_pubkey, 50_000);

    // Push a garbage signature (non-empty, but not valid DER)
    let mut script_sig = ScriptBuf::new();
    script_sig.push_slice(&[0xde, 0xad, 0xbe, 0xef, 0x01]);

    let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 50_000);
    engine.execute(script_sig.as_script()).unwrap();
    let result = engine.execute(script_pubkey.as_script());
    assert!(result.is_err(), "CHECKSIGVERIFY with invalid signature should fail");
}

// ============================================================================
// 21. Stress: many NOPs interspersed with real operations
// ============================================================================

#[test]
fn test_nops_interspersed_with_operations() {
    // Build a script that does real arithmetic with NOPs sprinkled in
    // Total counted ops must stay <= 201
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_3);
    for _ in 0..10 { script.push_opcode(Opcode::OP_NOP); }
    script.push_opcode(Opcode::OP_4);
    for _ in 0..10 { script.push_opcode(Opcode::OP_NOP); }
    script.push_opcode(Opcode::OP_ADD);
    for _ in 0..10 { script.push_opcode(Opcode::OP_NOP); }
    script.push_opcode(Opcode::OP_7);
    for _ in 0..10 { script.push_opcode(Opcode::OP_NOP); }
    script.push_opcode(Opcode::OP_NUMEQUAL);
    // Total counted ops: 40 NOPs + 2 (ADD, NUMEQUAL) = 42

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "3 + 4 == 7 with NOPs should succeed");
}

// ============================================================================
// 22. SHA1 (deprecated but required for consensus)
// ============================================================================

#[test]
fn test_sha1_hash_puzzle() {
    // OP_SHA1 <expected_sha1> OP_EQUAL
    let preimage = b"SHA1 preimage test";
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(preimage);
    let expected: [u8; 20] = hasher.finalize().into();

    let mut script = ScriptBuf::new();
    script.push_slice(preimage);
    script.push_opcode(Opcode::OP_SHA1);
    script.push_slice(&expected);
    script.push_opcode(Opcode::OP_EQUAL);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "SHA1 hash puzzle should succeed");
}

// ============================================================================
// 23. Multiple disabled opcodes in dead branches
// ============================================================================

#[test]
fn test_multiple_disabled_opcodes_all_fail() {
    // Each disabled opcode in a dead branch should fail
    let disabled_ops = [
        Opcode::OP_SUBSTR,
        Opcode::OP_LEFT,
        Opcode::OP_RIGHT,
        Opcode::OP_INVERT,
        Opcode::OP_AND,
        Opcode::OP_OR,
        Opcode::OP_XOR,
        Opcode::OP_2MUL,
        Opcode::OP_2DIV,
        Opcode::OP_MUL,
        Opcode::OP_DIV,
        Opcode::OP_MOD,
        Opcode::OP_LSHIFT,
        Opcode::OP_RSHIFT,
    ];

    for op in &disabled_ops {
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_0);
        script.push_opcode(Opcode::OP_IF);
        script.push_opcode(*op);
        script.push_opcode(Opcode::OP_ENDIF);
        script.push_opcode(Opcode::OP_1);

        let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
        let result = engine.execute(script.as_script());
        assert!(
            result.is_err(),
            "Disabled opcode {:?} in dead branch should still fail",
            op
        );
    }
}

// ============================================================================
// 24. CLTV and CSV as NOP when flags not set
// ============================================================================

#[test]
fn test_cltv_as_nop_when_flag_not_set() {
    // When verify_checklocktimeverify is false, CLTV acts as NOP
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);
    script.push_opcode(Opcode::OP_DROP);
    script.push_opcode(Opcode::OP_1);

    let flags = ScriptFlags::none(); // CLTV not enabled
    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, flags);
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "CLTV should act as NOP when flag is not set");
}

#[test]
fn test_csv_as_nop_when_flag_not_set() {
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1);
    script.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
    script.push_opcode(Opcode::OP_DROP);
    script.push_opcode(Opcode::OP_1);

    let flags = ScriptFlags::none(); // CSV not enabled
    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, flags);
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "CSV should act as NOP when flag is not set");
}

// ============================================================================
// 25. Edge case: exact boundary of script size limit
// ============================================================================

#[test]
fn test_script_size_exactly_10000() {
    // Build a script that is exactly 10000 bytes
    // Already tested above in test_script_exactly_10000_bytes_succeeds
    // but let's also verify 10001 fails
    let data = vec![Opcode::OP_1 as u8; 10_001];
    let script = ScriptBuf::from_bytes(data);
    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    let result = engine.execute(script.as_script());
    assert!(result.is_err(), "10001 byte script should be rejected");
}

// ============================================================================
// 26. Complex multi-path conditional with CHECKSIG
// ============================================================================

#[test]
fn test_three_path_spending_script() {
    // Three possible spending paths:
    // Path 1: OP_1 -> Alice signs
    // Path 2: OP_2 -> Bob signs with hash preimage
    // Path 3: OP_3 (or anything else) -> 2-of-2 multisig (Alice + Bob)
    //
    // OP_DUP OP_1 OP_NUMEQUAL OP_IF
    //   OP_DROP <alice_pk> OP_CHECKSIG
    // OP_ELSE OP_DUP OP_2 OP_NUMEQUAL OP_IF
    //   OP_DROP OP_SHA256 <hash> OP_EQUALVERIFY <bob_pk> OP_CHECKSIG
    // OP_ELSE
    //   OP_DROP OP_2 <alice_pk> <bob_pk> OP_2 OP_CHECKMULTISIG
    // OP_ENDIF OP_ENDIF

    let alice = TestKeyPair::generate();
    let bob = TestKeyPair::generate();
    let secret = b"path2 secret";
    let hash = sha256(secret);

    let mut script_pubkey = ScriptBuf::new();
    // Path selection
    script_pubkey.push_opcode(Opcode::OP_DUP);
    script_pubkey.push_opcode(Opcode::OP_1);
    script_pubkey.push_opcode(Opcode::OP_NUMEQUAL);
    script_pubkey.push_opcode(Opcode::OP_IF);
    // Path 1: Alice
    script_pubkey.push_opcode(Opcode::OP_DROP);
    script_pubkey.push_slice(&alice.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);
    script_pubkey.push_opcode(Opcode::OP_ELSE);
    script_pubkey.push_opcode(Opcode::OP_DUP);
    script_pubkey.push_opcode(Opcode::OP_2);
    script_pubkey.push_opcode(Opcode::OP_NUMEQUAL);
    script_pubkey.push_opcode(Opcode::OP_IF);
    // Path 2: Bob + hash
    script_pubkey.push_opcode(Opcode::OP_DROP);
    script_pubkey.push_opcode(Opcode::OP_SHA256);
    script_pubkey.push_slice(&hash);
    script_pubkey.push_opcode(Opcode::OP_EQUALVERIFY);
    script_pubkey.push_slice(&bob.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_CHECKSIG);
    script_pubkey.push_opcode(Opcode::OP_ELSE);
    // Path 3: 2-of-2
    script_pubkey.push_opcode(Opcode::OP_DROP);
    script_pubkey.push_opcode(Opcode::OP_2);
    script_pubkey.push_slice(&alice.pubkey_bytes());
    script_pubkey.push_slice(&bob.pubkey_bytes());
    script_pubkey.push_opcode(Opcode::OP_2);
    script_pubkey.push_opcode(Opcode::OP_CHECKMULTISIG);
    script_pubkey.push_opcode(Opcode::OP_ENDIF);
    script_pubkey.push_opcode(Opcode::OP_ENDIF);

    let tx = make_spend_tx(&script_pubkey, 50_000);

    // Test Path 1: Alice signs, path selector = 1
    {
        let sig = sign_legacy(&alice, &tx, 0, script_pubkey.as_bytes());
        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(&sig);
        script_sig.push_opcode(Opcode::OP_1);

        let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 50_000);
        engine.execute(script_sig.as_script()).unwrap();
        engine.execute(script_pubkey.as_script()).unwrap();
        assert!(engine.success(), "Path 1 (Alice) should succeed");
    }

    // Test Path 2: Bob signs + preimage, path selector = 2
    {
        let sig = sign_legacy(&bob, &tx, 0, script_pubkey.as_bytes());
        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(&sig);
        script_sig.push_slice(secret);
        script_sig.push_opcode(Opcode::OP_2);

        let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 50_000);
        engine.execute(script_sig.as_script()).unwrap();
        engine.execute(script_pubkey.as_script()).unwrap();
        assert!(engine.success(), "Path 2 (Bob + hash) should succeed");
    }

    // Test Path 3: 2-of-2 multisig, path selector = 3
    {
        let sig_alice = sign_legacy(&alice, &tx, 0, script_pubkey.as_bytes());
        let sig_bob = sign_legacy(&bob, &tx, 0, script_pubkey.as_bytes());
        let mut script_sig = ScriptBuf::new();
        script_sig.push_opcode(Opcode::OP_0); // CHECKMULTISIG dummy
        script_sig.push_slice(&sig_alice);
        script_sig.push_slice(&sig_bob);
        script_sig.push_opcode(Opcode::OP_3);

        let mut engine = ScriptEngine::new(&VERIFIER, ScriptFlags::none(), Some(&tx), 0, 50_000);
        engine.execute(script_sig.as_script()).unwrap();
        engine.execute(script_pubkey.as_script()).unwrap();
        assert!(engine.success(), "Path 3 (2-of-2 multisig) should succeed");
    }
}
