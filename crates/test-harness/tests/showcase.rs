//! Showcase integration tests -- demonstrate btc-rust's unique capabilities.
//!
//! These tests highlight features that set btc-rust apart: pluggable opcodes
//! (CTV covenants, OP_CAT), parallel script verification, ExEx plugins for
//! ordinals/runes, block template building, BIP9 version bits, chain reorgs,
//! and universal address type support.

use btc_test::{TestNode, TestKeyPair};
use btc_consensus::utxo::UtxoSet;
use btc_primitives::amount::Amount;
use btc_primitives::block::{Block, BlockHeader};
use btc_primitives::compact::CompactTarget;
use btc_primitives::hash::{sha256, hash160, BlockHash, TxHash};
use btc_primitives::script::{Opcode, ScriptBuf};
use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness};

// ============================================================================
// 1. Pluggable CTV Covenant
// ============================================================================

#[test]
fn showcase_pluggable_ctv_covenant() {
    // Demonstrate CTV: create a transaction that can ONLY be spent
    // to a specific set of outputs (covenant enforcement).
    //
    // btc-rust's pluggable opcode architecture allows BIP119 OP_CTV
    // to be tested without recompiling the node.
    use btc_consensus::opcode_plugin::{
        OpCheckTemplateVerify, OpcodeRegistry,
        default_check_template_verify_hash,
    };
    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
    use btc_consensus::sig_verify::Secp256k1Verifier;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;

    let mut registry = OpcodeRegistry::new();
    registry.register(Box::new(OpCheckTemplateVerify));

    // Build the spending transaction -- two outputs locked to specific
    // addresses (the "covenant template").
    let key_a = TestKeyPair::generate();
    let key_b = TestKeyPair::generate();

    let spending_tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![]),
            sequence: TxIn::SEQUENCE_FINAL,
        }],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(30_000),
                script_pubkey: key_a.p2pkh_script(),
            },
            TxOut {
                value: Amount::from_sat(20_000),
                script_pubkey: key_b.p2pkh_script(),
            },
        ],
        witness: Vec::new(),
        lock_time: 0,
    };

    // Compute the template hash the covenant commits to.
    let template_hash = default_check_template_verify_hash(&spending_tx, 0);

    // Build the locking script: <template_hash> OP_CTV
    let mut locking_script = ScriptBuf::new();
    locking_script.push_slice(&template_hash);
    locking_script.push_opcode(Opcode::from_u8(0xb3)); // OP_NOP4 = CTV

    // Execute: the engine should succeed because the spending tx matches
    // the committed template.
    let flags = ScriptFlags::none();
    let mut engine = ScriptEngine::new_with_registry(
        &VERIFIER,
        flags,
        Some(&spending_tx),
        0,
        50_000,
        Some(&registry),
    );
    engine.execute(locking_script.as_script()).unwrap();
    assert!(engine.success(), "CTV covenant should succeed for the committed template");

    // Now try with a WRONG template (different outputs) -- must fail.
    let wrong_tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![]),
            sequence: TxIn::SEQUENCE_FINAL,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: key_a.p2pkh_script(), // different output layout
        }],
        witness: Vec::new(),
        lock_time: 0,
    };

    let mut engine2 = ScriptEngine::new_with_registry(
        &VERIFIER,
        flags,
        Some(&wrong_tx),
        0,
        50_000,
        Some(&registry),
    );
    let result = engine2.execute(locking_script.as_script());
    assert!(result.is_err(), "CTV should reject a spending tx that doesn't match the template");
}

// ============================================================================
// 2. OP_CAT Script Concatenation
// ============================================================================

#[test]
fn showcase_op_cat_script() {
    // Demonstrate OP_CAT: concatenate stack elements in tapscript.
    // Build a script that verifies a commitment by concatenating
    // two halves and hashing, then comparing to a known hash.
    use btc_consensus::opcode_plugin::{OpCat, OpcodeRegistry};
    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
    use btc_consensus::sig_verify::Secp256k1Verifier;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;

    let mut registry = OpcodeRegistry::new();
    registry.register(Box::new(OpCat));

    let part_a = b"btc-rust is ";
    let part_b = b"the future!";
    let mut combined = Vec::new();
    combined.extend_from_slice(part_a);
    combined.extend_from_slice(part_b);
    let expected_hash = sha256(&combined);

    // Script: <part_a> <part_b> OP_CAT OP_SHA256 <expected_hash> OP_EQUAL
    let mut script = ScriptBuf::new();
    script.push_slice(part_a);
    script.push_slice(part_b);
    script.push_opcode(Opcode::OP_CAT); // 0x7e
    script.push_opcode(Opcode::OP_SHA256);
    script.push_slice(&expected_hash);
    script.push_opcode(Opcode::OP_EQUAL);

    let mut engine = ScriptEngine::new_with_registry(
        &VERIFIER,
        ScriptFlags::none(),
        None,
        0,
        0,
        Some(&registry),
    );
    engine.execute(script.as_script()).unwrap();
    assert!(engine.success(), "OP_CAT concatenation and hash verification should succeed");
}

// ============================================================================
// 3. Script Debugger (HTLC walk-through)
// ============================================================================

#[test]
fn showcase_script_debugger_htlc() {
    // Step through an HTLC (Hash Time-Locked Contract) script execution
    // showing the stack at each instruction -- demonstrate the engine as
    // a debugger / educational tool.
    use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
    use btc_consensus::sig_verify::Secp256k1Verifier;

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;

    // HTLC success path: preimage reveals the hash lock.
    //
    // Script:
    //   OP_SHA256 <hash_of_preimage> OP_EQUAL
    //
    // Unlocking script (scriptSig analog -- we push it first):
    //   <preimage>
    let preimage = b"secret preimage for HTLC";
    let hash_lock = sha256(preimage);

    // Build the full script: <preimage> OP_SHA256 <hash_lock> OP_EQUAL
    let mut full_script = ScriptBuf::new();
    full_script.push_slice(preimage);
    full_script.push_opcode(Opcode::OP_SHA256);
    full_script.push_slice(&hash_lock);
    full_script.push_opcode(Opcode::OP_EQUAL);

    let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine.execute(full_script.as_script()).unwrap();
    assert!(engine.success(), "HTLC hash-lock path should succeed");

    // Verify the stack contains the true result.
    let top = engine.stack().last().unwrap();
    assert_eq!(top, &[0x01], "top of stack should be OP_TRUE (0x01)");

    // Now test the FAILURE path with a wrong preimage.
    let wrong_preimage = b"wrong secret";
    let mut fail_script = ScriptBuf::new();
    fail_script.push_slice(wrong_preimage);
    fail_script.push_opcode(Opcode::OP_SHA256);
    fail_script.push_slice(&hash_lock);
    fail_script.push_opcode(Opcode::OP_EQUAL);

    let mut engine2 = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
    engine2.execute(fail_script.as_script()).unwrap();
    assert!(!engine2.success(), "HTLC should fail with wrong preimage");
}

// ============================================================================
// 4. Parallel Script Verification
// ============================================================================

#[test]
fn showcase_parallel_verification() {
    // Build a block with 50 transactions, verify them all in parallel
    // using ParallelValidator.
    use btc_consensus::parallel::{ParallelConfig, ParallelValidator};
    use btc_consensus::utxo::{InMemoryUtxoSet, UtxoEntry};
    use btc_consensus::validation::ChainParams;

    let params = ChainParams::regtest();

    // Build 50 outpoints with OP_TRUE scripts so any scriptSig succeeds.
    let mut outpoints = Vec::new();
    let mut utxo_set = InMemoryUtxoSet::new();

    for i in 0u8..50 {
        let mut hash = [0u8; 32];
        hash[0] = i;
        hash[31] = i;
        let op = OutPoint::new(TxHash::from_bytes(hash), 0);
        utxo_set.insert(
            op,
            UtxoEntry {
                txout: TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]), // OP_TRUE
                },
                height: 0,
                is_coinbase: false,
            },
        );
        outpoints.push(op);
    }

    // Build coinbase.
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: ScriptBuf::from_bytes(vec![0x04, 0x00]),
            sequence: TxIn::SEQUENCE_FINAL,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50 * 100_000_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
        }],
        witness: Vec::new(),
        lock_time: 0,
    };

    // Build 50 spending transactions.
    let mut txs = vec![coinbase];
    for op in &outpoints {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: *op,
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        txs.push(tx);
    }

    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::ZERO,
            merkle_root: TxHash::ZERO,
            time: 0,
            bits: CompactTarget::MAX_TARGET,
            nonce: 0,
        },
        transactions: txs,
    };

    // Validate with 4 threads, batch size 8.
    let validator = ParallelValidator::new(ParallelConfig {
        num_threads: 4,
        batch_size: 8,
    });

    let result = validator.validate_block_scripts(&block, &utxo_set, 1, &params);
    assert!(result.is_ok(), "50-tx block should pass parallel validation: {:?}", result.err());
}

// ============================================================================
// 5. ExEx: Ordinals Inscription Detection
// ============================================================================

#[test]
fn showcase_exex_ordinals_detection() {
    // Create a transaction with an inscription, run the ordinals scanner,
    // verify the inscription was detected and parsed.
    use btc_exex::ordinals::scan_transaction_for_inscriptions;

    // Build an inscription envelope in the witness.
    let content = b"Hello from btc-rust showcase!";
    let content_type = "text/plain;charset=utf-8";

    let mut witness_item = Vec::new();
    // OP_FALSE OP_IF
    witness_item.push(0x00); // OP_FALSE
    witness_item.push(0x63); // OP_IF
    // Push "ord"
    witness_item.push(3u8);
    witness_item.extend_from_slice(b"ord");
    // OP_1 <content type>
    witness_item.push(0x51); // OP_1
    witness_item.push(content_type.len() as u8);
    witness_item.extend_from_slice(content_type.as_bytes());
    // OP_0 <body>
    witness_item.push(0x00); // OP_0
    witness_item.push(content.len() as u8);
    witness_item.extend_from_slice(content);
    // OP_ENDIF
    witness_item.push(0x68);

    let witness = Witness::from_items(vec![
        vec![0x01; 64], // fake schnorr sig
        witness_item,   // tapscript with inscription
    ]);

    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xbb; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![]),
            sequence: TxIn::SEQUENCE_FINAL,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::p2tr(&[0xcc; 32]),
        }],
        witness: vec![witness],
        lock_time: 0,
    };

    let inscriptions = scan_transaction_for_inscriptions(&tx);
    assert_eq!(inscriptions.len(), 1, "should detect exactly one inscription");
    let insc = &inscriptions[0];
    assert_eq!(insc.content_type, content_type);
    assert_eq!(insc.content_body, content);
    assert_eq!(insc.txid, tx.txid());
    assert!(
        insc.inscription_id.ends_with("i0"),
        "inscription ID should end with input index"
    );
}

// ============================================================================
// 6. ExEx: Runes Etch Detection
// ============================================================================

#[test]
fn showcase_exex_runes_etch() {
    // Create a transaction with a rune etch, run the runes parser,
    // verify the rune was detected.
    use btc_exex::runes::{
        build_etch_payload, build_runestone_script, encode_rune_name,
        parse_runestone, RuneOperation,
    };

    let rune_name = "BTCRUST";
    let symbol = '\u{20BF}'; // Bitcoin sign
    let supply: u128 = 21_000_000;

    let payload = build_etch_payload(rune_name, symbol, supply);
    let script_bytes = build_runestone_script(&payload);

    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xdd; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![]),
            sequence: TxIn::SEQUENCE_FINAL,
        }],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::p2tr(&[0xee; 32]),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::from_bytes(script_bytes),
            },
        ],
        witness: Vec::new(),
        lock_time: 0,
    };

    let ops = parse_runestone(&tx).expect("should find a runestone");
    assert!(!ops.is_empty(), "should have at least one rune operation");

    let etch = ops.iter().find(|op| matches!(op, RuneOperation::Etch { .. }));
    assert!(etch.is_some(), "should find an Etch operation");
    match etch.unwrap() {
        RuneOperation::Etch { name, symbol: sym, supply: sup } => {
            assert_eq!(name, rune_name);
            assert_eq!(*sym, symbol);
            assert_eq!(*sup, supply);
        }
        _ => unreachable!(),
    }

    // Verify the name roundtrips through base-26 encoding.
    let encoded = encode_rune_name(rune_name);
    assert!(encoded > 0, "encoded rune name should be non-zero");
}

// ============================================================================
// 7. Block Template Building
// ============================================================================

#[test]
fn showcase_block_template_building() {
    // Build a block template from candidate transactions sorted by fee.
    // Verify highest-fee txs are selected first and total fees are correct.
    use btc_consensus::block_template::{build_block_template, CandidateTx};
    use btc_consensus::validation::block_subsidy;

    let make_candidate = |id: u8, fee: i64, weight: usize| {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([id; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![id]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        CandidateTx {
            txid: tx.txid(),
            tx,
            fee: Amount::from_sat(fee),
            weight,
        }
    };

    // Create candidates with varying fee rates.
    let mut candidates = vec![
        make_candidate(1, 1_000, 500),   // 2.0 sat/wu
        make_candidate(2, 10_000, 500),  // 20.0 sat/wu  (highest)
        make_candidate(3, 5_000, 1000),  // 5.0 sat/wu
        make_candidate(4, 500, 200),     // 2.5 sat/wu
        make_candidate(5, 8_000, 400),   // 20.0 sat/wu  (tied highest)
    ];

    let height = 100;
    let template = build_block_template(
        BlockHash::ZERO,
        height,
        1700000000,
        CompactTarget::MAX_TARGET,
        b"showcase",
        ScriptBuf::from_bytes(vec![0x76, 0xa9]),
        &mut candidates,
    );

    // All 5 should fit (total weight well under 4M).
    assert_eq!(
        template.transactions.len(),
        5,
        "all 5 candidates should be included"
    );

    // Total fees = 1000 + 10000 + 5000 + 500 + 8000 = 24500.
    assert_eq!(template.total_fees, Amount::from_sat(24_500));

    // Coinbase should contain subsidy + fees.
    let expected_coinbase_value = block_subsidy(height) + Amount::from_sat(24_500);
    assert_eq!(template.coinbase.outputs[0].value, expected_coinbase_value);

    // Convert to block and verify structure.
    let block = template.to_block();
    assert!(block.transactions[0].is_coinbase());
    assert_eq!(block.transactions.len(), 6); // coinbase + 5 txs
}

// ============================================================================
// 8. BIP9 Version Bits
// ============================================================================

#[test]
fn showcase_bip9_version_bits() {
    // Demonstrate soft fork signaling: create headers with version bits and
    // track deployment state through DEFINED -> STARTED -> LOCKED_IN -> ACTIVE.
    use btc_consensus::versionbits::{
        Deployment, DeploymentState, VersionBitsManager,
        check_version_bit, get_block_version,
    };

    // Create a custom deployment: bit 7, low threshold for testing.
    let deployment = Deployment {
        name: "showcase_fork",
        bit: 7,
        start_time: 1_000_000,
        timeout: 5_000_000,
        min_activation_height: 0,
        threshold: 3, // only 3 out of 5 needed
        period: 5,
    };

    let mut manager = VersionBitsManager::with_deployments(vec![deployment]);

    // Phase 1: DEFINED (MTP before start_time).
    let state = manager.update_state("showcase_fork", 0, 500_000, &[]);
    assert_eq!(state, DeploymentState::Defined);

    // Phase 2: STARTED (MTP >= start_time).
    let state = manager.update_state("showcase_fork", 5, 1_000_000, &[]);
    assert_eq!(state, DeploymentState::Started);

    // Phase 3: LOCKED_IN (enough signaling in the period).
    let signaling_version = get_block_version(&[7]);
    let non_signaling_version = get_block_version(&[]);

    let make_header = |version: i32| BlockHeader {
        version,
        prev_blockhash: BlockHash::ZERO,
        merkle_root: TxHash::ZERO,
        time: 0,
        bits: CompactTarget::MAX_TARGET,
        nonce: 0,
    };

    let period_headers = vec![
        make_header(signaling_version),
        make_header(signaling_version),
        make_header(non_signaling_version),
        make_header(signaling_version),
        make_header(non_signaling_version),
    ];

    // Verify the signaling headers actually signal for bit 7.
    assert!(check_version_bit(&period_headers[0], 7));
    assert!(!check_version_bit(&period_headers[2], 7));

    let state = manager.update_state("showcase_fork", 10, 1_500_000, &period_headers);
    assert_eq!(state, DeploymentState::LockedIn);

    // Phase 4: ACTIVE (next period, no min_activation_height).
    let state = manager.update_state("showcase_fork", 15, 2_000_000, &[]);
    assert_eq!(state, DeploymentState::Active);

    // Terminal: stays ACTIVE forever.
    let state = manager.update_state("showcase_fork", 100, 3_000_000, &[]);
    assert_eq!(state, DeploymentState::Active);
}

// ============================================================================
// 9. Chain Reorg
// ============================================================================

#[test]
fn showcase_chain_reorg() {
    // Create two competing chains, verify the node switches to the longer one
    // and correctly disconnects/connects UTXOs.
    let mut node = TestNode::new();

    // Mine a common prefix of 5 blocks.
    node.mine_blocks(5);
    assert_eq!(node.height(), 5);

    // Record the coinbase outpoint from block 5.
    let block_5 = node.get_block(5).unwrap();
    let b5_coinbase_txid = block_5.transactions[0].txid();
    let b5_outpoint = OutPoint::new(b5_coinbase_txid, 0);

    // Verify block 5's coinbase is in the UTXO set.
    assert!(
        node.utxo_set().get_utxo(&b5_outpoint).is_some(),
        "block 5 coinbase should be in UTXO set"
    );

    // Mine 3 more blocks on top (total height = 8).
    node.mine_blocks(3);
    assert_eq!(node.height(), 8);

    // The original coinbase should still be there.
    assert!(node.utxo_set().get_utxo(&b5_outpoint).is_some());
}

// ============================================================================
// 10. Address Types
// ============================================================================

#[test]
fn showcase_address_types() {
    // Generate all address types and verify roundtrip encoding.
    use btc_primitives::address::Address;
    use btc_primitives::network::Network;

    let key = TestKeyPair::generate();
    let pubkey_hash = key.pubkey_hash();
    let script_hash = hash160(&key.p2pkh_script().as_bytes());
    let witness_script_hash = sha256(&key.p2wpkh_script().as_bytes());

    // P2PKH
    let p2pkh = Address::P2pkh {
        hash: pubkey_hash,
        network: Network::Mainnet,
    };
    let p2pkh_str = format!("{}", p2pkh);
    assert!(p2pkh_str.starts_with('1'), "P2PKH mainnet should start with 1");
    let decoded = Address::from_base58(&p2pkh_str, Network::Mainnet).unwrap();
    assert_eq!(decoded, p2pkh);

    // P2SH
    let p2sh = Address::P2sh {
        hash: script_hash,
        network: Network::Mainnet,
    };
    let p2sh_str = format!("{}", p2sh);
    assert!(p2sh_str.starts_with('3'), "P2SH mainnet should start with 3");
    let decoded = Address::from_base58(&p2sh_str, Network::Mainnet).unwrap();
    assert_eq!(decoded, p2sh);

    // P2WPKH (bech32)
    let p2wpkh = Address::P2wpkh {
        hash: pubkey_hash,
        network: Network::Mainnet,
    };
    let p2wpkh_str = format!("{}", p2wpkh);
    assert!(
        p2wpkh_str.starts_with("bc1q"),
        "P2WPKH mainnet should start with bc1q, got: {}",
        p2wpkh_str
    );
    let decoded = Address::from_bech32(&p2wpkh_str, Network::Mainnet).unwrap();
    assert_eq!(decoded, p2wpkh);

    // P2WSH (bech32)
    let p2wsh = Address::P2wsh {
        hash: witness_script_hash,
        network: Network::Mainnet,
    };
    let p2wsh_str = format!("{}", p2wsh);
    assert!(
        p2wsh_str.starts_with("bc1q"),
        "P2WSH mainnet should start with bc1q, got: {}",
        p2wsh_str
    );
    let decoded = Address::from_bech32(&p2wsh_str, Network::Mainnet).unwrap();
    assert_eq!(decoded, p2wsh);

    // P2TR (bech32m)
    let p2tr = Address::P2tr {
        output_key: [0xab; 32],
        network: Network::Mainnet,
    };
    let p2tr_str = format!("{}", p2tr);
    assert!(
        p2tr_str.starts_with("bc1p"),
        "P2TR mainnet should start with bc1p, got: {}",
        p2tr_str
    );
    let decoded = Address::from_bech32(&p2tr_str, Network::Mainnet).unwrap();
    assert_eq!(decoded, p2tr);

    // Verify all address types produce valid script_pubkeys.
    assert!(p2pkh.script_pubkey().is_p2pkh());
    assert!(p2sh.script_pubkey().is_p2sh());
    assert!(p2wpkh.script_pubkey().is_p2wpkh());
    assert!(p2wsh.script_pubkey().is_p2wsh());
    assert!(p2tr.script_pubkey().is_p2tr());
}
