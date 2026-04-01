#![cfg(all(feature = "ordinals", feature = "runes"))]
//! Comprehensive integration tests for the ExEx (Execution Extensions) system.
//!
//! Tests cover the full pipeline: manager notification dispatch, extension
//! processing, and the specialized indexing plugins (Ordinals, Runes).

use btc_consensus::utxo::{UtxoEntry, UtxoSetUpdate};
use btc_exex::ordinals::{
    scan_transaction_for_inscriptions, OrdinalsExEx,
};
use btc_exex::runes::{
    build_etch_payload, build_mint_payload, build_runestone_script, build_transfer_payload,
    parse_runestone, RuneOperation, RunesExEx,
};
use btc_exex::{
    ExEx, ExExManager, ExExNotification, LoggingExEx, MetricsExEx,
};
use tokio::sync::broadcast;
use btc_primitives::amount::Amount;
use btc_primitives::block::{Block, BlockHeader};
use btc_primitives::compact::CompactTarget;
use btc_primitives::hash::{BlockHash, TxHash};
use btc_primitives::network::Network;
use btc_primitives::script::{Opcode, ScriptBuf};
use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build a minimal test block with a single coinbase transaction.
fn make_test_block() -> Block {
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: ScriptBuf::from_bytes(vec![0x04, 0x00]),
            sequence: TxIn::SEQUENCE_FINAL,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
        }],
        witness: Vec::new(),
        lock_time: 0,
    };

    Block {
        header: BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::ZERO,
            merkle_root: TxHash::ZERO,
            time: 1231006505,
            bits: CompactTarget::MAX_TARGET,
            nonce: 0,
        },
        transactions: vec![coinbase],
    }
}

/// Build a test block with specific transactions.
fn make_block_with_txs(txs: Vec<Transaction>, nonce: u32) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::ZERO,
            merkle_root: TxHash::ZERO,
            time: 1231006505 + nonce,
            bits: CompactTarget::MAX_TARGET,
            nonce,
        },
        transactions: txs,
    }
}

/// Build a test UtxoSetUpdate with the given counts of created/spent entries.
fn make_utxo_update(created_count: usize, spent_count: usize) -> UtxoSetUpdate {
    let make_entry = |i: u8| {
        (
            OutPoint::new(TxHash::from_bytes([i; 32]), 0),
            UtxoEntry {
                txout: TxOut {
                    value: Amount::from_sat(1000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00]),
                },
                height: 0,
                is_coinbase: false,
            },
        )
    };

    UtxoSetUpdate {
        created: (0..created_count as u8).map(make_entry).collect(),
        spent: (100..100 + spent_count as u8).map(make_entry).collect(),
    }
}

/// Build a witness item containing an inscription envelope.
fn make_inscription_witness_item(content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();

    // OP_FALSE OP_IF
    data.push(Opcode::OP_0 as u8);
    data.push(Opcode::OP_IF as u8);

    // Push "ord" (3 bytes)
    data.push(3u8);
    data.extend_from_slice(b"ord");

    // OP_1 (content type tag)
    data.push(Opcode::OP_1 as u8);

    // Push content type
    let ct_bytes = content_type.as_bytes();
    data.push(ct_bytes.len() as u8);
    data.extend_from_slice(ct_bytes);

    // OP_0 (body tag)
    data.push(Opcode::OP_0 as u8);

    // Push body
    if body.len() <= 75 {
        data.push(body.len() as u8);
        data.extend_from_slice(body);
    } else {
        data.push(Opcode::OP_PUSHDATA1 as u8);
        data.push(body.len() as u8);
        data.extend_from_slice(body);
    }

    // OP_ENDIF
    data.push(Opcode::OP_ENDIF as u8);

    data
}

/// Build a transaction with an inscription in the witness.
fn make_inscription_tx(content_type: &str, body: &[u8], id_byte: u8) -> Transaction {
    let witness_item = make_inscription_witness_item(content_type, body);
    let witness = Witness::from_items(vec![
        vec![0x01; 64], // fake signature
        witness_item,   // tapscript with inscription
    ]);

    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([id_byte; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![]),
            sequence: TxIn::SEQUENCE_FINAL,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::p2tr(&[0xaa; 32]),
        }],
        witness: vec![witness],
        lock_time: 0,
    }
}

/// Build a transaction with a runestone OP_RETURN output.
fn make_rune_tx(payload: &[u8], id_byte: u8) -> Transaction {
    let script_bytes = build_runestone_script(payload);
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([id_byte; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![]),
            sequence: TxIn::SEQUENCE_FINAL,
        }],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::p2tr(&[0xaa; 32]),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::from_bytes(script_bytes),
            },
        ],
        witness: Vec::new(),
        lock_time: 0,
    }
}

// ===========================================================================
// Part 2: Comprehensive ExEx integration tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Test: BlockCommitted flows to all extensions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_exex_block_committed_flows_to_all_extensions() {
    let manager = ExExManager::new(Network::Regtest);
    let mut ctx1 = manager.subscribe();
    let mut ctx2 = manager.subscribe();

    // Emit a BlockCommitted notification
    let block = make_test_block();
    let hash = block.block_hash();
    let utxo_changes = make_utxo_update(2, 1);

    manager.notify(ExExNotification::BlockCommitted {
        height: 1,
        hash,
        block: block.clone(),
        utxo_changes,
    });

    // Both subscribers should receive it
    let notif1 = ctx1.notifications.recv().await.unwrap();
    let notif2 = ctx2.notifications.recv().await.unwrap();

    // Verify contents for subscriber 1
    match &notif1 {
        ExExNotification::BlockCommitted {
            height,
            hash: recv_hash,
            block: recv_block,
            utxo_changes: recv_utxo,
        } => {
            assert_eq!(*height, 1);
            assert_eq!(*recv_hash, hash);
            assert_eq!(recv_block.transactions.len(), 1);
            assert_eq!(recv_utxo.created.len(), 2);
            assert_eq!(recv_utxo.spent.len(), 1);
        }
        _ => panic!("expected BlockCommitted for subscriber 1"),
    }

    // Verify contents for subscriber 2
    match &notif2 {
        ExExNotification::BlockCommitted {
            height,
            hash: recv_hash,
            ..
        } => {
            assert_eq!(*height, 1);
            assert_eq!(*recv_hash, hash);
        }
        _ => panic!("expected BlockCommitted for subscriber 2"),
    }
}

// ---------------------------------------------------------------------------
// Test: LoggingExEx processes all notification types
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_logging_exex_processes_all_notification_types() {
    let manager = ExExManager::new(Network::Regtest);
    let ctx = manager.subscribe();

    // Emit all three notification types
    let block = make_test_block();
    let hash = block.block_hash();
    let utxo_changes = make_utxo_update(1, 0);

    manager.notify(ExExNotification::BlockCommitted {
        height: 1,
        hash,
        block,
        utxo_changes,
    });

    manager.notify(ExExNotification::BlockReverted {
        height: 1,
        hash,
    });

    let old_tip = BlockHash::from_bytes([0x01; 32]);
    let new_tip = BlockHash::from_bytes([0x02; 32]);
    manager.notify(ExExNotification::ChainReorged {
        old_tip,
        new_tip,
        fork_height: 0,
        reverted: vec![hash],
        committed: vec![(1, new_tip)],
    });

    // Drop the manager to close the channel so the ExEx will exit
    drop(manager);

    // LoggingExEx should process all three and then exit cleanly
    let result = LoggingExEx.start(ctx).await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Test: MetricsExEx tracks chain height
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_metrics_exex_tracks_chain_height() {
    let manager = ExExManager::new(Network::Regtest);
    let ctx = manager.subscribe();

    // Emit blocks at increasing heights
    for height in 1..=10u64 {
        let block = make_test_block();
        let hash = block.block_hash();
        let utxo_changes = make_utxo_update(1, 0);
        manager.notify(ExExNotification::BlockCommitted {
            height,
            hash,
            block,
            utxo_changes,
        });
    }

    // Drop manager so the ExEx can finish
    drop(manager);

    // MetricsExEx should process all 10 blocks and then exit
    let result = MetricsExEx::new().start(ctx).await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Test: OrdinalsExEx detects inscription
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_ordinals_exex_detects_inscription() {
    let manager = ExExManager::new(Network::Regtest);
    let ctx = manager.subscribe();

    // Create a block with a fake inscription in taproot witness
    let inscription_tx = make_inscription_tx("text/plain", b"Hello Ordinals!", 0x10);

    // Verify the inscription can be detected at the transaction level
    let inscriptions = scan_transaction_for_inscriptions(&inscription_tx);
    assert_eq!(inscriptions.len(), 1);
    assert_eq!(inscriptions[0].content_type, "text/plain");
    assert_eq!(inscriptions[0].content_body, b"Hello Ordinals!");

    let block = make_block_with_txs(vec![inscription_tx], 42);
    let hash = block.block_hash();
    let utxo_changes = make_utxo_update(1, 0);

    manager.notify(ExExNotification::BlockCommitted {
        height: 1,
        hash,
        block,
        utxo_changes,
    });

    drop(manager);

    // Run OrdinalsExEx -- it processes the block with the inscription and exits
    let result = OrdinalsExEx::new().start(ctx).await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Test: RunesExEx detects etch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_runes_exex_detects_etch() {
    let manager = ExExManager::new(Network::Regtest);
    let ctx = manager.subscribe();

    // Create a block with an OP_RETURN rune etch
    let payload = build_etch_payload("TESTRUNE", '$', 21_000_000);
    let rune_tx = make_rune_tx(&payload, 0x20);

    // Verify the rune can be detected at the transaction level
    let ops = parse_runestone(&rune_tx).expect("should find runestone");
    assert_eq!(ops.len(), 1);
    match &ops[0] {
        RuneOperation::Etch {
            name,
            symbol,
            supply,
        } => {
            assert_eq!(name, "TESTRUNE");
            assert_eq!(*symbol, '$');
            assert_eq!(*supply, 21_000_000);
        }
        _ => panic!("expected Etch operation"),
    }

    let block = make_block_with_txs(vec![rune_tx], 99);
    let hash = block.block_hash();
    let utxo_changes = make_utxo_update(1, 0);

    manager.notify(ExExNotification::BlockCommitted {
        height: 1,
        hash,
        block,
        utxo_changes,
    });

    drop(manager);

    // Run RunesExEx -- it processes the block with the rune etch and exits
    let result = RunesExEx::new().start(ctx).await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Test: RunesExEx detects mint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_runes_exex_detects_mint() {
    let manager = ExExManager::new(Network::Regtest);
    let ctx = manager.subscribe();

    let payload = build_mint_payload(840000, 1);
    let rune_tx = make_rune_tx(&payload, 0x21);

    let ops = parse_runestone(&rune_tx).expect("should find runestone");
    assert_eq!(ops.len(), 1);
    match &ops[0] {
        RuneOperation::Mint { rune_id } => {
            assert_eq!(rune_id, "840000:1");
        }
        _ => panic!("expected Mint operation"),
    }

    let block = make_block_with_txs(vec![rune_tx], 100);
    let hash = block.block_hash();
    let utxo_changes = make_utxo_update(1, 0);

    manager.notify(ExExNotification::BlockCommitted {
        height: 1,
        hash,
        block,
        utxo_changes,
    });

    drop(manager);

    let result = RunesExEx::new().start(ctx).await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Test: RunesExEx detects transfer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_runes_exex_detects_transfer() {
    let manager = ExExManager::new(Network::Regtest);
    let ctx = manager.subscribe();

    let payload = build_transfer_payload(100, 5, 50000, 0);
    let rune_tx = make_rune_tx(&payload, 0x22);

    let ops = parse_runestone(&rune_tx).expect("should find runestone");
    assert_eq!(ops.len(), 1);
    match &ops[0] {
        RuneOperation::Transfer { rune_id, amount } => {
            assert_eq!(rune_id, "100:5");
            assert_eq!(*amount, 50000);
        }
        _ => panic!("expected Transfer operation"),
    }

    let block = make_block_with_txs(vec![rune_tx], 101);
    let hash = block.block_hash();
    let utxo_changes = make_utxo_update(1, 0);

    manager.notify(ExExNotification::BlockCommitted {
        height: 1,
        hash,
        block,
        utxo_changes,
    });

    drop(manager);

    let result = RunesExEx::new().start(ctx).await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Test: ExEx handles reorg notification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_exex_handles_reorg_notification() {
    let manager = ExExManager::new(Network::Regtest);
    let ctx_logging = manager.subscribe();
    let ctx_metrics = manager.subscribe();
    let ctx_ordinals = manager.subscribe();
    let ctx_runes = manager.subscribe();

    let old_tip = BlockHash::from_bytes([0x01; 32]);
    let new_tip = BlockHash::from_bytes([0x02; 32]);
    let reverted1 = BlockHash::from_bytes([0x03; 32]);
    let reverted2 = BlockHash::from_bytes([0x04; 32]);
    let committed1 = BlockHash::from_bytes([0x05; 32]);

    manager.notify(ExExNotification::ChainReorged {
        old_tip,
        new_tip,
        fork_height: 50,
        reverted: vec![reverted1, reverted2],
        committed: vec![(51, committed1), (52, new_tip)],
    });

    // Drop manager so all ExExes will exit after processing
    drop(manager);

    // All four ExExes should handle the reorg gracefully and exit
    let (r1, r2, r3, r4) = tokio::join!(
        LoggingExEx.start(ctx_logging),
        MetricsExEx::new().start(ctx_metrics),
        OrdinalsExEx::new().start(ctx_ordinals),
        RunesExEx::new().start(ctx_runes),
    );

    assert!(r1.is_ok(), "LoggingExEx failed on reorg");
    assert!(r2.is_ok(), "MetricsExEx failed on reorg");
    assert!(r3.is_ok(), "OrdinalsExEx failed on reorg");
    assert!(r4.is_ok(), "RunesExEx failed on reorg");
}

// ---------------------------------------------------------------------------
// Test: Multiple ExExes running concurrently
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_multiple_exex_concurrent() {
    let manager = ExExManager::new(Network::Regtest);

    let ctx_logging = manager.subscribe();
    let ctx_metrics = manager.subscribe();
    let ctx_ordinals = manager.subscribe();
    let ctx_runes = manager.subscribe();

    // Emit 100 blocks, some with inscriptions, some with runes
    for i in 0..100u64 {
        let mut txs = vec![];

        // Every 10th block: add an inscription
        if i % 10 == 0 {
            let inscription_tx = make_inscription_tx(
                "text/plain",
                format!("inscription #{}", i).as_bytes(),
                (i as u8).wrapping_add(1),
            );
            txs.push(inscription_tx);
        }

        // Every 15th block: add a rune etch
        if i % 15 == 0 {
            let name = format!("RUNE{}", i);
            let payload = build_etch_payload(&name, '#', (i as u128 + 1) * 1000);
            let rune_tx = make_rune_tx(&payload, (i as u8).wrapping_add(128));
            txs.push(rune_tx);
        }

        // Always add a coinbase
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, i as u8]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        txs.insert(0, coinbase);

        let block = make_block_with_txs(txs, i as u32);
        let hash = block.block_hash();
        let utxo_changes = make_utxo_update(1, 0);

        manager.notify(ExExNotification::BlockCommitted {
            height: i + 1,
            hash,
            block,
            utxo_changes,
        });
    }

    // Drop manager so all ExExes will exit
    drop(manager);

    // Run all four ExExes concurrently
    let (r1, r2, r3, r4) = tokio::join!(
        LoggingExEx.start(ctx_logging),
        MetricsExEx::new().start(ctx_metrics),
        OrdinalsExEx::new().start(ctx_ordinals),
        RunesExEx::new().start(ctx_runes),
    );

    assert!(r1.is_ok(), "LoggingExEx failed during concurrent test");
    assert!(r2.is_ok(), "MetricsExEx failed during concurrent test");
    assert!(r3.is_ok(), "OrdinalsExEx failed during concurrent test");
    assert!(r4.is_ok(), "RunesExEx failed during concurrent test");
}

// ---------------------------------------------------------------------------
// Test: Multiple subscribers receive BlockReverted
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_block_reverted_flows_to_all_subscribers() {
    let manager = ExExManager::new(Network::Regtest);
    let mut ctx1 = manager.subscribe();
    let mut ctx2 = manager.subscribe();
    let mut ctx3 = manager.subscribe();

    let hash = BlockHash::from_bytes([0xbb; 32]);
    manager.notify(ExExNotification::BlockReverted {
        height: 42,
        hash,
    });

    for ctx in [&mut ctx1, &mut ctx2, &mut ctx3] {
        let notif = ctx.notifications.recv().await.unwrap();
        match notif {
            ExExNotification::BlockReverted {
                height,
                hash: recv_hash,
            } => {
                assert_eq!(height, 42);
                assert_eq!(recv_hash, hash);
            }
            _ => panic!("expected BlockReverted"),
        }
    }
}

// ---------------------------------------------------------------------------
// Test: ExEx manager register and list
// ---------------------------------------------------------------------------

#[test]
fn test_exex_manager_register_all_plugins() {
    let mut manager = ExExManager::new(Network::Regtest);

    manager.register("logging");
    manager.register("metrics");
    manager.register("ordinals");
    manager.register("runes");

    let ext = manager.registered_extensions();
    assert_eq!(ext.len(), 4);
    assert_eq!(ext[0], "logging");
    assert_eq!(ext[1], "metrics");
    assert_eq!(ext[2], "ordinals");
    assert_eq!(ext[3], "runes");
}

// ---------------------------------------------------------------------------
// Test: ExEx names are correct
// ---------------------------------------------------------------------------

#[test]
fn test_all_exex_names() {
    assert_eq!(LoggingExEx.name(), "logging");
    assert_eq!(MetricsExEx::new().name(), "metrics");
    assert_eq!(OrdinalsExEx::new().name(), "ordinals");
    assert_eq!(RunesExEx::new().name(), "runes");
}

// ---------------------------------------------------------------------------
// Test: Inscription scanning - multiple inscriptions in one block
// ---------------------------------------------------------------------------

#[test]
fn test_multiple_inscriptions_in_block() {
    let tx1 = make_inscription_tx("text/plain", b"first", 0x30);
    let tx2 = make_inscription_tx("image/png", &[0x89, 0x50, 0x4E, 0x47], 0x31);
    let tx3 = make_inscription_tx("text/html", b"<h1>hi</h1>", 0x32);

    let i1 = scan_transaction_for_inscriptions(&tx1);
    let i2 = scan_transaction_for_inscriptions(&tx2);
    let i3 = scan_transaction_for_inscriptions(&tx3);

    assert_eq!(i1.len(), 1);
    assert_eq!(i2.len(), 1);
    assert_eq!(i3.len(), 1);
    assert_eq!(i1[0].content_type, "text/plain");
    assert_eq!(i2[0].content_type, "image/png");
    assert_eq!(i3[0].content_type, "text/html");
}

// ---------------------------------------------------------------------------
// Test: Rune parsing - multiple rune txs in one block
// ---------------------------------------------------------------------------

#[test]
fn test_multiple_rune_txs_in_block() {
    let etch_payload = build_etch_payload("ALPHA", 'A', 1000);
    let mint_payload = build_mint_payload(100, 0);
    let transfer_payload = build_transfer_payload(100, 0, 500, 1);

    let tx1 = make_rune_tx(&etch_payload, 0x40);
    let tx2 = make_rune_tx(&mint_payload, 0x41);
    let tx3 = make_rune_tx(&transfer_payload, 0x42);

    let ops1 = parse_runestone(&tx1).expect("should find etch");
    let ops2 = parse_runestone(&tx2).expect("should find mint");
    let ops3 = parse_runestone(&tx3).expect("should find transfer");

    assert_eq!(ops1.len(), 1);
    assert!(matches!(&ops1[0], RuneOperation::Etch { name, .. } if name == "ALPHA"));

    assert_eq!(ops2.len(), 1);
    assert!(matches!(&ops2[0], RuneOperation::Mint { rune_id } if rune_id == "100:0"));

    assert_eq!(ops3.len(), 1);
    assert!(matches!(&ops3[0], RuneOperation::Transfer { rune_id, amount } if rune_id == "100:0" && *amount == 500));
}

// ---------------------------------------------------------------------------
// Test: Mixed block with both inscriptions and runes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mixed_block_inscriptions_and_runes() {
    let manager = ExExManager::new(Network::Regtest);
    let ctx_ordinals = manager.subscribe();
    let ctx_runes = manager.subscribe();

    // Create a block with both an inscription tx and a rune tx
    let inscription_tx = make_inscription_tx("text/plain", b"Ordinals!", 0x50);
    let rune_payload = build_etch_payload("MIXED", 'M', 5000);
    let rune_tx = make_rune_tx(&rune_payload, 0x51);

    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: ScriptBuf::from_bytes(vec![0x04, 0x00]),
            sequence: TxIn::SEQUENCE_FINAL,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
        }],
        witness: Vec::new(),
        lock_time: 0,
    };

    let block = make_block_with_txs(vec![coinbase, inscription_tx, rune_tx], 77);
    let hash = block.block_hash();
    let utxo_changes = make_utxo_update(3, 0);

    manager.notify(ExExNotification::BlockCommitted {
        height: 1,
        hash,
        block,
        utxo_changes,
    });

    drop(manager);

    let (r1, r2) = tokio::join!(
        OrdinalsExEx::new().start(ctx_ordinals),
        RunesExEx::new().start(ctx_runes),
    );

    assert!(r1.is_ok(), "OrdinalsExEx failed on mixed block");
    assert!(r2.is_ok(), "RunesExEx failed on mixed block");
}

// ---------------------------------------------------------------------------
// Test: Sequence of commits then revert
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_commit_then_revert_sequence() {
    let manager = ExExManager::new(Network::Regtest);
    let mut ctx = manager.subscribe();

    // Commit 5 blocks
    for height in 1..=5u64 {
        let block = make_test_block();
        let hash = block.block_hash();
        let utxo = make_utxo_update(1, 0);
        manager.notify(ExExNotification::BlockCommitted {
            height,
            hash,
            block,
            utxo_changes: utxo,
        });
    }

    // Revert 2 blocks
    for height in [5u64, 4] {
        manager.notify(ExExNotification::BlockReverted {
            height,
            hash: BlockHash::from_bytes([height as u8; 32]),
        });
    }

    // Verify we receive all 7 notifications in order
    for i in 0..7 {
        let notif = ctx.notifications.recv().await.unwrap();
        if i < 5 {
            assert!(matches!(notif, ExExNotification::BlockCommitted { .. }));
        } else {
            assert!(matches!(notif, ExExNotification::BlockReverted { .. }));
        }
    }
}

// ===========================================================================
// Part 3: ExEx stress tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Test: ExEx handles 1000 blocks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_exex_handles_1000_blocks() {
    let manager = ExExManager::new(Network::Regtest);
    let ctx = manager.subscribe();

    // Emit 1000 BlockCommitted notifications rapidly
    for height in 1..=1000u64 {
        let block = make_test_block();
        let hash = block.block_hash();
        let utxo_changes = make_utxo_update(1, 0);
        manager.notify(ExExNotification::BlockCommitted {
            height,
            hash,
            block,
            utxo_changes,
        });
    }

    // Drop manager so the ExEx can finish
    drop(manager);

    // MetricsExEx should process all 1000 blocks
    let result = MetricsExEx::new().start(ctx).await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Test: Slow consumer does not block producer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_exex_slow_consumer_doesnt_block_producer() {
    // Use a small capacity to make it easier to overflow
    let manager = ExExManager::with_capacity(Network::Regtest, 16);

    // Subscribe but intentionally do NOT read
    let _ctx_slow = manager.subscribe();

    // Also subscribe a fast consumer to verify messages are sent
    let mut ctx_fast = manager.subscribe();

    // Emit more notifications than the channel capacity
    // The broadcast channel should handle this by lagging the slow consumer,
    // not by blocking the producer.
    for height in 1..=50u64 {
        let block = make_test_block();
        let hash = block.block_hash();
        let utxo_changes = make_utxo_update(1, 0);
        manager.notify(ExExNotification::BlockCommitted {
            height,
            hash,
            block,
            utxo_changes,
        });
    }

    // The fast consumer might have received some or all (broadcast doesn't block
    // the sender). We verify the manager did not panic or deadlock by reaching
    // this point.

    // Try to receive from the fast consumer - it may get a Lagged error
    // for the oldest messages but should still work
    let mut received_count = 0u64;
    let mut lagged = false;
    loop {
        match ctx_fast.notifications.try_recv() {
            Ok(_) => received_count += 1,
            Err(broadcast::error::TryRecvError::Lagged(n)) => {
                lagged = true;
                // After lagging, we can continue receiving
                received_count += n;
            }
            Err(broadcast::error::TryRecvError::Empty) => break,
            Err(broadcast::error::TryRecvError::Closed) => break,
        }
    }

    // We should have received some notifications (or lagged past some)
    assert!(
        received_count > 0 || lagged,
        "fast consumer should have received something"
    );

    // The key assertion: we reached this point without blocking, which proves
    // the producer was not blocked by the slow consumer.
}

// ---------------------------------------------------------------------------
// Test: 1000 blocks with all four ExExes running concurrently
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_exex_1000_blocks_all_concurrent() {
    let manager = ExExManager::new(Network::Regtest);
    let ctx_logging = manager.subscribe();
    let ctx_metrics = manager.subscribe();
    let ctx_ordinals = manager.subscribe();
    let ctx_runes = manager.subscribe();

    // Emit 1000 blocks
    for height in 1..=1000u64 {
        let block = make_test_block();
        let hash = block.block_hash();
        let utxo_changes = make_utxo_update(1, 0);
        manager.notify(ExExNotification::BlockCommitted {
            height,
            hash,
            block,
            utxo_changes,
        });
    }

    drop(manager);

    let (r1, r2, r3, r4) = tokio::join!(
        LoggingExEx.start(ctx_logging),
        MetricsExEx::new().start(ctx_metrics),
        OrdinalsExEx::new().start(ctx_ordinals),
        RunesExEx::new().start(ctx_runes),
    );

    assert!(r1.is_ok());
    assert!(r2.is_ok());
    assert!(r3.is_ok());
    assert!(r4.is_ok());
}

// ---------------------------------------------------------------------------
// Test: Rapid reorgs don't crash extensions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_rapid_reorgs_dont_crash() {
    let manager = ExExManager::new(Network::Regtest);
    let ctx = manager.subscribe();

    // Emit 100 reorg notifications rapidly
    for i in 0..100u64 {
        let old_tip = BlockHash::from_bytes([(i & 0xFF) as u8; 32]);
        let new_tip = BlockHash::from_bytes([((i + 1) & 0xFF) as u8; 32]);
        manager.notify(ExExNotification::ChainReorged {
            old_tip,
            new_tip,
            fork_height: i.saturating_sub(1),
            reverted: vec![old_tip],
            committed: vec![(i + 1, new_tip)],
        });
    }

    drop(manager);

    let result = MetricsExEx::new().start(ctx).await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Test: Empty blocks are handled gracefully
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_empty_blocks_handled() {
    let manager = ExExManager::new(Network::Regtest);
    let ctx_ordinals = manager.subscribe();
    let ctx_runes = manager.subscribe();

    // Emit blocks with no transactions (unusual but shouldn't crash)
    for height in 1..=10u64 {
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::ZERO,
                time: 1231006505 + height as u32,
                bits: CompactTarget::MAX_TARGET,
                nonce: height as u32,
            },
            transactions: vec![],
        };
        let hash = block.block_hash();
        let utxo_changes = make_utxo_update(0, 0);
        manager.notify(ExExNotification::BlockCommitted {
            height,
            hash,
            block,
            utxo_changes,
        });
    }

    drop(manager);

    let (r1, r2) = tokio::join!(
        OrdinalsExEx::new().start(ctx_ordinals),
        RunesExEx::new().start(ctx_runes),
    );

    assert!(r1.is_ok(), "OrdinalsExEx should handle empty blocks");
    assert!(r2.is_ok(), "RunesExEx should handle empty blocks");
}

// ---------------------------------------------------------------------------
// Test: Network parameter is propagated correctly
// ---------------------------------------------------------------------------

#[test]
fn test_network_propagation() {
    for network in [
        Network::Mainnet,
        Network::Testnet,
        Network::Signet,
        Network::Regtest,
    ] {
        let manager = ExExManager::new(network);
        let ctx = manager.subscribe();
        assert_eq!(ctx.network, network);
    }
}

// ---------------------------------------------------------------------------
// Test: Subscribe after notifications already sent
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_late_subscriber_misses_earlier_notifications() {
    let manager = ExExManager::new(Network::Regtest);

    // Emit a block BEFORE subscribing
    let block = make_test_block();
    let hash = block.block_hash();
    let utxo_changes = make_utxo_update(1, 0);
    manager.notify(ExExNotification::BlockCommitted {
        height: 1,
        hash,
        block: block.clone(),
        utxo_changes,
    });

    // Now subscribe
    let mut ctx = manager.subscribe();

    // Emit another block
    let utxo_changes2 = make_utxo_update(1, 0);
    manager.notify(ExExNotification::BlockCommitted {
        height: 2,
        hash,
        block,
        utxo_changes: utxo_changes2,
    });

    // The subscriber should only see height=2
    let notif = ctx.notifications.recv().await.unwrap();
    match notif {
        ExExNotification::BlockCommitted { height, .. } => {
            assert_eq!(height, 2, "late subscriber should only see block 2");
        }
        _ => panic!("expected BlockCommitted"),
    }
}
