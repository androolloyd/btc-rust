use btc_consensus::{
    utxo::{connect_block, disconnect_block, InMemoryUtxoSet, UtxoEntry, UtxoSet},
    validation::{BlockValidator, ValidationError},
};
use btc_primitives::{
    amount::Amount,
    block::{merkle_root, Block, BlockHeader},
    compact::CompactTarget,
    hash::{sha256d, BlockHash, TxHash},
    script::ScriptBuf,
    transaction::{OutPoint, Transaction, TxIn, TxOut, Witness},
};
fn tx(op: OutPoint, value: i64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::from_bytes(vec![1, 1]),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
        witness: vec![],
        lock_time: 0,
    }
}
fn block(txs: Vec<Transaction>) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::ZERO,
            merkle_root: TxHash::ZERO,
            time: 0,
            bits: CompactTarget::MAX_TARGET,
            nonce: 0,
        },
        transactions: txs,
    }
}
#[test]
fn duplicate_inputs_and_cross_transaction_double_spends_are_rejected() {
    let op = OutPoint::new(TxHash::from_bytes([1; 32]), 0);
    let mut set = InMemoryUtxoSet::new();
    set.insert(
        op,
        UtxoEntry {
            txout: tx(op, 10).outputs[0].clone(),
            height: 0,
            is_coinbase: false,
        },
    );
    let mut duplicate = tx(op, 15);
    duplicate.inputs.push(duplicate.inputs[0].clone());
    assert!(connect_block(&block(vec![tx(OutPoint::COINBASE, 0), duplicate]), 1, &set).is_err());
    assert!(connect_block(
        &block(vec![tx(OutPoint::COINBASE, 0), tx(op, 5), tx(op, 4)]),
        1,
        &set
    )
    .is_err());
}
#[test]
fn same_block_spends_are_absent_after_connect_and_disconnect() {
    let op = OutPoint::new(TxHash::from_bytes([1; 32]), 0);
    let mut set = InMemoryUtxoSet::new();
    let entry = UtxoEntry {
        txout: tx(op, 10).outputs[0].clone(),
        height: 0,
        is_coinbase: false,
    };
    set.insert(op, entry.clone());
    let parent = tx(op, 9);
    let internal = OutPoint::new(parent.txid(), 0);
    let child = tx(internal, 8);
    let child_op = OutPoint::new(child.txid(), 0);
    let update = connect_block(
        &block(vec![tx(OutPoint::COINBASE, 0), parent, child]),
        1,
        &set,
    )
    .unwrap();
    set.apply_update(&update);
    assert!(!set.contains(&op));
    assert!(!set.contains(&internal));
    assert!(set.contains(&child_op));
    disconnect_block(&mut set, &update);
    assert_eq!(set.get_utxo(&op), Some(entry));
    assert!(!set.contains(&internal));
    assert!(!set.contains(&child_op));
}
fn committed_block() -> Block {
    let mut coinbase = tx(OutPoint::COINBASE, 0);
    coinbase.witness = vec![Witness::from_items(vec![vec![0; 32]])];
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    let mut preimage = merkle_root(&[[0; 32]]).to_vec();
    preimage.extend([0; 32]);
    script.extend(sha256d(&preimage));
    coinbase.outputs[0].script_pubkey = ScriptBuf::from_bytes(script);
    block(vec![coinbase])
}
#[test]
fn commitments_are_checked_without_non_coinbase_witness() {
    let mut b = committed_block();
    assert!(BlockValidator::verify_witness_commitment(&b).is_ok());
    let mut script = b.transactions[0].outputs[0]
        .script_pubkey
        .as_bytes()
        .to_vec();
    script[6] ^= 1;
    b.transactions[0].outputs[0].script_pubkey = ScriptBuf::from_bytes(script);
    assert!(matches!(
        BlockValidator::verify_witness_commitment(&b),
        Err(ValidationError::WitnessCommitmentMismatch)
    ));
}
#[test]
fn witness_reserved_value_is_mandatory_and_exactly_one_item() {
    for items in [vec![], vec![vec![0; 31]], vec![vec![0; 32], vec![]]] {
        let mut b = committed_block();
        b.transactions[0].witness = vec![Witness::from_items(items)];
        assert!(matches!(
            BlockValidator::verify_witness_commitment(&b),
            Err(ValidationError::InvalidWitnessReservedValue)
        ));
    }
    let mut b = committed_block();
    b.transactions[0].outputs[0].script_pubkey = ScriptBuf::new();
    assert!(matches!(
        BlockValidator::verify_witness_commitment(&b),
        Err(ValidationError::MissingWitnessCommitment)
    ));
}
#[test]
fn taproot_signatures_commit_to_all_prevouts() {
    use btc_consensus::{
        script_engine::ScriptFlags, sig_verify::Secp256k1Verifier, sighash::sighash_taproot,
        witness::verify_input_with_prevouts,
    };
    use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7; 32]).unwrap());
    let key = keypair.x_only_public_key().0.serialize();
    let prevout = TxOut {
        value: Amount::from_sat(100),
        script_pubkey: ScriptBuf::p2tr(&key),
    };
    let mut spending = tx(OutPoint::new(TxHash::from_bytes([4; 32]), 0), 150);
    spending.inputs.push(TxIn {
        previous_output: OutPoint::new(TxHash::from_bytes([5; 32]), 0),
        script_sig: ScriptBuf::new(),
        sequence: u32::MAX,
    });
    spending.inputs[0].script_sig = ScriptBuf::new();
    let prevouts = vec![prevout.clone(), prevout];
    let flags = ScriptFlags::consensus();
    spending.witness = vec![Witness::from_items(vec![vec![0; 64]]), Witness::new()];
    assert!(
        verify_input_with_prevouts(&spending, 0, &prevouts, &Secp256k1Verifier, &flags).is_err()
    );
    let hash = sighash_taproot(
        &spending,
        0,
        &prevouts,
        btc_consensus::sighash::SighashType(0),
        None,
        None,
    )
    .unwrap();
    let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(hash), &keypair);
    spending.witness[0] = Witness::from_items(vec![signature.as_ref().to_vec()]);
    assert!(
        verify_input_with_prevouts(&spending, 0, &prevouts, &Secp256k1Verifier, &flags).is_ok()
    );
    let mut wrong = prevouts;
    wrong[1].value = Amount::from_sat(99);
    assert!(verify_input_with_prevouts(&spending, 0, &wrong, &Secp256k1Verifier, &flags).is_err());
}
#[test]
fn time_locks_use_ancestor_median_time_and_exact_boundary() {
    use btc_consensus::{
        utxo::{connect_block_with_context, LockTimeContext, SEQUENCE_LOCKTIME_TYPE_FLAG},
        validation::ChainParams,
    };
    let op = OutPoint::new(TxHash::from_bytes([8; 32]), 0);
    let mut set = InMemoryUtxoSet::new();
    set.insert(
        op,
        UtxoEntry {
            txout: tx(op, 100).outputs[0].clone(),
            height: 5,
            is_coinbase: false,
        },
    );
    let mut spending = tx(op, 99);
    spending.version = 2;
    spending.inputs[0].sequence = SEQUENCE_LOCKTIME_TYPE_FLAG | 1;
    let b = block(vec![tx(OutPoint::COINBASE, 0), spending]);
    let mut params = ChainParams::regtest();
    params.bip34_height = u64::MAX;
    let ancestor = |height| {
        assert_eq!(height, 4);
        Some(1000)
    };
    let before = LockTimeContext {
        median_time_past: 1511,
        ancestor_mtp: &ancestor,
    };
    assert!(connect_block_with_context(&b, 6, &set, &params, Some(&before)).is_err());
    let boundary = LockTimeContext {
        median_time_past: 1512,
        ancestor_mtp: &ancestor,
    };
    assert!(connect_block_with_context(&b, 6, &set, &params, Some(&boundary)).is_ok());
}
#[test]
fn invalid_amounts_cannot_overflow_or_create_money() {
    let op = OutPoint::new(TxHash::from_bytes([1; 32]), 0);
    let mut set = InMemoryUtxoSet::new();
    set.insert(
        op,
        UtxoEntry {
            txout: tx(op, 10).outputs[0].clone(),
            height: 0,
            is_coinbase: false,
        },
    );
    for amount in [-1, i64::MAX] {
        assert!(connect_block(
            &block(vec![tx(OutPoint::COINBASE, 0), tx(op, amount)]),
            1,
            &set
        )
        .is_err());
    }
}
