#![no_main]

use libfuzzer_sys::fuzz_target;
use std::panic;

use btc_primitives::amount::Amount;
use btc_primitives::compact::CompactTarget;
use btc_primitives::hash::{BlockHash, TxHash};
use btc_primitives::script::ScriptBuf;
use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use btc_consensus::block_template::{build_block_template, CandidateTx};

fuzz_target!(|data: &[u8]| {
    // Build random candidate transactions from the fuzz input.
    // Each candidate is encoded as:
    //   [0] = id byte (makes txid unique)
    //   [1..4] = fee in satoshis (u24, to keep values reasonable)
    //   [4..6] = weight (u16)
    // So each candidate needs 6 bytes.
    if data.len() < 6 {
        return;
    }

    let num_candidates = data.len() / 6;
    // Cap to avoid excessive computation
    let num_candidates = num_candidates.min(200);

    let mut candidates: Vec<CandidateTx> = Vec::with_capacity(num_candidates);

    for i in 0..num_candidates {
        let chunk = &data[i * 6..(i + 1) * 6];
        let id_byte = chunk[0];
        let fee = u32::from_le_bytes([chunk[1], chunk[2], chunk[3], 0]);
        let weight = u16::from_le_bytes([chunk[4], chunk[5]]) as usize;

        // Skip zero-weight candidates (would cause div-by-zero in fee rate)
        if weight == 0 {
            continue;
        }

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(
                    TxHash::from_bytes({
                        let mut h = [0u8; 32];
                        h[0] = id_byte;
                        h[1] = i as u8;
                        h
                    }),
                    0,
                ),
                script_sig: ScriptBuf::from_bytes(vec![id_byte]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        candidates.push(CandidateTx {
            txid: tx.txid(),
            tx,
            fee: Amount::from_sat(fee as i64),
            weight,
        });
    }

    // build_block_template must NEVER panic.
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let template = build_block_template(
            BlockHash::ZERO,
            100,
            1700000000,
            CompactTarget::MAX_TARGET,
            b"fuzz",
            ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            &mut candidates,
        );

        // Basic sanity: coinbase should be valid
        assert!(template.coinbase.is_coinbase());

        // Total weight should not exceed the block limit
        assert!(template.total_weight <= 4_000_000);

        // to_block should not panic
        let _block = template.to_block();
    }));

    if let Err(e) = result {
        panic::resume_unwind(e);
    }
});
