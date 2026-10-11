#![no_main]

use libfuzzer_sys::fuzz_target;
use std::panic;

use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
use btc_consensus::sig_verify::Secp256k1Verifier;
use btc_consensus::witness::verify_input_with_prevouts;
use btc_primitives::amount::Amount;
use btc_primitives::hash::{hash160, TxHash};
use btc_primitives::script::ScriptBuf;
use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness};

fuzz_target!(|data: &[u8]| {
    // Cap script size to Bitcoin's consensus limit (10 000 bytes) to keep
    // fuzzer iterations fast. The engine itself enforces this limit, but
    // skipping obviously-oversized inputs avoids spending time on them.
    if data.len() > 10_000 {
        return;
    }

    let script = ScriptBuf::from_bytes(data.to_vec());

    // --- Instruction iterator must not panic ---
    for _instr in script.as_script().instructions() {
        // Each instruction may return Ok or Err, both are fine.
    }

    // --- Classification helpers must not panic ---
    let _p2pkh = script.is_p2pkh();
    let _p2sh = script.is_p2sh();
    let _p2wpkh = script.is_p2wpkh();
    let _p2wsh = script.is_p2wsh();
    let _p2tr = script.is_p2tr();
    let _wp = script.is_witness_program();
    let _opr = script.is_op_return();

    // --- Script engine execution must NEVER panic ---
    // We use catch_unwind to turn any panic into a test failure that the
    // fuzzer will save as a crash artifact.
    let verifier = Secp256k1Verifier;
    let flags = ScriptFlags::none();
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let mut engine = ScriptEngine::new_without_tx(&verifier, flags);
        let _ = engine.execute(script.as_script());
        // Also exercise the production P2SH dispatcher. The raw engine alone
        // cannot detect missing script phases or stack-restoration panics.
        if data.len() >= 3 {
            let mask = data[0];
            let payload = &data[3..];
            let split = usize::from(u16::from_le_bytes([data[1], data[2]])).min(payload.len());
            let (arguments, redeem) = payload.split_at(split);
            let mut script_sig = ScriptBuf::from_bytes(arguments.to_vec());
            script_sig.push_slice(redeem);
            let previous = TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::p2sh(&hash160(redeem)),
            };
            let tx = Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([1; 32]), 0),
                    script_sig,
                    sequence: u32::MAX,
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(49_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
                witness: if mask & 4 != 0 {
                    vec![Witness::from_items(vec![arguments.to_vec()])]
                } else {
                    vec![]
                },
                lock_time: 0,
            };
            let mut flags = ScriptFlags::consensus();
            flags.verify_p2sh = mask & 1 != 0;
            flags.verify_witness = mask & 2 != 0;
            flags.verify_cleanstack = mask & 8 != 0;
            let _ = verify_input_with_prevouts(&tx, 0, &[previous], &verifier, &flags);
        }
    }));

    // A panic in the script engine is a real bug -- re-panic so the fuzzer
    // records it as a crash.
    if let Err(e) = result {
        panic::resume_unwind(e);
    }
});
