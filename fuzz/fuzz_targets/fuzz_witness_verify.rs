#![no_main]

use libfuzzer_sys::fuzz_target;
use std::panic;

use btc_primitives::amount::Amount;
use btc_primitives::hash::TxHash;
use btc_primitives::script::ScriptBuf;
use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness};
use btc_consensus::script_engine::ScriptFlags;
use btc_consensus::sig_verify::Secp256k1Verifier;
use btc_consensus::witness::{verify_witness_program, verify_input};

fuzz_target!(|data: &[u8]| {
    // We need at least a few bytes to construct meaningful inputs:
    // [0]    = witness version (0-16)
    // [1]    = program length (bounded)
    // [2..N] = program bytes
    // rest   = witness item bytes
    if data.len() < 4 {
        return;
    }

    let version = data[0] % 17; // 0-16
    let prog_len = (data[1] as usize) % 33; // max 32 bytes for program
    if data.len() < 2 + prog_len + 1 {
        return;
    }
    let program = &data[2..2 + prog_len];
    let witness_data = &data[2 + prog_len..];

    // Split witness_data into items: first byte is count (max 4), then
    // each item is prefixed by its length byte (max 75).
    let num_items = (witness_data[0] % 5) as usize;
    let mut items: Vec<Vec<u8>> = Vec::new();
    let mut pos = 1;
    for _ in 0..num_items {
        if pos >= witness_data.len() {
            break;
        }
        let item_len = (witness_data[pos] as usize).min(witness_data.len() - pos - 1).min(75);
        pos += 1;
        if pos + item_len > witness_data.len() {
            break;
        }
        items.push(witness_data[pos..pos + item_len].to_vec());
        pos += item_len;
    }

    let witness = Witness::from_items(items);

    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![]),
            sequence: 0xffffffff,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
        }],
        witness: vec![witness.clone()],
        lock_time: 0,
    };

    let verifier = Secp256k1Verifier;
    let flags = ScriptFlags::all();

    // verify_witness_program must NEVER panic, regardless of inputs.
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let _ = verify_witness_program(
            version,
            program,
            &witness,
            &tx,
            0,
            50_000,
            &verifier,
            &flags,
        );
    }));
    if let Err(e) = result {
        panic::resume_unwind(e);
    }

    // Also fuzz verify_input with various scriptPubKey types.
    // Build a scriptPubKey from the version and program (native segwit format).
    if prog_len >= 2 && prog_len <= 40 {
        let version_opcode = if version == 0 { 0x00 } else { 0x50 + version };
        let mut spk = vec![version_opcode, prog_len as u8];
        spk.extend_from_slice(program);
        let prev_output = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(spk),
        };

        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let _ = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        }));
        if let Err(e) = result {
            panic::resume_unwind(e);
        }
    }
});
