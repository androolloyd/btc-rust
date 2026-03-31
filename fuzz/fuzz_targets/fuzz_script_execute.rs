#![no_main]

use libfuzzer_sys::fuzz_target;
use std::panic;

use btc_primitives::script::ScriptBuf;
use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
use btc_consensus::sig_verify::Secp256k1Verifier;

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
    }));

    // A panic in the script engine is a real bug -- re-panic so the fuzzer
    // records it as a crash.
    if let Err(e) = result {
        panic::resume_unwind(e);
    }
});
