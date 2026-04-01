//! Build and execute Bitcoin scripts interactively.
//!
//! Usage: cargo run --example script_playground

use btc_primitives::script::{Opcode, ScriptBuf};
use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
use btc_consensus::sig_verify::Secp256k1Verifier;

fn main() {
    // Build: 2 + 3 == 5
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_3);
    script.push_opcode(Opcode::OP_ADD);
    script.push_opcode(Opcode::OP_5);
    script.push_opcode(Opcode::OP_EQUAL);

    let verifier = Secp256k1Verifier;
    let mut engine = ScriptEngine::new_without_tx(&verifier, ScriptFlags::none());
    let exec_result = engine.execute(script.as_script());

    println!("Script: {}", hex::encode(script.as_bytes()));
    println!("Execution: {:?}", exec_result);
    println!(
        "Result: {}",
        if engine.success() {
            "SUCCESS"
        } else {
            "FAILURE"
        }
    );
    println!("Final stack: {:?}", engine.stack());
}
