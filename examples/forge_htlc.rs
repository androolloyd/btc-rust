//! Build and test a Hash Time-Locked Contract using btc-forge.
//!
//! Usage: cargo run --example forge_htlc

use btc_forge::{ForgeScript, ScriptDebugger, ScriptEnv, analyze_script};
use btc_primitives::hash::sha256;

fn main() {
    let mut env = ScriptEnv::new();
    let _ = env.new_named_account("alice");
    let _ = env.new_named_account("bob");

    // Access accounts by index after creation to avoid borrow issues.
    let alice_pubkey = env.account(0).keypair.public_key.serialize();
    let bob_pubkey = env.account(1).keypair.public_key.serialize();

    let preimage = b"secret_preimage_12345678";
    let hash = sha256(preimage);

    let htlc = ForgeScript::htlc(
        &bob_pubkey,   // receiver
        &alice_pubkey, // sender (refund path)
        &hash,
        100,
    )
    .build();

    let analysis = analyze_script(htlc.as_script());
    println!("HTLC Script:");
    println!("  Size: {} bytes", analysis.size_bytes);
    println!("  Opcodes: {}", analysis.op_count);
    println!("  Sigops: {}", analysis.sigop_count);
    println!("  Has signature ops: {}", analysis.has_signature_ops);
    println!("  Max stack depth: {}", analysis.max_stack_depth);
    println!("  Branches: {}", analysis.branches.len());
    for (i, branch) in analysis.branches.iter().enumerate() {
        println!("    Branch {}: {} ({} ops)", i, branch.condition, branch.ops.len());
    }
    println!("  Hex: {}", hex::encode(htlc.as_bytes()));

    // Debug step through
    let mut debugger = ScriptDebugger::new(htlc.as_script());
    let trace = debugger.run();
    println!("\nExecution trace ({} steps):", trace.len());
    for step in &trace {
        println!("  PC:{:3}  {:?}", step.pc, step.opcode);
    }
}
