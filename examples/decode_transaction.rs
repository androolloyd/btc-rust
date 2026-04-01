//! Decode a raw Bitcoin transaction and print its structure.
//!
//! Usage: cargo run --example decode_transaction -- <hex>

use btc_primitives::{Transaction, decode};

fn main() {
    let hex_str = std::env::args().nth(1).unwrap_or_else(|| {
        // Default: the genesis coinbase
        "01000000010000000000000000000000000000000000000000000000000000000000000000\
         ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368\
         616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420\
         666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a6\
         7130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c\
         384df7ba0b8d578a4c702b6bf11d5fac00000000"
            .to_string()
    });

    let bytes = hex::decode(&hex_str).expect("invalid hex");
    let tx: Transaction = decode(&bytes).expect("invalid transaction");

    println!("TXID:     {}", tx.txid());
    println!("Version:  {}", tx.version);
    println!("Inputs:   {}", tx.inputs.len());
    for (i, input) in tx.inputs.iter().enumerate() {
        println!("  Input {}:", i);
        println!("    prev txid: {}", input.previous_output.txid);
        println!("    prev vout: {}", input.previous_output.vout);
        println!("    script_sig: {} bytes", input.script_sig.len());
        println!("    sequence: 0x{:08x}", input.sequence);
    }
    println!("Outputs:  {}", tx.outputs.len());
    for (i, output) in tx.outputs.iter().enumerate() {
        println!("  Output {}:", i);
        println!("    value: {} sats", output.value.as_sat());
        println!("    script_pubkey: {} bytes", output.script_pubkey.len());
    }
    println!("Locktime: {}", tx.lock_time);
    println!("Segwit:   {}", tx.is_segwit());
    println!("Coinbase: {}", tx.is_coinbase());
}
