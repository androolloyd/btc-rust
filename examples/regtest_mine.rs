//! Spin up a regtest node and mine blocks.
//!
//! Usage: cargo run --example regtest_mine

use btc_test::{TestNode, TestKeyPair};

fn main() {
    let mut node = TestNode::new();
    let key = TestKeyPair::generate();

    println!("Mining 10 blocks on regtest...");
    let blocks = node.mine_blocks(10);
    println!("Chain height: {}", node.height());
    println!("Blocks mined: {}", blocks.len());
    println!("Key (compressed): {}", hex::encode(key.public_key.serialize()));
    println!("P2PKH script: {}", hex::encode(key.p2pkh_script().as_bytes()));
    println!("P2WPKH script: {}", hex::encode(key.p2wpkh_script().as_bytes()));

    // Mine a block paying the key
    let block = node.mine_block_to(key.p2pkh_script(), vec![]);
    println!(
        "\nBlock {} mined with coinbase paying our key:",
        node.height()
    );
    println!("  Block hash: {}", block.block_hash());
    println!("  Transactions: {}", block.transactions.len());
    println!(
        "  Coinbase value: {} sats",
        block.transactions[0].outputs[0].value.as_sat()
    );
}
