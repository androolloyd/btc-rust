//! Generate and display all Bitcoin address types.
//!
//! Usage: cargo run --example address_types

use btc_primitives::address::Address;
use btc_primitives::hash::hash160;
use btc_primitives::network::Network;

fn main() {
    let fake_pubkey_hash = hash160(b"example public key data");
    let fake_script_hash = hash160(b"example script data");
    let fake_witness_key = [0xab; 32];

    let p2pkh = Address::P2pkh {
        hash: fake_pubkey_hash,
        network: Network::Mainnet,
    };
    let p2sh = Address::P2sh {
        hash: fake_script_hash,
        network: Network::Mainnet,
    };
    let p2wpkh = Address::P2wpkh {
        hash: fake_pubkey_hash,
        network: Network::Mainnet,
    };
    let p2wsh = Address::P2wsh {
        hash: [0xcd; 32],
        network: Network::Mainnet,
    };
    let p2tr = Address::P2tr {
        output_key: fake_witness_key,
        network: Network::Mainnet,
    };

    println!("=== Bitcoin Address Types (Mainnet) ===\n");
    println!("P2PKH:  {}", p2pkh);
    println!("P2SH:   {}", p2sh);
    println!("P2WPKH: {}", p2wpkh);
    println!("P2WSH:  {}", p2wsh);
    println!("P2TR:   {}", p2tr);

    println!("\n=== Script PubKeys ===\n");
    println!("P2PKH  script: {}", hex::encode(p2pkh.script_pubkey().as_bytes()));
    println!("P2SH   script: {}", hex::encode(p2sh.script_pubkey().as_bytes()));
    println!("P2WPKH script: {}", hex::encode(p2wpkh.script_pubkey().as_bytes()));
    println!("P2WSH  script: {}", hex::encode(p2wsh.script_pubkey().as_bytes()));
    println!("P2TR   script: {}", hex::encode(p2tr.script_pubkey().as_bytes()));
}
