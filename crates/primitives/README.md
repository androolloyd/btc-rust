# btc-primitives

Bitcoin primitives library -- types, encoding, hashing, script, and bech32. No rust-bitcoin dependency.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
btc-primitives = "0.1"
```

### Example

```rust
use btc_primitives::{Transaction, Block, Amount, BlockHash, sha256d};
use btc_primitives::encode::{encode, decode};

// Decode a raw transaction
let raw_tx: Vec<u8> = /* raw bytes */;
let tx: Transaction = decode(&raw_tx).expect("valid transaction");
println!("txid: {}", tx.txid());
println!("segwit: {}", tx.is_segwit());

// Work with amounts
let fee = Amount::from_sat(10_000);
assert!(fee.is_valid());
println!("{fee}"); // "0.00010000 BTC"

// Hash data with Bitcoin's double-SHA256
let hash = sha256d(b"hello");
```

## Features

- **Transaction / Block**: Full consensus encoding and decoding (legacy + segwit).
- **Script**: Builder, pattern detection (P2PKH, P2SH, P2WPKH, P2WSH, P2TR), instruction iterator.
- **Hashing**: SHA-256, SHA-256d, HASH160, typed `BlockHash` / `TxHash` / `Hash256`.
- **Amount**: Satoshi-based arithmetic with BTC display formatting.
- **VarInt / Encodable / Decodable**: Bitcoin wire-format serialisation traits.
- **Bech32**: Native segwit and taproot address encoding.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
