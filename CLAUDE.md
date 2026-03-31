# btc-rust

A modular Rust Bitcoin full node inspired by reth's architecture.

## Build & Test

```bash
cargo build          # build all crates
cargo test           # run all tests (~280+ tests)
cargo test -p <crate> # test individual crate
cargo run -- --help  # CLI help
```

## Architecture

8-crate workspace following reth's patterns:

- **btc-primitives** — Hash, encode, script, tx, block, address, amount, bech32. All our own code, no rust-bitcoin dependency.
- **btc-consensus** — Script engine with real CHECKSIG/secp256k1, sighash (500/500 Core vectors), UTXO processing, header chain management, taproot, segwit witness verification, chain reorgs.
- **btc-storage** — Database trait + QMDB backend (LayerZero's Quick Merkle Database). Also has redb fallback.
- **btc-network** — P2P codec (all message types), handshake, connection management, DNS seed discovery, peer manager with scoring, compact blocks (BIP152).
- **btc-mempool** — Fee-sorted tx pool, eviction policies, fee estimation.
- **btc-stages** — Reth-style pipeline: Headers → Bodies → Execution → Indexing. Execute/unwind pattern.
- **btc-rpc** — JSON-RPC 2.0 server with Core-compatible methods.
- **btc-node** — CLI binary, type-state NodeBuilder, sync manager, agent-friendly output.

## Key Design Decisions

- **Own everything** — We author our own encoding, hashing, serialization, bech32. No rust-bitcoin dependency. Supply chain security.
- **QMDB storage** — Forked from androolloyd/qmdb. Block-oriented writes map naturally to Bitcoin's block processing.
- **Swappable signatures** — `SignatureVerifier` trait allows plugging in post-quantum algorithms.
- **Agent-friendly CLI** — `--output json` for machine consumption, `--interactive` for humans. Logs to stderr, structured output to stdout.

## Testing Against Bitcoin Core

Test vectors from bitcoin/bitcoin are in `testdata/`:
- script_tests.json, tx_valid.json, tx_invalid.json
- sighash.json (500/500 pass), base58_encode_decode.json
- key_io_valid.json, key_io_invalid.json, blockfilters.json

## Dependencies to Fork

External deps should be forked into androolloyd GitHub account for supply chain security. Currently forked:
- qmdb (androolloyd/qmdb)
