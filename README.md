# btc-rust

A modular Rust Bitcoin full node and development platform. Built from scratch with no dependency on `rust-bitcoin` — we own our encoding, hashing, serialization, and consensus implementation.

Inspired by [reth](https://github.com/paradigmxyz/reth)'s architecture: pipeline/stages sync, trait-based database abstraction, type-state node builder, and execution extensions (ExEx) plugin system.

## Quick Start

```bash
# Build
cargo build --release

# Run on signet
./target/release/btc-node run --network signet --datadir ~/.btc-rust

# Run on mainnet
./target/release/btc-node run --network mainnet

# JSON output (for agents/automation)
./target/release/btc-node status --output json

# Interactive mode (for humans)
./target/release/btc-node run --interactive
```

## Architecture

11 crates in a Cargo workspace, each independently importable:

```
btc-primitives   → Hash, encode, script, transaction, block, address, bech32, PSBT
btc-consensus    → Script engine, sighash, segwit, taproot, UTXO, chain state, block filters
btc-storage      → Database traits, QMDB backend, redb fallback, UTXO persistence, pruning
btc-network      → P2P codec, handshake, DNS seeds, peer manager, compact blocks, tx relay
btc-mempool      → Fee-sorted pool, RBF (BIP125), cluster mempool, fee estimation
btc-stages       → Pipeline: Headers → Bodies → Execution → Indexing → AddressIndex
btc-rpc          → JSON-RPC 2.0 server with Bitcoin Core-compatible methods
btc-exex         → Execution Extensions plugin system (ordinals indexer included)
btc-electrum     → Embedded Electrum protocol server (14 methods)
btc-test         → In-process regtest harness for BIP development
btc-node         → CLI, NodeBuilder, sync manager, Esplora REST, Prometheus, ZMQ
```

## Features

### Consensus
- Full script engine with real ECDSA/Schnorr signature verification via secp256k1
- Legacy sighash (500/500 Bitcoin Core test vectors), BIP143 segwit sighash, BIP341 taproot sighash
- Segregated Witness validation (BIP141/143)
- Taproot key path and script path spending (BIP340/341/342)
- UTXO set processing with connect/disconnect for chain reorgs
- Header chain management with difficulty adjustment
- Block template construction for mining
- BIP157/158 compact block filters (Golomb-coded sets)
- BIP9 version bits signaling with Speedy Trial support
- Parallel script verification across multiple CPU cores
- 30 mainnet checkpoints through height 810,000
- Assume-valid optimization for fast IBD

### Pluggable Opcode Framework
The killer feature for BIP development. Add new opcodes without forking:

```rust
use btc_consensus::opcode_plugin::{OpcodePlugin, OpcodeRegistry, OpcodeContext};

struct MyNewOpcode;
impl OpcodePlugin for MyNewOpcode {
    fn opcode(&self) -> u8 { 0xb3 }  // OP_NOP4 slot
    fn name(&self) -> &str { "OP_MYOPCODE" }
    fn context(&self) -> OpcodeContext { OpcodeContext::NopUpgrade }
    fn execute(&self, ctx: &mut OpcodeExecContext) -> Result<(), ScriptError> {
        // Your opcode logic here
        Ok(())
    }
}

let mut registry = OpcodeRegistry::new();
registry.register(Box::new(MyNewOpcode));
```

Built-in example plugins:
- **OP_CHECKTEMPLATEVERIFY** (BIP119) — covenant primitive
- **OP_CAT** (BIP347) — concatenation in tapscript
- **OP_CHECKSIGFROMSTACK** (BIP348) — verify signature against arbitrary message
- **OP_INTERNALKEY** (BIP349) — push taproot internal key to stack

### Storage
- [QMDB](https://github.com/androolloyd/qmdb) (Quick Merkle Database) — LayerZero's append-only SSD-optimized database with built-in Merkle proofs. 6x throughput over RocksDB.
- Persistent UTXO set with hot cache
- Block pruning with NODE_NETWORK_LIMITED (BIP159)
- Trait-based abstraction — swap backends without touching consensus code

### Networking
- Full Bitcoin P2P protocol: version, verack, ping/pong, inv, getdata, headers, blocks, tx
- wtxidrelay (BIP339), sendcmpct (BIP152), addrv2 (BIP155), feefilter (BIP133)
- DNS seed peer discovery with peer scoring and banning
- Compact block relay (BIP152) with SipHash short IDs
- Transaction relay with inv/getdata protocol
- BIP324 v2 encrypted transport (structure)
- BIP331 package relay for Lightning safety

### APIs
- **JSON-RPC** — 9 Bitcoin Core-compatible methods wired to real chain state
- **Electrum protocol** — 14 methods, embedded server, no separate Electrs needed
- **Esplora REST** — 9 endpoints matching Blockstream's API format
- **Prometheus** — `/metrics` endpoint with 7 gauges (chain height, peers, mempool, sync progress, etc.)
- **ZMQ notifications** — hashblock, hashtx, rawblock, rawtx, sequence via ExEx

### Execution Extensions (ExEx)
Subscribe to chain events without forking the node:

```rust
use btc_exex::{ExEx, ExExContext, ExExNotification};

struct MyPlugin;
impl ExEx for MyPlugin {
    fn name(&self) -> &str { "my-plugin" }
    async fn start(self, mut ctx: ExExContext) -> eyre::Result<()> {
        loop {
            match ctx.notifications.recv().await? {
                ExExNotification::BlockCommitted { height, block, utxo_changes, .. } => {
                    // React to new blocks
                }
                ExExNotification::BlockReverted { height, .. } => {
                    // Handle reorgs
                }
                _ => {}
            }
        }
    }
}
```

Built-in ExEx plugins:
- **OrdinalsExEx** — inscription detection and indexing
- **MetricsExEx** — chain height, tx count, UTXO set tracking
- **LoggingExEx** — structured event logging

### Test Harness
In-process regtest for BIP development — `cargo add btc-test --dev`:

```rust
use btc_test::{TestNode, TestKeyPair, ScriptBuilder};

let mut node = TestNode::new();
let key = TestKeyPair::generate();

// Mine 101 blocks (100 for coinbase maturity + 1 to spend)
node.mine_blocks(101);

// Get spendable UTXOs
let utxos = node.get_utxos(&key.p2wpkh_script_hash());

// Submit a transaction
node.submit_transaction(my_tx)?;

// Mine it into a block
node.mine_block(vec![my_tx]);
```

## CLI

```
btc-node run          Start syncing
btc-node status       Show node status
btc-node sync         Show sync progress
btc-node peers        List connected peers
btc-node config       Show configuration
btc-node init         Initialize data directory
btc-node version      Show version info
btc-node rpc METHOD   Send RPC command

Flags:
  --network signet|testnet|mainnet|regtest
  --datadir PATH
  --output json|text     (auto-detects: JSON when piped)
  --interactive          (human-friendly mode)
  --rpc-port PORT
  --port PORT
  --log-level LEVEL
```

## Testing

```bash
cargo test                    # 909 tests, 0 failures
cargo test -p btc-consensus   # Consensus tests (267 tests)
cargo test -p btc-primitives  # Primitives + Core test vectors
cargo test -p btc-network     # P2P codec + discovery
cargo test -p btc-test        # Test harness

# Fuzzing (requires nightly)
cd fuzz && cargo +nightly fuzz run fuzz_transaction_decode
cargo +nightly fuzz run fuzz_script_execute
cargo +nightly fuzz run fuzz_p2p_message
cargo +nightly fuzz run fuzz_bech32_decode
cargo +nightly fuzz run fuzz_block_decode
cargo +nightly fuzz run fuzz_varint_decode

# Coverage
cargo tarpaulin --skip-clean --out stdout
```

## BIP Coverage

| Status | BIPs |
|--------|------|
| **Consensus** | 16, 30, 34, 42, 65, 66, 68, 90, 91, 112, 113, 141, 143, 147, 148, 340, 341, 342, 343 |
| **P2P** | 14, 31, 35, 130, 133, 144, 152, 155, 157, 158, 159, 324, 325, 331, 339 |
| **Wallet** | 13, 125, 173, 174, 350, 370 |
| **Activation** | 8, 9 (version bits + Speedy Trial) |
| **Proposed** | 119 (CTV), 347 (CAT), 348 (CSFS), 349 (INTERNALKEY) — via pluggable opcode framework |

## Devnet

Spin up a multi-node test network with [Kurtosis](https://www.kurtosis.com/):

```bash
docker build -t btc-rust:latest -f devnet/Dockerfile .
kurtosis run devnet/kurtosis.yml
```

## Design Principles

- **Own everything** — No rust-bitcoin dependency. Own encoding, hashing, bech32. Supply chain minimized.
- **Neutral policy** — We implement consensus, not opinions. No Knots-style policy divergence.
- **Agent-friendly** — JSON output, non-interactive by default, structured progress events.
- **Pluggable** — ExEx for chain events, opcode registry for new BIPs, trait-based storage.
- **Quantum-ready** — `SignatureVerifier` trait allows swapping secp256k1 for post-quantum algorithms.

## Security

This project has undergone two automated code review passes covering:
- Consensus correctness (5 critical bugs found and fixed)
- DoS resistance (deserialization limits, decode count bounds)
- Memory safety (unsafe audit, `#[repr(transparent)]` enforcement)
- Performance (O(N^2) hotpath elimination, SighashCache)

6 cargo-fuzz targets cover the primary attack surfaces (transaction/block/script decode, P2P messages, bech32).

**This is experimental software. Do not use for production workloads without additional auditing.**

## License

MIT OR Apache-2.0
