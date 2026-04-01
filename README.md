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

## Script Development Quickstart

btc-rust includes `btc-forge`, a Foundry-equivalent toolkit for Bitcoin Script development. No external tools needed — write, test, debug, and analyze scripts entirely in Rust.

### 1. Add dependencies

```toml
# Cargo.toml
[dev-dependencies]
btc-forge = { path = "crates/forge" }  # or from registry when published
btc-test = { path = "crates/test-harness" }
```

### 2. Write and test a script

```rust
use btc_forge::{ScriptEnv, ForgeScript, ScriptDebugger, TxBuilder, Amount, Opcode};
use btc_forge::analyze_script;

#[test]
fn test_hash_timelock_contract() {
    let mut env = ScriptEnv::new();
    let alice = env.new_named_account("alice");
    let bob = env.new_named_account("bob");

    // Build an HTLC: Bob can claim with preimage, Alice can reclaim after timeout
    let preimage = b"my_secret_preimage_here!";
    let hash = sha256(preimage);

    let htlc = ForgeScript::htlc(
        &env.accounts[1].keypair.public_key.serialize(),  // bob
        &env.accounts[0].keypair.public_key.serialize(),  // alice
        &hash,
        100,  // timeout at block 100
    ).build();

    // Analyze the script
    let analysis = analyze_script(htlc.as_script());
    println!("Size: {} bytes", analysis.size_bytes);
    println!("Opcodes: {}", analysis.op_count);
    println!("Sigops: {}", analysis.sigop_count);
    println!("Branches: {}", analysis.branches.len());
}
```

### 3. Debug script execution step-by-step

```rust
#[test]
fn test_debug_arithmetic() {
    // Build: 2 + 3 == 5 ?
    let script = ForgeScript::new()
        .push_num(2)
        .push_num(3)
        .op(Opcode::OP_ADD)
        .push_num(5)
        .op(Opcode::OP_EQUAL)
        .build();

    let mut debugger = ScriptDebugger::new(script.as_script());
    let trace = debugger.run();

    // Inspect stack at each step
    for step in &trace {
        println!("PC:{} {:?} → stack: {:?}", step.pc, step.opcode, step.stack);
    }
    // PC:0 PushBytes([2]) → stack: [[2]]
    // PC:2 PushBytes([3]) → stack: [[2], [3]]
    // PC:4 OP_ADD         → stack: [[5]]
    // PC:5 PushBytes([5]) → stack: [[5], [5]]
    // PC:7 OP_EQUAL       → stack: [[1]]
}
```

### 4. Build and verify transactions

```rust
#[test]
fn test_spend_p2pkh() {
    let mut env = ScriptEnv::new();
    let alice = env.new_named_account("alice");

    // Fund alice with 1 BTC
    let utxo = env.fund_p2pkh(0, Amount::from_sat(100_000_000));

    // Build a spending transaction
    let tx = TxBuilder::new()
        .add_input(&utxo)
        .add_output(
            ForgeScript::p2pkh(&[0u8; 20]).build(),
            Amount::from_sat(99_990_000),  // 10K sat fee
        )
        .sign_input(0, &env.accounts[0].keypair, &utxo.txout)
        .build();

    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 1);
}
```

### 5. Test timelocks (CLTV/CSV)

```rust
#[test]
fn test_timelock_enforced() {
    let mut env = ScriptEnv::new();

    // Script: require block height >= 500
    let script = ForgeScript::new()
        .push_num(500)
        .op(Opcode::OP_CHECKLOCKTIMEVERIFY)
        .op(Opcode::OP_DROP)
        .op(Opcode::OP_1)
        .build();

    // At height 100: should fail
    let result = env.verify_script_at_height(&script, 100);
    assert!(result.is_err());

    // At height 600: should succeed
    let result = env.verify_script_at_height(&script, 600);
    assert!(result.is_ok());
}
```

### 6. Test proposed opcodes (CTV, CAT)

```rust
use btc_consensus::opcode_plugin::{OpCat, OpCheckTemplateVerify, OpcodeRegistry};

#[test]
fn test_op_cat() {
    let mut registry = OpcodeRegistry::new();
    registry.register(Box::new(OpCat));

    let script = ForgeScript::new()
        .push_bytes(b"hello")
        .push_bytes(b"world")
        .op(Opcode::OP_CAT)  // concatenate
        .build();

    // Execute with the custom opcode registry
    let result = env.execute_with_registry(&script, &registry);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().final_stack[0], b"helloworld");
}
```

### 7. Common script patterns

```rust
// P2PKH
let script = ForgeScript::p2pkh(&pubkey_hash).build();

// P2WPKH
let script = ForgeScript::p2wpkh(&pubkey_hash).build();

// Multisig (2-of-3)
let script = ForgeScript::multisig(2, &[&pk1, &pk2, &pk3]).build();

// Hash timelock (HTLC)
let script = ForgeScript::htlc(&receiver_pk, &sender_pk, &hash, timeout).build();

// Timelock wrapper
let script = ForgeScript::timelock(1000, &inner_script).build();

// Hash lock wrapper
let script = ForgeScript::hashlock(&sha256_hash, &inner_script).build();

// OP_RETURN data
let script = ForgeScript::op_return(b"hello from btc-rust").build();
```

### 8. Run the regtest test harness

```rust
use btc_test::{TestNode, TestKeyPair};

#[test]
fn test_full_flow() {
    let mut node = TestNode::new();  // in-process regtest node

    // Mine 101 blocks (coinbase maturity)
    node.mine_blocks(101);
    assert_eq!(node.height(), 101);

    // Check balance
    let key = TestKeyPair::generate();
    let balance = node.get_balance(&key.p2pkh_script_hash());
    assert_eq!(balance, 0);
}
```

## Policy Configuration

btc-rust lets you tune your node's validation policy without forking:

### Presets

```bash
# Match Bitcoin Core exactly (default)
btc-node run --policy core

# Consensus rules only — accept anything technically valid
btc-node run --policy consensus

# Maximum strictness
btc-node run --policy all
```

### Individual flags

```bash
# Core-compliant but disable specific policies
btc-node run --policy core --no-nullfail

# Custom dust limit (satoshis)
btc-node run --dust-limit 330

# Custom OP_RETURN data limit (bytes)
btc-node run --datacarrier-size 100000
```

### Policy presets detail

| Flag | `consensus` | `core` | `all` |
|------|:-----------:|:------:|:-----:|
| P2SH | ✓ | ✓ | ✓ |
| WITNESS | ✓ | ✓ | ✓ |
| TAPROOT | ✓ | ✓ | ✓ |
| CLTV/CSV | ✓ | ✓ | ✓ |
| DERSIG | ✓ | ✓ | ✓ |
| NULLDUMMY | ✓ | ✓ | ✓ |
| SIGPUSHONLY | | ✓ | ✓ |
| CLEANSTACK | | ✓ | ✓ |
| NULLFAIL | | ✓ | ✓ |
| MINIMALDATA | | ✓ | ✓ |
| MINIMALIF | | | ✓ |
| DISCOURAGE_UPGRADABLE_NOPS | | | ✓ |

## Agent Integration

btc-rust is designed to be operated by AI agents and automation:

```bash
# All commands support JSON output
btc-node status --output json
btc-node decode-tx <hex> --output json

# Shorthand
btc-node status --json

# Progress events on stderr (JSON lines)
btc-node run --output json 2>progress.jsonl

# Pipe-friendly: data on stdout, logs on stderr
btc-node decode-tx <hex> --json | jq '.txid'

# Exit codes are meaningful
btc-node decode-tx <invalid> --json; echo "exit: $?"
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Network error |
| 4 | Consensus error |
| 5 | Storage error |

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
btc-node decode-tx    Decode raw transaction hex
btc-node decode-script  Decode raw script hex
btc-node decode-header  Decode raw block header hex
btc-node watch ADDR   Watch address for transactions
btc-node simulate-tx  Simulate transaction (dry run)
btc-node compile      Compile miniscript policy to script
btc-node explore      Launch block explorer web UI
btc-node playground   Interactive script playground (no JSON mode)

Flags:
  --network signet|testnet|mainnet|regtest
  --datadir PATH
  --output json|text     (auto-detects: JSON when piped)
  --json                 (shorthand for --output json)
  --interactive          (human-friendly mode)
  --rpc-port PORT
  --port PORT
  --log-level LEVEL

Run flags:
  --policy core|consensus|all  (validation policy preset)
  --no-nullfail               (disable NULLFAIL policy)
  --dust-limit SATS           (custom dust limit)
  --datacarrier-size BYTES    (custom OP_RETURN data limit)
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
