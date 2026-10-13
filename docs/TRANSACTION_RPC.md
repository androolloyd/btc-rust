# Transaction RPC over validated history

The production RPC backend renders actual mempool transactions, stored block
bodies and checksummed block undo. HTTP clients use the per-start cookie
described in [RPC_HTTP.md](RPC_HTTP.md); newline clients use the same backend.

| Method | Verbosity | Result |
| --- | --- | --- |
| `getrawtransaction txid` | omitted/null or <= 0 | Exact serialized transaction hex |
| `getrawtransaction txid 1` | 1 or true | Transaction fields and available block context |
| `getrawtransaction txid 2` | >= 2 | Details plus actual confirmed input prevouts and fee |
| `getblock blockhash` | omitted/null, 1 or true | Actual transaction IDs and block metadata |
| `getblock blockhash 0` | <= 0 or false | Exact serialized block hex |
| `getblock blockhash 2` | 2 | Complete transaction details and undo-backed fees |
| `getblock blockhash 3` | >= 3 | Details, fees and input prevouts |

Transaction details include txid, witness hash, version, actual serialized size,
weight and rounded virtual size, locktime, sequence, scriptSig disassembly,
nonempty per-input witness stacks and each numbered output's value/script.
Coinbase inputs use `coinbase` rather than fabricated previous-output fields.
Blocks also report actual witness-stripped size. `gettxout` uses the same output
script view, including disassembly, type, descriptor and address when applicable.
It returns null for provably unspendable OP_RETURN/oversized outputs, including
rows retained by older local databases. Physical pruning of those historical
rows and general UTXO-set parity remain separate storage/consensus work.

The optional third `getrawtransaction` argument scopes the lookup to that exact
stored block. A transaction found in another block or the pool cannot satisfy
it. The verbose result includes `in_active_chain`; active transactions report
positive confirmations and actual block time, while retained stale blocks report
zero confirmations and omit active-chain time fields. Block confirmations remain
-1 for a stale block. Block-contained transaction objects carry no invented
per-transaction confirmation context.

Without a block hash, the backend first searches the actual mempool and then
the durable **active-chain** transaction index. Retained detached bodies are
available by explicit block hash. An orphan record alone is insufficient for
an implicit query. This differs from a separately maintained Core `-txindex`
that can retain detached transaction locations; there is no configurable global
side-branch transaction index here.

Mempool transaction results omit block context, fees and prevouts even at
verbosity 2, matching Core's behavior. Confirmed prevouts come from validated
block undo, including outputs spent later in the same block; they are not
reconstructed from today's UTXO set. Coinbase results omit fees. Missing,
damaged, duplicate or incomplete required undo returns an explicit error.
The chain lock keeps lookup, active-chain context and pool state consistent
through reorgs; restart resolves the same durable bodies and undo.

Descriptors describe recognized templates and encoded material from actual
outputs using Core's dummy-provider inference; inference can canonicalize pushes.
There is no wallet ownership, identity, key derivation or signing claim.
Legacy `pk`/`multi` inference preserves structurally encoded key bytes even when
they are not valid curve points. A `rawtr` descriptor requires a valid x-only
point; otherwise the actual witness address describes that output. Unknown and
malformed scripts retain their actual hex and Core-style disassembly errors.
No script classification activates experimental consensus behavior.

All five supported networks now store their exact canonical genesis body, so
raw and verbose `getblock` work at height zero. Old valid header-only stores gain
the exact body in a transaction after normal history verification. No genesis
coins, transaction-index rows, script history or fee observations are created;
Core-style genesis-coinbase `getrawtransaction` queries are still rejected.
Testnet4 now uses its published distinct merkle root. A database anchored to the
previous incorrect Testnet4 header fails without overwriting its records; preserve
that directory and resync in a separate data directory. This establishes genesis
identity, not complete Testnet4/BIP94 consensus parity.

Header and block JSON now include Core v29's `target`: its rendering uses the
current active tip's difficulty target, while `bits`/`difficulty` describe the
queried block. Named arguments, general parameter/error-message parity, Core
multi-horizon fee estimation, prioritization and remaining Electrum protocol
methods remain separate work. Actual bounded fee providers are in [FEES.md](FEES.md).
Large HTTP results are subject to the existing 16 MiB response budget and may
return 503; use transaction queries or lower block verbosity where appropriate.

Primary references are Core v29's [transaction RPC and block context](https://github.com/bitcoin/bitcoin/blob/v29.0/src/rpc/rawtransaction.cpp),
[transaction/script rendering](https://github.com/bitcoin/bitcoin/blob/v29.0/src/core_write.cpp),
[block verbosity, header target and undo](https://github.com/bitcoin/bitcoin/blob/v29.0/src/rpc/blockchain.cpp),
[canonical genesis bodies](https://github.com/bitcoin/bitcoin/blob/v29.0/src/kernel/chainparams.cpp),
[script template solver](https://github.com/bitcoin/bitcoin/blob/v29.0/src/script/solver.cpp),
[descriptor inference](https://github.com/bitcoin/bitcoin/blob/v29.0/src/script/descriptor.cpp)
and [Core's unspendable-coin exclusion](https://github.com/bitcoin/bitcoin/blob/v29.0/src/coins.cpp),
plus [BIP141 weight](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#block-size).

Independent native acceptance uses released Core wallet signatures and ordinary
block validation, with all transaction bytes, amounts, scripts, descriptors,
prevout metadata and confirmations compared exactly. Core's rounded floating
difficulty field is compared at 1e-14 relative precision; the header target and
every transaction field are exact. No transaction assertion is relaxed.

```sh
python3 scripts/check_core_verbose.py --bitcoind /path/to/bitcoin-29.0/bin/bitcoind
```

Acceptance passed 350 independent transaction/block/coin views, 283 scripts in
an actual validated coinbase, ten error classifications, a Core-wallet-signed
mixed legacy/nested/SegWit-v0/Taproot input and same-block child, branch replacement,
pool restoration/re-mining and restart at height 108. Local corrupt/incomplete
undo and retained-unspendable-output regressions pass, together with 3,408 tests
in 43 suites, formatting, Clippy, minimal feature checks and the release build
(two preexisting ignored tests). No dependency or ordinary consensus changes.
The existing eighteen-case HTTP/released `bitcoin-cli` acceptance and all four
inbound/outbound v1/v2 P2P relay/reorg/mempool/IBD/restart scenarios also pass.

The genesis/transaction-position follow-up passes exact released Core v29 genesis
hashes, complete serialized headers/bodies, header JSON and block verbosity 1/2/3
on Mainnet, Testnet3, Testnet4, Signet and Regtest, before and after durable
restart. Genesis output exclusion, ordinary transaction-lookup rejection,
empty script history and actual singleton Electrum proofs remain checked.
The final gate passes 3,347 tests in 43 suites (two existing ignores). Regressions
preserve old incompatible Testnet4 rows, reject damaged genesis bodies without
replacement and prevent transaction-position success from corrupt actual bodies.
The first gate exposed a 32-versus-33-byte Testnet4 construction mistake; the
published 33-byte script was restored before the complete passing rerun. All
350 existing verbose comparisons, 283 real coinbase scripts and ten error
classifications also pass with the formerly excluded target checked exactly.

```sh
python3 scripts/check_core_genesis.py --bitcoind /path/to/bitcoin-29.0/bin/bitcoind
```
