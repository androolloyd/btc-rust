# Experimental Electrum chain and script service

The compiled node can serve actual chain/transaction queries on an explicitly
enabled **loopback** TCP port. It is disabled by default:

```sh
btc-node --network regtest --datadir /path/to/regtest-data --electrum-port 50001 run
```

This is an implemented subset, not a complete wallet server. `server.version`
and `server.features` return explicit unsupported errors; failed version
negotiation closes that connection. The service advertises no completed Electrum
protocol version. The protocol requires every nonoptional method of an advertised
version to work. Status subscriptions, header checkpoint proofs, fee estimation
and other required methods remain unfinished and return explicit errors.
Script history, balances, mempool and unspent queries now use an independently
maintained validated index and the actual pool. Unknown scripts return real
empty state only when that index is complete for the active tip.

| Implemented method | Actual data/operation |
| --- | --- |
| `blockchain.headers.subscribe()` | Validated tip height and serialized header, with committed-tip notifications |
| `blockchain.block.header(height, cp_height=0)` | Actual active-chain header, including network genesis |
| `blockchain.block.headers(start_height, count, cp_height=0)` | Up to 2016 actual headers; short/empty ranges report their actual count |
| `blockchain.transaction.get(tx_hash, verbose=false)` | Actual pool/active-chain transaction, raw or the shared Core-style verbose view |
| `blockchain.transaction.broadcast(raw_tx)` | Ordinary validated admission, durable pool update and the existing transaction relay event |
| `blockchain.transaction.get_merkle(tx_hash, height)` | Actual active-block position and txid merkle branch |
| `blockchain.scripthash.get_history(scripthash)` | Confirmed transactions in block order, then actual pool touches/fees with height 0 or -1 |
| `blockchain.scripthash.get_mempool(scripthash)` | Actual transactions receiving or spending the script, including unconfirmed parents |
| `blockchain.scripthash.get_balance(scripthash)` | Durable coin balance including immature coinbases; signed net mempool delta |
| `blockchain.scripthash.listunspent(scripthash)` | Confirmed outputs in block order followed by unspent pool outputs; pool-spent outputs excluded |
| `server.ping()` / `server.banner()` | Connection keepalive / explicit subset description |

Queries use the same mutex-protected validated backend as HTTP RPC, mining and
P2P. Transaction lookup follows the active-index/mempool boundaries described in
[TRANSACTION_RPC.md](TRANSACTION_RPC.md). Broadcast decodes the actual bytes,
checks scripts/policy/client fee limits and only returns a real txid after
admission. Malformed, invalid, unavailable and already-admitted transactions
return errors; there is no double-hash-of-arbitrary-bytes success path. Actual
peer propagation uses the existing relay queue; it depends on connected peers.

Merkle branches use actual txids rather than witness hashes, Bitcoin's byte
order and odd-width sibling duplication, and agree with the stored header root.
After a reorg, the same height resolves the new active block; a detached
transaction cannot retain an active proof. Header notifications report the
latest committed tip, so intermediate tips can be coalesced as the protocol
allows. Lagged subscribers reread the real tip. Subscriptions belong to each
connection and disappear when it closes; there is no global fake status map.
If a provider's event source closes, subscribed clients disconnect rather than
remaining attached to an apparently active subscription without updates.

The validated index has one row per script/transaction, so multiple receipts,
self payments and input/output overlap cannot duplicate history. Input scripts
come from checksummed spent-coin undo, including outputs consumed in the same
block. Side branches are excluded until they win; disconnect/reconnect updates
history, per-block counts/checksums, coins, the revalidated pool and the index tip
in the same transaction. Genesis coinbase, OP_RETURN and oversized unspendable
outputs are excluded. Stored coin heights prevent historical duplicate txids
from counting the same active coin twice. Physical unspendable-coin pruning in
the underlying consensus store remains separate work.

Databases without this index undergo full script-verified body replay, with
exact stored-undo and durable-coin agreement, before a single transaction
publishes the index. Stage address rows never supply wallet results. An existing
index is checked against active block hashes and its complete row counts/digests
on every reopen; malformed receipts, missing/extra rows and mismatched manifests
fail explicitly. This adds a full index scan on reopen and a verified chain replay
on first upgrade; it is not a fast migration or pruning claim.

A script query uses one chain lock and one database snapshot. Script hashes use
Electrum's reversed SHA256 byte order and accept either hex case. History and
unspent results are bounded to 10,000 entries; queries also cap inspected
inputs/outputs at 1,000,000 and loaded block weight at 64 MiB. Exceeding a bound
returns an explicit error rather than truncating balances or history. Balances
ignore pool spends in the confirmed total, while the unconfirmed signed delta
includes every actual pool receipt and spend. Unspent pool outputs always have
height zero; pool history uses -1 whenever any parent remains unconfirmed.

The transport handles positional/named implemented arguments, sequential batches
up to 128 members, v2 notifications and legacy/v2 response envelopes. Empty or
oversized batches are rejected before dispatch. Batches are not atomic; if a
result exceeds the response budget, already executed members are not rolled
back. Do not blindly retry mutating batches.

Limits are 64 connections, 8 MiB plus 4096 request bytes, 16 MiB response bytes
and 30-second partial-frame/write deadlines. Idle clients do not allocate an
unbounded frame, and request buffering is limited to one queued frame per
connection. A separate owned reader preserves partial requests while header
notifications are written. Shutdown closes active, idle and partial clients
without requiring another request. Configured bind failures fail startup before
network tasks are spawned; the node never reports a silently disabled listener
as success. This is local unauthenticated TCP; HTTP cookies do not authenticate
this port, and TLS/public hosting are not provided.

Primary references are [ElectrumX protocol basics](https://electrumx.readthedocs.io/en/latest/protocol-basics.html),
[ElectrumX 1.4 method semantics](https://electrumx.readthedocs.io/en/latest/protocol-methods.html),
Core v29's [transaction RPC](https://github.com/bitcoin/bitcoin/blob/v29.0/src/rpc/rawtransaction.cpp)
and [block/merkle primitives](https://github.com/bitcoin/bitcoin/blob/v29.0/src/consensus/merkle.cpp),
plus Core's [coin handling](https://github.com/bitcoin/bitcoin/blob/v29.0/src/coins.cpp).

Independent acceptance runs the compiled listener against released Core v29
using real wallet signatures, identical validated blocks, independently computed
even/odd-width merkle paths and actual reorg/restart state:

```sh
python3 scripts/check_core_electrum.py --bitcoind /path/to/bitcoin-29.0/bin/bitcoind
```

Acceptance passed released Core genesis/header/range comparisons, three actual
wallet-signed witness admissions and mined transactions, exact raw/verbose views,
independent even/odd merkle proofs, notification during a partial inbound frame,
real reorg/pool restoration and restart at height 104, unsupported/malformed/batch
responses, shutdown and occupied-port startup failure. That chain-service milestone's local gate
passed 3,333 tests in 43 suites, formatting, Clippy, minimal feature checks and
release build (two preexisting ignored tests). Eighty-two obsolete mock/placeholder
checks were replaced by seven handler/real-transport regressions plus the separate
native Core harness. Existing crypto, consensus and fuzz artifacts are preserved;
no package versions or ordinary consensus rules changed.
The closed-provider-stream regression also passes; existing released Core HTTP
acceptance and all 350 verbose transaction/block/coin comparisons still pass.

The validated script-query milestone adds 200 exact Core-derived comparisons
across ten real snapshots and five scripts. They cover empty/genesis/unspendable
state, immature coinbases, negative pool deltas, self payments, RBF, dependent
parents, same-block child execution, fork restoration and restart at 105. Core's
explicit invalidation temporarily drops a height-3 spend as immature at height
101; it independently re-admits the original signed bytes at height 104 before
comparing identical pools. No expected query results are taken from Rust and no
maturity check is relaxed. All five actual Core-wallet-signed transactions are
admitted and mined. The local gate passes 3,337 tests; verified old-body upgrade,
transaction/unwind aborts, corrupt receipt/row/manifest and query bounds pass.
Legacy archival preserves both index tables and tests all 26 rollback stages.
Status subscriptions and complete protocol negotiation remain unfinished.
Existing HTTP acceptance, all 350 verbose RPC comparisons and both v1/v2 legacy
checkpoint crash/resync/restart scenarios also pass with the index enabled.
