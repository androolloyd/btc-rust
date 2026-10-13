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
version to work. Remaining mandatory protocol methods are still unfinished.
Header checkpoint proofs use the actual validated active-chain prefix. Relay
fees, pool histograms and bounded empirical confirmation estimates now use real
providers; their scope and insufficient-data behavior are in [FEES.md](FEES.md).
Script history, balances, mempool and unspent queries now use an independently
maintained validated index and the actual pool. Unknown scripts return real
empty state only when that index is complete for the active tip.

| Implemented method | Actual data/operation |
| --- | --- |
| `blockchain.headers.subscribe()` | Validated tip height and serialized header, with committed-tip notifications |
| `blockchain.block.header(height, cp_height=0)` | Actual active-chain header, including network genesis; positive checkpoint returns header, branch and root |
| `blockchain.block.headers(start_height, count, cp_height=0)` | Up to 2016 actual headers; positive checkpoint proves the last returned header in a nonempty range |
| `blockchain.transaction.get(tx_hash, verbose=false)` | Actual pool/active-chain transaction, raw or the shared Core-style verbose view |
| `blockchain.transaction.broadcast(raw_tx)` | Ordinary validated admission, durable pool update and the existing transaction relay event |
| `blockchain.transaction.get_merkle(tx_hash, height)` | Actual active-block position and txid merkle branch |
| `blockchain.scripthash.get_history(scripthash)` | Confirmed transactions in block order, then actual pool touches/fees with height 0 or -1 |
| `blockchain.scripthash.get_mempool(scripthash)` | Actual transactions receiving or spending the script, including unconfirmed parents |
| `blockchain.scripthash.get_balance(scripthash)` | Durable coin balance including immature coinbases; signed net mempool delta |
| `blockchain.scripthash.listunspent(scripthash)` | Confirmed outputs in block order followed by unspent pool outputs; pool-spent outputs excluded |
| `blockchain.scripthash.subscribe(scripthash)` | Actual history status plus connection-owned notifications after durable chain/pool changes |
| `blockchain.scripthash.unsubscribe(scripthash)` | Removes only this connection's script subscription; returns whether it existed |
| `blockchain.relayfee()` | Actual configured pool admission floor |
| `mempool.get_fee_histogram()` | Actual current pool fee/virtual-size bins using released ElectrumX compression |
| `blockchain.estimatefee(number, mode)` | Actual observed confirmation quote, or `-1` for insufficient data |
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

Header checkpoint leaves are the actual header SHA256d hashes from genesis
through `cp_height`, inclusive. Trees use ElectrumX's natural height, double-SHA256
pair hashing, odd-width sibling duplication and reversed display byte order.
With a positive checkpoint, a single-header response contains `header`, `branch`
and `root`; a chunk adds `branch` and `root` to `hex`, actual `count` and `max`.
Its proof covers the last header actually returned after the 2016-header cap and
tip truncation. Empty output has no proof and does not require an available
checkpoint. Omitted/zero checkpoints retain the existing unproved response.
Wrong checkpoint types fail; nonempty proofs require
`header_height <= cp_height <= validated_tip`.

One backend-wide cached tree is keyed by prefix length and the actual checkpoint
block hash while holding the chain lock. A winning reorg changes that identity;
equal-work side branches do not. Extensions above the checkpoint can reuse it.
Only a complete successful tree receives a cache identity, and an old tree is
released before replacement. Proof prefixes are bounded to 1,048,576 headers
(`cp_height <= 1,048,575`), roughly 64 MiB of hash payload. Larger proofs error
explicitly; this does not limit block acceptance or chain height. Cold requests
build the entire prefix under the chain lock; cached paths take logarithmic work.
Repeated cold prefixes and broad-load/public hosting remain unqualified.

A root supplied by this server is not an independent trust anchor. Clients must
pin an independently trusted checkpoint commitment to authenticate a branch.
These query proofs do not install or alter consensus checkpoints.

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

Script status is SHA256 of the ordered `tx_hash:height:` history, or null for
empty history, as specified in the primary protocol. Confirmed rows retain block
order; pool rows now use stable ascending display-txid order for both history
and status, preserving hashes across pool rebuild/restart. Status ignores fees.
A coalesced revision is published only after successful durable block/admission/
pool-configuration commits. It covers removed RBF descendants, disconnected and
restored transactions, and policy revalidation rather than only new broadcasts.
Rejected writes publish no revision.

Subscriptions belong to their TCP connection. Subscribe returns the actual
initial status; repeats and hex-case variants reuse the same entry. Unsubscribe
returns true only when that connection owned the entry, and prevents subsequent
notifications for it. Disconnect/restart clears ownership and requires a fresh
subscribe. State is never stored in a global fake wallet map.

Each connection captures the revision stream before querying its initial status,
so a commit between the query and response cannot disappear. Refresh obtains one
chain lock and database snapshot for all subscribed scripts; subsequent changes
remain pending. Only changed statuses generate notifications, with canonical
script hashes and `[scripthash, status]` parameters. Revisions coalesce under load;
clients may observe the latest state without every intermediate transition.
The owned reader retains fragmented inbound requests during both header and
script notifications. Connection selection is fair between requests and events.
Closed event sources or failed refreshes disconnect subscribed clients instead
of leaving a silently stale subscription.

There are at most 64 scripts per connection. Initial subscribe checks the entire
connection against a shared budget of 10,000 history references, 1,000,000 examined
inputs/outputs, 64 MiB of loaded block weight and 64 MiB of examined script bytes.
Refresh uses the same budget. A new subscription that exceeds it errors before
changing ownership; failure during a later refresh closes the connection.
Ordinary wallet queries also bound examined script bytes. Larger indexed wallets,
public hosting and broad-load performance remain unqualified. Stateless library
dispatch cannot acknowledge a live script subscription; it errors explicitly.

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
released ElectrumX 1.16.0's [header query implementation](https://github.com/spesmilo/electrumx/blob/1.16.0/electrumx/server/session.py)
and [Merkle implementation](https://github.com/spesmilo/electrumx/blob/1.16.0/electrumx/lib/merkle.py),
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
Status subscriptions are accepted below; complete protocol negotiation remains
unfinished.
Existing HTTP acceptance, all 350 verbose RPC comparisons and both v1/v2 legacy
checkpoint crash/resync/restart scenarios also pass with the index enabled.

The status-subscription milestone passes 260 exact Core-derived wallet-query
comparisons across thirteen real snapshots plus independently calculated status
hashes and actual streamed updates on separate connections. A real subscribe +
signed broadcast batch proves a change after the initial query but before its
response still arrives. Notifications arrive during a partial inbound JSON frame.
Real RBF removes an existing parent and child; snapshots and notifications agree
with Core before new dependent admission and same-block mining. Unsubscribe on
one connection leaves the other receiving updates, repeats return true/false,
case variants reuse capacity, the 65th subscription fails and freed capacity is
reusable. Batch and notification unsubscribe work. Stable hashes survive restart
with four actual pool transactions and a confirmed-chain restart at 105; new
connections inherit no subscriptions. Unknown-script null status is deduplicated.
The gate passes 3,339 tests across 43 suites (two existing ignores), formatting,
Clippy, feature checks and release build. Closed-stream and successful-versus-
rejected-publication regressions pass. No package or consensus rules changed.

The header-checkpoint milestone passes 628 exact proof comparisons against
actual Core v29 headers and the unchanged Merkle class from released ElectrumX
1.16.0. Its source is checksum-pinned by `scripts/electrumx_reference.py`, retains
the upstream license in the temporary download, and introduces no node dependency.
Every position in selected even/odd prefixes through height 101 is covered,
alongside cached paths, named/positional arguments, malformed types, unavailable
windows, overflow and empty output. A warmed height-103 checkpoint stays unchanged
on equal-work side branches and is queried immediately after the winning reorg,
before another prefix can evict the cache. Its branch/root change while a header
below the fork remains identical; a checkpoint below the fork remains unchanged.
Proofs survive real pool and confirmed-chain restarts. Actual validation through
height 2018 tests the precise 2016-header chunk endpoint, short tip ranges and
2,019-header trees again after reopening the same database. Existing 260 wallet
query comparisons, status notifications and admission/reorg assertions still pass.

The final gate passes 3,342 tests across 43 suites (two existing ignores),
formatting, Clippy, feature checks and release build. Three new regressions cover
the unchanged published height-5/checkpoint-8 header proof, allocation bounds
before source reads, and failed-prefix cache publication. The first native run
found an obsolete fixture expecting checkpoint support to be absent; that
expectation was corrected to the actual window error. The complete rerun and
strengthened warm-cache reorg follow-up both pass. No dependency versions,
lockfiles or ordinary consensus rules changed. Fee providers are accepted in
[FEES.md](FEES.md); remaining mandatory protocol methods, full negotiation, TLS and broad public-chain/load
qualification remain unfinished.
