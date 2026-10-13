# Validated fee providers

The opt-in loopback Electrum service and the production RPC backend now obtain
fees from the actual shared validated pool and observed confirmations. They do
not use the separate library's backlog heuristic or fixed REST example numbers.

| Method | Data and units |
| --- | --- |
| `blockchain.relayfee()` | Actual configured admission floor, BTC per 1000 virtual bytes |
| `mempool.get_fee_histogram()` | Compact `[sat/vbyte, virtual_bytes]` bins from current validated pool entries |
| `blockchain.estimatefee(number, mode)` | Bounded empirical confirmation quote in BTC per 1000 virtual bytes; `-1` when unavailable |
| RPC `estimatefee(target, mode)` | The same empirical quote or `-1` |
| RPC `estimatesmartfee(target, mode)` | `feerate` and `blocks`, or an explicit insufficient-observation `errors` array |
| RPC `getmempoolfees()` | Actual count, virtual size, total satoshi fee and compact histogram |

These are bounded empirical estimates, with their own algorithm. They do not
implement Bitcoin Core's decaying, multi-horizon fee estimator or establish Core
fee-estimation parity. An estimate cannot guarantee confirmation under changing
traffic or miner selection. The optional mode is `CONSERVATIVE` (default) or
`ECONOMICAL`; malformed targets/modes fail. RPC targets are 1 through 1008. The
current observation horizon can only quote targets 1 through 144; larger valid
targets have insufficient data, never a substituted fixed rate. Electrum targets
must be positive integers and also return `-1` beyond the observation horizon.

Learning starts when an actually admitted transaction has no remaining pool
parents, at the actual validated height. It does not retroactively infer arrival
times from imported blocks or missing old metadata. Confirmation delay is the
number of subsequently validated blocks before the transaction is mined. Removed
or replaced transactions are failed observations. Pending entries old enough to
miss a requested target count as failures; younger pending entries are censored.
Package/ancestor fee estimation is not implemented.

Resolved observations expire once more than 144 blocks old. Rates round up to integral satoshis per
1000 virtual bytes. The estimator considers cumulative tails from higher to lower
observed rates, requiring at least twenty resolved or sufficiently aged entries
and a success fraction of 95% for conservative mode or 85% for economical mode.
It returns the lowest qualifying observed threshold, clamped to the actual relay
floor. If none qualifies, it returns no quote. These sample thresholds are an
explicit experimental policy, not a production prediction-quality claim.

An isolated candidate observation state is written in the same durable database
transaction as the pool/admission/configuration or active chain transition, then
published in memory only after commit. Equal-work side branches do not change it.
A winning reorg clears learned outcomes and begins observing the restored actual
pool at its new height; detached confirmations cannot remain successes. A
versioned checksum receipt in the existing Meta table binds state to the actual
committed height/hash. Reopen preserves learning, rejects damaged/stale receipts,
and reconciles entries dropped during ordinary pool revalidation. Missing receipts
start with no historical evidence. Legacy archival preserves this Meta data but
archived observations never authorize a fresh chain's quotes.

Learning is bounded to 20,000 pending entries and 20,000 resolved observations,
with an 8 MiB stored-receipt limit checked before reading/copying. Capacity
exhaustion clears learning rather than truncating a sample or rejecting a valid
block. It must warm up again. Histogram queries refuse pools above 20,000 entries
before scanning. These limits do not restrict ordinary block acceptance, and
broad-load performance and public-chain prediction quality remain unqualified.

Histogram compression matches released ElectrumX 1.16.0: rates round down to
0.1 sat/vbyte, bins start at 100,000 virtual bytes and grow by 10%, a large lump
can flush a preceding smaller bin, and the final undersized tail is omitted.
Thus a small real pool can correctly have an empty compact histogram. Bins use
each transaction's policy virtual size, not serialized witness bytes, and are
queried under the same chain lock as pool changes. `getmempoolinfo` now also reports
actual pool virtual bytes and configured relay/minimum fees. Dynamic eviction and
rolling eviction floors remain unfinished; current full-pool admission errors.

The separate metrics-only REST/explorer service has no installed validated fee
or pool provider. `/api/fee-estimates` and `/api/mempool` now return explicit errors
instead of invented quotes, zero total fees or empty placeholder histograms. This
does not complete the other REST/explorer backends or wire their standalone CLI.

Primary sources are the [Electrum fee method contract](https://electrumx.readthedocs.io/en/latest/protocol-methods.html),
released ElectrumX's [fee methods](https://github.com/spesmilo/electrumx/blob/1.16.0/electrumx/server/session.py)
and [compact histogram](https://github.com/spesmilo/electrumx/blob/1.16.0/electrumx/server/mempool.py),
and Bitcoin Core v29's distinct [fee estimator](https://github.com/bitcoin/bitcoin/blob/v29.0/src/policy/fees.cpp).
The acceptance helper checksum-pins the released histogram source and executes
only its unchanged compression method, retaining its license in the temporary
download. No production dependency is introduced.

```sh
python3 scripts/check_core_fees.py --bitcoind /path/to/bitcoin-29.0/bin/bitcoind
```

Native acceptance passes actual Core-signed 180-output funding, independent
validation of 180 standard witness spends with distinct real virtual sizes,
multiple large bins against the unchanged released compressor, a real RBF
replacement, rejected witness mutation, aged versus censored pending entries and
partial confirmations that distinguish 85%/95% modes. Quotes survive restart at
height 105, equal-work branches retain learning, a winning fork clears it, actual
restored spends relearn at height 107, and 145 subsequently validated blocks expire
the observations. Both implementations' real fees/pool sizes are compared; quote
expectations come from actual Core-derived rates and forced real confirmation
delays, never Rust responses. This accepts the tested empirical behavior, not
general prediction accuracy or the Core estimator's algorithm.

The final local gate passes 3,343 tests in 43 suites (two existing ignores),
formatting, Clippy, features and release build. Custom policy/relay reporting,
failed receipt transactions with unchanged publication, damaged/stale receipts
on reopen and unavailable REST-provider propagation pass. Two obsolete REST
mock successes were replaced by one explicit unavailable-provider regression;
the explorer forwards that failure. Initial gates caught misplaced regression
scope and the old explorer success expectation. Native follow-up kept all
assertions and used a 60-second Core invalidation deadline plus 25-block,
30-second mining batches after ten-second operation timeouts. Existing Core HTTP
acceptance and all eighteen envelope comparisons pass, with real insufficient-
estimate output through released `bitcoin-cli`; legacy missing-method cases use
an actually unknown method because fee estimation is now implemented.
No dependencies, lockfiles or ordinary consensus rules changed.
The existing Electrum native acceptance also passes all 260 wallet-query
comparisons, actual script-status races/notifications, 628 upstream checkpoint
comparisons, RBF/reorg/pool restoration and the 2016-header cap before/after the
height-2018 restart with fee receipts enabled.
