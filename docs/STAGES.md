# Validated stage backend

The production node runs its configured pipeline for each actual candidate block received through RPC, mining or inbound/outbound P2P synchronization. The existing bounded network downloader supplies real blocks. Passing a target height to an unbound pipeline does not download or validate anything and returns an explicit unavailable-provider error.

| Phase | Actual work before publication |
| --- | --- |
| Headers | Validate the supplied header against real ancestry, work, difficulty and time; prepare the fork-specific view when needed. |
| Bodies | Check the real body, merkle/witness commitments and context-free block limits. |
| Validation | Execute contextual transaction/script rules against actual external and same-block coins; prepare the real coin and checksummed undo delta. |
| TxIndex | Derive txids and block positions from the committed body. |
| AddressIndex | Derive touched-script history from actual outputs and executed spent coins, including same-block spends. |

Preparation is isolated. Every required phase must finish the supplied candidate before the backend commits. One redb transaction publishes body/header/transactions, undo, active transaction and script indexes, coins, fee observations, revalidated pool, active tip and the stage receipt. Caches, chain events and wallet notifications follow that successful commit. Errors discard prepared work and retain previously validated progress; they do not unwind the database to genesis.

The 76-byte `validated_stages_v1` receipt records the format, active height and actual block hash with a SHA256 checksum. `getstageinfo` reads it under the chain lock and verifies agreement with the active tip. All five phases share this atomic checkpoint. Their intermediate results are not separate independently advancing durable checkpoints.

Side branches retain their validated bodies and undo without advancing the canonical receipt. Equal-work branches retain the active selection. A greater-work branch disconnects and reconnects actual coin deltas and transaction/script rows in the same publication transaction. There is no height-only manual unwind: valid fork ancestry and checked undo are required.

On first adoption, an old complete body-history database is replayed through the real validator. Actual undo, existing transaction locations, script-index tip and the entire resulting coin set must agree before a stage receipt is written. Missing transaction rows are reconstructed from the completely validated bodies in the receipt transaction; conflicting rows fail. Legacy stage-generated address rows and numeric counters cannot authorize state. Replay is a full historical pass and can be expensive; it is not a fast-sync or public-chain qualification claim. Reopening an existing receipt checks its format/checksum and chain binding alongside existing chain/index integrity checks, rather than repeating signature execution on every startup.

The stage library now uses `StageBackend` and `Pipeline::run_with` for preparation/publication. Former synthetic header/body/undo records, height-shaped transaction/script identifiers and fake balance lookups have been removed. `Stage::execute`, unbound `Pipeline::run` and manual `Stage::unwind` explicitly fail without a real provider. Pipeline getters contain the last successful run in that pipeline instance; `getstageinfo` is the durable node view. Builders require the five ordered stages, and the node backend verifies that their actual preparation occurred before permitting commit.

Primary implementation evidence is [Bitcoin Core v29 validation](https://github.com/bitcoin/bitcoin/blob/v29.0/src/validation.cpp): `ProcessNewBlock`, `AcceptBlock`, `ConnectTip`, `DisconnectTip`, `ActivateBestChain` and mempool reconciliation use real bodies, contextual coin views and undo. This project reuses its existing validated backend and does not add consensus activation rules. Full historical consensus parity remains a separate acceptance item.

Local regressions cover absent providers, wrong actual targets, late preparation failure without body/coin/index/event publication, genuine old-body-store migration, corrupt/stale receipts, aborted receipt writes, and injected commit rollback with retry. The required Core fixtures also inspect all five checkpoints while importing actual blocks, rejecting invalid PoW/body/reward candidates, retaining equal-work forks, replacing a winning fork, executing real signed spends, and reopening real chain state. Acceptance results are recorded in BUILD_PLAN.md after verification.
