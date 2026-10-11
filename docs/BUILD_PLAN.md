# Autonomous build and repair plan

The user authorized reviewing and fixing this repository, replacing placeholder behavior, and setting up autonomous development. Priority is BIP transport and wallet cryptography. Proceed with routine implementation choices without requesting confirmation. Preserve existing user changes and test artifacts. The user also authorized keeping the working branch updated and prefers no pull requests: the agent performs review and verification. Automatic approval review rejected a proposed workflow that would publish directly to `main` and close the existing draft, because it requires explicit authorization beyond the working branch. Continue verified updates to `codex/review-bip-runtime-fixes` without creating or maintaining PRs while that authorization is pending. Do not force-push, integrate main, publish releases, deploy, or send external messages without separate authorization.

## Work loop

1. Read this plan and REVIEW.md, inspect Git status, and identify the highest-impact incomplete item.
2. Read the real implementation and the primary specification. Trace runtime callers; a module that works only in a self-test is not integrated.
3. Add a meaningful regression or authoritative vector and replace the underlying behavior, keeping proposed consensus changes out of normal network validation. Batch the coherent changes before running tests, as the user requested to save time.
4. Run verification and the repository gate after the batch stabilizes. Use focused follow-up checks for failures or unresolved concerns. Record what passed and what remains unsupported.
5. Review the final diff, commit each verified milestone, and push normally to `codex/review-bip-runtime-fixes`, preserving unrelated user changes. Do not create PRs or require user review. Keep this plan accurate and report meaningful results in the chat. Main integration and closing the initial draft await explicit authorization. Mark a task complete only when its acceptance condition is met. Stop recurring repair work when all required items below are complete; report actual unresolved external blockers.

## Implemented foundation

- [x] Real BIP324 crypto, packet vectors, rekeying, authenticated handshake, framed messages, and outbound node negotiation.
- [x] BIP352 sending, receiving, labels and official vectors; real address encoding and key validation.
- [x] Actual BIP325 virtual-transaction signature verification and corrected default challenge.
- [x] Taproot signature verification through the generic node path, with all prevouts.
- [x] Duplicate-input and intra-block UTXO state/undo regressions; tombstones and dirty-cache persistence.
- [x] Canonical wire decoding, BIP141 commitments, amount bounds, historical script activation, BIP68 time locks and BIP113 context.
- [x] BIP39 NFKD normalization; CLI RPC transport.
- [x] Pinned toolchain and lockfile; cross-platform CI, feature checks, audit and fuzz workflows; local check script and container build.
- [x] Shared validated RPC/sync backend with atomic block/history/UTXO commits, real regtest mining, stored chain queries, bounded RPC transport and clean stop/restart.

## Remaining runtime implementations

- [x] **P0: one validated chain backend for sync and RPC.** Node startup now shares a backend that executes header/structural/contextual/script/witness/Signet checks and commits headers, block bodies, transaction indices, UTXOs and the validated tip together before publication. Mining creates real regtest blocks; chain queries and mining statistics use stored data. Acceptance passed: RPC mining, mature P2PKH spend, invalid scripts/PoW rejected without changing coins or tip, reopening with the same balances and tip, reversed/interleaved P2P delivery visible to RPC, and actual compiled-node RPC mine/stop/restart. Full Core consensus parity remains the separate P1 task below.
- [ ] **P0: durable chain and UTXO checkpoint consistency.** The shared backend now persists header/body history and each validated block atomically with coins and tip. Injected commit-failure tests prove neither cache nor independent readers see failed writes, and retry succeeds. Add migration for legacy databases with tip/coins but no header history; startup currently rejects them explicitly and preserves their data. Acceptance: injected commit failure and restart between each persistence step cannot skip an unvalidated block or reuse a spent output, including legacy checkpoint migration.
- [ ] **P0: full block relay and reorg integration.** IBD now buffers reversed peer delivery and ignores unrequested blocks without advancing its completion count. Steady-state announcements still only log; the reorg helper operates on an in-memory view without updating the persistent backend. Request announced blocks/transactions and run the same validation path. Acceptance: two regtest branches, reorg, reconnect, and restart preserve correct spends and undo data.
- [ ] **P1: validate BIP34 coinbase construction and all transaction/block limits against Core.** Small heights now use OP_1..OP_16, miners/test harness share the encoder, and contextual rewards use network-specific halving intervals. Regtest activation defaults match Core v29. Complete sigops, scriptSig limits across every validator, locktime, BIP30 historical exceptions and preactivation differential coverage. Acceptance: explicit Core fixtures and differential coverage rather than permissive artificial fixtures.
- [ ] **P1: RPC/Electrum backend and protocol errors.** RPC now reads actual chain/body/transaction/coin data, returns errors for unavailable data/backends, bounds request buffers, propagates bind failures and stops without a new connection. Electrum's zero headers and made-up broadcasts still need replacement. Connect mempool and peer details, verbose transaction data, and RPC-origin block notifications to the live services. Acceptance: real RPC/Electrum roundtrip against shared state, rejection of malformed txs and unavailable data, shutdown without a new connection.
- [ ] **P1: LevelDB chainstate adapter.** Implement actual database opening/reads/import with Core XOR obfuscation, preserving height and coinbase metadata. Avoid modifying a live Core database; use a verified read-only snapshot. Acceptance: imported P2PKH, SegWit and Taproot outputs match Core and remain spendable after reopening our store.
- [ ] **P1: AssumeUTXO integrity and background validation.** Current background-validation TODOs must become a real second chainstate. Pin supported snapshot hashes and independently verify the advertised commitment; do not call the current custom hash a Core-compatible MuHash without vector parity. Acceptance: tampered snapshot fails, valid snapshot synchronizes, background validation joins it, and invalid history disables the snapshot chain.
- [ ] **P1: Erlay reconciliation.** Replace the sketch's retained full-set/local symmetric-difference shortcut with real finite-field PinSketch/minisketch serialization and decoding. Derive short IDs as specified, negotiate with peers and handle collisions/capacity failures. Acceptance: decode a sketch received from a separate process without access to that process's original set, plus official interoperability vectors.
- [ ] **P1: real stage data access.** Headers/Bodies/Execution/Indexing stages currently simulate records/progress. Connect them to actual providers and rollback transactions. Acceptance: checkpoints cannot advance without downloaded and validated data; indices resolve real txids/addresses and unwind a reorg.
- [ ] **P2: package relay.** Replace message byte placeholders with canonical BIP331 structures and bounded decoding. Keep draft protocol negotiation experimental until interoperability is demonstrated.
- [ ] **P2: devnet orchestration.** Replace the participants-shaped YAML with a valid Kurtosis package/main.star and an actual regtest block producer/peer topology. Acceptance: clean automated startup, block propagation, real RPC query, teardown, and a CI smoke run.
- [ ] **P2: standards-level wallet extensions.** Implement PSBT v2/Taproot fields and descriptor operations against authoritative vectors before adding MuSig2/PSBT extensions. Remove claims that exceed verified behavior.
- [ ] **P2: dependency maintenance.** Migrate QMDB's unmaintained bincode serialization with explicit format compatibility; keep patched lockfiles and audits current.

Test signatures, debugger markers and HTML input placeholders are legitimate test/UI data and do not require inventing production behavior. Static script resource estimates should explain their bounds rather than claim exact dynamic execution.

## Verification commands

`./scripts/check.sh` is the standard local gate. `cargo audit --deny unsound` checks dependencies. Run bounded fuzz smoke tests with `cargo +nightly fuzz run <target> -- -max_total_time=30 -rss_limit_mb=2048`. Verify external behavior against Bitcoin Core in regtest; do not use real funds for acceptance tests.

## Latest results

Final local verification on 2026-10-11:

- 3,329 tests passed, zero failed; two preexisting documentation examples remain ignored. Thirty-five tests that asserted fabricated RPC responses were replaced with backend errors and substantive node integration coverage.
- All 28 official BIP352 scenarios and all supplied BIP324 packet-vector rows pass.
- New regressions cover signature rejection, two-input Taproot commitments, witness commitments, monetary range, BIP68 time boundaries, block double-spends, intra-block connect/undo, dirty cache/tombstones, atomic block/tip persistence and injected commit failure/retry, reversed/interleaved local P2P block delivery visible to RPC, mature spending/restart, regtest subsidy/height boundaries, RPC request limits/stop/bind failures, and header fork height-index replacement.
- Workspace/all-feature Clippy passes. Machine-applicable lint fixes were applied; remaining nonfatal style/API warnings are still visible.
- Formatting and Git whitespace checks pass; primitives/network/storage build with default features disabled.
- Native release build and Linux Docker build pass; the container CLI help smoke test passes.
- The latest native binary passed an actual TCP RPC smoke run in a temporary regtest directory: mine three blocks, read stored blocks, return the stop response, exit cleanly, restart and recover the same tip. The shared-backend batch's container/remote CI will run on publication.
- Every fuzz target builds. Initial transaction-parser fuzz smoke completed 1,613,391 executions without a crash. The standalone fuzz lockfile was also updated to patched rand.
- Root RustSec audit reports zero vulnerabilities and zero unsound warnings; QMDB's unmaintained bincode warning remains.
- Hourly local repair is active in this chat as `btc-rust autonomous build and repair`. It follows the acceptance tasks above and stops when they are complete. Local execution requires the desktop app and computer to remain running.
- GitHub's Ubuntu/macOS build, audit, container and all eight fuzz checks passed for parser-repair commit `8a9454a`. Reject strings validate their declared length against available bytes before allocation, with direct/framed regressions. The P2P fuzzer completed 1,260,115 local executions in 31 seconds including the original CI crash seed without failure. Fuzz checks run on pushes as well as PRs.
- The workflow now uses agent review and verified working-branch updates without creating or maintaining PRs. Direct updates to `main` and closing the initial draft were rejected by automatic approval review and await explicit authorization.
