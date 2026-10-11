# Autonomous build and repair plan

The user authorized reviewing and fixing this repository, replacing placeholder behavior, and setting up autonomous development. Priority is BIP transport and wallet cryptography. Proceed with routine implementation choices without requesting confirmation. Preserve existing user changes and test artifacts. The user also authorized keeping the repository updated. Commit acceptance-tested changes and push them to `codex/review-bip-runtime-fixes`, maintaining its draft PR. Do not force-push, merge, publish releases, deploy, or send external messages without separate authorization.

## Work loop

1. Read this plan and REVIEW.md, inspect Git status, and identify the highest-impact incomplete item.
2. Read the real implementation and the primary specification. Trace runtime callers; a module that works only in a self-test is not integrated.
3. Reproduce the issue with a meaningful regression or authoritative vector. Replace the underlying behavior, keeping proposed consensus changes out of normal network validation.
4. Run focused verification, then the repository checks after the patch stabilizes. Record what passed and what remains unsupported.
5. Commit and push each verified milestone to the working branch, preserving unrelated user changes. Keep the draft PR description and this plan accurate. Mark a task complete only when its acceptance condition is met. Stop recurring repair work when all required items below are complete; report actual unresolved external blockers.

## Implemented foundation

- [x] Real BIP324 crypto, packet vectors, rekeying, authenticated handshake, framed messages, and outbound node negotiation.
- [x] BIP352 sending, receiving, labels and official vectors; real address encoding and key validation.
- [x] Actual BIP325 virtual-transaction signature verification and corrected default challenge.
- [x] Taproot signature verification through the generic node path, with all prevouts.
- [x] Duplicate-input and intra-block UTXO state/undo regressions; tombstones and dirty-cache persistence.
- [x] Canonical wire decoding, BIP141 commitments, amount bounds, historical script activation, BIP68 time locks and BIP113 context.
- [x] BIP39 NFKD normalization; CLI RPC transport.
- [x] Pinned toolchain and lockfile; cross-platform CI, feature checks, audit and fuzz workflows; local check script and container build.

## Remaining runtime implementations

- [ ] **P0: one validated chain backend for sync and RPC.** Replace submitblock's structural-only success and generatetoaddress's fabricated hashes. Both must execute complete validation, change the same authoritative chain/UTXO state, and persist it. getblockhash/getblockheader/template/mining statistics must read real headers and blocks. Acceptance: mine valid regtest blocks through RPC, spend a mature output, reject invalid scripts/PoW, restart, and confirm the same chain tip and balances.
- [ ] **P0: durable chain and UTXO checkpoint consistency.** Validated height/hash now commits atomically with UTXOs, JSON publication follows the commit, and resume uses the database tip. Add injected commit-failure/restart coverage and persisted header/body history; verify old checkpoint migration. Acceptance: injected commit failure and restart between each persistence step cannot skip an unvalidated block or reuse a spent output.
- [ ] **P0: full block relay and reorg integration.** IBD now buffers reversed peer delivery and ignores unrequested blocks without advancing its completion count. Steady-state announcements still only log; the reorg helper operates on an in-memory view without updating the persistent backend. Request announced blocks/transactions and run the same validation path. Acceptance: two regtest branches, reorg, reconnect, and restart preserve correct spends and undo data.
- [ ] **P1: validate BIP34 coinbase construction and all transaction/block limits against Core.** Reuse canonical CScript height encoding in every miner/test harness; cover small heights, sign-bit boundaries, sigops, scriptSig bounds, network-specific subsidy intervals, locktime, BIP30 historical exceptions, and preactivation behavior. Acceptance: explicit Core fixtures and differential coverage rather than permissive artificial fixtures.
- [ ] **P1: RPC/Electrum backend and protocol errors.** Remove default zero headers and made-up transaction broadcast acknowledgements. Use the real chain, index and mempool; unknown data produces a protocol error. Bound request buffers, correctly report bind failures, and implement clean shutdown. Acceptance: real RPC/Electrum roundtrip against shared state, rejection of malformed txs and unavailable data, shutdown without a new connection.
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

- 3,352 tests passed, zero failed; two preexisting documentation examples remain ignored.
- All 28 official BIP352 scenarios and all supplied BIP324 packet-vector rows pass.
- New regressions cover signature rejection, two-input Taproot commitments, witness commitments, monetary range, BIP68 time boundaries, block double-spends, intra-block connect/undo, dirty cache/tombstones, atomic tip persistence, and reversed/interleaved local P2P block delivery.
- Workspace/all-feature Clippy passes. Machine-applicable lint fixes were applied; remaining nonfatal style/API warnings are still visible.
- Formatting and Git whitespace checks pass; primitives/network/storage build with default features disabled.
- Native release build and Linux Docker build pass; the container CLI help smoke test passes.
- Every fuzz target builds. Initial transaction-parser fuzz smoke completed 1,613,391 executions without a crash. The standalone fuzz lockfile was also updated to patched rand.
- Root RustSec audit reports zero vulnerabilities and zero unsound warnings; QMDB's unmaintained bincode warning remains.
- Hourly local repair is active in this chat as `btc-rust autonomous build and repair`. It follows the acceptance tasks above and stops when they are complete. Local execution requires the desktop app and computer to remain running.
- The verified baseline is published on `codex/review-bip-runtime-fixes` in [draft PR #1](https://github.com/androolloyd/btc-rust/pull/1). GitHub build/verify and fuzz workflows are running; their outcome is pending. The hourly repair job is authorized to commit and push verified milestones to this branch and keep the PR current.
