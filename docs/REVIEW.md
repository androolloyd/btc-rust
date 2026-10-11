# Repository review — 2026-10-11

This is an experimental implementation. A green unit suite does not establish Bitcoin Core consensus parity or make every advertised node feature operational. Remaining implementation work is tracked in [BUILD_PLAN.md](BUILD_PLAN.md).

## Fixed findings

- **P0 — Taproot signature bypass:** the generic witness dispatcher returned success for any nonempty Taproot witness. It now runs the real key/script-path verifier. Parallel block verification supplies every prevout required by BIP341; the regression proves a valid two-input signature fails when another prevout amount changes.
- **P0 — double spending:** block connection reused entries from the immutable external UTXO view. It now tracks all spent outpoints, rejecting duplicate inputs and cross-transaction double spends.
- **P0 — UTXO resurrection:** cached deletions fell through to the database before a flush. Tombstones now hide those entries immediately. Outputs created and spent within a block are omitted from forward state and undo restoration.
- **P1 — unsafe cache references:** read-through insertion could rehash a HashMap while earlier entry references remained live. The consensus UTXO API now returns owned entries; the persistent cache uses a mutex and bounded clean reads.
- **P1 — lost dirty outputs:** cache eviction discarded creations before persistence. Dirty entries remain pinned until a successful transaction commits. Failed writes retain the pending delta.
- **P1 — BIP141 commitments:** validation skipped coinbase-only witness, ignored commitments in otherwise legacy blocks, and substituted a zero nonce for malformed witness. It now checks any present commitment, requires one 32-byte reserved value, and rejects witness without a commitment. Mining templates generate the actual commitment.
- **P1 — checkpoint and delivery ordering:** validated tips commit with their UTXO delta, JSON checkpoints follow successful persistence, and restart checks the committed tip against the header chain. Reversed peer blocks are buffered and validated in height order; unrequested blocks cannot reduce the requested count. A local P2P regression covers both cases.
- **P1 — missing contextual checks:** sync now calls contextual UTXO validation and witness/Signet checks, without retrying consensus failures against a different UTXO view. BIP68 time locks and BIP113 finality receive ancestor median-time-past; script flags follow historical activation heights.
- **P1 — fake BIP324 cryptography:** replaced public-key hashing, publicly computable pseudo-ECDH, and pseudo-HKDF with libsecp256k1 ElligatorSwift XDH and HMAC-SHA256 HKDF. Packet length encryption, separate transport/application headers, command IDs, authenticated garbage, version exchange, and 224-packet rekeying match official vectors. The sync client negotiates encrypted transport and can reconnect using v1.
- **P1 — fake BIP352 cryptography and wrong addresses:** addresses now use a separate 5-bit version, validate curve keys, and encode the 66-byte key payload. Sender and receiver implement eligible input extraction, scalar/point aggregation, Taproot parity normalization, smallest serialized outpoint, actual ECDH points, labeled outputs, and grouped counters. All 28 official send/receive cases are checked.
- **P1 — fake Signet validation:** solution parsing now reads optional data from the selected coinbase commitment, constructs the two BIP325 virtual transactions, and executes the actual challenge. Corrected the default operator key; its derived network magic matches Core.
- **P1 — BIP39 Unicode seed mismatch:** passphrases and mnemonic text are normalized with NFKD before PBKDF2.
- **P1 — permissive decoding:** full-buffer decoding rejects trailing bytes, CompactSize rejects nonminimal forms, and transactions reject a superfluous witness record. Stream decoding remains composable. Two preexisting transaction fixtures contained an extra byte and were corrected.
- **P1 — monetary arithmetic:** block connection rejects invalid values and checked totals beyond MAX_MONEY rather than risking signed overflow or negative-output inflation.
- **Tooling:** fixed the all-feature FFI build, marked raw-pointer exports unsafe for Rust callers, routed legacy FFI through the input verifier, fixed fatal Clippy diagnostics, corrected the CLI RPC client, pinned Rust 1.88, included lockfiles, made the normal root build include btc-node, fixed the container build, and added CI and fuzz workflows.
- **Dependencies:** updated crossbeam-epoch, anyhow, and both rand release lines to patched compatible versions. QMDB still uses unmaintained bincode 1.3; replacing that serialization is a separate migration.

## Verification scope

The full workspace suite, official crypto vectors, feature-minimal checks, Clippy, formatting, native release build, container build, and bounded parser fuzz run are the intended completion checks. The detailed current results are recorded in BUILD_PLAN.md. External Core-to-node network interoperability, full-chain replay, restart/reorg behavior, and every placeholder backend are separate acceptance surfaces.

## API changes

`UtxoSet::get_utxo` returns an owned `UtxoEntry`. Silent payment APIs now require real input key/prevout information and return validation errors; the former pseudo-key API cannot produce interoperable payments. V2 decryption accepts complete packets including their encrypted length. Rust callers of raw-pointer FFI exports must use unsafe with valid buffers; the C ABI is unchanged.

## Primary references

- [Bitcoin Core serialization](https://github.com/bitcoin/bitcoin/blob/master/src/serialize.h)
- [BIP141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki), [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki), [BIP68](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki), [BIP113](https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki)
- [BIP324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki) and [packet vectors](https://github.com/bitcoin/bips/blob/master/bip-0324/packet_encoding_test_vectors.csv)
- [BIP352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki) and [send/receive vectors](https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json)
- [BIP325](https://github.com/bitcoin/bips/blob/master/bip-0325.mediawiki) and [Core Signet implementation](https://github.com/bitcoin/bitcoin/blob/master/src/signet.cpp)
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
