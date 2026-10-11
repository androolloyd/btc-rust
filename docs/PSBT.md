# PSBT wallet tools

The compiled `btc-node` CLI parses BIP174 v0 and BIP370 v2. Input/output arguments
are hexadecimal PSBT bytes; convert Core's base64 representation explicitly when
exchanging data with Core RPC.

```sh
btc-node --json decode-psbt "$PSBT_HEX"
btc-node --json convert-psbt "$PSBT_HEX" --version 2
btc-node --json convert-psbt "$PSBT_V2_HEX" --version 0
btc-node --json extract-psbt "$FINALIZED_PSBT_HEX"
```

Inspection reports the actual unsigned transaction, PSBT version, resolved
locktime, prevouts, sequences, output values/scripts, available UTXO/final fields
and signature counts. Taproot inspection also exposes internal keys, input merkle
roots, leaf scripts/control blocks, output trees and key-origin/leaf-hash records.
Paths are reported as the original u32 child indices, including hardened bits.
`unsigned_txid` identifies the transaction being signed;
BIP370's `psbt_id` uses zero sequences as required by its unique-identification
rule. The tools set `signatures_verified` to false: parsing and copying external
final fields do not prove that a transaction can spend its inputs. Submit extracted
transactions through the validated mempool or an independent validating node.
The tools do not sign, derive wallet keys, choose coins, or automatically finalize
partial signatures.

V2 serialization excludes the global unsigned transaction and includes transaction
version, counts, per-input prevouts, and per-output amounts/scripts. Optional
sequences default to final. Locktime uses the maximum common input requirement,
preferring height when both types are possible; incompatible requirements fail.
Unknown modification flag bits are preserved. Conversion keeps the transaction,
signatures, derivations and unknown/proprietary fields. V2 to v0 necessarily
collapses construction permissions and input locktime requirements into the fixed
transaction. V0 to v2 gives no new permission to modify that transaction.

The parser checks canonical CompactSize keys and lengths, unique raw keys in each
map, singleton key shapes, fixed field lengths, unsigned v0 transaction scripts,
v0/v2 inclusion/exclusion and required fields, and complete buffer consumption.
It bounds blobs by the bytes remaining before allocating, caps the input at 32 MiB,
and caps map count, total key/value pairs, final-witness item count, tree leaf count
and each Taproot derivation's hash count at 100,000.
These are local resource bounds, not Bitcoin consensus limits. Publicly assembled
models should use `try_serialize`, which returns errors for invalid models;
`serialize` retains the legacy infallible convenience API and panics for such
models. Combining malformed models fails before changing the receiver. Combining
different versions or v2 construction fields requires explicit reconciliation;
this combiner does not automatically change sequences or locktime requirements.

All BIP371 fields are typed, including input leaf scripts and input/output Taproot
BIP32 origins and output trees. X-only keys must be actual secp256k1 points. Control
blocks require `33 + 32*m` bytes with `m <= 128`, an on-curve internal key and a
leaf version matching the control byte. Derivation counts are canonical CompactSize
and bounded before allocation, with a complete fingerprint/path suffix. Output
trees require even leaf versions, depths at most 128, depth-first order and exactly
one complete root. Empty scripts and even future leaf versions remain metadata.
These records survive serialization, conversion and combining; known Taproot
records cannot bypass parsing through the unknown-field collection.

Parsing does not validate signature equations, sighash semantics, claimed key
derivations, merkle commitments against UTXOs or script satisfactions. Remaining
BIP174 curve/DER/key-origin and UTXO consistency checks, wallet signing/finalization,
descriptor operations and MuSig2 remain unfinished. Empty v2 creator maps can be
represented; converting an empty-input creator to v0 is rejected by the legacy
transaction decoder.

Independent acceptance uses all 47 published BIP370 format/locktime vectors in
`crates/primitives/tests/data/bip370.json`, including 24 invalid layouts and one
incompatible locktime. All 17 published BIP371 vectors (six valid, eleven invalid)
are in `crates/primitives/tests/data/bip371.json`, with source provenance and hex
cross-checked against the accompanying base64. Malformed-input regressions cover duplicate/unknown keys,
noncanonical/truncated key types, oversized lengths/counts, trailing data and
invalid public models. `scripts/check_core_psbt.py` creates and signs real SegWit
and Taproot key/script-path regtest spends with Core v29, converts signed and finalized PSBTs
through the compiled CLI, compares the extracted bytes and asks Core to validate
them. The script-path wallet uses a NUMS internal key and two real signing keys,
requiring a script-path witness; input controls/origins and output trees are checked
through the CLI. Core also decodes every published BIP371 case independently,
compares the CLI's controls, trees, leaf hashes, fingerprints and paths against
Core's inspection, and compares valid PSBTs before/after conversion. CI runs this with the checksum-verified
Core binary. The PSBT fuzz target checks arbitrary decoding plus canonical
serialization/conversion invariants, seeded with both BIP370 and BIP371 vectors.

Primary specifications: [BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki),
[BIP370 and its vectors](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki),
[BIP371](https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki),
and [Core v29 PSBT RPCs](https://github.com/bitcoin/bitcoin/blob/v29.0/src/rpc/rawtransaction.cpp).
