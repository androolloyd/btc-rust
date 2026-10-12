# PSBT wallet tools

The compiled `btc-node` CLI parses BIP174 v0 and BIP370 v2. Input/output arguments
are hexadecimal PSBT bytes; convert Core's base64 representation explicitly when
exchanging data with Core RPC.

```sh
btc-node --json decode-psbt "$PSBT_HEX"
btc-node --json convert-psbt "$PSBT_HEX" --version 2
btc-node --json convert-psbt "$PSBT_V2_HEX" --version 0
btc-node --json extract-psbt "$FINALIZED_PSBT_HEX"
btc-node --json verify-psbt "$FINALIZED_PSBT_HEX"
btc-node --json verify-psbt "$PARTIALLY_SIGNED_PSBT_HEX" --partial
btc-node --json finalize-psbt "$PARTIALLY_SIGNED_PSBT_HEX"
```

Inspection reports the actual unsigned transaction, PSBT version, resolved
locktime, prevouts, sequences, output values/scripts, available UTXO/final fields
and signature counts. Taproot inspection also exposes internal keys, input merkle
roots, leaf scripts/control blocks, output trees and key-origin/leaf-hash records.
Paths are reported as the original u32 child indices, including hardened bits.
Input/output `bip32_derivation` arrays also expose legacy public-key origins.
`global_xpub_records` includes the Base58 and serialized extended public key,
depth, parent fingerprint, child number, public key and claimed master origin;
`global_xpubs` retains the existing count.
Input `utxo` reports the supplied amount/script and its source, or null when absent.
`txid_linked` means a full parent transaction hashes to the referenced txid; it does
not mean the output has been confirmed or is currently unspent. Witness-only
records have `txid_linked: false` and remain claims from the updater.
`unsigned_txid` identifies the transaction being signed;
BIP370's `psbt_id` uses zero sequences as required by its unique-identification
rule. Decode, convert and extract set `signatures_verified` to false: parsing and copying external
final fields do not prove that a transaction can spend its inputs. Submit extracted
transactions through the validated mempool or an independent validating node.
The tools do not create signatures, derive wallet keys or choose coins.
Inspection exposes the declared `sighash_type`, per-key partial-signature types,
the Taproot key-signature type and script-signature key/leaf/type records.
An implicit 64-byte Taproot signature reports type zero (DEFAULT).

`verify-psbt` evaluates the final transaction's spending conditions with the node's
real ECDSA/Schnorr verifier and all supplied prevouts. It supports P2PKH/P2PK and
bare canonical multisig, legacy P2SH with those known redeem templates,
native/wrapped P2WPKH, native/wrapped P2WSH with P2PK,
P2PKH or canonical multisig scripts, Taproot key paths, and version-c0 single-key
`<32-byte key> CHECKSIG` Taproot leaves. An annex is included in the Taproot digest.
Arbitrary witness/tapscript programs, future witness/leaf/key versions,
OP_SUCCESS and signature-free scripts return explicit errors. This bounded wallet
scope prevents consensus forward-compatibility success from becoming a signature
verification claim; ordinary node consensus rules are unchanged.

Every input needs final fields and a resolved UTXO. Legacy inputs additionally
require a txid-linked full parent; witness-only legacy amounts cannot establish
the fee because legacy signatures do not commit to them. Final signature types
must be defined and match a retained declaration. ECDSA signatures require strict
DER and low S, and witness-v0 public keys are compressed. Wrapped witness scriptSigs
must be canonical single pushes. Known scripts/controls and actual signature
equations must succeed for every input. Duplicate/null inputs, excessive weight,
out-of-range totals and outputs exceeding supplied values fail as well.

On success, `spending_conditions_verified` and `signatures_verified` are true;
`signatures_checked` counts real successful equations. `tx_hex` is the verified
transaction and `fee_sat` is the difference of supplied values.
`verification_scope` is `finalized_spends_against_supplied_prevouts` and
`txid_linked_prevouts` reports full-parent linkage per input. Witness-only values
remain supplied claims, particularly for other inputs under ANYONECANPAY.
`partial_signatures_verified` and `active_chain_verified` remain false: unused
partial records and key origins are not verified, and this offline command does
not establish confirmation, unspentness, maturity, chain finality, activation at
a historical height, mempool fee/standardness policy or full Core consensus parity.
Submit the verified transaction through a validating node for chain admission.

`verify-psbt --partial` checks every supplied partial ECDSA, Taproot key and
Taproot script signature before finalization. Each input must be unfinalized,
have a resolved UTXO and contain at least one partial signature. It binds ECDSA
keys to the known P2PKH/P2PK/multisig script, using the exact legacy or BIP143
scriptCode and supplied amount. Native/wrapped witness-v0 templates and legacy
P2SH with known key/multisig redeem scripts are supported. Legacy inputs still
require full parent transactions; the witness-only amount attack is rejected.
Missing redeem/witness scripts, unrelated keys and unsupported templates fail.
Taproot key signatures verify against the actual output key Q. Each script
signature must name a supplied, committed version-c0 single-key CHECKSIG leaf
and its actual key; unknown leaf hashes or missing controls/scripts fail.
All prevouts enter the BIP341 digest where required. This mode uses no annex and
no OP_CODESEPARATOR, because its supported partial-record context has neither.
Finalized inputs are rejected; annex-bearing final witnesses belong to the
separate final-spend verification path.

On success, partial mode sets `partial_signatures_verified` and
`signatures_verified` to true, reports `signatures_checked` and
`signatures_per_input`, and returns `unsigned_tx_hex`/`unsigned_txid`.
It never returns broadcast transaction bytes. The scope is
`partial_signatures_against_supplied_prevouts`; `spending_conditions_verified`,
`final_fields_verified`, `key_origins_verified` and `active_chain_verified` remain
false. One valid signature in a 2-of-2 multisig verifies successfully while the
transaction remains incomplete. This operation is read-only: it neither signs
nor finalizes inputs. Full key-origin proofs, arbitrary script satisfaction,
wallet signing and chain admission remain separate work.

`finalize-psbt` assembles complete spends from supplied signatures for the same
known templates. It verifies every supplied partial record, including excess
multisig signatures and signatures for unselected Taproot leaves. Multisig uses
the script's key order and requires the full threshold; a valid incomplete set
returns an error. Taproot prefers a complete key path, otherwise the smallest
serialized witness for a supported signed leaf, with deterministic Core-compatible
ties. Wrapped witness uses an exact redeem-program push; legacy/witness multisig
includes its empty CHECKMULTISIG dummy. No annex or separator context is invented
for partial records. Existing final inputs are preserved and verified, enabling
mixed partial/final transactions and idempotent finalization.

The final transaction passes the actual shared spend verifier before the result
is returned. Present sighash declarations are checked before cleanup. BIP174/371
cleanup removes known signing metadata, keeping UTXOs, final fields and opaque
unknown/proprietary input records. BIP370 construction/locktime fields and global
modification flags survive; output/global metadata remains unchanged. Failure
does not mutate the input PSBT or return partially finalized bytes.

Success returns `complete: true`, cleaned `psbt_hex`, verified `tx_hex`, fee and
scope/linkage fields. `signatures_checked` counts final-spend equations;
`partial_signatures_checked` and `partial_signatures_per_input` count all supplied
partial equations, including unused records. Both partial and final verification
flags are true, including the vacuous check of zero partial records on already
finalized inputs. Key-origin and active-chain verification remain false. These
are offline supplied-prevout checks; broadcast still requires chain/policy
admission. This command creates no signatures or wallet secrets. General script
satisfaction, HD origin proofs, signing and active-chain wallet integration remain
unfinished.

Finalizer references: [BIP174 Input Finalizer](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#input-finalizer),
[BIP370 retained construction fields](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#input-finalizer),
[BIP371 Taproot cleanup](https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki),
and [Core v29 signature assembly and path selection](https://github.com/bitcoin/bitcoin/blob/v29.0/src/script/sign.cpp).

V2 serialization excludes the global unsigned transaction and includes transaction
version, counts, per-input prevouts, and per-output amounts/scripts. Optional
sequences default to final. Locktime uses the maximum common input requirement,
preferring height when both types are possible; incompatible requirements fail.
Unknown modification flag bits are preserved. Conversion keeps the transaction,
signatures, derivations and unknown/proprietary fields. V2 to v0 necessarily
collapses construction permissions and input locktime requirements into the fixed
transaction. V0 to v2 gives no new permission to modify that transaction.
When partial signatures use SIGHASH_SINGLE, conversion sets the v2 pairing flag.
V2 partial signatures forbid input modification unless ANYONECANPAY is set,
forbid output modification unless NONE is used, and require the SINGLE pairing
flag when applicable. Unknown flag bits are retained.

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

Supplied non-witness transactions must match the input txid (excluding parent
witness data), and the referenced output must exist. If both UTXO forms are
provided, their amounts and scripts must agree exactly. Supplied prevout amounts
are range checked in both wire parsing and public models. Known input and output
redeem scripts must match P2SH HASH160 commitments; witness scripts must match
native or wrapped P2WSH SHA256 programs. Incomplete inputs can omit UTXOs, and a
P2SH input can omit its redeem script; checks depending on absent data are deferred.
Contradictory data fails parsing, serialization, conversion, extraction and an
isolated combine result before the receiver changes. These checks apply at the
tool boundary even to BIP174 examples which are structurally valid but fail the
Signer role's script checks. This does not implement a signer.

Legacy partial-signature and input/output BIP32 record keys must use compressed
or uncompressed encodings of actual secp256k1 points. Global xpubs use BIP32's
78-byte layout, compressed curve keys and standard xpub/tpub version bytes.
Unsupported custom versions and private-key versions fail explicitly. A master
extended key must have zero parent fingerprint and child number; the standalone
BIP32 private/public decoders enforce this as well. A global xpub's origin path
length must match its depth and its final index must match the header's child
number. The master fingerprint must agree where directly known: the key's own
fingerprint at depth zero or the parent fingerprint at depth one. At greater
depths it remains a claim without the missing master ancestor. These consistency
checks neither establish the full derivation nor link every input/output origin
to a global xpub. Compressed/uncompressed keys retain their original encoding.

All BIP371 fields are typed, including input leaf scripts and input/output Taproot
BIP32 origins and output trees. X-only keys must be actual secp256k1 points. Control
blocks require `33 + 32*m` bytes with `m <= 128`, an on-curve internal key and a
leaf version matching the control byte. Derivation counts are canonical CompactSize
and bounded before allocation, with a complete fingerprint/path suffix. Output
trees require even leaf versions, depths at most 128, depth-first order and exactly
one complete root. Empty scripts and even future leaf versions remain metadata.
These records survive serialization, conversion and combining; known Taproot
records cannot bypass parsing through the unknown-field collection.

Taproot leaves use BIP341 tagged TapLeaf/TapBranch hashing, lift the control's
internal key on secp256k1 and apply the actual TapTweak scalar. Every supplied
control must agree on internal key/root and declare the resulting output parity.
Supplied internal-key/root fields must agree with those proofs. When a UTXO is
available, the computed output key must match its native P2TR program. An explicit
internal-key/root pair is also checked without leaf scripts. Complete output trees
are reconstructed and, with an internal key, checked against the transaction's
output key. Taproot fields on known non-Taproot inputs/outputs are rejected.

Missing data remains incomplete: an omitted root/tree can describe unrevealed
scripts, and an omitted UTXO cannot establish which output is spent. An internal
key alone is not assumed to mean a key-only output. Commitment checks needing that
data are deferred. These public commitments do not prove signature equations,
key derivations, confirmation, unspentness or script satisfaction. Sorted branch
hashing permits exchanging complete sibling subtrees without changing the root.

Partial ECDSA signature records require strict DER, nonzero scalars below the
curve order and one of the six defined legacy sighash bytes. High S remains
representable and is preserved; this parser does not impose low-S policy.
Taproot records require 64 bytes for DEFAULT, or 65 bytes with a defined nonzero
type. Their r must be below the BIP340 field modulus and s below the curve order.
Explicit DEFAULT, unsupported/draft types and out-of-range values fail.
Present partial signatures must match a declared type exactly, including the
distinction between Taproot DEFAULT and ALL. Known non-Taproot inputs cannot use
DEFAULT, and known Taproot inputs cannot carry ECDSA partial signatures. Taproot
SINGLE signatures require a corresponding output. Combining complementary
records validates these relationships before changing the receiver.

These checks validate encoding and metadata consistency. Parsing does not
validate signature equations, complete sighash context, full claimed key
derivations or script satisfactions. Remaining
BIP174/371 general-script/annex context and full key-origin verification, witness-only legacy signing restrictions,
active-chain/unspentness checks, wallet signing and generalized finalization,
descriptor operations and MuSig2 remain unfinished. Empty v2 creator maps can be
represented; converting an empty-input creator to v0 is rejected by the legacy
transaction decoder.

Independent acceptance uses all 47 published BIP370 format/locktime vectors in
`crates/primitives/tests/data/bip370.json`, including 24 invalid layouts and one
incompatible locktime. All 17 published BIP371 vectors (six valid, eleven invalid)
are in `crates/primitives/tests/data/bip371.json`, with source provenance and hex
cross-checked against the accompanying base64. Malformed-input regressions cover duplicate/unknown keys,
noncanonical/truncated key types, oversized lengths/counts, trailing data and
invalid public models. `bip174-utxo.json` contains eight nonempty valid-format
examples and all three published signer-script-mismatch examples, with source
provenance and hex/base64 agreement. `scripts/check_core_psbt.py` creates and signs
real P2PKH, P2SH-P2WPKH, P2WPKH, P2WSH, P2SH-P2WSH and Taproot key/script-path
regtest spends with Core v29, converts signed and finalized PSBTs
through the compiled CLI, compares the extracted bytes and asks Core to validate
them. The finalizer additionally matches Core's exact final bytes in v0/v2 across
twelve funded spend types and 26 hash-mode variants, preserves cleanup/unknown
records, and submits Rust-assembled transactions for actual Core admission/mining.
2-of-3 multisig has three valid partial records in reversed wire order; corrupting
even the unselected one fails our explicit all-record verification. Unequal-depth
Taproot leaves test the smallest serialized witness independently; equal-size
leaves test deterministic selection. Mixed final/partial two-input Taproot spends
remain valid, while corrupted existing final signatures fail. The script-path
wallet uses a NUMS internal key and two real signing keys,
requiring a script-path witness; input controls/origins and output trees are checked
through the CLI. Core also decodes every published BIP371 case independently,
compares the CLI's controls, trees, leaf hashes, fingerprints and paths against
Core's inspection, and compares valid PSBTs before/after conversion. CI runs this with the checksum-verified
Core binary. The PSBT fuzz target checks arbitrary decoding plus canonical
serialization/conversion invariants, seeded with BIP174, BIP370, BIP371 and BIP341-wrapper cases.
Full-parent inspection matches Core's active UTXO amounts/scripts; substituted
parents, conflicting UTXOs and altered input/output scripts are rejected through
all CLI tools. Valid signed and finalized records keep identical transaction bytes.

`bip32-keys.json` retains all 17 valid public/private key pairs from BIP32 vectors
1–4 and all 16 invalid extended keys from vector 5, with source hashes. Derivation
from the published seeds and paths must match the exact extended key bytes,
including leading zeros. Independently serialized PSBT wrappers carry the public
keys and origins; these have no UTXOs/signatures and make no spendability claim.
The fixture also retains three published BIP174 malformed-key cases, for 27 PSBT
cases in total. The compiled tools reject substituted off-curve keys and altered
depth/index/fingerprint records. Core independently checks curve/extended-key
encoding and valid conversion data; its PSBT decoder preserves custom version
bytes and does not bind origin paths to headers, so those stricter supported-version
and origin checks are reported separately. Core-signed legacy/witness spends
also exercise input/output key substitution. The fuzzer includes these envelopes.

`bip341-commitments.json` retains all seven published scriptPubKey commitment cases,
with exact tweaks, output keys, leaf hashes, roots and twelve control proofs,
including an even future leaf version. It also contains independently constructed
PSBT wrappers used by the compiled CLI, Core decoding/conversion comparison and
the fuzzer. These wrappers have test-only witness UTXO claims and no signatures;
they do not claim a spendable or active-chain transaction. Real Core script-path
spends provide independent signature/finalization/acceptance evidence. Mutated
roots, internal keys, control parities, leaf scripts, merkle paths and output trees
fail the actual tools. Tagged commitment hashing is shared with the existing
consensus verifier through primitives; consensus rules are unchanged.

Primary specifications: [BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki),
[BIP32 and its vectors](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki),
[BIP370 and its vectors](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki),
[BIP371](https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki),
[BIP341 and wallet vectors](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki),
and [Core v29 PSBT RPCs](https://github.com/bitcoin/bitcoin/blob/v29.0/src/rpc/rawtransaction.cpp).

`psbt-signatures.json` retains 20 single-push Core v29 DER/STRICTENC/LOW_S cases
and all 19 BIP340 signature bodies, with source hashes and 58 independently
serialized PSBT envelopes. Numeric encoding validity is kept separate from
BIP340 equation verification; encodings of wrong-key/message signatures remain
representable. Core's PSBT decoder is more permissive about partial signatures
than its script validator, and those differences are explicit in acceptance.
Real Core-signed legacy, witness-v0 and Taproot key/script spends cover the six
defined ECDSA and seven Taproot types, including DEFAULT, NONE, SINGLE and
ANYONECANPAY. Metadata/encoding substitution fails the compiled tools; unchanged
valid signatures survive conversion and independent Core finalization/admission.
Final scriptSig/witness fields remain opaque external records. Their signature
encoding, declared-type agreement and equations are not verified by extraction.
The separate `verify-psbt` command checks those properties for supported templates.

Final-spend references: [BIP174 Extractor and retained UTXOs](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#transaction-extractor),
[BIP143 amount and script commitments](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki),
[BIP341 all-prevout and annex commitments](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki),
[BIP342 future success/key semantics](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki),
and [Core v29 finalized PSBT verification](https://github.com/bitcoin/bitcoin/blob/v29.0/src/psbt.cpp).

Signature references: [BIP66 strict DER](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki),
[BIP340 vectors](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv),
[Core v29 script vectors](https://github.com/bitcoin/bitcoin/blob/v29.0/src/test/data/script_tests.json),
and the BIP174/BIP341/BIP370 signing rules linked above.
