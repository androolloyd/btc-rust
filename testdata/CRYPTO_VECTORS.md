# Cryptographic fixture provenance

Downloaded on 2026-10-11 from the canonical bitcoin/bips repository:

- `bip324_packet_vectors.json`: lossless field conversion of [packet_encoding_test_vectors.csv](https://github.com/bitcoin/bips/blob/master/bip-0324/packet_encoding_test_vectors.csv). BIP324 is BSD-3-Clause.
- `bip352_vectors.json`: unchanged [send_and_receive_test_vectors.json](https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json). BIP352 is BSD-2-Clause.

These fixtures must remain independent expected values. Update them deliberately from the upstream source and rerun every case; do not regenerate expected cryptographic values from our implementation.

`crates/primitives/tests/data/bip32-child-tweaks.json` contains 45 independent
post-HMAC child arithmetic cases from `scripts/core29_bip32.py`. It uses unchanged,
checksum-pinned Core v29 curve code and public test secrets, with 23 valid and
22 invalid outcomes and exact public/private extended-child serialization.
Zero IL, small/high valid tweaks, order boundaries, cancellation, leading zeros,
different key parities/networks and depths through 254 are covered. Injected
IL/IR values exercise rare boundaries; they are explicitly not claimed HMAC
outputs from a real seed. Production always computes HMAC; the injection helpers
are private. The unchanged 17 published key pairs still independently test actual
seed/path/HMAC derivation, and the 16 published invalid records still fail.
The BIP32 fuzzer seeds both Base58 text and checksum-valid raw records, retaining
the invalid-checksum example as text rather than erasing its negative condition.
It also exercises three known legacy addresses and the preserved Unicode-alias
crash input. Base58 character policy follows [Core v29 base58.cpp](https://github.com/bitcoin/bitcoin/blob/v29.0/src/base58.cpp);
child arithmetic follows [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki),
[Core public derivation](https://github.com/bitcoin/bitcoin/blob/v29.0/src/pubkey.cpp)
and [Core private derivation](https://github.com/bitcoin/bitcoin/blob/v29.0/src/key.cpp).

`crates/primitives/tests/data/descriptors.json` retains twenty public-only
descriptor examples and twenty-four unchanged expected scripts from BIP381,
BIP382, BIP383 and BIP386. Source URLs, SHA256s and BSD-2-Clause licenses are
recorded in the fixture. Private/WIF examples were omitted, without rewriting
their keys into new expected values. Ranged descriptors retain all three
published child scripts. Live Core v29 acceptance separately compares public
descriptor checksums/addresses, context and multisig boundaries, and public
descriptors for funded outputs against Core's actual PSBT spending metadata.
Published xpubs are checked unchanged by the mainnet CLI; the regtest/Core
comparison changes only their network version and Base58 checksum to tpub,
preserving every cryptographic/header byte and independent expected script.

The public derivation proof regression reuses all 17 published points, xpub headers
and path indices in `crates/primitives/tests/data/bip32-keys.json`. Expected child
points are copied from the unchanged published serialization, rather than derived
by this implementation. `scripts/seed_psbt_derivations.py` independently serializes
17 unsigned metadata envelopes with input/output legacy/x-only records for sanitizer
and CI coverage; their outpoints are test data and carry no signatures or UTXOs.
Real Core wallet acceptance separately exports public descriptor account xpubs
and verifies 43 HD records across thirteen funded wallet cases, v0/v2 preservation,
changed-path rejection and explicit missing-anchor failure. Literal NUMS annotations
are retained in the original Core PSBTs and must fail complete proof verification;
only separately labeled HD-subset checks omit those optional opaque records.

`core29_sigops.json` contains 26 transaction/prevout cost cases and 19 opcode cases from `scripts/core29_sigops.py`, using the same checksum-pinned unchanged Core script, curve and wire modules. Expected counts come from Core's `CScript.GetSigOpCount`; legacy output costs use standard P2PKH and bare multisig scripts with real public fixture keys. The live harness checks independently funded consensus and policy boundaries, including 80,000/80,001 block costs, 16,000/16,001 transaction costs, P2SH 15/16, Taproot exclusion and exact sigop-adjusted fee/RPC-cap sizes. Large counter scripts are deliberately in skipped branches, while their pushed bytes and OP_N accurate/legacy distinctions have separate regressions. These are resource-count fixtures, not signature-equation claims. Primary definitions are [Core v29 transaction counts](https://github.com/bitcoin/bitcoin/blob/v29.0/src/consensus/tx_verify.cpp), [script counts](https://github.com/bitcoin/bitcoin/blob/v29.0/src/script/script.cpp), [witness counts](https://github.com/bitcoin/bitcoin/blob/v29.0/src/script/interpreter.cpp), [policy sizing](https://github.com/bitcoin/bitcoin/blob/v29.0/src/policy/policy.cpp) and [BIP141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki).

`core29_p2sh.json` retains all 17 plain non-WITNESS, P2SH-flagged cases with an exact BIP16 scriptPubKey from [Core v29 script_tests.json](https://github.com/bitcoin/bitcoin/blob/v29.0/src/test/data/script_tests.json) (MIT). Source SHA256: `195d1ae4c1701ffa4e4b0ac14ba2b451da0e73fb22292656cd0f2196a78010db`. Original zero-based row indices, flags, outcomes, scripts and comments are preserved. These cases run through the production input dispatcher with Core's credit/spend transaction context; they do not rely on the broad differential harness's separate P2SH implementation.

`core29_witness.json` preserves all 48 native/wrapped witness-v0 conditional cases (zero-based rows 1197..1247, excluding comment rows) from the same checksum-pinned Core v29 `script_tests.json` source as `core29_p2sh.json` (MIT). Each includes exact witness arguments, one-satoshi prevout amount, scriptSig/scriptPubKey, flags and expected result. The dispatcher regression uses the actual node verifier and hard-asserts each outcome; none of these cases enables the legacy CLEANSTACK policy flag. It includes nonminimal argument bytes accepted by consensus and MINIMALIF rejections under the explicit policy flag. It supplements direct extra-stack, empty-script, 520/521-byte and aggregate-argument regressions plus live Core transaction/block checks.

`core29_tapscript.json` contains 64 deterministic transaction/prevout cases generated by `scripts/core29_tapscript.py` from checksum-pinned Core v29 test-framework curve, signer, Taproot hash/commitment and wire implementations (MIT). The manifest pins every source file. Protocol code is imported unchanged; only three ordinary assertion/random-mutation utilities are extracted from Core's process-oriented util module. Offline outpoints and public fixture keys are explicitly test data. The vectors include exact independent digests/signatures and script/control proofs; undefined sighash bodies intentionally carry mathematically signed but consensus-invalid messages. Acceptance labels are checked separately against real funded Core v29 regtest blocks with correct commitments and PoW in the P2P harness. Cases cover empty keys, all three signature opcodes, empty/nonempty signature budgets, serialized-witness boundaries, known/unknown key types, minimal conditionals, skipped/active disabled multisig, executed/skipped/multiple separators, seven supported sighash modes, undefined types and script/key annex boundaries at 252/253 bytes. These comparisons do not establish all Core policy/consensus behavior.

`core29_scriptcode.json` contains 59 deterministic legacy/BIP143 transaction/prevout cases from `scripts/core29_scriptcode.py`, using the same checksum-pinned, unmodified Core signer/hash/wire modules. Each equation's exact scriptCode/digest is retained. Actual PUSHDATA1/2/4 widths (including empty pushes), executed/skipped/later/multiple separators, all six hash modes, and signatures for the former incorrect byte offset cover both P2SH and native P2WSH. Legacy checks in a real scriptSig verify minimal signature-push removal, repeated/skipped copies, CHECKMULTISIG/VERIFY removal of every signature before any equation, empty-signature OP_0 removal, and a corrupted multisig equation. Test keys/offline outpoints are fixture data; the live P2P harness funds the actual scripts and independently checks block and mempool-policy outcomes against released Core v29. Oversized P2SH redeem pushes deliberately fail while the same witness scripts remain valid. CONST_SCRIPTCODE is isolated from other policy flags in the ordinary regression and remains a policy flag, not a new block rule.

`core29_witness_policy.json` contains 70 deterministic cases from `scripts/core29_witness_policy.py`, using the same checksum-pinned unchanged Core curve, signer, hash, commitment and wire modules. Compressed/uncompressed signed P2SH/native/wrapped witness spends include ten exact independent ECDSA digests. Empty signatures exercise encoding shape separately from equation/curve verification, including multisig's visited-key order. Taproot cases cover future key types across signature opcodes, skipped keys, OP_SUCCESS decoding/argument precedence and real future-leaf commitments. Native/wrapped future witness programs and Core v29's native pay-to-anchor exception have separate interpreter expectations. The ordinary dispatcher regression compares consensus and both policy presets. Live wallet funding includes nonstandard future outputs in an independently validated real Core block; all 70 spending block outcomes and 69 specified mempool outcomes agree with released Core. Native anchor interpreter/block behavior is covered, but its mempool result is explicitly null because full TRUC/anchor policy is outside this milestone. Fixture keys/outpoints are public test data, not claimed active-chain records; live funding replaces them with actual wallet coins.

The Taproot resource expansion adds actual skewed trees at depth 0, 128 and 129, truncated maximum-depth controls, OP_SUCCESS/future-leaf depth precedence and nested/multiple ELSE cases. Core constructs real sibling leaf hashes and output curve points. Four additional live cases construct signed scripts with 250,000 nested levels (balanced true, skipped outer branch, inner ELSE and unbalanced). Those repeated megabytes are generated at runtime rather than stored in JSON. Both node and Core validate the same funded blocks; the 64 compact cases also run in the ordinary workspace gate. Conditional-state regression compares observable execution state to a simple boolean model over all 16,384 seven-step push/pop/toggle sequences.
