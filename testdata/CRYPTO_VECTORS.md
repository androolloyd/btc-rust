# Cryptographic fixture provenance

Downloaded on 2026-10-11 from the canonical bitcoin/bips repository:

- `bip324_packet_vectors.json`: lossless field conversion of [packet_encoding_test_vectors.csv](https://github.com/bitcoin/bips/blob/master/bip-0324/packet_encoding_test_vectors.csv). BIP324 is BSD-3-Clause.
- `bip352_vectors.json`: unchanged [send_and_receive_test_vectors.json](https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json). BIP352 is BSD-2-Clause.

These fixtures must remain independent expected values. Update them deliberately from the upstream source and rerun every case; do not regenerate expected cryptographic values from our implementation.

`core29_p2sh.json` retains all 17 plain non-WITNESS, P2SH-flagged cases with an exact BIP16 scriptPubKey from [Core v29 script_tests.json](https://github.com/bitcoin/bitcoin/blob/v29.0/src/test/data/script_tests.json) (MIT). Source SHA256: `195d1ae4c1701ffa4e4b0ac14ba2b451da0e73fb22292656cd0f2196a78010db`. Original zero-based row indices, flags, outcomes, scripts and comments are preserved. These cases run through the production input dispatcher with Core's credit/spend transaction context; they do not rely on the broad differential harness's separate P2SH implementation.

`core29_witness.json` preserves all 48 native/wrapped witness-v0 conditional cases (zero-based rows 1197..1247, excluding comment rows) from the same checksum-pinned Core v29 `script_tests.json` source as `core29_p2sh.json` (MIT). Each includes exact witness arguments, one-satoshi prevout amount, scriptSig/scriptPubKey, flags and expected result. The dispatcher regression uses the actual node verifier and hard-asserts each outcome; none of these cases enables the legacy CLEANSTACK policy flag. It includes nonminimal argument bytes accepted by consensus and MINIMALIF rejections under the explicit policy flag. It supplements direct extra-stack, empty-script, 520/521-byte and aggregate-argument regressions plus live Core transaction/block checks.
