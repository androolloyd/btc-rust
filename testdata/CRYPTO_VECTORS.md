# Cryptographic fixture provenance

Downloaded on 2026-10-11 from the canonical bitcoin/bips repository:

- `bip324_packet_vectors.json`: lossless field conversion of [packet_encoding_test_vectors.csv](https://github.com/bitcoin/bips/blob/master/bip-0324/packet_encoding_test_vectors.csv). BIP324 is BSD-3-Clause.
- `bip352_vectors.json`: unchanged [send_and_receive_test_vectors.json](https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json). BIP352 is BSD-2-Clause.

These fixtures must remain independent expected values. Update them deliberately from the upstream source and rerun every case; do not regenerate expected cryptographic values from our implementation.
