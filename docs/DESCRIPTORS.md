# Public output descriptor expansion

The library `Descriptor::expand(index, network)` and compiled CLI produce actual
public scripts and addresses from supported descriptors:

```sh
btc-node --json --network regtest derive-descriptor "wpkh($ACCOUNT_TPUB/0/*)" --index 7
btc-node --json derive-descriptor "sh(wpkh($PUBLIC_KEY))"
btc-node --json derive-descriptor "tr($INTERNAL_XONLY,pk($LEAF_XONLY))"
btc-node --json derive-descriptor "tr($INTERNAL_XONLY,multi_a(2,$KEY_A,$KEY_B,$KEY_C))"
```

Checksums are optional on input and verified when supplied. Output includes a
checksummed descriptor, the exact scriptPubKey, an address when the script has a
supported address form, and any redeem/witness scripts. Bare `pk` and multisig
scripts have no corresponding address. `Descriptor::script_pubkey()` uses the
same implementation for fixed descriptors with mainnet address interpretation.
`Descriptor::parse()` builds a bounded structural representation; expansion
performs the key and script-context checks before returning a result.

Supported public expressions are `pk`, `pkh`, `wpkh`, `multi`, `sortedmulti`, `multi_a`, `sortedmulti_a`,
`sh`, `wsh`, `tr`, `addr` and `raw`. `sh` is top level; `wsh` and `wpkh` can be
top level or inside `sh`. Their inner script contexts are checked. Witness-v0
keys must be compressed. Bare multisig has at most three keys; P2SH uses the
actual 520-byte redeem-script bound, and witness multisig has at most twenty
keys. Threshold/count integers above sixteen use minimal script-number pushes.
`sortedmulti` sorts the actual serialized child keys after derivation.

Keys can be curve-valid compressed/uncompressed hex public keys, or standard
xpub/tpub keys matching the selected network, followed by nonhardened child
components and an optional final `/*`. All wildcards in one descriptor use the supplied index. A ranged descriptor
requires `--index`; a fixed descriptor rejects it. Child indices are below
2^31, and resulting BIP32 depth cannot exceed 255. Optional `[fingerprint/path]`
annotations are parsed as metadata and do not authenticate the key's origin.
Hardened suffixes, private extended keys and WIF keys fail explicitly; diagnostics
from the public-key resolver do not echo potential private material.
Extended-key text and legacy addresses accept only the actual ASCII Base58
alphabet. Unicode characters are never truncated into ASCII aliases. The shared
HD primitive permits a zero child tweak while retaining the required rejection
of out-of-range tweaks and infinite child points; the child chain code and header
still advance when its point equals the parent's point.

Taproot accepts x-only or compressed keys and key-path-only outputs or binary
trees of `pk`, `multi_a` and `sortedmulti_a` leaves. Threshold leaves use the
BIP387 CHECKSIG/CHECKSIGADD/NUMEQUAL script and support 1..999 keys with a
threshold from one through the key count. `sortedmulti_a` sorts the derived
x-only children. Thresholds use minimal signed-magnitude numbers, including
the sign-padding byte at 128. BIP387's 999-key maximum leaves room for the first
key push within BIP342's 1000-element stack limit. It applies the actual BIP341 tweak, leaf/branch hashes and
output parity. Results include the internal key, merkle root when present, leaf
scripts/hashes and complete control blocks, with a maximum tree depth of 128.
Uncompressed Taproot keys and unsupported leaf templates fail.

Untrusted input is bounded to 262,144 ASCII bytes and 132 delimiter nesting
levels before recursive parsing. Expansion bounds key expressions to 4,096 bytes,
1,024 total keys, 1,024 leaves and 10,000 CKDpub operations; raw scripts are at
most 10,000 bytes. These are explicit implementation limits, not new consensus
rules. Unsupported witness address versions fail explicitly; address parsing
uses the selected network. Errors return no partial expansion.

The CLI scope is `public_descriptor_scripts`. `key_origins_verified`,
`wallet_ownership_verified`, `signatures_verified` and `active_chain_verified`
remain false. No signer, wallet import/rescan, spending-key coverage or chain
admission is implied. General Miniscript, multipath, `combo`, `rawtr` and
private descriptor operations remain unfinished.

The independent fixture retains twenty public descriptors and twenty-four exact
scripts from the canonical BIP381/382/383/386 vectors, with source SHA256s and
licenses. Core acceptance separately compares checksums, addresses, multisig
limits and public descriptors for actual funded wallet outputs, including the
redeem/witness scripts and Taproot control proofs emitted by Core's PSBT updater.
Published xpub vectors also pass unchanged through the mainnet CLI. For Core's
regtest parser, only their extended-key version and Base58 checksum are converted
to tpub; curve keys, chain codes, origin/header metadata and expected scripts stay
unchanged. Wrong-network extended keys fail explicitly.

Threshold regressions retain four unchanged published BIP387 public outputs,
fifty-two Core reference-generated script/control commitments spanning one through
999 keys, and independently signed offline PSBTs. Synthetic outpoints establish
equations only. Live Core wallet acceptance separately funds and mines unsorted
and sorted 2-of-3, 17-of-20 and mixed-depth threshold/key-leaf spends, plus real
2-of-999, 128-of-128 and 999-of-999 spends. Text/key/derivation budgets still apply
to large descriptors; private and hardened-suffix expressions remain unsupported.

Primary definitions: [BIP380 key expressions/checksums](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki),
[BIP381 legacy contexts](https://github.com/bitcoin/bips/blob/master/bip-0381.mediawiki),
[BIP382 witness contexts](https://github.com/bitcoin/bips/blob/master/bip-0382.mediawiki),
[BIP383 multisig](https://github.com/bitcoin/bips/blob/master/bip-0383.mediawiki),
[BIP386 Taproot](https://github.com/bitcoin/bips/blob/master/bip-0386.mediawiki) and
[BIP387 threshold leaves](https://github.com/bitcoin/bips/blob/master/bip-0387.mediawiki),
[Core v29 descriptor parsing/expansion](https://github.com/bitcoin/bitcoin/blob/v29.0/src/script/descriptor.cpp).
