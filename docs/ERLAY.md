# Experimental BIP330 sketch primitives

`btc_network::erlay` implements the sketch and salted short-ID primitives from
[BIP330](https://github.com/bitcoin/bips/blob/master/bip-0330.mediawiki).
It does not activate negotiated Erlay transaction relay. Normal node connections
continue using their existing INV/transaction handling.

The previous implementation stored the sender's original set and computed a
local symmetric difference. Its XOR buckets and capacity/bucket-count header
were incompatible with the specification. That code, its unsalted txid prefix,
fake negotiation flag, and inaccurate unused message structs have been removed.
The public API now returns explicit errors and operates on witness transaction
IDs. There were no runtime callers of the removed interfaces.

## Arithmetic and bounds

`Minisketch` stores only odd power sums over GF(2^32), with the modulus
`x^32 + x^7 + x^3 + x^2 + 1`. Capacity `c` serializes to exactly `4c` bytes,
with no additional header. Received bytes are sufficient for decoding: the
implementation reconstructs even syndromes, solves the error locator through
Berlekamp-Massey, reverses its coefficients and finds field roots. A Frobenius
test rejects repeated roots and factors outside the field. Deterministic basis
traces bound root splitting, and every successful result must reproduce all
received syndromes. The decoding algorithms carry the upstream reference's
MIT copyright/permission notice in the source.

The local capacity limit is 64, not a protocol limit. Deserialization checks
length and capacity before allocating. Capacity mismatches fail merge without
mutation. Zero elements are rejected. Adding an element twice cancels it; the
sketch cannot report the cardinality or original contents of the sender's set.
Sketch extensions concatenate additional power sums from the same snapshot.

Short IDs use sorted 64-bit little-endian peer salts, the BIP340 tagged hash
domain `Tx Relay Salting`, SipHash-2-4 of the internal-order **wtxid**, and
`1 + (hash mod 0xffffffff)`. The shared hash type currently cannot distinguish
txids from wtxids; API callers must supply the witness hash. `ReconciliationSet`
retains only the local ID-to-wtxid mapping, bounds it to 65,535 entries, and
fails explicitly if distinct local wtxids collide.

Decoding is guaranteed when the actual symmetric difference fits capacity.
Above capacity, sketches can alias smaller sets: a one-slot sketch of `[1,2]`
decodes to `[3]`, and `[1,2,3]` can decode empty. A successful decode therefore
does not authenticate the sender's original set. Cross-peer short-ID collisions
also cannot be detected from sketches alone. Complete relay needs normal
transaction validation, appropriate extension/fallback handling and collision
recovery; these are not replaced with a success flag.

## Compiled tooling and independent evidence

`btc-node --json erlay-sketch --capacity 8 --salt-a 12345 --salt-b 67890
--wtxid <display-order-wtxid>` constructs the real serialized primitive.
`btc-node --json erlay-reconcile <raw-skdata-hex> --salt-a 12345 --salt-b 67890
--wtxid <local-display-order-wtxid>` classifies its decoded difference against
the local snapshot. Repeat `--wtxid`; duplicate hashes are set members once.
These commands are offline experimental tooling, with `live_relay: false`.
Reconciliation also reports `original_difference_verified: false`. No missing
short ID is converted into a fabricated full transaction hash.

`scripts/generate_erlay_vectors.py` generates fixtures using the unchanged,
checksum-pinned [upstream minisketch Python reference](https://github.com/sipa/minisketch/blob/a12f5de1c96e21d76f64bc647ae4f65e4fc1b636/tests/pyminisketch.py)
and Bitcoin Core v29's SipHash implementation. These are **generated independent
reference cases**, not a claimed published official vector collection. The
fixture records source hashes. It covers constructed/arbitrary received
sketches, capacities 0 through 64, duplicates, overflow aliases, high field
bits, inverses/products, SipHash input lengths and salted short IDs, plus a real
independently found short-ID collision.

`scripts/check_erlay.py` exercises the compiled node against a separate
reference subprocess. Only peer sketch bytes and the receiver's local hashes
cross into Rust. Reverse-direction decoding uses upstream minisketch, including
sets larger than sketch capacity whose symmetric difference still fits.
The seeded sanitizer target is `fuzz_erlay`; the isolated `erlay` feature is
checked independently from compact-block support.

## Acceptance results

The final workspace gate passes 3,391 tests across 43 suites, formatting,
Clippy, minimal/isolated feature checks and release build (two preexisting
ignored tests). All 79 reference received-sketch classifications and 48 salted
IDs pass the compiled tools, including malformed-input and actual collision
rejection. Thirty-two bidirectional separate-process cases pass with capacities
1 through 64 and up to 1,000 common wtxids. Seventy-six independent temporary
seeds produced 10,102 sanitizer executions in 31 seconds without failure.

## Remaining acceptance

Peer negotiation must require BIP339, correct version/verack/relay ordering,
roles and supported versions. Canonical BIP330 messages, round snapshots,
capacity estimation, bounded extension/flooding recovery, dependency-ordered
INV announcements and long adversarial live sessions are unfinished. The BIP
remains a proposal: these primitive results do not claim complete Erlay
interoperability or enable new consensus rules.
