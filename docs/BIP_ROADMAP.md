# BIP review — 2026-10-11

The [canonical BIP index](https://github.com/bitcoin/bips/blob/master/README.mediawiki) is the status source. A specification marked Complete is not evidence of mainnet consensus activation. Recommendations below are based on repository gaps, rather than an instruction to activate new consensus rules.

| Priority | BIPs | Current upstream status | Repository work |
|---|---|---|---|
| Immediate | 324 | Deployed | Inbound/outbound transport implemented; Core v29 inbound/outbound v1/v2 handshakes, matching v2 session IDs, live block/transaction relay, initial sync, signed mempool/RBF admission, spend reorg/undo, reconnect and restart pass. Expand long-session, hostile-peer and additional-version coverage. |
| Immediate | 352 | Complete | Real address/sender/receiver vectors now pass; integrate wallet coin selection, scanning and backups. |
| Immediate | 325 | Complete | Real challenge verification implemented; replay public Signet blocks. |
| Next | 370, 371 | Deployed | PSBT v0/v2 parsing/conversion and external-final-field extraction now have all 47 BIP370 vectors and real Core v29 signed SegWit/Taproot CLI interoperability. Finish semantic BIP174/371 checks, remaining typed Taproot fields and wallet signing/finalization before MuSig2. |
| Next | 327, 373 | Deployed; Complete | MuSig2 and PSBT integration, including strict nonce lifecycle and malicious-participant vectors. |
| Follow | 374–376, 392 | Draft | DLEQ and silent-payment PSBT/descriptors after base wallet interoperability. |
| Follow | 353 | Complete | Authenticated DNS payment instructions and address-resolution errors. |
| Follow | 379, 389, 390 | Draft | Miniscript/multipath/musig descriptor parity and official compiler vectors. |
| Experimental | 54, 118, 119, 346–349, 360 | Complete or Draft; no activation inferred | Dedicated regtest experiments. Audit existing proposed opcode and ANYPREVOUT code against the exact current documents before advertising parity. |
| Protocol work | 330, 331 | Draft | Implement real reconciliation/package messages and explicit feature negotiation. |

Baseline deployed consensus correctness and backend integration precede new proposal implementation. BUILD_PLAN.md defines the outstanding acceptance tests.
