# HTTP RPC

The compiled node serves HTTP JSON-RPC on its existing loopback RPC port, using
the same validated chain/mempool backend as newline RPC and P2P. Each startup
creates a fresh `.cookie` in the selected data directory. Unix permissions are
0600; publication uses a synced private temporary file and an atomic rename.
The password comes from fallible OS randomness. Creation errors fail startup,
credentials are not logged, normal shutdown removes the owned cookie, and
restart rotates stale credentials. Replaced cookies are not removed by the old
owner. Windows uses inherited directory ACLs and replaces a stale destination
before starting the listener; Unix atomic replacement was acceptance-tested.

Released Bitcoin Core's client can query and mutate actual runtime state:

```sh
bitcoin-cli -regtest -rpcconnect=127.0.0.1 -rpcport=18443 \
  -rpccookiefile=/path/to/btc-rust-data/.cookie getblockchaininfo
```

The root `/` endpoint accepts authenticated POST with explicit Content-Length.
HTTP/1.0 closes after its response; HTTP/1.1 supports keepalive, pipelining and
authenticated `Expect: 100-continue`. Credentials are checked before allocating
or waiting for a body. Authentication uses Basic/Base64 with constant-time
credential comparison. Missing/wrong credentials return 401 and a Basic
challenge. HTTP is unavailable when an embedding creates `RpcServer` without
credentials. The production builder always configures a fresh cookie.

Transport bounds are 64 simultaneous clients, 16 KiB/64 header fields, an
8 MiB + 4096-byte request body, 128 operations per batch, 128-byte method names,
16 MiB of serialized response and 100 requests per keepalive. Reads/writes have
30-second deadlines per phase; shutdown wakes idle/partial clients. Duplicate
Content-Length, Authorization or Host, transfer coding, signed/comma lengths,
obs-fold, bare LF, truncated bodies and ambiguous frames fail before dispatch.
Errors close the connection; neither an HTTP body nor a later keepalive can
switch into newline dispatch. Chunked/compressed requests, arbitrary endpoints,
TLS, static password/rpcauth configuration and wallet endpoints are unsupported.

The wire adapter accepts JSON-RPC 2.0 and Core's legacy absent/null/1.0 marker.
Legacy replies include both result/error, with 400/404/500 RPC error statuses;
v2 method errors use HTTP 200 and an exclusive error/result field. Valid v2
notifications execute and return 204 without a JSON reply. Batches retain member
IDs/order, omit notification replies and use HTTP 200; an all-notification batch
uses 204, while an empty batch retains Core's `[]` compatibility behavior.
Malformed members get fresh envelope state instead of inheriting another
member's ID/version. Envelope parsing failures use explicit errors. Positional
parameters are supported; named objects return -32602 before a handler can
silently treat supplied values as absent. Broader named-parameter support and
verbose transaction/fee/Electrum implementations remain build-plan items. Fixed fake
fee estimates and the unused priority-delta map/getter were removed; these methods
now require a real backend, and the current node returns unsupported errors.

Batches execute sequentially and are not atomic transactions. Oversized batches
are rejected before any member runs. If actual output exceeds the response
budget, the server returns a bounded 503 error; previously executed members are
not rolled back. Use smaller batches when results can be large, and do not
blindly retry mutating batches.

Existing `btc-node rpc` and newline clients remain available on the same
loopback port. HTTP cookie authentication applies to HTTP; legacy newline TCP
still trusts local clients. This milestone does not claim authentication of that
legacy transport or complete Bitcoin Core RPC method/protocol parity.

Primary references are Core v29's [JSON-RPC interface](https://github.com/bitcoin/bitcoin/blob/v29.0/doc/JSON-RPC-interface.md),
[HTTP RPC dispatcher](https://github.com/bitcoin/bitcoin/blob/v29.0/src/httprpc.cpp)
and [cookie/request parser](https://github.com/bitcoin/bitcoin/blob/v29.0/src/rpc/request.cpp),
the [JSON-RPC specification](https://www.jsonrpc.org/specification), and
[RFC 9112 message framing](https://www.rfc-editor.org/rfc/rfc9112.html#name-message-body-length).

The native acceptance command uses released `bitcoin-cli`, real Core wallet
signatures and ordinary P2P block validation, alongside independent Core HTTP
envelope comparisons and hostile transport regressions:

```sh
python3 scripts/check_core_http.py --bitcoind /path/to/bitcoin-29.0/bin/bitcoind
```
