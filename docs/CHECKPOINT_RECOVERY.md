# Legacy checkpoint recovery

Normal startup refuses an old database that records a non-genesis tip and coins
without the corresponding validated header/body history. A checkpoint does not
prove its coins or its chain. Recovery re-downloads and validates history from
the selected network's genesis:

```sh
./target/release/btc-node --network regtest --datadir /path/to/data \
  --connect 127.0.0.1:18444 run --resync-legacy-checkpoint
```

The option applies only to tip-only layouts with empty body/undo tables and
empty or genesis-only header/height tables. Existing non-genesis history follows
ordinary startup verification; a damaged partial history is not silently reset.
An orphan coin set without a committed tip, or coins attached to genesis, fails
startup. The option conflicts with loading an AssumeUTXO snapshot.

One redb transaction renames all ten known active tables to
`LegacyCheckpointV1.<original name>`, creates empty replacement tables, installs
the actual network genesis header/index/tip, and records the recovery genesis in
`LegacyCheckpointResyncV1`. Renaming retains the original raw bytes, including
coin metadata, pool entries and obsolete indices, without decoding those values
or copying the entire coin set into memory. Unrelated tables remain untouched.
Any error before commit aborts the whole transition. The archived tables remain
in the same database; recovery never deletes or restores them into active state.

The fresh backend creates its caches after the transaction commits. RPC and P2P
then use the existing full block validator and atomic persistence path. A
restart resumes at the freshly validated durable tip, including after abrupt
termination. Repeating the option leaves that progress and the archive intact.
It does not seek the old checkpoint hash or trust that checkpoint's height,
coins, pool, transaction records or indices. The validated chain may legitimately
diverge from the old checkpoint. Changing the selected network after recovery
is rejected using the receipt's genesis.

`getblockchaininfo.legacy_checkpoint_archive` returns the unverified original
height/hash, recovery genesis and `used_for_validation: false`; it is null for a
database without an archive. Ordinary chain fields always describe fresh
validated state. A second archive cannot overwrite an existing archive. The
raw archive is preserved for offline diagnosis; an automatic restore/export
command is outside this recovery scope.

Bitcoin Core v29's [initialization options](https://github.com/bitcoin/bitcoin/blob/v29.0/src/init.cpp)
and [chainstate loader](https://github.com/bitcoin/bitcoin/blob/v29.0/src/node/chainstate.cpp)
likewise rebuild unsupported chainstate from block history instead of granting
validation to an unsupported coin database. This project's tip-only format has
no usable block history, so it resynchronizes over the ordinary validated peer
path. This is a project-specific redb migration, not a Core LevelDB importer or
a verified AssumeUTXO snapshot. Broader consensus/full-chain parity remains a
separate acceptance item.

The regression suite injects an abort before every table rename/recreation and
before the atomic commit, reopens the database and compares all raw rows. The
Core acceptance command builds a real 102-block history with a wallet-signed
spend, seeds the old layout with that spent coin and stale indices/pool, checks
preservation, kills the recovering node after 37 validated blocks, and resumes
over v1 and v2 peers. It compares actual bodies and coin metadata, rejects reuse
of the spent coin, mines in both directions and restarts at height 104:

```sh
cargo build --release --locked --package btc-node --bin btc-node \
  --example legacy_checkpoint_fixture
python3 scripts/check_core_checkpoint.py --bitcoind /path/to/bitcoin-29.0/bin/bitcoind
```

The example is an acceptance-fixture writer/digest tool. It is not used by node
startup and does not validate or import production checkpoints.
