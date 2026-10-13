#!/usr/bin/env python3
"""Actual BIP152 peer checks using real funded Core regtest blocks/spends."""
import io
import socket
import struct

from check_core_p2p import core_rpc, rust_rpc, signed_wallet_spend, wait_for_tx_relay, wait_until, compact_size, sha256d
from core29_tapscript import reference


class WirePeer:
    """An explicit v1 protocol client for hostile completion/fallback checks."""
    def __init__(self, port, now):
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.socket.settimeout(40)
        version = struct.pack("<iQq", 70016, 9, now) + bytes(52) + struct.pack("<Q", 0x152330)
        agent = b"/bip152-acceptance/"
        self.send("version", version + compact_size(len(agent)) + agent + struct.pack("<iB", 0, 1))
        while True:
            command, _ = self.recv()
            if command == "version":
                self.send("wtxidrelay", b"")
                self.send("verack", b"")
            if command == "verack":
                break
        offered = self.next("sendcmpct")
        assert offered == b"\x00" + (2).to_bytes(8, "little")
        self.send("sendcmpct", offered)

    def close(self):
        self.socket.close()

    def read(self, size):
        data = bytearray()
        while len(data) < size:
            part = self.socket.recv(size - len(data))
            if not part:
                raise EOFError("peer closed")
            data.extend(part)
        return bytes(data)

    def recv(self):
        header = self.read(24)
        assert header[:4] == bytes.fromhex("fabfb5da")
        length = int.from_bytes(header[16:20], "little")
        assert length <= 4_000_000
        payload = self.read(length)
        assert sha256d(payload)[:4] == header[20:24]
        return header[4:16].rstrip(b"\x00").decode(), payload

    def next(self, wanted):
        while True:
            command, payload = self.recv()
            if command == "ping":
                self.send("pong", payload)
            elif command == wanted:
                return payload

    def send(self, command, payload):
        header = bytes.fromhex("fabfb5da") + command.encode().ljust(12, b"\x00")
        header += len(payload).to_bytes(4, "little") + sha256d(payload)[:4]
        self.socket.sendall(header + payload)

    def announce(self, block, m):
        self.send("headers", b"\x01" + m.CBlockHeader(block).serialize() + b"\x00")
        self.expect_block_request(4, block)

    def expect_block_request(self, kind, block):
        assert self.next("getdata") == b"\x01" + kind.to_bytes(4, "little") + block.sha256.to_bytes(32, "little")


def block_from_rpc(core_port, hash, m):
    raw = bytes.fromhex(core_rpc(core_port, "getblock", [hash, 0]))
    block = m.CBlock()
    block.deserialize(io.BytesIO(raw))
    block.rehash()
    return block


def compact(block, m, prefilled=None):
    result = m.HeaderAndShortIDs()
    result.initialize_from_block(block, nonce=0x0102030405060708, prefill_list=prefilled, use_witness=True)
    return result


def private_block(core_port, address, m, spends=1):
    coins = []
    for _ in range(spends):
        raw, coin = signed_wallet_spend(core_port)
        core_rpc(core_port, "sendrawtransaction", [raw])
        coins.append(coin)
    hash = core_rpc(core_port, "generatetoaddress", [1, address])[-1]
    return block_from_rpc(core_port, hash, m), coins


def hostile_checks(core_port, rust_port, p2p_port, clock, address, outbound):
    _, _, m = reference()
    core_rpc(core_port, "setnetworkactive", [False])
    wait_until(lambda: not rust_rpc(rust_port, "getpeerinfo", []))
    peer = None
    try:
        # Correct Core-funded blocks, but altered compact metadata must not
        # publish anything. Duplicate short IDs force full-block recovery.
        block, coins = private_block(core_port, address, m, spends=2)
        parent = rust_rpc(rust_port, "getbestblockhash", [])
        pool = rust_rpc(rust_port, "getrawmempool", [])
        peer = WirePeer(p2p_port, clock.now)
        peer.announce(block, m)
        data = compact(block, m)
        assert len(data.shortids) >= 2
        data.shortids[1] = data.shortids[0]
        peer.send("cmpctblock", data.to_p2p().serialize())
        peer.expect_block_request(0x40000002, block)
        assert rust_rpc(rust_port, "getbestblockhash", []) == parent
        assert rust_rpc(rust_port, "getrawmempool", []) == pool
        for coin in coins:
            assert rust_rpc(rust_port, "gettxout", [coin["txid"], coin["vout"], False]) is not None
        peer.send("block", block.serialize())
        wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == block.hash)
        assert rust_rpc(rust_port, "getblock", [block.hash, 0]) == block.serialize().hex()

        # Wrong blocktxn cardinality causes fallback, rather than partial commit.
        block, _ = private_block(core_port, address, m)
        parent = rust_rpc(rust_port, "getbestblockhash", [])
        peer.announce(block, m)
        peer.send("cmpctblock", compact(block, m).to_p2p().serialize())
        request = m.BlockTransactionsRequest(); request.deserialize(io.BytesIO(peer.next("getblocktxn")))
        assert request.to_absolute() == list(range(1, len(block.vtx)))
        peer.send("blocktxn", m.BlockTransactions(block.sha256, []).serialize())
        peer.expect_block_request(0x40000002, block)
        assert rust_rpc(rust_port, "getbestblockhash", []) == parent
        peer.send("block", block.serialize())
        wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == block.hash)

        # A real missing-transaction round also has a bounded response timeout.
        block, _ = private_block(core_port, address, m)
        parent = rust_rpc(rust_port, "getbestblockhash", [])
        peer.announce(block, m)
        peer.send("cmpctblock", compact(block, m).to_p2p().serialize())
        peer.next("getblocktxn")
        peer.expect_block_request(0x40000002, block)  # Withhold for the actual 30s timer.
        assert rust_rpc(rust_port, "getbestblockhash", []) == parent
        peer.send("block", block.serialize())
        wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == block.hash)
        peer.close(); peer = None

        # All transactions are prefilled: reconstruction succeeds structurally,
        # but a mutated witness MUST still fail the ordinary chain validator.
        original, coins = private_block(core_port, address, m)
        bad = m.CBlock()
        bad.deserialize(io.BytesIO(original.serialize()))
        witness = bytearray(bad.vtx[1].wit.vtxinwit[0].scriptWitness.stack[0])
        witness[-2] ^= 1
        bad.vtx[1].wit.vtxinwit[0].scriptWitness.stack[0] = bytes(witness)
        bad.nNonce += 100
        bad.solve()
        rejected = core_rpc(core_port, "submitblock", [bad.serialize().hex()])
        assert isinstance(rejected, str) and rejected not in ["duplicate", "duplicate-inconclusive"], rejected
        parent = rust_rpc(rust_port, "getbestblockhash", [])
        pool = rust_rpc(rust_port, "getrawmempool", [])
        peer = WirePeer(p2p_port, clock.now)
        peer.announce(bad, m)
        peer.send("cmpctblock", compact(bad, m, list(range(len(bad.vtx)))).to_p2p().serialize())
        try:
            while True:
                peer.recv()
        except EOFError:
            pass
        assert rust_rpc(rust_port, "getbestblockhash", []) == parent
        assert rust_rpc(rust_port, "getrawmempool", []) == pool
        for coin in coins:
            assert rust_rpc(rust_port, "gettxout", [coin["txid"], coin["vout"], False]) is not None
        peer.close(); peer = WirePeer(p2p_port, clock.now)
        peer.announce(original, m)
        peer.send("cmpctblock", compact(original, m).to_p2p().serialize())
        request = m.BlockTransactionsRequest(); request.deserialize(io.BytesIO(peer.next("getblocktxn")))
        peer.send("blocktxn", m.BlockTransactions(original.sha256, [original.vtx[i] for i in request.to_absolute()]).serialize())
        wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == original.hash)

        # Request a Rust-mined signed-spend block over the actual serving path,
        # reconstruct with unchanged Core helpers, and have Core validate it.
        raw, _ = signed_wallet_spend(core_port)
        rust_rpc(rust_port, "sendrawtransaction", [raw])
        hash = rust_rpc(rust_port, "generatetoaddress", [1, address])[-1]
        peer.send("getdata", b"\x01" + (4).to_bytes(4, "little") + bytes.fromhex(hash)[::-1])
        received = m.P2PHeaderAndShortIDs(); received.deserialize(io.BytesIO(peer.next("cmpctblock")))
        received = m.HeaderAndShortIDs(received); received.use_witness = True
        request = m.BlockTransactionsRequest(int(hash, 16)); request.from_absolute(list(range(1, len(received.shortids) + 1)))
        peer.send("getblocktxn", request.serialize())
        response = m.BlockTransactions(); response.deserialize(io.BytesIO(peer.next("blocktxn")))
        rebuilt = m.CBlock(received.header)
        rebuilt.vtx = [received.prefilled_txn[0].tx] + response.transactions
        rebuilt.rehash()
        reference_data = compact(rebuilt, m)
        reference_data.nonce = received.nonce
        reference_data.initialize_from_block(rebuilt, nonce=received.nonce, use_witness=True)
        assert received.shortids == reference_data.shortids
        assert rebuilt.serialize().hex() == rust_rpc(rust_port, "getblock", [hash, 0])
        assert core_rpc(core_port, "submitblock", [rebuilt.serialize().hex()]) is None
        assert core_rpc(core_port, "getbestblockhash", []) == hash
        print("BIP152 live hostile checks: duplicate IDs, malformed response, actual timeout, full-block recovery, witness rejection/unchanged state and Core-validated compact serving passed", flush=True)
    finally:
        if peer is not None:
            peer.close()
        core_rpc(core_port, "setnetworkactive", [True])
        if not outbound:
            core_rpc(core_port, "addnode", [f"127.0.0.1:{p2p_port}", "onetry", False])
        wait_until(lambda: len(rust_rpc(rust_port, "getpeerinfo", [])) == 1, timeout=60)


def check(core_port, rust_port, p2p_port, outbound, encrypted, clock, address):
    raw, _ = signed_wallet_spend(core_port)
    txid = core_rpc(core_port, "sendrawtransaction", [raw])
    # No trickle-clock advancement: the block arrives before this transaction
    # is in the receiver's pool, forcing a real getblocktxn/blocktxn round.
    assert txid not in rust_rpc(rust_port, "getrawmempool", [])
    hash = core_rpc(core_port, "generatetoaddress", [1, address])[-1]
    missing_hash = hash
    wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == hash)
    assert core_rpc(core_port, "getblock", [hash, 0]) == rust_rpc(rust_port, "getblock", [hash, 0])
    raw, _ = signed_wallet_spend(core_port)
    txid = rust_rpc(rust_port, "sendrawtransaction", [raw])
    wait_for_tx_relay(core_port, rust_port, clock, txid, from_core=False)
    hash = core_rpc(core_port, "generatetoaddress", [1, address])[-1]
    wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == hash)
    assert core_rpc(core_port, "getblock", [hash, 0]) == rust_rpc(rust_port, "getblock", [hash, 0])
    shared_hash = hash
    if not outbound and not encrypted:
        hostile_checks(core_port, rust_port, p2p_port, clock, address, outbound)
    print(f"BIP152 {'outbound' if outbound else 'inbound'} {'v2' if encrypted else 'v1'}: real missing-transaction and shared-mempool block rounds passed", flush=True)
    return missing_hash, shared_hash
