#!/usr/bin/env python3
"""Check inbound/outbound v1/v2 relay, reconnect and restart against Core v29.

Requires a checksum-verified bitcoind binary; uses disposable data directories
and loopback connections, with discovery disabled on both regtest nodes. Core's
regtest clock is advanced during transaction relay waits so privacy trickling
does not make acceptance depend on unbounded random wall-clock delays.
"""
import argparse
import base64
import hashlib
from io import BytesIO
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


class WaitTimeout(RuntimeError):
    pass


def wait_until(check, timeout=30, description="condition", on_retry=None):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = check()
            if value:
                return value
            last = value
        except (OSError, ValueError, RuntimeError) as error:
            last = error
        if on_retry is not None:
            on_retry()
        time.sleep(0.05)
    raise WaitTimeout(f"{description} timed out: last observation: {last}")


def free_port(span=1, excluded=()):
    for _ in range(100):
        held = []
        try:
            first = socket.socket()
            first.bind(("127.0.0.1", 0))
            held.append(first)
            port = first.getsockname()[1]
            if port + span > 65536 or any(value in excluded for value in range(port, port + span)):
                continue
            for offset in range(1, span):
                other = socket.socket()
                held.append(other)
                other.bind(("127.0.0.1", port + offset))
            return port
        except OSError:
            pass
        finally:
            for item in held:
                item.close()
    raise RuntimeError("no available port range")


def core_rpc(port, method, params, timeout=10):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{port}/", data=payload)
    request.add_header("Authorization", "Basic " + base64.b64encode(b"interop:regtest-only").decode())
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        result = json.load(response)
    if result.get("error"):
        raise RuntimeError(result["error"])
    return result["result"]


def rust_rpc(port, method, params):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        connection.sendall((json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}) + "\n").encode())
        with connection.makefile("rb") as reader:
            result = json.loads(reader.readline(8 * 1024 * 1024 + 4096))
    if result.get("error"):
        raise RuntimeError(result["error"])
    return result["result"]


class CoreClock:
    """Drive Core's actual regtest relay scheduler without relaxing validation.

    Core v29 net_processing.cpp uses exponentially distributed 5s/2s inventory
    intervals and mockable GetTime. Freeze time from process startup, then move
    it one second per retry. Retain the wall-clock timeout and cap advancement
    below the two-hour future-block bound of the real-time Rust validator.
    """
    def __init__(self, port):
        self.port = port
        self.initial = self.now = int(time.time())

    def advance(self):
        if self.now - self.initial >= 3600:
            raise RuntimeError("Core relay test clock exceeded its one-hour bound")
        self.now += 1
        core_rpc(self.port, "setmocktime", [self.now])


def relay_snapshot(core_port, rust_port):
    snapshot = {}
    for node, port, rpc in [("Core", core_port, core_rpc), ("Rust", rust_port, rust_rpc)]:
        snapshot[node] = {}
        for method in ["getbestblockhash", "getrawmempool", "getpeerinfo"]:
            try:
                snapshot[node][method] = rpc(port, method, [])
            except (OSError, ValueError, RuntimeError) as error:
                snapshot[node][method] = str(error)
    return json.dumps(snapshot, sort_keys=True)


def wait_for_tx_relay(core_port, rust_port, clock, txid, from_core):
    source = core_rpc if from_core else rust_rpc
    target = rust_rpc if from_core else core_rpc
    source_port, target_port = (core_port, rust_port) if from_core else (rust_port, core_port)
    direction = "Core -> Rust" if from_core else "Rust -> Core"
    assert txid in source(source_port, "getrawmempool", []), f"{direction}: missing source transaction {txid}"
    try:
        wait_until(lambda: txid in target(target_port, "getrawmempool", []),
                   description=f"{direction} mempool relay of {txid}", on_retry=clock.advance)
    except RuntimeError as error:
        raise RuntimeError(f"{error}; mocktime={clock.now}; {relay_snapshot(core_port, rust_port)}") from error


def signed_wallet_spend(core_port, coin=None, fee=0.00002):
    # Core supplies a real mature wallet coin and independently signs SegWit.
    if coin is None:
        coins = core_rpc(core_port, "listunspent", [100])
        assert coins, "expected a mature Core wallet coin"
        coin = coins[0]
    address = core_rpc(core_port, "getnewaddress", ["", "bech32"])
    amount = round(coin["amount"] - fee, 8)
    raw = core_rpc(core_port, "createrawtransaction", [[{"txid": coin["txid"], "vout": coin["vout"]}], {address: amount}])
    signed = core_rpc(core_port, "signrawtransactionwithwallet", [raw])
    assert signed["complete"] is True
    return signed["hex"], coin


def runtime_script_addresses(core_port):
    root = next(d["desc"] for d in core_rpc(core_port, "listdescriptors", [True])["descriptors"]
                if d["active"] and not d["internal"] and d["desc"].startswith("wpkh("))
    key = root.split("#")[0][5:-1]
    assert key.endswith("/0/*")
    nums = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    addresses = {}
    for kind, descriptor in {
        "p2sh": f"sh(multi(2,{key},{key[:-4]}/1/*))",
        "p2wsh": f"wsh(pk({key}))",
        "taproot": f"tr({nums},pk({key}))",
    }.items():
        checksum = core_rpc(core_port, "getdescriptorinfo", [descriptor])["checksum"]
        descriptor += "#" + checksum
        imported = core_rpc(core_port, "importdescriptors", [[{"desc": descriptor, "timestamp": "now", "range": [0, 1]}]])
        assert all(item["success"] for item in imported)
        addresses[kind] = core_rpc(core_port, "deriveaddresses", [descriptor, [0, 0]])[0]
    return addresses


def compact_size(n):
    if n < 253:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def replace_legacy_script(raw, replacement):
    # These independent Core-produced spends have one legacy input. Preserve
    # every transaction field other than its scriptSig and CompactSize length.
    data = bytes.fromhex(raw)
    assert data[4] == 1
    length_pos = 4 + 1 + 36
    size = data[length_pos]
    size_bytes = 1
    if size == 253:
        size = int.from_bytes(data[length_pos + 1:length_pos + 3], "little")
        size_bytes = 3
    assert size < 0x10000
    suffix = length_pos + size_bytes + size
    return (data[:length_pos] + compact_size(len(replacement)) + replacement + data[suffix:]).hex()


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def check_p2sh_runtime(core_port, rust_port, p2p_port, outbound, encrypted, clock, address, multisig):
    funding = core_rpc(core_port, "sendtoaddress", [multisig, 1.0])
    wait_for_tx_relay(core_port, rust_port, clock, funding, from_core=True)
    funded_tip = core_rpc(core_port, "generatetoaddress", [1, address])[-1]
    wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == funded_tip)
    coin = next(coin for coin in core_rpc(core_port, "listunspent", [1]) if coin["txid"] == funding and coin["address"] == multisig)
    raw, _ = signed_wallet_spend(core_port, coin)
    decoded = core_rpc(core_port, "decoderawtransaction", [raw])
    script = bytes.fromhex(decoded["vin"][0]["scriptSig"]["hex"])
    assert script[0] == 0  # CHECKMULTISIG dummy
    first_len = script[1]
    assert 9 <= first_len <= 73
    second_pos = 2 + first_len
    second_len = script[second_pos]
    assert 9 <= second_len <= 73
    redeem_pos = second_pos + 1 + second_len
    bad_script = bytearray(script); bad_script[2 + first_len - 2] ^= 1
    corrupted = replace_legacy_script(raw, bad_script)
    missing = replace_legacy_script(raw, b"\x00\x00\x00" + script[redeem_pos:])
    nonpush = replace_legacy_script(raw, b"\x61" + script)
    for bad in [corrupted, missing, nonpush]:
        before = rust_rpc(rust_port, "getrawmempool", [])
        assert core_rpc(core_port, "testmempoolaccept", [[bad]])[0]["allowed"] is False
        assert rust_rpc(rust_port, "testmempoolaccept", [[bad]])[0]["allowed"] is False
        try:
            rust_rpc(rust_port, "sendrawtransaction", [bad])
        except RuntimeError as error:
            assert error.args[0]["code"] == -26
        else:
            raise AssertionError("Rust accepted an invalid P2SH signature/script")
        assert rust_rpc(rust_port, "getrawmempool", []) == before
        assert rust_rpc(rust_port, "gettxout", [coin["txid"], coin["vout"], False])["value"] == coin["amount"]
    expected = core_rpc(core_port, "testmempoolaccept", [[raw]])[0]
    actual = rust_rpc(rust_port, "testmempoolaccept", [[raw]])[0]
    assert expected["allowed"] == actual["allowed"] is True
    assert expected["vsize"] == actual["vsize"] and expected["fees"]["base"] == actual["fees"]["base"]
    txid = rust_rpc(rust_port, "sendrawtransaction", [raw])
    wait_for_tx_relay(core_port, rust_port, clock, txid, from_core=False)
    # Keep Core at the funded parent while Rust mines the valid spend. An
    # invalid competing block must exceed Core's current work to trigger its
    # script checks, rather than merely becoming an unchecked equal-work body.
    core_rpc(core_port, "setnetworkactive", [False])
    wait_until(lambda: not rust_rpc(rust_port, "getpeerinfo", []))
    valid_tip = rust_rpc(rust_port, "generatetoaddress", [1, address])[-1]
    block = bytes.fromhex(rust_rpc(rust_port, "getblock", [valid_tip, 0]))
    txids = rust_rpc(rust_port, "getblock", [valid_tip])["tx"]
    assert len(txids) == 2 and txids[1] == txid and block.endswith(bytes.fromhex(raw))
    coinbase_hash = bytes.fromhex(txids[0])[::-1]
    assert block[36:68] == sha256d(coinbase_hash + sha256d(bytes.fromhex(raw)))
    header = bytearray(block[:80])
    header[36:68] = sha256d(coinbase_hash + sha256d(bytes.fromhex(corrupted)))
    bits = int.from_bytes(header[72:76], "little")
    target = (bits & 0x7fffff) << (8 * ((bits >> 24) - 3))
    for nonce in range(1_000_000):
        header[76:80] = nonce.to_bytes(4, "little")
        if int.from_bytes(sha256d(header), "little") <= target:
            break
    else:
        raise AssertionError("regtest PoW search exhausted")
    bad_block = (header + block[80:-len(bytes.fromhex(raw))] + bytes.fromhex(corrupted)).hex()
    for port, rpc, tip in [(core_port, core_rpc, funded_tip), (rust_port, rust_rpc, valid_tip)]:
        coin_before = rpc(port, "gettxout", [coin["txid"], coin["vout"], False])
        rejected = rpc(port, "submitblock", [bad_block])
        assert isinstance(rejected, str) and "script" in rejected.lower(), rejected
        assert rpc(port, "getbestblockhash", []) == tip
        assert rpc(port, "gettxout", [coin["txid"], coin["vout"], False]) == coin_before
    core_rpc(core_port, "setnetworkactive", [True])
    if not outbound:
        core_rpc(core_port, "addnode", [f"127.0.0.1:{p2p_port}", "onetry", encrypted])
    wait_until(lambda: core_rpc(core_port, "getbestblockhash", []) == valid_tip, timeout=60)
    assert core_rpc(core_port, "getblock", [valid_tip, 0]) == block.hex()
    assert core_rpc(core_port, "getrawmempool", []) == rust_rpc(rust_port, "getrawmempool", []) == []


def read_compact_size(data, pos):
    first = data[pos]
    width = {253: 2, 254: 4, 255: 8}.get(first, 0)
    if not width:
        return first, pos + 1
    return int.from_bytes(data[pos + 1:pos + 1 + width], "little"), pos + 1 + width


def witness_transaction_parts(raw):
    data = bytes.fromhex(raw)
    assert data[4:6] == b"\x00\x01"
    count, pos = read_compact_size(data, 6)
    assert count == 1
    for _ in range(count):
        pos += 36
        size, pos = read_compact_size(data, pos)
        pos += size + 4
    outputs, pos = read_compact_size(data, pos)
    for _ in range(outputs):
        pos += 8
        size, pos = read_compact_size(data, pos)
        pos += size
    witness_pos = pos
    count, pos = read_compact_size(data, pos)
    items = []
    for _ in range(count):
        size, pos = read_compact_size(data, pos)
        items.append(data[pos:pos + size])
        pos += size
    assert pos + 4 == len(data)
    base = data[:4] + data[6:witness_pos] + data[-4:]
    return data[:witness_pos], items, data[-4:], base


def replace_witness(raw, items):
    prefix, _, locktime, _ = witness_transaction_parts(raw)
    return (prefix + compact_size(len(items)) + b"".join(compact_size(len(item)) + item for item in items) + locktime).hex()


def check_witness_runtime(core_port, rust_port, p2p_port, outbound, encrypted, clock, address, destination, kind):
    funding = core_rpc(core_port, "sendtoaddress", [destination, 1.0])
    wait_for_tx_relay(core_port, rust_port, clock, funding, from_core=True)
    funded_tip = core_rpc(core_port, "generatetoaddress", [1, address])[-1]
    wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == funded_tip)
    coin = next(c for c in core_rpc(core_port, "listunspent", [1]) if c["txid"] == funding and c["address"] == destination)
    raw, _ = signed_wallet_spend(core_port, coin)
    _, items, _, base = witness_transaction_parts(raw)
    assert len(items) == (3 if kind == "taproot" else 2)
    malformed = [replace_witness(raw, [extra] + items) for extra in [b"", b"\x01", bytes(521)]]
    if kind == "p2wpkh":
        # Same curve equation, but a redundant leading zero violates BIP66.
        signature = bytearray(items[0])
        assert signature[0] == 0x30 and signature[2] == 2
        signature[1] += 1
        signature[3] += 1
        signature.insert(4, 0)
        malformed.append(replace_witness(raw, [bytes(signature)] + items[1:]))
    for bad in malformed:
        # Preserve the unsigned transaction. Added arguments keep every
        # signature/script/proof; the DER mutation preserves its curve equation.
        assert witness_transaction_parts(bad)[3] == base
        before = rust_rpc(rust_port, "getrawmempool", [])
        assert core_rpc(core_port, "testmempoolaccept", [[bad]])[0]["allowed"] is False
        assert rust_rpc(rust_port, "testmempoolaccept", [[bad]])[0]["allowed"] is False
        try:
            rust_rpc(rust_port, "sendrawtransaction", [bad])
        except RuntimeError as error:
            assert error.args[0]["code"] == -26
        else:
            raise AssertionError(f"Rust accepted invalid {kind} witness stack")
        assert rust_rpc(rust_port, "getrawmempool", []) == before
        assert rust_rpc(rust_port, "gettxout", [coin["txid"], coin["vout"], False])["value"] == coin["amount"]
    expected = core_rpc(core_port, "testmempoolaccept", [[raw]])[0]
    actual = rust_rpc(rust_port, "testmempoolaccept", [[raw]])[0]
    assert expected["allowed"] == actual["allowed"] is True
    assert expected["vsize"] == actual["vsize"] and expected["fees"]["base"] == actual["fees"]["base"]
    txid = rust_rpc(rust_port, "sendrawtransaction", [raw])
    wait_for_tx_relay(core_port, rust_port, clock, txid, from_core=False)
    core_rpc(core_port, "setnetworkactive", [False])
    wait_until(lambda: not rust_rpc(rust_port, "getpeerinfo", []))
    valid_tip = rust_rpc(rust_port, "generatetoaddress", [1, address])[-1]
    block = bytes.fromhex(rust_rpc(rust_port, "getblock", [valid_tip, 0]))
    txids = rust_rpc(rust_port, "getblock", [valid_tip])["tx"]
    assert len(txids) == 2 and txids[1] == txid and block[80] == 2 and block.endswith(bytes.fromhex(raw))
    original_coinbase = block[81:-len(bytes.fromhex(raw))]
    assert witness_transaction_parts(original_coinbase.hex())[1] == [bytes(32)]
    original_commitment = sha256d(sha256d(bytes(32) + sha256d(bytes.fromhex(raw))) + bytes(32))
    for bad in malformed:
        # Rebuild both commitments and PoW. A changed witness with an unchanged
        # commitment would only test the block commitment check, not execution.
        new_commitment = sha256d(sha256d(bytes(32) + sha256d(bytes.fromhex(bad))) + bytes(32))
        old_script = bytes.fromhex("6a24aa21a9ed") + original_commitment
        assert original_coinbase.count(old_script) == 1
        coinbase = original_coinbase.replace(old_script, bytes.fromhex("6a24aa21a9ed") + new_commitment)
        coinbase_id = sha256d(witness_transaction_parts(coinbase.hex())[3])
        header = bytearray(block[:80])
        header[36:68] = sha256d(coinbase_id + sha256d(base))
        bits = int.from_bytes(header[72:76], "little")
        target = (bits & 0x7fffff) << (8 * ((bits >> 24) - 3))
        for nonce in range(1_000_000):
            header[76:80] = nonce.to_bytes(4, "little")
            if int.from_bytes(sha256d(header), "little") <= target:
                break
        else:
            raise AssertionError("regtest PoW search exhausted")
        bad_block = (header + b"\x02" + coinbase + bytes.fromhex(bad)).hex()
        for port, rpc, tip in [(core_port, core_rpc, funded_tip), (rust_port, rust_rpc, valid_tip)]:
            coin_before = rpc(port, "gettxout", [coin["txid"], coin["vout"], False])
            rejected = rpc(port, "submitblock", [bad_block])
            assert isinstance(rejected, str) and "script" in rejected.lower(), (kind, rejected)
            assert rpc(port, "getbestblockhash", []) == tip
            assert rpc(port, "gettxout", [coin["txid"], coin["vout"], False]) == coin_before
    core_rpc(core_port, "setnetworkactive", [True])
    if not outbound:
        core_rpc(core_port, "addnode", [f"127.0.0.1:{p2p_port}", "onetry", encrypted])
    wait_until(lambda: core_rpc(core_port, "getbestblockhash", []) == valid_tip, timeout=60)
    assert core_rpc(core_port, "getblock", [valid_tip, 0]) == block.hex()
    assert core_rpc(core_port, "getrawmempool", []) == rust_rpc(rust_port, "getrawmempool", []) == []
    print(f"PASSED: {kind} valid relay/mining and invalid witness transaction/block rejection", flush=True)


def check_taproot_execution(core_port, rust_port, p2p_port, clock, address):
    from core29_tapscript import cases, output, spend, reference
    _, _, m = reference()
    tests = cases()
    addresses = {}
    for case in tests:
        info = output(case)
        descriptor = f"rawtr({info.output_pubkey.hex()})"
        descriptor += "#" + core_rpc(core_port, "getdescriptorinfo", [descriptor])["checksum"]
        addresses[case["name"]] = core_rpc(core_port, "deriveaddresses", [descriptor])[0]
    funding = core_rpc(core_port, "sendmany", ["", {a: 1.0 for a in set(addresses.values())}])
    wait_for_tx_relay(core_port, rust_port, clock, funding, from_core=True)
    funded_tip = core_rpc(core_port, "generatetoaddress", [1, address])[-1]
    wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == funded_tip)
    funded = core_rpc(core_port, "decoderawtransaction", [core_rpc(core_port, "gettransaction", [funding])["hex"]])
    coins = {v["scriptPubKey"]["address"]: v for v in funded["vout"] if "address" in v["scriptPubKey"]}
    destination = bytes.fromhex(core_rpc(core_port, "getaddressinfo", [address])["scriptPubKey"])
    core_rpc(core_port, "setnetworkactive", [False])
    wait_until(lambda: not rust_rpc(rust_port, "getpeerinfo", []))
    # Keep Rust one block ahead: all case bodies are equal-work siblings on
    # Rust, but win on Core and therefore force Core to execute every script.
    rust_tip = rust_rpc(rust_port, "generatetoaddress", [1, address])[-1]
    empty = bytes.fromhex(rust_rpc(rust_port, "getblock", [rust_tip, 0]))
    assert empty[80] == 1
    for case_index, case in enumerate(tests):
        coin = coins[addresses[case["name"]]]
        amount = round(coin["value"] * 100_000_000)
        tx, previous, _ = spend(case, funding, coin["n"], amount, destination)
        assert previous.scriptPubKey.hex() == coin["scriptPubKey"]["hex"]
        raw = tx.serialize()
        if not case["allowed"]:
            assert core_rpc(core_port, "testmempoolaccept", [[raw.hex()]])[0]["allowed"] is False
            assert rust_rpc(rust_port, "testmempoolaccept", [[raw.hex()]])[0]["allowed"] is False
            try:
                rust_rpc(rust_port, "sendrawtransaction", [raw.hex()])
            except RuntimeError as error:
                assert error.args[0]["code"] == -26, (case["name"], error)
            else:
                raise AssertionError(f"invalid Taproot transaction admitted: {case['name']}")
            assert rust_rpc(rust_port, "getrawmempool", []) == []
        coinbase = m.CTransaction()
        coinbase.deserialize(BytesIO(empty[81:]))
        coinbase.wit.vtxinwit = [m.CTxInWitness()]
        coinbase.wit.vtxinwit[0].scriptWitness.stack = [bytes(32)]
        commitment = sha256d(sha256d(bytes(32) + sha256d(raw)) + bytes(32))
        coinbase.vout.append(m.CTxOut(0, bytes.fromhex("6a24aa21a9ed") + commitment))
        header = bytearray(empty[:80])
        header[36:68] = sha256d(sha256d(coinbase.serialize_without_witness()) + sha256d(tx.serialize_without_witness()))
        bits = int.from_bytes(header[72:76], "little")
        target = (bits & 0x7fffff) << (8 * ((bits >> 24) - 3))
        # Distinct nonce ranges also distinguish intentionally identical
        # transactions after Core invalidates a previous valid sibling.
        nonce_start = case_index * 1_000_000
        for nonce in range(nonce_start, nonce_start + 1_000_000):
            header[76:80] = nonce.to_bytes(4, "little")
            if int.from_bytes(sha256d(header), "little") <= target:
                break
        else:
            raise AssertionError("regtest PoW search exhausted")
        body = (header + b"\x02" + coinbase.serialize() + raw).hex()
        block_hash = sha256d(header)[::-1].hex()
        before = rust_rpc(rust_port, "gettxout", [funding, coin["n"], False])
        result = core_rpc(core_port, "submitblock", [body])
        if case["allowed"]:
            assert result is None, (case["name"], result)
            assert core_rpc(core_port, "getbestblockhash", []) == block_hash
            assert core_rpc(core_port, "gettxout", [funding, coin["n"], False]) is None
            core_rpc(core_port, "invalidateblock", [block_hash])
            assert core_rpc(core_port, "getbestblockhash", []) == funded_tip
        else:
            assert isinstance(result, str) and "script" in result.lower(), (case["name"], result)
            assert core_rpc(core_port, "getbestblockhash", []) == funded_tip
        actual = rust_rpc(rust_port, "submitblock", [body])
        if case["allowed"]:
            assert actual is None, (case["name"], actual)
            assert rust_rpc(rust_port, "getblock", [block_hash, 0]) == body
        else:
            assert isinstance(actual, str) and "script" in actual.lower(), (case["name"], actual)
        assert rust_rpc(rust_port, "getbestblockhash", []) == rust_tip
        assert rust_rpc(rust_port, "gettxout", [funding, coin["n"], False]) == before
        assert rust_rpc(rust_port, "getrawmempool", []) == []
    core_rpc(core_port, "setnetworkactive", [True])
    core_rpc(core_port, "addnode", [f"127.0.0.1:{p2p_port}", "onetry", False])
    wait_until(lambda: core_rpc(core_port, "getbestblockhash", []) == rust_tip, timeout=60)
    assert core_rpc(core_port, "getblock", [rust_tip, 0]) == empty.hex()
    print(f"PASSED: {len(tests)} independently signed Core Taproot script/key blocks with exact consensus outcomes", flush=True)


def check_reorg_and_mempool(core_port, rust_port, p2p_port, outbound, encrypted, clock):
    core_rpc(core_port, "createwallet", ["interop-wallet"])
    scripts = runtime_script_addresses(core_port)
    address = core_rpc(core_port, "getnewaddress", ["", "bech32"])
    scripts["p2wpkh"] = address
    hashes = core_rpc(core_port, "generatetoaddress", [105, address], timeout=30)
    wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == hashes[-1], timeout=60)
    # Core -> Rust wtxid announcement and actual signature-checked admission.
    parent_id = core_rpc(core_port, "sendtoaddress", ["mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn", 0.25])
    assert parent_id in core_rpc(core_port, "getrawmempool", [])
    # Negative control: a completed handshake and synchronized chain cannot
    # guarantee a transaction announcement while Core's privacy timer is frozen.
    # This reproduces the scheduler dependency without waiting 30 real seconds.
    try:
        wait_until(lambda: parent_id in rust_rpc(rust_port, "getrawmempool", []),
                   timeout=0.25, description="frozen-clock transaction relay")
    except WaitTimeout:
        assert parent_id not in rust_rpc(rust_port, "getrawmempool", [])
        assert len(core_rpc(core_port, "getpeerinfo", [])) == len(rust_rpc(rust_port, "getpeerinfo", [])) == 1
    else:
        raise AssertionError("Core announced a transaction without advancing its frozen trickle timer")
    wait_for_tx_relay(core_port, rust_port, clock, parent_id, from_core=True)
    raw, replacement_coin = signed_wallet_spend(core_port)
    core_accept = core_rpc(core_port, "testmempoolaccept", [[raw]])[0]
    rust_accept = rust_rpc(rust_port, "testmempoolaccept", [[raw]])[0]
    assert core_accept["allowed"] == rust_accept["allowed"] is True
    assert core_accept["vsize"] == rust_accept["vsize"]
    assert core_accept["fees"]["base"] == rust_accept["fees"]["base"]
    assert core_rpc(core_port, "testmempoolaccept", [[raw], 0.00001])[0]["allowed"] is False
    assert rust_rpc(rust_port, "testmempoolaccept", [[raw], 0.00001])[0]["allowed"] is False
    # Rust -> Core relay lets Core independently verify the same witness tx.
    child_id = rust_rpc(rust_port, "sendrawtransaction", [raw])
    wait_for_tx_relay(core_port, rust_port, clock, child_id, from_core=False)
    replacement, _ = signed_wallet_spend(core_port, replacement_coin, 0.00008)
    assert core_rpc(core_port, "testmempoolaccept", [[replacement]])[0]["allowed"] is True
    assert rust_rpc(rust_port, "testmempoolaccept", [[replacement]])[0]["allowed"] is True
    replaced_id = child_id
    child_id = rust_rpc(rust_port, "sendrawtransaction", [replacement])
    wait_for_tx_relay(core_port, rust_port, clock, child_id, from_core=False)
    assert replaced_id not in core_rpc(core_port, "getrawmempool", [])
    assert replaced_id not in rust_rpc(rust_port, "getrawmempool", [])
    assert rust_rpc(rust_port, "getmempoolinfo", [])["size"] == 2
    hashes = rust_rpc(rust_port, "generatetoaddress", [1, address])
    wait_until(lambda: core_rpc(core_port, "getbestblockhash", []) == hashes[-1])
    assert core_rpc(core_port, "getrawmempool", []) == rust_rpc(rust_port, "getrawmempool", []) == []
    mined = core_rpc(core_port, "getblock", [hashes[-1]])
    assert parent_id in mined["tx"] and child_id in mined["tx"]
    assert core_rpc(core_port, "getblock", [hashes[-1], 0]) == rust_rpc(rust_port, "getblock", [hashes[-1], 0])
    # A real signed immature coinbase spend is rejected by both validators.
    coinbase = core_rpc(core_port, "getblock", [hashes[-1], 2])["tx"][0]
    immature = {"txid": coinbase["txid"], "vout": 0, "amount": coinbase["vout"][0]["value"]}
    raw_immature = core_rpc(core_port, "createrawtransaction", [[{"txid": immature["txid"], "vout": immature["vout"]}], {address: round(immature["amount"] - 0.00002, 8)}])
    raw_immature = core_rpc(core_port, "signrawtransactionwithwallet", [raw_immature])["hex"]
    assert core_rpc(core_port, "testmempoolaccept", [[raw_immature]])[0]["allowed"] is False
    assert rust_rpc(rust_port, "testmempoolaccept", [[raw_immature]])[0]["allowed"] is False
    check_p2sh_runtime(core_port, rust_port, p2p_port, outbound, encrypted, clock, address, scripts["p2sh"])
    for kind in ["p2wpkh", "p2wsh", "taproot"]:
        check_witness_runtime(core_port, rust_port, p2p_port, outbound, encrypted, clock, address, scripts[kind], kind)
    if not outbound and not encrypted:
        check_taproot_execution(core_port, rust_port, p2p_port, clock, address)
    # Separate branches, including a real spend in the branch to be disconnected.
    core_rpc(core_port, "setnetworkactive", [False])
    wait_until(lambda: not rust_rpc(rust_port, "getpeerinfo", []))
    raw_fork, coin = signed_wallet_spend(core_port)
    fork_txid = rust_rpc(rust_port, "sendrawtransaction", [raw_fork])
    old_hashes = rust_rpc(rust_port, "generatetoaddress", [2, address])
    assert rust_rpc(rust_port, "gettxout", [coin["txid"], coin["vout"], False]) is None
    new_hashes = core_rpc(core_port, "generatetoaddress", [3, address])
    core_rpc(core_port, "setnetworkactive", [True])
    if not outbound:
        core_rpc(core_port, "addnode", [f"127.0.0.1:{p2p_port}", "onetry", encrypted])
    wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == new_hashes[-1], timeout=60)
    assert rust_rpc(rust_port, "getblockheader", [old_hashes[-1]])["confirmations"] == -1
    restored = rust_rpc(rust_port, "gettxout", [coin["txid"], coin["vout"], False])
    assert restored["value"] == coin["amount"]
    assert restored["confirmations"] == core_rpc(core_port, "gettxout", [coin["txid"], coin["vout"], False])["confirmations"]
    assert fork_txid in rust_rpc(rust_port, "getrawmempool", [])
    wait_for_tx_relay(core_port, rust_port, clock, fork_txid, from_core=False)
    final = rust_rpc(rust_port, "generatetoaddress", [1, address])[-1]
    wait_until(lambda: core_rpc(core_port, "getbestblockhash", []) == final)
    assert fork_txid in core_rpc(core_port, "getblock", [final])["tx"]
    assert core_rpc(core_port, "getblock", [final, 0]) == rust_rpc(rust_port, "getblock", [final, 0])
    assert rust_rpc(rust_port, "getrawmempool", []) == []
    return final, old_hashes[-1]


def scenario(args, encrypted, outbound):
    mode = "v2" if encrypted else "v1"
    direction = "outbound" if outbound else "inbound"
    with tempfile.TemporaryDirectory(prefix=f"btc-core-{direction}-{mode}-") as directory:
        root = Path(directory)
        core_data, rust_data = root / "core", root / "rust"
        core_data.mkdir()
        rust_data.mkdir()
        core_port = free_port()
        clock = CoreClock(core_port)
        rust_port = free_port(3, {core_port})
        p2p_port = free_port(excluded={core_port, *range(rust_port, rust_port + 3)})
        core_p2p = free_port(excluded={core_port, p2p_port, *range(rust_port, rust_port + 3)})
        processes = []
        with (root / "core.log").open("w") as core_log, (root / "rust.log").open("w") as rust_log:
            try:
                core_command = [
                    str(args.bitcoind), "-regtest", f"-datadir={core_data}", "-server", f"-listen={int(outbound)}",
                    "-dnsseed=0", "-discover=0", "-connect=0", "-listenonion=0", "-par=1",
                    f"-rpcport={core_port}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
                    "-rpcuser=interop", "-rpcpassword=regtest-only", "-fallbackfee=0.00002", f"-v2transport={int(encrypted)}",
                    f"-mocktime={clock.now}", "-debug=net", "-debug=mempool",
                ]
                if outbound:
                    core_command += [f"-bind=127.0.0.1:{core_p2p}", f"-port={core_p2p}"]
                core = subprocess.Popen(core_command, stdout=core_log, stderr=core_log)
                processes.append(core)
                wait_until(lambda: core_rpc(core_port, "getblockchaininfo", []))
                address = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"
                initial_height = 19 if outbound else 0
                if initial_height:
                    core_rpc(core_port, "generatetoaddress", [initial_height, address])
                rust_command = [
                    str(args.node), "--network", "regtest", "--datadir", str(rust_data),
                    "--rpc-port", str(rust_port), "--port", str(p2p_port), "--log-level", "debug",
                ]
                if outbound:
                    rust_command += ["--connect", f"127.0.0.1:{core_p2p}"]
                rust_command += ["run"]
                rust = subprocess.Popen(rust_command, stdout=rust_log, stderr=rust_log)
                processes.append(rust)
                wait_until(lambda: rust_rpc(rust_port, "getblockchaininfo", []))
                if not outbound:
                    core_rpc(core_port, "addnode", [f"127.0.0.1:{p2p_port}", "onetry", encrypted])
                core_peers = wait_until(lambda: [peer for peer in core_rpc(core_port, "getpeerinfo", [])
                                                if peer.get("version", 0) >= 70016 and peer.get("transport_protocol_type") == mode])
                rust_peers = wait_until(lambda: rust_rpc(rust_port, "getpeerinfo", []))
                assert len(core_peers) == len(rust_peers) == 1
                assert core_peers[0]["transport_protocol_type"] == mode, core_peers
                assert rust_peers[0]["transport_protocol_type"] == mode, rust_peers
                assert rust_peers[0]["inbound"] is (not outbound)
                assert core_peers[0]["inbound"] is outbound
                wait_until(lambda: rust_rpc(rust_port, "getblockcount", []) == initial_height)
                assert core_peers[0]["relaytxes"] is True
                assert core_peers[0]["permissions"] == [], "acceptance must use ordinary peer validation"
                if encrypted:
                    assert core_peers[0]["session_id"] == rust_peers[0]["session_id"]
                    assert int(core_peers[0]["services"], 16) & (1 << 11)
                rust_hashes = rust_rpc(rust_port, "generatetoaddress", [3, address])
                wait_until(lambda: core_rpc(core_port, "getbestblockhash", []) == rust_hashes[-1])
                # Core independently checks our coinbase construction and proof of work.
                assert core_rpc(core_port, "getblockcount", []) == initial_height + 3
                core_hashes = core_rpc(core_port, "generatetoaddress", [2, address])
                wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == core_hashes[-1])
                assert rust_rpc(rust_port, "getblockcount", []) == initial_height + 5
                assert core_rpc(core_port, "getblock", [core_hashes[-1], 0]) == rust_rpc(rust_port, "getblock", [core_hashes[-1], 0])
                if outbound:
                    # Core drops our outbound connection; recover missing history
                    # across more than one live-download window, then keep relaying.
                    previous_peer = core_peers[0]["id"]
                    core_rpc(core_port, "disconnectnode", ["", previous_peer])
                    core_hashes = core_rpc(core_port, "generatetoaddress", [20, address])
                    wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == core_hashes[-1], timeout=60)
                    core_peers = core_rpc(core_port, "getpeerinfo", [])
                    rust_peers = rust_rpc(rust_port, "getpeerinfo", [])
                    assert len(core_peers) == len(rust_peers) == 1
                    assert core_peers[0]["id"] != previous_peer
                    assert rust_peers[0]["inbound"] is False
                    assert core_peers[0]["transport_protocol_type"] == rust_peers[0]["transport_protocol_type"] == mode
                    if encrypted:
                        assert core_peers[0]["session_id"] == rust_peers[0]["session_id"]
                    rust_rpc(rust_port, "stop", [])
                    assert rust.wait(10) == 0
                    wait_until(lambda: not core_rpc(core_port, "getpeerinfo", []))
                    core_hashes = core_rpc(core_port, "generatetoaddress", [2, address])
                    rust = subprocess.Popen(rust_command, stdout=rust_log, stderr=rust_log)
                    processes.append(rust)
                    wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == core_hashes[-1])
                    assert rust_rpc(rust_port, "getblockcount", []) == initial_height + 27
                    rust_hashes = rust_rpc(rust_port, "generatetoaddress", [1, address])
                    wait_until(lambda: core_rpc(core_port, "getbestblockhash", []) == rust_hashes[-1])
                    assert core_rpc(core_port, "getblock", [rust_hashes[-1], 0]) == rust_rpc(rust_port, "getblock", [rust_hashes[-1], 0])
                final, stale = check_reorg_and_mempool(core_port, rust_port, p2p_port, outbound, encrypted, clock)
                rust_rpc(rust_port, "stop", [])
                assert rust.wait(10) == 0
                wait_until(lambda: not core_rpc(core_port, "getpeerinfo", []))
                rust = subprocess.Popen(rust_command, stdout=rust_log, stderr=rust_log)
                processes.append(rust)
                wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == final)
                assert rust_rpc(rust_port, "getblockheader", [stale])["confirmations"] == -1
                assert rust_rpc(rust_port, "getrawmempool", []) == []
                rust_rpc(rust_port, "stop", [])
                core_rpc(core_port, "stop", [])
                assert rust.wait(10) == core.wait(10) == 0
                print(f"{direction} {mode}: Core/Rust sessions, real blocks both ways, "
                      + ("IBD, reconnect/restart, " if outbound else "") + "signed mempool relay/mining, spend reorg/undo, restart, and shutdown passed")
                print(f"{direction} {mode}: frozen-clock negative control and actual P2P relay passed "
                      f"with {clock.now - clock.initial}s of bounded Core clock advancement")
            except Exception:
                print((root / "rust.log").read_text()[-20000:])
                debug = core_data / "regtest" / "debug.log"
                print(debug.read_text()[-20000:] if debug.exists() else (root / "core.log").read_text())
                raise
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind", type=Path, required=True)
    parser.add_argument("--node", type=Path, default=Path(__file__).resolve().parents[1] / "target/release/btc-node")
    args = parser.parse_args()
    args.bitcoind = args.bitcoind.resolve()
    args.node = args.node.resolve()
    for outbound in [False, True]:
        for encrypted in [False, True]:
            scenario(args, encrypted, outbound)


if __name__ == "__main__":
    main()
