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


class ReservedPorts:
    def __init__(self, port, sockets):
        self.port = port
        self.sockets = sockets

    def close(self):
        for item in self.sockets:
            item.close()
        self.sockets.clear()


def reserve_ports(span=1, excluded=()):
    for _ in range(100):
        held = []
        try:
            first = socket.socket()
            first.bind(("0.0.0.0", 0))
            held.append(first)
            port = first.getsockname()[1]
            if port + span > 65536 or any(value in excluded for value in range(port, port + span)):
                continue
            for offset in range(1, span):
                other = socket.socket()
                held.append(other)
                other.bind(("0.0.0.0", port + offset))
            reservation = ReservedPorts(port, held)
            held = []  # Ownership moves to the caller until process launch.
            return reservation
        except OSError:
            pass
        finally:
            for item in held:
                item.close()
    raise RuntimeError("no available port range")


def free_port(span=1, excluded=()):
    reservation = reserve_ports(span, excluded)
    try:
        return reservation.port
    finally:
        reservation.close()


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


def check_base58_address_rejections(core_port, rust_port, address):
    assert core_rpc(core_port, "validateaddress", [address])["isvalid"]
    aliases = ["Ա" + address, address[0] + chr(0x100 + ord(address[1])) + address[2:], "3" * 1000]
    before = rust_rpc(rust_port, "getbestblockhash", [])
    for alias in aliases:
        assert core_rpc(core_port, "validateaddress", [alias])["isvalid"] is False
        for port, rpc in [(core_port, core_rpc), (rust_port, rust_rpc)]:
            try:
                rpc(port, "generatetoaddress", [1, alias])
                raise AssertionError("invalid Base58 address was mined")
            except RuntimeError as error:
                assert "-5" in str(error), str(error)
        assert rust_rpc(rust_port, "getbestblockhash", []) == before
    print("PASSED: Core/Rust reject Unicode Base58 aliases and oversized mining addresses without tip changes", flush=True)


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


def check_reference_execution(core_port, rust_port, p2p_port, clock, address, module, label):
    _, _, m = module.reference()
    tests = module.cases()
    addresses = {}
    for case in tests:
        info = module.output(case)
        if hasattr(module, "address"):
            addresses[case["name"]] = module.address(case, lambda method, params: core_rpc(core_port, method, params))
        else:
            descriptor = f"rawtr({info.output_pubkey.hex()})"
            descriptor += "#" + core_rpc(core_port, "getdescriptorinfo", [descriptor])["checksum"]
            addresses[case["name"]] = core_rpc(core_port, "deriveaddresses", [descriptor])[0]
    # Each case needs its own outpoint, even when scripts/addresses repeat.
    # invalidateblock re-admits disconnected transactions; reusing an output
    # could mask script-policy checks with conflicts or identical txids.
    funding_template = m.CTransaction()
    funding_template.version = 2
    funding_template.vout = [m.CTxOut(100_000_000, module.output(case).scriptPubKey) for case in tests]
    # Core's address-based creator forbids duplicate addresses. Its own wire
    # serializer can represent repeated outputs; the wallet still supplies and
    # signs the actual funding inputs below.
    raw_funding = funding_template.serialize_without_witness().hex()
    funded_raw = core_rpc(core_port, "fundrawtransaction", [raw_funding, {"changePosition": len(tests)}])["hex"]
    signed_funding = core_rpc(core_port, "signrawtransactionwithwallet", [funded_raw])
    assert signed_funding["complete"] is True
    if getattr(module, "fund_in_block", False):
        # Future witness outputs may be nonstandard. Core builds and validates
        # a real funding block; no mempool/consensus bypass is claimed.
        funding = core_rpc(core_port, "decoderawtransaction", [signed_funding["hex"]])["txid"]
        funded_tip = core_rpc(core_port, "generateblock", [address, [signed_funding["hex"]]])["hash"]
    else:
        funding = core_rpc(core_port, "sendrawtransaction", [signed_funding["hex"]])
        wait_for_tx_relay(core_port, rust_port, clock, funding, from_core=True)
        funded_tip = core_rpc(core_port, "generatetoaddress", [1, address])[-1]
    wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == funded_tip)
    funded = core_rpc(core_port, "decoderawtransaction", [core_rpc(core_port, "gettransaction", [funding])["hex"]])
    coins = funded["vout"][:len(tests)]
    destination = bytes.fromhex(core_rpc(core_port, "getaddressinfo", [address])["scriptPubKey"])
    core_rpc(core_port, "setnetworkactive", [False])
    wait_until(lambda: not rust_rpc(rust_port, "getpeerinfo", []))
    # Keep Rust one block ahead: all case bodies are equal-work siblings on
    # Rust, but win on Core and therefore force Core to execute every script.
    rust_tip = rust_rpc(rust_port, "generatetoaddress", [1, address])[-1]
    empty = bytes.fromhex(rust_rpc(rust_port, "getblock", [rust_tip, 0]))
    assert empty[80] == 1
    case_transactions = {}
    for case_index, case in enumerate(tests):
        coin = coins[case_index]
        assert coin["scriptPubKey"]["address"] == addresses[case["name"]]
        amount = round(coin["value"] * 100_000_000)
        tx, previous, _ = module.spend(case, funding, coin["n"], amount, destination)
        assert previous.scriptPubKey.hex() == coin["scriptPubKey"]["hex"]
        raw = tx.serialize()
        if hasattr(module, "cost"):
            txid = core_rpc(core_port, "decoderawtransaction", [raw.hex()])["txid"]
            case_transactions[txid] = (raw.hex(), module.cost(case))
        policy_allowed = case.get("policy_allowed", False if not case["allowed"] else None)
        if policy_allowed is not None:
            for rpc, port in [(core_rpc, core_port), (rust_rpc, rust_port)]:
                params = [[raw.hex()]] + ([case["fee_cap"]] if "fee_cap" in case else [])
                accepted = rpc(port, "testmempoolaccept", params)[0]
                assert accepted["allowed"] is policy_allowed, (case["name"], accepted)
                if policy_allowed is True and hasattr(module, "cost"):
                    expected_size = max(tx.get_weight(), module.cost(case) * 20)
                    assert accepted["vsize"] == (expected_size + 3) // 4, (case["name"], accepted)
        if policy_allowed is False:
            try:
                params = [raw.hex()] + ([case["fee_cap"]] if "fee_cap" in case else [])
                rust_rpc(rust_port, "sendrawtransaction", params)
            except RuntimeError as error:
                assert error.args[0]["code"] == (-25 if "fee_cap" in case else -26), (case["name"], error)
            else:
                raise AssertionError(f"policy-rejected transaction admitted: {case['name']}")
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
            assert isinstance(result, str) and case.get("reject_contains", "script") in result.lower(), (case["name"], result)
            assert core_rpc(core_port, "getbestblockhash", []) == funded_tip
        actual = rust_rpc(rust_port, "submitblock", [body])
        if case["allowed"]:
            assert actual is None, (case["name"], actual)
            assert rust_rpc(rust_port, "getblock", [block_hash, 0]) == body
        else:
            assert isinstance(actual, str) and case.get("reject_contains", "script") in actual.lower(), (case["name"], actual)
        assert rust_rpc(rust_port, "getbestblockhash", []) == rust_tip
        assert rust_rpc(rust_port, "gettxout", [funding, coin["n"], False]) == before
        assert rust_rpc(rust_port, "getrawmempool", []) == []
    core_rpc(core_port, "setnetworkactive", [True])
    core_rpc(core_port, "addnode", [f"127.0.0.1:{p2p_port}", "onetry", False])
    wait_until(lambda: core_rpc(core_port, "getbestblockhash", []) == rust_tip, timeout=60)
    assert core_rpc(core_port, "getblock", [rust_tip, 0]) == empty.hex()
    # Mine actually re-admitted standard spends after reconnecting. This both
    # drains the fixture's pool and validates real relay/active-chain execution
    # of the independent cases instead of leaving side-case transactions behind.
    if hasattr(module, "cost"):
        # Reorg restoration can retain valid transactions below mining's fee
        # floor, and the retained set can exceed one block's sigop capacity.
        # Core mines the actual transactions in bounded, fully validated blocks.
        for _ in range(len(tests)):
            pending = core_rpc(core_port, "getrawmempool", [])
            if not pending:
                break
            batch = []
            total = 0
            for txid in pending:
                raw, cost = case_transactions[txid]
                if total + cost <= 80_000:
                    batch.append(raw)
                    total += cost
            assert batch, (label, pending)
            drained = core_rpc(core_port, "generateblock", [address, batch])["hash"]
            wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == drained, timeout=60)
            assert core_rpc(core_port, "getblock", [drained, 0]) == rust_rpc(rust_port, "getblock", [drained, 0])
    else:
        drained = core_rpc(core_port, "generatetoaddress", [1, address])[-1]
        wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == drained, timeout=60)
        assert core_rpc(core_port, "getblock", [drained, 0]) == rust_rpc(rust_port, "getblock", [drained, 0])
    assert core_rpc(core_port, "getrawmempool", []) == rust_rpc(rust_port, "getrawmempool", []) == []
    print(f"PASSED: {len(tests)} Core reference {label} blocks with exact consensus outcomes", flush=True)


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
        import core29_tapscript
        import core29_scriptcode
        import core29_witness_policy
        import core29_sigops
        check_reference_execution(core_port, rust_port, p2p_port, clock, address, core29_tapscript, "Taproot script/key")
        check_reference_execution(core_port, rust_port, p2p_port, clock, address, core29_scriptcode, "legacy/BIP143 scriptCode and policy")
        check_reference_execution(core_port, rust_port, p2p_port, clock, address, core29_witness_policy, "witness/key policy boundaries")
        check_reference_execution(core_port, rust_port, p2p_port, clock, address, core29_sigops, "signature-operation cost/limits")
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
        core_reservation = reserve_ports()
        core_port = core_reservation.port
        clock = CoreClock(core_port)
        rust_reservation = reserve_ports(3, {core_port})
        rust_port = rust_reservation.port
        p2p_reservation = reserve_ports(excluded={core_port, *range(rust_port, rust_port + 3)})
        p2p_port = p2p_reservation.port
        core_p2p_reservation = reserve_ports(excluded={core_port, p2p_port, *range(rust_port, rust_port + 3)})
        core_p2p = core_p2p_reservation.port
        reservations = [core_reservation, rust_reservation, p2p_reservation, core_p2p_reservation]
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
                core_reservation.close()
                if outbound:
                    core_p2p_reservation.close()
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
                # Keep the future Rust endpoints unavailable to Core/RPC
                # ephemeral clients while Core starts and mines initial history.
                rust_reservation.close()
                p2p_reservation.close()
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
                check_base58_address_rejections(core_port, rust_port, address)
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
                for reservation in reservations:
                    reservation.close()
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
