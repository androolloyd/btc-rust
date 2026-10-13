#!/usr/bin/env python3
"""Separate-process BIP330 primitive interoperability with the compiled node.

This exercises unchanged upstream minisketch and Core SipHash, not negotiated
live Erlay peers. No sender's original set is passed to the Rust decoder.
"""
import argparse
import contextlib
import json
from pathlib import Path
import random
import select
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def node(binary, arguments, valid=True):
    result = subprocess.run([str(binary), "--json", *arguments], cwd=ROOT,
                            capture_output=True, text=True, timeout=60)
    if not valid:
        assert result.returncode != 0, f"invalid input succeeded: {arguments[:3]}"
        return None
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@contextlib.contextmanager
def reference_worker():
    with tempfile.TemporaryFile(mode="w+") as errors:
        process = subprocess.Popen([sys.executable, str(ROOT / "scripts/minisketch_reference.py")],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors,
                                   text=True, bufsize=1)

        def request(**kwargs):
            process.stdin.write(json.dumps(kwargs) + "\n")
            process.stdin.flush()
            ready, _, _ = select.select([process.stdout], [], [], 60)
            assert ready, "reference subprocess exceeded 60 seconds"
            line = process.stdout.readline()
            if not line:
                errors.seek(0)
                raise AssertionError("reference worker failed: " + errors.read())
            return json.loads(line)

        try:
            yield request
        finally:
            process.stdin.close()
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def hash_args(hashes):
    return [argument for value in hashes for argument in ["--wtxid", bytes.fromhex(value)[::-1].hex()]]


def check(binary):
    fixture = json.loads((ROOT / "crates/network/tests/data/bip330-sketches.json").read_text())
    received = fixture["sketches"] + fixture["raw_decodes"]
    for case in received:
        args = ["erlay-reconcile", case["hex"], "--salt-a", "0", "--salt-b", "0"]
        output = node(binary, args, valid=case["decoded"] is not None)
        if output is not None:
            assert output["we_need_ids"] == case["decoded"], case["name"]
            assert output["they_need_wtxids"] == []
            assert output["live_relay"] is False
            assert output["original_difference_verified"] is False
    for case in fixture["short_ids"]:
        output = node(binary, ["erlay-sketch", "--capacity", "1", "--salt-a", str(case["salt_a"]),
                              "--salt-b", str(case["salt_b"]), *hash_args([case["wtxid_internal"]])])
        assert bytes.fromhex(output["hex"]) == case["short_id"].to_bytes(4, "little")
        assert output["live_relay"] is False
    collision = fixture["collision"]
    node(binary, ["erlay-sketch", "--capacity", "4", "--salt-a", str(collision["salt_a"]),
                  "--salt-b", str(collision["salt_b"]), *hash_args(collision["wtxids_internal"])], valid=False)
    salts = ["--salt-a", "12345", "--salt-b", "67890"]
    for encoded in ["00", "000000", "gggggggg", "00" * 260]:
        node(binary, ["erlay-reconcile", encoded, *salts], valid=False)
    for capacity in [65, 2**64 - 1]:
        node(binary, ["erlay-sketch", "--capacity", str(capacity), *salts], valid=False)
    for bad_hash in ["00", "g" * 64, "0" * 66]:
        node(binary, ["erlay-sketch", "--capacity", "4", *salts, "--wtxid", bad_hash], valid=False)
    rng = random.Random(0xb1_0330)
    count = 0
    with reference_worker() as worker:
        for capacity in [1, 2, 3, 4, 8, 16, 32, 64]:
            for common_count in [0, 3, 100, 1000]:
                difference = capacity
                local_count = difference // 2
                hashes = [rng.getrandbits(256).to_bytes(32, "little").hex() for _ in range(common_count + difference)]
                common = hashes[:common_count]
                local_only = hashes[common_count:common_count + local_count]
                peer_only = hashes[common_count + local_count:]
                local, peer = common + local_only, common + peer_only
                request = dict(capacity=capacity, salt_a=12345, salt_b=67890)
                peer_sketch = worker(operation="sketch", wtxids_internal=peer, **request)["hex"]
                # Only local hashes and peer sketch bytes cross into the node.
                result = node(binary, ["erlay-reconcile", peer_sketch, *salts, *hash_args(local)])
                expected_known = {bytes.fromhex(value)[::-1].hex() for value in local_only}
                assert set(result["they_need_wtxids"]) == expected_known
                expected_unknown = worker(operation="sketch", wtxids_internal=peer_only, **request)["hex"]
                expected_unknown = worker(operation="decode", hex=expected_unknown, capacity=capacity)["decoded"]
                assert result["we_need_ids"] == expected_unknown
                # Reverse direction: the unchanged reference also decodes our
                # bytes. XOR with its local snapshot before decoding large sets.
                ours = node(binary, ["erlay-sketch", "--capacity", str(capacity), *salts, *hash_args(local)])["hex"]
                expected_ours = worker(operation="sketch", wtxids_internal=local, **request)["hex"]
                assert ours == expected_ours
                combined = bytes(a ^ b for a, b in zip(bytes.fromhex(ours), bytes.fromhex(peer_sketch))).hex()
                decoded = worker(operation="decode", hex=combined, capacity=capacity)["decoded"]
                expected_diff = worker(operation="sketch", wtxids_internal=local_only + peer_only, **request)["hex"]
                expected_diff = worker(operation="decode", hex=expected_diff, capacity=capacity)["decoded"]
                assert decoded == expected_diff and len(decoded) == difference
                count += 1
                print(f"Separate-process capacity {capacity}, {common_count} common wtxids: passed", flush=True)
    print(f"Passed {len(received)} reference decodes, {len(fixture['short_ids'])} salted short IDs, collision/malformed bounds and {count} bidirectional separate-process cases", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", type=Path, default=ROOT / "target/release/btc-node")
    check(parser.parse_args().node.resolve())
