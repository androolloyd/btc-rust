#!/usr/bin/env python3
"""Checksum-pinned, unchanged upstream minisketch reference for acceptance.

Fixture generation and a separate subprocess worker only; never used by the
node implementation. Upstream Python code is MIT licensed (Pieter Wuille).
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import urllib.request

COMMIT = "a12f5de1c96e21d76f64bc647ae4f65e4fc1b636"
SOURCE = f"https://raw.githubusercontent.com/sipa/minisketch/{COMMIT}/tests/pyminisketch.py"
SHA256 = "d7c9ab512ce684aa5884d2527b42afea8a8a228b89bf7bdc2df368b363c5865d"


def reference():
    path = Path(tempfile.gettempdir()) / f"btc-minisketch-{COMMIT}.py"
    if not path.exists():
        with urllib.request.urlopen(SOURCE, timeout=30) as response:
            data = response.read()
        assert hashlib.sha256(data).hexdigest() == SHA256, "minisketch source checksum"
        path.write_bytes(data)
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == SHA256, "cached minisketch source checksum"
    spec = importlib.util.spec_from_file_location("upstream_minisketch", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def short_id_key(salt_a, salt_b):
    tag = hashlib.sha256(b"Tx Relay Salting").digest()
    salt_a, salt_b = sorted([salt_a, salt_b])
    digest = hashlib.sha256(tag + tag + salt_a.to_bytes(8, "little") + salt_b.to_bytes(8, "little")).digest()
    return int.from_bytes(digest[:8], "little"), int.from_bytes(digest[8:16], "little")


def core_siphash():
    from core29_tapscript import reference as core_reference
    core_reference()
    from test_framework.crypto.siphash import siphash
    return siphash


def worker():
    """A separate sender/decoder. The receiving Rust process gets only bytes."""
    module = reference()
    siphash = core_siphash()
    for line in sys.stdin:
        request = json.loads(line)
        sketch = module.Minisketch(32, request["capacity"])
        if request["operation"] == "sketch":
            k0, k1 = short_id_key(request["salt_a"], request["salt_b"])
            # Hex here is INTERNAL byte order, unlike the CLI's display order.
            for wtxid in set(request["wtxids_internal"]):
                sketch.add(1 + siphash(k0, k1, bytes.fromhex(wtxid)) % 0xffffffff)
            result = {"hex": sketch.serialize().hex()}
        elif request["operation"] == "decode":
            sketch.deserialize(bytes.fromhex(request["hex"]))
            result = {"decoded": sketch.decode(request["capacity"])}
        else:
            raise ValueError("unsupported reference operation")
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    worker()
