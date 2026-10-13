#!/usr/bin/env python3
"""Checksum-pinned primary ElectrumX 1.16 Merkle reference for acceptance.

The unchanged Merkle class is loaded in isolation from its unrelated async/server
imports. Downloaded source retains its full MIT licence; no third-party package
installation, mainnet connection or production runtime dependency is introduced.
"""
import ast
import hashlib
import math
from pathlib import Path
import tempfile
from urllib.request import urlopen

SOURCE = "https://raw.githubusercontent.com/spesmilo/electrumx/1.16.0/electrumx/lib/merkle.py"
SHA256 = "ae9b654a7cc4f4cff28a6e3930db5363353669d249bbb96b79fde1be37cd046e"
_REFERENCE = None


def merkle_reference():
    global _REFERENCE
    if _REFERENCE is not None:
        return _REFERENCE
    with urlopen(SOURCE, timeout=30) as response:
        data = response.read(32 * 1024 + 1)
    assert hashlib.sha256(data).hexdigest() == SHA256, "ElectrumX source checksum"
    path = Path(tempfile.mkdtemp(prefix="btc-electrumx-reference-")) / "merkle.py"
    path.write_bytes(data)
    tree = ast.parse(data)
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Merkle"]
    assert len(classes) == 1
    double_sha256 = lambda value: hashlib.sha256(hashlib.sha256(value).digest()).digest()
    namespace = {"double_sha256": double_sha256, "ceil": math.ceil, "log": math.log}
    exec(compile(ast.Module(body=classes, type_ignores=[]), str(path), "exec"), namespace)
    _REFERENCE = namespace["Merkle"]()
    return _REFERENCE
