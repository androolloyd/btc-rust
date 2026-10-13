#!/usr/bin/env python3
"""Checksum-pinned primary ElectrumX 1.16 acceptance references.

Unchanged Merkle, fee and negotiation code is isolated from unrelated imports;
the released catalog is read through AST without executing its server module. Downloaded source retains its full MIT licence; no third-party package
installation, mainnet connection or production runtime dependency is introduced.
"""
import ast
import hashlib
import math
from pathlib import Path
import tempfile
from urllib.request import urlopen
from typing import Dict, Sequence, Tuple

SOURCE = "https://raw.githubusercontent.com/spesmilo/electrumx/1.16.0/electrumx/lib/merkle.py"
SHA256 = "ae9b654a7cc4f4cff28a6e3930db5363353669d249bbb96b79fde1be37cd046e"
_REFERENCE = None
_FEE_REFERENCE = None
_PROTOCOL_REFERENCE = None
_METHOD_REFERENCE = None


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


def fee_histogram_reference():
    """Execute the unchanged released compact-histogram class method only."""
    global _FEE_REFERENCE
    if _FEE_REFERENCE is not None:
        return _FEE_REFERENCE
    source = "https://raw.githubusercontent.com/spesmilo/electrumx/1.16.0/electrumx/server/mempool.py"
    with urlopen(source, timeout=30) as response:
        data = response.read(32 * 1024 + 1)
    assert hashlib.sha256(data).hexdigest() == "05eb9fd7e5a9cdc0b928b7edb04bfbb8f1aefb05f0988228ff2644baa34d50f0"
    path = Path(tempfile.mkdtemp(prefix="btc-electrumx-fees-")) / "mempool.py"
    path.write_bytes(data)
    tree = ast.parse(data)
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "MemPool")
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "_compress_histogram")
    cls.body = [method]
    cls.decorator_list = []
    namespace = {"Dict": Dict, "Sequence": Sequence, "Tuple": Tuple}
    exec(compile(ast.Module(body=[cls], type_ignores=[]), str(path), "exec"), namespace)
    _FEE_REFERENCE = namespace["MemPool"]._compress_histogram
    return _FEE_REFERENCE


def protocol_reference():
    """Unchanged released highest-common-version functions, isolated imports."""
    global _PROTOCOL_REFERENCE
    if _PROTOCOL_REFERENCE is None:
        source="https://raw.githubusercontent.com/spesmilo/electrumx/1.16.0/electrumx/lib/util.py"
        with urlopen(source,timeout=30) as response:data=response.read(32*1024+1)
        assert hashlib.sha256(data).hexdigest()=="d6c5c6ea2f51f93dfb2423b097cb55f3c4b29bc87daa1b4fc5c9dbe6b66dfd96"
        path=Path(tempfile.mkdtemp(prefix="btc-electrumx-protocol-"))/"util.py";path.write_bytes(data)
        names={"protocol_tuple","version_string","protocol_version"}
        functions=[node for node in ast.parse(data).body if isinstance(node,ast.FunctionDef) and node.name in names]
        assert len(functions)==3
        namespace={}
        exec(compile(ast.Module(body=functions,type_ignores=[]),str(path),"exec"),namespace)
        _PROTOCOL_REFERENCE=namespace["protocol_version"]
    return _PROTOCOL_REFERENCE


def methods_1_4_reference():
    """Read the released Bitcoin catalog, excluding the >=1.4.2 extension."""
    global _METHOD_REFERENCE
    if _METHOD_REFERENCE is None:
        source="https://raw.githubusercontent.com/spesmilo/electrumx/1.16.0/electrumx/server/session.py"
        with urlopen(source,timeout=30) as response:data=response.read(128*1024+1)
        assert hashlib.sha256(data).hexdigest()=="1a199471c77bf7d3388dc6e9fa3f15be00ce617fb3b06aefddb5ab3084e0538f"
        path=Path(tempfile.mkdtemp(prefix="btc-electrumx-methods-"))/"session.py";path.write_bytes(data)
        cls=next(node for node in ast.parse(data).body if isinstance(node,ast.ClassDef) and node.name=="ElectrumX")
        method=next(node for node in cls.body if isinstance(node,ast.FunctionDef) and node.name=="set_request_handlers")
        catalog=next(node.value for node in method.body if isinstance(node,ast.Assign) and isinstance(node.value,ast.Dict))
        _METHOD_REFERENCE={node.value for node in catalog.keys}
        assert len(_METHOD_REFERENCE)==22
    return _METHOD_REFERENCE
