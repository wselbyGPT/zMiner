from __future__ import annotations

import hashlib
import struct
from typing import Any


POW_N = 200
POW_K = 9
POW_SOLUTION_SIZE = 1344
POW_INPUT_SIZE = 4 + 32 + 32 + 32 + 4 + 4


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compact_size(n: int) -> bytes:
    if n < 0:
        raise ValueError("compactSize cannot encode negative integers")
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def reverse32_hex(hex_string: str) -> bytes:
    raw = bytes.fromhex(hex_string)
    if len(raw) != 32:
        raise ValueError(f"expected 32 bytes, got {len(raw)} from hex={hex_string!r}")
    return raw[::-1]


def bits_hex_to_le_bytes(bits_hex: str) -> bytes:
    raw = bytes.fromhex(bits_hex)
    if len(raw) != 4:
        raise ValueError(f"expected 4 bytes for nBits, got {len(raw)} from {bits_hex!r}")
    return raw[::-1]


def target_hex_to_bytes(target_hex: str) -> bytes:
    raw = bytes.fromhex(target_hex)
    if len(raw) != 32:
        raise ValueError(f"expected 32 bytes for target, got {len(raw)} from {target_hex!r}")
    return raw


def tx_hashes_from_template(template: dict[str, Any]) -> list[bytes]:
    txs: list[bytes] = []
    coinbase = template.get("coinbasetxn")
    if not coinbase or "hash" not in coinbase:
        raise ValueError("template missing coinbasetxn.hash")
    # Per Zcash getblocktemplate docs, tx hashes are encoded in little-endian hex.
    txs.append(bytes.fromhex(coinbase["hash"]))
    for tx in template.get("transactions", []):
        txs.append(bytes.fromhex(tx["hash"]))
    return txs


def merkle_root_internal_bytes(tx_hashes: list[bytes]) -> bytes:
    if not tx_hashes:
        raise ValueError("cannot compute merkle root of empty transaction list")
    layer = tx_hashes[:]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        nxt: list[bytes] = []
        for i in range(0, len(layer), 2):
            nxt.append(sha256d(layer[i] + layer[i + 1]))
        layer = nxt
    return layer[0]


def choose_merkle_root_bytes(template: dict[str, Any]) -> bytes:
    defaultroots = template.get("defaultroots") or {}
    if "merkleroot" in defaultroots:
        # RPC/root strings are typically displayed in natural hex order, while the header stores internal byte order.
        return reverse32_hex(defaultroots["merkleroot"])
    return merkle_root_internal_bytes(tx_hashes_from_template(template))


def choose_block_commitments_bytes(template: dict[str, Any]) -> bytes:
    defaultroots = template.get("defaultroots") or {}
    if "blockcommitmentshash" in defaultroots:
        return reverse32_hex(defaultroots["blockcommitmentshash"])
    if "blockcommitmentshash" in template:
        return reverse32_hex(template["blockcommitmentshash"])
    if "lightclientroothash" in template:
        return reverse32_hex(template["lightclientroothash"])
    if "finalsaplingroothash" in template:
        return reverse32_hex(template["finalsaplingroothash"])
    return b"\x00" * 32


def build_pow_input(template: dict[str, Any]) -> bytes:
    version = int(template["version"])
    prev_hash = reverse32_hex(template["previousblockhash"])
    merkle_root = choose_merkle_root_bytes(template)
    block_commitments = choose_block_commitments_bytes(template)
    ntime = int(template["curtime"])
    bits = bits_hex_to_le_bytes(template["bits"])

    pow_input = b"".join(
        [
            struct.pack("<i", version),
            prev_hash,
            merkle_root,
            block_commitments,
            struct.pack("<I", ntime),
            bits,
        ]
    )
    if len(pow_input) != POW_INPUT_SIZE:
        raise AssertionError(f"unexpected pow input size: {len(pow_input)}")
    return pow_input


def build_header_from_pow_input(pow_input: bytes, nonce32: bytes, solution: bytes) -> bytes:
    if len(pow_input) != POW_INPUT_SIZE:
        raise ValueError(f"pow input must be {POW_INPUT_SIZE} bytes, got {len(pow_input)}")
    if len(nonce32) != 32:
        raise ValueError(f"nonce must be 32 bytes, got {len(nonce32)}")
    return pow_input + nonce32 + compact_size(len(solution)) + solution


def build_header(template: dict[str, Any], nonce32: bytes, solution: bytes) -> bytes:
    return build_header_from_pow_input(build_pow_input(template), nonce32=nonce32, solution=solution)


def collect_raw_transactions(template: dict[str, Any]) -> list[bytes]:
    coinbase = template.get("coinbasetxn")
    if not coinbase or "data" not in coinbase:
        raise ValueError("template missing coinbasetxn.data")
    txs = [bytes.fromhex(coinbase["data"])]
    for tx in template.get("transactions", []):
        txs.append(bytes.fromhex(tx["data"]))
    return txs


def build_block(template: dict[str, Any], nonce32: bytes, solution: bytes) -> bytes:
    header = build_header(template, nonce32=nonce32, solution=solution)
    txs = collect_raw_transactions(template)
    return header + compact_size(len(txs)) + b"".join(txs)


def header_hash_bytes(header: bytes) -> bytes:
    return sha256d(header)


def header_hash_rpc_hex(header: bytes) -> str:
    return header_hash_bytes(header)[::-1].hex()


def header_meets_target(header: bytes, target_hex: str) -> bool:
    target = target_hex_to_bytes(target_hex)
    # Zcash compares the SHA-256d digest interpreted in little-endian integer order,
    # which is equivalent to reversing the bytes and comparing as a big-endian byte string.
    return header_hash_bytes(header)[::-1] <= target


def summarize_template(template: dict[str, Any]) -> dict[str, Any]:
    tx_count = 1 + len(template.get("transactions", []))
    return {
        "height": template.get("height"),
        "version": template.get("version"),
        "previousblockhash": template.get("previousblockhash"),
        "bits": template.get("bits"),
        "target": template.get("target"),
        "curtime": template.get("curtime"),
        "tx_count_including_coinbase": tx_count,
        "mutable": template.get("mutable", []),
        "defaultroots": template.get("defaultroots", {}),
    }
