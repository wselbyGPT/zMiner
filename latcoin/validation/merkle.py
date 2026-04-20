from __future__ import annotations

from latcoin.codec.hash import hash32
from latcoin.codec.tx import Transaction, txid


def merkle_root_from_hashes(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hash32(b"")
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            next_level.append(hash32(level[i] + level[i + 1]))
        level = next_level
    return level[0]


def merkle_root_for_txs(txs: list[Transaction]) -> bytes:
    return merkle_root_from_hashes([txid(tx) for tx in txs])
