from __future__ import annotations

from latcoin.codec.block import Block
from latcoin.codec.tx import txid
from latcoin.validation.errors import BlockValidationError
from latcoin.validation.merkle import merkle_root_for_txs

MAX_BLOCK_TXS = 10_000


def _raise(msg: str) -> None:
    raise BlockValidationError(msg)


def _is_coinbase_tx(tx) -> bool:
    if len(tx.body.inputs) != 1:
        return False
    txin = tx.body.inputs[0]
    return txin.prev_txid == (b"\x00" * 32) and txin.prev_index == 0xFFFFFFFF


def validate_block_structure(block: Block) -> None:
    if block.header.version <= 0:
        _raise("block header version must be positive")
    if len(block.header.prev_block_hash) != 32:
        _raise("prev_block_hash must be exactly 32 bytes")
    if len(block.header.merkle_root) != 32:
        _raise("merkle_root must be exactly 32 bytes")
    if block.header.height < 0:
        _raise("block height must be non-negative")
    if len(block.txs) == 0:
        _raise("block must contain at least one transaction")
    if len(block.txs) > MAX_BLOCK_TXS:
        _raise("block contains too many transactions")
    if not _is_coinbase_tx(block.txs[0]):
        _raise("first transaction must be coinbase")
    for i, tx in enumerate(block.txs[1:], start=1):
        if _is_coinbase_tx(tx):
            _raise(f"non-first transaction at index {i} is coinbase-like")
    seen_txids: set[bytes] = set()
    for i, tx in enumerate(block.txs):
        tid = txid(tx)
        if tid in seen_txids:
            _raise(f"duplicate transaction id in block at index {i}: {tid.hex()}")
        seen_txids.add(tid)
    computed_merkle = merkle_root_for_txs(block.txs)
    if computed_merkle != block.header.merkle_root:
        _raise("block merkle_root does not match transactions")
