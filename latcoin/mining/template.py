from __future__ import annotations

import time
from dataclasses import dataclass

from latcoin.codec.block import Block, BlockHeader, block_hash
from latcoin.codec.constants import LOCK_P2LPKH, SCHEME_SIG_V1, TX_VERSION_V1
from latcoin.codec.tx import Transaction, TxBody, TxInput, TxOutput
from latcoin.validation.merkle import merkle_root_for_txs
from latcoin.validation.pow import hash_meets_target

BLOCK_VERSION_V1 = 0x01
DEFAULT_BLOCK_SUBSIDY = 50 * 100_000_000


@dataclass(frozen=True, slots=True)
class BlockTemplate:
    block: Block
    total_fees: int
    subsidy: int
    selected_tx_count: int


def block_subsidy(height: int) -> int:
    # Fixed devnet subsidy for now.
    if height < 0:
        raise ValueError("height must be non-negative")
    return DEFAULT_BLOCK_SUBSIDY


def create_coinbase_tx(
    *,
    network_id: int,
    height: int,
    reward_lock_data: bytes,
    reward_amount: int,
    scheme_id: int = SCHEME_SIG_V1,
) -> Transaction:
    if len(reward_lock_data) != 32:
        raise ValueError("reward_lock_data must be exactly 32 bytes for P2LPKH coinbase outputs")
    return Transaction(
        body=TxBody(
            version=TX_VERSION_V1,
            network_id=network_id,
            flags=0,
            lock_height=0,
            inputs=[
                TxInput(
                    prev_txid=b"\x00" * 32,
                    prev_index=0xFFFFFFFF,
                    sequence=height & 0xFFFFFFFF,
                )
            ],
            outputs=[
                TxOutput(
                    amount=reward_amount,
                    lock_type=LOCK_P2LPKH,
                    scheme_id=scheme_id,
                    lock_data=reward_lock_data,
                )
            ],
            memo=b"",
        ),
        witnesses=[],
    )


_DEFAULT_MAX_GRIND_ATTEMPTS = 1 << 40


def build_block_template(
    *,
    network_id: int,
    height: int,
    prev_block_hash: bytes,
    reward_lock_data: bytes,
    bits: int,
    reward_scheme_id: int = SCHEME_SIG_V1,
    mempool_txs: list[Transaction],
    total_fees: int,
    timestamp: int | None = None,
    nonce_start: int = 0,
    max_attempts: int = _DEFAULT_MAX_GRIND_ATTEMPTS,
) -> BlockTemplate:
    subsidy = block_subsidy(height)
    coinbase = create_coinbase_tx(
        network_id=network_id,
        height=height,
        reward_lock_data=reward_lock_data,
        reward_amount=subsidy + total_fees,
        scheme_id=reward_scheme_id,
    )
    txs = [coinbase, *mempool_txs]
    merkle = merkle_root_for_txs(txs)
    ts = int(time.time()) if timestamp is None else int(timestamp)

    mined_header: BlockHeader | None = None
    for i in range(max_attempts):
        candidate = BlockHeader(
            version=BLOCK_VERSION_V1,
            prev_block_hash=prev_block_hash,
            merkle_root=merkle,
            timestamp=ts,
            height=height,
            bits=bits,
            nonce=(nonce_start + i) & 0xFFFFFFFFFFFFFFFF,
        )
        if hash_meets_target(block_hash(candidate), bits):
            mined_header = candidate
            break
    if mined_header is None:
        raise RuntimeError(f"failed to find a valid nonce within {max_attempts} attempts at bits={bits}")

    return BlockTemplate(
        block=Block(header=mined_header, txs=txs),
        total_fees=total_fees,
        subsidy=subsidy,
        selected_tx_count=len(mempool_txs),
    )
