from __future__ import annotations

import pytest

from latcoin.codec.block import Block, BlockHeader, block_hash, encode_block_header
from latcoin.codec.constants import (
    LOCK_P2LPKH,
    NETWORK_DEVNET,
    SCHEME_SIG_V1,
    TX_VERSION_V1,
)
from latcoin.codec.tx import Transaction, TxBody, TxInput, TxOutput
from latcoin.mining.template import build_block_template
from latcoin.validation.block_context import BlockChainContext, validate_block_context
from latcoin.validation.errors import BlockValidationError
from latcoin.validation.pow import hash_meets_target
from latcoin.validation.tx_context import UtxoEntry


def _build_template_at_bits(bits: int):
    return build_block_template(
        network_id=NETWORK_DEVNET,
        height=0,
        prev_block_hash=b"\x00" * 32,
        reward_lock_data=b"\xaa" * 32,
        bits=bits,
        mempool_txs=[],
        total_fees=0,
        timestamp=1_700_000_000,
    )


def test_miner_produces_header_that_meets_target() -> None:
    template = _build_template_at_bits(bits=6)
    header = template.block.header
    assert header.bits == 6
    assert hash_meets_target(block_hash(header), bits=6)


def test_miner_at_two_bits_differ_in_nonce_or_hash() -> None:
    t1 = _build_template_at_bits(bits=4)
    t2 = _build_template_at_bits(bits=10)
    assert hash_meets_target(block_hash(t1.block.header), bits=4)
    assert hash_meets_target(block_hash(t2.block.header), bits=10)
    # Harder target should (with extremely high probability) need a different nonce.
    assert t1.block.header.nonce != t2.block.header.nonce or t1.block.header != t2.block.header


def test_validate_block_context_rejects_wrong_bits() -> None:
    template = _build_template_at_bits(bits=4)
    ctx = BlockChainContext(
        network_id=NETWORK_DEVNET,
        current_height=0,
        median_time_past=0,
        expected_prev_block_hash=b"\x00" * 32,
        coinbase_maturity=0,
        expected_bits=8,  # miner used 4, validator expects 8
    )
    with pytest.raises(BlockValidationError, match="bits"):
        validate_block_context(template.block, {}, ctx)


def test_validate_block_context_rejects_bad_pow() -> None:
    template = _build_template_at_bits(bits=4)
    # Craft a header that declares bits=4 but whose hash does not meet that target.
    header = template.block.header
    for extra_nonce in range(1, 10_000):
        bad_header = BlockHeader(
            version=header.version,
            prev_block_hash=header.prev_block_hash,
            merkle_root=header.merkle_root,
            timestamp=header.timestamp,
            height=header.height,
            bits=header.bits,
            nonce=(header.nonce + extra_nonce) & 0xFFFFFFFFFFFFFFFF,
        )
        if not hash_meets_target(block_hash(bad_header), bits=header.bits):
            break
    else:
        pytest.fail("could not find a failing nonce")

    bad_block = Block(header=bad_header, txs=template.block.txs)
    ctx = BlockChainContext(
        network_id=NETWORK_DEVNET,
        current_height=0,
        median_time_past=0,
        expected_prev_block_hash=b"\x00" * 32,
        coinbase_maturity=0,
        expected_bits=4,
    )
    with pytest.raises(BlockValidationError, match="proof-of-work"):
        validate_block_context(bad_block, {}, ctx)


def test_miner_raises_when_grind_exhausted() -> None:
    with pytest.raises(RuntimeError, match="failed to find a valid nonce"):
        build_block_template(
            network_id=NETWORK_DEVNET,
            height=0,
            prev_block_hash=b"\x00" * 32,
            reward_lock_data=b"\xbb" * 32,
            bits=200,  # essentially unreachable
            mempool_txs=[],
            total_fees=0,
            timestamp=1_700_000_000,
            max_attempts=8,
        )
