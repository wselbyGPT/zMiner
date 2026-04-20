from __future__ import annotations

from latcoin.codec.block import (
    Block,
    BlockHeader,
    block_hash,
    decode_block,
    encode_block,
    encode_block_header,
)
from latcoin.codec.constants import (
    FLAG_HAS_WITNESS,
    LOCK_P2LPKH,
    NETWORK_DEVNET,
    SCHEME_SIG_V1,
    TX_VERSION_V1,
)
from latcoin.codec.tx import Transaction, TxBody, TxInput, TxOutput, TxWitness


def _coinbase_tx() -> Transaction:
    body = TxBody(
        version=TX_VERSION_V1,
        network_id=NETWORK_DEVNET,
        flags=0,
        lock_height=0,
        inputs=[TxInput(prev_txid=b"\x00" * 32, prev_index=0xFFFFFFFF, sequence=0)],
        outputs=[TxOutput(amount=5_000_000_000, lock_type=LOCK_P2LPKH, scheme_id=SCHEME_SIG_V1, lock_data=b"\x11" * 32)],
        memo=b"",
    )
    return Transaction(body=body, witnesses=[])


def _regular_tx() -> Transaction:
    body = TxBody(
        version=TX_VERSION_V1,
        network_id=NETWORK_DEVNET,
        flags=FLAG_HAS_WITNESS,
        lock_height=0,
        inputs=[TxInput(prev_txid=b"\xab" * 32, prev_index=0, sequence=0)],
        outputs=[TxOutput(amount=1_000_000, lock_type=LOCK_P2LPKH, scheme_id=SCHEME_SIG_V1, lock_data=b"\x22" * 32)],
        memo=b"",
    )
    return Transaction(body=body, witnesses=[TxWitness(raw=b"signature-bytes")])


def _header() -> BlockHeader:
    return BlockHeader(
        version=1,
        prev_block_hash=b"\x00" * 32,
        merkle_root=b"\x77" * 32,
        timestamp=1_700_000_000,
        height=42,
        bits=8,
        nonce=9,
    )


def test_block_header_fixed_size() -> None:
    # version + prev_block_hash + merkle_root + timestamp + height + bits + nonce
    assert len(encode_block_header(_header())) == 4 + 32 + 32 + 8 + 4 + 4 + 8


def test_block_roundtrip_empty_body() -> None:
    block = Block(header=_header(), txs=[])
    assert decode_block(encode_block(block)) == block


def test_block_roundtrip_with_txs() -> None:
    block = Block(header=_header(), txs=[_coinbase_tx(), _regular_tx()])
    assert decode_block(encode_block(block)) == block


def test_block_hash_is_deterministic() -> None:
    h1 = block_hash(_header())
    h2 = block_hash(_header())
    assert h1 == h2
    assert len(h1) == 32


def test_block_hash_changes_when_header_changes() -> None:
    base = _header()
    other = BlockHeader(
        version=base.version,
        prev_block_hash=base.prev_block_hash,
        merkle_root=base.merkle_root,
        timestamp=base.timestamp,
        height=base.height,
        bits=base.bits,
        nonce=base.nonce + 1,
    )
    assert block_hash(base) != block_hash(other)
