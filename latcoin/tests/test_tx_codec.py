from __future__ import annotations

import pytest

from latcoin.codec.constants import (
    FLAG_HAS_MEMO,
    FLAG_HAS_WITNESS,
    LOCK_P2LPKH,
    NETWORK_DEVNET,
    SCHEME_SIG_V1,
    TX_VERSION_V1,
)
from latcoin.codec.errors import InvalidField
from latcoin.codec.tx import (
    Transaction,
    TxBody,
    TxInput,
    TxOutput,
    TxWitness,
    decode_transaction,
    encode_transaction,
    txid,
    wtxid,
)


def _coinbase_like_input() -> TxInput:
    return TxInput(prev_txid=b"\x00" * 32, prev_index=0xFFFFFFFF, sequence=0)


def _p2lpkh_output(amount: int = 5_000_000, tag: int = 0xAA) -> TxOutput:
    return TxOutput(
        amount=amount,
        lock_type=LOCK_P2LPKH,
        scheme_id=SCHEME_SIG_V1,
        lock_data=bytes([tag]) * 32,
    )


def _build_tx(*, flags: int = 0, memo: bytes = b"", witnesses: list[TxWitness] | None = None) -> Transaction:
    body = TxBody(
        version=TX_VERSION_V1,
        network_id=NETWORK_DEVNET,
        flags=flags,
        lock_height=0,
        inputs=[_coinbase_like_input()],
        outputs=[_p2lpkh_output()],
        memo=memo,
    )
    return Transaction(body=body, witnesses=witnesses or [])


def test_roundtrip_minimal_tx() -> None:
    tx = _build_tx()
    data = encode_transaction(tx)
    again = decode_transaction(data)
    assert again == tx


def test_roundtrip_with_memo() -> None:
    tx = _build_tx(flags=FLAG_HAS_MEMO, memo=b"hello-latcoin")
    again = decode_transaction(encode_transaction(tx))
    assert again.body.memo == b"hello-latcoin"
    assert again == tx


def test_roundtrip_with_witness() -> None:
    witness = TxWitness(raw=b"\xde\xad\xbe\xef")
    tx = _build_tx(flags=FLAG_HAS_WITNESS, witnesses=[witness])
    encoded = encode_transaction(tx)
    again = decode_transaction(encoded)
    assert again == tx
    # wtxid must differ from txid when witnesses are present
    assert wtxid(tx) != txid(tx)


def test_wtxid_matches_txid_without_witness() -> None:
    tx = _build_tx()
    assert wtxid(tx) == txid(tx)


def test_trailing_bytes_rejected() -> None:
    tx = _build_tx()
    data = encode_transaction(tx) + b"\x00"
    with pytest.raises(InvalidField):
        decode_transaction(data)


def test_memo_without_flag_rejected() -> None:
    body = TxBody(
        version=TX_VERSION_V1,
        network_id=NETWORK_DEVNET,
        flags=0,
        lock_height=0,
        inputs=[_coinbase_like_input()],
        outputs=[_p2lpkh_output()],
        memo=b"oops",
    )
    with pytest.raises(InvalidField):
        encode_transaction(Transaction(body=body, witnesses=[]))


def test_witness_count_mismatch_rejected() -> None:
    tx = _build_tx(flags=FLAG_HAS_WITNESS, witnesses=[])
    with pytest.raises(InvalidField):
        encode_transaction(tx)


def test_unknown_flag_rejected() -> None:
    body = TxBody(
        version=TX_VERSION_V1,
        network_id=NETWORK_DEVNET,
        flags=0x8000,
        lock_height=0,
        inputs=[_coinbase_like_input()],
        outputs=[_p2lpkh_output()],
        memo=b"",
    )
    with pytest.raises(InvalidField):
        encode_transaction(Transaction(body=body, witnesses=[]))
