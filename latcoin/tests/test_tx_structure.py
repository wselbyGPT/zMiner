from __future__ import annotations

import pytest

from latcoin.codec.constants import (
    LOCK_P2LPKH,
    MAX_MONEY,
    NETWORK_DEVNET,
    SCHEME_SIG_V1,
    TX_VERSION_V1,
)
from latcoin.codec.tx import Transaction, TxBody, TxInput, TxOutput
from latcoin.validation.errors import StructuralValidationError
from latcoin.validation.tx_structure import validate_tx_structure


def _make_input(tag: int = 1, index: int = 0) -> TxInput:
    return TxInput(prev_txid=bytes([tag]) * 32, prev_index=index, sequence=0)


def _make_output(amount: int = 1_000) -> TxOutput:
    return TxOutput(
        amount=amount,
        lock_type=LOCK_P2LPKH,
        scheme_id=SCHEME_SIG_V1,
        lock_data=b"\xaa" * 32,
    )


def _make_tx(
    *,
    inputs: list[TxInput] | None = None,
    outputs: list[TxOutput] | None = None,
) -> Transaction:
    body = TxBody(
        version=TX_VERSION_V1,
        network_id=NETWORK_DEVNET,
        flags=0,
        lock_height=0,
        inputs=inputs if inputs is not None else [_make_input()],
        outputs=outputs if outputs is not None else [_make_output()],
        memo=b"",
    )
    return Transaction(body=body, witnesses=[])


def test_valid_tx_passes() -> None:
    validate_tx_structure(_make_tx())


def test_no_inputs_rejected() -> None:
    with pytest.raises(StructuralValidationError, match="at least one input"):
        validate_tx_structure(_make_tx(inputs=[]))


def test_no_outputs_rejected() -> None:
    with pytest.raises(StructuralValidationError, match="at least one output"):
        validate_tx_structure(_make_tx(outputs=[]))


def test_duplicate_inputs_rejected() -> None:
    dup = _make_input(tag=9, index=0)
    with pytest.raises(StructuralValidationError, match="duplicate input"):
        validate_tx_structure(_make_tx(inputs=[dup, dup]))


def test_zero_amount_output_rejected() -> None:
    with pytest.raises(StructuralValidationError, match="greater than zero"):
        validate_tx_structure(_make_tx(outputs=[_make_output(amount=0)]))


def test_output_exceeding_max_money_rejected() -> None:
    with pytest.raises(StructuralValidationError, match="MAX_MONEY"):
        validate_tx_structure(_make_tx(outputs=[_make_output(amount=MAX_MONEY + 1)]))


def test_aggregate_output_overflow_rejected() -> None:
    half = MAX_MONEY // 2 + 1
    outs = [_make_output(amount=half), _make_output(amount=half)]
    with pytest.raises(StructuralValidationError, match="aggregate"):
        validate_tx_structure(_make_tx(outputs=outs))


def test_unsupported_scheme_id_rejected() -> None:
    bad = TxOutput(amount=10, lock_type=LOCK_P2LPKH, scheme_id=0x00AA, lock_data=b"\xaa" * 32)
    with pytest.raises(StructuralValidationError, match="scheme_id"):
        validate_tx_structure(_make_tx(outputs=[bad]))


def test_short_p2lpkh_lock_data_rejected() -> None:
    bad = TxOutput(amount=10, lock_type=LOCK_P2LPKH, scheme_id=SCHEME_SIG_V1, lock_data=b"\xaa" * 31)
    with pytest.raises(StructuralValidationError, match="32 bytes"):
        validate_tx_structure(_make_tx(outputs=[bad]))


def test_coinbase_input_rejected_by_default() -> None:
    coinbase_in = TxInput(prev_txid=b"\x00" * 32, prev_index=0xFFFFFFFF, sequence=0)
    with pytest.raises(StructuralValidationError, match="coinbase"):
        validate_tx_structure(_make_tx(inputs=[coinbase_in]))


def test_coinbase_allowed_when_requested() -> None:
    coinbase_in = TxInput(prev_txid=b"\x00" * 32, prev_index=0xFFFFFFFF, sequence=0)
    validate_tx_structure(_make_tx(inputs=[coinbase_in]), allow_coinbase=True)
