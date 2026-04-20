from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from latcoin.codec.constants import MAX_MONEY
from latcoin.codec.tx import Transaction
from latcoin.validation.errors import ContextValidationError
from latcoin.validation.tx_structure import validate_tx_structure


@dataclass(frozen=True, slots=True)
class UtxoEntry:
    txid: bytes
    index: int
    amount: int
    lock_type: int
    scheme_id: int
    lock_data: bytes
    created_height: int
    is_coinbase: bool
    network_id: int | None = None


@dataclass(frozen=True, slots=True)
class ChainContext:
    network_id: int
    current_height: int
    median_time_past: int
    coinbase_maturity: int = 100


WitnessValidator = Callable[[Transaction, int, UtxoEntry, ChainContext], None]


def _raise(msg: str) -> None:
    raise ContextValidationError(msg)


def _is_coinbase_like(tx: Transaction) -> bool:
    if len(tx.body.inputs) != 1:
        return False
    txin = tx.body.inputs[0]
    return txin.prev_txid == (b"\x00" * 32) and txin.prev_index == 0xFFFFFFFF


def _checked_add_money(total: int, value: int, *, label: str) -> int:
    if value < 0:
        _raise(f"{label} includes a negative value")
    total += value
    if total > MAX_MONEY:
        _raise(f"{label} exceeds MAX_MONEY")
    return total


def validate_tx_against_utxos(
    tx: Transaction,
    utxo_lookup: Mapping[tuple[bytes, int], UtxoEntry],
    ctx: ChainContext,
    *,
    witness_validator: WitnessValidator | None = None,
) -> int:
    validate_tx_structure(tx)

    if _is_coinbase_like(tx):
        _raise("coinbase transactions must be validated at block level")

    if tx.body.network_id != ctx.network_id:
        _raise(
            f"transaction network_id {tx.body.network_id} "
            f"does not match chain context network_id {ctx.network_id}"
        )

    if ctx.current_height < tx.body.lock_height:
        _raise(
            f"transaction lock_height {tx.body.lock_height} "
            f"is greater than current height {ctx.current_height}"
        )

    if witness_validator is None:
        from latcoin.validation.witnesses import validate_input_witness as validator
    else:
        validator = witness_validator

    seen_outpoints: set[tuple[bytes, int]] = set()
    input_sum = 0

    for input_index, txin in enumerate(tx.body.inputs):
        outpoint = (txin.prev_txid, txin.prev_index)

        if outpoint in seen_outpoints:
            _raise(f"duplicate input outpoint at index {input_index}")
        seen_outpoints.add(outpoint)

        prevout = utxo_lookup.get(outpoint)
        if prevout is None:
            _raise(
                f"missing UTXO for input {input_index}: "
                f"{txin.prev_txid.hex()}:{txin.prev_index}"
            )

        if prevout.network_id is not None and prevout.network_id != ctx.network_id:
            _raise(
                f"input {input_index} references a UTXO from a different network: "
                f"{prevout.network_id}"
            )

        if prevout.is_coinbase:
            matured_at = prevout.created_height + ctx.coinbase_maturity
            if ctx.current_height < matured_at:
                _raise(
                    f"coinbase UTXO for input {input_index} is immature: "
                    f"current_height={ctx.current_height}, required={matured_at}"
                )

        validator(tx, input_index, prevout, ctx)
        input_sum = _checked_add_money(input_sum, prevout.amount, label="input sum")

    output_sum = 0
    for txout in tx.body.outputs:
        output_sum = _checked_add_money(output_sum, txout.amount, label="output sum")

    if input_sum < output_sum:
        _raise(
            f"transaction spends more than it owns: "
            f"inputs={input_sum}, outputs={output_sum}"
        )

    fee = input_sum - output_sum
    if fee < 0:
        _raise("computed negative fee")

    return fee
