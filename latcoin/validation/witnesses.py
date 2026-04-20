from __future__ import annotations

from latcoin.codec.constants import FLAG_HAS_WITNESS
from latcoin.codec.tx import Transaction
from latcoin.validation.errors import WitnessValidationError
from latcoin.validation.scripts import validate_prevout_lock
from latcoin.validation.tx_context import ChainContext, UtxoEntry


def validate_input_witness(
    tx: Transaction,
    input_index: int,
    prevout: UtxoEntry,
    ctx: ChainContext,
) -> None:
    if not (tx.body.flags & FLAG_HAS_WITNESS):
        raise WitnessValidationError("transaction is missing FLAG_HAS_WITNESS")
    if input_index < 0 or input_index >= len(tx.witnesses):
        raise WitnessValidationError(f"input index {input_index} has no witness entry")
    validate_prevout_lock(tx, input_index, prevout, ctx)
