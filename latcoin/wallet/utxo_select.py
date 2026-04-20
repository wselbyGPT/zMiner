from __future__ import annotations

from latcoin.validation.tx_context import UtxoEntry


class InsufficientFundsError(ValueError):
    pass


def select_utxos(utxos: list[UtxoEntry], target_amount: int) -> tuple[list[UtxoEntry], int]:
    if target_amount <= 0:
        raise ValueError("target_amount must be positive")

    ordered = sorted(utxos, key=lambda e: (e.amount, e.created_height, e.txid, e.index))
    selected: list[UtxoEntry] = []
    total = 0
    for entry in ordered:
        selected.append(entry)
        total += entry.amount
        if total >= target_amount:
            return selected, total

    raise InsufficientFundsError(
        f"insufficient funds: need {target_amount}, have {total}"
    )
