from __future__ import annotations

from latcoin.codec.constants import LOCK_P2LPKH, LOCK_P2LSTH, LOCK_P2LVAULT, SCHEME_SIG_V1, TX_VERSION_V1
from latcoin.codec.tx import Transaction, TxBody, TxInput, TxOutput
from latcoin.validation.tx_context import UtxoEntry


def build_payment_tx(
    *,
    network_id: int,
    selected_utxos: list[UtxoEntry],
    recipient_lock_type: int,
    recipient_lock_data: bytes,
    recipient_scheme_id: int,
    amount: int,
    fee: int,
    change_key_hash: bytes | None = None,
    change_scheme_id: int = SCHEME_SIG_V1,
    lock_height: int = 0,
) -> tuple[Transaction, int]:
    if amount <= 0:
        raise ValueError("amount must be positive")
    if fee < 0:
        raise ValueError("fee must be non-negative")
    if not selected_utxos:
        raise ValueError("selected_utxos must not be empty")

    input_total = sum(entry.amount for entry in selected_utxos)
    required = amount + fee
    if input_total < required:
        raise ValueError(f"input total {input_total} is below required amount {required}")

    inputs = [TxInput(prev_txid=entry.txid, prev_index=entry.index, sequence=0xFFFFFFFF) for entry in selected_utxos]
    outputs = [TxOutput(amount=amount, lock_type=recipient_lock_type, scheme_id=recipient_scheme_id, lock_data=recipient_lock_data)]

    change = input_total - required
    if change > 0:
        if change_key_hash is None:
            raise ValueError("change_key_hash is required when a change output is needed")
        outputs.append(TxOutput(amount=change, lock_type=LOCK_P2LPKH, scheme_id=change_scheme_id, lock_data=change_key_hash))

    tx = Transaction(
        body=TxBody(
            version=TX_VERSION_V1,
            network_id=network_id,
            flags=0,
            lock_height=lock_height,
            inputs=inputs,
            outputs=outputs,
            memo=b"",
        ),
        witnesses=[],
    )
    return tx, change


def build_p2lpkh_payment_tx(
    *,
    network_id: int,
    selected_utxos: list[UtxoEntry],
    recipient_key_hash: bytes,
    recipient_scheme_id: int = SCHEME_SIG_V1,
    amount: int,
    fee: int,
    change_key_hash: bytes | None = None,
    change_scheme_id: int = SCHEME_SIG_V1,
    lock_height: int = 0,
) -> tuple[Transaction, int]:
    if len(recipient_key_hash) != 32:
        raise ValueError("recipient_key_hash must be exactly 32 bytes")
    if change_key_hash is not None and len(change_key_hash) != 32:
        raise ValueError("change_key_hash must be exactly 32 bytes")
    return build_payment_tx(
        network_id=network_id,
        selected_utxos=selected_utxos,
        recipient_lock_type=LOCK_P2LPKH,
        recipient_lock_data=recipient_key_hash,
        recipient_scheme_id=recipient_scheme_id,
        amount=amount,
        fee=fee,
        change_key_hash=change_key_hash,
        change_scheme_id=change_scheme_id,
        lock_height=lock_height,
    )


def build_p2lvault_funding_tx(
    *,
    network_id: int,
    selected_utxos: list[UtxoEntry],
    vault_lock_data: bytes,
    vault_scheme_id: int,
    amount: int,
    fee: int,
    change_key_hash: bytes | None = None,
    change_scheme_id: int = SCHEME_SIG_V1,
    lock_height: int = 0,
) -> tuple[Transaction, int]:
    return build_payment_tx(
        network_id=network_id,
        selected_utxos=selected_utxos,
        recipient_lock_type=LOCK_P2LVAULT,
        recipient_lock_data=vault_lock_data,
        recipient_scheme_id=vault_scheme_id,
        amount=amount,
        fee=fee,
        change_key_hash=change_key_hash,
        change_scheme_id=change_scheme_id,
        lock_height=lock_height,
    )


def build_p2lsth_payment_tx(
    *,
    network_id: int,
    selected_utxos: list[UtxoEntry],
    stealth_lock_data: bytes,
    spend_scheme_id: int,
    amount: int,
    fee: int,
    change_key_hash: bytes | None = None,
    change_scheme_id: int = SCHEME_SIG_V1,
    lock_height: int = 0,
) -> tuple[Transaction, int]:
    return build_payment_tx(
        network_id=network_id,
        selected_utxos=selected_utxos,
        recipient_lock_type=LOCK_P2LSTH,
        recipient_lock_data=stealth_lock_data,
        recipient_scheme_id=spend_scheme_id,
        amount=amount,
        fee=fee,
        change_key_hash=change_key_hash,
        change_scheme_id=change_scheme_id,
        lock_height=lock_height,
    )
