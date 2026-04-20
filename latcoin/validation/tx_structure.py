from __future__ import annotations

from latcoin.codec.constants import (
    FLAG_HAS_MEMO,
    FLAG_HAS_WITNESS,
    LOCK_P2LPKH,
    LOCK_P2LSTH,
    LOCK_P2LTL,
    LOCK_P2LVAULT,
    MAX_MONEY,
    MAX_WITNESS_ITEM_BYTES,
)
from latcoin.codec.primitives import read_u16le, read_u32le, read_u8
from latcoin.codec.stealth import decode_stealth_lock
from latcoin.codec.tx import Transaction, TxOutput
from latcoin.codec.vault import decode_vault_lock
from latcoin.crypto.schemes import SUPPORTED_SIGNATURE_SCHEMES, SUPPORTED_STEALTH_SCHEMES
from latcoin.validation.errors import StructuralValidationError

_SUPPORTED_SIG_SCHEMES = set(SUPPORTED_SIGNATURE_SCHEMES)
_SUPPORTED_STEALTH_SUITES = set(SUPPORTED_STEALTH_SCHEMES)


def _is_coinbase_like(tx: Transaction) -> bool:
    if len(tx.body.inputs) != 1:
        return False
    txin = tx.body.inputs[0]
    return txin.prev_txid == (b"\x00" * 32) and txin.prev_index == 0xFFFFFFFF


def _raise(msg: str) -> None:
    raise StructuralValidationError(msg)


def _decode_p2ltl_lock(data: bytes) -> tuple[int, int, bytes, int, int]:
    offset = 0
    lock_version, offset = read_u8(data, offset)
    scheme_id, offset = read_u16le(data, offset)
    if offset + 32 > len(data):
        _raise("P2LTL lock_data truncated while reading key_hash")
    key_hash = data[offset : offset + 32]
    offset += 32
    unlock_height, offset = read_u32le(data, offset)
    flags, offset = read_u8(data, offset)
    if offset != len(data):
        _raise("P2LTL lock_data has trailing bytes")
    return lock_version, scheme_id, key_hash, unlock_height, flags


def _validate_lock_payload(txout: TxOutput) -> None:
    if txout.lock_type == LOCK_P2LPKH:
        if txout.scheme_id not in _SUPPORTED_SIG_SCHEMES:
            _raise(f"unsupported P2LPKH scheme_id: 0x{txout.scheme_id:04x}")
        if len(txout.lock_data) != 32:
            _raise("P2LPKH lock_data must be exactly 32 bytes")

    elif txout.lock_type == LOCK_P2LSTH:
        if txout.scheme_id not in _SUPPORTED_SIG_SCHEMES:
            _raise(f"unsupported P2LSTH spend scheme_id: 0x{txout.scheme_id:04x}")
        lock = decode_stealth_lock(txout.lock_data)
        if lock.lock_version != 0x01:
            _raise("unsupported stealth lock version")
        if lock.suite_id not in _SUPPORTED_STEALTH_SUITES:
            _raise("unsupported stealth suite_id")
        if len(lock.one_time_key_hash) != 32:
            _raise("stealth one_time_key_hash must be exactly 32 bytes")

    elif txout.lock_type == LOCK_P2LTL:
        if txout.scheme_id not in _SUPPORTED_SIG_SCHEMES:
            _raise(f"unsupported P2LTL scheme_id: 0x{txout.scheme_id:04x}")
        lock_version, scheme_id, key_hash, _unlock_height, flags = _decode_p2ltl_lock(txout.lock_data)
        if lock_version != 0x01:
            _raise("unsupported P2LTL lock version")
        if scheme_id != txout.scheme_id:
            _raise("P2LTL embedded scheme_id does not match output scheme_id")
        if len(key_hash) != 32:
            _raise("P2LTL key_hash must be exactly 32 bytes")
        if flags != 0:
            _raise("P2LTL flags must be zero in v0")

    elif txout.lock_type == LOCK_P2LVAULT:
        if txout.scheme_id not in _SUPPORTED_SIG_SCHEMES:
            _raise(f"unsupported P2LVAULT scheme_id: 0x{txout.scheme_id:04x}")
        lock = decode_vault_lock(txout.lock_data)
        if lock.lock_version != 0x01:
            _raise("unsupported vault lock version")
        if lock.scheme_id != txout.scheme_id:
            _raise("vault embedded scheme_id does not match output scheme_id")
        if len(lock.hot_key_hash) != 32 or len(lock.cold_key_hash) != 32:
            _raise("vault key hashes must be exactly 32 bytes")
        if lock.flags != 0:
            _raise("vault flags must be zero in v0")

    else:
        _raise(f"unknown lock_type: {txout.lock_type}")


def validate_tx_structure(tx: Transaction, *, allow_coinbase: bool = False) -> None:
    body = tx.body

    if not allow_coinbase and _is_coinbase_like(tx):
        _raise("coinbase-like transaction is not valid in ordinary tx validation")

    if len(body.inputs) == 0:
        _raise("transaction must have at least one input")
    if len(body.outputs) == 0:
        _raise("transaction must have at least one output")

    if body.flags & FLAG_HAS_MEMO:
        if len(body.memo) == 0:
            pass
    else:
        if body.memo:
            _raise("memo bytes present but FLAG_HAS_MEMO is not set")

    has_witness = bool(body.flags & FLAG_HAS_WITNESS)
    if has_witness:
        if len(tx.witnesses) != len(body.inputs):
            _raise("witness count must match input count")
        for idx, witness in enumerate(tx.witnesses):
            if len(witness.raw) > MAX_WITNESS_ITEM_BYTES:
                _raise(f"witness {idx} exceeds maximum size")
    else:
        if tx.witnesses:
            _raise("witnesses present without FLAG_HAS_WITNESS")

    seen_outpoints: set[tuple[bytes, int]] = set()
    for idx, txin in enumerate(body.inputs):
        outpoint = (txin.prev_txid, txin.prev_index)
        if outpoint in seen_outpoints:
            _raise(f"duplicate input at index {idx}")
        seen_outpoints.add(outpoint)

    output_sum = 0
    for idx, txout in enumerate(body.outputs):
        if txout.amount <= 0:
            _raise(f"output {idx} amount must be greater than zero")
        if txout.amount > MAX_MONEY:
            _raise(f"output {idx} amount exceeds MAX_MONEY")
        output_sum += txout.amount
        if output_sum > MAX_MONEY:
            _raise("aggregate output value exceeds MAX_MONEY")
        _validate_lock_payload(txout)
