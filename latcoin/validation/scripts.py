from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from latcoin.codec.constants import (
    FLAG_HAS_WITNESS,
    LOCK_P2LPKH,
    LOCK_P2LSTH,
    LOCK_P2LTL,
    LOCK_P2LVAULT,
    STANDARD_SPEND,
    VAULT_SPEND_COLD,
    VAULT_SPEND_HOT,
)
from latcoin.codec.errors import CodecError, InvalidField
from latcoin.codec.hash import hash32
from latcoin.codec.primitives import (
    decode_varbytes,
    read_u16le,
    read_u32le,
    read_u64le,
    read_u8,
    u16le,
    u32le,
    u64le,
    u8,
)
from latcoin.codec.stealth import decode_stealth_lock
from latcoin.codec.tx import Transaction, encode_tx_output
from latcoin.codec.vault import decode_vault_lock
from latcoin.crypto.signatures import verify_signature
from latcoin.validation.errors import WitnessValidationError

if TYPE_CHECKING:
    from latcoin.validation.tx_context import ChainContext, UtxoEntry


@dataclass(frozen=True, slots=True)
class PrevoutContext:
    amount: int
    lock_type: int
    scheme_id: int
    lock_data: bytes


@dataclass(frozen=True, slots=True)
class StandardWitness:
    witness_version: int
    spend_mode: int
    scheme_id: int
    pubkey: bytes
    signature: bytes


@dataclass(frozen=True, slots=True)
class TimelockLockData:
    lock_version: int
    scheme_id: int
    key_hash: bytes
    unlock_height: int
    flags: int


def _raise(msg: str) -> None:
    raise WitnessValidationError(msg)


def _parse_standard_witness(raw: bytes) -> StandardWitness:
    try:
        offset = 0
        witness_version, offset = read_u8(raw, offset)
        spend_mode, offset = read_u8(raw, offset)
        scheme_id, offset = read_u16le(raw, offset)
        pubkey, offset = decode_varbytes(raw, offset)
        signature, offset = decode_varbytes(raw, offset)
    except CodecError as exc:
        _raise(f"malformed witness: {exc}")

    if offset != len(raw):
        _raise("witness has trailing bytes")

    return StandardWitness(
        witness_version=witness_version,
        spend_mode=spend_mode,
        scheme_id=scheme_id,
        pubkey=pubkey,
        signature=signature,
    )


def encode_standard_witness(
    *,
    pubkey: bytes,
    signature: bytes,
    scheme_id: int,
    spend_mode: int = STANDARD_SPEND,
    witness_version: int = 0x01,
) -> bytes:
    from latcoin.codec.primitives import encode_varbytes

    return b"".join(
        (
            u8(witness_version),
            u8(spend_mode),
            u16le(scheme_id),
            encode_varbytes(pubkey),
            encode_varbytes(signature),
        )
    )


def _decode_p2ltl_lock(data: bytes) -> TimelockLockData:
    try:
        offset = 0
        lock_version, offset = read_u8(data, offset)
        scheme_id, offset = read_u16le(data, offset)
        if offset + 32 > len(data):
            raise InvalidField("P2LTL lock_data truncated while reading key_hash")
        key_hash = data[offset : offset + 32]
        offset += 32
        unlock_height, offset = read_u32le(data, offset)
        flags, offset = read_u8(data, offset)
    except CodecError as exc:
        _raise(f"malformed P2LTL lock_data: {exc}")

    if offset != len(data):
        _raise("P2LTL lock_data has trailing bytes")

    return TimelockLockData(
        lock_version=lock_version,
        scheme_id=scheme_id,
        key_hash=key_hash,
        unlock_height=unlock_height,
        flags=flags,
    )


def build_sighash(
    tx: Transaction,
    input_index: int,
    prevout: PrevoutContext,
    spend_mode: int,
) -> bytes:
    if not (0 <= input_index < len(tx.body.inputs)):
        raise InvalidField("input_index out of range")

    current_input = tx.body.inputs[input_index]
    flags_masked = tx.body.flags & ~FLAG_HAS_WITNESS

    prevouts_blob = b"".join(
        txin.prev_txid + u32le(txin.prev_index)
        for txin in tx.body.inputs
    )
    sequences_blob = b"".join(u32le(txin.sequence) for txin in tx.body.inputs)
    outputs_blob = b"".join(encode_tx_output(txout) for txout in tx.body.outputs)

    hash_prevouts = hash32(prevouts_blob)
    hash_sequences = hash32(sequences_blob)
    hash_outputs = hash32(outputs_blob)
    hash_memo = hash32(tx.body.memo)
    prev_lock_hash = hash32(prevout.lock_data)

    preimage = b"".join(
        (
            b"LatCoin-TX-SIGHASH-v1",
            u8(tx.body.version),
            u8(tx.body.network_id),
            u16le(flags_masked),
            u32le(tx.body.lock_height),
            hash_prevouts,
            hash_sequences,
            hash_outputs,
            hash_memo,
            u32le(input_index),
            current_input.prev_txid,
            u32le(current_input.prev_index),
            u64le(prevout.amount),
            u8(prevout.lock_type),
            u16le(prevout.scheme_id),
            prev_lock_hash,
            u8(spend_mode),
        )
    )
    return hash32(preimage)


def validate_p2lpkh(
    tx: Transaction,
    input_index: int,
    prevout: "UtxoEntry",
) -> None:
    witness = _parse_standard_witness(tx.witnesses[input_index].raw)

    if witness.witness_version != 0x01:
        _raise("unsupported witness version for P2LPKH")
    if witness.spend_mode != STANDARD_SPEND:
        _raise("P2LPKH must use STANDARD spend mode")
    if witness.scheme_id != prevout.scheme_id:
        _raise("P2LPKH witness scheme_id does not match prevout scheme_id")
    if hash32(witness.pubkey) != prevout.lock_data:
        _raise("P2LPKH pubkey hash does not match prevout lock_data")

    sighash = build_sighash(
        tx,
        input_index,
        PrevoutContext(
            amount=prevout.amount,
            lock_type=prevout.lock_type,
            scheme_id=prevout.scheme_id,
            lock_data=prevout.lock_data,
        ),
        spend_mode=witness.spend_mode,
    )
    if not verify_signature(witness.pubkey, sighash, witness.signature, scheme_id=witness.scheme_id):
        _raise("P2LPKH signature verification failed")


def validate_p2lsth(
    tx: Transaction,
    input_index: int,
    prevout: "UtxoEntry",
) -> None:
    lock = decode_stealth_lock(prevout.lock_data)
    witness = _parse_standard_witness(tx.witnesses[input_index].raw)

    if witness.witness_version != 0x01:
        _raise("unsupported witness version for P2LSTH")
    if witness.spend_mode != STANDARD_SPEND:
        _raise("P2LSTH must use STANDARD spend mode")
    if witness.scheme_id != prevout.scheme_id:
        _raise("P2LSTH witness scheme_id does not match prevout scheme_id")
    if hash32(witness.pubkey) != lock.one_time_key_hash:
        _raise("P2LSTH revealed pubkey does not match one_time_key_hash")

    sighash = build_sighash(
        tx,
        input_index,
        PrevoutContext(
            amount=prevout.amount,
            lock_type=prevout.lock_type,
            scheme_id=prevout.scheme_id,
            lock_data=prevout.lock_data,
        ),
        spend_mode=witness.spend_mode,
    )
    if not verify_signature(witness.pubkey, sighash, witness.signature, scheme_id=witness.scheme_id):
        _raise("P2LSTH signature verification failed")


def validate_p2ltl(
    tx: Transaction,
    input_index: int,
    prevout: "UtxoEntry",
    ctx: "ChainContext",
) -> None:
    lock = _decode_p2ltl_lock(prevout.lock_data)
    witness = _parse_standard_witness(tx.witnesses[input_index].raw)

    if lock.lock_version != 0x01:
        _raise("unsupported P2LTL lock version")
    if lock.scheme_id != prevout.scheme_id:
        _raise("P2LTL embedded scheme_id does not match prevout scheme_id")
    if lock.flags != 0:
        _raise("P2LTL flags must be zero in v0")
    if ctx.current_height < lock.unlock_height:
        _raise(
            f"P2LTL output is still timelocked until height {lock.unlock_height}, "
            f"current height is {ctx.current_height}"
        )
    if witness.witness_version != 0x01:
        _raise("unsupported witness version for P2LTL")
    if witness.spend_mode != STANDARD_SPEND:
        _raise("P2LTL must use STANDARD spend mode")
    if witness.scheme_id != prevout.scheme_id:
        _raise("P2LTL witness scheme_id does not match prevout scheme_id")
    if hash32(witness.pubkey) != lock.key_hash:
        _raise("P2LTL pubkey hash does not match key_hash")

    sighash = build_sighash(
        tx,
        input_index,
        PrevoutContext(
            amount=prevout.amount,
            lock_type=prevout.lock_type,
            scheme_id=prevout.scheme_id,
            lock_data=prevout.lock_data,
        ),
        spend_mode=witness.spend_mode,
    )
    if not verify_signature(witness.pubkey, sighash, witness.signature, scheme_id=witness.scheme_id):
        _raise("P2LTL signature verification failed")


def validate_p2lvault(
    tx: Transaction,
    input_index: int,
    prevout: "UtxoEntry",
    ctx: "ChainContext",
) -> None:
    lock = decode_vault_lock(prevout.lock_data)
    witness = _parse_standard_witness(tx.witnesses[input_index].raw)

    if lock.lock_version != 0x01:
        _raise("unsupported vault lock version")
    if lock.scheme_id != prevout.scheme_id:
        _raise("vault embedded scheme_id does not match prevout scheme_id")
    if lock.flags != 0:
        _raise("vault flags must be zero in v0")
    if witness.witness_version != 0x01:
        _raise("unsupported witness version for P2LVAULT")
    if witness.scheme_id != prevout.scheme_id:
        _raise("vault witness scheme_id does not match prevout scheme_id")

    if witness.spend_mode == VAULT_SPEND_HOT:
        if hash32(witness.pubkey) != lock.hot_key_hash:
            _raise("vault HOT pubkey hash does not match hot_key_hash")
        required_height = prevout.created_height + lock.hot_delay_blocks
        if ctx.current_height < required_height:
            _raise(
                f"vault HOT spend is timelocked until height {required_height}, "
                f"current height is {ctx.current_height}"
            )
    elif witness.spend_mode == VAULT_SPEND_COLD:
        if hash32(witness.pubkey) != lock.cold_key_hash:
            _raise("vault COLD pubkey hash does not match cold_key_hash")
    else:
        _raise(f"unsupported vault spend mode: {witness.spend_mode}")

    sighash = build_sighash(
        tx,
        input_index,
        PrevoutContext(
            amount=prevout.amount,
            lock_type=prevout.lock_type,
            scheme_id=prevout.scheme_id,
            lock_data=prevout.lock_data,
        ),
        spend_mode=witness.spend_mode,
    )
    if not verify_signature(witness.pubkey, sighash, witness.signature, scheme_id=witness.scheme_id):
        _raise("P2LVAULT signature verification failed")


def validate_prevout_lock(
    tx: Transaction,
    input_index: int,
    prevout: "UtxoEntry",
    ctx: "ChainContext",
) -> None:
    if prevout.lock_type == LOCK_P2LPKH:
        validate_p2lpkh(tx, input_index, prevout)
    elif prevout.lock_type == LOCK_P2LSTH:
        validate_p2lsth(tx, input_index, prevout)
    elif prevout.lock_type == LOCK_P2LTL:
        validate_p2ltl(tx, input_index, prevout, ctx)
    elif prevout.lock_type == LOCK_P2LVAULT:
        validate_p2lvault(tx, input_index, prevout, ctx)
    else:
        _raise(f"unsupported prevout lock_type: {prevout.lock_type}")
