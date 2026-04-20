from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .constants import (
    FLAG_HAS_MEMO,
    FLAG_HAS_WITNESS,
    LOCK_P2LPKH,
    LOCK_P2LSTH,
    LOCK_P2LTL,
    LOCK_P2LVAULT,
    MAX_OUTPUT_LOCK_BYTES,
    MAX_TX_INPUTS,
    MAX_TX_MEMO_BYTES,
    MAX_TX_OUTPUTS,
    MAX_WITNESS_ITEM_BYTES,
    NETWORK_DEVNET,
    NETWORK_MAINNET,
    NETWORK_TESTNET,
    TX_VERSION_V1,
)
from .errors import InvalidField, UnexpectedEOF
from .hash import hash32
from .primitives import (
    decode_varbytes,
    encode_varbytes,
    read_u16le,
    read_u32le,
    read_u64le,
    read_u8,
    u16le,
    u32le,
    u64le,
    u8,
)
from .varint import decode_varint, encode_varint

_VALID_NETWORK_IDS: Final[set[int]] = {
    NETWORK_MAINNET,
    NETWORK_TESTNET,
    NETWORK_DEVNET,
}
_KNOWN_LOCK_TYPES: Final[set[int]] = {
    LOCK_P2LPKH,
    LOCK_P2LSTH,
    LOCK_P2LTL,
    LOCK_P2LVAULT,
}
_KNOWN_FLAG_MASK: Final[int] = FLAG_HAS_WITNESS | FLAG_HAS_MEMO


@dataclass(frozen=True, slots=True)
class TxInput:
    prev_txid: bytes
    prev_index: int
    sequence: int


@dataclass(frozen=True, slots=True)
class TxOutput:
    amount: int
    lock_type: int
    scheme_id: int
    lock_data: bytes


@dataclass(frozen=True, slots=True)
class TxBody:
    version: int
    network_id: int
    flags: int
    lock_height: int
    inputs: list[TxInput]
    outputs: list[TxOutput]
    memo: bytes


@dataclass(frozen=True, slots=True)
class TxWitness:
    raw: bytes


@dataclass(frozen=True, slots=True)
class Transaction:
    body: TxBody
    witnesses: list[TxWitness]


def _read_exact(buf: bytes, offset: int, size: int) -> tuple[bytes, int]:
    end = offset + size
    if end > len(buf):
        raise UnexpectedEOF(f"needed {size} bytes at offset {offset}, only {len(buf) - offset} remain")
    return buf[offset:end], end


def _require_u32(name: str, value: int) -> None:
    if not (0 <= value <= 0xFFFFFFFF):
        raise InvalidField(f"{name} must fit in uint32")


def _require_u16(name: str, value: int) -> None:
    if not (0 <= value <= 0xFFFF):
        raise InvalidField(f"{name} must fit in uint16")


def _require_u8(name: str, value: int) -> None:
    if not (0 <= value <= 0xFF):
        raise InvalidField(f"{name} must fit in uint8")


def _validate_tx_input(txin: TxInput) -> None:
    if len(txin.prev_txid) != 32:
        raise InvalidField("prev_txid must be exactly 32 bytes")
    _require_u32("prev_index", txin.prev_index)
    _require_u32("sequence", txin.sequence)


def _validate_tx_output(txout: TxOutput) -> None:
    if not (0 <= txout.amount <= 0xFFFFFFFFFFFFFFFF):
        raise InvalidField("amount must fit in uint64")
    _require_u8("lock_type", txout.lock_type)
    _require_u16("scheme_id", txout.scheme_id)
    if txout.lock_type not in _KNOWN_LOCK_TYPES:
        raise InvalidField(f"unknown lock_type: {txout.lock_type}")
    if len(txout.lock_data) > MAX_OUTPUT_LOCK_BYTES:
        raise InvalidField("lock_data exceeds maximum size")


def _validate_tx_body(body: TxBody) -> None:
    _require_u8("version", body.version)
    _require_u8("network_id", body.network_id)
    if body.version != TX_VERSION_V1:
        raise InvalidField(f"unsupported transaction version: {body.version}")
    if body.network_id not in _VALID_NETWORK_IDS:
        raise InvalidField(f"invalid network_id: {body.network_id}")
    if body.flags & ~_KNOWN_FLAG_MASK:
        raise InvalidField(f"unknown transaction flags set: 0x{body.flags:04x}")
    _require_u32("lock_height", body.lock_height)

    if len(body.inputs) > MAX_TX_INPUTS:
        raise InvalidField("too many transaction inputs")
    if len(body.outputs) > MAX_TX_OUTPUTS:
        raise InvalidField("too many transaction outputs")
    if len(body.memo) > MAX_TX_MEMO_BYTES:
        raise InvalidField("memo exceeds maximum size")

    if body.memo and not (body.flags & FLAG_HAS_MEMO):
        raise InvalidField("memo bytes present but FLAG_HAS_MEMO is not set")

    for txin in body.inputs:
        _validate_tx_input(txin)
    for txout in body.outputs:
        _validate_tx_output(txout)


def _validate_transaction(tx: Transaction) -> None:
    _validate_tx_body(tx.body)

    has_witness_flag = bool(tx.body.flags & FLAG_HAS_WITNESS)
    if has_witness_flag:
        if len(tx.witnesses) != len(tx.body.inputs):
            raise InvalidField("witness count must equal input count when FLAG_HAS_WITNESS is set")
        for witness in tx.witnesses:
            if len(witness.raw) > MAX_WITNESS_ITEM_BYTES:
                raise InvalidField("witness item exceeds maximum size")
    else:
        if tx.witnesses:
            raise InvalidField("witnesses present but FLAG_HAS_WITNESS is not set")


def encode_tx_input(txin: TxInput) -> bytes:
    _validate_tx_input(txin)
    return b"".join(
        (
            txin.prev_txid,
            u32le(txin.prev_index),
            u32le(txin.sequence),
        )
    )


def decode_tx_input(buf: bytes, offset: int = 0) -> tuple[TxInput, int]:
    prev_txid, offset = _read_exact(buf, offset, 32)
    prev_index, offset = read_u32le(buf, offset)
    sequence, offset = read_u32le(buf, offset)
    txin = TxInput(
        prev_txid=prev_txid,
        prev_index=prev_index,
        sequence=sequence,
    )
    _validate_tx_input(txin)
    return txin, offset


def encode_tx_output(txout: TxOutput) -> bytes:
    _validate_tx_output(txout)
    return b"".join(
        (
            u64le(txout.amount),
            u8(txout.lock_type),
            u16le(txout.scheme_id),
            encode_varbytes(txout.lock_data),
        )
    )


def decode_tx_output(buf: bytes, offset: int = 0) -> tuple[TxOutput, int]:
    amount, offset = read_u64le(buf, offset)
    lock_type, offset = read_u8(buf, offset)
    scheme_id, offset = read_u16le(buf, offset)
    lock_data, offset = decode_varbytes(buf, offset, max_len=MAX_OUTPUT_LOCK_BYTES)

    txout = TxOutput(
        amount=amount,
        lock_type=lock_type,
        scheme_id=scheme_id,
        lock_data=lock_data,
    )
    _validate_tx_output(txout)
    return txout, offset


def encode_tx_body(body: TxBody) -> bytes:
    _validate_tx_body(body)

    parts: list[bytes] = [
        u8(body.version),
        u8(body.network_id),
        u16le(body.flags),
        u32le(body.lock_height),
        encode_varint(len(body.inputs)),
    ]
    parts.extend(encode_tx_input(txin) for txin in body.inputs)
    parts.append(encode_varint(len(body.outputs)))
    parts.extend(encode_tx_output(txout) for txout in body.outputs)
    parts.append(encode_varbytes(body.memo))
    return b"".join(parts)


def decode_tx_body(buf: bytes, offset: int = 0) -> tuple[TxBody, int]:
    version, offset = read_u8(buf, offset)
    network_id, offset = read_u8(buf, offset)
    flags, offset = read_u16le(buf, offset)
    lock_height, offset = read_u32le(buf, offset)

    input_count, offset = decode_varint(buf, offset)
    if input_count > MAX_TX_INPUTS:
        raise InvalidField("too many transaction inputs")
    inputs: list[TxInput] = []
    for _ in range(input_count):
        txin, offset = decode_tx_input(buf, offset)
        inputs.append(txin)

    output_count, offset = decode_varint(buf, offset)
    if output_count > MAX_TX_OUTPUTS:
        raise InvalidField("too many transaction outputs")
    outputs: list[TxOutput] = []
    for _ in range(output_count):
        txout, offset = decode_tx_output(buf, offset)
        outputs.append(txout)

    memo, offset = decode_varbytes(buf, offset, max_len=MAX_TX_MEMO_BYTES)

    body = TxBody(
        version=version,
        network_id=network_id,
        flags=flags,
        lock_height=lock_height,
        inputs=inputs,
        outputs=outputs,
        memo=memo,
    )
    _validate_tx_body(body)
    return body, offset


def encode_witness_item(witness: TxWitness) -> bytes:
    if len(witness.raw) > MAX_WITNESS_ITEM_BYTES:
        raise InvalidField("witness item exceeds maximum size")
    return encode_varbytes(witness.raw)


def decode_witness_item(buf: bytes, offset: int = 0) -> tuple[TxWitness, int]:
    raw, offset = decode_varbytes(buf, offset, max_len=MAX_WITNESS_ITEM_BYTES)
    return TxWitness(raw=raw), offset


def encode_witness_section(witnesses: list[TxWitness]) -> bytes:
    parts: list[bytes] = [encode_varint(len(witnesses))]
    parts.extend(encode_witness_item(w) for w in witnesses)
    return b"".join(parts)


def decode_witness_section(
    buf: bytes,
    offset: int = 0,
    *,
    expected_count: int | None = None,
) -> tuple[list[TxWitness], int]:
    count, offset = decode_varint(buf, offset)
    if expected_count is not None and count != expected_count:
        raise InvalidField("witness count does not match input count")

    witnesses: list[TxWitness] = []
    for _ in range(count):
        witness, offset = decode_witness_item(buf, offset)
        witnesses.append(witness)
    return witnesses, offset


def encode_transaction(tx: Transaction) -> bytes:
    _validate_transaction(tx)

    body_bytes = encode_tx_body(tx.body)
    if tx.body.flags & FLAG_HAS_WITNESS:
        return body_bytes + encode_witness_section(tx.witnesses)
    return body_bytes


def decode_transaction_from(buf: bytes, offset: int = 0) -> tuple[Transaction, int]:
    body, offset = decode_tx_body(buf, offset)

    witnesses: list[TxWitness] = []
    if body.flags & FLAG_HAS_WITNESS:
        witnesses, offset = decode_witness_section(
            buf,
            offset,
            expected_count=len(body.inputs),
        )

    tx = Transaction(body=body, witnesses=witnesses)
    _validate_transaction(tx)
    return tx, offset


def decode_transaction(buf: bytes) -> Transaction:
    tx, offset = decode_transaction_from(buf, 0)
    if offset != len(buf):
        raise InvalidField("trailing bytes after transaction payload")
    return tx


def txid(tx: Transaction) -> bytes:
    _validate_transaction(tx)
    return hash32(encode_tx_body(tx.body))


def wtxid(tx: Transaction) -> bytes:
    _validate_transaction(tx)
    if tx.body.flags & FLAG_HAS_WITNESS:
        return hash32(encode_tx_body(tx.body) + encode_witness_section(tx.witnesses))
    return txid(tx)
