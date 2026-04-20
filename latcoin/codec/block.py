from __future__ import annotations

from dataclasses import dataclass

from .errors import InvalidField
from .hash import hash32
from .primitives import read_u32le, read_u64le, u32le, u64le
from .tx import Transaction, decode_transaction, decode_transaction_from, encode_transaction
from .varint import decode_varint, encode_varint


@dataclass(frozen=True, slots=True)
class BlockHeader:
    version: int
    prev_block_hash: bytes
    merkle_root: bytes
    timestamp: int
    height: int
    bits: int
    nonce: int


@dataclass(frozen=True, slots=True)
class Block:
    header: BlockHeader
    txs: list[Transaction]


def _validate_header(header: BlockHeader) -> None:
    if not (0 <= header.version <= 0xFFFFFFFF):
        raise InvalidField("block header version must fit in uint32")
    if len(header.prev_block_hash) != 32:
        raise InvalidField("prev_block_hash must be exactly 32 bytes")
    if len(header.merkle_root) != 32:
        raise InvalidField("merkle_root must be exactly 32 bytes")
    if not (0 <= header.timestamp <= 0xFFFFFFFFFFFFFFFF):
        raise InvalidField("timestamp must fit in uint64")
    if not (0 <= header.height <= 0xFFFFFFFF):
        raise InvalidField("height must fit in uint32")
    if not (0 <= header.bits <= 0xFFFFFFFF):
        raise InvalidField("bits must fit in uint32")
    if not (0 <= header.nonce <= 0xFFFFFFFFFFFFFFFF):
        raise InvalidField("nonce must fit in uint64")


def encode_block_header(header: BlockHeader) -> bytes:
    _validate_header(header)
    return b"".join(
        (
            u32le(header.version),
            header.prev_block_hash,
            header.merkle_root,
            u64le(header.timestamp),
            u32le(header.height),
            u32le(header.bits),
            u64le(header.nonce),
        )
    )


def decode_block_header(buf: bytes, offset: int = 0) -> tuple[BlockHeader, int]:
    version, offset = read_u32le(buf, offset)
    end = offset + 32
    if end > len(buf):
        raise InvalidField("truncated prev_block_hash")
    prev_block_hash = buf[offset:end]
    offset = end
    end = offset + 32
    if end > len(buf):
        raise InvalidField("truncated merkle_root")
    merkle_root = buf[offset:end]
    offset = end
    timestamp, offset = read_u64le(buf, offset)
    height, offset = read_u32le(buf, offset)
    bits, offset = read_u32le(buf, offset)
    nonce, offset = read_u64le(buf, offset)
    header = BlockHeader(
        version=version,
        prev_block_hash=prev_block_hash,
        merkle_root=merkle_root,
        timestamp=timestamp,
        height=height,
        bits=bits,
        nonce=nonce,
    )
    _validate_header(header)
    return header, offset


def encode_block(block: Block) -> bytes:
    parts = [encode_block_header(block.header), encode_varint(len(block.txs))]
    parts.extend(encode_transaction(tx) for tx in block.txs)
    return b"".join(parts)


def decode_block(buf: bytes) -> Block:
    header, offset = decode_block_header(buf, 0)
    tx_count, offset = decode_varint(buf, offset)
    txs: list[Transaction] = []
    for _ in range(tx_count):
        tx, offset = decode_transaction_from(buf, offset)
        txs.append(tx)
    if offset != len(buf):
        raise InvalidField("trailing bytes after block payload")
    return Block(header=header, txs=txs)


def block_hash(header: BlockHeader) -> bytes:
    return hash32(encode_block_header(header))
