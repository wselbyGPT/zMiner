from __future__ import annotations

from dataclasses import dataclass

from .errors import InvalidField
from .primitives import read_u16le, read_u32le, read_u8, u16le, u32le, u8

@dataclass(frozen=True, slots=True)
class VaultLockData:
    lock_version: int
    scheme_id: int
    hot_key_hash: bytes
    cold_key_hash: bytes
    hot_delay_blocks: int
    flags: int

def encode_vault_lock(lock: VaultLockData) -> bytes:
    if len(lock.hot_key_hash) != 32 or len(lock.cold_key_hash) != 32:
        raise InvalidField("vault key hashes must be exactly 32 bytes")
    return b"".join(
        (
            u8(lock.lock_version),
            u16le(lock.scheme_id),
            lock.hot_key_hash,
            lock.cold_key_hash,
            u32le(lock.hot_delay_blocks),
            u8(lock.flags),
        )
    )

def decode_vault_lock(data: bytes) -> VaultLockData:
    offset = 0
    lock_version, offset = read_u8(data, offset)
    scheme_id, offset = read_u16le(data, offset)
    if offset + 64 > len(data):
        raise InvalidField("vault lock_data truncated while reading key hashes")
    hot_key_hash = data[offset:offset+32]
    offset += 32
    cold_key_hash = data[offset:offset+32]
    offset += 32
    hot_delay_blocks, offset = read_u32le(data, offset)
    flags, offset = read_u8(data, offset)
    if offset != len(data):
        raise InvalidField("vault lock_data has trailing bytes")
    return VaultLockData(
        lock_version=lock_version,
        scheme_id=scheme_id,
        hot_key_hash=hot_key_hash,
        cold_key_hash=cold_key_hash,
        hot_delay_blocks=hot_delay_blocks,
        flags=flags,
    )
