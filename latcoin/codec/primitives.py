from __future__ import annotations

from .errors import InvalidField, UnexpectedEOF
from .varint import decode_varint, encode_varint

def _check_uint(name: str, n: int, bits: int) -> None:
    if not isinstance(n, int):
        raise InvalidField(f"{name} must be an int")
    if n < 0 or n > (1 << bits) - 1:
        raise InvalidField(f"{name} must fit in uint{bits}")

def u8(n: int) -> bytes:
    _check_uint("u8", n, 8)
    return n.to_bytes(1, "little")

def u16le(n: int) -> bytes:
    _check_uint("u16", n, 16)
    return n.to_bytes(2, "little")

def u32le(n: int) -> bytes:
    _check_uint("u32", n, 32)
    return n.to_bytes(4, "little")

def u64le(n: int) -> bytes:
    _check_uint("u64", n, 64)
    return n.to_bytes(8, "little")

def _read_exact(buf: bytes, offset: int, size: int) -> tuple[bytes, int]:
    end = offset + size
    if end > len(buf):
        raise UnexpectedEOF(f"needed {size} bytes at offset {offset}, only {len(buf) - offset} remain")
    return buf[offset:end], end

def read_u8(buf: bytes, offset: int = 0) -> tuple[int, int]:
    data, offset = _read_exact(buf, offset, 1)
    return data[0], offset

def read_u16le(buf: bytes, offset: int = 0) -> tuple[int, int]:
    data, offset = _read_exact(buf, offset, 2)
    return int.from_bytes(data, "little"), offset

def read_u32le(buf: bytes, offset: int = 0) -> tuple[int, int]:
    data, offset = _read_exact(buf, offset, 4)
    return int.from_bytes(data, "little"), offset

def read_u64le(buf: bytes, offset: int = 0) -> tuple[int, int]:
    data, offset = _read_exact(buf, offset, 8)
    return int.from_bytes(data, "little"), offset

def encode_varbytes(b: bytes) -> bytes:
    return encode_varint(len(b)) + b

def decode_varbytes(buf: bytes, offset: int = 0, *, max_len: int | None = None) -> tuple[bytes, int]:
    length, offset = decode_varint(buf, offset)
    if max_len is not None and length > max_len:
        raise InvalidField(f"byte string length {length} exceeds limit {max_len}")
    return _read_exact(buf, offset, length)
