from __future__ import annotations

from .errors import InvalidField, NonCanonicalEncoding, UnexpectedEOF

def encode_varint(n: int) -> bytes:
    if n < 0:
        raise InvalidField("varint cannot encode negative values")
    if n <= 0xFC:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    if n <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + n.to_bytes(8, "little")
    raise InvalidField("varint value too large")

def decode_varint(buf: bytes, offset: int = 0) -> tuple[int, int]:
    if offset >= len(buf):
        raise UnexpectedEOF("unexpected EOF while reading varint")
    first = buf[offset]
    offset += 1

    if first <= 0xFC:
        return first, offset

    if first == 0xFD:
        end = offset + 2
        if end > len(buf):
            raise UnexpectedEOF("unexpected EOF while reading uint16 varint")
        value = int.from_bytes(buf[offset:end], "little")
        if value < 0xFD:
            raise NonCanonicalEncoding("non-canonical uint16 varint")
        return value, end

    if first == 0xFE:
        end = offset + 4
        if end > len(buf):
            raise UnexpectedEOF("unexpected EOF while reading uint32 varint")
        value = int.from_bytes(buf[offset:end], "little")
        if value <= 0xFFFF:
            raise NonCanonicalEncoding("non-canonical uint32 varint")
        return value, end

    end = offset + 8
    if end > len(buf):
        raise UnexpectedEOF("unexpected EOF while reading uint64 varint")
    value = int.from_bytes(buf[offset:end], "little")
    if value <= 0xFFFFFFFF:
        raise NonCanonicalEncoding("non-canonical uint64 varint")
    return value, end
