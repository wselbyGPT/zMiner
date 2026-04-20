from __future__ import annotations

import pytest

from latcoin.codec.errors import InvalidField, UnexpectedEOF
from latcoin.codec.primitives import (
    decode_varbytes,
    encode_varbytes,
    read_u8,
    read_u16le,
    read_u32le,
    read_u64le,
    u8,
    u16le,
    u32le,
    u64le,
)


@pytest.mark.parametrize(
    ("enc", "dec", "value"),
    [
        (u8, read_u8, 0),
        (u8, read_u8, 0xFF),
        (u16le, read_u16le, 0x1234),
        (u16le, read_u16le, 0xFFFF),
        (u32le, read_u32le, 0xDEAD_BEEF),
        (u64le, read_u64le, 0xCAFEBABE_DEADBEEF),
    ],
)
def test_fixed_width_uint_roundtrips(enc, dec, value: int) -> None:
    buf = enc(value)
    got, consumed = dec(buf, 0)
    assert got == value
    assert consumed == len(buf)


@pytest.mark.parametrize("fn, bits", [(u8, 8), (u16le, 16), (u32le, 32), (u64le, 64)])
def test_uint_rejects_overflow(fn, bits: int) -> None:
    with pytest.raises(InvalidField):
        fn(1 << bits)


@pytest.mark.parametrize("fn", [u8, u16le, u32le, u64le])
def test_uint_rejects_negative(fn) -> None:
    with pytest.raises(InvalidField):
        fn(-1)


@pytest.mark.parametrize("payload", [b"", b"hello", bytes(range(256))])
def test_varbytes_roundtrip(payload: bytes) -> None:
    encoded = encode_varbytes(payload)
    decoded, offset = decode_varbytes(encoded, 0)
    assert decoded == payload
    assert offset == len(encoded)


def test_varbytes_max_len_enforced() -> None:
    with pytest.raises(InvalidField):
        decode_varbytes(encode_varbytes(b"abcd"), 0, max_len=3)


def test_read_past_end_raises() -> None:
    with pytest.raises(UnexpectedEOF):
        read_u32le(b"\x01\x02", 0)
