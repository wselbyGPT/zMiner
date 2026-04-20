from __future__ import annotations

import pytest

from latcoin.codec.errors import InvalidField, NonCanonicalEncoding, UnexpectedEOF
from latcoin.codec.varint import decode_varint, encode_varint


@pytest.mark.parametrize(
    "value",
    [0, 1, 252, 253, 254, 0xFFFF - 1, 0xFFFF, 0x10000, 0xFFFFFFFF - 1, 0xFFFFFFFF, 0x1_0000_0000, 0xFFFF_FFFF_FFFF_FFFF],
)
def test_varint_roundtrip(value: int) -> None:
    encoded = encode_varint(value)
    decoded, consumed = decode_varint(encoded, 0)
    assert decoded == value
    assert consumed == len(encoded)


def test_varint_prefix_widths() -> None:
    assert len(encode_varint(0)) == 1
    assert len(encode_varint(252)) == 1
    assert len(encode_varint(253)) == 3
    assert len(encode_varint(0xFFFF)) == 3
    assert len(encode_varint(0x10000)) == 5
    assert len(encode_varint(0xFFFFFFFF)) == 5
    assert len(encode_varint(0x1_0000_0000)) == 9


def test_varint_rejects_negative() -> None:
    with pytest.raises(InvalidField):
        encode_varint(-1)


def test_varint_rejects_overflow() -> None:
    with pytest.raises(InvalidField):
        encode_varint(1 << 64)


def test_varint_decode_truncated_raises() -> None:
    with pytest.raises(UnexpectedEOF):
        decode_varint(b"\xfd\x01", 0)


def test_varint_decode_noncanonical_raises() -> None:
    with pytest.raises(NonCanonicalEncoding):
        decode_varint(b"\xfd\x00\x00", 0)
    with pytest.raises(NonCanonicalEncoding):
        decode_varint(b"\xfe\x00\x00\x00\x00", 0)
