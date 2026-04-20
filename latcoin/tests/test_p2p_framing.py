from __future__ import annotations

import pytest

from latcoin.codec.constants import NETWORK_DEVNET, NETWORK_MAINNET, NETWORK_TESTNET
from latcoin.net.framing import (
    COMMAND_SIZE,
    HEADER_SIZE,
    MAX_PAYLOAD_BYTES,
    FrameError,
    FrameHeader,
    decode_frame,
    decode_frame_header,
    encode_frame,
    magic_for_network,
    payload_checksum,
    try_decode_frame,
)


def test_magic_is_four_bytes_per_network() -> None:
    assert len(magic_for_network(NETWORK_MAINNET)) == 4
    assert len(magic_for_network(NETWORK_TESTNET)) == 4
    assert len(magic_for_network(NETWORK_DEVNET)) == 4


def test_magic_values_are_distinct() -> None:
    m = magic_for_network(NETWORK_MAINNET)
    t = magic_for_network(NETWORK_TESTNET)
    d = magic_for_network(NETWORK_DEVNET)
    assert m != t != d and m != d


def test_magic_rejects_unknown_network() -> None:
    with pytest.raises(ValueError):
        magic_for_network(0xABCD)


def test_encode_frame_produces_header_plus_payload() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    payload = b"hello"
    frame = encode_frame(magic, "verack", payload)
    assert len(frame) == HEADER_SIZE + len(payload)
    assert frame.startswith(magic)
    assert frame[HEADER_SIZE:] == payload


def test_encode_decode_roundtrip_for_empty_payload() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    frame = encode_frame(magic, b"ping", b"")
    header, payload, off = decode_frame(frame)
    assert off == len(frame)
    assert header.magic == magic
    assert header.command == b"ping"
    assert header.payload_length == 0
    assert payload == b""


def test_encode_decode_roundtrip_for_large_payload() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    payload = bytes(range(256)) * 200  # 51200 bytes
    frame = encode_frame(magic, "block", payload)
    header, decoded, off = decode_frame(frame)
    assert off == len(frame)
    assert header.command == b"block"
    assert header.payload_length == len(payload)
    assert decoded == payload


def test_command_padded_with_nulls_in_header() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    frame = encode_frame(magic, "tx", b"\x01\x02")
    command_bytes = frame[4 : 4 + COMMAND_SIZE]
    assert command_bytes == b"tx" + b"\x00" * (COMMAND_SIZE - 2)


def test_decode_strips_null_padding_from_command() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    frame = encode_frame(magic, "headers", b"")
    header = decode_frame_header(frame[:HEADER_SIZE])
    assert header.command == b"headers"


def test_encode_rejects_overlong_command() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    with pytest.raises(FrameError):
        encode_frame(magic, "x" * (COMMAND_SIZE + 1), b"")


def test_encode_rejects_empty_command() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    with pytest.raises(FrameError):
        encode_frame(magic, "", b"")


def test_encode_rejects_non_ascii_command() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    with pytest.raises(FrameError):
        encode_frame(magic, "héadr", b"")


def test_encode_rejects_embedded_null_in_command() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    with pytest.raises(FrameError):
        encode_frame(magic, b"foo\x00bar", b"")


def test_encode_rejects_bad_magic_length() -> None:
    with pytest.raises(FrameError):
        encode_frame(b"LAT", "ping", b"")


def test_decode_rejects_short_header() -> None:
    with pytest.raises(FrameError):
        decode_frame_header(b"\x00" * (HEADER_SIZE - 1))


def test_decode_rejects_payload_length_overflow() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    # Forge a header with length > MAX_PAYLOAD_BYTES
    forged = (
        magic
        + b"verack".ljust(COMMAND_SIZE, b"\x00")
        + (MAX_PAYLOAD_BYTES + 1).to_bytes(4, "little")
        + b"\x00\x00\x00\x00"
    )
    with pytest.raises(FrameError):
        decode_frame_header(forged)


def test_decode_full_buffer_detects_bad_checksum() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    frame = bytearray(encode_frame(magic, "tx", b"payload"))
    # Corrupt the first byte of payload
    frame[HEADER_SIZE] ^= 0xFF
    with pytest.raises(FrameError, match="checksum"):
        decode_frame(bytes(frame))


def test_decode_full_buffer_detects_truncated_payload() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    frame = encode_frame(magic, "tx", b"ABCDEFGHIJ")
    with pytest.raises(FrameError):
        decode_frame(frame[:-1])


def test_try_decode_returns_none_when_header_incomplete() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    frame = encode_frame(magic, "ping", b"")
    assert try_decode_frame(frame[:10]) is None


def test_try_decode_returns_none_when_payload_incomplete() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    frame = encode_frame(magic, "tx", b"ABCDE")
    assert try_decode_frame(frame[: HEADER_SIZE + 2]) is None


def test_try_decode_returns_frame_on_complete_buffer() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    frame = encode_frame(magic, "inv", b"\x01\x02\x03")
    result = try_decode_frame(frame)
    assert result is not None
    header, payload, off = result
    assert off == len(frame)
    assert header.command == b"inv"
    assert payload == b"\x01\x02\x03"


def test_try_decode_still_raises_on_bad_checksum() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    frame = bytearray(encode_frame(magic, "tx", b"corrupt-me"))
    frame[HEADER_SIZE] ^= 0x01
    with pytest.raises(FrameError, match="checksum"):
        try_decode_frame(bytes(frame))


def test_two_frames_can_be_decoded_sequentially() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    a = encode_frame(magic, "ping", b"1")
    b = encode_frame(magic, "pong", b"2")
    buf = a + b
    h1, p1, off1 = decode_frame(buf)
    assert off1 == len(a)
    h2, p2, off2 = decode_frame(buf, off1)
    assert off2 == len(buf)
    assert h1.command == b"ping" and p1 == b"1"
    assert h2.command == b"pong" and p2 == b"2"


def test_payload_checksum_is_deterministic() -> None:
    c1 = payload_checksum(b"hello")
    c2 = payload_checksum(b"hello")
    assert c1 == c2 and len(c1) == 4


def test_frame_header_dataclass_equality() -> None:
    magic = magic_for_network(NETWORK_DEVNET)
    frame = encode_frame(magic, "ping", b"")
    h1 = decode_frame_header(frame[:HEADER_SIZE])
    h2 = decode_frame_header(frame[:HEADER_SIZE])
    assert h1 == h2
    assert isinstance(h1, FrameHeader)
