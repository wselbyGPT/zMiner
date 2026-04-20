"""P2P wire framing for LatCoin.

Each network message is a 24-byte header followed by a variable-length payload.

Header layout (little-endian integers):

    offset  size  field
    ------  ----  ----------------------------------------------------------
    0       4     magic         — per-network constant, identifies protocol
    4       12    command       — ASCII name, null-padded (e.g. ``b"version"``)
    16      4     length        — payload length in bytes (uint32 LE)
    20      4     checksum      — first 4 bytes of ``hash32(payload)``

The empty payload has checksum ``hash32(b"")[:4]``.
"""
from __future__ import annotations

from dataclasses import dataclass

from latcoin.codec.constants import NETWORK_DEVNET, NETWORK_MAINNET, NETWORK_TESTNET
from latcoin.codec.hash import hash32
from latcoin.codec.primitives import u32le

HEADER_SIZE = 24
COMMAND_SIZE = 12
MAGIC_SIZE = 4
CHECKSUM_SIZE = 4

# 32 MiB is plenty for block messages on devnet; guards against DoS from a
# lying ``length`` field before we allocate the payload buffer.
MAX_PAYLOAD_BYTES = 32 * 1024 * 1024

NETWORK_MAGIC: dict[int, bytes] = {
    NETWORK_MAINNET: b"LATm",
    NETWORK_TESTNET: b"LATt",
    NETWORK_DEVNET: b"LATd",
}


class FrameError(Exception):
    """Raised when a wire frame cannot be decoded."""


@dataclass(frozen=True, slots=True)
class FrameHeader:
    magic: bytes
    command: bytes  # stripped of trailing NULs
    payload_length: int
    checksum: bytes


def magic_for_network(network_id: int) -> bytes:
    try:
        return NETWORK_MAGIC[network_id]
    except KeyError as exc:
        raise ValueError(f"no network magic defined for network_id={network_id}") from exc


def _encode_command(command: bytes | str) -> bytes:
    if isinstance(command, str):
        try:
            command = command.encode("ascii")
        except UnicodeEncodeError as exc:
            raise FrameError("command must be ASCII") from exc
    if not isinstance(command, (bytes, bytearray)):
        raise TypeError("command must be bytes or str")
    if len(command) == 0:
        raise FrameError("command must be non-empty")
    if len(command) > COMMAND_SIZE:
        raise FrameError(f"command exceeds {COMMAND_SIZE} bytes: {command!r}")
    if b"\x00" in command:
        raise FrameError("command must not contain NUL bytes")
    try:
        command.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FrameError("command must be ASCII") from exc
    return command.ljust(COMMAND_SIZE, b"\x00")


def payload_checksum(payload: bytes) -> bytes:
    return hash32(payload)[:CHECKSUM_SIZE]


def encode_frame(magic: bytes, command: bytes | str, payload: bytes) -> bytes:
    if len(magic) != MAGIC_SIZE:
        raise FrameError(f"magic must be {MAGIC_SIZE} bytes")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise FrameError(
            f"payload length {len(payload)} exceeds MAX_PAYLOAD_BYTES={MAX_PAYLOAD_BYTES}"
        )
    return b"".join(
        (
            magic,
            _encode_command(command),
            u32le(len(payload)),
            payload_checksum(payload),
            payload,
        )
    )


def decode_frame_header(header: bytes) -> FrameHeader:
    """Parse a 24-byte header; does not verify the checksum (payload not present)."""
    if len(header) != HEADER_SIZE:
        raise FrameError(f"header must be exactly {HEADER_SIZE} bytes, got {len(header)}")
    magic = bytes(header[0:MAGIC_SIZE])
    command_raw = bytes(header[MAGIC_SIZE : MAGIC_SIZE + COMMAND_SIZE])
    command = command_raw.rstrip(b"\x00")
    if b"\x00" in command:
        raise FrameError("command contains embedded NUL byte")
    try:
        command.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FrameError("command bytes are not ASCII") from exc
    length = int.from_bytes(header[16:20], "little")
    if length > MAX_PAYLOAD_BYTES:
        raise FrameError(f"payload length {length} exceeds MAX_PAYLOAD_BYTES={MAX_PAYLOAD_BYTES}")
    checksum = bytes(header[20:24])
    return FrameHeader(magic=magic, command=command, payload_length=length, checksum=checksum)


def verify_payload(header: FrameHeader, payload: bytes) -> None:
    if len(payload) != header.payload_length:
        raise FrameError(
            f"payload length {len(payload)} does not match header {header.payload_length}"
        )
    if payload_checksum(payload) != header.checksum:
        raise FrameError("payload checksum mismatch")


def decode_frame(buf: bytes, offset: int = 0) -> tuple[FrameHeader, bytes, int]:
    """Decode one frame from ``buf`` starting at ``offset``.

    Raises :class:`FrameError` if ``buf`` is truncated.
    Returns ``(header, payload, new_offset)``.
    """
    if len(buf) - offset < HEADER_SIZE:
        raise FrameError("buffer truncated before frame header")
    header = decode_frame_header(buf[offset : offset + HEADER_SIZE])
    start = offset + HEADER_SIZE
    end = start + header.payload_length
    if end > len(buf):
        raise FrameError("buffer truncated before full payload")
    payload = bytes(buf[start:end])
    verify_payload(header, payload)
    return header, payload, end


def try_decode_frame(buf: bytes, offset: int = 0) -> tuple[FrameHeader, bytes, int] | None:
    """Like :func:`decode_frame` but returns ``None`` when more bytes are needed.

    Still raises :class:`FrameError` for genuinely malformed input (bad checksum,
    length overrun, non-ASCII command, etc).
    """
    if len(buf) - offset < HEADER_SIZE:
        return None
    header = decode_frame_header(buf[offset : offset + HEADER_SIZE])
    start = offset + HEADER_SIZE
    end = start + header.payload_length
    if end > len(buf):
        return None
    payload = bytes(buf[start:end])
    verify_payload(header, payload)
    return header, payload, end
