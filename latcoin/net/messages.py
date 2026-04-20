"""Payload codecs for LatCoin P2P messages.

Wire protocol summary
---------------------
Every message travels inside a framing.encode_frame envelope (24-byte header +
payload).  This module owns only the payload layer:

    encode_*(msg) -> bytes      payload bytes to pass to encode_frame
    decode_*(payload) -> msg    decode raw payload bytes back to a dataclass

Command → payload format
------------------------
version     VersionMessage
verack       empty (b"")
ping         PingMessage  (8-byte nonce)
pong         PingMessage  (8-byte nonce)
getaddr      empty (b"")
addr         AddrMessage
inv          InvMessage
getdata      InvMessage
notfound     InvMessage
getblocks    GetBlocksMessage
getheaders   GetBlocksMessage
headers      HeadersMessage
block        raw block bytes (use codec.block.encode_block / decode_block)
tx           raw tx bytes   (use codec.tx.encode_transaction / decode_transaction)
reject       RejectMessage
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from latcoin.codec.block import BlockHeader, decode_block_header, encode_block_header
from latcoin.codec.primitives import (
    decode_varbytes,
    encode_varbytes,
    read_u16le,
    read_u32le,
    read_u64le,
    u16le,
    u32le,
    u64le,
)
from latcoin.codec.varint import decode_varint, encode_varint

PROTOCOL_VERSION: int = 70001
USER_AGENT: bytes = b"/latcoind:0.1/"

# Service-flag bitfield values
SVC_NETWORK: int = 1 << 0   # full-node, can serve the block chain

# Inventory type codes
INV_TX: int = 1
INV_BLOCK: int = 2

# Reject reason codes (mirrors Bitcoin's REJECT_* codes)
REJECT_MALFORMED: int = 0x01
REJECT_INVALID: int = 0x10
REJECT_OBSOLETE: int = 0x11
REJECT_DUPLICATE: int = 0x12
REJECT_NONSTANDARD: int = 0x40
REJECT_DUST: int = 0x41
REJECT_INSUFFICIENTFEE: int = 0x42
REJECT_CHECKPOINT: int = 0x43

# IPv4-mapped-in-IPv6 prefix (10 × 0x00 + 0xFFFF)
_IPV4_PREFIX: bytes = b"\x00" * 10 + b"\xff\xff"


class MessageError(Exception):
    """Raised when a message payload cannot be decoded."""


# ---------------------------------------------------------------------------
# version / verack
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class VersionMessage:
    version: int
    services: int
    timestamp: int
    recv_ip: bytes    # 16 bytes, IPv4-mapped or raw IPv6
    recv_port: int    # u16
    from_ip: bytes    # 16 bytes
    from_port: int    # u16
    nonce: int        # u64, random; used to detect self-connections
    user_agent: bytes # max 256 bytes
    start_height: int # best block height known to the sender


def encode_version(msg: VersionMessage) -> bytes:
    if len(msg.recv_ip) != 16:
        raise MessageError("recv_ip must be exactly 16 bytes")
    if len(msg.from_ip) != 16:
        raise MessageError("from_ip must be exactly 16 bytes")
    if len(msg.user_agent) > 256:
        raise MessageError("user_agent exceeds 256 bytes")
    return b"".join((
        u32le(msg.version),
        u64le(msg.services),
        u64le(msg.timestamp),
        msg.recv_ip,
        u16le(msg.recv_port),
        msg.from_ip,
        u16le(msg.from_port),
        u64le(msg.nonce),
        encode_varbytes(msg.user_agent),
        u32le(msg.start_height),
    ))


def decode_version(payload: bytes) -> VersionMessage:
    try:
        version, off = read_u32le(payload, 0)
        services, off = read_u64le(payload, off)
        timestamp, off = read_u64le(payload, off)
        if off + 16 > len(payload):
            raise MessageError("truncated recv_ip")
        recv_ip = bytes(payload[off:off + 16])
        off += 16
        recv_port, off = read_u16le(payload, off)
        if off + 16 > len(payload):
            raise MessageError("truncated from_ip")
        from_ip = bytes(payload[off:off + 16])
        off += 16
        from_port, off = read_u16le(payload, off)
        nonce, off = read_u64le(payload, off)
        user_agent, off = decode_varbytes(payload, off, max_len=256)
        start_height, off = read_u32le(payload, off)
    except MessageError:
        raise
    except Exception as exc:
        raise MessageError(f"malformed version payload: {exc}") from exc
    return VersionMessage(
        version=version, services=services, timestamp=timestamp,
        recv_ip=recv_ip, recv_port=recv_port,
        from_ip=from_ip, from_port=from_port,
        nonce=nonce, user_agent=user_agent, start_height=start_height,
    )


def encode_verack() -> bytes:
    return b""


# ---------------------------------------------------------------------------
# ping / pong
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class PingMessage:
    nonce: int  # u64; echoed back in pong


def encode_ping(msg: PingMessage) -> bytes:
    return u64le(msg.nonce)


def decode_ping(payload: bytes) -> PingMessage:
    if len(payload) < 8:
        raise MessageError("ping payload too short (need 8 bytes)")
    return PingMessage(nonce=int.from_bytes(payload[:8], "little"))


def encode_pong(msg: PingMessage) -> bytes:
    return u64le(msg.nonce)


def decode_pong(payload: bytes) -> PingMessage:
    if len(payload) < 8:
        raise MessageError("pong payload too short (need 8 bytes)")
    return PingMessage(nonce=int.from_bytes(payload[:8], "little"))


# ---------------------------------------------------------------------------
# addr / getaddr
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class NetAddr:
    timestamp: int  # u32 unix seconds; when this peer was last seen
    ip: bytes       # 16 bytes
    port: int       # u16


@dataclass(frozen=True, slots=True)
class AddrMessage:
    addrs: list[NetAddr]


def encode_addr(msg: AddrMessage) -> bytes:
    parts: list[bytes] = [encode_varint(len(msg.addrs))]
    for a in msg.addrs:
        if len(a.ip) != 16:
            raise MessageError("NetAddr.ip must be 16 bytes")
        parts.append(u32le(a.timestamp))
        parts.append(a.ip)
        parts.append(u16le(a.port))
    return b"".join(parts)


def decode_addr(payload: bytes) -> AddrMessage:
    try:
        count, off = decode_varint(payload, 0)
        if count > 1000:
            raise MessageError(f"addr count {count} exceeds limit of 1000")
        addrs: list[NetAddr] = []
        for _ in range(count):
            ts, off = read_u32le(payload, off)
            if off + 16 > len(payload):
                raise MessageError("truncated addr entry ip")
            ip = bytes(payload[off:off + 16])
            off += 16
            port, off = read_u16le(payload, off)
            addrs.append(NetAddr(timestamp=ts, ip=ip, port=port))
    except MessageError:
        raise
    except Exception as exc:
        raise MessageError(f"malformed addr payload: {exc}") from exc
    return AddrMessage(addrs=addrs)


def encode_getaddr() -> bytes:
    return b""


# ---------------------------------------------------------------------------
# inv / getdata / notfound
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class InvItem:
    type: int    # INV_TX or INV_BLOCK
    hash: bytes  # 32 bytes, txid or block hash


@dataclass(frozen=True, slots=True)
class InvMessage:
    items: list[InvItem]


def _encode_inv_payload(items: list[InvItem]) -> bytes:
    parts: list[bytes] = [encode_varint(len(items))]
    for item in items:
        if len(item.hash) != 32:
            raise MessageError("InvItem.hash must be 32 bytes")
        parts.append(bytes([item.type & 0xFF]))
        parts.append(item.hash)
    return b"".join(parts)


def _decode_inv_payload(payload: bytes) -> list[InvItem]:
    try:
        count, off = decode_varint(payload, 0)
        if count > 50_000:
            raise MessageError(f"inv count {count} exceeds limit of 50000")
        items: list[InvItem] = []
        for _ in range(count):
            if off >= len(payload):
                raise MessageError("truncated inv list")
            inv_type = payload[off]
            off += 1
            if off + 32 > len(payload):
                raise MessageError("truncated inv hash")
            hash_bytes = bytes(payload[off:off + 32])
            off += 32
            items.append(InvItem(type=inv_type, hash=hash_bytes))
    except MessageError:
        raise
    except Exception as exc:
        raise MessageError(f"malformed inv payload: {exc}") from exc
    return items


def encode_inv(msg: InvMessage) -> bytes:
    return _encode_inv_payload(msg.items)


def decode_inv(payload: bytes) -> InvMessage:
    return InvMessage(items=_decode_inv_payload(payload))


def encode_getdata(msg: InvMessage) -> bytes:
    return _encode_inv_payload(msg.items)


def decode_getdata(payload: bytes) -> InvMessage:
    return InvMessage(items=_decode_inv_payload(payload))


def encode_notfound(msg: InvMessage) -> bytes:
    return _encode_inv_payload(msg.items)


def decode_notfound(payload: bytes) -> InvMessage:
    return InvMessage(items=_decode_inv_payload(payload))


# ---------------------------------------------------------------------------
# getblocks / getheaders
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class GetBlocksMessage:
    version: int
    locator_hashes: list[bytes]  # most-recent-first; each 32 bytes
    stop_hash: bytes             # 32 bytes; all-zero = open-ended


def _encode_locator_payload(msg: GetBlocksMessage) -> bytes:
    parts: list[bytes] = [u32le(msg.version), encode_varint(len(msg.locator_hashes))]
    for h in msg.locator_hashes:
        if len(h) != 32:
            raise MessageError("locator hash must be 32 bytes")
        parts.append(h)
    if len(msg.stop_hash) != 32:
        raise MessageError("stop_hash must be 32 bytes")
    parts.append(msg.stop_hash)
    return b"".join(parts)


def _decode_locator_payload(payload: bytes) -> GetBlocksMessage:
    try:
        version, off = read_u32le(payload, 0)
        count, off = decode_varint(payload, off)
        if count > 500:
            raise MessageError(f"locator hash count {count} exceeds limit of 500")
        locator_hashes: list[bytes] = []
        for _ in range(count):
            if off + 32 > len(payload):
                raise MessageError("truncated locator hash")
            locator_hashes.append(bytes(payload[off:off + 32]))
            off += 32
        if off + 32 > len(payload):
            raise MessageError("truncated stop_hash")
        stop_hash = bytes(payload[off:off + 32])
    except MessageError:
        raise
    except Exception as exc:
        raise MessageError(f"malformed getblocks/getheaders payload: {exc}") from exc
    return GetBlocksMessage(version=version, locator_hashes=locator_hashes, stop_hash=stop_hash)


def encode_getblocks(msg: GetBlocksMessage) -> bytes:
    return _encode_locator_payload(msg)


def decode_getblocks(payload: bytes) -> GetBlocksMessage:
    return _decode_locator_payload(payload)


def encode_getheaders(msg: GetBlocksMessage) -> bytes:
    return _encode_locator_payload(msg)


def decode_getheaders(payload: bytes) -> GetBlocksMessage:
    return _decode_locator_payload(payload)


# ---------------------------------------------------------------------------
# headers
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class HeadersMessage:
    headers: list[BlockHeader]


def encode_headers(msg: HeadersMessage) -> bytes:
    parts: list[bytes] = [encode_varint(len(msg.headers))]
    for h in msg.headers:
        parts.append(encode_block_header(h))
    return b"".join(parts)


def decode_headers(payload: bytes) -> HeadersMessage:
    try:
        count, off = decode_varint(payload, 0)
        if count > 2000:
            raise MessageError(f"headers count {count} exceeds limit of 2000")
        headers: list[BlockHeader] = []
        for _ in range(count):
            header, off = decode_block_header(payload, off)
            headers.append(header)
    except MessageError:
        raise
    except Exception as exc:
        raise MessageError(f"malformed headers payload: {exc}") from exc
    return HeadersMessage(headers=headers)


# ---------------------------------------------------------------------------
# block / tx  (thin wrappers; real codec lives in codec.block / codec.tx)
# ---------------------------------------------------------------------------

def encode_block_payload(block_bytes: bytes) -> bytes:
    return block_bytes


def encode_tx_payload(tx_bytes: bytes) -> bytes:
    return tx_bytes


# ---------------------------------------------------------------------------
# reject
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class RejectMessage:
    message: bytes    # command being rejected (e.g. b"tx", b"block")
    code: int         # one of REJECT_* constants
    reason: bytes     # human-readable reason string
    data: bytes = field(default=b"")  # optional extra data (txid / block hash)


def encode_reject(msg: RejectMessage) -> bytes:
    return b"".join((
        encode_varbytes(msg.message),
        bytes([msg.code & 0xFF]),
        encode_varbytes(msg.reason),
        msg.data,
    ))


def decode_reject(payload: bytes) -> RejectMessage:
    try:
        message, off = decode_varbytes(payload, 0, max_len=12)
        if off >= len(payload):
            raise MessageError("reject payload truncated before code")
        code = payload[off]
        off += 1
        reason, off = decode_varbytes(payload, off, max_len=111)
        data = bytes(payload[off:])
    except MessageError:
        raise
    except Exception as exc:
        raise MessageError(f"malformed reject payload: {exc}") from exc
    return RejectMessage(message=message, code=code, reason=reason, data=data)


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def ipv4_to_net_ip(ipv4: str) -> bytes:
    """Convert a dotted-decimal IPv4 string to a 16-byte IPv4-mapped IPv6 address."""
    parts = ipv4.split(".")
    if len(parts) != 4:
        raise ValueError(f"invalid IPv4 address: {ipv4!r}")
    try:
        octets = bytes(int(p) for p in parts)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid IPv4 address: {ipv4!r}") from exc
    return _IPV4_PREFIX + octets


def net_ip_to_str(ip: bytes) -> str:
    """Format a 16-byte network address as a human-readable string."""
    if ip[:12] == _IPV4_PREFIX:
        return ".".join(str(b) for b in ip[12:])
    return ":".join(ip[i:i + 2].hex() for i in range(0, 16, 2))


def make_version(
    *,
    start_height: int,
    nonce: int | None = None,
    recv_ip: str = "127.0.0.1",
    recv_port: int = 0,
    from_ip: str = "127.0.0.1",
    from_port: int = 0,
    user_agent: bytes = USER_AGENT,
    services: int = SVC_NETWORK,
) -> VersionMessage:
    """Build a VersionMessage with sensible defaults."""
    return VersionMessage(
        version=PROTOCOL_VERSION,
        services=services,
        timestamp=int(time.time()),
        recv_ip=ipv4_to_net_ip(recv_ip),
        recv_port=recv_port,
        from_ip=ipv4_to_net_ip(from_ip),
        from_port=from_port,
        nonce=nonce if nonce is not None else int.from_bytes(os.urandom(8), "little"),
        user_agent=user_agent,
        start_height=start_height,
    )
