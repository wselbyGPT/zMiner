"""Tests for net.messages payload codecs."""
from __future__ import annotations

import time

import pytest

from latcoin.codec.block import BlockHeader
from latcoin.net.messages import (
    INV_BLOCK,
    INV_TX,
    PROTOCOL_VERSION,
    REJECT_INVALID,
    AddrMessage,
    GetBlocksMessage,
    HeadersMessage,
    InvItem,
    InvMessage,
    MessageError,
    NetAddr,
    PingMessage,
    RejectMessage,
    VersionMessage,
    decode_addr,
    decode_getblocks,
    decode_getheaders,
    decode_getdata,
    decode_headers,
    decode_inv,
    decode_notfound,
    decode_ping,
    decode_pong,
    decode_reject,
    decode_version,
    encode_addr,
    encode_getaddr,
    encode_getblocks,
    encode_getheaders,
    encode_getdata,
    encode_headers,
    encode_inv,
    encode_notfound,
    encode_ping,
    encode_pong,
    encode_reject,
    encode_verack,
    encode_version,
    ipv4_to_net_ip,
    make_version,
    net_ip_to_str,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_version_msg(height: int = 42) -> VersionMessage:
    return make_version(start_height=height, nonce=0xDEADBEEF_CAFEBABE)


def _zero_hash() -> bytes:
    return b"\x00" * 32


def _sample_header() -> BlockHeader:
    return BlockHeader(
        version=1,
        prev_block_hash=_zero_hash(),
        merkle_root=bytes(range(32)),
        timestamp=1_700_000_000,
        height=0,
        bits=0x1F00FFFF,
        nonce=12345,
    )


# ---------------------------------------------------------------------------
# version / verack
# ---------------------------------------------------------------------------

class TestVersion:
    def test_roundtrip(self) -> None:
        msg = _make_version_msg()
        decoded = decode_version(encode_version(msg))
        assert decoded == msg

    def test_version_field(self) -> None:
        msg = _make_version_msg()
        assert decode_version(encode_version(msg)).version == PROTOCOL_VERSION

    def test_start_height_preserved(self) -> None:
        msg = _make_version_msg(height=9999)
        assert decode_version(encode_version(msg)).start_height == 9999

    def test_nonce_preserved(self) -> None:
        msg = make_version(start_height=0, nonce=0x1122334455667788)
        assert decode_version(encode_version(msg)).nonce == 0x1122334455667788

    def test_user_agent_preserved(self) -> None:
        msg = make_version(start_height=0, nonce=1, user_agent=b"/lattest:0.0/")
        assert decode_version(encode_version(msg)).user_agent == b"/lattest:0.0/"

    def test_rejects_overlong_user_agent(self) -> None:
        msg = make_version(start_height=0, nonce=1, user_agent=b"x" * 257)
        with pytest.raises(MessageError):
            encode_version(msg)

    def test_rejects_bad_ip_length(self) -> None:
        msg = VersionMessage(
            version=PROTOCOL_VERSION, services=1, timestamp=0,
            recv_ip=b"\x00" * 4, recv_port=0,
            from_ip=b"\x00" * 16, from_port=0,
            nonce=0, user_agent=b"", start_height=0,
        )
        with pytest.raises(MessageError):
            encode_version(msg)

    def test_decode_truncated_raises(self) -> None:
        payload = encode_version(_make_version_msg())
        with pytest.raises(MessageError):
            decode_version(payload[:10])


class TestVerack:
    def test_empty_payload(self) -> None:
        assert encode_verack() == b""


# ---------------------------------------------------------------------------
# ping / pong
# ---------------------------------------------------------------------------

class TestPingPong:
    def test_ping_roundtrip(self) -> None:
        msg = PingMessage(nonce=0xABCD1234_5678EF90)
        assert decode_ping(encode_ping(msg)).nonce == msg.nonce

    def test_pong_roundtrip(self) -> None:
        msg = PingMessage(nonce=0x0102030405060708)
        assert decode_pong(encode_pong(msg)).nonce == msg.nonce

    def test_pong_echoes_ping_nonce(self) -> None:
        nonce = 0xDEAD_BEEF_0000_0001
        ping_payload = encode_ping(PingMessage(nonce=nonce))
        ping = decode_ping(ping_payload)
        pong_payload = encode_pong(PingMessage(nonce=ping.nonce))
        pong = decode_pong(pong_payload)
        assert pong.nonce == nonce

    def test_ping_too_short_raises(self) -> None:
        with pytest.raises(MessageError):
            decode_ping(b"\x01\x02\x03")

    def test_pong_too_short_raises(self) -> None:
        with pytest.raises(MessageError):
            decode_pong(b"")


# ---------------------------------------------------------------------------
# addr / getaddr
# ---------------------------------------------------------------------------

class TestAddr:
    def _sample_addr(self, port: int = 9338) -> NetAddr:
        return NetAddr(
            timestamp=int(time.time()),
            ip=ipv4_to_net_ip("127.0.0.1"),
            port=port,
        )

    def test_empty_addr_roundtrip(self) -> None:
        msg = AddrMessage(addrs=[])
        assert decode_addr(encode_addr(msg)).addrs == []

    def test_single_addr_roundtrip(self) -> None:
        entry = self._sample_addr()
        msg = AddrMessage(addrs=[entry])
        decoded = decode_addr(encode_addr(msg))
        assert decoded.addrs[0] == entry

    def test_multiple_addrs_roundtrip(self) -> None:
        addrs = [self._sample_addr(port=9000 + i) for i in range(5)]
        msg = AddrMessage(addrs=addrs)
        decoded = decode_addr(encode_addr(msg))
        assert decoded.addrs == addrs

    def test_addr_count_limit(self) -> None:
        # Build a payload that claims 1001 entries
        count_bytes = (1001).to_bytes(2, "little")
        forged = b"\xfd" + count_bytes
        with pytest.raises(MessageError, match="1001"):
            decode_addr(forged)

    def test_bad_ip_length_raises(self) -> None:
        entry = NetAddr(timestamp=0, ip=b"\x00" * 4, port=9338)
        with pytest.raises(MessageError):
            encode_addr(AddrMessage(addrs=[entry]))

    def test_getaddr_empty(self) -> None:
        assert encode_getaddr() == b""


# ---------------------------------------------------------------------------
# inv / getdata / notfound
# ---------------------------------------------------------------------------

class TestInv:
    def _sample_items(self) -> list[InvItem]:
        return [
            InvItem(type=INV_TX, hash=bytes(range(32))),
            InvItem(type=INV_BLOCK, hash=bytes(reversed(range(32)))),
        ]

    def test_inv_roundtrip(self) -> None:
        items = self._sample_items()
        decoded = decode_inv(encode_inv(InvMessage(items=items)))
        assert decoded.items == items

    def test_getdata_roundtrip(self) -> None:
        items = self._sample_items()
        decoded = decode_getdata(encode_getdata(InvMessage(items=items)))
        assert decoded.items == items

    def test_notfound_roundtrip(self) -> None:
        items = self._sample_items()
        decoded = decode_notfound(encode_notfound(InvMessage(items=items)))
        assert decoded.items == items

    def test_empty_inv(self) -> None:
        decoded = decode_inv(encode_inv(InvMessage(items=[])))
        assert decoded.items == []

    def test_inv_type_preserved(self) -> None:
        items = [InvItem(type=INV_BLOCK, hash=_zero_hash())]
        decoded = decode_inv(encode_inv(InvMessage(items=items)))
        assert decoded.items[0].type == INV_BLOCK

    def test_inv_hash_must_be_32_bytes(self) -> None:
        items = [InvItem(type=INV_TX, hash=b"\x00" * 31)]
        with pytest.raises(MessageError):
            encode_inv(InvMessage(items=items))

    def test_inv_count_limit(self) -> None:
        # 50001 is in the u16 range so canonical varint uses 0xFD prefix (2 bytes)
        count_bytes = (50001).to_bytes(2, "little")
        forged = b"\xfd" + count_bytes
        with pytest.raises(MessageError, match="50001"):
            decode_inv(forged)


# ---------------------------------------------------------------------------
# getblocks / getheaders
# ---------------------------------------------------------------------------

class TestGetBlocks:
    def _sample_msg(self, n_hashes: int = 3) -> GetBlocksMessage:
        return GetBlocksMessage(
            version=PROTOCOL_VERSION,
            locator_hashes=[bytes([i] * 32) for i in range(n_hashes)],
            stop_hash=_zero_hash(),
        )

    def test_getblocks_roundtrip(self) -> None:
        msg = self._sample_msg()
        decoded = decode_getblocks(encode_getblocks(msg))
        assert decoded == msg

    def test_getheaders_roundtrip(self) -> None:
        msg = self._sample_msg(n_hashes=1)
        decoded = decode_getheaders(encode_getheaders(msg))
        assert decoded == msg

    def test_empty_locator(self) -> None:
        msg = GetBlocksMessage(version=PROTOCOL_VERSION, locator_hashes=[], stop_hash=_zero_hash())
        decoded = decode_getblocks(encode_getblocks(msg))
        assert decoded.locator_hashes == []

    def test_locator_hash_must_be_32_bytes(self) -> None:
        msg = GetBlocksMessage(
            version=PROTOCOL_VERSION,
            locator_hashes=[b"\x00" * 16],
            stop_hash=_zero_hash(),
        )
        with pytest.raises(MessageError):
            encode_getblocks(msg)

    def test_stop_hash_must_be_32_bytes(self) -> None:
        msg = GetBlocksMessage(
            version=PROTOCOL_VERSION,
            locator_hashes=[],
            stop_hash=b"\x00" * 16,
        )
        with pytest.raises(MessageError):
            encode_getblocks(msg)

    def test_locator_count_limit(self) -> None:
        count_bytes = (501).to_bytes(2, "little")
        forged = b"\x04\x00\x00\x00" + b"\xfd" + count_bytes
        with pytest.raises(MessageError, match="501"):
            decode_getblocks(forged)


# ---------------------------------------------------------------------------
# headers
# ---------------------------------------------------------------------------

class TestHeaders:
    def test_empty_headers_roundtrip(self) -> None:
        msg = HeadersMessage(headers=[])
        decoded = decode_headers(encode_headers(msg))
        assert decoded.headers == []

    def test_single_header_roundtrip(self) -> None:
        h = _sample_header()
        msg = HeadersMessage(headers=[h])
        decoded = decode_headers(encode_headers(msg))
        assert decoded.headers[0] == h

    def test_multiple_headers_roundtrip(self) -> None:
        headers = [
            BlockHeader(
                version=1,
                prev_block_hash=bytes([i] * 32),
                merkle_root=bytes([i ^ 0xFF] * 32),
                timestamp=1_700_000_000 + i,
                height=i,
                bits=0x1F00FFFF,
                nonce=i * 1000,
            )
            for i in range(5)
        ]
        msg = HeadersMessage(headers=headers)
        decoded = decode_headers(encode_headers(msg))
        assert decoded.headers == headers

    def test_headers_count_limit(self) -> None:
        count_bytes = (2001).to_bytes(2, "little")
        forged = b"\xfd" + count_bytes
        with pytest.raises(MessageError, match="2001"):
            decode_headers(forged)


# ---------------------------------------------------------------------------
# reject
# ---------------------------------------------------------------------------

class TestReject:
    def test_basic_roundtrip(self) -> None:
        msg = RejectMessage(
            message=b"tx",
            code=REJECT_INVALID,
            reason=b"bad-sig",
            data=_zero_hash(),
        )
        decoded = decode_reject(encode_reject(msg))
        assert decoded == msg

    def test_no_data(self) -> None:
        msg = RejectMessage(message=b"block", code=REJECT_INVALID, reason=b"bad-pow")
        decoded = decode_reject(encode_reject(msg))
        assert decoded.data == b""
        assert decoded.code == REJECT_INVALID

    def test_decode_truncated_raises(self) -> None:
        msg = RejectMessage(message=b"tx", code=0x10, reason=b"x")
        with pytest.raises(MessageError):
            decode_reject(encode_reject(msg)[:2])


# ---------------------------------------------------------------------------
# IP helpers
# ---------------------------------------------------------------------------

class TestIpHelpers:
    def test_ipv4_roundtrip(self) -> None:
        ip = "192.168.1.100"
        assert net_ip_to_str(ipv4_to_net_ip(ip)) == ip

    def test_loopback(self) -> None:
        assert net_ip_to_str(ipv4_to_net_ip("127.0.0.1")) == "127.0.0.1"

    def test_broadcast(self) -> None:
        assert net_ip_to_str(ipv4_to_net_ip("255.255.255.255")) == "255.255.255.255"

    def test_invalid_ipv4_raises(self) -> None:
        with pytest.raises(ValueError):
            ipv4_to_net_ip("not-an-ip")

    def test_invalid_octets_raise(self) -> None:
        with pytest.raises(ValueError):
            ipv4_to_net_ip("256.0.0.1")


# ---------------------------------------------------------------------------
# make_version helper
# ---------------------------------------------------------------------------

class TestMakeVersion:
    def test_returns_version_message(self) -> None:
        msg = make_version(start_height=10, nonce=42)
        assert isinstance(msg, VersionMessage)

    def test_start_height(self) -> None:
        msg = make_version(start_height=777, nonce=0)
        assert msg.start_height == 777

    def test_nonce_passed_through(self) -> None:
        msg = make_version(start_height=0, nonce=0xCAFE)
        assert msg.nonce == 0xCAFE

    def test_random_nonce_when_omitted(self) -> None:
        a = make_version(start_height=0)
        b = make_version(start_height=0)
        # Astronomically unlikely to collide
        assert a.nonce != b.nonce

    def test_ip_encoding(self) -> None:
        msg = make_version(start_height=0, nonce=0, recv_ip="10.0.0.1", recv_port=9338)
        assert net_ip_to_str(msg.recv_ip) == "10.0.0.1"
        assert msg.recv_port == 9338

    def test_full_roundtrip(self) -> None:
        msg = make_version(start_height=100, nonce=999)
        assert decode_version(encode_version(msg)).start_height == 100
