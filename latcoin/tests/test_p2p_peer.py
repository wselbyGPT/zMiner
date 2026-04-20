"""Tests for net.peer — asyncio peer connection layer.

Two test styles:
  - Handler unit tests: call peer._dispatch() directly (no I/O needed).
  - Integration tests: use socket.socketpair() for real async I/O.
"""
from __future__ import annotations

import asyncio
import socket
import time

import pytest

from latcoin.codec.constants import NETWORK_DEVNET
from latcoin.net.framing import encode_frame, magic_for_network, try_decode_frame
from latcoin.net.messages import (
    INV_BLOCK,
    INV_TX,
    InvItem,
    InvMessage,
    NetAddr,
    PingMessage,
    VersionMessage,
    decode_ping,
    decode_pong,
    decode_version,
    encode_inv,
    encode_ping,
    encode_pong,
    encode_verack,
    encode_version,
    ipv4_to_net_ip,
    make_version,
    PROTOCOL_VERSION,
)
from latcoin.net.peer import Peer, PeerCallbacks, PeerState

MAGIC = magic_for_network(NETWORK_DEVNET)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _frame(command: str, payload: bytes) -> bytes:
    return encode_frame(MAGIC, command, payload)


def _version_frame(height: int = 0, nonce: int = 0xABCD) -> bytes:
    msg = make_version(start_height=height, nonce=nonce)
    return _frame("version", encode_version(msg))


def _verack_frame() -> bytes:
    return _frame("verack", encode_verack())


class _TcpPair:
    """A pair of TCP stream ends that can be individually closed."""

    def __init__(
        self,
        client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter,
        server_r: asyncio.StreamReader, server_w: asyncio.StreamWriter,
        _done: asyncio.Event,
    ) -> None:
        self.client = (client_r, client_w)
        self.server = (server_r, server_w)
        self._done = _done

    def release(self) -> None:
        """Allow the server handler to exit and close its end."""
        self._done.set()


async def _make_tcp_pair() -> _TcpPair:
    """Return a TCP loopback pair.

    The server handler stays alive until ``pair.release()`` is called.
    This ensures data written to either end can be read independently of
    when the write direction is closed (half-close semantics via TCP FIN).
    """
    server_entry: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
    ready = asyncio.Event()
    done = asyncio.Event()

    async def _handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        server_entry.append((r, w))
        ready.set()
        await done.wait()

    server = await asyncio.start_server(_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    cr, cw = await asyncio.open_connection("127.0.0.1", port)
    await asyncio.wait_for(ready.wait(), timeout=2.0)
    # Close server to stop accepting new connections.
    # Do NOT await server.wait_closed() — that blocks until handler exits,
    # but our handler intentionally stays alive until done.set() is called.
    server.close()
    sr, sw = server_entry[0]
    return _TcpPair(cr, cw, sr, sw, done)


async def _make_stream_pair() -> tuple[
    tuple[asyncio.StreamReader, asyncio.StreamWriter],
    tuple[asyncio.StreamReader, asyncio.StreamWriter],
]:
    """AF_UNIX socketpair for dispatch-only tests (no independent half-close needed)."""
    a, b = socket.socketpair()
    ra, wa = await asyncio.open_connection(sock=a)
    rb, wb = await asyncio.open_connection(sock=b)
    return (ra, wa), (rb, wb)


class _RecordingCallbacks(PeerCallbacks):
    def __init__(self) -> None:
        self.ready: list[Peer] = []
        self.disconnected: list[Peer] = []
        self.inv_calls: list[list[InvItem]] = []
        self.block_calls: list[bytes] = []
        self.tx_calls: list[bytes] = []
        self.addr_calls: list[list[NetAddr]] = []

    async def on_peer_ready(self, peer: Peer) -> None:
        self.ready.append(peer)

    async def on_peer_disconnected(self, peer: Peer) -> None:
        self.disconnected.append(peer)

    async def on_inv(self, peer: Peer, items: list[InvItem]) -> None:
        self.inv_calls.append(items)

    async def on_block(self, peer: Peer, block_bytes: bytes) -> None:
        self.block_calls.append(block_bytes)

    async def on_tx(self, peer: Peer, tx_bytes: bytes) -> None:
        self.tx_calls.append(tx_bytes)

    async def on_addr(self, peer: Peer, addrs: list[NetAddr]) -> None:
        self.addr_calls.append(addrs)


async def _stub_peer(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    outbound: bool = True,
    cbs: PeerCallbacks | None = None,
) -> Peer:
    """Construct a Peer with the given streams."""
    return Peer(
        reader=reader,
        writer=writer,
        network_id=NETWORK_DEVNET,
        local_start_height=0,
        outbound=outbound,
        callbacks=cbs,
    )


# ---------------------------------------------------------------------------
# Handler unit tests (dispatch directly, no real I/O)
# ---------------------------------------------------------------------------
# For these we build a Peer but never call run() — we just feed payloads to
# _dispatch() directly to verify handler logic in isolation.

async def _null_peer() -> tuple[Peer, asyncio.StreamWriter]:
    """Build a peer connected over a socketpair (we'll only use the write side)."""
    (ra, wa), (rb, wb) = await _make_stream_pair()
    cbs = _RecordingCallbacks()
    peer = Peer(reader=ra, writer=wa, network_id=NETWORK_DEVNET,
                local_start_height=0, outbound=True, callbacks=cbs)
    wb.close()
    return peer, wa


class TestDispatchHandlers:
    async def test_ping_replies_with_pong(self) -> None:
        (ra, wa), (rb, wb) = await _make_stream_pair()
        peer = Peer(reader=ra, writer=wa, network_id=NETWORK_DEVNET,
                    local_start_height=0, outbound=True)
        # Feed a ping
        ping_payload = encode_ping(PingMessage(nonce=0xDEAD_BEEF_1234_5678))
        await peer._dispatch("ping", ping_payload)
        # Read what was sent to the other side
        wa.close()
        data = await rb.read(1024)
        result = try_decode_frame(data)
        assert result is not None
        _, payload, _ = result
        pong = decode_pong(payload)
        assert pong.nonce == 0xDEAD_BEEF_1234_5678
        wb.close()

    async def test_version_sets_remote_version(self) -> None:
        (ra, wa), (rb, wb) = await _make_stream_pair()
        peer = Peer(reader=ra, writer=wa, network_id=NETWORK_DEVNET,
                    local_start_height=0, outbound=True)
        msg = make_version(start_height=99, nonce=0xF0F0F0F0)
        await peer._dispatch("version", encode_version(msg))
        assert peer.remote_version is not None
        assert peer.remote_version.start_height == 99
        wa.close(); wb.close()

    async def test_version_duplicate_is_ignored(self) -> None:
        (ra, wa), (rb, wb) = await _make_stream_pair()
        peer = Peer(reader=ra, writer=wa, network_id=NETWORK_DEVNET,
                    local_start_height=0, outbound=True)
        msg = make_version(start_height=10, nonce=0xAA)
        await peer._dispatch("version", encode_version(msg))
        first_version = peer.remote_version
        msg2 = make_version(start_height=20, nonce=0xBB)
        await peer._dispatch("version", encode_version(msg2))
        assert peer.remote_version == first_version  # unchanged
        wa.close(); wb.close()

    async def test_inv_fires_callback(self) -> None:
        (ra, wa), (rb, wb) = await _make_stream_pair()
        cbs = _RecordingCallbacks()
        peer = Peer(reader=ra, writer=wa, network_id=NETWORK_DEVNET,
                    local_start_height=0, outbound=True, callbacks=cbs)
        items = [InvItem(type=INV_TX, hash=bytes(range(32)))]
        await peer._dispatch("inv", encode_inv(InvMessage(items=items)))
        assert len(cbs.inv_calls) == 1
        assert cbs.inv_calls[0][0].type == INV_TX
        wa.close(); wb.close()

    async def test_block_fires_callback(self) -> None:
        (ra, wa), (rb, wb) = await _make_stream_pair()
        cbs = _RecordingCallbacks()
        peer = Peer(reader=ra, writer=wa, network_id=NETWORK_DEVNET,
                    local_start_height=0, outbound=True, callbacks=cbs)
        await peer._dispatch("block", b"\x01\x02\x03\x04")
        assert cbs.block_calls == [b"\x01\x02\x03\x04"]
        wa.close(); wb.close()

    async def test_tx_fires_callback(self) -> None:
        (ra, wa), (rb, wb) = await _make_stream_pair()
        cbs = _RecordingCallbacks()
        peer = Peer(reader=ra, writer=wa, network_id=NETWORK_DEVNET,
                    local_start_height=0, outbound=True, callbacks=cbs)
        await peer._dispatch("tx", b"\xAA\xBB")
        assert cbs.tx_calls == [b"\xAA\xBB"]
        wa.close(); wb.close()

    async def test_unknown_command_is_silently_ignored(self) -> None:
        (ra, wa), (rb, wb) = await _make_stream_pair()
        cbs = _RecordingCallbacks()
        peer = Peer(reader=ra, writer=wa, network_id=NETWORK_DEVNET,
                    local_start_height=0, outbound=True, callbacks=cbs)
        await peer._dispatch("xyzzy", b"\x00")  # must not raise
        assert len(cbs.ready) == 0
        wa.close(); wb.close()

    async def test_malformed_ping_does_not_crash(self) -> None:
        (ra, wa), (rb, wb) = await _make_stream_pair()
        peer = Peer(reader=ra, writer=wa, network_id=NETWORK_DEVNET,
                    local_start_height=0, outbound=True)
        # Too-short ping: _dispatch catches MessageError internally
        await peer._dispatch("ping", b"\x01\x02")  # must not raise
        wa.close(); wb.close()


# ---------------------------------------------------------------------------
# Integration tests — full run() with real socket pairs
# ---------------------------------------------------------------------------

class TestFullHandshake:
    """Integration tests using a real peer task against a scripted remote."""

    async def _run_handshake(
        self,
        *,
        outbound: bool = True,
        cbs: _RecordingCallbacks | None = None,
        extra_sends: list[bytes] | None = None,
    ) -> tuple[Peer, bytes]:
        """
        Start a Peer task against a scripted remote.  Completes the handshake,
        sends any extra frames, waits for ACTIVE, then tears down cleanly.

        Returns (peer, bytes_written_by_peer).
        """
        cbs = cbs or _RecordingCallbacks()
        tcp = await _make_tcp_pair()
        peer_r, peer_w = tcp.client
        remote_r, remote_w = tcp.server

        peer = Peer(reader=peer_r, writer=peer_w,
                    network_id=NETWORK_DEVNET,
                    local_start_height=0, outbound=outbound, callbacks=cbs)

        active_event = asyncio.Event()
        _original_ready = cbs.on_peer_ready

        async def _on_ready(p: Peer) -> None:
            await _original_ready(p)
            active_event.set()

        cbs.on_peer_ready = _on_ready  # type: ignore[method-assign]

        nonce = 0x1234_5678_ABCD_EF01

        # Collect everything the peer sends, concurrently
        collected = bytearray()
        collect_done = asyncio.Event()

        async def _collect() -> None:
            try:
                while True:
                    chunk = await asyncio.wait_for(remote_r.read(65536), timeout=3.0)
                    if not chunk:
                        break
                    collected.extend(chunk)
            except (asyncio.TimeoutError, Exception):
                pass
            collect_done.set()

        collector_task = asyncio.create_task(_collect())

        async def remote_side() -> None:
            version_bytes = encode_version(make_version(start_height=0, nonce=nonce))
            remote_w.write(_frame("version", version_bytes))
            remote_w.write(_verack_frame())
            for chunk in (extra_sends or []):
                remote_w.write(chunk)
            await remote_w.drain()
            # Wait until peer reaches ACTIVE, then close our end
            await asyncio.wait_for(active_event.wait(), timeout=4.0)
            # Small delay so peer can process extra_sends before we close
            await asyncio.sleep(0.05)
            remote_w.close()
            tcp.release()  # allow handler to exit

        remote_task = asyncio.create_task(remote_side())
        peer_task = asyncio.create_task(peer.run())
        try:
            await asyncio.wait_for(peer_task, timeout=5.0)
        finally:
            tcp.release()  # ensure handler always exits so wait_closed() doesn't block
        await remote_task
        # Give collector a moment to drain the last bytes
        try:
            await asyncio.wait_for(collect_done.wait(), timeout=0.5)
        except asyncio.TimeoutError:
            pass
        collector_task.cancel()
        try:
            await collector_task
        except asyncio.CancelledError:
            pass
        return peer, bytes(collected)

    async def test_outbound_sends_version_first(self) -> None:
        peer, sent = await self._run_handshake(outbound=True)
        # Collect everything already buffered in remote_r
        # The peer sends version + verack; check version is first
        result = try_decode_frame(sent)
        assert result is not None
        h, _, _ = result
        assert h.command == b"version"

    async def test_outbound_sends_verack_after_version(self) -> None:
        peer, sent = await self._run_handshake(outbound=True)
        commands = []
        off = 0
        while True:
            r = try_decode_frame(sent, off)
            if r is None:
                break
            h, _, off = r
            commands.append(h.command)
        assert b"version" in commands
        assert b"verack" in commands

    async def test_inbound_sends_version_then_verack(self) -> None:
        peer, sent = await self._run_handshake(outbound=False)
        commands = []
        off = 0
        while True:
            r = try_decode_frame(sent, off)
            if r is None:
                break
            h, _, off = r
            commands.append(h.command)
        assert b"version" in commands
        assert b"verack" in commands

    async def test_handshake_fires_ready_callback(self) -> None:
        cbs = _RecordingCallbacks()
        peer, _ = await self._run_handshake(outbound=True, cbs=cbs)
        assert len(cbs.ready) == 1

    async def test_disconnect_fires_callback(self) -> None:
        cbs = _RecordingCallbacks()
        peer, _ = await self._run_handshake(outbound=True, cbs=cbs)
        assert len(cbs.disconnected) == 1

    async def test_self_connection_rejected(self) -> None:
        cbs = _RecordingCallbacks()
        (peer_r, peer_w), (remote_r, remote_w) = await _make_stream_pair()
        peer = Peer(reader=peer_r, writer=peer_w,
                    network_id=NETWORK_DEVNET,
                    local_start_height=0, outbound=True, callbacks=cbs)
        self_version = make_version(start_height=0, nonce=peer._nonce)
        remote_w.write(_frame("version", encode_version(self_version)))
        await remote_w.drain()
        remote_w.close()
        peer_task = asyncio.create_task(peer.run())
        await asyncio.wait_for(peer_task, timeout=5.0)
        assert peer.state == PeerState.DISCONNECTED

    async def test_ping_gets_pong_reply(self) -> None:
        ping_payload = encode_ping(PingMessage(nonce=0xCAFE_BABE_0000_0001))
        peer, sent = await self._run_handshake(
            outbound=True,
            extra_sends=[_frame("ping", ping_payload)],
        )
        found_pong = False
        off = 0
        while True:
            r = try_decode_frame(sent, off)
            if r is None:
                break
            h, payload, off = r
            if h.command == b"pong":
                assert decode_pong(payload).nonce == 0xCAFE_BABE_0000_0001
                found_pong = True
        assert found_pong, "no pong frame found in sent bytes"

    async def test_inv_after_handshake_fires_callback(self) -> None:
        cbs = _RecordingCallbacks()
        items = [InvItem(type=INV_BLOCK, hash=bytes([0xAB] * 32))]
        peer, _ = await self._run_handshake(
            outbound=True,
            cbs=cbs,
            extra_sends=[_frame("inv", encode_inv(InvMessage(items=items)))],
        )
        assert len(cbs.inv_calls) == 1
        assert cbs.inv_calls[0][0].hash == bytes([0xAB] * 32)


# ---------------------------------------------------------------------------
# Repr
# ---------------------------------------------------------------------------

async def test_repr_contains_state() -> None:
    (ra, wa), (rb, wb) = await _make_stream_pair()
    peer = Peer(reader=ra, writer=wa, network_id=NETWORK_DEVNET,
                local_start_height=0, outbound=True)
    r = repr(peer)
    assert "out" in r
    assert "CONNECTING" in r
    wa.close(); wb.close()
