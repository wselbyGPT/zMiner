"""Asyncio-based P2P peer connection for LatCoin.

Each Peer object represents one TCP connection.  The caller owns the
PeerManager (see net/manager.py); peers call back into it via the
PeerCallbacks interface so the two can be tested independently.

Handshake
---------
Initiator (outbound)              Responder (inbound)
-----------------                 ----------------
  send version     -->
                   <--   send version
  send verack      -->
                   <--   send verack
  (ACTIVE)                         (ACTIVE)

After ACTIVE state both peers exchange ping/pong on PING_INTERVAL seconds.
Objects (tx, block) are announced via inv, fetched via getdata.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from enum import Enum, auto
from typing import Callable, Awaitable

from latcoin.codec.block import decode_block, encode_block
from latcoin.codec.constants import NETWORK_DEVNET
from latcoin.codec.tx import decode_transaction, encode_transaction, txid
from latcoin.net.framing import (
    FrameError,
    encode_frame,
    magic_for_network,
    try_decode_frame,
)
from latcoin.net.messages import (
    PROTOCOL_VERSION,
    INV_BLOCK,
    INV_TX,
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
    encode_getblocks,
    encode_getheaders,
    encode_headers,
    encode_inv,
    encode_ping,
    encode_pong,
    encode_verack,
    encode_version,
    ipv4_to_net_ip,
    make_version,
    net_ip_to_str,
)

log = logging.getLogger(__name__)

PING_INTERVAL: float = 120.0    # seconds between pings
PING_TIMEOUT: float = 30.0      # seconds to wait for pong
HANDSHAKE_TIMEOUT: float = 10.0 # seconds for version/verack exchange
RECV_BUF_SIZE: int = 65536      # asyncio stream read chunk

READ_TIMEOUT: float = 300.0     # max silence before disconnecting peer


class PeerState(Enum):
    CONNECTING = auto()
    HANDSHAKING = auto()
    ACTIVE = auto()
    DISCONNECTING = auto()
    DISCONNECTED = auto()


class PeerCallbacks:
    """Interface the peer uses to talk back to the manager / chain engine.

    Default implementations are no-ops so unit tests can use a bare instance
    or a minimal subclass.
    """

    async def on_peer_ready(self, peer: "Peer") -> None:
        """Called once after the handshake completes."""

    async def on_peer_disconnected(self, peer: "Peer") -> None:
        """Called after the connection is closed (or fails)."""

    async def on_inv(self, peer: "Peer", items: list[InvItem]) -> None:
        """Called when an inv message is received."""

    async def on_block(self, peer: "Peer", block_bytes: bytes) -> None:
        """Called when a block payload is received."""

    async def on_tx(self, peer: "Peer", tx_bytes: bytes) -> None:
        """Called when a tx payload is received."""

    async def on_addr(self, peer: "Peer", addrs: list[NetAddr]) -> None:
        """Called when an addr payload is received."""

    async def on_getaddr(self, peer: "Peer") -> None:
        """Called when a peer requests our address list."""

    async def on_getdata(self, peer: "Peer", items: list[InvItem]) -> None:
        """Called when a peer asks us to send specific items."""

    async def on_getheaders(self, peer: "Peer", msg: GetBlocksMessage) -> None:
        """Called when a peer asks for headers."""

    async def on_getblocks(self, peer: "Peer", msg: GetBlocksMessage) -> None:
        """Called when a peer asks for block inv."""

    async def on_headers(self, peer: "Peer", msg: "HeadersMessage") -> None:
        """Called when a headers message is received."""


class Peer:
    """One TCP connection to a remote LatCoin peer."""

    def __init__(
        self,
        *,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        network_id: int = NETWORK_DEVNET,
        local_start_height: int = 0,
        local_port: int = 0,
        outbound: bool = True,
        callbacks: PeerCallbacks | None = None,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._network_id = network_id
        self._magic = magic_for_network(network_id)
        self._local_start_height = local_start_height
        self._local_port = local_port
        self.outbound = outbound
        self._callbacks = callbacks or PeerCallbacks()

        self.state = PeerState.CONNECTING
        self.remote_version: VersionMessage | None = None
        peername = writer.get_extra_info("peername", ("?", 0))
        if isinstance(peername, tuple) and len(peername) >= 2:
            self.remote_addr: tuple[str, int] = (str(peername[0]), int(peername[1]))
        else:
            self.remote_addr = ("?", 0)

        self._nonce = int.from_bytes(os.urandom(8), "little")
        self._pending_ping_nonce: int | None = None
        self._last_ping_sent: float = 0.0
        self._recv_buf = bytearray()

        self._handshake_complete = asyncio.Event()
        self._ping_task: asyncio.Task | None = None
        self._read_task: asyncio.Task | None = None

    # ------------------------------------------------------------------
    # Public send helpers
    # ------------------------------------------------------------------

    async def send_version(self) -> None:
        host, port = self.remote_addr
        try:
            recv_ip = ipv4_to_net_ip(host)
        except ValueError:
            recv_ip = b"\x00" * 16
        msg = VersionMessage(
            version=PROTOCOL_VERSION,
            services=1,
            timestamp=int(time.time()),
            recv_ip=recv_ip,
            recv_port=port,
            from_ip=ipv4_to_net_ip("127.0.0.1"),
            from_port=self._local_port,
            nonce=self._nonce,
            user_agent=b"/latcoind:0.1/",
            start_height=self._local_start_height,
        )
        await self._send("version", encode_version(msg))

    async def send_verack(self) -> None:
        await self._send("verack", encode_verack())

    async def send_ping(self) -> None:
        nonce = int.from_bytes(os.urandom(8), "little")
        self._pending_ping_nonce = nonce
        self._last_ping_sent = time.monotonic()
        await self._send("ping", encode_ping(PingMessage(nonce=nonce)))

    async def send_inv(self, items: list[InvItem]) -> None:
        await self._send("inv", encode_inv(InvMessage(items=items)))

    async def send_getdata(self, items: list[InvItem]) -> None:
        await self._send("getdata", encode_inv(InvMessage(items=items)))

    async def send_block(self, block_bytes: bytes) -> None:
        await self._send("block", block_bytes)

    async def send_tx(self, tx_bytes: bytes) -> None:
        await self._send("tx", tx_bytes)

    async def send_headers(self, msg: HeadersMessage) -> None:
        await self._send("headers", encode_headers(msg))

    async def send_addr(self, msg: AddrMessage) -> None:
        await self._send("addr", encode_addr(msg))

    async def send_getaddr(self) -> None:
        await self._send("getaddr", b"")

    async def send_getblocks(self, msg: GetBlocksMessage) -> None:
        await self._send("getblocks", encode_getblocks(msg))

    async def send_getheaders(self, msg: GetBlocksMessage) -> None:
        await self._send("getheaders", encode_getheaders(msg))

    async def disconnect(self) -> None:
        if self.state in (PeerState.DISCONNECTED, PeerState.DISCONNECTING):
            return
        self.state = PeerState.DISCONNECTING
        if self._ping_task and not self._ping_task.done():
            self._ping_task.cancel()
        try:
            self._writer.close()
            await asyncio.wait_for(self._writer.wait_closed(), timeout=2.0)
        except Exception:
            pass
        self.state = PeerState.DISCONNECTED
        await self._callbacks.on_peer_disconnected(self)

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Drive this peer's read loop.  Returns when the connection closes."""
        self.state = PeerState.HANDSHAKING
        read_task: asyncio.Task | None = None
        try:
            if self.outbound:
                await self.send_version()
            # Start the read loop as a background task so it can process
            # the incoming version/verack while we wait for the handshake.
            read_task = asyncio.create_task(self._read_loop(), name="peer-read")
            try:
                async with asyncio.timeout(HANDSHAKE_TIMEOUT):
                    await self._handshake_complete.wait()
            except asyncio.TimeoutError:
                log.debug("handshake timed out with %s", self.remote_addr)
                return
            self._ping_task = asyncio.create_task(self._ping_loop(), name="peer-ping")
            await read_task
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            log.debug("connection closed by %s", self.remote_addr)
        except Exception as exc:
            log.warning("peer %s error: %s", self.remote_addr, exc)
        finally:
            if read_task and not read_task.done():
                read_task.cancel()
                try:
                    await read_task
                except (asyncio.CancelledError, Exception):
                    pass
            await self.disconnect()

    # ------------------------------------------------------------------
    # Internal — I/O
    # ------------------------------------------------------------------

    async def _send(self, command: str, payload: bytes) -> None:
        frame = encode_frame(self._magic, command, payload)
        self._writer.write(frame)
        await self._writer.drain()

    async def _read_loop(self) -> None:
        while True:
            chunk = await asyncio.wait_for(
                self._reader.read(RECV_BUF_SIZE), timeout=READ_TIMEOUT
            )
            if not chunk:
                break
            self._recv_buf.extend(chunk)
            await self._drain_buffer()

    async def _drain_buffer(self) -> None:
        while True:
            result = try_decode_frame(bytes(self._recv_buf))
            if result is None:
                break
            header, payload, consumed = result
            del self._recv_buf[:consumed]
            if header.magic != self._magic:
                log.warning("wrong magic from %s, dropping", self.remote_addr)
                continue
            await self._dispatch(header.command.decode("ascii"), payload)

    # ------------------------------------------------------------------
    # Internal — dispatch
    # ------------------------------------------------------------------

    async def _dispatch(self, command: str, payload: bytes) -> None:
        handler = {
            "version": self._handle_version,
            "verack": self._handle_verack,
            "ping": self._handle_ping,
            "pong": self._handle_pong,
            "inv": self._handle_inv,
            "getdata": self._handle_getdata,
            "block": self._handle_block,
            "tx": self._handle_tx,
            "addr": self._handle_addr,
            "getaddr": self._handle_getaddr,
            "headers": self._handle_headers,
            "getheaders": self._handle_getheaders,
            "getblocks": self._handle_getblocks,
            "notfound": self._handle_notfound,
            "reject": self._handle_reject,
        }.get(command)
        if handler is None:
            log.debug("unknown command %r from %s, ignoring", command, self.remote_addr)
            return
        try:
            await handler(payload)
        except (MessageError, FrameError) as exc:
            log.warning("bad %s from %s: %s", command, self.remote_addr, exc)

    # ------------------------------------------------------------------
    # Internal — handlers
    # ------------------------------------------------------------------

    async def _handle_version(self, payload: bytes) -> None:
        if self.remote_version is not None:
            return  # duplicate version — ignore
        msg = decode_version(payload)
        if msg.nonce == self._nonce:
            log.warning("connected to self (%s), disconnecting", self.remote_addr)
            await self.disconnect()
            return
        self.remote_version = msg
        log.debug("version from %s: height=%d ua=%s",
                  self.remote_addr, msg.start_height, msg.user_agent)
        if not self.outbound:
            # Inbound sends its own version first so the outbound peer sets
            # remote_version before the verack arrives (TCP preserves order).
            await self.send_version()
        await self.send_verack()

    async def _handle_verack(self, payload: bytes) -> None:  # noqa: ARG002
        if self.remote_version is None:
            return  # verack before version — ignore
        if self.state != PeerState.HANDSHAKING:
            return
        self.state = PeerState.ACTIVE
        self._handshake_complete.set()
        log.debug("handshake complete with %s", self.remote_addr)
        await self._callbacks.on_peer_ready(self)

    async def _handle_ping(self, payload: bytes) -> None:
        msg = decode_ping(payload)
        await self._send("pong", encode_pong(PingMessage(nonce=msg.nonce)))

    async def _handle_pong(self, payload: bytes) -> None:
        msg = decode_pong(payload)
        if msg.nonce == self._pending_ping_nonce:
            rtt = time.monotonic() - self._last_ping_sent
            log.debug("pong from %s (rtt=%.1fms)", self.remote_addr, rtt * 1000)
            self._pending_ping_nonce = None

    async def _handle_inv(self, payload: bytes) -> None:
        msg = decode_inv(payload)
        await self._callbacks.on_inv(self, msg.items)

    async def _handle_getdata(self, payload: bytes) -> None:
        msg = decode_getdata(payload)
        await self._callbacks.on_getdata(self, msg.items)

    async def _handle_block(self, payload: bytes) -> None:
        await self._callbacks.on_block(self, payload)

    async def _handle_tx(self, payload: bytes) -> None:
        await self._callbacks.on_tx(self, payload)

    async def _handle_addr(self, payload: bytes) -> None:
        msg = decode_addr(payload)
        await self._callbacks.on_addr(self, msg.addrs)

    async def _handle_getaddr(self, payload: bytes) -> None:  # noqa: ARG002
        await self._callbacks.on_getaddr(self)

    async def _handle_headers(self, payload: bytes) -> None:
        msg = decode_headers(payload)
        await self._callbacks.on_headers(self, msg)

    async def _handle_getheaders(self, payload: bytes) -> None:
        msg = decode_getheaders(payload)
        await self._callbacks.on_getheaders(self, msg)

    async def _handle_getblocks(self, payload: bytes) -> None:
        msg = decode_getblocks(payload)
        await self._callbacks.on_getblocks(self, msg)

    async def _handle_notfound(self, payload: bytes) -> None:
        decode_notfound(payload)

    async def _handle_reject(self, payload: bytes) -> None:
        msg = decode_reject(payload)
        log.warning("reject from %s: msg=%s code=0x%02x reason=%s",
                    self.remote_addr, msg.message, msg.code, msg.reason)

    # ------------------------------------------------------------------
    # Internal — keepalive
    # ------------------------------------------------------------------

    async def _ping_loop(self) -> None:
        try:
            while self.state == PeerState.ACTIVE:
                await asyncio.sleep(PING_INTERVAL)
                if self.state != PeerState.ACTIVE:
                    break
                await self.send_ping()
                await asyncio.sleep(PING_TIMEOUT)
                if self._pending_ping_nonce is not None:
                    log.warning("ping timeout for %s, disconnecting", self.remote_addr)
                    await self.disconnect()
                    break
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------
    # Repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        host, port = self.remote_addr
        direction = "out" if self.outbound else "in"
        return f"<Peer {host}:{port} [{direction}] {self.state.name}>"
