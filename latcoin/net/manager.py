"""PeerManager — manages the full lifecycle of all P2P connections.

Responsibilities:
- Listen for inbound TCP connections via asyncio.start_server
- Dial outbound connections to seed/configured peers
- Enforce MAX_OUTBOUND / MAX_INBOUND connection limits
- Implement PeerCallbacks to route P2P messages to ChainEngine / Mempool:
    inv        → getdata for items we don't have
    block      → submit_block → relay inv to other peers
    tx         → add to mempool → relay inv to other peers
    getdata    → serve block or tx from engine/mempool
    getheaders → locator-based headers response
    getblocks  → locator-based inv response
    headers    → submit_header_only per header, request block bodies
    peer_ready → trigger IBD if remote is ahead, else announce mempool
- Use ThreadPoolExecutor so synchronous ChainEngine/Mempool calls don't
  block the event loop.
"""
from __future__ import annotations

import asyncio
import functools
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Sequence

from latcoin.chain.engine import ChainEngine, SubmitResult
from latcoin.codec.block import Block, block_hash, decode_block, encode_block
from latcoin.codec.constants import NETWORK_DEVNET
from latcoin.codec.tx import decode_transaction, encode_transaction, txid
from latcoin.net.addr_manager import AddrManager
from latcoin.net.messages import (
    PROTOCOL_VERSION,
    INV_BLOCK,
    INV_TX,
    AddrMessage,
    GetBlocksMessage,
    HeadersMessage,
    InvItem,
    InvMessage,
    NetAddr,
    encode_addr,
    encode_inv,
    ipv4_to_net_ip,
    net_ip_to_str,
)
from latcoin.net.peer import Peer, PeerCallbacks, PeerState
from latcoin.validation.errors import BlockValidationError
from latcoin.validation.tx_context import ChainContext

log = logging.getLogger(__name__)

MAX_OUTBOUND: int = 8
MAX_INBOUND: int = 125
MAX_HEADERS_PER_MSG: int = 2000
MAX_INV_PER_MSG: int = 500
MAX_SEEN_CACHE: int = 50_000

_DEFAULT_EXECUTOR = object()  # sentinel: create a new ThreadPoolExecutor


class PeerManager(PeerCallbacks):
    """Owns all peer connections and routes messages to the chain engine."""

    def __init__(
        self,
        engine: ChainEngine,
        *,
        network_id: int = NETWORK_DEVNET,
        listen_host: str = "0.0.0.0",
        listen_port: int = 9338,
        max_outbound: int = MAX_OUTBOUND,
        max_inbound: int = MAX_INBOUND,
        addr_manager: AddrManager | None = None,
        executor: ThreadPoolExecutor | None | object = _DEFAULT_EXECUTOR,
    ) -> None:
        self._engine = engine
        self._network_id = network_id
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._max_outbound = max_outbound
        self._max_inbound = max_inbound
        self._addr_mgr = addr_manager
        if executor is _DEFAULT_EXECUTOR:
            self._executor: ThreadPoolExecutor | None = ThreadPoolExecutor(
                max_workers=4, thread_name_prefix="manager"
            )
            self._owns_executor = True
        else:
            self._executor = executor  # type: ignore[assignment]
            self._owns_executor = False

        self._peers: dict[Peer, asyncio.Task] = {}
        self._outbound_count: int = 0
        self._inbound_count: int = 0
        # Peers that have completed the handshake; used to distinguish
        # clean disconnects from failed outbound attempts.
        self._active_peers: set[Peer] = set()

        self._seen_blocks: set[bytes] = set()
        self._seen_txs: set[bytes] = set()

        self._server: asyncio.Server | None = None
        self._maintain_task: asyncio.Task | None = None

    # ------------------------------------------------------------------ startup

    async def start_listener(self) -> int:
        """Start the TCP listener (and outbound-maintenance loop). Returns the bound port."""
        self._server = await asyncio.start_server(
            self._accept_inbound,
            self._listen_host,
            self._listen_port,
        )
        port = self._server.sockets[0].getsockname()[1]
        log.info("P2P listening on %s:%d", self._listen_host, port)
        if self._addr_mgr is not None:
            self._maintain_task = asyncio.create_task(
                self._maintain_outbound(), name="p2p-maintain"
            )
        return port

    async def stop(self) -> None:
        """Disconnect all peers and shut down the listener."""
        if self._maintain_task is not None and not self._maintain_task.done():
            self._maintain_task.cancel()
            try:
                await self._maintain_task
            except asyncio.CancelledError:
                pass
            self._maintain_task = None
        if self._server is not None:
            self._server.close()
            self._server = None
        for peer in list(self._peers):
            await peer.disconnect()
        if self._owns_executor and self._executor is not None:
            self._executor.shutdown(wait=False)

    # ------------------------------------------------------------------ dialing

    async def connect_to(self, host: str, port: int) -> Peer | None:
        """Dial an outbound connection. Returns the Peer on success, else None."""
        if self._outbound_count >= self._max_outbound:
            log.debug("outbound limit reached, not connecting to %s:%d", host, port)
            return None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10.0
            )
        except (OSError, asyncio.TimeoutError) as exc:
            log.debug("failed to connect to %s:%d: %s", host, port, exc)
            return None
        peer = Peer(
            reader=reader,
            writer=writer,
            network_id=self._network_id,
            local_start_height=max(0, self._engine.tip_height()),
            local_port=self._listen_port,
            outbound=True,
            callbacks=self,
        )
        self._outbound_count += 1
        task = asyncio.create_task(peer.run(), name=f"peer-out-{host}:{port}")
        self._peers[peer] = task
        return peer

    # ------------------------------------------------------------------ inbound

    async def _accept_inbound(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if self._inbound_count >= self._max_inbound:
            writer.close()
            return
        peer = Peer(
            reader=reader,
            writer=writer,
            network_id=self._network_id,
            local_start_height=max(0, self._engine.tip_height()),
            local_port=self._listen_port,
            outbound=False,
            callbacks=self,
        )
        self._inbound_count += 1
        addr = peer.remote_addr
        task = asyncio.create_task(peer.run(), name=f"peer-in-{addr[0]}:{addr[1]}")
        self._peers[peer] = task

    # ------------------------------------------------------------------ PeerCallbacks

    async def on_peer_ready(self, peer: Peer) -> None:
        if peer.remote_version is None:
            return
        self._active_peers.add(peer)
        # Record the peer's advertised listening address in the address book
        if self._addr_mgr is not None:
            adv_ip = net_ip_to_str(peer.remote_version.from_ip)
            adv_port = peer.remote_version.from_port
            if adv_port > 0:
                await self._run_sync(self._addr_mgr.mark_good, adv_ip, adv_port)
        remote_height = peer.remote_version.start_height
        our_height = await self._run_sync(self._engine.tip_height)
        log.debug(
            "peer ready: %s  remote_height=%d our_height=%d",
            peer, remote_height, our_height,
        )
        if remote_height > our_height:
            locators = await self._run_sync(self._engine.locator_hashes)
            await peer.send_getheaders(GetBlocksMessage(
                version=PROTOCOL_VERSION,
                locator_hashes=locators,
                stop_hash=b"\x00" * 32,
            ))
        else:
            items = [
                InvItem(type=INV_TX, hash=e.txid_bytes)
                for e in self._engine.mempool.entries.values()
            ]
            for chunk in _chunks(items, MAX_INV_PER_MSG):
                await peer.send_inv(chunk)
        # Ask new outbound peers for their address book
        if peer.outbound and self._addr_mgr is not None:
            await peer.send_getaddr()

    async def on_peer_disconnected(self, peer: Peer) -> None:
        log.debug("peer disconnected: %s", peer)
        self._peers.pop(peer, None)
        if peer.outbound:
            self._outbound_count = max(0, self._outbound_count - 1)
            # If this outbound peer never reached ACTIVE, the connection failed
            if peer not in self._active_peers and self._addr_mgr is not None:
                host, port = peer.remote_addr
                await self._run_sync(self._addr_mgr.mark_attempted, host, port)
        else:
            self._inbound_count = max(0, self._inbound_count - 1)
        self._active_peers.discard(peer)

    async def on_inv(self, peer: Peer, items: list[InvItem]) -> None:
        want: list[InvItem] = []
        for item in items:
            if item.type == INV_BLOCK:
                if item.hash not in self._seen_blocks and \
                        not await self._run_sync(self._engine.have_block, item.hash):
                    want.append(item)
            elif item.type == INV_TX:
                if item.hash not in self._seen_txs and \
                        item.hash not in self._engine.mempool.entries:
                    want.append(item)
        if want:
            for chunk in _chunks(want, MAX_INV_PER_MSG):
                await peer.send_getdata(chunk)

    async def on_block(self, peer: Peer, block_bytes: bytes) -> None:
        try:
            block = decode_block(block_bytes)
        except Exception as exc:
            log.warning("malformed block from %s: %s", peer, exc)
            return
        bh = block_hash(block.header)
        if bh in self._seen_blocks:
            return
        _cache_add(self._seen_blocks, bh, MAX_SEEN_CACHE)
        try:
            result: SubmitResult = await self._run_sync(self._engine.submit_block, block)
        except BlockValidationError as exc:
            log.warning("invalid block from %s: %s", peer, exc)
            return
        except Exception as exc:
            log.warning("block error from %s: %s", peer, exc)
            return
        if result.accepted:
            log.info(
                "accepted block height=%d hash=%.16s",
                result.height, bh.hex(),
            )
            await self._relay_inv(INV_BLOCK, bh, exclude=peer)
        if result.became_active_tip and peer.remote_version is not None:
            our_height = await self._run_sync(self._engine.tip_height)
            if our_height < peer.remote_version.start_height:
                locators = await self._run_sync(self._engine.locator_hashes)
                await peer.send_getheaders(GetBlocksMessage(
                    version=PROTOCOL_VERSION,
                    locator_hashes=locators,
                    stop_hash=b"\x00" * 32,
                ))

    async def on_tx(self, peer: Peer, tx_bytes: bytes) -> None:
        try:
            tx = decode_transaction(tx_bytes)
        except Exception as exc:
            log.warning("malformed tx from %s: %s", peer, exc)
            return
        tx_hash = txid(tx)
        if tx_hash in self._seen_txs or tx_hash in self._engine.mempool.entries:
            return
        _cache_add(self._seen_txs, tx_hash, MAX_SEEN_CACHE)
        try:
            await self._run_sync(functools.partial(
                self._engine.mempool.add_transaction,
                tx,
                self._engine.utxos.get,
                ChainContext(
                    network_id=self._network_id,
                    current_height=self._engine.tip_height(),
                    median_time_past=int(time.time()),
                    coinbase_maturity=self._engine.coinbase_maturity,
                ),
            ))
        except Exception as exc:
            log.debug("tx from %s rejected by mempool: %s", peer, exc)
            return
        await self._relay_inv(INV_TX, tx_hash, exclude=peer)

    async def on_addr(self, peer: Peer, addrs: list[NetAddr]) -> None:
        if self._addr_mgr is None:
            return
        added = await self._run_sync(self._addr_mgr.add_many, addrs)
        log.debug("on_addr from %s: %d/%d new entries", peer, added, len(addrs))

    async def on_getaddr(self, peer: Peer) -> None:
        if self._addr_mgr is None:
            return
        entries = await self._run_sync(self._addr_mgr.get_addrs_for_relay)
        if not entries:
            return
        wire_addrs = [
            NetAddr(timestamp=e.timestamp, ip=_str_to_net_ip(e.ip), port=e.port)
            for e in entries
        ]
        # addr messages are capped at 1000 entries by the wire protocol
        for chunk in _chunks(wire_addrs, 1000):
            await peer.send_addr(AddrMessage(addrs=chunk))

    async def on_getdata(self, peer: Peer, items: list[InvItem]) -> None:
        for item in items:
            if item.type == INV_BLOCK:
                block = await self._run_sync(self._engine.get_block, item.hash)
                if block is not None:
                    await peer.send_block(encode_block(block))
                else:
                    await peer._send(
                        "notfound",
                        encode_inv(InvMessage(items=[item])),
                    )
            elif item.type == INV_TX:
                entry = self._engine.mempool.entries.get(item.hash)
                if entry is not None:
                    await peer.send_tx(encode_transaction(entry.tx))
                else:
                    await peer._send(
                        "notfound",
                        encode_inv(InvMessage(items=[item])),
                    )

    async def on_getheaders(self, peer: Peer, msg: GetBlocksMessage) -> None:
        stop = msg.stop_hash if msg.stop_hash != b"\x00" * 32 else None
        entries = await self._run_sync(
            self._engine.active_headers_after,
            msg.locator_hashes,
            stop,
            MAX_HEADERS_PER_MSG,
        )
        await peer.send_headers(HeadersMessage(headers=[e.header for e in entries]))

    async def on_getblocks(self, peer: Peer, msg: GetBlocksMessage) -> None:
        stop = msg.stop_hash if msg.stop_hash != b"\x00" * 32 else None
        entries = await self._run_sync(
            self._engine.active_headers_after,
            msg.locator_hashes,
            stop,
            MAX_INV_PER_MSG,
        )
        items = [InvItem(type=INV_BLOCK, hash=e.block_hash) for e in entries]
        for chunk in _chunks(items, MAX_INV_PER_MSG):
            await peer.send_inv(chunk)

    async def on_headers(self, peer: Peer, msg: HeadersMessage) -> None:
        if not msg.headers:
            return
        new_hashes: list[bytes] = []
        for header in msg.headers:
            try:
                added = await self._run_sync(self._engine.submit_header_only, header)
            except BlockValidationError as exc:
                log.warning("bad header from %s: %s", peer, exc)
                break
            if added:
                new_hashes.append(block_hash(header))
        # Request bodies for headers we don't have yet
        want: list[InvItem] = []
        for bh in new_hashes:
            if not await self._run_sync(self._engine.have_block, bh):
                want.append(InvItem(type=INV_BLOCK, hash=bh))
        for chunk in _chunks(want, MAX_INV_PER_MSG):
            await peer.send_getdata(chunk)
        # If we got a full batch, there are likely more headers
        if len(msg.headers) == MAX_HEADERS_PER_MSG:
            locators = await self._run_sync(self._engine.locator_hashes)
            await peer.send_getheaders(GetBlocksMessage(
                version=PROTOCOL_VERSION,
                locator_hashes=locators,
                stop_hash=b"\x00" * 32,
            ))

    # ------------------------------------------------------------------ helpers

    async def _relay_inv(
        self, inv_type: int, item_hash: bytes, *, exclude: Peer | None = None
    ) -> None:
        item = InvItem(type=inv_type, hash=item_hash)
        for peer in list(self._peers):
            if peer is exclude or peer.state != PeerState.ACTIVE:
                continue
            try:
                await peer.send_inv([item])
            except Exception:
                pass

    async def _run_sync(self, fn, *args):
        """Run a synchronous function without blocking the event loop."""
        if self._executor is None:
            return fn(*args)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, fn, *args)

    # ------------------------------------------------------------------ outbound maintenance

    async def _maintain_outbound(self) -> None:
        """Periodically top up outbound connections from the address book."""
        try:
            while True:
                await asyncio.sleep(30)
                if self._addr_mgr is None:
                    continue
                while self._outbound_count < self._max_outbound:
                    exclude = {
                        f"{p.remote_addr[0]}:{p.remote_addr[1]}"
                        for p in self._peers
                    }
                    entry = await self._run_sync(
                        self._addr_mgr.select_for_connection, exclude=exclude
                    )
                    if entry is None:
                        break
                    asyncio.create_task(
                        self.connect_to(entry.ip, entry.port),
                        name=f"dial-{entry.ip}:{entry.port}",
                    )
                    await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------ queries

    def peer_count(self) -> tuple[int, int]:
        """Return (outbound_count, inbound_count)."""
        return self._outbound_count, self._inbound_count

    def active_peers(self) -> list[Peer]:
        return [p for p in self._peers if p.state == PeerState.ACTIVE]


# ------------------------------------------------------------------ module helpers

def _chunks(lst: list, size: int):
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


def _cache_add(cache: set, value: object, max_size: int) -> None:
    if len(cache) >= max_size:
        cache.clear()
    cache.add(value)


def _str_to_net_ip(ip: str) -> bytes:
    """Convert a human-readable IP string to a 16-byte wire address."""
    try:
        return ipv4_to_net_ip(ip)
    except ValueError:
        # IPv6: encode as raw 16 bytes
        import ipaddress
        return ipaddress.ip_address(ip).packed
