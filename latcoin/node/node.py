from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path

from latcoin.chain.engine import ChainEngine
from latcoin.codec.constants import NETWORK_DEVNET
from latcoin.net.addr_manager import AddrManager
from latcoin.net.manager import PeerManager
from latcoin.node.seeds import seeds_for_network

log = logging.getLogger(__name__)

DEFAULT_P2P_PORT = 9337


class LatcoinNode:
    """Ties ChainEngine and PeerManager into a runnable node.

    The P2P event loop runs in a background thread so callers can block on
    synchronous work (e.g., the RPC HTTP server) on the calling thread.
    """

    def __init__(
        self,
        datadir: Path,
        network_id: int = NETWORK_DEVNET,
        *,
        listen_host: str = "0.0.0.0",
        listen_port: int = DEFAULT_P2P_PORT,
        seed_peers: list[tuple[str, int]] | None = None,
        seeds: list[tuple[str, int]] | None = None,
        coinbase_maturity: int = 100,
    ) -> None:
        """
        Parameters
        ----------
        seed_peers:
            Explicit peers from ``--peer`` CLI args; always dialled on startup.
        seeds:
            Hardcoded bootstrap seeds.  ``None`` (default) uses the built-in
            list for *network_id*.  Pass ``[]`` to disable seed bootstrapping.
        """
        explicit_peers: list[tuple[str, int]] = seed_peers or []
        boot_seeds: list[tuple[str, int]] = (
            seeds_for_network(network_id) if seeds is None else seeds
        )
        datadir = Path(datadir)

        self.engine = ChainEngine(
            datadir, network_id, coinbase_maturity=coinbase_maturity
        )
        addr_mgr = AddrManager(
            datadir / "peers.json",
            allow_private=(network_id == NETWORK_DEVNET),
        )

        # Decide what to dial on startup before mutating the address book.
        # Seeds are only force-dialled on first boot (empty address book) so
        # that subsequent restarts rely on the persisted tried/new tables.
        _was_empty = addr_mgr.size() == (0, 0)
        addr_mgr.add_seeds(boot_seeds)

        seen: set[tuple[str, int]] = set()
        dial_list: list[tuple[str, int]] = []
        for hp in explicit_peers + (boot_seeds if _was_empty else []):
            if hp not in seen:
                seen.add(hp)
                dial_list.append(hp)
        self._dial_on_start = dial_list

        self.peer_manager = PeerManager(
            self.engine,
            network_id=network_id,
            listen_host=listen_host,
            listen_port=listen_port,
            addr_manager=addr_mgr,
        )

        self._p2p_port: int = listen_port
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None

    @property
    def p2p_port(self) -> int:
        """Actual bound P2P port (resolved after start())."""
        return self._p2p_port

    def start(self) -> None:
        """Start the P2P listener in a background thread and connect to seeds."""
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever, name="p2p-loop", daemon=True
        )
        self._thread.start()
        future = asyncio.run_coroutine_threadsafe(self._setup(), self._loop)
        future.result(timeout=10)

    def stop(self) -> None:
        """Shut down the P2P stack and persist chain state."""
        if self._loop is not None:
            future = asyncio.run_coroutine_threadsafe(
                self.peer_manager.stop(), self._loop
            )
            future.result(timeout=5)
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5)
        self.engine.persist()

    async def _setup(self) -> None:
        port = await self.peer_manager.start_listener()
        self._p2p_port = port
        log.info("P2P listening on port %d", port)
        for host, p in self._dial_on_start:
            asyncio.create_task(self.peer_manager.connect_to(host, p))
