"""Two-node IBD smoke test.

Node A mines BLOCK_COUNT devnet blocks.  Node B starts empty, connects to A,
and must reach the same tip within SYNC_TIMEOUT seconds.

This exercises the full stack end-to-end:
  ChainEngine (block storage / index)
  → Miner (PoW + template)
  → LatcoinNode (asyncio P2P loop in background thread)
  → PeerManager (getheaders / headers / getdata / block relay)
  → ChainEngine (block acceptance on the receiving side)
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from latcoin.chain.engine import ChainEngine
from latcoin.codec.constants import NETWORK_DEVNET, SCHEME_SIG_V1
from latcoin.codec.hash import hash32
from latcoin.crypto.signatures import keygen
from latcoin.mining.miner import Miner
from latcoin.node.node import LatcoinNode

BLOCK_COUNT = 10
SYNC_TIMEOUT = 15.0  # seconds; devnet PoW is trivial, real sync takes <<1s


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _init_datadir(path: Path) -> Path:
    """Create the three directories ChainEngine and AddrManager need."""
    (path / "blocks").mkdir(parents=True)
    (path / "chainstate").mkdir(parents=True)
    (path / "mempool").mkdir(parents=True)
    return path


def _mine_blocks(datadir: Path, count: int) -> None:
    """Mine *count* devnet blocks directly against a local ChainEngine."""
    _, pubkey = keygen(SCHEME_SIG_V1)   # mocksig-v1 — no real crypto cost
    engine = ChainEngine(datadir, NETWORK_DEVNET, coinbase_maturity=0)
    miner = Miner(engine, hash32(pubkey), SCHEME_SIG_V1)
    stats = miner.run(max_blocks=count)
    assert stats.blocks_found == count, (
        f"pre-condition: expected {count} blocks mined, got {stats.blocks_found}"
    )
    engine.persist()


def _poll_height(engine: ChainEngine, target: int, timeout: float) -> bool:
    """Return True once engine.tip_height() reaches *target*, False on timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if engine.tip_height() == target:
            return True
        time.sleep(0.05)
    return False


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

def test_ibd_node_b_syncs_to_node_a(tmp_path: Path) -> None:
    datadir_a = _init_datadir(tmp_path / "node_a")
    datadir_b = _init_datadir(tmp_path / "node_b")

    # --- pre-condition: mine 10 blocks onto A's chain before P2P starts ---
    _mine_blocks(datadir_a, BLOCK_COUNT)

    node_a = LatcoinNode(
        datadir_a,
        NETWORK_DEVNET,
        listen_host="127.0.0.1",
        listen_port=0,        # OS picks a free port
        seeds=[],             # no automatic seed dialling
    )
    node_a.start()
    # start() blocks until the listener is bound, so p2p_port is valid here.
    assert node_a.engine.tip_height() == BLOCK_COUNT - 1, (
        "pre-condition: node A must have pre-mined blocks loaded"
    )

    node_b = LatcoinNode(
        datadir_b,
        NETWORK_DEVNET,
        listen_host="127.0.0.1",
        listen_port=0,
        seed_peers=[("127.0.0.1", node_a.p2p_port)],
        seeds=[],
    )
    assert node_b.engine.tip_height() == -1, (
        "pre-condition: node B must start with an empty chain"
    )

    node_b.start()

    try:
        synced = _poll_height(node_b.engine, BLOCK_COUNT - 1, SYNC_TIMEOUT)
        if not synced:
            pytest.fail(
                f"IBD timeout after {SYNC_TIMEOUT}s: "
                f"node B at height {node_b.engine.tip_height()}, "
                f"expected {BLOCK_COUNT - 1}"
            )

        assert node_b.engine.tip_height() == BLOCK_COUNT - 1
        assert node_b.engine.tip_hash() == node_a.engine.tip_hash(), (
            "tip hash mismatch: nodes do not agree on the best chain"
        )
    finally:
        node_b.stop()
        node_a.stop()
