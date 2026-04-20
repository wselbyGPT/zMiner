from __future__ import annotations

from pathlib import Path

import pytest

from latcoin.chain.blockindex import STATUS_ACTIVE, STATUS_VALID, ZERO32
from latcoin.chain.engine import ChainEngine
from latcoin.codec.block import Block, block_hash
from latcoin.codec.constants import NETWORK_DEVNET
from latcoin.mining.template import build_block_template

ALICE_LOCK = b"\xa1" * 32
BOB_LOCK = b"\xb2" * 32

# Bits used for every test block. Genesis bits for devnet is 8, so we stay there
# to keep mining cheap; no retarget happens inside a few blocks.
_BITS = 8


def _new_engine(root: Path) -> ChainEngine:
    (root / "mempool").mkdir(parents=True, exist_ok=True)
    return ChainEngine(root, NETWORK_DEVNET, coinbase_maturity=0)


def _mine_on(
    engine: ChainEngine,
    *,
    parent_hash: bytes,
    height: int,
    reward_lock: bytes,
    timestamp: int,
) -> Block:
    template = build_block_template(
        network_id=NETWORK_DEVNET,
        height=height,
        prev_block_hash=parent_hash,
        reward_lock_data=reward_lock,
        bits=_BITS,
        mempool_txs=[],
        total_fees=0,
        timestamp=timestamp,
    )
    return template.block


def _balances(engine: ChainEngine) -> dict[bytes, int]:
    """Total lats per lock_data across the current UTXO set."""
    out: dict[bytes, int] = {}
    for utxo in engine.utxos.entries.values():
        out[utxo.lock_data] = out.get(utxo.lock_data, 0) + utxo.amount
    return out


@pytest.fixture
def datadir(tmp_path: Path) -> Path:
    root = tmp_path / "node"
    root.mkdir()
    return root


def test_simple_extension_tip_follows(datadir: Path) -> None:
    engine = _new_engine(datadir)
    genesis = _mine_on(engine, parent_hash=ZERO32, height=0, reward_lock=ALICE_LOCK, timestamp=1_700_000_000)
    r0 = engine.submit_block(genesis, persist=False)
    assert r0.accepted and r0.became_active_tip
    assert r0.reorg_depth == 0
    assert engine.tip_hash() == r0.block_hash

    a1 = _mine_on(engine, parent_hash=r0.block_hash, height=1, reward_lock=ALICE_LOCK, timestamp=1_700_000_010)
    r1 = engine.submit_block(a1, persist=False)
    assert r1.accepted and r1.became_active_tip
    assert r1.reorg_depth == 0
    assert engine.tip_height() == 1


def test_duplicate_submit_is_idempotent(datadir: Path) -> None:
    engine = _new_engine(datadir)
    genesis = _mine_on(engine, parent_hash=ZERO32, height=0, reward_lock=ALICE_LOCK, timestamp=1_700_000_000)
    r0 = engine.submit_block(genesis, persist=False)
    utxos_before = dict(engine.utxos.entries)

    r0_again = engine.submit_block(genesis, persist=False)
    assert r0_again.already_known is True
    assert r0_again.accepted is True
    assert r0_again.reorg_depth == 0
    assert engine.tip_hash() == r0.block_hash
    assert engine.utxos.entries == utxos_before


def test_equal_work_fork_does_not_reorg(datadir: Path) -> None:
    """With cumulative_work tie, the current active tip wins (no churn)."""
    engine = _new_engine(datadir)
    genesis = _mine_on(engine, parent_hash=ZERO32, height=0, reward_lock=ALICE_LOCK, timestamp=1_700_000_000)
    r_g = engine.submit_block(genesis, persist=False)

    a1 = _mine_on(engine, parent_hash=r_g.block_hash, height=1, reward_lock=ALICE_LOCK, timestamp=1_700_000_010)
    r_a = engine.submit_block(a1, persist=False)
    assert engine.tip_hash() == r_a.block_hash

    # B1 builds on genesis with different timestamp → different hash, same work as A1
    b1 = _mine_on(engine, parent_hash=r_g.block_hash, height=1, reward_lock=BOB_LOCK, timestamp=1_700_000_050)
    r_b = engine.submit_block(b1, persist=False)
    assert r_b.accepted is True
    assert r_b.became_active_tip is False
    assert r_b.reorg_depth == 0
    assert engine.tip_hash() == r_a.block_hash  # A1 remains active


def test_heavier_fork_triggers_reorg(datadir: Path) -> None:
    """When B-branch accumulates more work, active tip swings to B."""
    engine = _new_engine(datadir)
    g = _mine_on(engine, parent_hash=ZERO32, height=0, reward_lock=ALICE_LOCK, timestamp=1_700_000_000)
    r_g = engine.submit_block(g, persist=False)

    a1 = _mine_on(engine, parent_hash=r_g.block_hash, height=1, reward_lock=ALICE_LOCK, timestamp=1_700_000_010)
    r_a1 = engine.submit_block(a1, persist=False)

    # B1 shares parent with A1 but carries a different coinbase (Bob's lock)
    b1 = _mine_on(engine, parent_hash=r_g.block_hash, height=1, reward_lock=BOB_LOCK, timestamp=1_700_000_050)
    r_b1 = engine.submit_block(b1, persist=False)
    assert r_b1.became_active_tip is False  # same work as A1
    assert engine.tip_hash() == r_a1.block_hash

    # B2 extends B1, tipping cumulative work beyond A1
    b2 = _mine_on(engine, parent_hash=r_b1.block_hash, height=2, reward_lock=BOB_LOCK, timestamp=1_700_000_060)
    r_b2 = engine.submit_block(b2, persist=False)
    assert r_b2.became_active_tip is True
    assert r_b2.reorg_depth == 1  # A1 got disconnected
    assert engine.tip_hash() == r_b2.block_hash
    assert engine.tip_height() == 2

    # Status labels: old A1 demoted to VALID, new tip is ACTIVE.
    assert engine.index.require(r_a1.block_hash).status == STATUS_VALID
    assert engine.index.require(r_b2.block_hash).status == STATUS_ACTIVE


def test_reorg_rewrites_utxo_set(datadir: Path) -> None:
    """A coinbase from the disconnected branch is removed; new-branch coinbases are added."""
    engine = _new_engine(datadir)
    g = _mine_on(engine, parent_hash=ZERO32, height=0, reward_lock=ALICE_LOCK, timestamp=1_700_000_000)
    r_g = engine.submit_block(g, persist=False)

    a1 = _mine_on(engine, parent_hash=r_g.block_hash, height=1, reward_lock=ALICE_LOCK, timestamp=1_700_000_010)
    engine.submit_block(a1, persist=False)
    # Before reorg: Alice has G (50) + A1 (50) = 100; Bob has 0.
    pre = _balances(engine)
    assert pre[ALICE_LOCK] == 50 * 100_000_000 * 2
    assert BOB_LOCK not in pre

    b1 = _mine_on(engine, parent_hash=r_g.block_hash, height=1, reward_lock=BOB_LOCK, timestamp=1_700_000_050)
    r_b1 = engine.submit_block(b1, persist=False)
    b2 = _mine_on(engine, parent_hash=r_b1.block_hash, height=2, reward_lock=BOB_LOCK, timestamp=1_700_000_060)
    engine.submit_block(b2, persist=False)

    post = _balances(engine)
    # After reorg: Alice keeps only G's coinbase; A1 is gone. Bob has B1 + B2.
    assert post[ALICE_LOCK] == 50 * 100_000_000
    assert post[BOB_LOCK] == 50 * 100_000_000 * 2


def test_two_deep_reorg_disconnect_and_connect(datadir: Path) -> None:
    """Branch A (A1, A2) loses to branch B (B1, B2, B3); reorg depth = 2."""
    engine = _new_engine(datadir)
    g = _mine_on(engine, parent_hash=ZERO32, height=0, reward_lock=ALICE_LOCK, timestamp=1_700_000_000)
    r_g = engine.submit_block(g, persist=False)

    a1 = _mine_on(engine, parent_hash=r_g.block_hash, height=1, reward_lock=ALICE_LOCK, timestamp=1_700_000_010)
    r_a1 = engine.submit_block(a1, persist=False)
    a2 = _mine_on(engine, parent_hash=r_a1.block_hash, height=2, reward_lock=ALICE_LOCK, timestamp=1_700_000_020)
    engine.submit_block(a2, persist=False)

    # B-branch forks at genesis.
    b1 = _mine_on(engine, parent_hash=r_g.block_hash, height=1, reward_lock=BOB_LOCK, timestamp=1_700_000_050)
    r_b1 = engine.submit_block(b1, persist=False)
    assert r_b1.became_active_tip is False
    b2 = _mine_on(engine, parent_hash=r_b1.block_hash, height=2, reward_lock=BOB_LOCK, timestamp=1_700_000_060)
    r_b2 = engine.submit_block(b2, persist=False)
    assert r_b2.became_active_tip is False  # still equal to A2's work
    b3 = _mine_on(engine, parent_hash=r_b2.block_hash, height=3, reward_lock=BOB_LOCK, timestamp=1_700_000_070)
    r_b3 = engine.submit_block(b3, persist=False)
    assert r_b3.became_active_tip is True
    assert r_b3.reorg_depth == 2
    assert engine.tip_hash() == r_b3.block_hash
    assert engine.tip_height() == 3

    post = _balances(engine)
    # Alice keeps only G; Bob has B1+B2+B3.
    assert post[ALICE_LOCK] == 50 * 100_000_000
    assert post[BOB_LOCK] == 50 * 100_000_000 * 3


def test_undo_records_written_for_active_blocks(datadir: Path) -> None:
    engine = _new_engine(datadir)
    g = _mine_on(engine, parent_hash=ZERO32, height=0, reward_lock=ALICE_LOCK, timestamp=1_700_000_000)
    r_g = engine.submit_block(g, persist=False)
    a1 = _mine_on(engine, parent_hash=r_g.block_hash, height=1, reward_lock=ALICE_LOCK, timestamp=1_700_000_010)
    r_a1 = engine.submit_block(a1, persist=False)

    undo_dir = datadir / "chainstate" / "undo"
    # There's an undo record for each connected block.
    undo_files = sorted(p.name for p in undo_dir.glob("*.json"))
    assert any(r_g.block_hash.hex() in name for name in undo_files)
    assert any(r_a1.block_hash.hex() in name for name in undo_files)


def test_persist_and_reload_preserves_active_tip_after_reorg(datadir: Path) -> None:
    engine = _new_engine(datadir)
    g = _mine_on(engine, parent_hash=ZERO32, height=0, reward_lock=ALICE_LOCK, timestamp=1_700_000_000)
    r_g = engine.submit_block(g)
    a1 = _mine_on(engine, parent_hash=r_g.block_hash, height=1, reward_lock=ALICE_LOCK, timestamp=1_700_000_010)
    engine.submit_block(a1)
    b1 = _mine_on(engine, parent_hash=r_g.block_hash, height=1, reward_lock=BOB_LOCK, timestamp=1_700_000_050)
    r_b1 = engine.submit_block(b1)
    b2 = _mine_on(engine, parent_hash=r_b1.block_hash, height=2, reward_lock=BOB_LOCK, timestamp=1_700_000_060)
    r_b2 = engine.submit_block(b2)
    assert engine.tip_hash() == r_b2.block_hash

    reloaded = ChainEngine(datadir, NETWORK_DEVNET, coinbase_maturity=0)
    assert reloaded.tip_hash() == r_b2.block_hash
    assert reloaded.tip_height() == 2
    assert _balances(reloaded)[BOB_LOCK] == 50 * 100_000_000 * 2
    # Fork-candidate block A1 is still indexed.
    assert a1.header.prev_block_hash == r_g.block_hash
    assert block_hash(a1.header) in reloaded.index


def test_locator_walks_active_chain(datadir: Path) -> None:
    engine = _new_engine(datadir)
    hashes: list[bytes] = []
    prev = ZERO32
    for height in range(4):
        block = _mine_on(
            engine,
            parent_hash=prev,
            height=height,
            reward_lock=ALICE_LOCK,
            timestamp=1_700_000_000 + height * 10,
        )
        r = engine.submit_block(block, persist=False)
        hashes.append(r.block_hash)
        prev = r.block_hash

    locator = engine.locator_hashes()
    # Locator is tip-first, includes genesis last.
    assert locator[0] == hashes[-1]
    assert hashes[0] in locator


def test_active_headers_after_returns_missing_tail(datadir: Path) -> None:
    engine = _new_engine(datadir)
    hashes: list[bytes] = []
    prev = ZERO32
    for height in range(5):
        block = _mine_on(
            engine,
            parent_hash=prev,
            height=height,
            reward_lock=ALICE_LOCK,
            timestamp=1_700_000_000 + height * 10,
        )
        r = engine.submit_block(block, persist=False)
        hashes.append(r.block_hash)
        prev = r.block_hash

    # Peer says they have up to block height=1; we should return heights 2..4.
    tail = engine.active_headers_after([hashes[1]], stop_hash=None, max_count=100)
    tail_hashes = [e.block_hash for e in tail]
    assert tail_hashes == hashes[2:]

    # Empty locator means walk from genesis.
    full = engine.active_headers_after([], stop_hash=None, max_count=100)
    assert [e.block_hash for e in full] == hashes

    # max_count caps output.
    capped = engine.active_headers_after([], stop_hash=None, max_count=2)
    assert len(capped) == 2


def test_submit_block_rejects_unknown_parent(datadir: Path) -> None:
    from latcoin.validation.errors import BlockValidationError

    engine = _new_engine(datadir)
    bogus_parent = b"\xde" * 32
    # Build a header that claims bogus_parent and just try to mine it.
    block = _mine_on(engine, parent_hash=bogus_parent, height=5, reward_lock=ALICE_LOCK, timestamp=1_700_000_000)
    with pytest.raises(BlockValidationError, match="unknown parent"):
        engine.submit_block(block, persist=False)


def test_submit_block_rejects_bad_height(datadir: Path) -> None:
    from latcoin.validation.errors import BlockValidationError

    engine = _new_engine(datadir)
    g = _mine_on(engine, parent_hash=ZERO32, height=0, reward_lock=ALICE_LOCK, timestamp=1_700_000_000)
    r_g = engine.submit_block(g, persist=False)

    # Next block should be height=1 but we claim height=5.
    bad = _mine_on(engine, parent_hash=r_g.block_hash, height=5, reward_lock=ALICE_LOCK, timestamp=1_700_000_010)
    with pytest.raises(BlockValidationError, match="height"):
        engine.submit_block(bad, persist=False)
