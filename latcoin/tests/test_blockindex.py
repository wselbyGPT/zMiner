from __future__ import annotations

import pytest

from latcoin.chain.blockindex import (
    STATUS_ACTIVE,
    STATUS_FAILED,
    STATUS_HEADER_ONLY,
    STATUS_VALID,
    ZERO32,
    BlockIndex,
    BlockIndexEntry,
)
from latcoin.codec.block import BlockHeader
from latcoin.validation.pow import PowState


def _header(tag: int) -> BlockHeader:
    return BlockHeader(
        version=1,
        prev_block_hash=b"\x00" * 32,
        merkle_root=bytes([tag]) * 32,
        timestamp=1_700_000_000 + tag,
        height=tag,
        bits=8,
        nonce=tag,
    )


def _pow_state() -> PowState:
    return PowState(
        current_bits=8,
        last_retarget_height=0,
        last_retarget_timestamp=0,
        tip_timestamp=0,
    )


def _entry(
    *,
    block_hash: bytes,
    parent_hash: bytes,
    height: int,
    work: int,
    tag: int,
    status: str = STATUS_HEADER_ONLY,
    have_block: bool = True,
) -> BlockIndexEntry:
    return BlockIndexEntry(
        block_hash=block_hash,
        header=_header(tag),
        height=height,
        parent_hash=parent_hash,
        cumulative_work=work,
        pow_state=_pow_state(),
        status=status,
        have_block=have_block,
    )


def _h(prefix: int) -> bytes:
    return bytes([prefix]) + b"\x00" * 31


def test_add_rejects_duplicate() -> None:
    index = BlockIndex()
    index.add(_entry(block_hash=_h(1), parent_hash=ZERO32, height=0, work=10, tag=1))
    with pytest.raises(ValueError, match="already indexed"):
        index.add(_entry(block_hash=_h(1), parent_hash=ZERO32, height=0, work=10, tag=1))


def test_require_raises_when_missing() -> None:
    index = BlockIndex()
    with pytest.raises(KeyError):
        index.require(_h(7))


def test_entry_rejects_bad_hash_lengths() -> None:
    with pytest.raises(ValueError):
        _entry(block_hash=b"\x01", parent_hash=ZERO32, height=0, work=1, tag=1)
    with pytest.raises(ValueError):
        _entry(block_hash=_h(1), parent_hash=b"\x00" * 4, height=0, work=1, tag=1)


def test_entry_rejects_invalid_status() -> None:
    with pytest.raises(ValueError, match="invalid status"):
        BlockIndexEntry(
            block_hash=_h(1),
            header=_header(1),
            height=0,
            parent_hash=ZERO32,
            cumulative_work=1,
            pow_state=_pow_state(),
            status="bogus",
        )


def test_best_candidate_prefers_more_work() -> None:
    index = BlockIndex()
    a = _entry(block_hash=_h(1), parent_hash=ZERO32, height=0, work=5, tag=1)
    b = _entry(block_hash=_h(2), parent_hash=ZERO32, height=0, work=7, tag=2)
    index.add(a)
    index.add(b)
    best = index.best_candidate()
    assert best is not None
    assert best.block_hash == _h(2)


def test_best_candidate_tiebreak_lower_hash_wins() -> None:
    index = BlockIndex()
    lo = _entry(block_hash=_h(1), parent_hash=ZERO32, height=0, work=5, tag=1)
    hi = _entry(block_hash=_h(9), parent_hash=ZERO32, height=0, work=5, tag=9)
    index.add(hi)
    index.add(lo)
    best = index.best_candidate()
    assert best is not None
    assert best.block_hash == _h(1)


def test_best_candidate_skips_failed() -> None:
    index = BlockIndex()
    a = _entry(block_hash=_h(1), parent_hash=ZERO32, height=0, work=10, tag=1, status=STATUS_FAILED)
    b = _entry(block_hash=_h(2), parent_hash=ZERO32, height=0, work=5, tag=2)
    index.add(a)
    index.add(b)
    best = index.best_candidate()
    assert best is not None
    assert best.block_hash == _h(2)


def test_best_candidate_empty_returns_none() -> None:
    assert BlockIndex().best_candidate() is None


def test_set_active_tip_updates_status_transitions() -> None:
    index = BlockIndex()
    a = _entry(block_hash=_h(1), parent_hash=ZERO32, height=0, work=5, tag=1, status=STATUS_VALID)
    b = _entry(block_hash=_h(2), parent_hash=_h(1), height=1, work=10, tag=2, status=STATUS_VALID)
    index.add(a)
    index.add(b)

    index.set_active_tip(_h(1))
    assert index.require(_h(1)).status == STATUS_ACTIVE
    assert index.active_tip().block_hash == _h(1)

    index.set_active_tip(_h(2))
    assert index.require(_h(1)).status == STATUS_VALID
    assert index.require(_h(2)).status == STATUS_ACTIVE

    index.set_active_tip(None)
    assert index.active_tip() is None
    assert index.require(_h(2)).status == STATUS_VALID


def test_set_active_tip_unknown_hash_raises() -> None:
    index = BlockIndex()
    with pytest.raises(KeyError):
        index.set_active_tip(_h(42))


def test_path_to_root_walks_parents_until_genesis() -> None:
    index = BlockIndex()
    index.add(_entry(block_hash=_h(1), parent_hash=ZERO32, height=0, work=1, tag=1))
    index.add(_entry(block_hash=_h(2), parent_hash=_h(1), height=1, work=2, tag=2))
    index.add(_entry(block_hash=_h(3), parent_hash=_h(2), height=2, work=3, tag=3))

    path = index.path_to_root(_h(3))
    assert [e.block_hash for e in path] == [_h(3), _h(2), _h(1)]


def test_path_to_root_unknown_hash_returns_empty() -> None:
    assert BlockIndex().path_to_root(_h(9)) == []


def test_children_of_tracks_multiple_children() -> None:
    index = BlockIndex()
    index.add(_entry(block_hash=_h(1), parent_hash=ZERO32, height=0, work=1, tag=1))
    index.add(_entry(block_hash=_h(2), parent_hash=_h(1), height=1, work=2, tag=2))
    index.add(_entry(block_hash=_h(3), parent_hash=_h(1), height=1, work=2, tag=3))
    kids = {e.block_hash for e in index.children_of(_h(1))}
    assert kids == {_h(2), _h(3)}


def test_find_fork_simple_extension() -> None:
    """Extending the active tip has empty disconnect and singleton connect."""
    index = BlockIndex()
    index.add(_entry(block_hash=_h(1), parent_hash=ZERO32, height=0, work=1, tag=1))
    index.add(_entry(block_hash=_h(2), parent_hash=_h(1), height=1, work=2, tag=2))

    disconnect, connect = index.find_fork(_h(1), _h(2))
    assert disconnect == []
    assert [e.block_hash for e in connect] == [_h(2)]


def test_find_fork_one_block_reorg() -> None:
    """From A1 to B1: disconnect A1, connect B1."""
    index = BlockIndex()
    index.add(_entry(block_hash=_h(0x10), parent_hash=ZERO32, height=0, work=1, tag=1))  # genesis
    index.add(_entry(block_hash=_h(0x20), parent_hash=_h(0x10), height=1, work=2, tag=2))  # A1
    index.add(_entry(block_hash=_h(0x30), parent_hash=_h(0x10), height=1, work=3, tag=3))  # B1

    disconnect, connect = index.find_fork(_h(0x20), _h(0x30))
    assert [e.block_hash for e in disconnect] == [_h(0x20)]
    assert [e.block_hash for e in connect] == [_h(0x30)]


def test_find_fork_two_deep_reorg() -> None:
    """Move from branch A (A1-A2) to branch B (B1-B2-B3) that forks at genesis."""
    index = BlockIndex()
    index.add(_entry(block_hash=_h(0x10), parent_hash=ZERO32, height=0, work=1, tag=1))
    # A: A1, A2
    index.add(_entry(block_hash=_h(0x21), parent_hash=_h(0x10), height=1, work=2, tag=2))
    index.add(_entry(block_hash=_h(0x22), parent_hash=_h(0x21), height=2, work=3, tag=3))
    # B: B1, B2, B3
    index.add(_entry(block_hash=_h(0x31), parent_hash=_h(0x10), height=1, work=2, tag=4))
    index.add(_entry(block_hash=_h(0x32), parent_hash=_h(0x31), height=2, work=3, tag=5))
    index.add(_entry(block_hash=_h(0x33), parent_hash=_h(0x32), height=3, work=4, tag=6))

    disconnect, connect = index.find_fork(_h(0x22), _h(0x33))
    assert [e.block_hash for e in disconnect] == [_h(0x22), _h(0x21)]
    assert [e.block_hash for e in connect] == [_h(0x31), _h(0x32), _h(0x33)]


def test_find_fork_target_on_same_chain_disconnects_to_target() -> None:
    """Moving back from tip to an ancestor is just a disconnect with no connect."""
    index = BlockIndex()
    index.add(_entry(block_hash=_h(1), parent_hash=ZERO32, height=0, work=1, tag=1))
    index.add(_entry(block_hash=_h(2), parent_hash=_h(1), height=1, work=2, tag=2))
    index.add(_entry(block_hash=_h(3), parent_hash=_h(2), height=2, work=3, tag=3))

    disconnect, connect = index.find_fork(_h(3), _h(1))
    assert [e.block_hash for e in disconnect] == [_h(3), _h(2)]
    assert connect == []


def test_json_roundtrip_preserves_state() -> None:
    index = BlockIndex()
    index.add(_entry(block_hash=_h(1), parent_hash=ZERO32, height=0, work=1, tag=1, status=STATUS_VALID))
    index.add(_entry(block_hash=_h(2), parent_hash=_h(1), height=1, work=3, tag=2, status=STATUS_VALID))
    index.set_active_tip(_h(2))

    payload = index.to_jsonable()
    restored = BlockIndex.from_jsonable(payload)

    assert len(restored) == 2
    assert _h(1) in restored
    assert _h(2) in restored
    assert restored.active_tip().block_hash == _h(2)
    assert restored.require(_h(2)).cumulative_work == 3
    assert [e.block_hash for e in restored.children_of(_h(1))] == [_h(2)]


def test_mark_have_block_flag_flips() -> None:
    index = BlockIndex()
    index.add(_entry(block_hash=_h(1), parent_hash=ZERO32, height=0, work=1, tag=1, have_block=False))
    assert index.require(_h(1)).have_block is False
    index.mark_have_block(_h(1))
    assert index.require(_h(1)).have_block is True
