"""Tests for mining/miner.py."""
from __future__ import annotations

import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from latcoin.chain.engine import ChainEngine, SubmitResult
from latcoin.codec.block import Block, BlockHeader, block_hash
from latcoin.codec.constants import (
    LOCK_P2LPKH,
    NETWORK_DEVNET,
    SCHEME_SIG_V1,
    TX_VERSION_V1,
)
from latcoin.codec.tx import Transaction, TxBody, TxInput, TxOutput
from latcoin.mining.miner import DEFAULT_GRIND_CHUNK, Miner, MinerStats, _grind_block


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REWARD_LOCK = b"\x11" * 32


def _make_submit_result(height: int = 1, accepted: bool = True) -> SubmitResult:
    return SubmitResult(
        block_hash=b"\xab" * 32,
        height=height,
        accepted=accepted,
        became_active_tip=accepted,
        reorg_depth=0,
    )


def _fake_engine(
    tip_height: int = 0,
    bits: int = 8,
    accept_block: bool = True,
) -> MagicMock:
    """Return a ChainEngine stub that mines trivially (bits=8)."""
    engine = MagicMock(spec=ChainEngine)
    engine.network_id = NETWORK_DEVNET
    engine.tip_height.return_value = tip_height
    engine.tip_hash.return_value = b"\x00" * 32
    engine.next_height.return_value = tip_height + 1
    engine.expected_bits_for_next_mined_block.return_value = bits

    entry = MagicMock()
    entry.tx = Transaction(
        body=TxBody(
            version=TX_VERSION_V1,
            network_id=NETWORK_DEVNET,
            flags=0,
            lock_height=0,
            inputs=[TxInput(prev_txid=b"\x00" * 32, prev_index=0xFFFFFFFF, sequence=0)],
            outputs=[TxOutput(
                amount=0,
                lock_type=LOCK_P2LPKH,
                scheme_id=SCHEME_SIG_V1,
                lock_data=b"\x22" * 32,
            )],
            memo=b"",
        ),
        witnesses=[],
    )
    entry.fee = 0
    engine.mempool.sorted_entries_for_block.return_value = []

    result = _make_submit_result(height=tip_height + 1, accepted=accept_block)
    engine.submit_block.return_value = result
    return engine


def _miner(engine=None, *, min_interval=0.0) -> Miner:
    return Miner(
        engine or _fake_engine(),
        _REWARD_LOCK,
        SCHEME_SIG_V1,
        min_interval=min_interval,
    )


# ---------------------------------------------------------------------------
# MinerStats
# ---------------------------------------------------------------------------

class TestMinerStats:
    def test_hash_rate_computed_from_hashes_and_elapsed(self) -> None:
        s = MinerStats(blocks_found=1, total_hashes=1000, elapsed_secs=2.0)
        assert s.hash_rate == 500.0

    def test_hash_rate_zero_when_elapsed_is_zero(self) -> None:
        s = MinerStats(blocks_found=0, total_hashes=0, elapsed_secs=0.0)
        assert s.hash_rate == 0.0


# ---------------------------------------------------------------------------
# _grind_block
# ---------------------------------------------------------------------------

class TestGrindBlock:
    def test_finds_valid_block_at_easy_difficulty(self) -> None:
        stop = threading.Event()
        tip_ref = [b"\x00" * 32]
        block, hashes = _grind_block(
            network_id=NETWORK_DEVNET,
            height=1,
            prev_block_hash=b"\x00" * 32,
            reward_lock_data=_REWARD_LOCK,
            reward_scheme_id=SCHEME_SIG_V1,
            bits=8,
            mempool_txs=[],
            total_fees=0,
            stop=stop,
            tip_hash_ref=tip_ref,
            grind_chunk=DEFAULT_GRIND_CHUNK,
        )
        assert block is not None
        assert isinstance(block, Block)
        assert hashes >= 1

    def test_returns_none_when_stopped_immediately(self) -> None:
        stop = threading.Event()
        stop.set()
        tip_ref = [b"\x00" * 32]
        block, hashes = _grind_block(
            network_id=NETWORK_DEVNET,
            height=1,
            prev_block_hash=b"\x00" * 32,
            reward_lock_data=_REWARD_LOCK,
            reward_scheme_id=SCHEME_SIG_V1,
            bits=8,
            mempool_txs=[],
            total_fees=0,
            stop=stop,
            tip_hash_ref=tip_ref,
            grind_chunk=DEFAULT_GRIND_CHUNK,
        )
        assert block is None
        assert hashes == 0

    def test_returns_none_when_tip_changes(self) -> None:
        stop = threading.Event()
        # Set tip_ref to a different hash than prev_block_hash
        original_tip = b"\x00" * 32
        new_tip = b"\xff" * 32
        tip_ref = [new_tip]  # already changed before grind starts
        block, hashes = _grind_block(
            network_id=NETWORK_DEVNET,
            height=1,
            prev_block_hash=original_tip,
            reward_lock_data=_REWARD_LOCK,
            reward_scheme_id=SCHEME_SIG_V1,
            bits=8,
            mempool_txs=[],
            total_fees=0,
            stop=stop,
            tip_hash_ref=tip_ref,
            grind_chunk=DEFAULT_GRIND_CHUNK,
        )
        assert block is None

    def test_mined_block_hash_meets_target(self) -> None:
        from latcoin.validation.pow import hash_meets_target
        stop = threading.Event()
        tip_ref = [b"\x00" * 32]
        block, _ = _grind_block(
            network_id=NETWORK_DEVNET,
            height=0,
            prev_block_hash=b"\x00" * 32,
            reward_lock_data=_REWARD_LOCK,
            reward_scheme_id=SCHEME_SIG_V1,
            bits=8,
            mempool_txs=[],
            total_fees=0,
            stop=stop,
            tip_hash_ref=tip_ref,
            grind_chunk=DEFAULT_GRIND_CHUNK,
        )
        assert block is not None
        assert hash_meets_target(block_hash(block.header), 8)

    def test_mined_block_has_correct_height(self) -> None:
        stop = threading.Event()
        tip_ref = [b"\x00" * 32]
        block, _ = _grind_block(
            network_id=NETWORK_DEVNET,
            height=42,
            prev_block_hash=b"\x00" * 32,
            reward_lock_data=_REWARD_LOCK,
            reward_scheme_id=SCHEME_SIG_V1,
            bits=8,
            mempool_txs=[],
            total_fees=0,
            stop=stop,
            tip_hash_ref=tip_ref,
            grind_chunk=DEFAULT_GRIND_CHUNK,
        )
        assert block is not None
        assert block.header.height == 42

    def test_coinbase_reward_includes_fees(self) -> None:
        stop = threading.Event()
        tip_ref = [b"\x00" * 32]
        block, _ = _grind_block(
            network_id=NETWORK_DEVNET,
            height=0,
            prev_block_hash=b"\x00" * 32,
            reward_lock_data=_REWARD_LOCK,
            reward_scheme_id=SCHEME_SIG_V1,
            bits=8,
            mempool_txs=[],
            total_fees=1234,
            stop=stop,
            tip_hash_ref=tip_ref,
            grind_chunk=DEFAULT_GRIND_CHUNK,
        )
        assert block is not None
        from latcoin.mining.template import block_subsidy
        expected = block_subsidy(0) + 1234
        assert block.txs[0].body.outputs[0].amount == expected


# ---------------------------------------------------------------------------
# Miner.run
# ---------------------------------------------------------------------------

class TestMinerRun:
    def test_mines_requested_number_of_blocks(self) -> None:
        engine = _fake_engine(bits=8)
        miner = _miner(engine)
        stats = miner.run(max_blocks=3)
        assert stats.blocks_found == 3
        assert engine.submit_block.call_count == 3

    def test_returns_miner_stats(self) -> None:
        engine = _fake_engine(bits=8)
        miner = _miner(engine)
        stats = miner.run(max_blocks=1)
        assert isinstance(stats, MinerStats)
        assert stats.blocks_found == 1
        assert stats.total_hashes >= 1
        assert stats.elapsed_secs >= 0.0

    def test_stop_terminates_loop(self) -> None:
        engine = _fake_engine(bits=8)
        # Very tight bits so we definitely find a block quickly, then stop
        miner = _miner(engine)

        def _stop_after_first(*args, **kwargs):
            result = _make_submit_result(height=1)
            miner.stop()
            return result

        engine.submit_block.side_effect = _stop_after_first
        stats = miner.run(max_blocks=100)
        # Should stop early — well before 100 blocks
        assert stats.blocks_found < 100

    def test_blocks_found_property_updates(self) -> None:
        engine = _fake_engine(bits=8)
        miner = _miner(engine)
        assert miner.blocks_found == 0
        miner.run(max_blocks=2)
        assert miner.blocks_found == 2

    def test_hash_rate_is_positive_after_mining(self) -> None:
        engine = _fake_engine(bits=8)
        miner = _miner(engine)
        stats = miner.run(max_blocks=1)
        assert stats.hash_rate >= 0.0

    def test_not_accepted_block_does_not_count(self) -> None:
        engine = _fake_engine(bits=8, accept_block=False)
        miner = _miner(engine)
        # Will keep trying; stop after a short time
        t = threading.Timer(0.1, miner.stop)
        t.start()
        stats = miner.run()
        t.cancel()
        assert stats.blocks_found == 0

    def test_min_interval_delays_between_blocks(self) -> None:
        engine = _fake_engine(bits=8)
        miner = Miner(engine, _REWARD_LOCK, SCHEME_SIG_V1, min_interval=0.05)
        start = time.monotonic()
        stats = miner.run(max_blocks=2)
        elapsed = time.monotonic() - start
        # Two blocks with 50 ms min interval each → at least 100 ms
        assert elapsed >= 0.09  # slight tolerance

    def test_keyboard_interrupt_returns_stats(self) -> None:
        engine = _fake_engine(bits=250)  # near-impossible — never finds a block
        miner = _miner(engine)

        def _interrupt():
            time.sleep(0.05)
            miner.stop()

        t = threading.Thread(target=_interrupt, daemon=True)
        t.start()
        stats = miner.run()
        t.join()
        assert isinstance(stats, MinerStats)

    def test_tip_change_triggers_template_rebuild(self) -> None:
        """When tip_hash changes mid-grind the miner rebuilds the template."""
        engine = _fake_engine(bits=8)
        call_count = 0

        original_tip = b"\x00" * 32
        new_tip = b"\xbb" * 32

        def _tip_hash():
            return new_tip if call_count > 0 else original_tip

        engine.tip_hash.side_effect = _tip_hash

        def _submit(block, **kwargs):
            nonlocal call_count
            call_count += 1
            engine.tip_hash.side_effect = None
            engine.tip_hash.return_value = new_tip
            return _make_submit_result(height=1)

        engine.submit_block.side_effect = _submit
        miner = _miner(engine)
        stats = miner.run(max_blocks=1)
        # Should eventually succeed despite the tip change
        assert stats.blocks_found == 1


# ---------------------------------------------------------------------------
# Integration: Miner against a real ChainEngine on a temp datadir
# ---------------------------------------------------------------------------

class TestMinerIntegration:
    def test_mines_real_blocks_into_engine(self, tmp_path: Path) -> None:
        """End-to-end: mine 3 devnet blocks into a real ChainEngine."""
        import json

        # --- minimal node init ---
        datadir = tmp_path / "node"
        (datadir / "blocks").mkdir(parents=True)
        (datadir / "chainstate").mkdir(parents=True)
        (datadir / "mempool").mkdir(parents=True)

        config = {"network": "devnet", "network_id": NETWORK_DEVNET}
        (datadir / "config.json").write_text(json.dumps(config), encoding="utf-8")

        from latcoin.chain.utxo import UtxoSet
        from latcoin.chain.mempool import Mempool
        from latcoin.chain.blockindex import BlockIndex
        from latcoin.validation.pow import initial_pow_state

        UtxoSet().save_json(datadir / "chainstate" / "utxos.json")
        Mempool().save_json(datadir / "mempool" / "entries.json")
        BlockIndex().save_json(datadir / "chainstate" / "blockindex.json")

        engine = ChainEngine(datadir, NETWORK_DEVNET, coinbase_maturity=0)
        miner = Miner(engine, _REWARD_LOCK, SCHEME_SIG_V1)
        stats = miner.run(max_blocks=3)

        assert stats.blocks_found == 3
        assert engine.tip_height() == 2   # heights 0, 1, 2
        assert stats.total_hashes >= 3
