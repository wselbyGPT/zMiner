"""Block template builder + PoW grind loop.

Standalone usage::

    miner = Miner(engine, reward_lock_data, reward_scheme_id)
    stats = miner.run(max_blocks=100)          # blocks; returns MinerStats

The Miner owns no I/O beyond the ChainEngine it receives.  Signal handling
and output formatting belong to the CLI layer (cli/main.py).

Design
------
* The nonce search happens in chunks of ``grind_chunk`` attempts so the stop
  flag and tip-change detection can run between chunks without sacrificing
  throughput.
* When the chain tip moves while grinding (another block arrived), the
  current template is discarded and a new one is built immediately.
* ``min_interval`` inserts an artificial delay after each found block so that
  devnet operators can control block production rate without changing PoW
  difficulty.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

from latcoin.chain.engine import ChainEngine
from latcoin.codec.block import Block, BlockHeader, block_hash
from latcoin.mining.template import (
    BLOCK_VERSION_V1,
    block_subsidy,
    create_coinbase_tx,
)
from latcoin.validation.merkle import merkle_root_for_txs
from latcoin.validation.pow import hash_meets_target

log = logging.getLogger(__name__)

# How many nonces to try before checking the stop flag / tip change.
# At ~500 kH/s in CPython this is ~100 ms per chunk — responsive enough.
DEFAULT_GRIND_CHUNK: int = 50_000


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass
class MinerStats:
    blocks_found: int
    total_hashes: int
    elapsed_secs: float

    @property
    def hash_rate(self) -> float:
        """Average hashes per second over the full run."""
        return self.total_hashes / self.elapsed_secs if self.elapsed_secs > 0 else 0.0


# ---------------------------------------------------------------------------
# Inner grind helper  (pure function — no side effects)
# ---------------------------------------------------------------------------

def _grind_block(
    *,
    network_id: int,
    height: int,
    prev_block_hash: bytes,
    reward_lock_data: bytes,
    reward_scheme_id: int,
    bits: int,
    mempool_txs: list,
    total_fees: int,
    stop: threading.Event,
    tip_hash_ref: list[bytes],   # single-element list; checked for tip changes
    grind_chunk: int,
) -> tuple[Block | None, int]:
    """Grind nonces until a valid hash is found, or until stopped / tip moves.

    Returns ``(block, hashes_tried)``.  ``block`` is ``None`` when the search
    was interrupted before a valid nonce was found.
    """
    subsidy = block_subsidy(height)
    coinbase = create_coinbase_tx(
        network_id=network_id,
        height=height,
        reward_lock_data=reward_lock_data,
        reward_amount=subsidy + total_fees,
        scheme_id=reward_scheme_id,
    )
    txs = [coinbase, *mempool_txs]
    merkle = merkle_root_for_txs(txs)
    ts = int(time.time())

    nonce = 0
    total = 0
    while not stop.is_set():
        # Check for a new tip (stale template) before each chunk
        if tip_hash_ref[0] != prev_block_hash:
            return None, total

        for i in range(grind_chunk):
            candidate = BlockHeader(
                version=BLOCK_VERSION_V1,
                prev_block_hash=prev_block_hash,
                merkle_root=merkle,
                timestamp=ts,
                height=height,
                bits=bits,
                nonce=(nonce + i) & 0xFFFFFFFFFFFFFFFF,
            )
            bh = block_hash(candidate)
            if hash_meets_target(bh, bits):
                return Block(header=candidate, txs=txs), total + i + 1

        total += grind_chunk
        nonce += grind_chunk
        # Refresh the timestamp each chunk so it advances with wall time
        ts = int(time.time())

    return None, total


# ---------------------------------------------------------------------------
# Miner
# ---------------------------------------------------------------------------

class Miner:
    """Single-threaded PoW miner that drives a ChainEngine directly.

    The ``run()`` method blocks until ``max_blocks`` blocks have been found,
    ``stop()`` is called from another thread, or a ``KeyboardInterrupt`` is
    raised.  It always returns a ``MinerStats`` summary.
    """

    def __init__(
        self,
        engine: ChainEngine,
        reward_lock_data: bytes,
        reward_scheme_id: int,
        *,
        grind_chunk: int = DEFAULT_GRIND_CHUNK,
        min_interval: float = 0.0,
    ) -> None:
        self._engine = engine
        self._reward_lock_data = reward_lock_data
        self._reward_scheme_id = reward_scheme_id
        self._grind_chunk = grind_chunk
        self._min_interval = max(0.0, min_interval)
        self._stop = threading.Event()
        self._blocks_found: int = 0

    @property
    def blocks_found(self) -> int:
        return self._blocks_found

    def stop(self) -> None:
        """Signal the mining loop to exit after the current chunk finishes."""
        self._stop.set()

    def run(
        self,
        *,
        max_blocks: int | None = None,
        stats_interval: float = 30.0,
    ) -> MinerStats:
        """Mine blocks until stopped.  Returns aggregated stats."""
        self._stop.clear()
        start = time.monotonic()
        total_hashes = 0
        blocks_found = 0
        last_stats = start

        # Mutable reference so _grind_block can detect tip changes
        tip_ref: list[bytes] = [self._engine.tip_hash()]

        try:
            while not self._stop.is_set():
                if max_blocks is not None and blocks_found >= max_blocks:
                    break

                block_start = time.monotonic()
                bits = self._engine.expected_bits_for_next_mined_block()
                height = self._engine.next_height()
                prev_hash = self._engine.tip_hash()
                tip_ref[0] = prev_hash

                entries = self._engine.mempool.sorted_entries_for_block()
                mempool_txs = [e.tx for e in entries]
                total_fees = sum(e.fee for e in entries)

                log.debug(
                    "building template: height=%d bits=%d mempool=%d",
                    height, bits, len(mempool_txs),
                )

                block, hashes = _grind_block(
                    network_id=self._engine.network_id,
                    height=height,
                    prev_block_hash=prev_hash,
                    reward_lock_data=self._reward_lock_data,
                    reward_scheme_id=self._reward_scheme_id,
                    bits=bits,
                    mempool_txs=mempool_txs,
                    total_fees=total_fees,
                    stop=self._stop,
                    tip_hash_ref=tip_ref,
                    grind_chunk=self._grind_chunk,
                )
                total_hashes += hashes

                if block is None:
                    # Stopped or tip changed — rebuild template next iteration
                    continue

                result = self._engine.submit_block(block)
                if result.accepted:
                    blocks_found += 1
                    self._blocks_found = blocks_found
                    elapsed_block = time.monotonic() - block_start
                    log.info(
                        "block %d accepted: hash=%.16s nonce=%d hashes=%d (%.1f ms)",
                        result.height,
                        result.block_hash.hex(),
                        block.header.nonce,
                        hashes,
                        elapsed_block * 1000,
                    )
                    tip_ref[0] = result.block_hash
                    if self._min_interval > 0.0 and elapsed_block < self._min_interval:
                        remaining = self._min_interval - elapsed_block
                        self._stop.wait(remaining)
                else:
                    log.debug("block at height=%d not accepted, rebuilding", height)

                # Periodic stats log
                now = time.monotonic()
                if now - last_stats >= stats_interval:
                    elapsed = now - start
                    rate = total_hashes / elapsed if elapsed > 0 else 0.0
                    log.info(
                        "miner stats: %.0f H/s  blocks=%d  hashes=%d",
                        rate, blocks_found, total_hashes,
                    )
                    last_stats = now

        except KeyboardInterrupt:
            pass

        elapsed = time.monotonic() - start
        return MinerStats(
            blocks_found=blocks_found,
            total_hashes=total_hashes,
            elapsed_secs=elapsed,
        )
