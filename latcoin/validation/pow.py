from __future__ import annotations

from dataclasses import dataclass

from latcoin.codec.constants import (
    POW_GENESIS_BITS,
    POW_MAX_BITS,
    POW_MIN_BITS,
    POW_RETARGET_INTERVAL_BLOCKS,
    POW_TARGET_BLOCK_TIME_SECS,
)


def target_from_bits(bits: int) -> int:
    if bits < POW_MIN_BITS or bits > POW_MAX_BITS:
        raise ValueError(f"bits out of range: {bits}")
    return 1 << (256 - bits)


def hash_meets_target(block_hash: bytes, bits: int) -> bool:
    if len(block_hash) != 32:
        raise ValueError("block hash must be 32 bytes")
    return int.from_bytes(block_hash, "big") < target_from_bits(bits)


def compute_next_bits(current_bits: int, actual_secs: int, expected_secs: int) -> int:
    """Return the required bits for the next window.

    Bitcoin-style bucketed retarget (no floating point). Adjustment is clamped
    so difficulty can't change faster than 4x per retarget.
    """
    if expected_secs <= 0:
        return current_bits
    actual = max(1, int(actual_secs))
    # actual >= 4 * expected  -> way too slow, ease by 2 bits
    # actual >= 2 * expected  -> too slow, ease by 1 bit
    # actual <= expected / 4  -> way too fast, harden by 2 bits
    # actual <= expected / 2  -> too fast, harden by 1 bit
    if actual >= 4 * expected_secs:
        delta = -2
    elif actual >= 2 * expected_secs:
        delta = -1
    elif actual * 4 <= expected_secs:
        delta = 2
    elif actual * 2 <= expected_secs:
        delta = 1
    else:
        delta = 0
    return max(POW_MIN_BITS, min(POW_MAX_BITS, current_bits + delta))


@dataclass(frozen=True, slots=True)
class PowParams:
    genesis_bits: int
    target_block_time_secs: int
    retarget_interval_blocks: int


def pow_params_for_network(network_id: int) -> PowParams:
    try:
        return PowParams(
            genesis_bits=POW_GENESIS_BITS[network_id],
            target_block_time_secs=POW_TARGET_BLOCK_TIME_SECS[network_id],
            retarget_interval_blocks=POW_RETARGET_INTERVAL_BLOCKS[network_id],
        )
    except KeyError as exc:
        raise ValueError(f"no PoW parameters defined for network_id {network_id}") from exc


@dataclass(frozen=True, slots=True)
class PowState:
    """Persistent PoW chain state.

    Anchored to the block at `last_retarget_height` whose timestamp is
    `last_retarget_timestamp`. `current_bits` is the difficulty in force
    for blocks in the window that began at that anchor. `tip_timestamp` is
    the timestamp of the current tip (used to measure elapsed time at the
    next retarget boundary).
    """
    current_bits: int
    last_retarget_height: int
    last_retarget_timestamp: int
    tip_timestamp: int


def initial_pow_state(network_id: int) -> PowState:
    params = pow_params_for_network(network_id)
    return PowState(
        current_bits=params.genesis_bits,
        last_retarget_height=0,
        last_retarget_timestamp=0,
        tip_timestamp=0,
    )


def expected_bits_for_next_block(
    state: PowState,
    next_height: int,
    params: PowParams,
) -> int:
    """Bits that the block at `next_height` must carry."""
    if next_height == 0:
        return params.genesis_bits
    if next_height % params.retarget_interval_blocks != 0:
        return state.current_bits
    if state.last_retarget_timestamp == 0 or state.tip_timestamp == 0:
        return state.current_bits
    actual = state.tip_timestamp - state.last_retarget_timestamp
    expected = params.retarget_interval_blocks * params.target_block_time_secs
    return compute_next_bits(state.current_bits, actual, expected)


def advance_pow_state(
    state: PowState,
    applied_height: int,
    applied_bits: int,
    applied_timestamp: int,
    params: PowParams,
) -> PowState:
    """Update `state` after a block at `applied_height` has been accepted."""
    at_anchor = applied_height == 0 or (applied_height % params.retarget_interval_blocks == 0)
    if at_anchor:
        return PowState(
            current_bits=applied_bits,
            last_retarget_height=applied_height,
            last_retarget_timestamp=applied_timestamp,
            tip_timestamp=applied_timestamp,
        )
    return PowState(
        current_bits=state.current_bits,
        last_retarget_height=state.last_retarget_height,
        last_retarget_timestamp=state.last_retarget_timestamp,
        tip_timestamp=applied_timestamp,
    )
