from __future__ import annotations

import pytest

from latcoin.codec.constants import NETWORK_DEVNET, NETWORK_MAINNET, NETWORK_TESTNET
from latcoin.validation.pow import (
    PowState,
    advance_pow_state,
    compute_next_bits,
    expected_bits_for_next_block,
    hash_meets_target,
    initial_pow_state,
    pow_params_for_network,
    target_from_bits,
)


def test_target_from_bits_doubles_per_bit_decrement() -> None:
    for bits in (1, 8, 64, 128, 240):
        assert target_from_bits(bits) == 1 << (256 - bits)
    assert target_from_bits(8) == target_from_bits(9) * 2


@pytest.mark.parametrize("bits", [0, -1, 251, 10_000])
def test_target_from_bits_rejects_out_of_range(bits: int) -> None:
    with pytest.raises(ValueError):
        target_from_bits(bits)


def test_hash_meets_target_leading_zero_bits() -> None:
    zero_hash = b"\x00" * 32
    assert hash_meets_target(zero_hash, bits=240)
    almost_max = b"\x7f" + b"\xff" * 31  # int < 2**255
    assert hash_meets_target(almost_max, bits=1)
    full = b"\xff" * 32
    assert not hash_meets_target(full, bits=1)


def test_hash_meets_target_rejects_wrong_length() -> None:
    with pytest.raises(ValueError):
        hash_meets_target(b"\x00" * 31, bits=8)


def test_compute_next_bits_no_change_within_window() -> None:
    # exact target time -> no adjustment
    assert compute_next_bits(current_bits=16, actual_secs=100, expected_secs=100) == 16
    # within the 0.5x..2x no-change band
    assert compute_next_bits(current_bits=16, actual_secs=120, expected_secs=100) == 16
    assert compute_next_bits(current_bits=16, actual_secs=70, expected_secs=100) == 16


def test_compute_next_bits_eases_when_too_slow() -> None:
    # 2x too slow -> ease by 1 bit
    assert compute_next_bits(current_bits=16, actual_secs=200, expected_secs=100) == 15
    # 4x too slow -> ease by 2 bits
    assert compute_next_bits(current_bits=16, actual_secs=400, expected_secs=100) == 14


def test_compute_next_bits_hardens_when_too_fast() -> None:
    # 2x too fast
    assert compute_next_bits(current_bits=16, actual_secs=50, expected_secs=100) == 17
    # 4x too fast
    assert compute_next_bits(current_bits=16, actual_secs=25, expected_secs=100) == 18


def test_compute_next_bits_clamps_to_range() -> None:
    # cannot drop below POW_MIN_BITS (1)
    assert compute_next_bits(current_bits=1, actual_secs=1_000_000, expected_secs=1) == 1
    # cannot rise above POW_MAX_BITS (250)
    assert compute_next_bits(current_bits=250, actual_secs=1, expected_secs=1_000_000) == 250


def test_compute_next_bits_handles_zero_actual() -> None:
    # actual==0 is clamped to 1; still treated as "very fast"
    result = compute_next_bits(current_bits=16, actual_secs=0, expected_secs=100)
    assert result >= 16


@pytest.mark.parametrize("network_id", [NETWORK_MAINNET, NETWORK_TESTNET, NETWORK_DEVNET])
def test_pow_params_defined_for_all_networks(network_id: int) -> None:
    params = pow_params_for_network(network_id)
    assert params.genesis_bits >= 1
    assert params.target_block_time_secs >= 1
    assert params.retarget_interval_blocks >= 1


def test_pow_params_rejects_unknown_network() -> None:
    with pytest.raises(ValueError):
        pow_params_for_network(0xAB)


def test_expected_bits_uses_genesis_for_block_zero() -> None:
    params = pow_params_for_network(NETWORK_DEVNET)
    state = initial_pow_state(NETWORK_DEVNET)
    assert expected_bits_for_next_block(state, next_height=0, params=params) == params.genesis_bits


def test_expected_bits_unchanged_within_window() -> None:
    params = pow_params_for_network(NETWORK_DEVNET)
    state = PowState(
        current_bits=12,
        last_retarget_height=0,
        last_retarget_timestamp=1_000_000,
        tip_timestamp=1_000_010,
    )
    # Any height not on a boundary -> same bits
    for h in (1, 2, params.retarget_interval_blocks - 1):
        assert expected_bits_for_next_block(state, next_height=h, params=params) == 12


def test_expected_bits_retargets_on_boundary() -> None:
    params = pow_params_for_network(NETWORK_DEVNET)
    # Chain ran 4x too slow over the last window -> ease by 2 bits
    interval = params.retarget_interval_blocks
    expected_window = interval * params.target_block_time_secs
    state = PowState(
        current_bits=16,
        last_retarget_height=0,
        last_retarget_timestamp=1_000_000,
        tip_timestamp=1_000_000 + 4 * expected_window,
    )
    assert expected_bits_for_next_block(state, next_height=interval, params=params) == 14


def test_advance_pow_state_updates_tip_timestamp_midwindow() -> None:
    params = pow_params_for_network(NETWORK_DEVNET)
    state = PowState(current_bits=8, last_retarget_height=0, last_retarget_timestamp=100, tip_timestamp=100)
    new = advance_pow_state(state, applied_height=1, applied_bits=8, applied_timestamp=130, params=params)
    assert new.current_bits == 8
    assert new.last_retarget_height == 0
    assert new.last_retarget_timestamp == 100
    assert new.tip_timestamp == 130


def test_advance_pow_state_resets_anchor_on_boundary() -> None:
    params = pow_params_for_network(NETWORK_DEVNET)
    interval = params.retarget_interval_blocks
    state = PowState(current_bits=8, last_retarget_height=0, last_retarget_timestamp=100, tip_timestamp=500)
    new = advance_pow_state(state, applied_height=interval, applied_bits=10, applied_timestamp=600, params=params)
    assert new.current_bits == 10
    assert new.last_retarget_height == interval
    assert new.last_retarget_timestamp == 600
    assert new.tip_timestamp == 600


def test_advance_pow_state_seeds_anchor_from_genesis_block() -> None:
    params = pow_params_for_network(NETWORK_DEVNET)
    state = initial_pow_state(NETWORK_DEVNET)
    new = advance_pow_state(state, applied_height=0, applied_bits=params.genesis_bits, applied_timestamp=42, params=params)
    assert new.last_retarget_height == 0
    assert new.last_retarget_timestamp == 42
    assert new.tip_timestamp == 42
