from __future__ import annotations

import pytest

from latcoin.chain.chainwork import work_from_bits


def test_work_is_strictly_monotonic_in_bits() -> None:
    prev = 0
    for bits in range(1, 32):
        w = work_from_bits(bits)
        assert w > prev
        prev = w


def test_work_doubles_per_extra_bit_for_moderate_difficulties() -> None:
    for bits in range(8, 40):
        a = work_from_bits(bits)
        b = work_from_bits(bits + 1)
        # One extra leading zero-bit roughly doubles the work.
        assert 1.8 * a <= b <= 2.2 * a


def test_work_from_bits_rejects_out_of_range() -> None:
    with pytest.raises(ValueError):
        work_from_bits(0)
    with pytest.raises(ValueError):
        work_from_bits(251)
