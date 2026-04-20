from __future__ import annotations

from latcoin.codec.constants import POW_MAX_BITS, POW_MIN_BITS


def work_from_bits(bits: int) -> int:
    """Work contribution of a block with the given difficulty.

    LatCoin PoW uses ``target = 1 << (256 - bits)`` (see
    ``validation.pow.target_from_bits``). Work is defined as
    ``2**256 // (target + 1)``, the standard Bitcoin-style formula, which
    ensures that harder blocks strictly contribute more work than easier
    ones and that blocks of equal difficulty contribute equal work.
    """
    if bits < POW_MIN_BITS or bits > POW_MAX_BITS:
        raise ValueError(f"bits out of range: {bits}")
    target = 1 << (256 - bits)
    return (1 << 256) // (target + 1)
