from __future__ import annotations

from latcoin.codec.hash import hash32
from latcoin.validation.merkle import merkle_root_from_hashes


def _leaves(n: int) -> list[bytes]:
    return [hash32(bytes([i])) for i in range(n)]


def test_empty_root_is_hash_of_empty() -> None:
    assert merkle_root_from_hashes([]) == hash32(b"")


def test_single_leaf_root_is_leaf() -> None:
    (leaf,) = _leaves(1)
    assert merkle_root_from_hashes([leaf]) == leaf


def test_two_leaves_concatenated() -> None:
    a, b = _leaves(2)
    assert merkle_root_from_hashes([a, b]) == hash32(a + b)


def test_odd_leaf_count_duplicates_last() -> None:
    a, b, c = _leaves(3)
    # layer 1: pad c to (c, c), hash pairs
    left = hash32(a + b)
    right = hash32(c + c)
    assert merkle_root_from_hashes([a, b, c]) == hash32(left + right)


def test_root_is_deterministic() -> None:
    leaves = _leaves(5)
    assert merkle_root_from_hashes(leaves) == merkle_root_from_hashes(leaves)


def test_root_changes_with_leaf_order() -> None:
    a, b = _leaves(2)
    assert merkle_root_from_hashes([a, b]) != merkle_root_from_hashes([b, a])
