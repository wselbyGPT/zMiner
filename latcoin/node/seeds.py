"""Hardcoded bootstrap seed peers, keyed by network_id.

Seeds are only used when a node's address book (peers.json) is empty —
i.e., on first boot or after the file is deleted.  Once the node has
connected to at least one peer and persisted its address book, the
maintenance loop in PeerManager uses that book for reconnection instead.

Adding a seed here does not permanently hard-code that peer into the
network; it is just an initial contact point.  For devnet a local
loopback address is enough to connect two nodes on the same machine
without any manual --peer flags.
"""
from __future__ import annotations

from latcoin.codec.constants import NETWORK_DEVNET, NETWORK_MAINNET, NETWORK_TESTNET

# fmt: off
DEVNET_SEEDS: list[tuple[str, int]] = [
    ("127.0.0.1", 9337),
]

TESTNET_SEEDS: list[tuple[str, int]] = [
    # fill in when public testnet nodes are available
]

MAINNET_SEEDS: list[tuple[str, int]] = [
    # fill in when mainnet launches
]
# fmt: on

_SEEDS: dict[int, list[tuple[str, int]]] = {
    NETWORK_DEVNET: DEVNET_SEEDS,
    NETWORK_TESTNET: TESTNET_SEEDS,
    NETWORK_MAINNET: MAINNET_SEEDS,
}


def seeds_for_network(network_id: int) -> list[tuple[str, int]]:
    """Return a copy of the seed list for *network_id* (empty list if unknown)."""
    return list(_SEEDS.get(network_id, []))
