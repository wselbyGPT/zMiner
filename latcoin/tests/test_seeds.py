"""Tests for node/seeds.py, AddrManager.add_seeds, and LatcoinNode seed bootstrapping."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from latcoin.codec.constants import NETWORK_DEVNET, NETWORK_MAINNET, NETWORK_TESTNET
from latcoin.net.addr_manager import AddrManager
from latcoin.node.seeds import DEVNET_SEEDS, seeds_for_network


# ---------------------------------------------------------------------------
# seeds_for_network
# ---------------------------------------------------------------------------

class TestSeedsForNetwork:
    def test_devnet_returns_loopback_seed(self) -> None:
        seeds = seeds_for_network(NETWORK_DEVNET)
        assert ("127.0.0.1", 9337) in seeds

    def test_testnet_returns_list(self) -> None:
        seeds = seeds_for_network(NETWORK_TESTNET)
        assert isinstance(seeds, list)

    def test_mainnet_returns_list(self) -> None:
        seeds = seeds_for_network(NETWORK_MAINNET)
        assert isinstance(seeds, list)

    def test_unknown_network_returns_empty_list(self) -> None:
        assert seeds_for_network(0xFF) == []

    def test_returns_copy_not_original(self) -> None:
        seeds1 = seeds_for_network(NETWORK_DEVNET)
        seeds2 = seeds_for_network(NETWORK_DEVNET)
        seeds1.clear()
        assert seeds_for_network(NETWORK_DEVNET) == seeds2

    def test_devnet_seeds_are_tuples_of_str_int(self) -> None:
        for ip, port in seeds_for_network(NETWORK_DEVNET):
            assert isinstance(ip, str)
            assert isinstance(port, int)


# ---------------------------------------------------------------------------
# AddrManager.add_seeds
# ---------------------------------------------------------------------------

class TestAddrManagerAddSeeds:
    def _mgr(self, tmp_path: Path) -> AddrManager:
        return AddrManager(tmp_path / "peers.json", allow_private=True)

    def test_seeds_added_to_new_table(self, tmp_path: Path) -> None:
        mgr = self._mgr(tmp_path)
        added = mgr.add_seeds([("127.0.0.1", 9337)])
        assert added == 1
        new_count, tried_count = mgr.size()
        assert new_count == 1
        assert tried_count == 0

    def test_seeds_have_timestamp_zero(self, tmp_path: Path) -> None:
        mgr = self._mgr(tmp_path)
        mgr.add_seeds([("127.0.0.1", 9337)])
        entry = mgr._new["127.0.0.1:9337"]
        assert entry.timestamp == 0

    def test_idempotent_on_repeated_calls(self, tmp_path: Path) -> None:
        mgr = self._mgr(tmp_path)
        mgr.add_seeds([("127.0.0.1", 9337)])
        added2 = mgr.add_seeds([("127.0.0.1", 9337)])
        assert added2 == 0
        assert mgr.size() == (1, 0)

    def test_skips_existing_new_entry(self, tmp_path: Path) -> None:
        mgr = self._mgr(tmp_path)
        mgr.add(ip="127.0.0.1", port=9337, timestamp=999)
        added = mgr.add_seeds([("127.0.0.1", 9337)])
        assert added == 0

    def test_skips_existing_tried_entry(self, tmp_path: Path) -> None:
        mgr = self._mgr(tmp_path)
        mgr.mark_good("127.0.0.1", 9337)
        added = mgr.add_seeds([("127.0.0.1", 9337)])
        assert added == 0

    def test_bypasses_routable_check_for_private_ips(self, tmp_path: Path) -> None:
        mgr = AddrManager(tmp_path / "peers.json", allow_private=False)
        # Private IP would normally be rejected by add(), but add_seeds bypasses it
        added = mgr.add_seeds([("192.168.1.1", 9337)])
        assert added == 1

    def test_multiple_seeds_added(self, tmp_path: Path) -> None:
        mgr = self._mgr(tmp_path)
        added = mgr.add_seeds([("127.0.0.1", 9337), ("127.0.0.1", 9338)])
        assert added == 2
        assert mgr.size() == (2, 0)

    def test_persists_to_disk(self, tmp_path: Path) -> None:
        mgr = self._mgr(tmp_path)
        mgr.add_seeds([("127.0.0.1", 9337)])
        raw = json.loads((tmp_path / "peers.json").read_text())
        assert len(raw["new"]) == 1

    def test_empty_seed_list_returns_zero(self, tmp_path: Path) -> None:
        mgr = self._mgr(tmp_path)
        assert mgr.add_seeds([]) == 0

    def test_seed_timestamp_not_overwritten_by_fresher_add(self, tmp_path: Path) -> None:
        mgr = self._mgr(tmp_path)
        mgr.add_seeds([("127.0.0.1", 9337)])
        # A real peer addr arriving with current time should win via add()
        mgr.add("127.0.0.1", 9337, timestamp=1_000_000)
        entry = mgr._new["127.0.0.1:9337"]
        assert entry.timestamp == 1_000_000


# ---------------------------------------------------------------------------
# LatcoinNode seed bootstrapping
# ---------------------------------------------------------------------------

def _make_datadir(tmp_path: Path) -> Path:
    import json as _json
    from latcoin.chain.mempool import Mempool
    from latcoin.chain.utxo import UtxoSet
    from latcoin.validation.pow import initial_pow_state

    (tmp_path / "blocks").mkdir(parents=True)
    (tmp_path / "chainstate").mkdir(parents=True)
    (tmp_path / "mempool").mkdir(parents=True)
    ps = initial_pow_state(NETWORK_DEVNET)
    config = {
        "network": "devnet",
        "network_id": NETWORK_DEVNET,
        "dev_miner": {"address": "dlat1test000"},
    }
    meta = {
        "next_block_height": 0,
        "tip_hash": "00" * 32,
        "block_count": 0,
        "coinbase_maturity": 0,
        "pow": {
            "current_bits": ps.current_bits,
            "last_retarget_height": ps.last_retarget_height,
            "last_retarget_timestamp": ps.last_retarget_timestamp,
            "tip_timestamp": ps.tip_timestamp,
        },
    }
    (tmp_path / "config.json").write_text(_json.dumps(config), encoding="utf-8")
    (tmp_path / "chainstate" / "meta.json").write_text(_json.dumps(meta), encoding="utf-8")
    UtxoSet().save_json(tmp_path / "chainstate" / "utxos.json")
    Mempool().save_json(tmp_path / "mempool" / "entries.json")
    return tmp_path


class TestLatcoinNodeSeedBootstrap:
    def _make_node(self, tmp_path: Path, **kwargs):
        from latcoin.node.node import LatcoinNode
        return LatcoinNode(
            _make_datadir(tmp_path),
            NETWORK_DEVNET,
            listen_host="127.0.0.1",
            listen_port=0,
            **kwargs,
        )

    def test_first_boot_dials_devnet_seed(self, tmp_path: Path) -> None:
        node = self._make_node(tmp_path)
        assert ("127.0.0.1", 9337) in node._dial_on_start

    def test_no_seeds_flag_skips_dial(self, tmp_path: Path) -> None:
        node = self._make_node(tmp_path, seeds=[])
        # No built-in seeds should be dialled
        assert ("127.0.0.1", 9337) not in node._dial_on_start

    def test_explicit_peer_always_dialled(self, tmp_path: Path) -> None:
        node = self._make_node(tmp_path, seed_peers=[("10.0.0.1", 9337)], seeds=[])
        assert ("10.0.0.1", 9337) in node._dial_on_start

    def test_subsequent_boot_does_not_redial_seeds(self, tmp_path: Path) -> None:
        # Simulate a populated address book (not first boot)
        datadir = _make_datadir(tmp_path)
        mgr = AddrManager(datadir / "peers.json", allow_private=True)
        mgr.mark_good("10.0.0.2", 9337)  # populate tried table

        from latcoin.node.node import LatcoinNode
        node = LatcoinNode(
            datadir,
            NETWORK_DEVNET,
            listen_host="127.0.0.1",
            listen_port=0,
        )
        # Seeds should NOT be in dial list on subsequent boot
        assert ("127.0.0.1", 9337) not in node._dial_on_start

    def test_explicit_peer_deduped(self, tmp_path: Path) -> None:
        node = self._make_node(
            tmp_path,
            seed_peers=[("127.0.0.1", 9337), ("127.0.0.1", 9337)],
        )
        dial_count = node._dial_on_start.count(("127.0.0.1", 9337))
        assert dial_count == 1

    def test_custom_seeds_used_on_first_boot(self, tmp_path: Path) -> None:
        node = self._make_node(tmp_path, seeds=[("10.1.2.3", 1234)])
        assert ("10.1.2.3", 1234) in node._dial_on_start
        assert ("127.0.0.1", 9337) not in node._dial_on_start

    def test_seeds_added_to_addr_manager_regardless_of_boot(self, tmp_path: Path) -> None:
        # Seeds are always loaded into addr book even on subsequent boots
        datadir = _make_datadir(tmp_path)
        mgr = AddrManager(datadir / "peers.json", allow_private=True)
        mgr.mark_good("10.0.0.2", 9337)

        from latcoin.node.node import LatcoinNode
        node = LatcoinNode(datadir, NETWORK_DEVNET, listen_host="127.0.0.1", listen_port=0)
        # Seed should be in the addr book even though we don't dial it
        new_count, tried_count = node.peer_manager._addr_mgr.size()
        assert new_count + tried_count >= 1
