"""Tests for net.addr_manager.AddrManager."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from latcoin.net.addr_manager import (
    MAX_NEW,
    MAX_TRIED,
    AddrEntry,
    AddrManager,
    _is_routable,
)
from latcoin.net.messages import NetAddr, ipv4_to_net_ip


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mgr(path: Path | None = None, *, allow_private: bool = True) -> AddrManager:
    return AddrManager(path, allow_private=allow_private)


def _entry(ip: str = "1.2.3.4", port: int = 9337, ts: int = 1_700_000_000) -> tuple[str, int, int]:
    return ip, port, ts


def _netaddr(ip: str, port: int, ts: int = 1_700_000_000) -> NetAddr:
    return NetAddr(timestamp=ts, ip=ipv4_to_net_ip(ip), port=port)


# ---------------------------------------------------------------------------
# _is_routable
# ---------------------------------------------------------------------------

class TestIsRoutable:
    def test_public_ipv4_is_routable(self) -> None:
        assert _is_routable("8.8.8.8")
        assert _is_routable("1.1.1.1")

    def test_private_ipv4_not_routable(self) -> None:
        assert not _is_routable("10.0.0.1")
        assert not _is_routable("192.168.1.1")
        assert not _is_routable("172.16.0.1")

    def test_loopback_not_routable(self) -> None:
        assert not _is_routable("127.0.0.1")

    def test_link_local_not_routable(self) -> None:
        assert not _is_routable("169.254.0.1")

    def test_unspecified_not_routable(self) -> None:
        assert not _is_routable("0.0.0.0")

    def test_invalid_string_not_routable(self) -> None:
        assert not _is_routable("not-an-ip")
        assert not _is_routable("")


# ---------------------------------------------------------------------------
# AddrManager.add
# ---------------------------------------------------------------------------

class TestAdd:
    def test_add_new_address_returns_true(self) -> None:
        mgr = _mgr()
        assert mgr.add("1.2.3.4", 9337, 1_700_000_000) is True
        assert mgr.size() == (1, 0)

    def test_add_duplicate_returns_false(self) -> None:
        mgr = _mgr()
        mgr.add("1.2.3.4", 9337, 1_700_000_000)
        assert mgr.add("1.2.3.4", 9337, 1_700_000_001) is False

    def test_add_freshens_timestamp_in_new(self) -> None:
        mgr = _mgr()
        mgr.add("1.2.3.4", 9337, 1_000)
        mgr.add("1.2.3.4", 9337, 2_000)
        assert mgr._new["1.2.3.4:9337"].timestamp == 2_000

    def test_add_does_not_rewind_timestamp(self) -> None:
        mgr = _mgr()
        mgr.add("1.2.3.4", 9337, 2_000)
        mgr.add("1.2.3.4", 9337, 1_000)
        assert mgr._new["1.2.3.4:9337"].timestamp == 2_000

    def test_add_freshens_timestamp_in_tried(self) -> None:
        mgr = _mgr()
        mgr.mark_good("1.2.3.4", 9337)
        before = mgr._tried["1.2.3.4:9337"].timestamp
        mgr.add("1.2.3.4", 9337, before + 100)
        assert mgr._tried["1.2.3.4:9337"].timestamp == before + 100

    def test_add_ignores_private_by_default(self) -> None:
        mgr = AddrManager(allow_private=False)
        assert mgr.add("192.168.1.1", 9337, 1_700_000_000) is False
        assert mgr.size() == (0, 0)

    def test_add_allows_private_when_enabled(self) -> None:
        mgr = _mgr(allow_private=True)
        assert mgr.add("127.0.0.1", 9337, 1_700_000_000) is True

    def test_add_evicts_when_new_table_full(self) -> None:
        mgr = _mgr()
        # Fill new table to capacity
        for i in range(MAX_NEW):
            mgr.add(f"1.2.{i // 256}.{i % 256}", 9337, 1_000)
        assert len(mgr._new) == MAX_NEW
        # One more should evict the worst entry and keep size at MAX_NEW
        mgr.add("9.9.9.9", 9338, 2_000)
        assert len(mgr._new) == MAX_NEW


# ---------------------------------------------------------------------------
# AddrManager.add_many
# ---------------------------------------------------------------------------

class TestAddMany:
    def test_add_many_absorbs_wire_addrs(self) -> None:
        mgr = _mgr()
        addrs = [_netaddr("1.2.3.4", 9337), _netaddr("5.6.7.8", 9337)]
        count = mgr.add_many(addrs)
        assert count == 2
        assert mgr.size() == (2, 0)

    def test_add_many_filters_port_zero(self) -> None:
        mgr = _mgr()
        addrs = [_netaddr("1.2.3.4", 0)]
        assert mgr.add_many(addrs) == 0

    def test_add_many_filters_port_over_65535(self) -> None:
        mgr = _mgr()
        addrs = [NetAddr(timestamp=1_000, ip=ipv4_to_net_ip("1.2.3.4"), port=70000)]
        assert mgr.add_many(addrs) == 0

    def test_add_many_deduplicates(self) -> None:
        mgr = _mgr()
        addrs = [_netaddr("1.2.3.4", 9337), _netaddr("1.2.3.4", 9337)]
        assert mgr.add_many(addrs) == 1

    def test_add_many_filters_private_when_disabled(self) -> None:
        mgr = AddrManager(allow_private=False)
        addrs = [_netaddr("127.0.0.1", 9337)]
        assert mgr.add_many(addrs) == 0

    def test_add_many_returns_zero_for_empty_list(self) -> None:
        mgr = _mgr()
        assert mgr.add_many([]) == 0


# ---------------------------------------------------------------------------
# AddrManager.mark_attempted
# ---------------------------------------------------------------------------

class TestMarkAttempted:
    def test_increments_attempts_in_new(self) -> None:
        mgr = _mgr()
        mgr.add("1.2.3.4", 9337, 1_000)
        mgr.mark_attempted("1.2.3.4", 9337)
        assert mgr._new["1.2.3.4:9337"].attempts == 1

    def test_increments_attempts_in_tried(self) -> None:
        mgr = _mgr()
        mgr.mark_good("1.2.3.4", 9337)
        mgr.mark_attempted("1.2.3.4", 9337)
        assert mgr._tried["1.2.3.4:9337"].attempts == 1

    def test_sets_last_attempt_timestamp(self) -> None:
        mgr = _mgr()
        mgr.add("1.2.3.4", 9337, 1_000)
        before = int(time.time())
        mgr.mark_attempted("1.2.3.4", 9337)
        assert mgr._new["1.2.3.4:9337"].last_attempt >= before

    def test_no_crash_for_unknown_address(self) -> None:
        mgr = _mgr()
        mgr.mark_attempted("9.9.9.9", 9337)  # should not raise

    def test_multiple_attempts_accumulate(self) -> None:
        mgr = _mgr()
        mgr.add("1.2.3.4", 9337, 1_000)
        mgr.mark_attempted("1.2.3.4", 9337)
        mgr.mark_attempted("1.2.3.4", 9337)
        mgr.mark_attempted("1.2.3.4", 9337)
        assert mgr._new["1.2.3.4:9337"].attempts == 3


# ---------------------------------------------------------------------------
# AddrManager.mark_good
# ---------------------------------------------------------------------------

class TestMarkGood:
    def test_promotes_from_new_to_tried(self) -> None:
        mgr = _mgr()
        mgr.add("1.2.3.4", 9337, 1_000)
        mgr.mark_good("1.2.3.4", 9337)
        assert "1.2.3.4:9337" not in mgr._new
        assert "1.2.3.4:9337" in mgr._tried

    def test_resets_attempts_to_zero(self) -> None:
        mgr = _mgr()
        mgr.add("1.2.3.4", 9337, 1_000)
        mgr.mark_attempted("1.2.3.4", 9337)
        mgr.mark_attempted("1.2.3.4", 9337)
        mgr.mark_good("1.2.3.4", 9337)
        assert mgr._tried["1.2.3.4:9337"].attempts == 0

    def test_sets_last_success(self) -> None:
        mgr = _mgr()
        mgr.add("1.2.3.4", 9337, 1_000)
        before = int(time.time())
        mgr.mark_good("1.2.3.4", 9337)
        assert mgr._tried["1.2.3.4:9337"].last_success >= before

    def test_creates_entry_for_unknown_address(self) -> None:
        mgr = _mgr()
        mgr.mark_good("1.2.3.4", 9337)
        assert "1.2.3.4:9337" in mgr._tried

    def test_idempotent_for_existing_tried_entry(self) -> None:
        mgr = _mgr()
        mgr.mark_good("1.2.3.4", 9337)
        mgr.mark_good("1.2.3.4", 9337)
        assert mgr.size() == (0, 1)

    def test_evicts_from_tried_when_full(self) -> None:
        mgr = _mgr()
        for i in range(MAX_TRIED):
            mgr.mark_good(f"1.2.{i // 256}.{i % 256}", 9337)
        assert len(mgr._tried) == MAX_TRIED
        mgr.mark_good("9.9.9.9", 9338)
        assert len(mgr._tried) == MAX_TRIED


# ---------------------------------------------------------------------------
# AddrManager.select_for_connection
# ---------------------------------------------------------------------------

class TestSelectForConnection:
    def test_returns_none_when_empty(self) -> None:
        mgr = _mgr()
        assert mgr.select_for_connection() is None

    def test_returns_tried_entry(self) -> None:
        mgr = _mgr()
        mgr.mark_good("1.2.3.4", 9337)
        entry = mgr.select_for_connection()
        assert entry is not None
        assert entry.ip == "1.2.3.4"
        assert entry.port == 9337

    def test_returns_new_entry_when_tried_empty(self) -> None:
        mgr = _mgr()
        mgr.add("1.2.3.4", 9337, 1_000)
        entry = mgr.select_for_connection()
        assert entry is not None
        assert entry.ip == "1.2.3.4"

    def test_excludes_specified_addresses(self) -> None:
        mgr = _mgr()
        mgr.mark_good("1.2.3.4", 9337)
        assert mgr.select_for_connection(exclude={"1.2.3.4:9337"}) is None

    def test_exclude_only_removes_matching_entry(self) -> None:
        mgr = _mgr()
        mgr.mark_good("1.2.3.4", 9337)
        mgr.mark_good("5.6.7.8", 9337)
        entry = mgr.select_for_connection(exclude={"1.2.3.4:9337"})
        assert entry is not None
        assert entry.ip == "5.6.7.8"

    def test_prefers_entries_with_fewer_attempts(self) -> None:
        mgr = _mgr()
        mgr.mark_good("1.2.3.4", 9337)
        mgr.mark_good("5.6.7.8", 9337)
        # Give one address many failed attempts so it sorts last
        for _ in range(10):
            mgr.mark_attempted("1.2.3.4", 9337)
        # 5.6.7.8 should be preferred (0 attempts vs 10)
        # Run multiple times to account for random choice from top half
        results = {mgr.select_for_connection().ip for _ in range(20)}
        assert "5.6.7.8" in results


# ---------------------------------------------------------------------------
# AddrManager.get_addrs_for_relay
# ---------------------------------------------------------------------------

class TestGetAddrsForRelay:
    def test_returns_fresh_entries(self) -> None:
        mgr = _mgr()
        now = int(time.time())
        mgr.add("1.2.3.4", 9337, now)
        addrs = mgr.get_addrs_for_relay()
        assert len(addrs) == 1
        assert addrs[0].ip == "1.2.3.4"

    def test_filters_stale_entries(self) -> None:
        mgr = _mgr()
        old_ts = int(time.time()) - 4 * 3600  # 4 hours ago
        mgr.add("1.2.3.4", 9337, old_ts)
        assert mgr.get_addrs_for_relay() == []

    def test_respects_max_count(self) -> None:
        mgr = _mgr()
        now = int(time.time())
        for i in range(20):
            mgr.add(f"1.2.3.{i}", 9337, now)
        addrs = mgr.get_addrs_for_relay(max_count=5)
        assert len(addrs) == 5

    def test_includes_tried_and_new(self) -> None:
        mgr = _mgr()
        now = int(time.time())
        mgr.add("1.2.3.4", 9337, now)
        mgr.mark_good("5.6.7.8", 9337)
        addrs = mgr.get_addrs_for_relay()
        ips = {e.ip for e in addrs}
        assert "1.2.3.4" in ips
        assert "5.6.7.8" in ips

    def test_empty_manager_returns_empty_list(self) -> None:
        mgr = _mgr()
        assert mgr.get_addrs_for_relay() == []


# ---------------------------------------------------------------------------
# AddrManager.size
# ---------------------------------------------------------------------------

class TestSize:
    def test_size_reflects_tables(self) -> None:
        mgr = _mgr()
        mgr.add("1.2.3.4", 9337, 1_000)
        mgr.mark_good("5.6.7.8", 9337)
        assert mgr.size() == (1, 1)


# ---------------------------------------------------------------------------
# AddrManager save / load
# ---------------------------------------------------------------------------

class TestSaveLoad:
    def test_roundtrip_preserves_all_fields(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"
        mgr = _mgr(path)
        now = int(time.time())
        mgr.add("1.2.3.4", 9337, now)
        mgr.mark_good("5.6.7.8", 9338)
        mgr.mark_attempted("5.6.7.8", 9338)
        mgr.save()

        mgr2 = _mgr(path)
        assert "1.2.3.4:9337" in mgr2._new
        assert "5.6.7.8:9338" in mgr2._tried
        e = mgr2._tried["5.6.7.8:9338"]
        assert e.attempts == 1
        assert e.last_success > 0

    def test_save_writes_valid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"
        mgr = _mgr(path)
        mgr.add("1.2.3.4", 9337, 1_700_000_000)
        mgr.save()
        raw = json.loads(path.read_text())
        assert "new" in raw and "tried" in raw
        assert raw["new"][0]["ip"] == "1.2.3.4"

    def test_load_nonexistent_path_starts_empty(self, tmp_path: Path) -> None:
        mgr = _mgr(tmp_path / "missing.json")
        assert mgr.size() == (0, 0)

    def test_load_corrupted_file_starts_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"
        path.write_text("not-json", encoding="utf-8")
        mgr = _mgr(path)  # should not raise
        assert mgr.size() == (0, 0)

    def test_no_path_save_is_noop(self) -> None:
        mgr = _mgr(path=None)
        mgr.add("1.2.3.4", 9337, 1_000)
        mgr.save()  # should not raise

    def test_save_on_add_many(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"
        mgr = _mgr(path)
        mgr.add_many([_netaddr("1.2.3.4", 9337)])
        assert path.exists()

    def test_save_on_mark_good(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"
        mgr = _mgr(path)
        mgr.mark_good("1.2.3.4", 9337)
        assert path.exists()

    def test_save_on_mark_attempted(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"
        mgr = _mgr(path)
        mgr.add("1.2.3.4", 9337, 1_000)
        mgr.mark_attempted("1.2.3.4", 9337)
        assert path.exists()
        raw = json.loads(path.read_text())
        assert raw["new"][0]["attempts"] == 1


# ---------------------------------------------------------------------------
# Eviction ordering
# ---------------------------------------------------------------------------

class TestEviction:
    def test_evicts_entry_with_most_attempts_from_new(self) -> None:
        mgr = _mgr()
        ts = 1_700_000_000
        for i in range(MAX_NEW):
            mgr.add(f"1.2.{i // 256}.{i % 256}", 9337, ts)
        # Add many attempts to one entry so it becomes the eviction candidate
        worst_key = "1.2.0.0:9337"
        for _ in range(10):
            mgr._new[worst_key] = AddrEntry(
                ip="1.2.0.0", port=9337, timestamp=ts, attempts=mgr._new[worst_key].attempts + 1
            )
        # Add a new entry — should evict the high-attempt entry
        mgr.add("9.9.9.9", 9999, ts + 1)
        assert worst_key not in mgr._new
        assert "9.9.9.9:9999" in mgr._new

    def test_evicts_entry_with_most_attempts_from_tried(self) -> None:
        mgr = _mgr()
        for i in range(MAX_TRIED):
            mgr.mark_good(f"1.2.{i // 256}.{i % 256}", 9337)
        # Inflate attempts on one entry
        worst_key = "1.2.0.0:9337"
        for _ in range(5):
            mgr.mark_attempted("1.2.0.0", 9337)
        mgr.mark_good("9.9.9.9", 9999)
        assert worst_key not in mgr._tried
        assert "9.9.9.9:9999" in mgr._tried
