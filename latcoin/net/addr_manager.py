"""AddrManager — persistent peer address book for P2P discovery.

Addresses live in two tables:
  new    — received from peers; not yet verified by a live connection
  tried  — addresses we have successfully completed a handshake with

Eviction policy:
  When a table is full the entry with the most failed connection attempts
  and the oldest last-seen timestamp is dropped.

On-disk format: JSON at the path supplied at construction time (peers.json).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import random
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from latcoin.net.messages import NetAddr, net_ip_to_str

log = logging.getLogger(__name__)

MAX_NEW: int = 1000
MAX_TRIED: int = 300
# Only relay addresses seen within this window
_STALE_SECS: int = 3 * 3600
MAX_RELAY: int = 1000


@dataclass
class AddrEntry:
    ip: str
    port: int
    timestamp: int        # unix seconds; last seen / announced
    attempts: int = 0     # consecutive failed outbound attempts
    last_attempt: int = 0 # unix seconds
    last_success: int = 0 # unix seconds


def _is_routable(ip: str) -> bool:
    """Return True for globally-routable unicast addresses only."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_multicast
    )


class AddrManager:
    """Thread-safe (GIL-protected) peer address book."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        allow_private: bool = False,
    ) -> None:
        self._path = path
        self._allow_private = allow_private
        # keyed by "ip:port"
        self._new: dict[str, AddrEntry] = {}
        self._tried: dict[str, AddrEntry] = {}
        if path is not None and path.exists():
            self._load()

    # ------------------------------------------------------------------ public

    def add(self, ip: str, port: int, timestamp: int) -> bool:
        """Add or freshen one address.  Returns True if it was newly inserted."""
        if not self._allow_private and not _is_routable(ip):
            return False
        key = self._key(ip, port)
        # Already in tried — just freshen the timestamp
        if key in self._tried:
            e = self._tried[key]
            if timestamp > e.timestamp:
                self._tried[key] = replace(e, timestamp=timestamp)
            return False
        # Already in new — freshen timestamp
        if key in self._new:
            e = self._new[key]
            if timestamp > e.timestamp:
                self._new[key] = replace(e, timestamp=timestamp)
            return False
        # New entry
        if len(self._new) >= MAX_NEW:
            self._evict_new()
        self._new[key] = AddrEntry(ip=ip, port=port, timestamp=timestamp)
        return True

    def add_many(self, addrs: list[NetAddr]) -> int:
        """Absorb addresses from a wire addr message.  Returns inserted count."""
        added = 0
        for a in addrs:
            if a.port == 0 or a.port > 65535:
                continue
            ip = net_ip_to_str(a.ip)
            if self.add(ip, a.port, a.timestamp):
                added += 1
        if added:
            self.save()
        return added

    def mark_attempted(self, ip: str, port: int) -> None:
        """Record a failed outbound connection attempt."""
        key = self._key(ip, port)
        now = int(time.time())
        for table in (self._tried, self._new):
            if key in table:
                e = table[key]
                table[key] = replace(e, attempts=e.attempts + 1, last_attempt=now)
                self.save()
                return

    def mark_good(self, ip: str, port: int) -> None:
        """Record a successful handshake; promotes new → tried, resets attempts."""
        key = self._key(ip, port)
        now = int(time.time())
        entry = self._new.pop(key, None)
        if entry is None:
            entry = self._tried.get(key)
        if entry is None:
            entry = AddrEntry(ip=ip, port=port, timestamp=now)
        entry = replace(entry, timestamp=now, attempts=0, last_success=now)
        if len(self._tried) >= MAX_TRIED and key not in self._tried:
            self._evict_tried()
        self._tried[key] = entry
        self.save()

    def select_for_connection(
        self, *, exclude: set[str] | None = None
    ) -> AddrEntry | None:
        """Pick one address to dial.

        Prefers tried addresses (verified at least once).  Within each pool
        favours entries with fewer failed attempts and a more recent last
        success.  Picks randomly from the top half so the same address isn't
        always chosen first.
        """
        exclude = exclude or set()
        tried = [e for k, e in self._tried.items() if k not in exclude]
        new = [e for k, e in self._new.items() if k not in exclude]

        # 75% bias toward tried when both tables have candidates
        if tried and (not new or random.random() < 0.75):
            pool = tried
        elif new:
            pool = new
        else:
            return None

        pool.sort(key=lambda e: (e.attempts, -e.last_success))
        top = pool[: max(1, len(pool) // 2)]
        return random.choice(top)

    def add_seeds(self, seeds: list[tuple[str, int]]) -> int:
        """Add trusted bootstrap addresses, bypassing the routable-IP check.

        Safe to call on every startup — entries already present in either
        table are left untouched.  Seeds are inserted with ``timestamp=0``
        so any address received from a real peer (which carries the current
        wall-clock time) will always win the freshness comparison.

        Returns the number of entries that were newly inserted.
        """
        added = 0
        for ip, port in seeds:
            key = self._key(ip, port)
            if key in self._tried or key in self._new:
                continue
            if len(self._new) >= MAX_NEW:
                self._evict_new()
            self._new[key] = AddrEntry(ip=ip, port=port, timestamp=0)
            added += 1
        if added:
            self.save()
        return added

    def get_addrs_for_relay(self, max_count: int = MAX_RELAY) -> list[AddrEntry]:
        """Return recently-seen addresses suitable for an addr message."""
        cutoff = int(time.time()) - _STALE_SECS
        fresh = [
            e
            for e in list(self._tried.values()) + list(self._new.values())
            if e.timestamp >= cutoff
        ]
        if len(fresh) > max_count:
            fresh = random.sample(fresh, max_count)
        return fresh

    def size(self) -> tuple[int, int]:
        """Return (new_count, tried_count)."""
        return len(self._new), len(self._tried)

    # ------------------------------------------------------------------ persistence

    def save(self) -> None:
        if self._path is None:
            return
        try:
            payload = {
                "new": [asdict(e) for e in self._new.values()],
                "tried": [asdict(e) for e in self._tried.values()],
            }
            self._path.write_text(
                json.dumps(payload, indent=2), encoding="utf-8"
            )
        except OSError as exc:
            log.warning("could not save peers.json: %s", exc)

    # ------------------------------------------------------------------ internals

    def _load(self) -> None:
        assert self._path is not None
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            for d in raw.get("new", []):
                e = AddrEntry(**d)
                self._new[self._key(e.ip, e.port)] = e
            for d in raw.get("tried", []):
                e = AddrEntry(**d)
                self._tried[self._key(e.ip, e.port)] = e
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            log.warning("could not load peers.json: %s", exc)

    def _key(self, ip: str, port: int) -> str:
        return f"{ip}:{port}"

    def _evict_new(self) -> None:
        if not self._new:
            return
        worst = max(
            self._new,
            key=lambda k: (self._new[k].attempts, -self._new[k].timestamp),
        )
        del self._new[worst]

    def _evict_tried(self) -> None:
        if not self._tried:
            return
        worst = max(
            self._tried,
            key=lambda k: (self._tried[k].attempts, -self._tried[k].last_success),
        )
        del self._tried[worst]
