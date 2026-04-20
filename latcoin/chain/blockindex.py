from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from latcoin.codec.block import BlockHeader
from latcoin.validation.pow import PowState

ZERO32 = b"\x00" * 32

STATUS_HEADER_ONLY = "header_only"
STATUS_VALID = "valid"
STATUS_ACTIVE = "active"
STATUS_FAILED = "failed"
_ALL_STATUSES = {STATUS_HEADER_ONLY, STATUS_VALID, STATUS_ACTIVE, STATUS_FAILED}


@dataclass(slots=True)
class BlockIndexEntry:
    block_hash: bytes
    header: BlockHeader
    height: int
    parent_hash: bytes
    cumulative_work: int
    pow_state: PowState
    status: str = STATUS_HEADER_ONLY
    have_block: bool = False

    def __post_init__(self) -> None:
        if self.status not in _ALL_STATUSES:
            raise ValueError(f"invalid status: {self.status}")
        if len(self.block_hash) != 32:
            raise ValueError("block_hash must be 32 bytes")
        if len(self.parent_hash) != 32:
            raise ValueError("parent_hash must be 32 bytes")


class BlockIndex:
    def __init__(self) -> None:
        self._entries: dict[bytes, BlockIndexEntry] = {}
        self._children: dict[bytes, list[bytes]] = {}
        self._active_tip_hash: bytes | None = None

    def __contains__(self, block_hash: bytes) -> bool:
        return block_hash in self._entries

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[BlockIndexEntry]:
        return iter(self._entries.values())

    def get(self, block_hash: bytes) -> BlockIndexEntry | None:
        return self._entries.get(block_hash)

    def require(self, block_hash: bytes) -> BlockIndexEntry:
        entry = self._entries.get(block_hash)
        if entry is None:
            raise KeyError(f"block_hash not in index: {block_hash.hex()}")
        return entry

    def add(self, entry: BlockIndexEntry) -> BlockIndexEntry:
        if entry.block_hash in self._entries:
            raise ValueError(f"block already indexed: {entry.block_hash.hex()}")
        self._entries[entry.block_hash] = entry
        self._children.setdefault(entry.parent_hash, []).append(entry.block_hash)
        return entry

    def update_status(self, block_hash: bytes, status: str) -> None:
        if status not in _ALL_STATUSES:
            raise ValueError(f"invalid status: {status}")
        entry = self.require(block_hash)
        entry.status = status

    def mark_have_block(self, block_hash: bytes) -> None:
        entry = self.require(block_hash)
        entry.have_block = True

    def set_active_tip(self, block_hash: bytes | None) -> None:
        if block_hash is not None and block_hash not in self._entries:
            raise KeyError(f"cannot set active tip to unknown hash: {block_hash.hex()}")
        if self._active_tip_hash is not None:
            prev = self._entries.get(self._active_tip_hash)
            if prev is not None and prev.status == STATUS_ACTIVE:
                prev.status = STATUS_VALID
        self._active_tip_hash = block_hash
        if block_hash is not None:
            self._entries[block_hash].status = STATUS_ACTIVE

    def active_tip(self) -> BlockIndexEntry | None:
        if self._active_tip_hash is None:
            return None
        return self._entries.get(self._active_tip_hash)

    def children_of(self, block_hash: bytes) -> list[BlockIndexEntry]:
        return [self._entries[h] for h in self._children.get(block_hash, [])]

    def best_candidate(self) -> BlockIndexEntry | None:
        """Return the entry with max cumulative_work that is not marked failed.

        Ties broken by lower block_hash for determinism.
        """
        best: BlockIndexEntry | None = None
        for entry in self._entries.values():
            if entry.status == STATUS_FAILED:
                continue
            if best is None:
                best = entry
                continue
            if entry.cumulative_work > best.cumulative_work:
                best = entry
            elif entry.cumulative_work == best.cumulative_work and entry.block_hash < best.block_hash:
                best = entry
        return best

    def path_to_root(self, block_hash: bytes) -> list[BlockIndexEntry]:
        """Return ``[entry, parent, ..., first_known_ancestor]``."""
        out: list[BlockIndexEntry] = []
        current = self._entries.get(block_hash)
        while current is not None:
            out.append(current)
            if current.parent_hash == ZERO32:
                break
            current = self._entries.get(current.parent_hash)
        return out

    def find_fork(self, from_hash: bytes, to_hash: bytes) -> tuple[list[BlockIndexEntry], list[BlockIndexEntry]]:
        """Return ``(disconnect, connect)`` to move active tip from ``from_hash`` to ``to_hash``.

        ``disconnect`` is ordered tip-first (blocks to rewind, in reverse).
        ``connect`` is ordered from fork-child to ``to_hash`` (blocks to apply).
        """
        from_path = {e.block_hash: e for e in self.path_to_root(from_hash)}
        to_branch: list[BlockIndexEntry] = []
        current = self._entries.get(to_hash)
        while current is not None and current.block_hash not in from_path:
            to_branch.append(current)
            if current.parent_hash == ZERO32:
                break
            current = self._entries.get(current.parent_hash)
        if current is None:
            raise ValueError(f"no shared ancestor between {from_hash.hex()} and {to_hash.hex()}")
        fork_hash = current.block_hash
        disconnect: list[BlockIndexEntry] = []
        for e in self.path_to_root(from_hash):
            if e.block_hash == fork_hash:
                break
            disconnect.append(e)
        connect = list(reversed(to_branch))
        return disconnect, connect

    def all_entries(self) -> list[BlockIndexEntry]:
        return list(self._entries.values())

    def to_jsonable(self) -> dict:
        rows = []
        for entry in sorted(self._entries.values(), key=lambda e: (e.height, e.block_hash)):
            rows.append(
                {
                    "block_hash": entry.block_hash.hex(),
                    "parent_hash": entry.parent_hash.hex(),
                    "height": entry.height,
                    "cumulative_work": str(entry.cumulative_work),
                    "status": entry.status,
                    "have_block": entry.have_block,
                    "header": {
                        "version": entry.header.version,
                        "prev_block_hash": entry.header.prev_block_hash.hex(),
                        "merkle_root": entry.header.merkle_root.hex(),
                        "timestamp": entry.header.timestamp,
                        "height": entry.header.height,
                        "bits": entry.header.bits,
                        "nonce": entry.header.nonce,
                    },
                    "pow_state": {
                        "current_bits": entry.pow_state.current_bits,
                        "last_retarget_height": entry.pow_state.last_retarget_height,
                        "last_retarget_timestamp": entry.pow_state.last_retarget_timestamp,
                        "tip_timestamp": entry.pow_state.tip_timestamp,
                    },
                }
            )
        return {
            "entries": rows,
            "active_tip_hash": None if self._active_tip_hash is None else self._active_tip_hash.hex(),
        }

    def save_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_jsonable(), indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def from_jsonable(cls, payload: dict) -> "BlockIndex":
        inst = cls()
        rows = payload.get("entries", [])
        for row in rows:
            header_row = row["header"]
            header = BlockHeader(
                version=int(header_row["version"]),
                prev_block_hash=bytes.fromhex(str(header_row["prev_block_hash"])),
                merkle_root=bytes.fromhex(str(header_row["merkle_root"])),
                timestamp=int(header_row["timestamp"]),
                height=int(header_row["height"]),
                bits=int(header_row["bits"]),
                nonce=int(header_row["nonce"]),
            )
            pow_row = row["pow_state"]
            pow_state = PowState(
                current_bits=int(pow_row["current_bits"]),
                last_retarget_height=int(pow_row["last_retarget_height"]),
                last_retarget_timestamp=int(pow_row["last_retarget_timestamp"]),
                tip_timestamp=int(pow_row["tip_timestamp"]),
            )
            entry = BlockIndexEntry(
                block_hash=bytes.fromhex(str(row["block_hash"])),
                header=header,
                height=int(row["height"]),
                parent_hash=bytes.fromhex(str(row["parent_hash"])),
                cumulative_work=int(row["cumulative_work"]),
                pow_state=pow_state,
                status=str(row.get("status", STATUS_VALID)),
                have_block=bool(row.get("have_block", True)),
            )
            inst.add(entry)
        tip_hash = payload.get("active_tip_hash")
        if tip_hash is not None:
            inst._active_tip_hash = bytes.fromhex(str(tip_hash))
        return inst

    @classmethod
    def load_json(cls, path: str | Path) -> "BlockIndex":
        path = Path(path)
        if not path.exists():
            return cls()
        payload = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_jsonable(payload)
