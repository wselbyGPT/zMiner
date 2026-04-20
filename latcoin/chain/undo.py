from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from latcoin.validation.pow import PowState
from latcoin.validation.tx_context import UtxoEntry


@dataclass(slots=True)
class UndoRecord:
    """Per-block data needed to disconnect a block from the active chain.

    Stored once per valid/active block under ``chainstate/undo/``. When a
    reorg needs to rewind ``block_hash``, we:

    1. Remove UTXOs created by the block (``created_outpoints``).
    2. Re-add UTXOs that the block spent (``spent_entries``).
    3. Restore the chain's PoW state to ``prior_pow_state``.
    """

    block_hash: bytes
    height: int
    spent_entries: list[UtxoEntry]
    created_outpoints: list[tuple[bytes, int]]
    prior_pow_state: PowState

    def to_jsonable(self) -> dict:
        return {
            "block_hash": self.block_hash.hex(),
            "height": self.height,
            "spent_entries": [
                {
                    "txid": e.txid.hex(),
                    "index": e.index,
                    "amount": e.amount,
                    "lock_type": e.lock_type,
                    "scheme_id": e.scheme_id,
                    "lock_data": e.lock_data.hex(),
                    "created_height": e.created_height,
                    "is_coinbase": e.is_coinbase,
                    "network_id": e.network_id,
                }
                for e in self.spent_entries
            ],
            "created_outpoints": [
                {"txid": txid.hex(), "index": index} for txid, index in self.created_outpoints
            ],
            "prior_pow_state": {
                "current_bits": self.prior_pow_state.current_bits,
                "last_retarget_height": self.prior_pow_state.last_retarget_height,
                "last_retarget_timestamp": self.prior_pow_state.last_retarget_timestamp,
                "tip_timestamp": self.prior_pow_state.tip_timestamp,
            },
        }

    @classmethod
    def from_jsonable(cls, payload: dict) -> "UndoRecord":
        spent = [
            UtxoEntry(
                txid=bytes.fromhex(str(row["txid"])),
                index=int(row["index"]),
                amount=int(row["amount"]),
                lock_type=int(row["lock_type"]),
                scheme_id=int(row["scheme_id"]),
                lock_data=bytes.fromhex(str(row["lock_data"])),
                created_height=int(row["created_height"]),
                is_coinbase=bool(row["is_coinbase"]),
                network_id=(None if row.get("network_id") is None else int(row["network_id"])),
            )
            for row in payload.get("spent_entries", [])
        ]
        created = [
            (bytes.fromhex(str(row["txid"])), int(row["index"]))
            for row in payload.get("created_outpoints", [])
        ]
        pow_row = payload["prior_pow_state"]
        prior = PowState(
            current_bits=int(pow_row["current_bits"]),
            last_retarget_height=int(pow_row["last_retarget_height"]),
            last_retarget_timestamp=int(pow_row["last_retarget_timestamp"]),
            tip_timestamp=int(pow_row["tip_timestamp"]),
        )
        return cls(
            block_hash=bytes.fromhex(str(payload["block_hash"])),
            height=int(payload["height"]),
            spent_entries=spent,
            created_outpoints=created,
            prior_pow_state=prior,
        )


class UndoStore:
    """On-disk store for per-block undo records."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, height: int, block_hash: bytes) -> Path:
        return self._root / f"{height:08d}-{block_hash.hex()}.json"

    def save(self, record: UndoRecord) -> Path:
        path = self._path_for(record.height, record.block_hash)
        path.write_text(json.dumps(record.to_jsonable(), indent=2, sort_keys=True), encoding="utf-8")
        return path

    def load(self, height: int, block_hash: bytes) -> UndoRecord:
        path = self._path_for(height, block_hash)
        if not path.exists():
            raise FileNotFoundError(f"undo record not found: {path}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        return UndoRecord.from_jsonable(payload)

    def exists(self, height: int, block_hash: bytes) -> bool:
        return self._path_for(height, block_hash).exists()

    def remove(self, height: int, block_hash: bytes) -> None:
        path = self._path_for(height, block_hash)
        if path.exists():
            path.unlink()
