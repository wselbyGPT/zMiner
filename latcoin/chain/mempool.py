from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from latcoin.codec.tx import Transaction, decode_transaction, encode_transaction, txid
from latcoin.validation.errors import ContextValidationError
from latcoin.validation.tx_context import ChainContext, UtxoEntry, validate_tx_against_utxos


@dataclass(frozen=True, slots=True)
class MempoolEntry:
    tx: Transaction
    txid_bytes: bytes
    fee: int
    size_bytes: int

    @property
    def fee_rate(self) -> float:
        if self.size_bytes == 0:
            return 0.0
        return self.fee / self.size_bytes


@dataclass(slots=True)
class Mempool:
    entries: dict[bytes, MempoolEntry] = field(default_factory=dict)
    spent_outpoints: set[tuple[bytes, int]] = field(default_factory=set)
    max_size_bytes: int = 4_000_000

    def __len__(self) -> int:
        return len(self.entries)

    def __contains__(self, txid_bytes: bytes) -> bool:
        return txid_bytes in self.entries

    def total_size_bytes(self) -> int:
        return sum(entry.size_bytes for entry in self.entries.values())

    def snapshot_spent_outpoints(self) -> set[tuple[bytes, int]]:
        return set(self.spent_outpoints)

    def add_transaction(
        self,
        tx: Transaction,
        utxo_lookup: dict[tuple[bytes, int], UtxoEntry] | dict,
        ctx: ChainContext,
        *,
        min_fee: int = 0,
    ) -> int:
        txid_bytes = txid(tx)
        if txid_bytes in self.entries:
            raise ContextValidationError(f"transaction already in mempool: {txid_bytes.hex()}")

        for idx, txin in enumerate(tx.body.inputs):
            outpoint = (txin.prev_txid, txin.prev_index)
            if outpoint in self.spent_outpoints:
                raise ContextValidationError(
                    f"transaction conflicts with mempool spend at input {idx}: "
                    f"{txin.prev_txid.hex()}:{txin.prev_index}"
                )

        fee = validate_tx_against_utxos(tx, utxo_lookup, ctx)
        if fee < min_fee:
            raise ContextValidationError(f"transaction fee {fee} is below minimum mempool fee {min_fee}")

        size_bytes = len(encode_transaction(tx))
        projected = self.total_size_bytes() + size_bytes
        if projected > self.max_size_bytes:
            raise ContextValidationError(
                f"mempool size limit exceeded: projected={projected}, limit={self.max_size_bytes}"
            )

        entry = MempoolEntry(tx=tx, txid_bytes=txid_bytes, fee=fee, size_bytes=size_bytes)
        self.entries[txid_bytes] = entry
        for txin in tx.body.inputs:
            self.spent_outpoints.add((txin.prev_txid, txin.prev_index))
        return fee

    def remove_transaction(self, txid_bytes: bytes) -> MempoolEntry | None:
        entry = self.entries.pop(txid_bytes, None)
        if entry is None:
            return None
        for txin in entry.tx.body.inputs:
            self.spent_outpoints.discard((txin.prev_txid, txin.prev_index))
        return entry

    def sorted_entries_for_block(self) -> list[MempoolEntry]:
        return sorted(
            self.entries.values(),
            key=lambda e: (-e.fee_rate, -e.fee, e.txid_bytes),
        )

    def transactions_for_block(self) -> list[Transaction]:
        return [entry.tx for entry in self.sorted_entries_for_block()]

    def to_jsonable(self) -> dict[str, object]:
        rows: list[dict[str, object]] = []
        for entry in self.sorted_entries_for_block():
            rows.append(
                {
                    "txid": entry.txid_bytes.hex(),
                    "fee": entry.fee,
                    "size_bytes": entry.size_bytes,
                    "tx_hex": encode_transaction(entry.tx).hex(),
                }
            )
        return {
            "max_size_bytes": self.max_size_bytes,
            "entries": rows,
        }

    def save_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_jsonable(), indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def from_jsonable(cls, payload: dict[str, object]) -> "Mempool":
        inst = cls(max_size_bytes=int(payload.get("max_size_bytes", 4_000_000)))
        rows = payload.get("entries", [])
        if not isinstance(rows, list):
            raise ValueError("mempool JSON payload must contain a list in 'entries'")
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("mempool entry must be an object")
            tx = decode_transaction(bytes.fromhex(str(row["tx_hex"])))
            entry = MempoolEntry(
                tx=tx,
                txid_bytes=bytes.fromhex(str(row["txid"])),
                fee=int(row["fee"]),
                size_bytes=int(row["size_bytes"]),
            )
            inst.entries[entry.txid_bytes] = entry
            for txin in tx.body.inputs:
                inst.spent_outpoints.add((txin.prev_txid, txin.prev_index))
        return inst

    @classmethod
    def load_json(cls, path: str | Path) -> "Mempool":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("mempool JSON payload must be an object")
        return cls.from_jsonable(payload)
