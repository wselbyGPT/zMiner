from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping

from latcoin.codec.tx import Transaction, txid
from latcoin.validation.errors import ContextValidationError
from latcoin.validation.tx_context import ChainContext, UtxoEntry, validate_tx_against_utxos


@dataclass(slots=True)
class UtxoSet:
    entries: dict[tuple[bytes, int], UtxoEntry]

    def __init__(self) -> None:
        self.entries = {}

    def __contains__(self, outpoint: tuple[bytes, int]) -> bool:
        return outpoint in self.entries

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, outpoint: tuple[bytes, int]) -> UtxoEntry | None:
        return self.entries.get(outpoint)

    def snapshot(self) -> dict[tuple[bytes, int], UtxoEntry]:
        return dict(self.entries)

    def add_entry(self, entry: UtxoEntry) -> None:
        outpoint = (entry.txid, entry.index)
        self.entries[outpoint] = entry

    def spend_outpoint(self, outpoint: tuple[bytes, int]) -> UtxoEntry:
        try:
            return self.entries.pop(outpoint)
        except KeyError as exc:
            raise ContextValidationError(
                f"cannot spend missing outpoint {outpoint[0].hex()}:{outpoint[1]}"
            ) from exc

    def add_transaction_outputs(
        self,
        tx: Transaction,
        *,
        created_height: int,
        is_coinbase: bool = False,
    ) -> list[UtxoEntry]:
        new_txid = txid(tx)
        created: list[UtxoEntry] = []
        for index, txout in enumerate(tx.body.outputs):
            entry = UtxoEntry(
                txid=new_txid,
                index=index,
                amount=txout.amount,
                lock_type=txout.lock_type,
                scheme_id=txout.scheme_id,
                lock_data=txout.lock_data,
                created_height=created_height,
                is_coinbase=is_coinbase,
                network_id=tx.body.network_id,
            )
            self.add_entry(entry)
            created.append(entry)
        return created

    def apply_transaction(
        self,
        tx: Transaction,
        *,
        ctx: ChainContext,
        is_coinbase: bool = False,
    ) -> int:
        """Validate then apply a transaction to the in-memory UTXO set.

        Returns the transaction fee. Coinbase transactions skip normal input
        validation and simply materialize outputs.
        """
        if is_coinbase:
            self.add_transaction_outputs(tx, created_height=ctx.current_height, is_coinbase=True)
            return 0

        fee = validate_tx_against_utxos(tx, self.entries, ctx)
        for txin in tx.body.inputs:
            self.spend_outpoint((txin.prev_txid, txin.prev_index))
        self.add_transaction_outputs(tx, created_height=ctx.current_height, is_coinbase=False)
        return fee

    def to_jsonable(self) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for entry in self.entries.values():
            row = asdict(entry)
            row["txid"] = entry.txid.hex()
            row["lock_data"] = entry.lock_data.hex()
            rows.append(row)
        rows.sort(key=lambda r: (r["txid"], r["index"]))
        return rows

    def save_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_jsonable(), indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def from_jsonable(cls, payload: list[dict[str, object]]) -> "UtxoSet":
        inst = cls()
        for row in payload:
            entry = UtxoEntry(
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
            inst.add_entry(entry)
        return inst

    @classmethod
    def load_json(cls, path: str | Path) -> "UtxoSet":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("UTXO JSON payload must be a list")
        return cls.from_jsonable(payload)
