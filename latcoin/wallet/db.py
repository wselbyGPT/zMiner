from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class WalletDB:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "WalletDB":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _init_schema(self) -> None:
        with self.conn:
            self.conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS wallet_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS wallet_addresses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT UNIQUE,
                    record_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS wallet_history (
                    txid TEXT PRIMARY KEY,
                    record_json TEXT NOT NULL
                );
                """
            )

    @classmethod
    def create_from_payload(cls, path: str | Path, payload: dict[str, Any]) -> None:
        with cls(path) as db:
            db.save_payload(payload)

    @classmethod
    def exists(cls, path: str | Path) -> bool:
        return Path(path).exists()

    def load_payload(self) -> dict[str, Any]:
        meta = {row["key"]: json.loads(row["value"]) for row in self.conn.execute("SELECT key, value FROM wallet_meta")}
        if not meta:
            raise FileNotFoundError(f"wallet db is empty: {self.path}")
        addresses = [json.loads(row["record_json"]) for row in self.conn.execute("SELECT record_json FROM wallet_addresses ORDER BY id")]
        history = [json.loads(row["record_json"]) for row in self.conn.execute("SELECT record_json FROM wallet_history ORDER BY txid")]
        payload = {
            "name": meta.get("name"),
            "created_at": meta.get("created_at"),
            "network": meta.get("network"),
            "seed_hex": meta.get("seed_hex"),
            "seed_id": meta.get("seed_id"),
            "notes": meta.get("notes", ""),
            "addresses": addresses,
            "history": history,
        }
        for key, value in meta.items():
            if key not in payload:
                payload[key] = value
        return payload

    def save_payload(self, payload: dict[str, Any]) -> None:
        meta = {
            "name": payload.get("name"),
            "created_at": payload.get("created_at"),
            "network": payload.get("network"),
            "seed_hex": payload.get("seed_hex"),
            "seed_id": payload.get("seed_id"),
            "notes": payload.get("notes", ""),
        }
        for key, value in payload.items():
            if key not in {"addresses", "history", *meta.keys()}:
                meta[key] = value

        addresses = payload.get("addresses", [])
        history = payload.get("history", [])

        with self.conn:
            self.conn.execute("DELETE FROM wallet_meta")
            self.conn.execute("DELETE FROM wallet_addresses")
            self.conn.execute("DELETE FROM wallet_history")
            self.conn.executemany(
                "INSERT INTO wallet_meta(key, value) VALUES (?, ?)",
                [(key, json.dumps(value, sort_keys=True)) for key, value in meta.items()],
            )
            self.conn.executemany(
                "INSERT INTO wallet_addresses(address, record_json) VALUES (?, ?)",
                [
                    (str(entry.get("address", f"row-{idx}")), json.dumps(entry, sort_keys=True))
                    for idx, entry in enumerate(addresses)
                ],
            )
            self.conn.executemany(
                "INSERT INTO wallet_history(txid, record_json) VALUES (?, ?)",
                [
                    (str(entry.get("txid", f"row-{idx}")), json.dumps(entry, sort_keys=True))
                    for idx, entry in enumerate(history)
                ],
            )

    @staticmethod
    def list_wallet_names(wallet_dir: str | Path) -> list[str]:
        wallet_dir = Path(wallet_dir)
        names = {path.stem for path in wallet_dir.glob("*.sqlite")}
        names.update(path.stem for path in wallet_dir.glob("*.json"))
        return sorted(names)
