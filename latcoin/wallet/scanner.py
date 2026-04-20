from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from latcoin.codec.constants import LOCK_P2LPKH, LOCK_P2LSTH, LOCK_P2LVAULT, STANDARD_SPEND, VAULT_SPEND_COLD, VAULT_SPEND_HOT
from latcoin.codec.hash import hash32
from latcoin.codec.stealth import decode_stealth_lock, recover_mock_stealth_one_time_privkey
from latcoin.codec.vault import decode_vault_lock
from latcoin.validation.tx_context import UtxoEntry


@dataclass(frozen=True, slots=True)
class OwnedUtxo:
    entry: UtxoEntry
    ownership: str
    key_hash: bytes
    privkey: bytes | None
    spend_mode: int
    source_address: str | None = None


def wallet_key_hashes(wallet_payload: dict[str, Any]) -> set[str]:
    hashes: set[str] = set()
    for entry in wallet_payload.get("addresses", []):
        if not isinstance(entry, dict):
            continue
        if entry.get("type") == "standard" and entry.get("key_hash_hex"):
            hashes.add(str(entry["key_hash_hex"]))
        elif entry.get("type") == "vault":
            hot = entry.get("hot_key_hash_hex")
            cold = entry.get("cold_key_hash_hex")
            if hot:
                hashes.add(str(hot))
            if cold:
                hashes.add(str(cold))
    return hashes


def _iter_standard_entries(wallet_payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [entry for entry in wallet_payload.get("addresses", []) if isinstance(entry, dict) and entry.get("type") == "standard"]


def _iter_stealth_entries(wallet_payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [entry for entry in wallet_payload.get("addresses", []) if isinstance(entry, dict) and entry.get("type") == "stealth"]


def _iter_vault_entries(wallet_payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [entry for entry in wallet_payload.get("addresses", []) if isinstance(entry, dict) and entry.get("type") == "vault"]


def scan_wallet_owned_utxos(wallet_payload: dict[str, Any], utxo_entries: Iterable[UtxoEntry]) -> list[OwnedUtxo]:
    standard_by_hash: dict[str, dict[str, Any]] = {}
    for entry in _iter_standard_entries(wallet_payload):
        if entry.get("key_hash_hex"):
            standard_by_hash[str(entry["key_hash_hex"])] = entry

    vault_by_hot_hash: dict[str, dict[str, Any]] = {}
    vault_by_cold_hash: dict[str, dict[str, Any]] = {}
    for entry in _iter_vault_entries(wallet_payload):
        if entry.get("hot_key_hash_hex"):
            vault_by_hot_hash[str(entry["hot_key_hash_hex"])] = entry
        if entry.get("cold_key_hash_hex"):
            vault_by_cold_hash[str(entry["cold_key_hash_hex"])] = entry

    stealth_entries = _iter_stealth_entries(wallet_payload)

    matches: list[OwnedUtxo] = []
    for utxo in utxo_entries:
        if utxo.lock_type == LOCK_P2LPKH:
            key_hash_hex = utxo.lock_data.hex()
            entry = standard_by_hash.get(key_hash_hex)
            if entry is not None:
                matches.append(
                    OwnedUtxo(
                        entry=utxo,
                        ownership="standard",
                        key_hash=utxo.lock_data,
                        privkey=bytes.fromhex(str(entry["privkey_hex"])),
                        spend_mode=STANDARD_SPEND,
                        source_address=entry.get("address"),
                    )
                )

        elif utxo.lock_type == LOCK_P2LSTH:
            lock = decode_stealth_lock(utxo.lock_data)
            for entry in stealth_entries:
                scan_secret_hex = entry.get("scan_secret_hex")
                if not scan_secret_hex:
                    continue
                candidate_privkey = recover_mock_stealth_one_time_privkey(lock, bytes.fromhex(str(scan_secret_hex)))
                if candidate_privkey is None:
                    continue
                matches.append(
                    OwnedUtxo(
                        entry=utxo,
                        ownership="stealth",
                        key_hash=hash32(candidate_privkey),
                        privkey=candidate_privkey,
                        spend_mode=STANDARD_SPEND,
                        source_address=entry.get("address"),
                    )
                )
                break

        elif utxo.lock_type == LOCK_P2LVAULT:
            lock = decode_vault_lock(utxo.lock_data)
            hot = vault_by_hot_hash.get(lock.hot_key_hash.hex())
            if hot is not None and hot.get("hot_privkey_hex"):
                matches.append(
                    OwnedUtxo(
                        entry=utxo,
                        ownership="vault-hot",
                        key_hash=lock.hot_key_hash,
                        privkey=bytes.fromhex(str(hot["hot_privkey_hex"])),
                        spend_mode=VAULT_SPEND_HOT,
                        source_address=hot.get("address"),
                    )
                )
            cold = vault_by_cold_hash.get(lock.cold_key_hash.hex())
            if cold is not None and cold.get("cold_privkey_hex"):
                matches.append(
                    OwnedUtxo(
                        entry=utxo,
                        ownership="vault-cold",
                        key_hash=lock.cold_key_hash,
                        privkey=bytes.fromhex(str(cold["cold_privkey_hex"])),
                        spend_mode=VAULT_SPEND_COLD,
                        source_address=cold.get("address"),
                    )
                )

    matches.sort(key=lambda row: (row.entry.created_height, row.entry.txid, row.entry.index, row.ownership))
    return matches


def scan_wallet_utxos(wallet_payload: dict[str, Any], utxo_entries: Iterable[UtxoEntry]) -> list[UtxoEntry]:
    return [row.entry for row in scan_wallet_owned_utxos(wallet_payload, utxo_entries)]
