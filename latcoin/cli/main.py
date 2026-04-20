from __future__ import annotations

import argparse
import binascii
import json
import secrets
import sys
import time
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation, ROUND_DOWN
from hashlib import sha3_256
from pathlib import Path
from typing import Any

from latcoin.chain.engine import ChainEngine
from latcoin.chain.mempool import Mempool
from latcoin.chain.utxo import UtxoSet
from latcoin.codec.block import block_hash, encode_block
from latcoin.codec.constants import (
    LOCK_P2LPKH,
    LOCK_P2LSTH,
    LOCK_P2LVAULT,
    LATS_PER_LAT,
    NETWORK_DEVNET,
    NETWORK_MAINNET,
    NETWORK_TESTNET,
    SCHEME_LATTICE_TOY_V1,
    SCHEME_LATTICE_STRONG_V1,
    SCHEME_SIG_V1,
    VAULT_SPEND_COLD,
    VAULT_SPEND_HOT,
)
from latcoin.codec.hash import hash32
from latcoin.codec.stealth import StealthAddressPayload, create_stealth_lock_for_address, decode_stealth_address, encode_stealth_address, toy_dh_pub_from_secret
from latcoin.codec.tx import Transaction, decode_transaction, encode_transaction, txid, wtxid
from latcoin.codec.vault import VaultLockData, encode_vault_lock
from latcoin.crypto.signatures import (
    keygen,
    scheme_id_to_name,
    scheme_name_to_id,
    supported_signature_scheme_ids,
)
from latcoin.mining.miner import Miner
from latcoin.mining.template import build_block_template
from latcoin.validation.block_context import BlockChainContext, validate_block_context
from latcoin.validation.pow import (
    PowState,
    advance_pow_state,
    expected_bits_for_next_block,
    initial_pow_state,
    pow_params_for_network,
)
from latcoin.validation.tx_context import ChainContext, validate_tx_against_utxos
from latcoin.validation.tx_structure import validate_tx_structure
from latcoin.node.node import DEFAULT_P2P_PORT, LatcoinNode
from latcoin.node.rpc import run_rpc_server
from latcoin.node.rpc_client import RpcError, call_rpc
from latcoin.wallet.builder import build_p2lpkh_payment_tx, build_p2lsth_payment_tx, build_p2lvault_funding_tx
from latcoin.wallet.db import WalletDB
from latcoin.wallet.history import rebuild_wallet_history
from latcoin.wallet.scanner import OwnedUtxo, scan_wallet_owned_utxos, scan_wallet_utxos, wallet_key_hashes
from latcoin.wallet.signer import sign_supported_transaction
from latcoin.wallet.utxo_select import InsufficientFundsError, select_utxos

DEFAULT_DATADIR = Path.home() / ".latcoin"
ZERO32_HEX = "00" * 32


def _parse_rpc_params(pairs: list[str]) -> dict[str, Any]:
    """Parse ``key=value`` strings into a params dict.

    Values are JSON-decoded when possible so that ``amount=1.5`` becomes a
    float, ``flag=true`` becomes a bool, and ``name=alice`` stays a string.
    """
    params: dict[str, Any] = {}
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"invalid param {pair!r}: expected key=value")
        key, _, raw = pair.partition("=")
        if not key:
            raise SystemExit(f"invalid param {pair!r}: key must not be empty")
        try:
            params[key] = json.loads(raw)
        except json.JSONDecodeError:
            params[key] = raw
    return params


def _iso_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _network_name_to_id(name: str) -> int:
    mapping = {
        "mainnet": NETWORK_MAINNET,
        "testnet": NETWORK_TESTNET,
        "devnet": NETWORK_DEVNET,
    }
    return mapping[name]


def _supported_scheme_choices() -> tuple[str, ...]:
    return tuple(sorted(scheme_id_to_name(sid) for sid in supported_signature_scheme_ids()))


def _network_hrp(name: str) -> str:
    return {
        "mainnet": "lat",
        "testnet": "tlat",
        "devnet": "dlat",
    }[name]


def _json_default(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, default=_json_default))


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _config_path(datadir: Path) -> Path:
    return datadir / "config.json"


def _chain_meta_path(datadir: Path) -> Path:
    return datadir / "chainstate" / "meta.json"


def _utxo_path(datadir: Path) -> Path:
    return datadir / "chainstate" / "utxos.json"


def _mempool_path(datadir: Path) -> Path:
    return datadir / "mempool" / "entries.json"


def _wallets_dir(datadir: Path) -> Path:
    return datadir / "wallets"


def _wallet_path(datadir: Path, name: str) -> Path:
    return _wallets_dir(datadir) / f"{name}.sqlite"


def _wallet_legacy_json_path(datadir: Path, name: str) -> Path:
    return _wallets_dir(datadir) / f"{name}.json"


def _load_config(datadir: Path) -> dict[str, Any]:
    path = _config_path(datadir)
    if not path.exists():
        raise SystemExit(f"missing config: {path} (run `lat node init` first)")
    return json.loads(path.read_text(encoding="utf-8"))


def _save_json(path: Path, payload: dict[str, Any] | list[dict[str, Any]]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_tx_bytes(value: str) -> bytes:
    candidate = Path(value)
    if candidate.exists():
        raw = candidate.read_bytes()
        try:
            text = raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            return raw

        compact = "".join(text.split())
        try:
            return bytes.fromhex(compact)
        except ValueError:
            return raw

    compact = "".join(value.split())
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise SystemExit(f"input is neither an existing file nor valid hex: {value}") from exc


def _write_tx_hex(path: Path | None, tx: Transaction) -> None:
    payload = encode_transaction(tx).hex()
    if path is None:
        print(payload)
        return
    path.write_text(payload + "\n", encoding="utf-8")


def _parse_amount_to_lats(value: str) -> int:
    try:
        dec = Decimal(str(value))
    except InvalidOperation as exc:
        raise SystemExit(f"invalid amount: {value}") from exc
    if dec <= 0:
        raise SystemExit("amount must be greater than zero")
    lats = (dec * Decimal(LATS_PER_LAT)).quantize(Decimal("1"), rounding=ROUND_DOWN)
    return int(lats)


def _format_lats(lats: int) -> str:
    return format((Decimal(lats) / Decimal(LATS_PER_LAT)).normalize(), "f")


_STANDARD_HRP_TO_NETWORK = {
    "lat": "mainnet",
    "tlat": "testnet",
    "dlat": "devnet",
}


def _standard_address_checksum(hrp: str, scheme_id: int, key_hash: bytes) -> bytes:
    return hash32(hrp.encode("ascii") + scheme_id.to_bytes(2, "big") + key_hash)[:4]


def _make_address_from_key_hash(network: str, key_hash: bytes, scheme_id: int = SCHEME_SIG_V1) -> str:
    if len(key_hash) != 32:
        raise SystemExit(f"standard address key_hash must be 32 bytes, got {len(key_hash)}")
    hrp = _network_hrp(network)
    checksum_hex = _standard_address_checksum(hrp, scheme_id, key_hash).hex()
    return f"{hrp}1{scheme_id:04x}{key_hash.hex()}{checksum_hex}"


def _parse_standard_address(address: str, expected_network: str | None = None) -> tuple[bytes, int]:
    if ":" in address:
        raise SystemExit(f"not a standard address: {address}")
    if "1" not in address:
        raise SystemExit(f"invalid address format: {address}")
    prefix, payload = address.split("1", 1)
    network_for_prefix = _STANDARD_HRP_TO_NETWORK.get(prefix)
    if network_for_prefix is None:
        raise SystemExit(f"unknown address prefix: {prefix}")
    if expected_network is not None and network_for_prefix != expected_network:
        raise SystemExit(
            f"address network {network_for_prefix} does not match expected network {expected_network}"
        )
    if len(payload) != 4 + 64 + 8:
        raise SystemExit(
            "standard LatCoin addresses must be hrp+1+scheme(4)+key_hash(64)+checksum(8); "
            f"got payload length {len(payload)} for {address}"
        )
    try:
        scheme_id = int(payload[:4], 16)
        key_hash = bytes.fromhex(payload[4:68])
        checksum = bytes.fromhex(payload[68:76])
    except ValueError as exc:
        raise SystemExit(f"invalid address payload hex: {address}") from exc
    expected = _standard_address_checksum(prefix, scheme_id, key_hash)
    if checksum != expected:
        raise SystemExit(f"standard address checksum mismatch for {address}")
    return key_hash, scheme_id


def _make_vault_address(network: str, scheme_id: int, hot_key_hash: bytes, cold_key_hash: bytes, hot_delay_blocks: int) -> str:
    prefix = {"mainnet": "latv", "testnet": "tlatv", "devnet": "dlatv"}[network]
    payload_hex = f"{scheme_id:04x}{hot_delay_blocks:08x}{hot_key_hash.hex()}{cold_key_hash.hex()}"
    checksum = hash32(bytes.fromhex(payload_hex))[:4].hex()
    return f"{prefix}1{payload_hex}{checksum}"


def _parse_vault_address(address: str, expected_network: str | None = None) -> VaultLockData:
    if ":" in address or "1" not in address:
        raise SystemExit(f"invalid vault address format: {address}")
    prefix, payload = address.split("1", 1)
    network_for_prefix = {"latv": "mainnet", "tlatv": "testnet", "dlatv": "devnet"}.get(prefix)
    if network_for_prefix is None:
        raise SystemExit(f"unknown vault address prefix: {prefix}")
    if expected_network is not None and network_for_prefix != expected_network:
        raise SystemExit(f"vault address network {network_for_prefix} does not match expected network {expected_network}")
    if len(payload) < 4 + 8 + 64 + 64 + 8:
        raise SystemExit("vault address payload is too short")
    body_hex, checksum = payload[:-8], payload[-8:]
    try:
        if hash32(bytes.fromhex(body_hex))[:4].hex() != checksum:
            raise SystemExit("vault address checksum mismatch")
        scheme_id = int(body_hex[:4], 16)
        hot_delay_blocks = int(body_hex[4:12], 16)
        hot_key_hash = bytes.fromhex(body_hex[12:76])
        cold_key_hash = bytes.fromhex(body_hex[76:140])
    except ValueError as exc:
        raise SystemExit(f"invalid vault address payload: {address}") from exc
    return VaultLockData(
        lock_version=0x01,
        scheme_id=scheme_id,
        hot_key_hash=hot_key_hash,
        cold_key_hash=cold_key_hash,
        hot_delay_blocks=hot_delay_blocks,
        flags=0,
    )


def _recipient_lock_from_address(address: str, expected_network: str) -> tuple[str, int, bytes, int]:
    if ":" in address:
        lock_data, scheme_id = create_stealth_lock_for_address(address, expected_network=expected_network)
        return "stealth", LOCK_P2LSTH, lock_data, scheme_id
    if address.startswith(("latv1", "tlatv1", "dlatv1")):
        lock = _parse_vault_address(address, expected_network=expected_network)
        return "vault", LOCK_P2LVAULT, encode_vault_lock(lock), lock.scheme_id
    key_hash, scheme_id = _parse_standard_address(address, expected_network=expected_network)
    return "standard", LOCK_P2LPKH, key_hash, scheme_id


def _make_standard_key_entry(network: str, scheme_id: int = SCHEME_SIG_V1) -> dict[str, Any]:
    privkey, pubkey = keygen(scheme_id)
    key_hash = hash32(pubkey)
    return {
        "type": "standard",
        "scheme_id": scheme_id,
        "scheme_name": scheme_id_to_name(scheme_id),
        "created_at": _iso_now(),
        "address": _make_address_from_key_hash(network, key_hash, scheme_id),
        "privkey_hex": privkey.hex(),
        "pubkey_hex": pubkey.hex(),
        "key_hash_hex": key_hash.hex(),
    }


def _make_stealth_entry(network: str) -> dict[str, Any]:
    spend_scheme_id = SCHEME_SIG_V1
    spend_privkey, spend_pub = keygen(spend_scheme_id)
    scan_secret = secrets.token_bytes(32)
    scan_pub = toy_dh_pub_from_secret(scan_secret)
    address = encode_stealth_address(
        network,
        StealthAddressPayload(
            addr_version=0x01,
            spend_scheme_id=spend_scheme_id,
            scan_pub=scan_pub,
            spend_pub=spend_pub,
        ),
    )
    return {
        "type": "stealth",
        "created_at": _iso_now(),
        "address": address,
        "scan_secret_hex": scan_secret.hex(),
        "scan_pub_hex": scan_pub.hex(),
        "spend_scheme_id": spend_scheme_id,
        "spend_scheme_name": scheme_id_to_name(spend_scheme_id),
        "spend_privkey_hex": spend_privkey.hex(),
        "spend_pub_hex": spend_pub.hex(),
    }


def _make_vault_entry(network: str, scheme_id: int = SCHEME_SIG_V1, hot_delay_blocks: int = 144) -> dict[str, Any]:
    hot_privkey, hot_pub = keygen(scheme_id)
    cold_privkey, cold_pub = keygen(scheme_id)
    hot_key_hash = hash32(hot_pub)
    cold_key_hash = hash32(cold_pub)
    address = _make_vault_address(network, scheme_id, hot_key_hash, cold_key_hash, hot_delay_blocks)
    return {
        "type": "vault",
        "scheme_id": scheme_id,
        "scheme_name": scheme_id_to_name(scheme_id),
        "created_at": _iso_now(),
        "address": address,
        "hot_delay_blocks": hot_delay_blocks,
        "hot_privkey_hex": hot_privkey.hex(),
        "hot_pubkey_hex": hot_pub.hex(),
        "hot_key_hash_hex": hot_key_hash.hex(),
        "cold_privkey_hex": cold_privkey.hex(),
        "cold_pubkey_hex": cold_pub.hex(),
        "cold_key_hash_hex": cold_key_hash.hex(),
    }


def _wallet_template(name: str, network: str) -> dict[str, Any]:
    seed_hex = secrets.token_hex(32)
    seed_id = sha3_256(seed_hex.encode("utf-8")).hexdigest()[:16]
    return {
        "name": name,
        "created_at": _iso_now(),
        "network": network,
        "seed_hex": seed_hex,
        "seed_id": seed_id,
        "addresses": [],
        "history": [],
        "notes": "Dev wallet file. Private keys are stored in plaintext for now.",
    }


def _default_chain_meta(network: str) -> dict[str, Any]:
    coinbase_maturity = 0 if network == "devnet" else 100
    network_id = _network_name_to_id(network)
    pow_state = initial_pow_state(network_id)
    return {
        "created_at": _iso_now(),
        "next_block_height": 0,
        "tip_hash": ZERO32_HEX,
        "block_count": 0,
        "coinbase_maturity": coinbase_maturity,
        "pow": {
            "current_bits": pow_state.current_bits,
            "last_retarget_height": pow_state.last_retarget_height,
            "last_retarget_timestamp": pow_state.last_retarget_timestamp,
            "tip_timestamp": pow_state.tip_timestamp,
        },
    }


def _pow_state_from_meta(meta: dict[str, Any], network_id: int) -> PowState:
    raw = meta.get("pow")
    if not isinstance(raw, dict):
        return initial_pow_state(network_id)
    return PowState(
        current_bits=int(raw.get("current_bits", initial_pow_state(network_id).current_bits)),
        last_retarget_height=int(raw.get("last_retarget_height", 0)),
        last_retarget_timestamp=int(raw.get("last_retarget_timestamp", 0)),
        tip_timestamp=int(raw.get("tip_timestamp", 0)),
    )


def _store_pow_state(meta: dict[str, Any], state: PowState) -> None:
    meta["pow"] = {
        "current_bits": state.current_bits,
        "last_retarget_height": state.last_retarget_height,
        "last_retarget_timestamp": state.last_retarget_timestamp,
        "tip_timestamp": state.tip_timestamp,
    }


def _load_chain_meta(datadir: Path) -> dict[str, Any]:
    path = _chain_meta_path(datadir)
    if not path.exists():
        raise SystemExit(f"missing chainstate meta: {path} (run `lat node init` first)")
    return _load_json(path)


def _save_chain_meta(datadir: Path, meta: dict[str, Any]) -> None:
    _save_json(_chain_meta_path(datadir), meta)


def _load_utxos(datadir: Path) -> UtxoSet:
    path = _utxo_path(datadir)
    if not path.exists():
        return UtxoSet()
    return UtxoSet.load_json(path)


def _save_utxos(datadir: Path, utxos: UtxoSet) -> None:
    utxos.save_json(_utxo_path(datadir))


def _load_mempool(datadir: Path) -> Mempool:
    path = _mempool_path(datadir)
    if not path.exists():
        return Mempool()
    return Mempool.load_json(path)


def _save_mempool(datadir: Path, mempool: Mempool) -> None:
    mempool.save_json(_mempool_path(datadir))


def _chain_context(config: dict[str, Any], meta: dict[str, Any]) -> ChainContext:
    return ChainContext(
        network_id=int(config["network_id"]),
        current_height=int(meta["next_block_height"]),
        median_time_past=max(0, int(meta["block_count"]) - 1),
        coinbase_maturity=int(meta.get("coinbase_maturity", 100)),
    )


def _block_context(config: dict[str, Any], meta: dict[str, Any]) -> BlockChainContext:
    network_id = int(config["network_id"])
    params = pow_params_for_network(network_id)
    state = _pow_state_from_meta(meta, network_id)
    expected_bits = expected_bits_for_next_block(state, int(meta["next_block_height"]), params)
    return BlockChainContext(
        network_id=network_id,
        current_height=int(meta["next_block_height"]),
        median_time_past=max(0, int(meta["block_count"]) - 1),
        expected_prev_block_hash=bytes.fromhex(str(meta["tip_hash"])),
        coinbase_maturity=int(meta.get("coinbase_maturity", 100)),
        expected_bits=expected_bits,
    )


def _save_block_file(datadir: Path, height: int, block_bytes: bytes, block_hash_hex: str) -> Path:
    path = datadir / "blocks" / f"{height:08d}-{block_hash_hex}.bin"
    path.write_bytes(block_bytes)
    return path


def _load_wallet(datadir: Path, name: str) -> dict[str, Any]:
    path = _wallet_path(datadir, name)
    legacy_path = _wallet_legacy_json_path(datadir, name)
    if not path.exists() and legacy_path.exists():
        payload = json.loads(legacy_path.read_text(encoding="utf-8"))
        WalletDB.create_from_payload(path, payload)
    if not path.exists():
        raise SystemExit(f"wallet not found: {path}")
    with WalletDB(path) as db:
        return db.load_payload()


def _save_wallet(datadir: Path, payload: dict[str, Any]) -> None:
    path = _wallet_path(datadir, str(payload["name"]))
    with WalletDB(path) as db:
        db.save_payload(payload)


def _wallet_standard_entries(wallet_payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [entry for entry in wallet_payload.get("addresses", []) if isinstance(entry, dict) and entry.get("type") == "standard"]


def _wallet_stealth_entries(wallet_payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [entry for entry in wallet_payload.get("addresses", []) if isinstance(entry, dict) and entry.get("type") == "stealth"]


def _wallet_vault_entries(wallet_payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [entry for entry in wallet_payload.get("addresses", []) if isinstance(entry, dict) and entry.get("type") == "vault"]


def _wallet_privkeys_by_key(wallet_payload: dict[str, Any]) -> dict[tuple[int, bytes], bytes]:
    mapping: dict[tuple[int, bytes], bytes] = {}
    for entry in _wallet_standard_entries(wallet_payload):
        key_hash_hex = entry.get("key_hash_hex")
        privkey_hex = entry.get("privkey_hex")
        scheme_id = int(entry.get("scheme_id", SCHEME_SIG_V1))
        if key_hash_hex and privkey_hex:
            mapping[(scheme_id, bytes.fromhex(str(key_hash_hex)))] = bytes.fromhex(str(privkey_hex))
    return mapping


def _wallet_default_change_entry(wallet_payload: dict[str, Any]) -> dict[str, Any]:
    entries = _wallet_standard_entries(wallet_payload)
    if not entries:
        raise SystemExit("wallet has no standard addresses; run `lat wallet new-address` first")
    return entries[0]


def _wallet_primary_address(wallet_payload: dict[str, Any]) -> str:
    entries = _wallet_standard_entries(wallet_payload)
    if not entries:
        raise SystemExit("wallet has no standard addresses; run `lat wallet new-address` first")
    return str(entries[0]["address"])


def _wallet_unique_owned_rows(datadir: Path, wallet_payload: dict[str, Any]) -> list[OwnedUtxo]:
    utxos = _load_utxos(datadir)
    mempool = _load_mempool(datadir)
    rows = scan_wallet_owned_utxos(wallet_payload, utxos.entries.values())
    by_outpoint: dict[tuple[bytes, int], OwnedUtxo] = {}
    for row in rows:
        outpoint = (row.entry.txid, row.entry.index)
        if outpoint in mempool.spent_outpoints:
            continue
        by_outpoint.setdefault(outpoint, row)
    return sorted(by_outpoint.values(), key=lambda row: (row.entry.created_height, row.entry.txid, row.entry.index))


def _wallet_scan_entries(datadir: Path, wallet_payload: dict[str, Any]) -> list[Any]:
    return [row.entry for row in _wallet_unique_owned_rows(datadir, wallet_payload)]


def _wallet_spendable_rows(datadir: Path, wallet_payload: dict[str, Any], *, include_vault: bool = False) -> list[OwnedUtxo]:
    if include_vault:
        utxos = _load_utxos(datadir)
        mempool = _load_mempool(datadir)
        rows = [row for row in scan_wallet_owned_utxos(wallet_payload, utxos.entries.values()) if (row.entry.txid, row.entry.index) not in mempool.spent_outpoints]
    else:
        rows = _wallet_unique_owned_rows(datadir, wallet_payload)
    allowed = {"standard", "stealth"}
    if include_vault:
        allowed.update({"vault-hot", "vault-cold"})
    return [row for row in rows if row.ownership in allowed]


def _refresh_wallet_history(datadir: Path, wallet_payload: dict[str, Any]) -> dict[str, Any]:
    wallet_payload["history"] = rebuild_wallet_history(datadir, wallet_payload)
    _save_wallet(datadir, wallet_payload)
    return wallet_payload


def _wallet_receive_entry(
    datadir: Path,
    wallet_payload: dict[str, Any],
    *,
    create_new: bool = False,
    scheme_id: int = SCHEME_SIG_V1,
    entry_type: str = "standard",
    hot_delay_blocks: int = 144,
) -> tuple[dict[str, Any], dict[str, Any]]:
    existing: list[dict[str, Any]]
    if entry_type == "standard":
        existing = _wallet_standard_entries(wallet_payload)
        factory = lambda: _make_standard_key_entry(str(wallet_payload["network"]), scheme_id=scheme_id)
    elif entry_type == "stealth":
        existing = _wallet_stealth_entries(wallet_payload)
        factory = lambda: _make_stealth_entry(str(wallet_payload["network"]))
    elif entry_type == "vault":
        existing = _wallet_vault_entries(wallet_payload)
        factory = lambda: _make_vault_entry(str(wallet_payload["network"]), scheme_id=scheme_id, hot_delay_blocks=hot_delay_blocks)
    else:
        raise SystemExit(f"unsupported receive type: {entry_type}")

    if create_new or not existing:
        entry = factory()
        wallet_payload.setdefault("addresses", []).append(entry)
        _save_wallet(datadir, wallet_payload)
        return wallet_payload, entry
    return wallet_payload, existing[0]


def _wallet_history_rows(wallet_payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = wallet_payload.get("history", [])
    if not isinstance(rows, list):
        return []
    return rows


def _find_prevouts_for_tx(datadir: Path, tx: Transaction) -> tuple[list[Any], list[str]]:
    utxos = _load_utxos(datadir)
    prevouts = []
    missing = []
    for txin in tx.body.inputs:
        prevout = utxos.get((txin.prev_txid, txin.prev_index))
        if prevout is None:
            missing.append(f"{txin.prev_txid.hex()}:{txin.prev_index}")
        else:
            prevouts.append(prevout)
    return prevouts, missing


def _build_unsigned_payment_tx(
    *,
    datadir: Path,
    wallet_payload: dict[str, Any],
    network_id: int,
    recipient_address: str,
    amount_lats: int,
    fee_lats: int,
    lock_height: int = 0,
) -> tuple[Transaction, list[Any], int, str]:
    available_rows = _wallet_spendable_rows(datadir, wallet_payload, include_vault=False)
    available_utxos = [row.entry for row in available_rows]
    selected, _total = select_utxos(available_utxos, amount_lats + fee_lats)
    recipient_kind, _lock_type, recipient_lock_data, recipient_scheme_id = _recipient_lock_from_address(recipient_address, expected_network=str(wallet_payload["network"]))
    change_entry = _wallet_default_change_entry(wallet_payload)
    change_key_hash = bytes.fromhex(str(change_entry["key_hash_hex"]))
    change_scheme_id = int(change_entry.get("scheme_id", SCHEME_SIG_V1))
    if recipient_kind == "standard":
        tx, change_lats = build_p2lpkh_payment_tx(
            network_id=network_id,
            selected_utxos=selected,
            recipient_key_hash=recipient_lock_data,
            recipient_scheme_id=recipient_scheme_id,
            amount=amount_lats,
            fee=fee_lats,
            change_key_hash=change_key_hash,
            change_scheme_id=change_scheme_id,
            lock_height=lock_height,
        )
    elif recipient_kind == "stealth":
        tx, change_lats = build_p2lsth_payment_tx(
            network_id=network_id,
            selected_utxos=selected,
            stealth_lock_data=recipient_lock_data,
            spend_scheme_id=recipient_scheme_id,
            amount=amount_lats,
            fee=fee_lats,
            change_key_hash=change_key_hash,
            change_scheme_id=change_scheme_id,
            lock_height=lock_height,
        )
    elif recipient_kind == "vault":
        tx, change_lats = build_p2lvault_funding_tx(
            network_id=network_id,
            selected_utxos=selected,
            vault_lock_data=recipient_lock_data,
            vault_scheme_id=recipient_scheme_id,
            amount=amount_lats,
            fee=fee_lats,
            change_key_hash=change_key_hash,
            change_scheme_id=change_scheme_id,
            lock_height=lock_height,
        )
    else:
        raise SystemExit(f"unsupported recipient kind: {recipient_kind}")
    return tx, selected, change_lats, recipient_kind


def _sign_transaction_for_wallet(
    *,
    tx: Transaction,
    datadir: Path,
    wallet_payload: dict[str, Any],
    prefer_vault_mode: int | None = None,
) -> Transaction:
    utxos = _load_utxos(datadir)
    prevouts = []
    owned_rows_by_outpoint: dict[tuple[bytes, int], list[OwnedUtxo]] = {}
    for row in scan_wallet_owned_utxos(wallet_payload, utxos.entries.values()):
        owned_rows_by_outpoint.setdefault((row.entry.txid, row.entry.index), []).append(row)

    key_material_by_input: dict[int, tuple[bytes, int]] = {}
    for input_index, txin in enumerate(tx.body.inputs):
        outpoint = (txin.prev_txid, txin.prev_index)
        prevout = utxos.get(outpoint)
        if prevout is None:
            raise SystemExit(f"missing prevout in chainstate for {txin.prev_txid.hex()}:{txin.prev_index}")
        prevouts.append(prevout)
        owned_candidates = owned_rows_by_outpoint.get(outpoint, [])
        if not owned_candidates:
            raise SystemExit(f"wallet does not control prevout {txin.prev_txid.hex()}:{txin.prev_index}")
        chosen = owned_candidates[0]
        if prevout.lock_type == LOCK_P2LVAULT and prefer_vault_mode is not None:
            for candidate in owned_candidates:
                if candidate.spend_mode == prefer_vault_mode:
                    chosen = candidate
                    break
        if chosen.privkey is None:
            raise SystemExit(f"wallet has no private key for prevout {txin.prev_txid.hex()}:{txin.prev_index}")
        key_material_by_input[input_index] = (chosen.privkey, chosen.spend_mode)

    return sign_supported_transaction(tx, prevouts, key_material_by_input)


def _apply_block_result(datadir: Path, result) -> UtxoSet:
    utxos = _load_utxos(datadir)
    for outpoint in result.spent_outpoints:
        utxos.spend_outpoint(outpoint)
    for entry in result.created_utxos:
        utxos.add_entry(entry)
    _save_utxos(datadir, utxos)
    return utxos


def cmd_node_init(args: argparse.Namespace) -> int:
    datadir = args.datadir
    _ensure_dir(datadir)
    _ensure_dir(datadir / "blocks")
    _ensure_dir(datadir / "chainstate")
    _ensure_dir(datadir / "mempool")
    _ensure_dir(_wallets_dir(datadir))

    dev_miner = _make_standard_key_entry(args.network, scheme_id=scheme_name_to_id(args.miner_scheme))
    chain_meta = _default_chain_meta(args.network)
    config = {
        "created_at": _iso_now(),
        "network": args.network,
        "network_id": _network_name_to_id(args.network),
        "datadir": str(datadir),
        "dev_miner": dev_miner,
    }
    _save_json(_config_path(datadir), config)
    _save_chain_meta(datadir, chain_meta)
    _save_utxos(datadir, UtxoSet())
    _save_mempool(datadir, Mempool())
    _print_json({"ok": True, "action": "node.init", "config": config, "chain_meta": chain_meta})
    return 0


def cmd_node_start(args: argparse.Namespace) -> int:
    config = _load_config(args.datadir)
    meta = _load_chain_meta(args.datadir)
    network_id = int(config["network_id"])
    coinbase_maturity = int(meta.get("coinbase_maturity", 100))

    seed_peers: list[tuple[str, int]] = []
    for peer_str in getattr(args, "peer", []) or []:
        host, _, port_str = peer_str.rpartition(":")
        if not host or not port_str:
            raise SystemExit(f"invalid --peer value {peer_str!r} (expected host:port)")
        seed_peers.append((host, int(port_str)))

    node = LatcoinNode(
        args.datadir,
        network_id,
        listen_host=args.p2p_host,
        listen_port=args.p2p_port,
        seed_peers=seed_peers,
        seeds=[] if getattr(args, "no_seeds", False) else None,
        coinbase_maturity=coinbase_maturity,
    )
    node.start()
    _print_json(
        {
            "ok": True,
            "action": "node.start",
            "message": "Starting LatCoin node",
            "rpc": {"host": args.rpc_host, "port": args.rpc_port},
            "p2p": {"host": args.p2p_host, "port": args.p2p_port},
            "config": config,
            "chain_meta": meta,
        }
    )
    try:
        run_rpc_server(args.datadir, host=args.rpc_host, port=args.rpc_port, engine=node.engine)
    finally:
        node.stop()
    return 0


def cmd_node_status(args: argparse.Namespace) -> int:
    try:
        body = call_rpc("status", host=args.rpc_host, port=args.rpc_port)
    except RpcError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _print_json(body)
    return 0 if body.get("ok") else 1


def cmd_node_submit_tx(args: argparse.Namespace) -> int:
    config = _load_config(args.datadir)
    meta = _load_chain_meta(args.datadir)
    utxos = _load_utxos(args.datadir)
    mempool = _load_mempool(args.datadir)

    raw = _load_tx_bytes(args.tx)
    tx = decode_transaction(raw)
    fee = mempool.add_transaction(tx, utxos.entries, _chain_context(config, meta), min_fee=args.min_fee)
    _save_mempool(args.datadir, mempool)
    txid_hex = txid(tx).hex()
    _print_json(
        {
            "ok": True,
            "action": "node.submit-tx",
            "txid": txid_hex,
            "fee": fee,
            "mempool_size": len(mempool),
        }
    )
    return 0


def cmd_node_mempool(args: argparse.Namespace) -> int:
    _load_config(args.datadir)
    mempool = _load_mempool(args.datadir)
    entries = []
    for entry in mempool.sorted_entries_for_block():
        entries.append(
            {
                "txid": entry.txid_bytes.hex(),
                "fee": entry.fee,
                "size_bytes": entry.size_bytes,
                "fee_rate": entry.fee_rate,
                "input_count": len(entry.tx.body.inputs),
                "output_count": len(entry.tx.body.outputs),
            }
        )
    _print_json({"ok": True, "action": "node.mempool", "count": len(entries), "entries": entries})
    return 0


def cmd_wallet_new(args: argparse.Namespace) -> int:
    _load_config(args.datadir)
    _ensure_dir(_wallets_dir(args.datadir))

    path = _wallet_path(args.datadir, args.name)
    if path.exists():
        raise SystemExit(f"wallet already exists: {path}")

    wallet = _wallet_template(args.name, args.network)
    _save_wallet(args.datadir, wallet)
    _print_json({"ok": True, "action": "wallet.new", "wallet": wallet, "path": path})
    return 0


def cmd_wallet_list(args: argparse.Namespace) -> int:
    _load_config(args.datadir)
    _ensure_dir(_wallets_dir(args.datadir))

    wallets = []
    for name in WalletDB.list_wallet_names(_wallets_dir(args.datadir)):
        payload = _load_wallet(args.datadir, name)
        wallets.append({"name": payload.get("name"), "network": payload.get("network"), "path": str(_wallet_path(args.datadir, name))})

    _print_json({"ok": True, "action": "wallet.list", "wallets": wallets})
    return 0


def cmd_wallet_info(args: argparse.Namespace) -> int:
    _load_config(args.datadir)
    payload = _load_wallet(args.datadir, args.name)
    _print_json({"ok": True, "action": "wallet.info", "wallet": payload})
    return 0


def cmd_wallet_balance(args: argparse.Namespace) -> int:
    _load_config(args.datadir)
    payload = _load_wallet(args.datadir, args.name)
    payload = _refresh_wallet_history(args.datadir, payload)
    matches = _wallet_unique_owned_rows(args.datadir, payload)
    confirmed_lats = sum(row.entry.amount for row in matches)
    _print_json(
        {
            "ok": True,
            "action": "wallet.balance",
            "name": payload["name"],
            "network": payload["network"],
            "confirmed_lats": confirmed_lats,
            "confirmed_lat": _format_lats(confirmed_lats),
            "unconfirmed_lats": 0,
            "history_count": len(_wallet_history_rows(payload)),
            "matching_utxos": [
                {
                    "txid": row.entry.txid.hex(),
                    "index": row.entry.index,
                    "amount": row.entry.amount,
                    "amount_lat": _format_lats(row.entry.amount),
                    "ownership": row.ownership,
                }
                for row in matches
            ],
        }
    )
    return 0


def cmd_wallet_scan(args: argparse.Namespace) -> int:
    _load_config(args.datadir)
    payload = _load_wallet(args.datadir, args.name)
    payload = _refresh_wallet_history(args.datadir, payload)
    rows = _wallet_unique_owned_rows(args.datadir, payload)
    key_hashes = wallet_key_hashes(payload)
    _print_json(
        {
            "ok": True,
            "action": "wallet.scan",
            "name": payload["name"],
            "address_count": len(payload.get("addresses", [])),
            "key_hashes": sorted(key_hashes),
            "utxo_count": len(rows),
            "history": _wallet_history_rows(payload),
            "utxos": [
                {
                    "txid": row.entry.txid.hex(),
                    "index": row.entry.index,
                    "amount": row.entry.amount,
                    "amount_lat": _format_lats(row.entry.amount),
                    "created_height": row.entry.created_height,
                    "is_coinbase": row.entry.is_coinbase,
                    "scheme_id": row.entry.scheme_id,
                    "scheme_name": scheme_id_to_name(row.entry.scheme_id),
                    "ownership": row.ownership,
                    "source_address": row.source_address,
                }
                for row in rows
            ],
        }
    )
    return 0


def cmd_wallet_receive(args: argparse.Namespace) -> int:
    _load_config(args.datadir)
    wallet = _load_wallet(args.datadir, args.name)
    scheme_id = scheme_name_to_id(args.scheme)
    wallet, entry = _wallet_receive_entry(
        args.datadir,
        wallet,
        create_new=args.new,
        scheme_id=scheme_id,
        entry_type=args.type,
        hot_delay_blocks=int(args.hot_delay),
    )
    wallet = _refresh_wallet_history(args.datadir, wallet)
    _print_json({
        "ok": True,
        "action": "wallet.receive",
        "created_new": bool(args.new or len(wallet.get("addresses", [])) == 1),
        "entry": entry,
        "history_count": len(_wallet_history_rows(wallet)),
    })
    return 0


def cmd_wallet_history(args: argparse.Namespace) -> int:
    _load_config(args.datadir)
    wallet = _load_wallet(args.datadir, args.name)
    wallet = _refresh_wallet_history(args.datadir, wallet)
    _print_json({
        "ok": True,
        "action": "wallet.history",
        "name": wallet["name"],
        "count": len(_wallet_history_rows(wallet)),
        "history": _wallet_history_rows(wallet),
    })
    return 0


def cmd_wallet_new_address(args: argparse.Namespace) -> int:
    _load_config(args.datadir)
    wallet = _load_wallet(args.datadir, args.name)
    if args.type == "standard":
        entry = _make_standard_key_entry(str(wallet["network"]), scheme_id=scheme_name_to_id(args.scheme))
    elif args.type == "stealth":
        entry = _make_stealth_entry(str(wallet["network"]))
    elif args.type == "vault":
        entry = _make_vault_entry(str(wallet["network"]), scheme_id=scheme_name_to_id(args.scheme), hot_delay_blocks=int(args.hot_delay))
    else:
        raise SystemExit(f"unsupported address type: {args.type}")
    wallet.setdefault("addresses", []).append(entry)
    _save_wallet(args.datadir, wallet)
    _print_json({"ok": True, "action": "wallet.new-address", "entry": entry})
    return 0


def cmd_wallet_send(args: argparse.Namespace) -> int:
    config = _load_config(args.datadir)
    meta = _load_chain_meta(args.datadir)
    wallet = _load_wallet(args.datadir, args.name)
    if wallet["network"] != config["network"]:
        raise SystemExit(f"wallet network {wallet['network']} does not match node network {config['network']}")

    amount_lats = _parse_amount_to_lats(args.amount)
    fee_lats = _parse_amount_to_lats(args.fee)

    unsigned_tx, selected, change_lats, recipient_kind = _build_unsigned_payment_tx(
        datadir=args.datadir,
        wallet_payload=wallet,
        network_id=int(config["network_id"]),
        recipient_address=args.to,
        amount_lats=amount_lats,
        fee_lats=fee_lats,
        lock_height=int(args.lock_height),
    )
    signed_tx = _sign_transaction_for_wallet(tx=unsigned_tx, datadir=args.datadir, wallet_payload=wallet)

    if args.out is not None:
        _write_tx_hex(args.out, signed_tx)

    broadcasted = False
    mempool_size = None
    if not args.no_broadcast:
        mempool = _load_mempool(args.datadir)
        fee = mempool.add_transaction(signed_tx, _load_utxos(args.datadir).entries, _chain_context(config, meta), min_fee=args.min_fee)
        _save_mempool(args.datadir, mempool)
        broadcasted = True
        mempool_size = len(mempool)
        if fee != fee_lats:
            raise SystemExit(f"internal fee mismatch after validation: expected {fee_lats}, got {fee}")

    wallet = _refresh_wallet_history(args.datadir, wallet)
    _print_json(
        {
            "ok": True,
            "action": "wallet.send",
            "txid": txid(signed_tx).hex(),
            "recipient_kind": recipient_kind,
            "broadcasted": broadcasted,
            "mempool_size": mempool_size,
            "amount_lats": amount_lats,
            "amount_lat": _format_lats(amount_lats),
            "fee_lats": fee_lats,
            "fee_lat": _format_lats(fee_lats),
            "change_lats": change_lats,
            "change_lat": _format_lats(change_lats),
            "selected_inputs": [f"{entry.txid.hex()}:{entry.index}" for entry in selected],
            "recipient": args.to,
            "change_address": _wallet_primary_address(wallet),
            "history_count": len(_wallet_history_rows(wallet)),
            "output_path": (None if args.out is None else str(args.out)),
        }
    )
    return 0


def cmd_wallet_vault_spend(args: argparse.Namespace) -> int:
    config = _load_config(args.datadir)
    meta = _load_chain_meta(args.datadir)
    wallet = _load_wallet(args.datadir, args.name)
    amount_lats = _parse_amount_to_lats(args.amount)
    fee_lats = _parse_amount_to_lats(args.fee)
    mode = VAULT_SPEND_HOT if args.mode == "hot" else VAULT_SPEND_COLD

    rows = [row for row in _wallet_spendable_rows(args.datadir, wallet, include_vault=True) if row.ownership.startswith("vault-") and row.spend_mode == mode]
    selected, _ = select_utxos([row.entry for row in rows], amount_lats + fee_lats)
    change_entry = _wallet_default_change_entry(wallet)
    change_key_hash = bytes.fromhex(str(change_entry["key_hash_hex"]))
    change_scheme_id = int(change_entry.get("scheme_id", SCHEME_SIG_V1))
    recipient_kind, _lock_type, lock_data, scheme_id = _recipient_lock_from_address(args.to, expected_network=str(wallet["network"]))
    if recipient_kind != "standard":
        raise SystemExit("vault-spend currently supports standard recipient addresses only")
    unsigned_tx, change_lats = build_p2lpkh_payment_tx(
        network_id=int(config["network_id"]),
        selected_utxos=selected,
        recipient_key_hash=lock_data,
        recipient_scheme_id=scheme_id,
        amount=amount_lats,
        fee=fee_lats,
        change_key_hash=change_key_hash,
        change_scheme_id=change_scheme_id,
        lock_height=int(args.lock_height),
    )
    signed_tx = _sign_transaction_for_wallet(tx=unsigned_tx, datadir=args.datadir, wallet_payload=wallet, prefer_vault_mode=mode)
    if args.out is not None:
        _write_tx_hex(args.out, signed_tx)
    broadcasted = False
    mempool_size = None
    if not args.no_broadcast:
        mempool = _load_mempool(args.datadir)
        mempool.add_transaction(signed_tx, _load_utxos(args.datadir).entries, _chain_context(config, meta), min_fee=args.min_fee)
        _save_mempool(args.datadir, mempool)
        broadcasted = True
        mempool_size = len(mempool)
    wallet = _refresh_wallet_history(args.datadir, wallet)
    _print_json({
        "ok": True,
        "action": "wallet.vault-spend",
        "txid": txid(signed_tx).hex(),
        "mode": args.mode,
        "broadcasted": broadcasted,
        "mempool_size": mempool_size,
        "amount_lats": amount_lats,
        "amount_lat": _format_lats(amount_lats),
        "fee_lats": fee_lats,
        "fee_lat": _format_lats(fee_lats),
        "change_lats": change_lats,
        "change_lat": _format_lats(change_lats),
        "selected_inputs": [f"{entry.txid.hex()}:{entry.index}" for entry in selected],
    })
    return 0


def cmd_tx_decode(args: argparse.Namespace) -> int:
    raw = _load_tx_bytes(args.tx)
    tx = decode_transaction(raw)
    _print_json({"ok": True, "action": "tx.decode", "transaction": tx})
    return 0


def cmd_tx_txid(args: argparse.Namespace) -> int:
    raw = _load_tx_bytes(args.tx)
    tx = decode_transaction(raw)
    print(txid(tx).hex())
    return 0


def cmd_tx_wtxid(args: argparse.Namespace) -> int:
    raw = _load_tx_bytes(args.tx)
    tx = decode_transaction(raw)
    print(wtxid(tx).hex())
    return 0


def cmd_tx_inspect(args: argparse.Namespace) -> int:
    raw = _load_tx_bytes(args.tx)
    tx = decode_transaction(raw)

    validate_result = {"valid_structure": True}
    try:
        validate_tx_structure(tx)
    except Exception as exc:
        validate_result = {
            "valid_structure": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }

    payload = {
        "ok": True,
        "action": "tx.inspect",
        "size_bytes": len(raw),
        "txid": txid(tx).hex(),
        "wtxid": wtxid(tx).hex(),
        "structure": validate_result,
        "transaction": tx,
    }
    _print_json(payload)
    return 0


def cmd_tx_verify(args: argparse.Namespace) -> int:
    config = _load_config(args.datadir)
    meta = _load_chain_meta(args.datadir)
    raw = _load_tx_bytes(args.tx)
    tx = decode_transaction(raw)

    structure = {"valid": True}
    try:
        validate_tx_structure(tx, allow_coinbase=args.allow_coinbase)
    except Exception as exc:
        structure = {"valid": False, "error_type": type(exc).__name__, "error": str(exc)}

    prevouts, missing = _find_prevouts_for_tx(args.datadir, tx)
    contextual = {"valid": False, "missing_prevouts": missing}
    if structure["valid"] and not missing:
        try:
            fee = validate_tx_against_utxos(tx, _load_utxos(args.datadir).entries, _chain_context(config, meta))
            contextual = {"valid": True, "fee": fee, "fee_lat": _format_lats(fee), "missing_prevouts": []}
        except Exception as exc:
            contextual = {"valid": False, "error_type": type(exc).__name__, "error": str(exc), "missing_prevouts": []}

    _print_json({
        "ok": True,
        "action": "tx.verify",
        "txid": txid(tx).hex(),
        "wtxid": wtxid(tx).hex(),
        "structure": structure,
        "contextual": contextual,
        "input_count": len(tx.body.inputs),
        "resolved_prevout_count": len(prevouts),
    })
    return 0


def cmd_tx_build(args: argparse.Namespace) -> int:
    config = _load_config(args.datadir)
    wallet = _load_wallet(args.datadir, args.wallet)
    if wallet["network"] != config["network"]:
        raise SystemExit(
            f"wallet network {wallet['network']} does not match node network {config['network']}"
        )
    amount_lats = _parse_amount_to_lats(args.amount)
    fee_lats = _parse_amount_to_lats(args.fee)

    unsigned_tx, selected, change_lats, recipient_kind = _build_unsigned_payment_tx(
        datadir=args.datadir,
        wallet_payload=wallet,
        network_id=int(config["network_id"]),
        recipient_address=args.to,
        amount_lats=amount_lats,
        fee_lats=fee_lats,
        lock_height=int(args.lock_height),
    )
    _write_tx_hex(args.out, unsigned_tx)
    if args.out is not None:
        destination = str(args.out)
    else:
        destination = "stdout"
    _print_json(
        {
            "ok": True,
            "action": "tx.build",
            "wallet": args.wallet,
            "txid_if_signed_later": txid(unsigned_tx).hex(),
            "selected_inputs": [f"{entry.txid.hex()}:{entry.index}" for entry in selected],
            "amount_lats": amount_lats,
            "amount_lat": _format_lats(amount_lats),
            "fee_lats": fee_lats,
            "fee_lat": _format_lats(fee_lats),
            "change_lats": change_lats,
            "change_lat": _format_lats(change_lats),
            "recipient_kind": recipient_kind,
            "destination": destination,
        }
    )
    return 0


def cmd_tx_sign(args: argparse.Namespace) -> int:
    _load_config(args.datadir)
    wallet = _load_wallet(args.datadir, args.wallet)
    raw = _load_tx_bytes(args.infile)
    tx = decode_transaction(raw)
    signed_tx = _sign_transaction_for_wallet(tx=tx, datadir=args.datadir, wallet_payload=wallet, prefer_vault_mode=(VAULT_SPEND_HOT if getattr(args, "vault_mode", "hot") == "hot" else VAULT_SPEND_COLD))
    _write_tx_hex(args.out, signed_tx)
    _print_json(
        {
            "ok": True,
            "action": "tx.sign",
            "wallet": args.wallet,
            "txid": txid(signed_tx).hex(),
            "wtxid": wtxid(signed_tx).hex(),
            "output_path": (None if args.out is None else str(args.out)),
        }
    )
    return 0


def cmd_mine_start(args: argparse.Namespace) -> int:
    config = _load_config(args.datadir)
    meta = _load_chain_meta(args.datadir)
    network = str(config["network"])
    network_id = int(config["network_id"])
    coinbase_maturity = int(meta.get("coinbase_maturity", 100))
    reward_address = args.address or str(config["dev_miner"]["address"])
    reward_lock_data, reward_scheme_id = _parse_standard_address(
        reward_address, expected_network=network
    )
    engine = ChainEngine(args.datadir, network_id, coinbase_maturity=coinbase_maturity)
    miner = Miner(
        engine,
        reward_lock_data,
        reward_scheme_id,
        min_interval=args.interval,
    )
    _print_json({
        "ok": True,
        "action": "mine.start",
        "network": network,
        "reward_address": reward_address,
        "interval": args.interval,
        "max_blocks": args.max_blocks,
    })
    stats = miner.run(max_blocks=args.max_blocks)
    _print_json({
        "ok": True,
        "action": "mine.done",
        "blocks_found": stats.blocks_found,
        "total_hashes": stats.total_hashes,
        "elapsed_secs": round(stats.elapsed_secs, 3),
        "hash_rate": round(stats.hash_rate, 1),
    })
    return 0


def cmd_mine_once(args: argparse.Namespace) -> int:
    config = _load_config(args.datadir)
    meta = _load_chain_meta(args.datadir)

    network = str(config["network"])
    network_id = int(config["network_id"])
    coinbase_maturity = int(meta.get("coinbase_maturity", 100))
    reward_address = args.address or str(config["dev_miner"]["address"])
    reward_lock_data, reward_scheme_id = _parse_standard_address(reward_address, expected_network=network)

    engine = ChainEngine(args.datadir, network_id, coinbase_maturity=coinbase_maturity)

    selected_entries = engine.mempool.sorted_entries_for_block()
    selected_txs = [entry.tx for entry in selected_entries]
    total_fees = sum(entry.fee for entry in selected_entries)

    next_height = engine.next_height()
    expected_bits = engine.expected_bits_for_next_mined_block()

    template = build_block_template(
        network_id=network_id,
        height=next_height,
        prev_block_hash=engine.tip_hash(),
        reward_lock_data=reward_lock_data,
        bits=expected_bits,
        reward_scheme_id=reward_scheme_id,
        mempool_txs=selected_txs,
        total_fees=total_fees,
    )

    result = engine.submit_block(template.block)
    block_path = engine._block_file_path(result.height, result.block_hash)

    _print_json(
        {
            "ok": True,
            "action": "mine.once",
            "height": result.height,
            "block_hash": result.block_hash.hex(),
            "block_path": str(block_path),
            "selected_tx_count": len(selected_entries),
            "selected_txids": [entry.txid_bytes.hex() for entry in selected_entries],
            "coinbase_reward": template.subsidy + total_fees,
            "coinbase_reward_lat": _format_lats(template.subsidy + total_fees),
            "fees": total_fees,
            "bits": template.block.header.bits,
            "nonce": template.block.header.nonce,
            "remaining_mempool_size": len(engine.mempool),
            "reward_address": reward_address,
            "reorg_depth": result.reorg_depth,
        }
    )
    return 0


def cmd_rpc_call(args: argparse.Namespace) -> int:
    params = _parse_rpc_params(args.params)
    try:
        body = call_rpc(
            args.method,
            params,
            host=args.rpc_host,
            port=args.rpc_port,
            timeout=args.timeout,
        )
    except RpcError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _print_json(body)
    return 0 if body.get("ok") else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lat", description="LatCoin CLI")
    parser.add_argument(
        "--datadir",
        type=Path,
        default=DEFAULT_DATADIR,
        help="LatCoin data directory",
    )

    subparsers = parser.add_subparsers(dest="command")

    node_parser = subparsers.add_parser("node", help="Node commands")
    node_sub = node_parser.add_subparsers(dest="node_command")

    node_init = node_sub.add_parser("init", help="Initialize a datadir")
    node_init.add_argument(
        "--network",
        choices=("mainnet", "testnet", "devnet"),
        default="devnet",
    )
    node_init.add_argument(
        "--miner-scheme",
        choices=_supported_scheme_choices(),
        default="mocksig-v1",
    )
    node_init.set_defaults(func=cmd_node_init)

    node_start = node_sub.add_parser("start", help="Start the node service")
    node_start.add_argument("--rpc-host", default="127.0.0.1")
    node_start.add_argument("--rpc-port", type=int, default=9338)
    node_start.add_argument("--p2p-host", default="0.0.0.0")
    node_start.add_argument("--p2p-port", type=int, default=DEFAULT_P2P_PORT)
    node_start.add_argument("--peer", action="append", metavar="HOST:PORT",
                            help="Seed peer to connect to on startup (repeatable)")
    node_start.add_argument("--no-seeds", action="store_true",
                            help="Disable built-in seed bootstrapping")
    node_start.set_defaults(func=cmd_node_start)

    node_status = node_sub.add_parser("status", help="Show node status via RPC")
    node_status.add_argument("--rpc-host", default="127.0.0.1")
    node_status.add_argument("--rpc-port", type=int, default=9338)
    node_status.set_defaults(func=cmd_node_status)

    node_submit = node_sub.add_parser("submit-tx", help="Validate and add a transaction to the local mempool")
    node_submit.add_argument("tx", help="Hex string or file path")
    node_submit.add_argument("--min-fee", type=int, default=0)
    node_submit.set_defaults(func=cmd_node_submit_tx)

    node_mempool = node_sub.add_parser("mempool", help="Show local mempool entries")
    node_mempool.set_defaults(func=cmd_node_mempool)

    wallet_parser = subparsers.add_parser("wallet", help="Wallet commands")
    wallet_sub = wallet_parser.add_subparsers(dest="wallet_command")

    wallet_new = wallet_sub.add_parser("new", help="Create a wallet")
    wallet_new.add_argument("--name", required=True)
    wallet_new.add_argument(
        "--network",
        choices=("mainnet", "testnet", "devnet"),
        default="devnet",
    )
    wallet_new.set_defaults(func=cmd_wallet_new)

    wallet_list = wallet_sub.add_parser("list", help="List wallets")
    wallet_list.set_defaults(func=cmd_wallet_list)

    wallet_info = wallet_sub.add_parser("info", help="Show wallet info")
    wallet_info.add_argument("--name", required=True)
    wallet_info.set_defaults(func=cmd_wallet_info)

    wallet_balance = wallet_sub.add_parser("balance", help="Show wallet balance")
    wallet_balance.add_argument("--name", required=True)
    wallet_balance.set_defaults(func=cmd_wallet_balance)

    wallet_scan = wallet_sub.add_parser("scan", help="Scan the local UTXO set for wallet outputs")
    wallet_scan.add_argument("--name", required=True)
    wallet_scan.set_defaults(func=cmd_wallet_scan)

    wallet_receive = wallet_sub.add_parser("receive", help="Show or create a receive address")
    wallet_receive.add_argument("--name", required=True)
    wallet_receive.add_argument("--new", action="store_true")
    wallet_receive.add_argument("--type", choices=("standard", "stealth", "vault"), default="standard")
    wallet_receive.add_argument("--scheme", choices=_supported_scheme_choices(), default="mocksig-v1")
    wallet_receive.add_argument("--hot-delay", type=int, default=144)
    wallet_receive.set_defaults(func=cmd_wallet_receive)

    wallet_history = wallet_sub.add_parser("history", help="Show persistent wallet transaction history")
    wallet_history.add_argument("--name", required=True)
    wallet_history.set_defaults(func=cmd_wallet_history)

    wallet_new_address = wallet_sub.add_parser("new-address", help="Create a new wallet address")
    wallet_new_address.add_argument("--name", required=True)
    wallet_new_address.add_argument("--type", choices=("standard", "stealth", "vault"), default="standard")
    wallet_new_address.add_argument("--scheme", choices=_supported_scheme_choices(), default="mocksig-v1")
    wallet_new_address.add_argument("--hot-delay", type=int, default=144)
    wallet_new_address.set_defaults(func=cmd_wallet_new_address)

    wallet_vault_spend = wallet_sub.add_parser("vault-spend", help="Spend from wallet-owned P2LVAULT outputs")
    wallet_vault_spend.add_argument("--name", required=True)
    wallet_vault_spend.add_argument("--to", required=True)
    wallet_vault_spend.add_argument("--amount", required=True)
    wallet_vault_spend.add_argument("--fee", default="0.000001")
    wallet_vault_spend.add_argument("--mode", choices=("hot", "cold"), default="cold")
    wallet_vault_spend.add_argument("--lock-height", type=int, default=0)
    wallet_vault_spend.add_argument("--min-fee", type=int, default=0)
    wallet_vault_spend.add_argument("--out", type=Path)
    wallet_vault_spend.add_argument("--no-broadcast", action="store_true")
    wallet_vault_spend.set_defaults(func=cmd_wallet_vault_spend)

    wallet_send = wallet_sub.add_parser("send", help="Build, sign, and optionally broadcast a transaction")
    wallet_send.add_argument("--name", required=True)
    wallet_send.add_argument("--to", required=True)
    wallet_send.add_argument("--amount", required=True, help="Amount in LAT, supports decimals")
    wallet_send.add_argument("--fee", default="0.000001", help="Fee in LAT, supports decimals")
    wallet_send.add_argument("--lock-height", type=int, default=0)
    wallet_send.add_argument("--min-fee", type=int, default=0, help="Minimum mempool fee in lats when broadcasting")
    wallet_send.add_argument("--out", type=Path, help="Optional path to also write signed tx hex")
    wallet_send.add_argument("--no-broadcast", action="store_true")
    wallet_send.set_defaults(func=cmd_wallet_send)

    tx_parser = subparsers.add_parser("tx", help="Transaction commands")
    tx_sub = tx_parser.add_subparsers(dest="tx_command")

    tx_decode = tx_sub.add_parser("decode", help="Decode a transaction")
    tx_decode.add_argument("tx", help="Hex string or file path")
    tx_decode.set_defaults(func=cmd_tx_decode)

    tx_txid = tx_sub.add_parser("txid", help="Compute txid")
    tx_txid.add_argument("tx", help="Hex string or file path")
    tx_txid.set_defaults(func=cmd_tx_txid)

    tx_wtxid = tx_sub.add_parser("wtxid", help="Compute wtxid")
    tx_wtxid.add_argument("tx", help="Hex string or file path")
    tx_wtxid.set_defaults(func=cmd_tx_wtxid)

    tx_inspect = tx_sub.add_parser("inspect", help="Inspect and structurally validate a transaction")
    tx_inspect.add_argument("tx", help="Hex string or file path")
    tx_inspect.set_defaults(func=cmd_tx_inspect)

    tx_verify = tx_sub.add_parser("verify", help="Verify a transaction structurally and against local chainstate when possible")
    tx_verify.add_argument("tx", help="Hex string or file path")
    tx_verify.add_argument("--allow-coinbase", action="store_true")
    tx_verify.set_defaults(func=cmd_tx_verify)

    tx_build = tx_sub.add_parser("build", help="Build an unsigned transaction from a wallet")
    tx_build.add_argument("--wallet", required=True)
    tx_build.add_argument("--to", required=True)
    tx_build.add_argument("--amount", required=True, help="Amount in LAT, supports decimals")
    tx_build.add_argument("--fee", default="0.000001", help="Fee in LAT, supports decimals")
    tx_build.add_argument("--lock-height", type=int, default=0)
    tx_build.add_argument("--out", type=Path, help="Optional output file for unsigned tx hex")
    tx_build.set_defaults(func=cmd_tx_build)

    tx_sign = tx_sub.add_parser("sign", help="Sign an unsigned transaction with wallet keys")
    tx_sign.add_argument("--wallet", required=True)
    tx_sign.add_argument("--in", dest="infile", required=True, help="Unsigned tx hex file or hex string")
    tx_sign.add_argument("--out", type=Path, help="Optional output file for signed tx hex")
    tx_sign.add_argument("--vault-mode", choices=("hot", "cold"), default="hot")
    tx_sign.set_defaults(func=cmd_tx_sign)

    mine_parser = subparsers.add_parser("mine", help="Mining commands")
    mine_sub = mine_parser.add_subparsers(dest="mine_command")

    mine_start = mine_sub.add_parser("start", help="Start a background miner loop")
    mine_start.add_argument("--address", help="Reward address")
    mine_start.add_argument("--interval", type=float, default=1.0)
    mine_start.add_argument("--max-blocks", type=int)
    mine_start.set_defaults(func=cmd_mine_start)

    mine_once = mine_sub.add_parser("once", help="Mine one candidate block")
    mine_once.add_argument("--address", help="Reward address. Defaults to the dev miner address created at node init.")
    mine_once.set_defaults(func=cmd_mine_once)

    rpc_parser = subparsers.add_parser(
        "rpc",
        help="Call a method on the running node via JSON-RPC",
    )
    rpc_parser.add_argument("--rpc-host", default="127.0.0.1")
    rpc_parser.add_argument("--rpc-port", type=int, default=9338)
    rpc_parser.add_argument(
        "--timeout", type=float, default=10.0, metavar="SECS",
        help="Request timeout in seconds (default: 10)",
    )
    rpc_parser.add_argument(
        "method",
        help="RPC method name (e.g. status, mempool, mine_once)",
    )
    rpc_parser.add_argument(
        "params",
        nargs="*",
        metavar="key=value",
        help="Method parameters; values are JSON-decoded when valid",
    )
    rpc_parser.set_defaults(func=cmd_rpc_call)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help(sys.stderr)
        return 2

    try:
        return int(args.func(args))
    except binascii.Error as exc:
        print(f"hex decoding error: {exc}", file=sys.stderr)
        return 1
    except InsufficientFundsError as exc:
        print(f"InsufficientFundsError: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _prepend_top_level(command_name: str, argv: list[str] | None) -> list[str]:
    tail = sys.argv[1:] if argv is None else argv
    return [command_name, *tail]


def main_node(argv: list[str] | None = None) -> int:
    return main(_prepend_top_level("node", argv))


def main_wallet(argv: list[str] | None = None) -> int:
    return main(_prepend_top_level("wallet", argv))


def main_miner(argv: list[str] | None = None) -> int:
    return main(_prepend_top_level("mine", argv))


def main_rpc(argv: list[str] | None = None) -> int:
    return main(_prepend_top_level("rpc", argv))


if __name__ == "__main__":
    raise SystemExit(main())
