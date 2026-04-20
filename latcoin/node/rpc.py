from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Thread
from typing import Any

from latcoin.chain.mempool import Mempool
from latcoin.chain.utxo import UtxoSet
from latcoin.codec.block import block_hash, encode_block
from latcoin.codec.tx import decode_transaction, encode_transaction, txid
from latcoin.mining.template import build_block_template
from latcoin.validation.block_context import BlockChainContext, validate_block_context
from latcoin.validation.pow import (
    advance_pow_state,
    expected_bits_for_next_block,
    pow_params_for_network,
)
from latcoin.validation.tx_context import ChainContext


class NodeFacade:
    def __init__(self, datadir: Path, engine: "ChainEngine | None" = None):
        self.datadir = Path(datadir)
        self._live_engine = engine
        self._miner_thread: Thread | None = None
        self._miner_stop = Event()
        self._miner_interval = 1.0
        self._miner_address: str | None = None
        self._miner_max_blocks: int | None = None
        self._miner_blocks_mined = 0
        self._miner_last_error: str | None = None

    def _load_json(self, path: Path) -> Any:
        return json.loads(path.read_text(encoding="utf-8"))

    def _save_json(self, path: Path, payload: Any) -> None:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def _config_path(self) -> Path:
        return self.datadir / "config.json"

    def _meta_path(self) -> Path:
        return self.datadir / "chainstate" / "meta.json"

    def _utxo_path(self) -> Path:
        return self.datadir / "chainstate" / "utxos.json"

    def _mempool_path(self) -> Path:
        return self.datadir / "mempool" / "entries.json"

    def _load_config(self) -> dict[str, Any]:
        return self._load_json(self._config_path())

    def _load_meta(self) -> dict[str, Any]:
        return self._load_json(self._meta_path())

    def _save_meta(self, payload: dict[str, Any]) -> None:
        self._save_json(self._meta_path(), payload)

    def _load_utxos(self) -> UtxoSet:
        path = self._utxo_path()
        return UtxoSet.load_json(path) if path.exists() else UtxoSet()

    def _save_utxos(self, utxos: UtxoSet) -> None:
        utxos.save_json(self._utxo_path())

    def _load_mempool(self) -> Mempool:
        path = self._mempool_path()
        return Mempool.load_json(path) if path.exists() else Mempool()

    def _save_mempool(self, mempool: Mempool) -> None:
        mempool.save_json(self._mempool_path())

    def _chain_context(self, config: dict[str, Any], meta: dict[str, Any]) -> ChainContext:
        return ChainContext(
            network_id=int(config["network_id"]),
            current_height=int(meta["next_block_height"]),
            median_time_past=max(0, int(meta["block_count"]) - 1),
            coinbase_maturity=int(meta.get("coinbase_maturity", 100)),
        )

    def _block_context(self, config: dict[str, Any], meta: dict[str, Any]) -> BlockChainContext:
        from latcoin.cli.main import _pow_state_from_meta

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

    def status(self) -> dict[str, Any]:
        config = self._load_config()
        if self._live_engine is not None:
            eng = self._live_engine
            next_height = eng.next_height()
            return {
                "network": config["network"],
                "next_block_height": next_height,
                "height": next_height - 1 if next_height > 0 else -1,
                "tip": eng.tip_hash().hex(),
                "mempool_size": len(eng.mempool),
                "utxo_count": len(eng.utxos),
                "dev_miner_address": config["dev_miner"]["address"],
                "miner": self.miner_status(),
            }
        meta = self._load_meta()
        mempool = self._load_mempool()
        utxos = self._load_utxos()
        next_height = int(meta["next_block_height"])
        return {
            "network": config["network"],
            "next_block_height": next_height,
            "height": next_height - 1 if next_height > 0 else -1,
            "tip": meta["tip_hash"],
            "mempool_size": len(mempool),
            "utxo_count": len(utxos),
            "dev_miner_address": config["dev_miner"]["address"],
            "miner": self.miner_status(),
        }

    def mempool(self) -> dict[str, Any]:
        mempool = self._load_mempool()
        return {
            "count": len(mempool),
            "entries": [
                {
                    "txid": entry.txid_bytes.hex(),
                    "fee": entry.fee,
                    "size_bytes": entry.size_bytes,
                    "fee_rate": entry.fee_rate,
                }
                for entry in mempool.sorted_entries_for_block()
            ],
        }

    def submit_tx(self, tx_hex: str, min_fee: int = 0) -> dict[str, Any]:
        config = self._load_config()
        meta = self._load_meta()
        utxos = self._load_utxos()
        mempool = self._load_mempool()
        tx = decode_transaction(bytes.fromhex("".join(tx_hex.split())))
        fee = mempool.add_transaction(tx, utxos.entries, self._chain_context(config, meta), min_fee=min_fee)
        self._save_mempool(mempool)
        return {"txid": txid(tx).hex(), "fee": fee, "mempool_size": len(mempool)}

    def _engine(self) -> "ChainEngine":
        if self._live_engine is not None:
            return self._live_engine
        from latcoin.chain.engine import ChainEngine

        config = self._load_config()
        meta = self._load_meta() if self._meta_path().exists() else {}
        network_id = int(config["network_id"])
        coinbase_maturity = int(meta.get("coinbase_maturity", 100))
        return ChainEngine(self.datadir, network_id, coinbase_maturity=coinbase_maturity)

    def mine_once(self, address: str | None = None) -> dict[str, Any]:
        from latcoin.cli.main import _parse_standard_address

        config = self._load_config()
        reward_address = address or str(config["dev_miner"]["address"])
        reward_lock_data, reward_scheme_id = _parse_standard_address(
            reward_address, expected_network=str(config["network"])
        )
        engine = self._engine()
        selected_entries = engine.mempool.sorted_entries_for_block()
        selected_txs = [entry.tx for entry in selected_entries]
        total_fees = sum(entry.fee for entry in selected_entries)
        next_height = engine.next_height()
        expected_bits = engine.expected_bits_for_next_mined_block()
        template = build_block_template(
            network_id=engine.network_id,
            height=next_height,
            prev_block_hash=engine.tip_hash(),
            reward_lock_data=reward_lock_data,
            bits=expected_bits,
            reward_scheme_id=reward_scheme_id,
            mempool_txs=selected_txs,
            total_fees=total_fees,
        )
        result = engine.submit_block(template.block)
        return {
            "height": result.height,
            "block_hash": result.block_hash.hex(),
            "bits": template.block.header.bits,
            "nonce": template.block.header.nonce,
            "selected_tx_count": len(selected_entries),
            "remaining_mempool_size": len(engine.mempool),
            "block_path": str(engine._block_file_path(result.height, result.block_hash)),
            "reorg_depth": result.reorg_depth,
        }

    def submit_block(self, block_hex: str) -> dict[str, Any]:
        from latcoin.codec.block import decode_block

        block = decode_block(bytes.fromhex("".join(block_hex.split())))
        engine = self._engine()
        result = engine.submit_block(block)
        return {
            "height": result.height,
            "block_hash": result.block_hash.hex(),
            "accepted": result.accepted,
            "became_active_tip": result.became_active_tip,
            "reorg_depth": result.reorg_depth,
            "already_known": result.already_known,
        }

    def wallet_receive(self, name: str, *, entry_type: str = "standard", create_new: bool = False, scheme: str = "mocksig-v1", hot_delay: int = 144) -> dict[str, Any]:
        from latcoin.cli.main import _load_wallet, _refresh_wallet_history, _wallet_history_rows, _wallet_receive_entry, scheme_name_to_id

        wallet = _load_wallet(self.datadir, name)
        wallet, entry = _wallet_receive_entry(self.datadir, wallet, create_new=create_new, scheme_id=scheme_name_to_id(scheme), entry_type=entry_type, hot_delay_blocks=hot_delay)
        wallet = _refresh_wallet_history(self.datadir, wallet)
        return {"entry": entry, "history_count": len(_wallet_history_rows(wallet))}

    def wallet_build(self, name: str, *, to: str, amount: str, fee: str = "0.000001", lock_height: int = 0) -> dict[str, Any]:
        from latcoin.cli.main import _build_unsigned_payment_tx, _format_lats, _load_wallet, _parse_amount_to_lats

        config = self._load_config()
        wallet = _load_wallet(self.datadir, name)
        amount_lats = _parse_amount_to_lats(amount)
        fee_lats = _parse_amount_to_lats(fee)
        unsigned_tx, selected, change_lats, recipient_kind = _build_unsigned_payment_tx(datadir=self.datadir, wallet_payload=wallet, network_id=int(config["network_id"]), recipient_address=to, amount_lats=amount_lats, fee_lats=fee_lats, lock_height=lock_height)
        return {
            "tx_hex": encode_transaction(unsigned_tx).hex(),
            "selected_inputs": [f"{entry.txid.hex()}:{entry.index}" for entry in selected],
            "change_lats": change_lats,
            "change_lat": _format_lats(change_lats),
            "recipient_kind": recipient_kind,
        }

    def wallet_sign(self, name: str, *, tx_hex: str, vault_mode: str = "hot") -> dict[str, Any]:
        from latcoin.cli.main import _load_wallet, _sign_transaction_for_wallet

        wallet = _load_wallet(self.datadir, name)
        tx = decode_transaction(bytes.fromhex("".join(tx_hex.split())))
        signed_tx = _sign_transaction_for_wallet(tx=tx, datadir=self.datadir, wallet_payload=wallet, prefer_vault_mode=(1 if vault_mode == "hot" else 2))
        return {"tx_hex": encode_transaction(signed_tx).hex(), "txid": txid(signed_tx).hex()}

    def wallet_send(self, name: str, *, to: str, amount: str, fee: str = "0.000001", lock_height: int = 0, min_fee: int = 0, no_broadcast: bool = False) -> dict[str, Any]:
        build = self.wallet_build(name, to=to, amount=amount, fee=fee, lock_height=lock_height)
        signed = self.wallet_sign(name, tx_hex=str(build["tx_hex"]))
        result = {"txid": signed["txid"], "recipient_kind": build["recipient_kind"], "tx_hex": signed["tx_hex"]}
        if not no_broadcast:
            result.update(self.submit_tx(str(signed["tx_hex"]), min_fee=min_fee))
        return result

    def tx_verify(self, tx_hex: str, allow_coinbase: bool = False) -> dict[str, Any]:
        from latcoin.cli.main import _find_prevouts_for_tx, _format_lats
        from latcoin.validation.tx_structure import validate_tx_structure
        from latcoin.validation.tx_context import validate_tx_against_utxos

        config = self._load_config()
        meta = self._load_meta()
        tx = decode_transaction(bytes.fromhex("".join(tx_hex.split())))
        structure = {"valid": True}
        try:
            validate_tx_structure(tx, allow_coinbase=allow_coinbase)
        except Exception as exc:
            structure = {"valid": False, "error_type": type(exc).__name__, "error": str(exc)}
        prevouts, missing = _find_prevouts_for_tx(self.datadir, tx)
        contextual = {"valid": False, "missing_prevouts": missing}
        if structure["valid"] and not missing:
            try:
                fee = validate_tx_against_utxos(tx, self._load_utxos().entries, self._chain_context(config, meta))
                contextual = {"valid": True, "fee": fee, "fee_lat": _format_lats(fee), "missing_prevouts": []}
            except Exception as exc:
                contextual = {"valid": False, "error_type": type(exc).__name__, "error": str(exc), "missing_prevouts": []}
        return {"txid": txid(tx).hex(), "structure": structure, "contextual": contextual, "resolved_prevout_count": len(prevouts)}

    def _miner_loop(self) -> None:
        while not self._miner_stop.is_set():
            try:
                self.mine_once(address=self._miner_address)
                self._miner_blocks_mined += 1
            except Exception as exc:  # pragma: no cover - best effort loop
                self._miner_last_error = f"{type(exc).__name__}: {exc}"
            if self._miner_max_blocks is not None and self._miner_blocks_mined >= self._miner_max_blocks:
                break
            self._miner_stop.wait(self._miner_interval)
        self._miner_stop.clear()
        self._miner_thread = None

    def start_miner(self, *, interval: float = 1.0, address: str | None = None, max_blocks: int | None = None) -> dict[str, Any]:
        if self._miner_thread is not None and self._miner_thread.is_alive():
            return self.miner_status()
        self._miner_interval = max(0.0, float(interval))
        self._miner_address = address
        self._miner_max_blocks = max_blocks
        self._miner_blocks_mined = 0
        self._miner_last_error = None
        self._miner_stop.clear()
        self._miner_thread = Thread(target=self._miner_loop, daemon=True)
        self._miner_thread.start()
        return self.miner_status()

    def stop_miner(self) -> dict[str, Any]:
        if self._miner_thread is not None:
            self._miner_stop.set()
            self._miner_thread.join(timeout=2)
        return self.miner_status()

    def miner_status(self) -> dict[str, Any]:
        return {
            "running": bool(self._miner_thread is not None and self._miner_thread.is_alive()),
            "interval": self._miner_interval,
            "address": self._miner_address,
            "max_blocks": self._miner_max_blocks,
            "blocks_mined": self._miner_blocks_mined,
            "last_error": self._miner_last_error,
        }

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params or {}
        if method == "status":
            return self.status()
        if method == "mempool":
            return self.mempool()
        if method == "submit_tx":
            return self.submit_tx(str(params["tx_hex"]), int(params.get("min_fee", 0)))
        if method == "submit_block":
            return self.submit_block(str(params["block_hex"]))
        if method == "mine_once":
            return self.mine_once(params.get("address"))
        if method == "wallet_receive":
            return self.wallet_receive(str(params["name"]), entry_type=str(params.get("type", "standard")), create_new=bool(params.get("new", False)), scheme=str(params.get("scheme", "mocksig-v1")), hot_delay=int(params.get("hot_delay", 144)))
        if method == "wallet_build":
            return self.wallet_build(str(params["name"]), to=str(params["to"]), amount=str(params["amount"]), fee=str(params.get("fee", "0.000001")), lock_height=int(params.get("lock_height", 0)))
        if method == "wallet_sign":
            return self.wallet_sign(str(params["name"]), tx_hex=str(params["tx_hex"]), vault_mode=str(params.get("vault_mode", "hot")))
        if method == "wallet_send":
            return self.wallet_send(str(params["name"]), to=str(params["to"]), amount=str(params["amount"]), fee=str(params.get("fee", "0.000001")), lock_height=int(params.get("lock_height", 0)), min_fee=int(params.get("min_fee", 0)), no_broadcast=bool(params.get("no_broadcast", False)))
        if method == "tx_verify":
            return self.tx_verify(str(params["tx_hex"]), allow_coinbase=bool(params.get("allow_coinbase", False)))
        if method == "start_miner":
            return self.start_miner(interval=float(params.get("interval", 1.0)), address=params.get("address"), max_blocks=(None if params.get("max_blocks") is None else int(params.get("max_blocks"))))
        if method == "stop_miner":
            return self.stop_miner()
        if method == "miner_status":
            return self.miner_status()
        raise KeyError(f"unknown RPC method: {method}")


class _RpcServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], datadir: Path, engine: "ChainEngine | None" = None):
        super().__init__(server_address, _RpcHandler)
        self.facade = NodeFacade(datadir, engine)


class _RpcHandler(BaseHTTPRequestHandler):
    server: _RpcServer

    def _write_json(self, status_code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/health", "/status"):
            self._write_json(200, {"ok": True, "result": self.server.facade.status()})
            return
        self._write_json(404, {"ok": False, "error": f"unknown path: {self.path}"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/rpc":
            self._write_json(404, {"ok": False, "error": f"unknown path: {self.path}"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8")) if raw else {}
            method = str(payload["method"])
            params = payload.get("params", {})
            if params is None:
                params = {}
            if not isinstance(params, dict):
                raise ValueError("params must be an object")
            result = self.server.facade.call(method, params)
            self._write_json(200, {"ok": True, "result": result})
        except Exception as exc:
            self._write_json(400, {"ok": False, "error": str(exc), "error_type": type(exc).__name__})


def run_rpc_server(
    datadir: Path,
    host: str = "127.0.0.1",
    port: int = 9338,
    engine: "ChainEngine | None" = None,
) -> None:
    server = _RpcServer((host, port), Path(datadir), engine)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.facade.stop_miner()
        server.server_close()


def start_rpc_server_in_thread(
    datadir: Path,
    host: str = "127.0.0.1",
    port: int = 0,
    engine: "ChainEngine | None" = None,
):
    server = _RpcServer((host, port), Path(datadir), engine)
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return server, thread
