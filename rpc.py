from __future__ import annotations

import base64
import json
import urllib.request
from pathlib import Path
from typing import Any

from .config import Settings


class RpcError(RuntimeError):
    pass


class ZebraRpc:
    def __init__(self, settings: Settings):
        self.settings = settings

    def _auth_header(self) -> dict[str, str]:
        if self.settings.rpc_disable_cookie_auth:
            return {}

        cookie_path: Path = self.settings.rpc_cookie_path
        if not cookie_path.exists():
            raise FileNotFoundError(
                f"RPC cookie file not found at {cookie_path}. "
                "Either enable cookie auth and point to the right file, or set ZCASH_RPC_DISABLE_COOKIE_AUTH=1."
            )

        raw = cookie_path.read_text(encoding="utf-8").strip()
        username, password = raw.split(":", 1)
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {token}"}

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        payload = json.dumps(
            {
                "jsonrpc": "1.0",
                "id": "zkcash-miner-skeleton",
                "method": method,
                "params": params or [],
            }
        ).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            **self._auth_header(),
        }

        req = urllib.request.Request(self.settings.rpc_url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                obj = json.loads(response.read().decode("utf-8"))
        except Exception as exc:  # pragma: no cover
            raise RpcError(f"RPC request failed for method={method}: {exc}") from exc

        if obj.get("error"):
            raise RpcError(f"RPC error for method={method}: {obj['error']}")
        return obj["result"]

    def getblocktemplate(self) -> dict[str, Any]:
        return self.call("getblocktemplate", [])

    def submitblock(self, block_hex: str) -> Any:
        return self.call("submitblock", [block_hex])
