"""Thin HTTP client for the LatCoin JSON-RPC server (node/rpc.py).

Usage::

    from latcoin.node.rpc_client import call_rpc, RpcError

    result = call_rpc("status")
    result = call_rpc("submit_tx", {"tx_hex": "dead..."}, port=9338)
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class RpcError(Exception):
    """Raised when the node cannot be reached or returns an unreadable response."""


def call_rpc(
    method: str,
    params: dict[str, Any] | None = None,
    *,
    host: str = "127.0.0.1",
    port: int = 9338,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Send one RPC call and return the full server response dict.

    The response always contains an ``ok`` key.  Server-side errors (unknown
    method, bad params, etc.) come back as ``{"ok": false, "error": "..."}``
    and are *returned*, not raised, so the caller decides what to do.

    ``RpcError`` is raised only when the node cannot be reached at all (TCP
    refused, network timeout, non-JSON body on a connection error).
    """
    url = f"http://{host}:{port}/rpc"
    body = json.dumps({"method": method, "params": params or {}}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # Server returned 4xx with a JSON body — read and return it so the
        # caller can inspect the error message.
        try:
            return json.loads(exc.read().decode("utf-8"))
        except Exception as inner:
            raise RpcError(f"HTTP {exc.code} from {host}:{port}") from inner
    except urllib.error.URLError as exc:
        raise RpcError(
            f"cannot reach node at {host}:{port}: {exc.reason}"
        ) from exc
