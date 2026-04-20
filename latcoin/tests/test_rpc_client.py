"""Tests for node.rpc_client and the cli rpc command."""
from __future__ import annotations

import json
import urllib.error
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from latcoin.node.rpc_client import RpcError, call_rpc


# ---------------------------------------------------------------------------
# Helpers — fake HTTP responses
# ---------------------------------------------------------------------------

def _fake_response(body: dict, status: int = 200):
    raw = json.dumps(body).encode("utf-8")
    resp = MagicMock()
    resp.read.return_value = raw
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _http_error(body: dict, code: int = 400):
    raw = json.dumps(body).encode("utf-8")
    exc = urllib.error.HTTPError(
        url="http://127.0.0.1:9338/rpc",
        code=code,
        msg="Bad Request",
        hdrs=MagicMock(),
        fp=BytesIO(raw),
    )
    exc.read = lambda: raw
    return exc


# ---------------------------------------------------------------------------
# call_rpc — unit tests (mocked urlopen)
# ---------------------------------------------------------------------------

class TestCallRpc:
    def test_returns_response_dict_on_success(self) -> None:
        ok_body = {"ok": True, "result": {"height": 5}}
        with patch("urllib.request.urlopen", return_value=_fake_response(ok_body)):
            result = call_rpc("status")
        assert result == ok_body

    def test_sends_correct_method_and_params(self) -> None:
        ok_body = {"ok": True, "result": {}}
        captured: list[urllib.request.Request] = []

        def _fake_open(req, timeout=None):
            captured.append(req)
            return _fake_response(ok_body)

        with patch("urllib.request.urlopen", side_effect=_fake_open):
            call_rpc("submit_tx", {"tx_hex": "deadbeef"}, host="10.0.0.1", port=1234)

        req = captured[0]
        assert req.full_url == "http://10.0.0.1:1234/rpc"
        payload = json.loads(req.data.decode())
        assert payload["method"] == "submit_tx"
        assert payload["params"]["tx_hex"] == "deadbeef"

    def test_empty_params_sends_empty_dict(self) -> None:
        ok_body = {"ok": True, "result": {}}
        captured: list = []

        def _fake_open(req, timeout=None):
            captured.append(json.loads(req.data.decode()))
            return _fake_response(ok_body)

        with patch("urllib.request.urlopen", side_effect=_fake_open):
            call_rpc("status")

        assert captured[0]["params"] == {}

    def test_none_params_sends_empty_dict(self) -> None:
        ok_body = {"ok": True, "result": {}}
        captured: list = []

        def _fake_open(req, timeout=None):
            captured.append(json.loads(req.data.decode()))
            return _fake_response(ok_body)

        with patch("urllib.request.urlopen", side_effect=_fake_open):
            call_rpc("status", None)

        assert captured[0]["params"] == {}

    def test_returns_error_dict_on_http_400(self) -> None:
        error_body = {"ok": False, "error": "unknown method"}
        with patch("urllib.request.urlopen", side_effect=_http_error(error_body, 400)):
            result = call_rpc("bad_method")
        assert result["ok"] is False
        assert "unknown method" in result["error"]

    def test_raises_rpc_error_on_connection_refused(self) -> None:
        url_err = urllib.error.URLError(reason=ConnectionRefusedError())
        with patch("urllib.request.urlopen", side_effect=url_err):
            with pytest.raises(RpcError, match="cannot reach node"):
                call_rpc("status")

    def test_raises_rpc_error_on_timeout(self) -> None:
        url_err = urllib.error.URLError(reason="timed out")
        with patch("urllib.request.urlopen", side_effect=url_err):
            with pytest.raises(RpcError):
                call_rpc("status")

    def test_uses_default_host_and_port(self) -> None:
        ok_body = {"ok": True, "result": {}}
        captured: list = []

        def _fake_open(req, timeout=None):
            captured.append(req.full_url)
            return _fake_response(ok_body)

        with patch("urllib.request.urlopen", side_effect=_fake_open):
            call_rpc("status")

        assert captured[0] == "http://127.0.0.1:9338/rpc"

    def test_passes_timeout_to_urlopen(self) -> None:
        ok_body = {"ok": True, "result": {}}
        captured: list = []

        def _fake_open(req, timeout=None):
            captured.append(timeout)
            return _fake_response(ok_body)

        with patch("urllib.request.urlopen", side_effect=_fake_open):
            call_rpc("status", timeout=42.0)

        assert captured[0] == 42.0

    def test_http_error_with_unreadable_body_raises_rpc_error(self) -> None:
        exc = urllib.error.HTTPError(
            url="http://127.0.0.1:9338/rpc",
            code=500,
            msg="Internal Server Error",
            hdrs=MagicMock(),
            fp=BytesIO(b"not json"),
        )
        exc.read = lambda: b"not json"
        with patch("urllib.request.urlopen", side_effect=exc):
            with pytest.raises(RpcError, match="HTTP 500"):
                call_rpc("status")


# ---------------------------------------------------------------------------
# _parse_rpc_params — unit tests
# ---------------------------------------------------------------------------

class TestParseRpcParams:
    def _parse(self, *pairs: str):
        from latcoin.cli.main import _parse_rpc_params
        return _parse_rpc_params(list(pairs))

    def test_empty_list_returns_empty_dict(self) -> None:
        assert self._parse() == {}

    def test_string_value_stays_string(self) -> None:
        assert self._parse("name=alice") == {"name": "alice"}

    def test_integer_value_decoded(self) -> None:
        assert self._parse("count=5") == {"count": 5}

    def test_float_value_decoded(self) -> None:
        result = self._parse("amount=1.5")
        assert result == {"amount": 1.5}
        assert isinstance(result["amount"], float)

    def test_bool_true_decoded(self) -> None:
        assert self._parse("flag=true") == {"flag": True}

    def test_bool_false_decoded(self) -> None:
        assert self._parse("flag=false") == {"flag": False}

    def test_null_decoded_to_none(self) -> None:
        assert self._parse("x=null") == {"x": None}

    def test_json_string_decoded(self) -> None:
        assert self._parse('name="alice"') == {"name": "alice"}

    def test_multiple_params(self) -> None:
        result = self._parse("name=bob", "amount=2.0", "flag=true")
        assert result == {"name": "bob", "amount": 2.0, "flag": True}

    def test_value_with_equals_sign(self) -> None:
        # Only splits on the first '='
        result = self._parse("url=http://a=b")
        assert result == {"url": "http://a=b"}

    def test_missing_equals_raises(self) -> None:
        with pytest.raises(SystemExit):
            self._parse("noequals")

    def test_empty_key_raises(self) -> None:
        with pytest.raises(SystemExit):
            self._parse("=value")

    def test_empty_string_value_stays_string(self) -> None:
        assert self._parse("key=") == {"key": ""}


# ---------------------------------------------------------------------------
# cmd_rpc_call — integration against a real RpcServer
# ---------------------------------------------------------------------------

def _init_datadir(datadir: Path) -> None:
    """Create the minimal files that NodeFacade needs."""
    import json as _json
    from latcoin.chain.mempool import Mempool
    from latcoin.chain.utxo import UtxoSet
    from latcoin.codec.constants import NETWORK_DEVNET
    from latcoin.validation.pow import initial_pow_state

    (datadir / "blocks").mkdir(parents=True)
    (datadir / "chainstate").mkdir(parents=True)
    (datadir / "mempool").mkdir(parents=True)

    ps = initial_pow_state(NETWORK_DEVNET)
    config = {
        "network": "devnet",
        "network_id": NETWORK_DEVNET,
        "dev_miner": {"address": "dlat1test000"},
    }
    meta = {
        "next_block_height": 0,
        "tip_hash": "00" * 32,
        "block_count": 0,
        "coinbase_maturity": 0,
        "pow": {
            "current_bits": ps.current_bits,
            "last_retarget_height": ps.last_retarget_height,
            "last_retarget_timestamp": ps.last_retarget_timestamp,
            "tip_timestamp": ps.tip_timestamp,
        },
    }
    (datadir / "config.json").write_text(_json.dumps(config), encoding="utf-8")
    (datadir / "chainstate" / "meta.json").write_text(_json.dumps(meta), encoding="utf-8")
    UtxoSet().save_json(datadir / "chainstate" / "utxos.json")
    Mempool().save_json(datadir / "mempool" / "entries.json")


class TestCallRpcIntegration:
    def test_status_returns_ok(self, tmp_path: Path) -> None:
        from latcoin.node.rpc import start_rpc_server_in_thread

        _init_datadir(tmp_path)
        server, thread = start_rpc_server_in_thread(tmp_path, host="127.0.0.1", port=0)
        port = server.server_address[1]
        try:
            result = call_rpc("status", host="127.0.0.1", port=port)
            assert result["ok"] is True
            assert "height" in result["result"]
        finally:
            server.shutdown()

    def test_unknown_method_returns_ok_false(self, tmp_path: Path) -> None:
        from latcoin.node.rpc import start_rpc_server_in_thread

        _init_datadir(tmp_path)
        server, thread = start_rpc_server_in_thread(tmp_path, host="127.0.0.1", port=0)
        port = server.server_address[1]
        try:
            result = call_rpc("does_not_exist", host="127.0.0.1", port=port)
            assert result["ok"] is False
            assert "error" in result
        finally:
            server.shutdown()

    def test_mempool_returns_list(self, tmp_path: Path) -> None:
        from latcoin.node.rpc import start_rpc_server_in_thread

        _init_datadir(tmp_path)
        server, _ = start_rpc_server_in_thread(tmp_path, host="127.0.0.1", port=0)
        port = server.server_address[1]
        try:
            result = call_rpc("mempool", host="127.0.0.1", port=port)
            assert result["ok"] is True
            assert isinstance(result["result"]["entries"], list)
        finally:
            server.shutdown()


# ---------------------------------------------------------------------------
# cmd_rpc_call — CLI integration
# ---------------------------------------------------------------------------

class TestCmdRpcCall:
    def _run(self, *args: str):
        from latcoin.cli.main import main
        return main(["rpc", *args])

    def test_calls_method_and_prints_result(self, tmp_path: Path, capsys) -> None:
        from latcoin.node.rpc import start_rpc_server_in_thread

        _init_datadir(tmp_path)
        server, _ = start_rpc_server_in_thread(tmp_path, host="127.0.0.1", port=0)
        port = server.server_address[1]
        try:
            rc = self._run(
                f"--rpc-port={port}", "status",
            )
            captured = capsys.readouterr()
            assert rc == 0
            body = json.loads(captured.out)
            assert body["ok"] is True
        finally:
            server.shutdown()

    def test_returns_1_on_connection_refused(self, capsys) -> None:
        # Port 1 is almost certainly not open
        rc = self._run("--rpc-port=1", "--timeout=1", "status")
        assert rc == 1
        captured = capsys.readouterr()
        assert "error" in captured.err

    def test_returns_1_when_ok_false(self, tmp_path: Path, capsys) -> None:
        from latcoin.node.rpc import start_rpc_server_in_thread

        _init_datadir(tmp_path)
        server, _ = start_rpc_server_in_thread(tmp_path, host="127.0.0.1", port=0)
        port = server.server_address[1]
        try:
            rc = self._run(f"--rpc-port={port}", "nonexistent_method")
            assert rc == 1
        finally:
            server.shutdown()
