from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from latcoin.cli.main import main
from latcoin.crypto.mldsa import liboqs_available
from latcoin.wallet.db import WalletDB

_requires_liboqs = pytest.mark.skipif(
    not liboqs_available(),
    reason="liboqs shared library not available",
)


def _run(argv: list[str]) -> dict:
    """Run the CLI and return the parsed JSON payload printed to stdout."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(argv)
    assert rc == 0, f"CLI command failed: {argv}\n{buf.getvalue()}"
    out = buf.getvalue().strip()
    return json.loads(out) if out.startswith("{") else {"raw": out}


def _wallet_first_address(datadir: Path, name: str) -> str:
    with WalletDB(datadir / "wallets" / f"{name}.sqlite") as db:
        return str(db.load_payload()["addresses"][0]["address"])


@pytest.fixture
def datadir(tmp_path: Path) -> Path:
    d = tmp_path / "node"
    _run(["--datadir", str(d), "node", "init", "--network", "devnet"])
    return d


def test_node_init_creates_expected_files(datadir: Path) -> None:
    assert (datadir / "config.json").exists()
    assert (datadir / "chainstate" / "meta.json").exists()
    assert (datadir / "chainstate" / "utxos.json").exists()
    assert (datadir / "mempool" / "entries.json").exists()
    assert (datadir / "wallets").is_dir()
    assert (datadir / "blocks").is_dir()


def test_node_status_reports_empty_chain(datadir: Path) -> None:
    from latcoin.node.rpc import start_rpc_server_in_thread

    server, _ = start_rpc_server_in_thread(datadir, host="127.0.0.1", port=0)
    port = server.server_address[1]
    try:
        body = _run(["--datadir", str(datadir), "node", "status", f"--rpc-port={port}"])
        status = body["result"]
        assert status["height"] == -1
        assert status["next_block_height"] == 0
        assert status["mempool_size"] == 0
        assert status["utxo_count"] == 0
    finally:
        server.shutdown()


def test_mine_once_credits_reward_address(datadir: Path) -> None:
    _run(["--datadir", str(datadir), "wallet", "new", "--name", "alice", "--network", "devnet"])
    _run(["--datadir", str(datadir), "wallet", "new-address", "--name", "alice"])
    alice = _wallet_first_address(datadir, "alice")

    mined = _run(["--datadir", str(datadir), "mine", "once", "--address", alice])
    assert mined["height"] == 0
    assert mined["reward_address"] == alice
    assert mined["coinbase_reward"] == 5_000_000_000  # 50 LAT devnet subsidy

    balance = _run(["--datadir", str(datadir), "wallet", "balance", "--name", "alice"])
    assert balance["confirmed_lats"] == 5_000_000_000


def test_send_flows_between_wallets_after_mine(datadir: Path) -> None:
    _run(["--datadir", str(datadir), "wallet", "new", "--name", "alice", "--network", "devnet"])
    _run(["--datadir", str(datadir), "wallet", "new-address", "--name", "alice"])
    _run(["--datadir", str(datadir), "wallet", "new", "--name", "bob", "--network", "devnet"])
    _run(["--datadir", str(datadir), "wallet", "new-address", "--name", "bob"])

    alice = _wallet_first_address(datadir, "alice")
    bob = _wallet_first_address(datadir, "bob")

    # Mine to alice so she has spendable funds
    _run(["--datadir", str(datadir), "mine", "once", "--address", alice])

    send = _run([
        "--datadir", str(datadir), "wallet", "send",
        "--name", "alice", "--to", bob,
        "--amount", "5", "--fee", "0.001",
    ])
    assert send["broadcasted"] is True
    assert send["mempool_size"] == 1
    assert send["amount_lats"] == 500_000_000
    assert send["fee_lats"] == 100_000
    assert send["change_lats"] == 5_000_000_000 - 500_000_000 - 100_000

    # Mine the pending tx to confirm it
    _run(["--datadir", str(datadir), "mine", "once"])

    alice_bal = _run(["--datadir", str(datadir), "wallet", "balance", "--name", "alice"])
    bob_bal = _run(["--datadir", str(datadir), "wallet", "balance", "--name", "bob"])

    assert alice_bal["confirmed_lats"] == 5_000_000_000 - 500_000_000 - 100_000
    assert bob_bal["confirmed_lats"] == 500_000_000


@_requires_liboqs
def test_ml_dsa_44_send_flow_end_to_end(datadir: Path) -> None:
    _run(["--datadir", str(datadir), "wallet", "new", "--name", "alice", "--network", "devnet"])
    _run([
        "--datadir", str(datadir),
        "wallet", "new-address", "--name", "alice",
        "--scheme", "ml-dsa-44",
    ])
    _run(["--datadir", str(datadir), "wallet", "new", "--name", "bob", "--network", "devnet"])
    _run([
        "--datadir", str(datadir),
        "wallet", "new-address", "--name", "bob",
        "--scheme", "ml-dsa-44",
    ])

    alice = _wallet_first_address(datadir, "alice")
    bob = _wallet_first_address(datadir, "bob")

    # Sanity: addresses carry the ML-DSA-44 scheme_id (0x0010) in their payload.
    assert alice.split("1", 1)[1].startswith("0010")
    assert bob.split("1", 1)[1].startswith("0010")

    _run(["--datadir", str(datadir), "mine", "once", "--address", alice])

    send = _run([
        "--datadir", str(datadir), "wallet", "send",
        "--name", "alice", "--to", bob,
        "--amount", "5", "--fee", "0.001",
    ])
    assert send["broadcasted"] is True
    assert send["mempool_size"] == 1
    assert send["amount_lats"] == 500_000_000
    assert send["fee_lats"] == 100_000

    _run(["--datadir", str(datadir), "mine", "once"])

    alice_bal = _run(["--datadir", str(datadir), "wallet", "balance", "--name", "alice"])
    bob_bal = _run(["--datadir", str(datadir), "wallet", "balance", "--name", "bob"])
    assert alice_bal["confirmed_lats"] == 5_000_000_000 - 500_000_000 - 100_000
    assert bob_bal["confirmed_lats"] == 500_000_000


def test_tx_build_sign_verify_pipeline(datadir: Path, tmp_path: Path) -> None:
    _run(["--datadir", str(datadir), "wallet", "new", "--name", "alice", "--network", "devnet"])
    _run(["--datadir", str(datadir), "wallet", "new-address", "--name", "alice"])
    _run(["--datadir", str(datadir), "wallet", "new", "--name", "bob", "--network", "devnet"])
    _run(["--datadir", str(datadir), "wallet", "new-address", "--name", "bob"])
    alice = _wallet_first_address(datadir, "alice")
    bob = _wallet_first_address(datadir, "bob")
    _run(["--datadir", str(datadir), "mine", "once", "--address", alice])

    unsigned = tmp_path / "unsigned.hex"
    signed = tmp_path / "signed.hex"

    build = _run([
        "--datadir", str(datadir), "tx", "build",
        "--wallet", "alice", "--to", bob,
        "--amount", "1", "--fee", "0.0001",
        "--out", str(unsigned),
    ])
    assert build["recipient_kind"] == "standard"
    assert unsigned.read_text().strip()

    _run([
        "--datadir", str(datadir), "tx", "sign",
        "--wallet", "alice", "--in", str(unsigned),
        "--out", str(signed),
    ])
    assert signed.read_text().strip() != unsigned.read_text().strip()

    verify = _run(["--datadir", str(datadir), "tx", "verify", str(signed)])
    assert verify["structure"]["valid"] is True
    assert verify["contextual"]["valid"] is True
    assert verify["contextual"]["fee"] == 10_000
