from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    rpc_url: str
    rpc_cookie_path: Path
    rpc_disable_cookie_auth: bool
    solver_bin: str


def load_settings() -> Settings:
    cookie_default = Path.home() / ".cache" / "zebra" / ".cookie"
    return Settings(
        rpc_url=os.environ.get("ZCASH_RPC_URL", "http://127.0.0.1:18232/"),
        rpc_cookie_path=Path(
            os.path.expanduser(os.environ.get("ZCASH_RPC_COOKIE_PATH", str(cookie_default)))
        ),
        rpc_disable_cookie_auth=os.environ.get("ZCASH_RPC_DISABLE_COOKIE_AUTH", "0") in {"1", "true", "TRUE", "yes"},
        solver_bin=os.environ.get("ZCASH_SOLVER_BIN", "./solver/target/release/zk_equihash_solver"),
    )
