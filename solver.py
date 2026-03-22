from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class SolverResult:
    status: str
    nonce32: bytes | None = None
    solution: bytes | None = None
    message: str | None = None
    pow_hash_hex: str | None = None
    checked_nonces: int | None = None
    target_met: bool | None = None


class SolverError(RuntimeError):
    pass


def run_solver(
    solver_bin: str,
    *,
    mode: str,
    template: dict,
    pow_input: bytes,
    target_hex: str,
    max_nonces: int = 16,
    require_target: bool = True,
    start_nonce_hex: str | None = None,
) -> SolverResult:
    payload = {
        "mode": mode,
        "template": {
            "height": template.get("height"),
            "version": template.get("version"),
            "previousblockhash": template.get("previousblockhash"),
            "bits": template.get("bits"),
            "curtime": template.get("curtime"),
        },
        "pow_input_hex": pow_input.hex(),
        "target_hex": target_hex,
        "max_nonces": int(max_nonces),
        "require_target": bool(require_target),
    }
    if start_nonce_hex:
        payload["start_nonce_hex"] = start_nonce_hex

    proc = subprocess.run(
        [solver_bin],
        input=json.dumps(payload).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    if proc.returncode != 0:
        raise SolverError(
            f"solver failed with code {proc.returncode}: {proc.stderr.decode('utf-8', errors='replace')}"
        )

    try:
        obj = json.loads(proc.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise SolverError(f"solver returned invalid JSON: {proc.stdout!r}") from exc

    status = obj.get("status", "error")
    if status != "ok":
        return SolverResult(
            status=status,
            message=obj.get("message"),
            pow_hash_hex=obj.get("pow_hash_hex"),
            checked_nonces=obj.get("checked_nonces"),
            target_met=obj.get("target_met"),
        )

    nonce_hex = obj.get("nonce32_hex")
    solution_hex = obj.get("solution_hex")
    if not isinstance(nonce_hex, str) or not isinstance(solution_hex, str):
        raise SolverError("solver returned ok without nonce32_hex / solution_hex")

    nonce32 = bytes.fromhex(nonce_hex)
    solution = bytes.fromhex(solution_hex)
    return SolverResult(
        status="ok",
        nonce32=nonce32,
        solution=solution,
        message=obj.get("message"),
        pow_hash_hex=obj.get("pow_hash_hex"),
        checked_nonces=obj.get("checked_nonces"),
        target_met=obj.get("target_met"),
    )
