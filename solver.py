from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class SolverCandidate:
    nonce32: bytes
    solution: bytes
    pow_hash_hex: str | None = None
    target_met: bool | None = None


@dataclass(frozen=True)
class SolverResult:
    status: str
    nonce32: bytes | None = None
    solution: bytes | None = None
    message: str | None = None
    pow_hash_hex: str | None = None
    checked_nonces: int | None = None
    target_met: bool | None = None


@dataclass(frozen=True)
class SolverBatchResult:
    status: str
    candidates: list[SolverCandidate]
    message: str | None = None
    checked_nonces: int | None = None


class SolverError(RuntimeError):
    pass


def _run_solver_payload(solver_bin: str, payload: dict) -> dict:
    proc = subprocess.run(
        [solver_bin],
        input=json.dumps(payload).encode('utf-8'),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    if proc.returncode != 0:
        raise SolverError(
            f"solver failed with code {proc.returncode}: {proc.stderr.decode('utf-8', errors='replace')}"
        )

    try:
        return json.loads(proc.stdout.decode('utf-8'))
    except json.JSONDecodeError as exc:
        raise SolverError(f"solver returned invalid JSON: {proc.stdout!r}") from exc


def _base_payload(
    *,
    mode: str,
    template: dict,
    pow_input: bytes,
    target_hex: str,
    max_nonces: int,
    require_target: bool,
    start_nonce_hex: str | None,
) -> dict:
    payload = {
        'mode': mode,
        'template': {
            'height': template.get('height'),
            'version': template.get('version'),
            'previousblockhash': template.get('previousblockhash'),
            'bits': template.get('bits'),
            'curtime': template.get('curtime'),
        },
        'pow_input_hex': pow_input.hex(),
        'target_hex': target_hex,
        'max_nonces': int(max_nonces),
        'require_target': bool(require_target),
    }
    if start_nonce_hex:
        payload['start_nonce_hex'] = start_nonce_hex
    return payload


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
    payload = _base_payload(
        mode=mode,
        template=template,
        pow_input=pow_input,
        target_hex=target_hex,
        max_nonces=max_nonces,
        require_target=require_target,
        start_nonce_hex=start_nonce_hex,
    )
    obj = _run_solver_payload(solver_bin, payload)

    status = obj.get('status', 'error')
    if status != 'ok':
        return SolverResult(
            status=status,
            message=obj.get('message'),
            pow_hash_hex=obj.get('pow_hash_hex'),
            checked_nonces=obj.get('checked_nonces'),
            target_met=obj.get('target_met'),
        )

    nonce_hex = obj.get('nonce32_hex')
    solution_hex = obj.get('solution_hex')
    if not isinstance(nonce_hex, str) or not isinstance(solution_hex, str):
        raise SolverError('solver returned ok without nonce32_hex / solution_hex')

    return SolverResult(
        status='ok',
        nonce32=bytes.fromhex(nonce_hex),
        solution=bytes.fromhex(solution_hex),
        message=obj.get('message'),
        pow_hash_hex=obj.get('pow_hash_hex'),
        checked_nonces=obj.get('checked_nonces'),
        target_met=obj.get('target_met'),
    )


def run_solver_batch(
    solver_bin: str,
    *,
    template: dict,
    pow_input: bytes,
    target_hex: str,
    max_nonces: int = 64,
    max_solutions: int = 16,
    require_target: bool = False,
    start_nonce_hex: str | None = None,
) -> SolverBatchResult:
    payload = _base_payload(
        mode='real_batch',
        template=template,
        pow_input=pow_input,
        target_hex=target_hex,
        max_nonces=max_nonces,
        require_target=require_target,
        start_nonce_hex=start_nonce_hex,
    )
    payload['max_solutions'] = int(max_solutions)
    obj = _run_solver_payload(solver_bin, payload)

    status = str(obj.get('status', 'error'))
    raw_candidates = obj.get('candidates') or []
    candidates: list[SolverCandidate] = []
    for item in raw_candidates:
        nonce_hex = item.get('nonce32_hex')
        solution_hex = item.get('solution_hex')
        if not isinstance(nonce_hex, str) or not isinstance(solution_hex, str):
            raise SolverError('solver batch response contained malformed candidate entry')
        candidates.append(
            SolverCandidate(
                nonce32=bytes.fromhex(nonce_hex),
                solution=bytes.fromhex(solution_hex),
                pow_hash_hex=item.get('pow_hash_hex'),
                target_met=item.get('target_met'),
            )
        )

    return SolverBatchResult(
        status=status,
        candidates=candidates,
        message=obj.get('message'),
        checked_nonces=obj.get('checked_nonces'),
    )
