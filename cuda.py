from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CudaProbeResult:
    status: str
    cuda_available: bool
    device_count: int
    raw: dict


@dataclass(frozen=True)
class CudaCheckResult:
    status: str
    processed_count: int
    first_match_index: int | None
    first_match_hash_hex: str | None
    raw: dict


class CudaWorkerError(RuntimeError):
    pass


def _run_json_command(args: list[str]) -> dict:
    proc = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise CudaWorkerError(
            f"cuda worker failed with code {proc.returncode}: {proc.stderr.decode('utf-8', errors='replace')}"
        )
    try:
        return json.loads(proc.stdout.decode('utf-8'))
    except json.JSONDecodeError as exc:
        raise CudaWorkerError(f"cuda worker returned invalid JSON: {proc.stdout!r}") from exc


def probe_cuda(cuda_solver_bin: str) -> CudaProbeResult:
    obj = _run_json_command([cuda_solver_bin, 'probe'])
    return CudaProbeResult(
        status=str(obj.get('status', 'error')),
        cuda_available=bool(obj.get('cuda_available', False)),
        device_count=int(obj.get('device_count', 0)),
        raw=obj,
    )


def check_headers_cuda(cuda_solver_bin: str, headers: list[bytes], target_hex: str) -> CudaCheckResult:
    if not headers:
        raise ValueError('headers must not be empty')
    header_bytes = len(headers[0])
    if header_bytes <= 0:
        raise ValueError('header size must be positive')
    if len(target_hex) != 64:
        raise ValueError('target_hex must be a 32-byte hex string')
    if any(len(header) != header_bytes for header in headers):
        raise ValueError('all headers must have identical length for GPU batching')

    with tempfile.TemporaryDirectory(prefix='zk_cuda_') as tmp:
        path = Path(tmp) / 'headers.bin'
        path.write_bytes(b''.join(headers))
        obj = _run_json_command(
            [
                cuda_solver_bin,
                'check-headers',
                '--headers-file',
                str(path),
                '--header-bytes',
                str(header_bytes),
                '--target-hex',
                target_hex,
            ]
        )

    first_match_index = obj.get('first_match_index')
    return CudaCheckResult(
        status=str(obj.get('status', 'error')),
        processed_count=int(obj.get('processed_count', 0)),
        first_match_index=int(first_match_index) if first_match_index is not None else None,
        first_match_hash_hex=obj.get('first_match_hash_hex'),
        raw=obj,
    )
