from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import load_settings
from .cuda import CudaWorkerError, check_headers_cuda, probe_cuda
from .protocol import (
    build_block,
    build_header,
    build_pow_input,
    header_hash_rpc_hex,
    header_meets_target,
    summarize_template,
)
from .rpc import ZebraRpc
from .solver import run_solver, run_solver_batch


def _write_artifact(out_dir: Path, name: str, data: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / name).write_text(data, encoding='utf-8')


def cmd_template(args: argparse.Namespace) -> int:
    settings = load_settings()
    rpc = ZebraRpc(settings)
    template = rpc.getblocktemplate()
    print(json.dumps(summarize_template(template), indent=2))
    return 0


def _candidate_payload(args: argparse.Namespace) -> dict:
    settings = load_settings()
    rpc = ZebraRpc(settings)
    template = rpc.getblocktemplate()
    pow_input = build_pow_input(template)
    target_hex = str(template['target'])

    solver = run_solver(
        settings.solver_bin,
        mode=args.solver_mode,
        template=template,
        pow_input=pow_input,
        target_hex=target_hex,
        max_nonces=args.max_nonces,
        require_target=not args.no_target,
        start_nonce_hex=args.start_nonce_hex or None,
    )
    if solver.status != 'ok':
        raise RuntimeError(f"solver did not return a solution: {solver.message or solver.status}")

    assert solver.nonce32 is not None
    assert solver.solution is not None

    header = build_header(template, nonce32=solver.nonce32, solution=solver.solution)
    block = build_block(template, nonce32=solver.nonce32, solution=solver.solution)
    pow_hash_hex = solver.pow_hash_hex or header_hash_rpc_hex(header)
    target_met = header_meets_target(header, target_hex)

    payload = {
        'mode': 'single',
        'template_summary': summarize_template(template),
        'pow_input_hex': pow_input.hex(),
        'target_hex': target_hex,
        'nonce32_hex': solver.nonce32.hex(),
        'solution_size': len(solver.solution),
        'pow_hash_hex': pow_hash_hex,
        'target_met': target_met,
        'checked_nonces': solver.checked_nonces,
        'solver_message': solver.message,
        'header_hex': header.hex(),
        'block_hex': block.hex(),
    }

    if args.write:
        out_dir = Path(args.write)
        _write_artifact(out_dir, 'template_summary.json', json.dumps(payload['template_summary'], indent=2))
        _write_artifact(out_dir, 'candidate_header.hex', payload['header_hex'] + "\n")
        _write_artifact(out_dir, 'candidate_block.hex', payload['block_hex'] + "\n")
        _write_artifact(out_dir, 'candidate_bundle.json', json.dumps(payload, indent=2))

    return payload


def _select_cpu_match(headers: list[bytes], target_hex: str) -> tuple[int | None, str | None]:
    for index, header in enumerate(headers):
        if header_meets_target(header, target_hex):
            return index, header_hash_rpc_hex(header)
    return None, None


def _hybrid_candidate_payload(args: argparse.Namespace) -> dict:
    settings = load_settings()
    rpc = ZebraRpc(settings)
    template = rpc.getblocktemplate()
    pow_input = build_pow_input(template)
    target_hex = str(template['target'])

    batch = run_solver_batch(
        settings.solver_bin,
        template=template,
        pow_input=pow_input,
        target_hex=target_hex,
        max_nonces=args.max_nonces,
        max_solutions=args.max_solutions,
        require_target=False,
        start_nonce_hex=args.start_nonce_hex or None,
    )
    if not batch.candidates:
        raise RuntimeError(f"solver did not return any valid Equihash solutions: {batch.message or batch.status}")

    headers = [build_header(template, nonce32=item.nonce32, solution=item.solution) for item in batch.candidates]

    gpu_result = None
    selected_index = None
    selected_hash_hex = None
    selection_source = 'cpu'

    try:
        gpu_result = check_headers_cuda(settings.cuda_solver_bin, headers, target_hex)
        selected_index = gpu_result.first_match_index
        selected_hash_hex = gpu_result.first_match_hash_hex
        selection_source = 'cuda'
    except CudaWorkerError as exc:
        if not args.cpu_fallback:
            raise RuntimeError(str(exc)) from exc

    if selected_index is None:
        selected_index, selected_hash_hex = _select_cpu_match(headers, target_hex)
        selection_source = 'cpu'

    if selected_index is None:
        if not args.no_target:
            raise RuntimeError(
                'hybrid batch produced valid Equihash solutions but none met target in the requested nonce window'
            )
        selected_index = 0
        selected_hash_hex = header_hash_rpc_hex(headers[0])
        selection_source = 'first-valid'

    chosen = batch.candidates[selected_index]
    chosen_header = headers[selected_index]
    chosen_block = build_block(template, nonce32=chosen.nonce32, solution=chosen.solution)

    payload = {
        'mode': 'hybrid',
        'template_summary': summarize_template(template),
        'pow_input_hex': pow_input.hex(),
        'target_hex': target_hex,
        'nonce32_hex': chosen.nonce32.hex(),
        'solution_size': len(chosen.solution),
        'pow_hash_hex': selected_hash_hex or header_hash_rpc_hex(chosen_header),
        'target_met': header_meets_target(chosen_header, target_hex),
        'checked_nonces': batch.checked_nonces,
        'solver_message': batch.message,
        'selection_source': selection_source,
        'batch_candidates': len(batch.candidates),
        'selected_index': selected_index,
        'header_hex': chosen_header.hex(),
        'block_hex': chosen_block.hex(),
        'cuda': gpu_result.raw if gpu_result is not None else None,
    }

    if args.write:
        out_dir = Path(args.write)
        _write_artifact(out_dir, 'template_summary.json', json.dumps(payload['template_summary'], indent=2))
        _write_artifact(out_dir, 'candidate_header.hex', payload['header_hex'] + "\n")
        _write_artifact(out_dir, 'candidate_block.hex', payload['block_hex'] + "\n")
        _write_artifact(out_dir, 'candidate_bundle.json', json.dumps(payload, indent=2))

    return payload


def cmd_candidate(args: argparse.Namespace) -> int:
    payload = _candidate_payload(args)
    print(json.dumps({
        'mode': payload['mode'],
        'solution_size': payload['solution_size'],
        'nonce32_hex': payload['nonce32_hex'],
        'pow_hash_hex': payload['pow_hash_hex'],
        'target_met': payload['target_met'],
        'checked_nonces': payload['checked_nonces'],
        'header_bytes': len(bytes.fromhex(payload['header_hex'])),
        'block_bytes': len(bytes.fromhex(payload['block_hex'])),
    }, indent=2))
    return 0


def cmd_submit(args: argparse.Namespace) -> int:
    settings = load_settings()
    rpc = ZebraRpc(settings)
    payload = _candidate_payload(args)
    result = rpc.submitblock(payload['block_hex'])
    print(json.dumps({'submitblock_result': result}, indent=2))
    return 0


def cmd_candidate_hybrid(args: argparse.Namespace) -> int:
    payload = _hybrid_candidate_payload(args)
    print(json.dumps({
        'mode': payload['mode'],
        'selection_source': payload['selection_source'],
        'batch_candidates': payload['batch_candidates'],
        'selected_index': payload['selected_index'],
        'solution_size': payload['solution_size'],
        'nonce32_hex': payload['nonce32_hex'],
        'pow_hash_hex': payload['pow_hash_hex'],
        'target_met': payload['target_met'],
        'checked_nonces': payload['checked_nonces'],
        'header_bytes': len(bytes.fromhex(payload['header_hex'])),
        'block_bytes': len(bytes.fromhex(payload['block_hex'])),
    }, indent=2))
    return 0


def cmd_submit_hybrid(args: argparse.Namespace) -> int:
    settings = load_settings()
    rpc = ZebraRpc(settings)
    payload = _hybrid_candidate_payload(args)
    result = rpc.submitblock(payload['block_hex'])
    print(json.dumps({'submitblock_result': result}, indent=2))
    return 0


def cmd_cuda_probe(args: argparse.Namespace) -> int:
    settings = load_settings()
    probe = probe_cuda(settings.cuda_solver_bin)
    print(json.dumps(probe.raw, indent=2))
    return 0 if probe.cuda_available else 1


def _add_mining_args(p: argparse.ArgumentParser, *, include_hybrid: bool = False) -> None:
    if include_hybrid:
        p.add_argument('--max-solutions', default=8, type=int, help='max valid Equihash solutions to batch')
        p.add_argument(
            '--cpu-fallback',
            action='store_true',
            help='fallback to CPU target checks if the CUDA worker is unavailable',
        )
    else:
        p.add_argument('--solver-mode', default='dummy', choices=['dummy', 'none', 'real'], help='solver mode')
    p.add_argument(
        '--max-nonces',
        default=16,
        type=int,
        help='how many 32-byte nonce values the solver should scan before giving up',
    )
    p.add_argument(
        '--no-target',
        action='store_true',
        help='accept the first valid Equihash solution even if it does not meet nBits difficulty',
    )
    p.add_argument(
        '--start-nonce-hex',
        default='',
        help='optional starting 32-byte nonce in hex, interpreted as a little-endian counter',
    )
    p.add_argument('--write', default='', help='directory to write candidate artifacts')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Zcash miner starter skeleton')
    sub = parser.add_subparsers(dest='command', required=True)

    p_template = sub.add_parser('template', help='Fetch and print getblocktemplate summary')
    p_template.set_defaults(func=cmd_template)

    p_cuda = sub.add_parser('cuda-probe', help='Inspect CUDA devices through the experimental worker')
    p_cuda.set_defaults(func=cmd_cuda_probe)

    for name, func in [('candidate', cmd_candidate), ('submit', cmd_submit)]:
        p = sub.add_parser(name, help=f'{name} using the configured solver')
        _add_mining_args(p, include_hybrid=False)
        p.set_defaults(func=func)

    for name, func in [('candidate-hybrid', cmd_candidate_hybrid), ('submit-hybrid', cmd_submit_hybrid)]:
        p = sub.add_parser(name, help=f'{name} using CPU Equihash batching + CUDA target checks')
        _add_mining_args(p, include_hybrid=True)
        p.set_defaults(func=func)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == '__main__':
    raise SystemExit(main())
