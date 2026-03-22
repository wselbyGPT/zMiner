from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import load_settings
from .protocol import (
    build_block,
    build_header,
    build_pow_input,
    header_hash_rpc_hex,
    header_meets_target,
    summarize_template,
)
from .rpc import ZebraRpc
from .solver import run_solver


def _write_artifact(out_dir: Path, name: str, data: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / name).write_text(data, encoding="utf-8")


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
    target_hex = str(template["target"])

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
    if solver.status != "ok":
        raise RuntimeError(f"solver did not return a solution: {solver.message or solver.status}")

    assert solver.nonce32 is not None
    assert solver.solution is not None

    header = build_header(template, nonce32=solver.nonce32, solution=solver.solution)
    block = build_block(template, nonce32=solver.nonce32, solution=solver.solution)
    pow_hash_hex = solver.pow_hash_hex or header_hash_rpc_hex(header)
    target_met = header_meets_target(header, target_hex)

    payload = {
        "template_summary": summarize_template(template),
        "pow_input_hex": pow_input.hex(),
        "target_hex": target_hex,
        "nonce32_hex": solver.nonce32.hex(),
        "solution_size": len(solver.solution),
        "pow_hash_hex": pow_hash_hex,
        "target_met": target_met,
        "checked_nonces": solver.checked_nonces,
        "solver_message": solver.message,
        "header_hex": header.hex(),
        "block_hex": block.hex(),
    }

    if args.write:
        out_dir = Path(args.write)
        _write_artifact(out_dir, "template_summary.json", json.dumps(payload["template_summary"], indent=2))
        _write_artifact(out_dir, "candidate_header.hex", payload["header_hex"] + "\n")
        _write_artifact(out_dir, "candidate_block.hex", payload["block_hex"] + "\n")
        _write_artifact(out_dir, "candidate_bundle.json", json.dumps(payload, indent=2))

    return payload


def cmd_candidate(args: argparse.Namespace) -> int:
    payload = _candidate_payload(args)
    print(json.dumps({
        "solution_size": payload["solution_size"],
        "nonce32_hex": payload["nonce32_hex"],
        "pow_hash_hex": payload["pow_hash_hex"],
        "target_met": payload["target_met"],
        "checked_nonces": payload["checked_nonces"],
        "header_bytes": len(bytes.fromhex(payload["header_hex"])),
        "block_bytes": len(bytes.fromhex(payload["block_hex"])),
    }, indent=2))
    return 0


def cmd_submit(args: argparse.Namespace) -> int:
    settings = load_settings()
    rpc = ZebraRpc(settings)
    payload = _candidate_payload(args)
    result = rpc.submitblock(payload["block_hex"])
    print(json.dumps({"submitblock_result": result}, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Zcash miner starter skeleton")
    sub = parser.add_subparsers(dest="command", required=True)

    p_template = sub.add_parser("template", help="Fetch and print getblocktemplate summary")
    p_template.set_defaults(func=cmd_template)

    for name, func in [("candidate", cmd_candidate), ("submit", cmd_submit)]:
        p = sub.add_parser(name, help=f"{name} using the configured solver")
        p.add_argument("--solver-mode", default="dummy", choices=["dummy", "none", "real"], help="solver mode")
        p.add_argument(
            "--max-nonces",
            default=16,
            type=int,
            help="how many 32-byte nonce values the real solver should scan before giving up",
        )
        p.add_argument(
            "--no-target",
            action="store_true",
            help="accept the first valid Equihash solution even if it does not meet nBits difficulty",
        )
        p.add_argument(
            "--start-nonce-hex",
            default="",
            help="optional starting 32-byte nonce in hex, interpreted as a little-endian counter",
        )
        p.add_argument("--write", default="", help="directory to write candidate artifacts")
        p.set_defaults(func=func)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
