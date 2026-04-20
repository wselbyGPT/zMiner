from __future__ import annotations

from pathlib import Path
from typing import Any

from latcoin.chain.mempool import Mempool
from latcoin.codec.block import decode_block
from latcoin.codec.tx import txid
from latcoin.crypto.signatures import scheme_id_to_name
from latcoin.validation.tx_context import UtxoEntry
from latcoin.wallet.scanner import OwnedUtxo, scan_wallet_owned_utxos


def _is_coinbase_tx(tx) -> bool:
    if len(tx.body.inputs) != 1:
        return False
    txin = tx.body.inputs[0]
    return txin.prev_txid == (b"\x00" * 32) and txin.prev_index == 0xFFFFFFFF


def _history_kind(*, spent: int, received: int, is_coinbase: bool) -> str:
    if is_coinbase and received > 0 and spent == 0:
        return "coinbase"
    if spent == 0 and received > 0:
        return "receive"
    if spent > 0 and received == 0:
        return "send"
    if spent > 0 and received > 0:
        return "self-transfer" if received >= spent else "send"
    return "other"


def _format_lats(lats: int) -> str:
    whole = abs(lats) // 100_000_000
    frac = abs(lats) % 100_000_000
    sign = "-" if lats < 0 else ""
    if frac == 0:
        return f"{sign}{whole}"
    frac_text = f"{frac:08d}".rstrip("0")
    return f"{sign}{whole}.{frac_text}"


def _out_meta_from_owned(row: OwnedUtxo) -> dict[str, Any]:
    return {
        "index": row.entry.index,
        "amount": row.entry.amount,
        "amount_lat": _format_lats(row.entry.amount),
        "scheme_id": row.entry.scheme_id,
        "scheme_name": scheme_id_to_name(row.entry.scheme_id),
        "address": row.source_address,
        "ownership": row.ownership,
    }


def _candidate_outputs(tx, *, created_height: int) -> list[UtxoEntry]:
    txid_bytes = txid(tx)
    return [
        UtxoEntry(
            txid=txid_bytes,
            index=index,
            amount=txout.amount,
            lock_type=txout.lock_type,
            scheme_id=txout.scheme_id,
            lock_data=txout.lock_data,
            created_height=created_height,
            is_coinbase=_is_coinbase_tx(tx),
            network_id=tx.body.network_id,
        )
        for index, txout in enumerate(tx.body.outputs)
    ]


def rebuild_wallet_history(datadir: Path, wallet_payload: dict[str, Any]) -> list[dict[str, Any]]:
    owned_outpoints: dict[tuple[bytes, int], dict[str, Any]] = {}
    history: list[dict[str, Any]] = []

    blocks_dir = Path(datadir) / "blocks"
    for block_path in sorted(blocks_dir.glob("*.bin")):
        block = decode_block(block_path.read_bytes())
        for tx in block.txs:
            txid_bytes = txid(tx)
            spent_amount = 0
            received_amount = 0
            spent_inputs: list[dict[str, Any]] = []
            received_outputs: list[dict[str, Any]] = []

            for txin in tx.body.inputs:
                prior = owned_outpoints.pop((txin.prev_txid, txin.prev_index), None)
                if prior is not None:
                    spent_amount += int(prior["amount"])
                    spent_inputs.append(
                        {
                            "prev_txid": txin.prev_txid.hex(),
                            "prev_index": txin.prev_index,
                            "amount": int(prior["amount"]),
                            "amount_lat": prior["amount_lat"],
                            "address": prior["address"],
                            "scheme_id": prior["scheme_id"],
                            "scheme_name": prior["scheme_name"],
                            "ownership": prior.get("ownership"),
                        }
                    )

            seen_outpoints: set[tuple[bytes, int]] = set()
            for row in scan_wallet_owned_utxos(wallet_payload, _candidate_outputs(tx, created_height=block.header.height)):
                outpoint = (row.entry.txid, row.entry.index)
                if outpoint in seen_outpoints:
                    continue
                seen_outpoints.add(outpoint)
                received_amount += row.entry.amount
                out_meta = _out_meta_from_owned(row)
                received_outputs.append(out_meta)
                owned_outpoints[outpoint] = dict(out_meta)

            if spent_amount or received_amount:
                history.append(
                    {
                        "status": "confirmed",
                        "block_height": block.header.height,
                        "txid": txid_bytes.hex(),
                        "kind": _history_kind(spent=spent_amount, received=received_amount, is_coinbase=_is_coinbase_tx(tx)),
                        "debit_lats": spent_amount,
                        "debit_lat": _format_lats(spent_amount),
                        "credit_lats": received_amount,
                        "credit_lat": _format_lats(received_amount),
                        "net_lats": received_amount - spent_amount,
                        "net_lat": _format_lats(received_amount - spent_amount),
                        "spent_inputs": spent_inputs,
                        "received_outputs": received_outputs,
                    }
                )

    mempool_path = Path(datadir) / "mempool" / "entries.json"
    if mempool_path.exists():
        mempool = Mempool.load_json(mempool_path)
        for entry in mempool.sorted_entries_for_block():
            tx = entry.tx
            txid_bytes = txid(tx)
            spent_amount = 0
            received_amount = 0
            spent_inputs: list[dict[str, Any]] = []
            received_outputs: list[dict[str, Any]] = []

            for txin in tx.body.inputs:
                prior = owned_outpoints.get((txin.prev_txid, txin.prev_index))
                if prior is not None:
                    spent_amount += int(prior["amount"])
                    spent_inputs.append(
                        {
                            "prev_txid": txin.prev_txid.hex(),
                            "prev_index": txin.prev_index,
                            "amount": int(prior["amount"]),
                            "amount_lat": prior["amount_lat"],
                            "address": prior["address"],
                            "scheme_id": prior["scheme_id"],
                            "scheme_name": prior["scheme_name"],
                            "ownership": prior.get("ownership"),
                        }
                    )

            seen_outpoints: set[tuple[bytes, int]] = set()
            for row in scan_wallet_owned_utxos(wallet_payload, _candidate_outputs(tx, created_height=10**9)):
                outpoint = (row.entry.txid, row.entry.index)
                if outpoint in seen_outpoints:
                    continue
                seen_outpoints.add(outpoint)
                received_amount += row.entry.amount
                received_outputs.append(_out_meta_from_owned(row))

            if spent_amount or received_amount:
                history.append(
                    {
                        "status": "mempool",
                        "block_height": None,
                        "txid": txid_bytes.hex(),
                        "kind": _history_kind(spent=spent_amount, received=received_amount, is_coinbase=False),
                        "debit_lats": spent_amount,
                        "debit_lat": _format_lats(spent_amount),
                        "credit_lats": received_amount,
                        "credit_lat": _format_lats(received_amount),
                        "net_lats": received_amount - spent_amount,
                        "net_lat": _format_lats(received_amount - spent_amount),
                        "spent_inputs": spent_inputs,
                        "received_outputs": received_outputs,
                    }
                )

    history.sort(key=lambda row: ((row["status"] != "confirmed"), row["block_height"] if row["block_height"] is not None else 10**12, row["txid"]))
    return history
