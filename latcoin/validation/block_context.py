from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from latcoin.codec.block import Block, block_hash
from latcoin.codec.constants import MAX_MONEY
from latcoin.validation.block_structure import validate_block_structure
from latcoin.validation.errors import BlockValidationError
from latcoin.validation.pow import hash_meets_target
from latcoin.validation.tx_context import ChainContext, UtxoEntry, validate_tx_against_utxos
from latcoin.validation.tx_structure import validate_tx_structure

COINBASE_MATURITY = 100
DEFAULT_BLOCK_SUBSIDY = 50 * 100_000_000


@dataclass(frozen=True, slots=True)
class BlockContextResult:
    total_fees: int
    spent_outpoints: list[tuple[bytes, int]]
    created_utxos: list[UtxoEntry]


@dataclass(frozen=True, slots=True)
class BlockChainContext:
    network_id: int
    current_height: int
    median_time_past: int
    expected_prev_block_hash: bytes | None = None
    coinbase_maturity: int = COINBASE_MATURITY
    expected_bits: int | None = None


def _raise(msg: str) -> None:
    raise BlockValidationError(msg)


def _is_coinbase_tx(tx) -> bool:
    if len(tx.body.inputs) != 1:
        return False
    txin = tx.body.inputs[0]
    return txin.prev_txid == (b"\x00" * 32) and txin.prev_index == 0xFFFFFFFF


def block_subsidy(height: int) -> int:
    if height < 0:
        _raise("block height must be non-negative")
    return DEFAULT_BLOCK_SUBSIDY


def _checked_add(total: int, value: int, label: str) -> int:
    total += value
    if total > MAX_MONEY:
        _raise(f"{label} exceeds MAX_MONEY")
    return total


def validate_block_context(
    block: Block,
    utxo_lookup: Mapping[tuple[bytes, int], UtxoEntry],
    ctx: BlockChainContext,
) -> BlockContextResult:
    validate_block_structure(block)

    if block.header.height != ctx.current_height:
        _raise(
            f"block height {block.header.height} does not match expected height {ctx.current_height}"
        )
    if ctx.expected_prev_block_hash is not None and block.header.prev_block_hash != ctx.expected_prev_block_hash:
        _raise("block prev_block_hash does not match expected previous tip hash")
    if block.header.timestamp < ctx.median_time_past:
        _raise("block timestamp is earlier than median_time_past")

    if ctx.expected_bits is not None and block.header.bits != ctx.expected_bits:
        _raise(
            f"block bits {block.header.bits} does not match expected bits {ctx.expected_bits}"
        )
    if not hash_meets_target(block_hash(block.header), block.header.bits):
        _raise("block hash does not satisfy proof-of-work target")

    rolling_utxos: dict[tuple[bytes, int], UtxoEntry] = dict(utxo_lookup)
    spent_outpoints: list[tuple[bytes, int]] = []
    created_utxos: list[UtxoEntry] = []
    total_fees = 0

    tx_ctx = ChainContext(
        network_id=ctx.network_id,
        current_height=ctx.current_height,
        median_time_past=ctx.median_time_past,
        coinbase_maturity=ctx.coinbase_maturity,
    )

    coinbase_tx = block.txs[0]
    validate_tx_structure(coinbase_tx, allow_coinbase=True)
    if coinbase_tx.body.flags != 0:
        _raise("coinbase transaction must not carry witness or memo flags in v0")
    if len(coinbase_tx.witnesses) != 0:
        _raise("coinbase transaction must not contain witnesses")
    if coinbase_tx.body.network_id != ctx.network_id:
        _raise("coinbase transaction network_id does not match block context network_id")

    for tx in block.txs[1:]:
        fee = validate_tx_against_utxos(tx, rolling_utxos, tx_ctx)
        total_fees = _checked_add(total_fees, fee, "total fees")
        for txin in tx.body.inputs:
            outpoint = (txin.prev_txid, txin.prev_index)
            spent = rolling_utxos.pop(outpoint, None)
            if spent is None:
                _raise(f"block spends missing outpoint {txin.prev_txid.hex()}:{txin.prev_index}")
            spent_outpoints.append(outpoint)
        from latcoin.codec.tx import txid  # local import to avoid accidental cycles during bootstrap

        new_txid = txid(tx)
        for idx, txout in enumerate(tx.body.outputs):
            entry = UtxoEntry(
                txid=new_txid,
                index=idx,
                amount=txout.amount,
                lock_type=txout.lock_type,
                scheme_id=txout.scheme_id,
                lock_data=txout.lock_data,
                created_height=ctx.current_height,
                is_coinbase=False,
                network_id=tx.body.network_id,
            )
            rolling_utxos[(new_txid, idx)] = entry
            created_utxos.append(entry)

    allowed_coinbase_value = block_subsidy(ctx.current_height) + total_fees
    coinbase_output_sum = 0
    for txout in coinbase_tx.body.outputs:
        coinbase_output_sum = _checked_add(coinbase_output_sum, txout.amount, "coinbase output sum")
    if coinbase_output_sum != allowed_coinbase_value:
        _raise(
            f"coinbase pays {coinbase_output_sum}, expected exactly {allowed_coinbase_value}"
        )

    from latcoin.codec.tx import txid  # local import to avoid cycle issues during bootstrap

    coinbase_txid = txid(coinbase_tx)
    for idx, txout in enumerate(coinbase_tx.body.outputs):
        entry = UtxoEntry(
            txid=coinbase_txid,
            index=idx,
            amount=txout.amount,
            lock_type=txout.lock_type,
            scheme_id=txout.scheme_id,
            lock_data=txout.lock_data,
            created_height=ctx.current_height,
            is_coinbase=True,
            network_id=coinbase_tx.body.network_id,
        )
        created_utxos.append(entry)

    return BlockContextResult(
        total_fees=total_fees,
        spent_outpoints=spent_outpoints,
        created_utxos=created_utxos,
    )
