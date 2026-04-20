from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from latcoin.chain.blockindex import (
    STATUS_FAILED,
    STATUS_HEADER_ONLY,
    STATUS_VALID,
    ZERO32,
    BlockIndex,
    BlockIndexEntry,
)
from latcoin.chain.chainwork import work_from_bits
from latcoin.chain.mempool import Mempool
from latcoin.chain.undo import UndoRecord, UndoStore
from latcoin.chain.utxo import UtxoSet
from latcoin.codec.block import Block, block_hash, decode_block, encode_block
from latcoin.codec.tx import Transaction, txid
from latcoin.validation.block_context import BlockChainContext, validate_block_context
from latcoin.validation.block_structure import validate_block_structure
from latcoin.validation.errors import BlockValidationError
from latcoin.validation.pow import (
    PowState,
    advance_pow_state,
    expected_bits_for_next_block,
    hash_meets_target,
    initial_pow_state,
    pow_params_for_network,
)
from latcoin.validation.tx_context import ChainContext, UtxoEntry


@dataclass(frozen=True, slots=True)
class SubmitResult:
    block_hash: bytes
    height: int
    accepted: bool
    became_active_tip: bool
    reorg_depth: int
    already_known: bool = False


@dataclass(frozen=True, slots=True)
class EngineStatus:
    tip_hash: bytes
    tip_height: int
    cumulative_work: int
    block_count: int


class ChainEngine:
    """Owns the block index, UTXO set, undo records, and mempool.

    Accepts full blocks via ``submit_block``. After each insertion the engine
    re-evaluates the best-work chain and, if the new tip beats the current
    active tip, performs a reorg by disconnecting blocks back to the fork
    point and connecting the blocks on the new branch. Each connected block
    writes an undo record so reorgs can be reversed later.
    """

    def __init__(
        self,
        datadir: Path,
        network_id: int,
        *,
        coinbase_maturity: int = 100,
    ) -> None:
        self.datadir = Path(datadir)
        self.network_id = network_id
        self.coinbase_maturity = coinbase_maturity
        self.params = pow_params_for_network(network_id)

        self._chainstate_dir = self.datadir / "chainstate"
        self._chainstate_dir.mkdir(parents=True, exist_ok=True)
        self._blocks_dir = self.datadir / "blocks"
        self._blocks_dir.mkdir(parents=True, exist_ok=True)
        self._undo_dir = self._chainstate_dir / "undo"

        self._index = BlockIndex.load_json(self._blockindex_path())
        self._utxos = (
            UtxoSet.load_json(self._utxos_path())
            if self._utxos_path().exists()
            else UtxoSet()
        )
        self._mempool = (
            Mempool.load_json(self._mempool_path())
            if self._mempool_path().exists()
            else Mempool()
        )
        self._undo = UndoStore(self._undo_dir)

    # ------------------------------------------------------------------ paths
    def _blockindex_path(self) -> Path:
        return self._chainstate_dir / "block_index.json"

    def _utxos_path(self) -> Path:
        return self._chainstate_dir / "utxos.json"

    def _meta_path(self) -> Path:
        return self._chainstate_dir / "meta.json"

    def _mempool_path(self) -> Path:
        return self.datadir / "mempool" / "entries.json"

    def _block_file_path(self, height: int, block_hash_bytes: bytes) -> Path:
        return self._blocks_dir / f"{height:08d}-{block_hash_bytes.hex()}.bin"

    # --------------------------------------------------------------- accessors
    @property
    def index(self) -> BlockIndex:
        return self._index

    @property
    def utxos(self) -> UtxoSet:
        return self._utxos

    @property
    def mempool(self) -> Mempool:
        return self._mempool

    def active_tip(self) -> BlockIndexEntry | None:
        return self._index.active_tip()

    def tip_hash(self) -> bytes:
        tip = self.active_tip()
        return ZERO32 if tip is None else tip.block_hash

    def tip_height(self) -> int:
        tip = self.active_tip()
        return -1 if tip is None else tip.height

    def next_height(self) -> int:
        return self.tip_height() + 1

    def tip_pow_state(self) -> PowState:
        tip = self.active_tip()
        return initial_pow_state(self.network_id) if tip is None else tip.pow_state

    def status(self) -> EngineStatus:
        tip = self.active_tip()
        return EngineStatus(
            tip_hash=self.tip_hash(),
            tip_height=self.tip_height(),
            cumulative_work=0 if tip is None else tip.cumulative_work,
            block_count=self.tip_height() + 1,
        )

    def expected_bits_for_next_mined_block(self) -> int:
        return expected_bits_for_next_block(self.tip_pow_state(), self.next_height(), self.params)

    # --------------------------------------------------------------- lookup
    def get_block(self, block_hash_bytes: bytes) -> Block | None:
        entry = self._index.get(block_hash_bytes)
        if entry is None or not entry.have_block:
            return None
        path = self._block_file_path(entry.height, entry.block_hash)
        if not path.exists():
            return None
        return decode_block(path.read_bytes())

    def have_block(self, block_hash_bytes: bytes) -> bool:
        entry = self._index.get(block_hash_bytes)
        return bool(entry and entry.have_block)

    def locator_hashes(self) -> list[bytes]:
        """Block-locator hashes from tip back toward genesis (Bitcoin-style).

        Dense near the tip, then exponentially sparser. The last element is
        genesis (or empty if no blocks yet).
        """
        tip = self.active_tip()
        if tip is None:
            return []
        hashes: list[bytes] = []
        step = 1
        current = tip
        while current is not None:
            hashes.append(current.block_hash)
            if len(hashes) >= 10:
                step *= 2
            # Walk back ``step`` blocks
            walked = 0
            cursor: BlockIndexEntry | None = current
            while walked < step and cursor is not None:
                if cursor.parent_hash == ZERO32:
                    cursor = None
                    break
                cursor = self._index.get(cursor.parent_hash)
                walked += 1
            if cursor is None:
                break
            current = cursor
        # Ensure genesis is included
        active_path = self._index.path_to_root(tip.block_hash)
        if active_path and active_path[-1].block_hash not in hashes:
            hashes.append(active_path[-1].block_hash)
        return hashes

    def active_headers_after(self, locator: list[bytes], stop_hash: bytes | None = None, max_count: int = 2000) -> list[BlockIndexEntry]:
        """Walk the active chain starting after the first match in ``locator``.

        If no locator entry matches, walk from genesis.
        """
        tip = self.active_tip()
        if tip is None:
            return []
        active_path = list(reversed(self._index.path_to_root(tip.block_hash)))
        start_index = 0
        locator_set = {h for h in locator}
        for i, entry in enumerate(active_path):
            if entry.block_hash in locator_set:
                start_index = i + 1
        out: list[BlockIndexEntry] = []
        for entry in active_path[start_index:]:
            out.append(entry)
            if stop_hash is not None and entry.block_hash == stop_hash:
                break
            if len(out) >= max_count:
                break
        return out

    # --------------------------------------------------------------- admission
    def _parent_pow_state(self, parent_hash: bytes) -> PowState:
        if parent_hash == ZERO32:
            return initial_pow_state(self.network_id)
        parent = self._index.require(parent_hash)
        return parent.pow_state

    def _parent_cumulative_work(self, parent_hash: bytes) -> int:
        if parent_hash == ZERO32:
            return 0
        parent = self._index.require(parent_hash)
        return parent.cumulative_work

    def _parent_height(self, parent_hash: bytes) -> int:
        if parent_hash == ZERO32:
            return -1
        return self._index.require(parent_hash).height

    def submit_header_only(self, header) -> bool:
        """Register a block header in the index without a block body.

        Returns True if newly added, False if already known. Rejects if PoW is
        invalid or parent is unknown.
        """
        h = block_hash(header)
        if h in self._index:
            return False
        if not hash_meets_target(h, header.bits):
            raise BlockValidationError("header hash does not satisfy proof-of-work target")
        parent_hash = header.prev_block_hash
        if parent_hash != ZERO32 and parent_hash not in self._index:
            raise BlockValidationError(f"unknown parent: {parent_hash.hex()}")
        parent_pow = self._parent_pow_state(parent_hash)
        parent_work = self._parent_cumulative_work(parent_hash)
        parent_height = self._parent_height(parent_hash)
        if header.height != parent_height + 1:
            raise BlockValidationError(
                f"header height {header.height} does not match expected {parent_height + 1}"
            )
        pow_state_after = advance_pow_state(
            parent_pow,
            applied_height=header.height,
            applied_bits=header.bits,
            applied_timestamp=header.timestamp,
            params=self.params,
        )
        entry = BlockIndexEntry(
            block_hash=h,
            header=header,
            height=header.height,
            parent_hash=parent_hash,
            cumulative_work=parent_work + work_from_bits(header.bits),
            pow_state=pow_state_after,
            status=STATUS_HEADER_ONLY,
            have_block=False,
        )
        self._index.add(entry)
        return True

    def submit_block(self, block: Block, *, persist: bool = True) -> SubmitResult:
        """Accept a block: structure + PoW check, index, store body, activate."""
        validate_block_structure(block)
        h = block_hash(block.header)
        if not hash_meets_target(h, block.header.bits):
            raise BlockValidationError("block hash does not satisfy proof-of-work target")

        existing = self._index.get(h)
        if existing is not None:
            if not existing.have_block:
                self._save_block_body(existing, block)
                self._index.mark_have_block(h)
            prior_tip = self.tip_hash()
            self.activate_best_chain()
            became_active = self.tip_hash() == h and prior_tip != h
            reorg_depth = self._compute_reorg_depth(prior_tip, self.tip_hash())
            if persist:
                self.persist()
            return SubmitResult(
                block_hash=h,
                height=existing.height,
                accepted=True,
                became_active_tip=became_active,
                reorg_depth=reorg_depth,
                already_known=True,
            )

        parent_hash = block.header.prev_block_hash
        if parent_hash != ZERO32 and parent_hash not in self._index:
            raise BlockValidationError(f"unknown parent: {parent_hash.hex()}")

        parent_pow = self._parent_pow_state(parent_hash)
        parent_work = self._parent_cumulative_work(parent_hash)
        parent_height = self._parent_height(parent_hash)
        if block.header.height != parent_height + 1:
            raise BlockValidationError(
                f"block height {block.header.height} does not match expected {parent_height + 1}"
            )
        pow_state_after = advance_pow_state(
            parent_pow,
            applied_height=block.header.height,
            applied_bits=block.header.bits,
            applied_timestamp=block.header.timestamp,
            params=self.params,
        )
        entry = BlockIndexEntry(
            block_hash=h,
            header=block.header,
            height=block.header.height,
            parent_hash=parent_hash,
            cumulative_work=parent_work + work_from_bits(block.header.bits),
            pow_state=pow_state_after,
            status=STATUS_HEADER_ONLY,
            have_block=False,
        )
        self._index.add(entry)
        self._save_block_body(entry, block)
        self._index.mark_have_block(h)

        prior_tip = self.tip_hash()
        self.activate_best_chain()
        became_active = self.tip_hash() == h
        reorg_depth = self._compute_reorg_depth(prior_tip, self.tip_hash())
        if persist:
            self.persist()

        return SubmitResult(
            block_hash=h,
            height=entry.height,
            accepted=True,
            became_active_tip=became_active,
            reorg_depth=reorg_depth,
        )

    def _save_block_body(self, entry: BlockIndexEntry, block: Block) -> Path:
        path = self._block_file_path(entry.height, entry.block_hash)
        path.write_bytes(encode_block(block))
        return path

    def _compute_reorg_depth(self, prior_tip: bytes, new_tip: bytes) -> int:
        if prior_tip == ZERO32 or new_tip == ZERO32 or prior_tip == new_tip:
            return 0
        if prior_tip not in self._index or new_tip not in self._index:
            return 0
        try:
            disconnect, _connect = self._index.find_fork(prior_tip, new_tip)
        except ValueError:
            return 0
        return len(disconnect)

    # --------------------------------------------------------------- activate
    def activate_best_chain(self) -> list[BlockIndexEntry]:
        activated: list[BlockIndexEntry] = []
        while True:
            best = self._index.best_candidate()
            if best is None:
                return activated
            active_tip = self.active_tip()
            if active_tip is not None and best.cumulative_work <= active_tip.cumulative_work:
                return activated
            from_hash = None if active_tip is None else active_tip.block_hash
            try:
                disconnect, connect = self._plan_reorg(from_hash, best.block_hash)
            except ValueError:
                self._index.update_status(best.block_hash, STATUS_FAILED)
                continue
            if any(not entry.have_block for entry in connect):
                return activated

            if not self._try_reorg(disconnect, connect):
                continue
            activated.extend(connect)

    def _plan_reorg(
        self, from_hash: bytes | None, to_hash: bytes
    ) -> tuple[list[BlockIndexEntry], list[BlockIndexEntry]]:
        if from_hash is None:
            path = self._index.path_to_root(to_hash)
            if not path:
                raise ValueError(f"unknown target tip: {to_hash.hex()}")
            if path[-1].parent_hash != ZERO32:
                raise ValueError("target tip does not connect to genesis")
            return [], list(reversed(path))
        return self._index.find_fork(from_hash, to_hash)

    def _try_reorg(
        self,
        disconnect: list[BlockIndexEntry],
        connect: list[BlockIndexEntry],
    ) -> bool:
        utxo_snapshot = dict(self._utxos.entries)
        mempool_snapshot = Mempool.from_jsonable(self._mempool.to_jsonable())
        tip_snapshot = self.active_tip()
        tip_snapshot_hash = None if tip_snapshot is None else tip_snapshot.block_hash
        resurrected: list[Transaction] = []
        connected_tx_ids: set[bytes] = set()
        connected: list[BlockIndexEntry] = []

        try:
            for entry in disconnect:
                block = self._load_block_body(entry)
                resurrected.extend(block.txs[1:])
                self._disconnect_block(entry)
                self._index.update_status(entry.block_hash, STATUS_VALID)
            for entry in connect:
                block = self._load_block_body(entry)
                self._connect_block(entry, block)
                for tx in block.txs:
                    connected_tx_ids.add(txid(tx))
                self._index.update_status(entry.block_hash, STATUS_VALID)
                connected.append(entry)
            self._index.set_active_tip(connect[-1].block_hash)
            self._reconcile_mempool(resurrected, connected_tx_ids)
            return True
        except BlockValidationError:
            self._utxos.entries = utxo_snapshot
            self._mempool = mempool_snapshot
            for entry in connected:
                self._undo.remove(entry.height, entry.block_hash)
                current = self._index.get(entry.block_hash)
                if current is not None and current.status != STATUS_FAILED:
                    self._index.update_status(entry.block_hash, STATUS_HEADER_ONLY)
            self._index.set_active_tip(tip_snapshot_hash)
            return False

    def _load_block_body(self, entry: BlockIndexEntry) -> Block:
        path = self._block_file_path(entry.height, entry.block_hash)
        return decode_block(path.read_bytes())

    def _connect_block(self, entry: BlockIndexEntry, block: Block) -> None:
        parent_pow = self._parent_pow_state(entry.parent_hash)
        expected_bits = expected_bits_for_next_block(parent_pow, entry.height, self.params)
        ctx = BlockChainContext(
            network_id=self.network_id,
            current_height=entry.height,
            median_time_past=max(0, entry.height - 1),
            expected_prev_block_hash=entry.parent_hash,
            coinbase_maturity=self.coinbase_maturity,
            expected_bits=expected_bits,
        )
        try:
            result = validate_block_context(block, self._utxos.entries, ctx)
        except BlockValidationError:
            self._mark_failed_recursive(entry.block_hash)
            raise

        spent_entries: list[UtxoEntry] = []
        for outpoint in result.spent_outpoints:
            spent_entries.append(self._utxos.spend_outpoint(outpoint))
        for utxo in result.created_utxos:
            self._utxos.add_entry(utxo)

        for tx in block.txs:
            self._mempool.remove_transaction(txid(tx))

        created_outpoints = [(u.txid, u.index) for u in result.created_utxos]
        self._undo.save(
            UndoRecord(
                block_hash=entry.block_hash,
                height=entry.height,
                spent_entries=spent_entries,
                created_outpoints=created_outpoints,
                prior_pow_state=parent_pow,
            )
        )

    def _disconnect_block(self, entry: BlockIndexEntry) -> None:
        record = self._undo.load(entry.height, entry.block_hash)
        for outpoint in record.created_outpoints:
            self._utxos.entries.pop(outpoint, None)
        for utxo in record.spent_entries:
            self._utxos.add_entry(utxo)

    def _mark_failed_recursive(self, block_hash_bytes: bytes) -> None:
        queue: list[bytes] = [block_hash_bytes]
        while queue:
            current = queue.pop()
            entry = self._index.get(current)
            if entry is None or entry.status == STATUS_FAILED:
                continue
            self._index.update_status(current, STATUS_FAILED)
            for child in self._index.children_of(current):
                queue.append(child.block_hash)

    # --------------------------------------------------------------- mempool
    def _tx_chain_context(self) -> ChainContext:
        return ChainContext(
            network_id=self.network_id,
            current_height=self.next_height(),
            median_time_past=max(0, self.tip_height()),
            coinbase_maturity=self.coinbase_maturity,
        )

    def _reconcile_mempool(
        self,
        resurrected: list[Transaction],
        connected_tx_ids: set[bytes],
    ) -> None:
        old_entries = list(self._mempool.entries.values())
        rebuilt = Mempool(max_size_bytes=self._mempool.max_size_bytes)
        ctx = self._tx_chain_context()
        candidates = resurrected + [entry.tx for entry in old_entries]
        seen: set[bytes] = set()
        for tx in candidates:
            tid = txid(tx)
            if tid in seen or tid in connected_tx_ids:
                continue
            seen.add(tid)
            try:
                rebuilt.add_transaction(tx, self._utxos.entries, ctx)
            except Exception:
                continue
        self._mempool = rebuilt

    def add_to_mempool(self, tx: Transaction, *, min_fee: int = 0) -> int:
        fee = self._mempool.add_transaction(
            tx, self._utxos.entries, self._tx_chain_context(), min_fee=min_fee
        )
        return fee

    def remove_from_mempool(self, txid_bytes: bytes) -> None:
        self._mempool.remove_transaction(txid_bytes)

    # --------------------------------------------------------------- persist
    def persist(self) -> None:
        self._index.save_json(self._blockindex_path())
        self._utxos.save_json(self._utxos_path())
        self._mempool.save_json(self._mempool_path())
        self._write_meta()

    def _write_meta(self) -> None:
        meta_path = self._meta_path()
        meta: dict[str, object] = {}
        if meta_path.exists():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        tip = self.active_tip()
        tip_hash_hex = tip.block_hash.hex() if tip is not None else ZERO32.hex()
        next_h = self.next_height()
        pow_state = self.tip_pow_state()
        meta["next_block_height"] = next_h
        meta["tip_hash"] = tip_hash_hex
        meta["block_count"] = self.tip_height() + 1
        meta.setdefault("coinbase_maturity", self.coinbase_maturity)
        meta["pow"] = {
            "current_bits": pow_state.current_bits,
            "last_retarget_height": pow_state.last_retarget_height,
            "last_retarget_timestamp": pow_state.last_retarget_timestamp,
            "tip_timestamp": pow_state.tip_timestamp,
        }
        meta["cumulative_work"] = str(0 if tip is None else tip.cumulative_work)
        meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")


def load_engine_from_config(datadir: Path) -> ChainEngine:
    config_path = Path(datadir) / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    network_id = int(config["network_id"])
    meta_path = Path(datadir) / "chainstate" / "meta.json"
    coinbase_maturity = 100
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        coinbase_maturity = int(meta.get("coinbase_maturity", coinbase_maturity))
    return ChainEngine(datadir, network_id, coinbase_maturity=coinbase_maturity)
