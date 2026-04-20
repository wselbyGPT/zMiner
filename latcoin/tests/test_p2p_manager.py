"""Tests for net.manager.PeerManager callbacks and routing."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Callable
from unittest.mock import MagicMock

import pytest

from latcoin.chain.engine import SubmitResult
from latcoin.codec.block import (
    Block,
    BlockHeader,
    block_hash,
    encode_block,
)
from latcoin.codec.constants import (
    FLAG_HAS_WITNESS,
    LOCK_P2LPKH,
    NETWORK_DEVNET,
    SCHEME_SIG_V1,
    TX_VERSION_V1,
)
from latcoin.codec.tx import (
    Transaction,
    TxBody,
    TxInput,
    TxOutput,
    TxWitness,
    encode_transaction,
    txid,
)
from latcoin.net.manager import PeerManager
from latcoin.net.messages import (
    INV_BLOCK,
    INV_TX,
    PROTOCOL_VERSION,
    GetBlocksMessage,
    HeadersMessage,
    InvItem,
    InvMessage,
    VersionMessage,
    encode_version,
    ipv4_to_net_ip,
    make_version,
)
from latcoin.net.peer import Peer, PeerState
from latcoin.validation.errors import BlockValidationError


# ---------------------------------------------------------------------------
# Fixtures — engine / mempool stubs
# ---------------------------------------------------------------------------

class _FakeMempool:
    def __init__(self) -> None:
        self.entries: dict[bytes, object] = {}
        self.add_calls: list[Transaction] = []
        self._raise_on_add: Exception | None = None

    def add_transaction(self, tx, utxo_lookup, ctx, *, min_fee=0) -> int:
        if self._raise_on_add is not None:
            raise self._raise_on_add
        self.add_calls.append(tx)
        tx_hash = txid(tx)
        entry = MagicMock()
        entry.txid_bytes = tx_hash
        entry.tx = tx
        self.entries[tx_hash] = entry
        return 0


class _FakeUtxos:
    def get(self, key):
        return None


class _FakeEngine:
    def __init__(self, tip: int = 0) -> None:
        self._tip = tip
        self.submitted_blocks: list[Block] = []
        self.submitted_headers: list[BlockHeader] = []
        self._accept_block = True
        self._raise_on_block: Exception | None = None
        self._headers_result: list = []
        self._known_blocks: dict[bytes, Block] = {}
        self.mempool = _FakeMempool()
        self.utxos = _FakeUtxos()
        self.coinbase_maturity = 100
        self.network_id = NETWORK_DEVNET

    def tip_height(self) -> int:
        return self._tip

    def locator_hashes(self) -> list[bytes]:
        return [b"\xaa" * 32]

    def have_block(self, h: bytes) -> bool:
        return h in self._known_blocks

    def get_block(self, h: bytes):
        return self._known_blocks.get(h)

    def submit_block(self, block: Block) -> SubmitResult:
        if self._raise_on_block is not None:
            raise self._raise_on_block
        bh = block_hash(block.header)
        self.submitted_blocks.append(block)
        self._known_blocks[bh] = block
        self._tip += 1
        return SubmitResult(
            block_hash=bh,
            height=self._tip,
            accepted=self._accept_block,
            became_active_tip=self._accept_block,
            reorg_depth=0,
        )

    def submit_header_only(self, header: BlockHeader) -> bool:
        self.submitted_headers.append(header)
        return True

    def active_headers_after(
        self, locator, stop=None, max_count=2000
    ) -> list:
        return self._headers_result


# ---------------------------------------------------------------------------
# Fixtures — peer stub
# ---------------------------------------------------------------------------

class _FakePeer:
    """Minimal peer stub that records outgoing messages."""

    def __init__(self, remote_height: int = 0, outbound: bool = True) -> None:
        self.state = PeerState.ACTIVE
        self.outbound = outbound
        self.remote_addr = ("127.0.0.1", 9999)
        self.remote_version = make_version(start_height=remote_height, nonce=0x1234)

        self.sent_inv: list[InvItem] = []
        self.sent_getdata: list[InvItem] = []
        self.sent_getheaders: list[GetBlocksMessage] = []
        self.sent_headers: list[HeadersMessage] = []
        self.sent_blocks: list[bytes] = []
        self.sent_txs: list[bytes] = []
        self.raw_sends: list[tuple[str, bytes]] = []

    async def send_inv(self, items: list[InvItem]) -> None:
        self.sent_inv.extend(items)

    async def send_getdata(self, items: list[InvItem]) -> None:
        self.sent_getdata.extend(items)

    async def send_getheaders(self, msg: GetBlocksMessage) -> None:
        self.sent_getheaders.append(msg)

    async def send_headers(self, msg: HeadersMessage) -> None:
        self.sent_headers.append(msg)

    async def send_block(self, data: bytes) -> None:
        self.sent_blocks.append(data)

    async def send_tx(self, data: bytes) -> None:
        self.sent_txs.append(data)

    async def disconnect(self) -> None:
        self.state = PeerState.DISCONNECTED

    async def _send(self, command: str, payload: bytes) -> None:
        self.raw_sends.append((command, payload))

    def __repr__(self) -> str:
        return f"<FakePeer height={self.remote_version.start_height}>"


# ---------------------------------------------------------------------------
# Helpers — block/tx construction
# ---------------------------------------------------------------------------

def _header(height: int = 0, bits: int = 0x1F00FFFF) -> BlockHeader:
    return BlockHeader(
        version=1,
        prev_block_hash=b"\x00" * 32,
        merkle_root=bytes(range(32)),
        timestamp=1_700_000_000 + height,
        height=height,
        bits=bits,
        nonce=height * 17 + 1,
    )


def _coinbase_tx() -> Transaction:
    body = TxBody(
        version=TX_VERSION_V1,
        network_id=NETWORK_DEVNET,
        flags=0,
        lock_height=0,
        inputs=[TxInput(prev_txid=b"\x00" * 32, prev_index=0xFFFFFFFF, sequence=0)],
        outputs=[TxOutput(
            amount=5_000_000_000,
            lock_type=LOCK_P2LPKH,
            scheme_id=SCHEME_SIG_V1,
            lock_data=b"\x11" * 32,
        )],
        memo=b"",
    )
    return Transaction(body=body, witnesses=[])


def _sample_block(height: int = 0) -> Block:
    return Block(header=_header(height), txs=[_coinbase_tx()])


def _manager(engine: _FakeEngine | None = None) -> PeerManager:
    """Create a PeerManager in sync mode (no thread pool) for testing."""
    return PeerManager(
        engine=engine or _FakeEngine(),
        network_id=NETWORK_DEVNET,
        executor=None,  # sync mode: _run_sync calls fn() directly
    )


# ---------------------------------------------------------------------------
# on_peer_ready
# ---------------------------------------------------------------------------

class TestOnPeerReady:
    async def test_sends_getheaders_when_remote_is_ahead(self) -> None:
        engine = _FakeEngine(tip=5)
        mgr = _manager(engine)
        peer = _FakePeer(remote_height=10)

        await mgr.on_peer_ready(peer)

        assert len(peer.sent_getheaders) == 1
        msg = peer.sent_getheaders[0]
        assert msg.locator_hashes == [b"\xaa" * 32]

    async def test_does_not_send_getheaders_when_equal_height(self) -> None:
        engine = _FakeEngine(tip=10)
        mgr = _manager(engine)
        peer = _FakePeer(remote_height=10)

        await mgr.on_peer_ready(peer)

        assert peer.sent_getheaders == []

    async def test_sends_mempool_inv_when_remote_is_behind(self) -> None:
        engine = _FakeEngine(tip=100)
        tx = _coinbase_tx()
        tx_hash = txid(tx)
        entry = MagicMock()
        entry.txid_bytes = tx_hash
        engine.mempool.entries[tx_hash] = entry
        mgr = _manager(engine)
        peer = _FakePeer(remote_height=50)

        await mgr.on_peer_ready(peer)

        assert any(i.type == INV_TX and i.hash == tx_hash for i in peer.sent_inv)

    async def test_no_mempool_inv_when_empty(self) -> None:
        engine = _FakeEngine(tip=10)
        mgr = _manager(engine)
        peer = _FakePeer(remote_height=5)

        await mgr.on_peer_ready(peer)

        assert peer.sent_inv == []

    async def test_no_action_without_remote_version(self) -> None:
        mgr = _manager()
        peer = _FakePeer()
        peer.remote_version = None

        await mgr.on_peer_ready(peer)

        assert peer.sent_getheaders == []
        assert peer.sent_inv == []


# ---------------------------------------------------------------------------
# on_peer_disconnected
# ---------------------------------------------------------------------------

class TestOnPeerDisconnected:
    async def test_removes_peer_from_tracking(self) -> None:
        mgr = _manager()
        peer = _FakePeer(outbound=True)
        task = MagicMock()
        mgr._peers[peer] = task
        mgr._outbound_count = 1

        await mgr.on_peer_disconnected(peer)

        assert peer not in mgr._peers
        assert mgr._outbound_count == 0

    async def test_decrements_inbound_count(self) -> None:
        mgr = _manager()
        peer = _FakePeer(outbound=False)
        task = MagicMock()
        mgr._peers[peer] = task
        mgr._inbound_count = 3

        await mgr.on_peer_disconnected(peer)

        assert mgr._inbound_count == 2

    async def test_count_does_not_go_negative(self) -> None:
        mgr = _manager()
        peer = _FakePeer(outbound=True)
        mgr._outbound_count = 0

        await mgr.on_peer_disconnected(peer)

        assert mgr._outbound_count == 0


# ---------------------------------------------------------------------------
# on_inv
# ---------------------------------------------------------------------------

class TestOnInv:
    async def test_requests_unknown_block(self) -> None:
        mgr = _manager()
        peer = _FakePeer()
        bh = b"\xbb" * 32

        await mgr.on_inv(peer, [InvItem(type=INV_BLOCK, hash=bh)])

        assert any(i.hash == bh and i.type == INV_BLOCK for i in peer.sent_getdata)

    async def test_skips_known_block(self) -> None:
        engine = _FakeEngine()
        block = _sample_block()
        bh = block_hash(block.header)
        engine._known_blocks[bh] = block
        mgr = _manager(engine)
        peer = _FakePeer()

        await mgr.on_inv(peer, [InvItem(type=INV_BLOCK, hash=bh)])

        assert peer.sent_getdata == []

    async def test_skips_seen_block(self) -> None:
        mgr = _manager()
        bh = b"\xcc" * 32
        mgr._seen_blocks.add(bh)
        peer = _FakePeer()

        await mgr.on_inv(peer, [InvItem(type=INV_BLOCK, hash=bh)])

        assert peer.sent_getdata == []

    async def test_requests_unknown_tx(self) -> None:
        mgr = _manager()
        peer = _FakePeer()
        tx_hash = b"\xdd" * 32

        await mgr.on_inv(peer, [InvItem(type=INV_TX, hash=tx_hash)])

        assert any(i.hash == tx_hash and i.type == INV_TX for i in peer.sent_getdata)

    async def test_skips_known_tx(self) -> None:
        engine = _FakeEngine()
        tx_hash = b"\xee" * 32
        engine.mempool.entries[tx_hash] = MagicMock()
        mgr = _manager(engine)
        peer = _FakePeer()

        await mgr.on_inv(peer, [InvItem(type=INV_TX, hash=tx_hash)])

        assert peer.sent_getdata == []


# ---------------------------------------------------------------------------
# on_block
# ---------------------------------------------------------------------------

class TestOnBlock:
    async def test_accepted_block_relays_inv_to_others(self) -> None:
        engine = _FakeEngine(tip=0)
        mgr = _manager(engine)
        sender = _FakePeer()
        other = _FakePeer()
        other_task = MagicMock()
        mgr._peers[other] = other_task

        block = _sample_block()
        bh = block_hash(block.header)
        await mgr.on_block(sender, encode_block(block))

        assert any(i.hash == bh and i.type == INV_BLOCK for i in other.sent_inv)

    async def test_accepted_block_not_relayed_to_sender(self) -> None:
        mgr = _manager()
        sender = _FakePeer()
        mgr._peers[sender] = MagicMock()

        block = _sample_block()
        await mgr.on_block(sender, encode_block(block))

        assert sender.sent_inv == []

    async def test_duplicate_block_ignored(self) -> None:
        engine = _FakeEngine()
        mgr = _manager(engine)
        block = _sample_block()
        bh = block_hash(block.header)
        mgr._seen_blocks.add(bh)

        await mgr.on_block(_FakePeer(), encode_block(block))

        assert engine.submitted_blocks == []

    async def test_malformed_bytes_do_not_crash(self) -> None:
        mgr = _manager()
        await mgr.on_block(_FakePeer(), b"\x00" * 10)

    async def test_invalid_block_raises_no_crash(self) -> None:
        engine = _FakeEngine()
        engine._raise_on_block = BlockValidationError("bad pow")
        mgr = _manager(engine)
        block = _sample_block()

        await mgr.on_block(_FakePeer(), encode_block(block))

    async def test_block_added_to_seen_cache(self) -> None:
        engine = _FakeEngine()
        mgr = _manager(engine)
        block = _sample_block()
        bh = block_hash(block.header)

        await mgr.on_block(_FakePeer(), encode_block(block))

        assert bh in mgr._seen_blocks

    async def test_new_tip_triggers_getheaders_when_still_behind(self) -> None:
        engine = _FakeEngine(tip=0)
        mgr = _manager(engine)
        peer = _FakePeer(remote_height=100)

        block = _sample_block()
        await mgr.on_block(peer, encode_block(block))

        assert len(peer.sent_getheaders) == 1


# ---------------------------------------------------------------------------
# on_tx
# ---------------------------------------------------------------------------

class TestOnTx:
    async def test_new_tx_added_to_mempool_and_relayed(self) -> None:
        engine = _FakeEngine()
        mgr = _manager(engine)
        sender = _FakePeer()
        other = _FakePeer()
        mgr._peers[other] = MagicMock()

        tx = _coinbase_tx()
        tx_hash = txid(tx)
        await mgr.on_tx(sender, encode_transaction(tx))

        assert len(engine.mempool.add_calls) == 1
        assert any(i.hash == tx_hash and i.type == INV_TX for i in other.sent_inv)

    async def test_duplicate_tx_ignored(self) -> None:
        engine = _FakeEngine()
        mgr = _manager(engine)
        tx = _coinbase_tx()
        tx_hash = txid(tx)
        mgr._seen_txs.add(tx_hash)

        await mgr.on_tx(_FakePeer(), encode_transaction(tx))

        assert engine.mempool.add_calls == []

    async def test_mempool_rejection_no_relay(self) -> None:
        engine = _FakeEngine()
        engine.mempool._raise_on_add = ValueError("fee too low")
        mgr = _manager(engine)
        other = _FakePeer()
        mgr._peers[other] = MagicMock()

        tx = _coinbase_tx()
        await mgr.on_tx(_FakePeer(), encode_transaction(tx))

        assert other.sent_inv == []

    async def test_malformed_tx_no_crash(self) -> None:
        mgr = _manager()
        await mgr.on_tx(_FakePeer(), b"\xff" * 5)


# ---------------------------------------------------------------------------
# on_getdata
# ---------------------------------------------------------------------------

class TestOnGetdata:
    async def test_serves_known_block(self) -> None:
        engine = _FakeEngine()
        block = _sample_block()
        bh = block_hash(block.header)
        engine._known_blocks[bh] = block
        mgr = _manager(engine)
        peer = _FakePeer()

        await mgr.on_getdata(peer, [InvItem(type=INV_BLOCK, hash=bh)])

        assert len(peer.sent_blocks) == 1
        assert peer.sent_blocks[0] == encode_block(block)

    async def test_notfound_for_missing_block(self) -> None:
        mgr = _manager()
        peer = _FakePeer()
        missing = b"\xab" * 32

        await mgr.on_getdata(peer, [InvItem(type=INV_BLOCK, hash=missing)])

        cmds = [cmd for cmd, _ in peer.raw_sends]
        assert "notfound" in cmds

    async def test_serves_mempool_tx(self) -> None:
        engine = _FakeEngine()
        tx = _coinbase_tx()
        tx_hash = txid(tx)
        entry = MagicMock()
        entry.tx = tx
        engine.mempool.entries[tx_hash] = entry
        mgr = _manager(engine)
        peer = _FakePeer()

        await mgr.on_getdata(peer, [InvItem(type=INV_TX, hash=tx_hash)])

        assert len(peer.sent_txs) == 1

    async def test_notfound_for_missing_tx(self) -> None:
        mgr = _manager()
        peer = _FakePeer()

        await mgr.on_getdata(peer, [InvItem(type=INV_TX, hash=b"\x00" * 32)])

        cmds = [cmd for cmd, _ in peer.raw_sends]
        assert "notfound" in cmds


# ---------------------------------------------------------------------------
# on_getheaders / on_getblocks
# ---------------------------------------------------------------------------

class TestOnGetheaders:
    async def test_sends_headers_from_engine(self) -> None:
        engine = _FakeEngine()
        h = _header(height=1)
        entry = MagicMock()
        entry.header = h
        engine._headers_result = [entry]
        mgr = _manager(engine)
        peer = _FakePeer()

        msg = GetBlocksMessage(
            version=PROTOCOL_VERSION,
            locator_hashes=[b"\x00" * 32],
            stop_hash=b"\x00" * 32,
        )
        await mgr.on_getheaders(peer, msg)

        assert len(peer.sent_headers) == 1
        assert peer.sent_headers[0].headers == [h]

    async def test_sends_empty_headers_when_none(self) -> None:
        mgr = _manager()
        peer = _FakePeer()
        msg = GetBlocksMessage(
            version=PROTOCOL_VERSION,
            locator_hashes=[],
            stop_hash=b"\x00" * 32,
        )
        await mgr.on_getheaders(peer, msg)

        assert len(peer.sent_headers) == 1
        assert peer.sent_headers[0].headers == []


class TestOnGetblocks:
    async def test_sends_inv_for_blocks(self) -> None:
        engine = _FakeEngine()
        bh = b"\xf1" * 32
        entry = MagicMock()
        entry.block_hash = bh
        engine._headers_result = [entry]
        mgr = _manager(engine)
        peer = _FakePeer()

        msg = GetBlocksMessage(
            version=PROTOCOL_VERSION,
            locator_hashes=[b"\x00" * 32],
            stop_hash=b"\x00" * 32,
        )
        await mgr.on_getblocks(peer, msg)

        assert any(i.hash == bh and i.type == INV_BLOCK for i in peer.sent_inv)


# ---------------------------------------------------------------------------
# on_headers
# ---------------------------------------------------------------------------

class TestOnHeaders:
    async def test_requests_block_bodies_for_new_headers(self) -> None:
        engine = _FakeEngine()
        mgr = _manager(engine)
        peer = _FakePeer(remote_height=5)

        h = _header(height=1)
        bh = block_hash(h)
        msg = HeadersMessage(headers=[h])
        await mgr.on_headers(peer, msg)

        assert len(engine.submitted_headers) == 1
        assert any(i.hash == bh and i.type == INV_BLOCK for i in peer.sent_getdata)

    async def test_skips_getdata_for_headers_we_have(self) -> None:
        engine = _FakeEngine()
        mgr = _manager(engine)

        h = _header(height=1)
        bh = block_hash(h)
        block = _sample_block(height=1)
        engine._known_blocks[bh] = block

        msg = HeadersMessage(headers=[h])
        await mgr.on_headers(_FakePeer(), msg)

        assert peer_getdata_for_hash(peer=_FakePeer(), mgr=mgr, bh=bh) is None

    async def test_empty_headers_no_action(self) -> None:
        engine = _FakeEngine()
        mgr = _manager(engine)
        peer = _FakePeer()

        await mgr.on_headers(peer, HeadersMessage(headers=[]))

        assert engine.submitted_headers == []
        assert peer.sent_getdata == []
        assert peer.sent_getheaders == []

    async def test_full_batch_requests_more(self) -> None:
        from latcoin.net.manager import MAX_HEADERS_PER_MSG
        engine = _FakeEngine()
        mgr = _manager(engine)
        peer = _FakePeer(remote_height=9999)

        headers = [_header(height=i) for i in range(MAX_HEADERS_PER_MSG)]
        msg = HeadersMessage(headers=headers)
        await mgr.on_headers(peer, msg)

        assert len(peer.sent_getheaders) == 1


# ---------------------------------------------------------------------------
# peer_count / active_peers
# ---------------------------------------------------------------------------

class TestManagerInfo:
    def test_peer_count(self) -> None:
        mgr = _manager()
        mgr._outbound_count = 3
        mgr._inbound_count = 7
        assert mgr.peer_count() == (3, 7)

    def test_active_peers_filters_by_state(self) -> None:
        mgr = _manager()
        p1 = _FakePeer()
        p2 = _FakePeer()
        p2.state = PeerState.DISCONNECTING
        mgr._peers[p1] = MagicMock()
        mgr._peers[p2] = MagicMock()

        active = mgr.active_peers()

        assert p1 in active
        assert p2 not in active


# ---------------------------------------------------------------------------
# helper used in test above
# ---------------------------------------------------------------------------

def peer_getdata_for_hash(peer, mgr, bh):
    """Return first getdata item matching bh, or None."""
    return next((i for i in peer.sent_getdata if i.hash == bh), None)
