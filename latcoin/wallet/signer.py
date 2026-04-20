from __future__ import annotations

from latcoin.codec.constants import FLAG_HAS_WITNESS, LOCK_P2LPKH, LOCK_P2LSTH, LOCK_P2LTL, LOCK_P2LVAULT, STANDARD_SPEND
from latcoin.codec.tx import Transaction, TxBody, TxWitness
from latcoin.codec.vault import decode_vault_lock
from latcoin.crypto.signatures import derive_pubkey, sign_message
from latcoin.validation.scripts import PrevoutContext, build_sighash, encode_standard_witness, TimelockLockData
from latcoin.validation.tx_context import UtxoEntry


class SigningError(ValueError):
    pass


def _decode_p2ltl_lock(data: bytes) -> TimelockLockData:
    from latcoin.validation.scripts import _decode_p2ltl_lock  # type: ignore[attr-defined]
    return _decode_p2ltl_lock(data)


def sign_supported_transaction(
    tx: Transaction,
    prevouts: list[UtxoEntry],
    key_material_by_input: dict[int, tuple[bytes, int]],
) -> Transaction:
    if len(prevouts) != len(tx.body.inputs):
        raise SigningError("prevouts must line up with transaction inputs")

    witnesses: list[TxWitness] = []
    for input_index, prevout in enumerate(prevouts):
        try:
            privkey, spend_mode = key_material_by_input[input_index]
        except KeyError as exc:
            raise SigningError(f"missing key material for input {input_index}") from exc

        pubkey = derive_pubkey(privkey, prevout.scheme_id)
        if prevout.lock_type == LOCK_P2LPKH:
            if spend_mode != STANDARD_SPEND:
                raise SigningError("P2LPKH inputs must use STANDARD spend mode")
        elif prevout.lock_type == LOCK_P2LSTH:
            if spend_mode != STANDARD_SPEND:
                raise SigningError("P2LSTH inputs must use STANDARD spend mode")
        elif prevout.lock_type == LOCK_P2LTL:
            lock = _decode_p2ltl_lock(prevout.lock_data)
            if spend_mode != STANDARD_SPEND:
                raise SigningError("P2LTL inputs must use STANDARD spend mode")
            if lock.key_hash != __import__('latcoin.codec.hash', fromlist=['hash32']).hash32(pubkey):
                raise SigningError("P2LTL private key does not match key_hash")
        elif prevout.lock_type == LOCK_P2LVAULT:
            lock = decode_vault_lock(prevout.lock_data)
            pub_hash = __import__('latcoin.codec.hash', fromlist=['hash32']).hash32(pubkey)
            if spend_mode == 1 and pub_hash != lock.hot_key_hash:
                raise SigningError("vault HOT private key does not match hot_key_hash")
            if spend_mode == 2 and pub_hash != lock.cold_key_hash:
                raise SigningError("vault COLD private key does not match cold_key_hash")
        else:
            raise SigningError(f"unsupported input lock_type for signing: {prevout.lock_type}")

        sighash = build_sighash(
            tx,
            input_index,
            PrevoutContext(
                amount=prevout.amount,
                lock_type=prevout.lock_type,
                scheme_id=prevout.scheme_id,
                lock_data=prevout.lock_data,
            ),
            spend_mode=spend_mode,
        )
        signature = sign_message(privkey, sighash, prevout.scheme_id)
        witnesses.append(
            TxWitness(
                raw=encode_standard_witness(
                    pubkey=pubkey,
                    signature=signature,
                    scheme_id=prevout.scheme_id,
                    spend_mode=spend_mode,
                )
            )
        )

    body = TxBody(
        version=tx.body.version,
        network_id=tx.body.network_id,
        flags=tx.body.flags | FLAG_HAS_WITNESS,
        lock_height=tx.body.lock_height,
        inputs=list(tx.body.inputs),
        outputs=list(tx.body.outputs),
        memo=tx.body.memo,
    )
    return Transaction(body=body, witnesses=witnesses)


def sign_p2lpkh_transaction(
    tx: Transaction,
    prevouts: list[UtxoEntry],
    privkeys_by_key: dict[tuple[int, bytes], bytes],
) -> Transaction:
    key_material_by_input: dict[int, tuple[bytes, int]] = {}
    for input_index, prevout in enumerate(prevouts):
        if prevout.lock_type != LOCK_P2LPKH:
            raise SigningError("sign_p2lpkh_transaction only supports P2LPKH prevouts")
        lookup_key = (prevout.scheme_id, prevout.lock_data)
        privkey = privkeys_by_key.get(lookup_key)
        if privkey is None:
            raise SigningError(
                f"wallet has no private key for input {input_index} with scheme {prevout.scheme_id} "
                f"and key hash {prevout.lock_data.hex()}"
            )
        key_material_by_input[input_index] = (privkey, STANDARD_SPEND)
    return sign_supported_transaction(tx, prevouts, key_material_by_input)
