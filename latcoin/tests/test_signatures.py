from __future__ import annotations

import pytest

from latcoin.codec.constants import (
    SCHEME_LATTICE_STRONG_V1,
    SCHEME_LATTICE_TOY_V1,
    SCHEME_SIG_V1,
)
from latcoin.codec.errors import InvalidField
from latcoin.crypto.signatures import (
    derive_privkey_from_seed,
    derive_pubkey,
    get_signature_backend,
    keygen,
    scheme_id_to_name,
    scheme_name_to_id,
    sign_message,
    supported_signature_scheme_ids,
    verify_signature,
)

ALL_SCHEMES = [SCHEME_SIG_V1, SCHEME_LATTICE_TOY_V1, SCHEME_LATTICE_STRONG_V1]


@pytest.mark.parametrize("scheme_id", ALL_SCHEMES)
def test_keygen_produces_pubkey_consistent_with_derive(scheme_id: int) -> None:
    privkey, pubkey = keygen(scheme_id)
    assert derive_pubkey(privkey, scheme_id=scheme_id) == pubkey


@pytest.mark.parametrize("scheme_id", ALL_SCHEMES)
def test_sign_verify_roundtrip(scheme_id: int) -> None:
    message = b"LatCoin-test-message"
    for _ in range(5):
        privkey, pubkey = keygen(scheme_id)
        sig = sign_message(privkey, message, scheme_id=scheme_id)
        assert verify_signature(pubkey, message, sig, scheme_id=scheme_id)


def test_mocksig_rejects_tampered_message() -> None:
    # MockSig is deterministic over (pubkey, message); tampering always breaks it.
    priv, pub = keygen(SCHEME_SIG_V1)
    sig = sign_message(priv, b"m1", scheme_id=SCHEME_SIG_V1)
    assert not verify_signature(pub, b"m2", sig, scheme_id=SCHEME_SIG_V1)


def test_mocksig_rejects_wrong_pubkey() -> None:
    priv_a, _ = keygen(SCHEME_SIG_V1)
    _, pub_b = keygen(SCHEME_SIG_V1)
    sig = sign_message(priv_a, b"m", scheme_id=SCHEME_SIG_V1)
    assert not verify_signature(pub_b, b"m", sig, scheme_id=SCHEME_SIG_V1)


def test_verify_rejects_wrong_length_signature() -> None:
    _, pub = keygen(SCHEME_SIG_V1)
    assert not verify_signature(pub, b"m", b"", scheme_id=SCHEME_SIG_V1)
    assert not verify_signature(pub, b"m", b"\x00" * 31, scheme_id=SCHEME_SIG_V1)


@pytest.mark.parametrize("scheme_id", ALL_SCHEMES)
def test_derive_privkey_from_seed_is_deterministic(scheme_id: int) -> None:
    seed = b"A" * 32
    a = derive_privkey_from_seed(seed, scheme_id=scheme_id)
    b = derive_privkey_from_seed(seed, scheme_id=scheme_id)
    assert a == b


def test_scheme_name_id_roundtrip() -> None:
    for scheme_id in ALL_SCHEMES:
        assert scheme_name_to_id(scheme_id_to_name(scheme_id)) == scheme_id


def test_unknown_scheme_raises() -> None:
    with pytest.raises(InvalidField):
        get_signature_backend(0xFFFF)
    with pytest.raises(InvalidField):
        scheme_name_to_id("no-such-scheme")


def test_supported_scheme_ids_covers_all_known() -> None:
    assert set(ALL_SCHEMES).issubset(set(supported_signature_scheme_ids()))
