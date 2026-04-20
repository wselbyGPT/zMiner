from __future__ import annotations

import pytest

from latcoin.codec.constants import (
    SCHEME_ML_DSA_44,
    SCHEME_ML_DSA_65,
    SCHEME_ML_DSA_87,
)
from latcoin.crypto.mldsa import liboqs_available

if not liboqs_available():
    pytest.skip("liboqs shared library not available", allow_module_level=True)

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

ML_DSA_SCHEMES = [SCHEME_ML_DSA_44, SCHEME_ML_DSA_65, SCHEME_ML_DSA_87]


@pytest.mark.parametrize("scheme_id", ML_DSA_SCHEMES)
def test_ml_dsa_registered(scheme_id: int) -> None:
    assert scheme_id in supported_signature_scheme_ids()


@pytest.mark.parametrize(
    ("scheme_id", "expected_name"),
    [
        (SCHEME_ML_DSA_44, "ml-dsa-44"),
        (SCHEME_ML_DSA_65, "ml-dsa-65"),
        (SCHEME_ML_DSA_87, "ml-dsa-87"),
    ],
)
def test_ml_dsa_name_mapping(scheme_id: int, expected_name: str) -> None:
    assert scheme_id_to_name(scheme_id) == expected_name
    assert scheme_name_to_id(expected_name) == scheme_id


@pytest.mark.parametrize(
    ("scheme_id", "pk_len", "sk_len", "sig_len"),
    [
        (SCHEME_ML_DSA_44, 1312, 2560, 2420),
        (SCHEME_ML_DSA_65, 1952, 4032, 3309),
        (SCHEME_ML_DSA_87, 2592, 4896, 4627),
    ],
)
def test_ml_dsa_key_and_sig_sizes(scheme_id: int, pk_len: int, sk_len: int, sig_len: int) -> None:
    backend = get_signature_backend(scheme_id)
    privkey, pubkey = backend.keygen()
    assert len(pubkey) == pk_len
    # Internal layout is (sk || pk) so the recovered pubkey matches.
    assert len(privkey) == sk_len + pk_len
    sig = backend.sign(privkey, b"size probe")
    assert len(sig) == sig_len


@pytest.mark.parametrize("scheme_id", ML_DSA_SCHEMES)
def test_ml_dsa_keygen_pubkey_consistent_with_derive(scheme_id: int) -> None:
    privkey, pubkey = keygen(scheme_id)
    assert derive_pubkey(privkey, scheme_id=scheme_id) == pubkey


@pytest.mark.parametrize("scheme_id", ML_DSA_SCHEMES)
def test_ml_dsa_sign_verify_roundtrip(scheme_id: int) -> None:
    message = b"LatCoin-ML-DSA-roundtrip"
    privkey, pubkey = keygen(scheme_id)
    sig = sign_message(privkey, message, scheme_id=scheme_id)
    assert verify_signature(pubkey, message, sig, scheme_id=scheme_id)


@pytest.mark.parametrize("scheme_id", ML_DSA_SCHEMES)
def test_ml_dsa_rejects_tampered_message(scheme_id: int) -> None:
    privkey, pubkey = keygen(scheme_id)
    sig = sign_message(privkey, b"alpha", scheme_id=scheme_id)
    assert not verify_signature(pubkey, b"beta", sig, scheme_id=scheme_id)


@pytest.mark.parametrize("scheme_id", ML_DSA_SCHEMES)
def test_ml_dsa_rejects_wrong_pubkey(scheme_id: int) -> None:
    priv_a, _ = keygen(scheme_id)
    _, pub_b = keygen(scheme_id)
    sig = sign_message(priv_a, b"m", scheme_id=scheme_id)
    assert not verify_signature(pub_b, b"m", sig, scheme_id=scheme_id)


@pytest.mark.parametrize("scheme_id", ML_DSA_SCHEMES)
def test_ml_dsa_rejects_wrong_length_signature(scheme_id: int) -> None:
    _, pubkey = keygen(scheme_id)
    assert not verify_signature(pubkey, b"m", b"", scheme_id=scheme_id)
    assert not verify_signature(pubkey, b"m", b"\x00" * 16, scheme_id=scheme_id)


@pytest.mark.parametrize("scheme_id", ML_DSA_SCHEMES)
def test_ml_dsa_derive_privkey_from_seed_is_deterministic(scheme_id: int) -> None:
    seed = b"LatCoin-ML-DSA-test-seed-32-byte"
    assert len(seed) == 32
    first = derive_privkey_from_seed(seed, scheme_id=scheme_id)
    second = derive_privkey_from_seed(seed, scheme_id=scheme_id)
    assert first == second


@pytest.mark.parametrize("scheme_id", ML_DSA_SCHEMES)
def test_ml_dsa_seed_derived_key_signs_and_verifies(scheme_id: int) -> None:
    seed = b"B" * 48
    privkey = derive_privkey_from_seed(seed, scheme_id=scheme_id)
    pubkey = derive_pubkey(privkey, scheme_id=scheme_id)
    sig = sign_message(privkey, b"seed-derived", scheme_id=scheme_id)
    assert verify_signature(pubkey, b"seed-derived", sig, scheme_id=scheme_id)


@pytest.mark.parametrize("scheme_id", ML_DSA_SCHEMES)
def test_ml_dsa_distinct_seeds_give_distinct_keys(scheme_id: int) -> None:
    a = derive_privkey_from_seed(b"seed-A-distinct-inputs-1", scheme_id=scheme_id)
    b = derive_privkey_from_seed(b"seed-B-distinct-inputs-2", scheme_id=scheme_id)
    assert a != b
