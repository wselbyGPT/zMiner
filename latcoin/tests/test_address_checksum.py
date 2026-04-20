from __future__ import annotations

import pytest

from latcoin.cli.main import (
    _make_address_from_key_hash,
    _parse_standard_address,
    _standard_address_checksum,
)
from latcoin.codec.constants import SCHEME_ML_DSA_44, SCHEME_SIG_V1


KEY_HASH = bytes.fromhex("0f732ccf550e34107c8488eb1234cfedc647f10f8593b3fd0cb33f462737430e")


@pytest.mark.parametrize(
    ("network", "hrp"),
    [("mainnet", "lat"), ("testnet", "tlat"), ("devnet", "dlat")],
)
@pytest.mark.parametrize("scheme_id", [SCHEME_SIG_V1, SCHEME_ML_DSA_44])
def test_make_and_parse_roundtrips(network: str, hrp: str, scheme_id: int) -> None:
    address = _make_address_from_key_hash(network, KEY_HASH, scheme_id)
    assert address.startswith(f"{hrp}1{scheme_id:04x}")
    key_hash, parsed_scheme_id = _parse_standard_address(address, expected_network=network)
    assert key_hash == KEY_HASH
    assert parsed_scheme_id == scheme_id


def test_emitted_address_embeds_expected_checksum() -> None:
    address = _make_address_from_key_hash("devnet", KEY_HASH, SCHEME_ML_DSA_44)
    payload = address.split("1", 1)[1]
    assert len(payload) == 4 + 64 + 8
    expected_checksum = _standard_address_checksum("dlat", SCHEME_ML_DSA_44, KEY_HASH).hex()
    assert payload.endswith(expected_checksum)


def test_parse_rejects_tampered_key_hash() -> None:
    good = _make_address_from_key_hash("devnet", KEY_HASH, SCHEME_ML_DSA_44)
    # Flip the first hex char of the key_hash (position = 5 chars for "dlat1" + 4 for scheme).
    idx = len("dlat1") + 4
    swapped = "0" if good[idx] != "0" else "1"
    tampered = good[:idx] + swapped + good[idx + 1:]
    assert tampered != good
    with pytest.raises(SystemExit, match="checksum mismatch"):
        _parse_standard_address(tampered)


def test_parse_rejects_tampered_checksum() -> None:
    good = _make_address_from_key_hash("mainnet", KEY_HASH, SCHEME_SIG_V1)
    tampered = good[:-1] + ("0" if good[-1] != "0" else "1")
    with pytest.raises(SystemExit, match="checksum mismatch"):
        _parse_standard_address(tampered)


def test_parse_rejects_prefix_typo_between_networks() -> None:
    # A mainnet address whose HRP is swapped to a testnet HRP must fail the
    # HRP-bound checksum even if the caller does not pin expected_network.
    good = _make_address_from_key_hash("mainnet", KEY_HASH, SCHEME_ML_DSA_44)
    assert good.startswith("lat1")
    retyped = "tlat1" + good[len("lat1"):]
    with pytest.raises(SystemExit, match="checksum mismatch"):
        _parse_standard_address(retyped)


def test_parse_rejects_legacy_no_checksum_payloads() -> None:
    hrp = "dlat"
    legacy_64_hex = f"{hrp}1{KEY_HASH.hex()}"
    with pytest.raises(SystemExit, match="payload length"):
        _parse_standard_address(legacy_64_hex)
    legacy_68_hex = f"{hrp}1{SCHEME_ML_DSA_44:04x}{KEY_HASH.hex()}"
    with pytest.raises(SystemExit, match="payload length"):
        _parse_standard_address(legacy_68_hex)


def test_parse_rejects_unknown_prefix() -> None:
    address = f"zzz1{SCHEME_ML_DSA_44:04x}{KEY_HASH.hex()}00000000"
    with pytest.raises(SystemExit, match="unknown address prefix"):
        _parse_standard_address(address)


def test_parse_enforces_expected_network_when_supplied() -> None:
    address = _make_address_from_key_hash("testnet", KEY_HASH, SCHEME_SIG_V1)
    with pytest.raises(SystemExit, match="does not match expected network"):
        _parse_standard_address(address, expected_network="mainnet")
    # Same address parses fine when the expected_network matches.
    key_hash, scheme_id = _parse_standard_address(address, expected_network="testnet")
    assert key_hash == KEY_HASH
    assert scheme_id == SCHEME_SIG_V1
