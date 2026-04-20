from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass

from latcoin.codec.constants import SCHEME_SIG_V1, SCHEME_STEALTH_V1
from latcoin.codec.hash import hash32
from .errors import InvalidField
from .primitives import decode_varbytes, encode_varbytes, read_u16le, read_u8, u16le, u8

TOY_DH_P = 2147483647  # 2^31 - 1
TOY_DH_G = 5


@dataclass(frozen=True, slots=True)
class StealthLockData:
    lock_version: int
    suite_id: int
    view_tag: int
    one_time_key_hash: bytes
    kem_ct: bytes
    pubaux: bytes


@dataclass(frozen=True, slots=True)
class StealthAddressPayload:
    addr_version: int
    spend_scheme_id: int
    scan_pub: bytes
    spend_pub: bytes


def encode_stealth_lock(lock: StealthLockData) -> bytes:
    if len(lock.one_time_key_hash) != 32:
        raise InvalidField("one_time_key_hash must be exactly 32 bytes")
    return b"".join(
        (
            u8(lock.lock_version),
            u16le(lock.suite_id),
            u8(lock.view_tag),
            lock.one_time_key_hash,
            encode_varbytes(lock.kem_ct),
            encode_varbytes(lock.pubaux),
        )
    )


def decode_stealth_lock(data: bytes) -> StealthLockData:
    offset = 0
    lock_version, offset = read_u8(data, offset)
    suite_id, offset = read_u16le(data, offset)
    view_tag, offset = read_u8(data, offset)
    if offset + 32 > len(data):
        raise InvalidField("stealth lock_data truncated while reading one_time_key_hash")
    one_time_key_hash = data[offset:offset+32]
    offset += 32
    kem_ct, offset = decode_varbytes(data, offset)
    pubaux, offset = decode_varbytes(data, offset)
    if offset != len(data):
        raise InvalidField("stealth lock_data has trailing bytes")
    return StealthLockData(
        lock_version=lock_version,
        suite_id=suite_id,
        view_tag=view_tag,
        one_time_key_hash=one_time_key_hash,
        kem_ct=kem_ct,
        pubaux=pubaux,
    )


def _network_prefix(network: str) -> str:
    mapping = {"mainnet": "lats", "testnet": "tlats", "devnet": "dlats"}
    try:
        return mapping[network]
    except KeyError as exc:
        raise InvalidField(f"unsupported network for stealth address: {network}") from exc


def encode_stealth_address(network: str, payload: StealthAddressPayload) -> str:
    raw = b"".join(
        (
            u8(payload.addr_version),
            u16le(payload.spend_scheme_id),
            encode_varbytes(payload.scan_pub),
            encode_varbytes(payload.spend_pub),
        )
    )
    checksum = hash32(raw)[:6].hex()
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"{_network_prefix(network)}:{encoded}:{checksum}"


def decode_stealth_address(address: str, expected_network: str | None = None) -> StealthAddressPayload:
    try:
        prefix, encoded, checksum = address.split(":", 2)
    except ValueError as exc:
        raise InvalidField("malformed stealth address") from exc

    network = {"lats": "mainnet", "tlats": "testnet", "dlats": "devnet"}.get(prefix)
    if network is None:
        raise InvalidField(f"unknown stealth address prefix: {prefix}")
    if expected_network is not None and network != expected_network:
        raise InvalidField(
            f"stealth address network {network} does not match expected network {expected_network}"
        )

    padded = encoded + ("=" * ((4 - (len(encoded) % 4)) % 4))
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    if hash32(raw)[:6].hex() != checksum:
        raise InvalidField("stealth address checksum mismatch")

    offset = 0
    addr_version, offset = read_u8(raw, offset)
    spend_scheme_id, offset = read_u16le(raw, offset)
    scan_pub, offset = decode_varbytes(raw, offset)
    spend_pub, offset = decode_varbytes(raw, offset)
    if offset != len(raw):
        raise InvalidField("stealth address has trailing bytes")
    return StealthAddressPayload(
        addr_version=addr_version,
        spend_scheme_id=spend_scheme_id,
        scan_pub=scan_pub,
        spend_pub=spend_pub,
    )


def toy_dh_pub_from_secret(scan_secret: bytes) -> bytes:
    if len(scan_secret) != 32:
        raise InvalidField("scan_secret must be exactly 32 bytes")
    x = (int.from_bytes(scan_secret, "little") % (TOY_DH_P - 2)) + 1
    return pow(TOY_DH_G, x, TOY_DH_P).to_bytes(8, "little")


def _toy_dh_shared_from_pub(scan_pub: bytes, eph_secret: int) -> bytes:
    pub = int.from_bytes(scan_pub, "little")
    shared = pow(pub, eph_secret, TOY_DH_P)
    return shared.to_bytes(32, "little", signed=False)


def _toy_dh_shared_from_secret(scan_secret: bytes, kem_ct: bytes) -> bytes:
    x = (int.from_bytes(scan_secret, "little") % (TOY_DH_P - 2)) + 1
    eph_pub = int.from_bytes(kem_ct, "little")
    shared = pow(eph_pub, x, TOY_DH_P)
    return shared.to_bytes(32, "little", signed=False)


def derive_mock_stealth_one_time_privkey(shared_secret: bytes, spend_pub: bytes) -> bytes:
    if len(spend_pub) != 32:
        raise InvalidField("toy stealth currently only supports 32-byte mock spend public keys")
    return hash32(b"LatCoin-Stealth-OneTime-v1" + shared_secret + spend_pub)


def create_stealth_lock_for_address(address: str, *, expected_network: str | None = None) -> tuple[bytes, int]:
    payload = decode_stealth_address(address, expected_network=expected_network)
    if payload.spend_scheme_id != SCHEME_SIG_V1:
        raise InvalidField("toy stealth send currently supports only mocksig-v1 spend keys")
    eph_secret = secrets.randbelow(TOY_DH_P - 2) + 1
    kem_ct = pow(TOY_DH_G, eph_secret, TOY_DH_P).to_bytes(8, "little")
    shared_secret = _toy_dh_shared_from_pub(payload.scan_pub, eph_secret)
    one_time_privkey = derive_mock_stealth_one_time_privkey(shared_secret, payload.spend_pub)
    one_time_key_hash = hash32(one_time_privkey)
    lock = StealthLockData(
        lock_version=0x01,
        suite_id=SCHEME_STEALTH_V1,
        view_tag=shared_secret[0],
        one_time_key_hash=one_time_key_hash,
        kem_ct=kem_ct,
        pubaux=payload.spend_pub,
    )
    return encode_stealth_lock(lock), payload.spend_scheme_id


def recover_mock_stealth_one_time_privkey(lock: StealthLockData, scan_secret: bytes) -> bytes | None:
    if lock.suite_id != SCHEME_STEALTH_V1:
        return None
    if len(lock.pubaux) != 32:
        return None
    shared_secret = _toy_dh_shared_from_secret(scan_secret, lock.kem_ct)
    if shared_secret[0] != lock.view_tag:
        return None
    candidate = derive_mock_stealth_one_time_privkey(shared_secret, lock.pubaux)
    if hash32(candidate) != lock.one_time_key_hash:
        return None
    return candidate
