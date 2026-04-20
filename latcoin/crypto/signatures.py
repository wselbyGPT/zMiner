from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from hashlib import sha3_256
from typing import Protocol

from latcoin.codec.constants import SCHEME_LATTICE_STRONG_V1, SCHEME_LATTICE_TOY_V1, SCHEME_SIG_V1
from latcoin.codec.errors import InvalidField
from latcoin.codec.hash import hash32


class SignatureBackend(Protocol):
    scheme_id: int
    name: str

    def keygen(self) -> tuple[bytes, bytes]: ...
    def derive_pubkey(self, privkey: bytes) -> bytes: ...
    def sign(self, privkey: bytes, message: bytes) -> bytes: ...
    def verify(self, pubkey: bytes, message: bytes, signature: bytes) -> bool: ...
    def derive_privkey_from_seed(self, seed: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class MockSignatureScheme:
    scheme_id: int = SCHEME_SIG_V1
    name: str = "mocksig-v1"
    key_size: int = 32
    sig_size: int = 32

    def keygen(self) -> tuple[bytes, bytes]:
        privkey = secrets.token_bytes(self.key_size)
        return privkey, self.derive_pubkey(privkey)

    def derive_pubkey(self, privkey: bytes) -> bytes:
        self._require_key_bytes(privkey, "privkey")
        return bytes(privkey)

    def sign(self, privkey: bytes, message: bytes) -> bytes:
        pubkey = self.derive_pubkey(privkey)
        return hash32(b"LatCoin-MockSig-v1" + pubkey + message)

    def verify(self, pubkey: bytes, message: bytes, signature: bytes) -> bool:
        self._require_key_bytes(pubkey, "pubkey")
        if len(signature) != self.sig_size:
            return False
        expected = hash32(b"LatCoin-MockSig-v1" + pubkey + message)
        return signature == expected

    def derive_privkey_from_seed(self, seed: bytes) -> bytes:
        return hash32(b"LatCoin-MockSig-Seed-v1" + seed)

    def _require_key_bytes(self, value: bytes, name: str) -> None:
        if not isinstance(value, (bytes, bytearray)):
            raise InvalidField(f"{name} must be bytes")
        if len(value) != self.key_size:
            raise InvalidField(f"{name} must be exactly {self.key_size} bytes")


@dataclass(frozen=True, slots=True)
class _BaseToyLatticeSignatureScheme:
    scheme_id: int
    name: str
    q: int
    n: int
    m: int
    y_abs: int
    challenge_abs: int
    _A: list[list[int]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_A", self._build_matrix())

    @property
    def pubkey_size(self) -> int:
        return 1 + (2 * self.n)

    @property
    def privkey_size(self) -> int:
        return 1 + self.m

    @property
    def sig_size(self) -> int:
        return 2 + self.m

    def keygen(self) -> tuple[bytes, bytes]:
        seed = secrets.token_bytes(32)
        privkey = self.derive_privkey_from_seed(seed)
        return privkey, self.derive_pubkey(privkey)

    def derive_privkey_from_seed(self, seed: bytes) -> bytes:
        coeffs = self._expand_small_coeffs(seed, self.m, -1, 1)
        return self._encode_small_vector(coeffs, version=1, lo=-1, hi=1)

    def derive_pubkey(self, privkey: bytes) -> bytes:
        x = self._decode_small_vector(privkey, expected_version=1, expected_len=self.m, lo=-1, hi=1)
        t = self._mat_vec(self._A, x)
        return self._encode_mod_vector(t)

    def sign(self, privkey: bytes, message: bytes) -> bytes:
        x = self._decode_small_vector(privkey, expected_version=1, expected_len=self.m, lo=-1, hi=1)
        pubkey = self.derive_pubkey(privkey)
        y = self._expand_small_coeffs(secrets.token_bytes(32) + message, self.m, -self.y_abs, self.y_abs)
        w = self._mat_vec(self._A, y)
        c = self._challenge(pubkey, message, w)
        z = [yi + (c * xi) for yi, xi in zip(y, x, strict=True)]
        if any(abs(zi) > (self.y_abs + self.challenge_abs) for zi in z):
            return self.sign(privkey, message)
        return bytes([1, c + self.challenge_abs, *[zi + (self.y_abs + self.challenge_abs) for zi in z]])

    def verify(self, pubkey: bytes, message: bytes, signature: bytes) -> bool:
        try:
            t = self._decode_mod_vector(pubkey)
            if len(signature) != self.sig_size:
                return False
            if signature[0] != 1:
                return False
            c = signature[1] - self.challenge_abs
            if c < -self.challenge_abs or c > self.challenge_abs:
                return False
            z = [b - (self.y_abs + self.challenge_abs) for b in signature[2:]]
            if len(z) != self.m:
                return False
            if any(abs(zi) > (self.y_abs + self.challenge_abs) for zi in z):
                return False
            az = self._mat_vec(self._A, z)
            w_prime = [self._mod_q(azi - (c * ti)) for azi, ti in zip(az, t, strict=True)]
            return self._challenge(pubkey, message, w_prime) == c
        except InvalidField:
            return False

    def _build_matrix(self) -> list[list[int]]:
        rows: list[list[int]] = []
        for i in range(self.n):
            row: list[int] = []
            for j in range(self.m):
                digest = sha3_256(f"LatCoin-{self.name}-A:{i}:{j}".encode("utf-8")).digest()
                row.append(int.from_bytes(digest[:4], "little") % self.q)
            rows.append(row)
        return rows

    def _expand_small_coeffs(self, seed: bytes, count: int, lo: int, hi: int) -> list[int]:
        span = hi - lo + 1
        out: list[int] = []
        counter = 0
        while len(out) < count:
            digest = sha3_256(seed + counter.to_bytes(4, "little") + self.name.encode("utf-8")).digest()
            counter += 1
            for byte in digest:
                out.append((byte % span) + lo)
                if len(out) == count:
                    break
        return out

    def _mat_vec(self, matrix: list[list[int]], vec: list[int]) -> list[int]:
        out: list[int] = []
        for row in matrix:
            accum = 0
            for aij, vj in zip(row, vec, strict=True):
                accum += aij * vj
            out.append(self._mod_q(accum))
        return out

    def _mod_q(self, value: int) -> int:
        return value % self.q

    def _challenge(self, pubkey: bytes, message: bytes, w: list[int]) -> int:
        digest = sha3_256(pubkey + message + self._encode_mod_vector(w) + self.name.encode("utf-8")).digest()
        return (digest[0] % (2 * self.challenge_abs + 1)) - self.challenge_abs

    def _encode_mod_vector(self, values: list[int]) -> bytes:
        if len(values) != self.n:
            raise InvalidField("mod-q vector has wrong length")
        out = bytearray([1])
        for value in values:
            if not (0 <= value < self.q):
                raise InvalidField("mod-q vector value out of range")
            out.extend(int(value).to_bytes(2, "little"))
        return bytes(out)

    def _decode_mod_vector(self, encoded: bytes) -> list[int]:
        if len(encoded) != self.pubkey_size:
            raise InvalidField(f"pubkey must be exactly {self.pubkey_size} bytes")
        if encoded[0] != 1:
            raise InvalidField("unsupported lattice pubkey version")
        values: list[int] = []
        offset = 1
        for _ in range(self.n):
            value = int.from_bytes(encoded[offset:offset + 2], "little")
            if not (0 <= value < self.q):
                raise InvalidField("lattice pubkey coordinate out of range")
            values.append(value)
            offset += 2
        return values

    def _encode_small_vector(self, values: list[int], *, version: int, lo: int, hi: int) -> bytes:
        if len(values) != self.m:
            raise InvalidField("small vector has wrong length")
        out = bytearray([version])
        for value in values:
            if value < lo or value > hi:
                raise InvalidField("small vector coefficient out of range")
            out.append(value - lo)
        return bytes(out)

    def _decode_small_vector(self, encoded: bytes, *, expected_version: int, expected_len: int, lo: int, hi: int) -> list[int]:
        if len(encoded) != 1 + expected_len:
            raise InvalidField(f"encoded vector must be exactly {1 + expected_len} bytes")
        if encoded[0] != expected_version:
            raise InvalidField("unsupported lattice private-key version")
        span = hi - lo
        values: list[int] = []
        for raw in encoded[1:]:
            if raw > span:
                raise InvalidField("small vector encoding out of range")
            values.append(raw + lo)
        return values


@dataclass(frozen=True, slots=True)
class ToyLatticeSignatureScheme(_BaseToyLatticeSignatureScheme):
    scheme_id: int = SCHEME_LATTICE_TOY_V1
    name: str = "latsig-toy-v1"
    q: int = 257
    n: int = 8
    m: int = 16
    y_abs: int = 1
    challenge_abs: int = 1


@dataclass(frozen=True, slots=True)
class StrongLatticeSignatureScheme(_BaseToyLatticeSignatureScheme):
    scheme_id: int = SCHEME_LATTICE_STRONG_V1
    name: str = "latsig-strong-v1"
    q: int = 4093
    n: int = 16
    m: int = 32
    y_abs: int = 2
    challenge_abs: int = 3


_MOCKSIG_V1 = MockSignatureScheme()
_LATSIG_TOY_V1 = ToyLatticeSignatureScheme()
_LATSIG_STRONG_V1 = StrongLatticeSignatureScheme()
_SCHEMES: dict[int, SignatureBackend] = {
    _MOCKSIG_V1.scheme_id: _MOCKSIG_V1,
    _LATSIG_TOY_V1.scheme_id: _LATSIG_TOY_V1,
    _LATSIG_STRONG_V1.scheme_id: _LATSIG_STRONG_V1,
}
_NAME_TO_SCHEME_ID: dict[str, int] = {
    _MOCKSIG_V1.name: _MOCKSIG_V1.scheme_id,
    _LATSIG_TOY_V1.name: _LATSIG_TOY_V1.scheme_id,
    _LATSIG_STRONG_V1.name: _LATSIG_STRONG_V1.scheme_id,
}


def _register_mldsa_backends_if_available() -> None:
    try:
        from latcoin.crypto.mldsa import liboqs_available, ml_dsa_schemes
    except Exception:
        return
    if not liboqs_available():
        return
    for backend in ml_dsa_schemes():
        _SCHEMES[backend.scheme_id] = backend
        _NAME_TO_SCHEME_ID[backend.name] = backend.scheme_id


_register_mldsa_backends_if_available()


def register_signature_backend(backend: SignatureBackend) -> None:
    _SCHEMES[backend.scheme_id] = backend
    _NAME_TO_SCHEME_ID[backend.name] = backend.scheme_id


def get_signature_backend(scheme_id: int) -> SignatureBackend:
    try:
        return _SCHEMES[scheme_id]
    except KeyError as exc:
        raise InvalidField(f"unsupported signature scheme_id: 0x{scheme_id:04x}") from exc


def supported_signature_scheme_ids() -> tuple[int, ...]:
    return tuple(sorted(_SCHEMES))


def scheme_name_to_id(name: str) -> int:
    try:
        return _NAME_TO_SCHEME_ID[name]
    except KeyError as exc:
        raise InvalidField(f"unsupported signature scheme name: {name}") from exc


def scheme_id_to_name(scheme_id: int) -> str:
    return get_signature_backend(scheme_id).name


def keygen(scheme_id: int = SCHEME_SIG_V1) -> tuple[bytes, bytes]:
    return get_signature_backend(scheme_id).keygen()


def derive_privkey_from_seed(seed: bytes, scheme_id: int = SCHEME_SIG_V1) -> bytes:
    return get_signature_backend(scheme_id).derive_privkey_from_seed(seed)


def derive_pubkey(privkey: bytes, scheme_id: int = SCHEME_SIG_V1) -> bytes:
    return get_signature_backend(scheme_id).derive_pubkey(privkey)


def sign_message(privkey: bytes, message: bytes, scheme_id: int = SCHEME_SIG_V1) -> bytes:
    return get_signature_backend(scheme_id).sign(privkey, message)


def verify_signature(pubkey: bytes, message: bytes, signature: bytes, scheme_id: int = SCHEME_SIG_V1) -> bool:
    return get_signature_backend(scheme_id).verify(pubkey, message, signature)
