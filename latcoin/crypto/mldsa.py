from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import os
import threading
from typing import Final

from latcoin.codec.constants import (
    SCHEME_ML_DSA_44,
    SCHEME_ML_DSA_65,
    SCHEME_ML_DSA_87,
)
from latcoin.codec.errors import InvalidField

_OQS_SUCCESS: Final[int] = 0

_ML_DSA_PARAMS: Final[dict[str, dict[str, int]]] = {
    "ML-DSA-44": {"pk": 1312, "sk": 2560, "sig": 2420},
    "ML-DSA-65": {"pk": 1952, "sk": 4032, "sig": 3309},
    "ML-DSA-87": {"pk": 2592, "sk": 4896, "sig": 4627},
}


def _candidate_liboqs_paths() -> list[str]:
    out: list[str] = []
    env = os.environ.get("LATCOIN_LIBOQS_PATH")
    if env:
        out.append(env)
    found = ctypes.util.find_library("oqs")
    if found:
        out.append(found)
    out.extend([
        "/home/wselby/_oqs/lib/liboqs.so",
        "/home/wselby/_oqs/lib/liboqs.so.8",
        "/usr/local/lib/liboqs.so",
        "/usr/lib/liboqs.so",
        "/usr/lib/x86_64-linux-gnu/liboqs.so",
        "liboqs.so",
    ])
    return out


def _load_liboqs() -> ctypes.CDLL | None:
    for path in _candidate_liboqs_paths():
        try:
            return ctypes.CDLL(path)
        except OSError:
            continue
    return None


_liboqs: ctypes.CDLL | None = _load_liboqs()

_RNG_FN = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t)
_CALLBACK_REF: ctypes.CFUNCTYPE | None = None


def _bind_liboqs(lib: ctypes.CDLL) -> None:
    lib.OQS_SIG_new.restype = ctypes.c_void_p
    lib.OQS_SIG_new.argtypes = [ctypes.c_char_p]

    lib.OQS_SIG_free.restype = None
    lib.OQS_SIG_free.argtypes = [ctypes.c_void_p]

    lib.OQS_SIG_keypair.restype = ctypes.c_int
    lib.OQS_SIG_keypair.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

    lib.OQS_SIG_sign.restype = ctypes.c_int
    lib.OQS_SIG_sign.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
    ]

    lib.OQS_SIG_verify.restype = ctypes.c_int
    lib.OQS_SIG_verify.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
    ]

    lib.OQS_randombytes_custom_algorithm.restype = None
    lib.OQS_randombytes_custom_algorithm.argtypes = [_RNG_FN]

    lib.OQS_randombytes_switch_algorithm.restype = ctypes.c_int
    lib.OQS_randombytes_switch_algorithm.argtypes = [ctypes.c_char_p]


class _SeedStream:
    __slots__ = ("_seed", "_counter", "_pool")

    def __init__(self, seed: bytes) -> None:
        if not isinstance(seed, (bytes, bytearray)):
            raise InvalidField("ML-DSA seed must be bytes")
        self._seed = hashlib.sha3_256(b"LatCoin-MLDSA-DerandRNG-v1:" + bytes(seed)).digest()
        self._counter = 0
        self._pool = bytearray()

    def take(self, n: int) -> bytes:
        while len(self._pool) < n:
            block = hashlib.shake_256(
                self._seed + self._counter.to_bytes(8, "little")
            ).digest(256)
            self._pool.extend(block)
            self._counter += 1
        out = bytes(self._pool[:n])
        del self._pool[:n]
        return out


_rng_lock = threading.Lock()
_current_stream: _SeedStream | None = None


def _init_callback() -> None:
    global _CALLBACK_REF
    if _liboqs is None or _CALLBACK_REF is not None:
        return

    def _oqs_rng_callback(buf_ptr, length) -> None:
        n = int(length)
        stream = _current_stream
        data = stream.take(n) if stream is not None else os.urandom(n)
        ctypes.memmove(buf_ptr, data, n)

    # Hold the trampoline in a module-global so it isn't garbage-collected
    # while liboqs still holds its function pointer.
    _CALLBACK_REF = _RNG_FN(_oqs_rng_callback)


if _liboqs is not None:
    _bind_liboqs(_liboqs)
    _init_callback()


def liboqs_available() -> bool:
    return _liboqs is not None


class MLDSASignatureScheme:
    __slots__ = ("scheme_id", "name", "alg_name", "_pk_len", "_sk_len", "_sig_len")

    def __init__(self, scheme_id: int, name: str, alg_name: str) -> None:
        if alg_name not in _ML_DSA_PARAMS:
            raise InvalidField(f"unsupported ML-DSA algorithm: {alg_name}")
        params = _ML_DSA_PARAMS[alg_name]
        self.scheme_id = scheme_id
        self.name = name
        self.alg_name = alg_name
        self._pk_len = params["pk"]
        self._sk_len = params["sk"]
        self._sig_len = params["sig"]

    @property
    def pubkey_size(self) -> int:
        return self._pk_len

    @property
    def privkey_size(self) -> int:
        return self._sk_len + self._pk_len

    @property
    def sig_size(self) -> int:
        return self._sig_len

    def keygen(self) -> tuple[bytes, bytes]:
        pk, sk = self._liboqs_keypair(seed=None)
        return sk + pk, pk

    def derive_privkey_from_seed(self, seed: bytes) -> bytes:
        pk, sk = self._liboqs_keypair(seed=bytes(seed))
        return sk + pk

    def derive_pubkey(self, privkey: bytes) -> bytes:
        self._require_privkey(privkey)
        return bytes(privkey[self._sk_len : self._sk_len + self._pk_len])

    def sign(self, privkey: bytes, message: bytes) -> bytes:
        self._require_privkey(privkey)
        return self._liboqs_sign(bytes(privkey[: self._sk_len]), bytes(message))

    def verify(self, pubkey: bytes, message: bytes, signature: bytes) -> bool:
        if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != self._pk_len:
            return False
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != self._sig_len:
            return False
        try:
            return self._liboqs_verify(bytes(pubkey), bytes(message), bytes(signature))
        except OSError:
            return False

    def _require_privkey(self, value: bytes) -> None:
        if not isinstance(value, (bytes, bytearray)):
            raise InvalidField("privkey must be bytes")
        if len(value) != self.privkey_size:
            raise InvalidField(f"privkey must be exactly {self.privkey_size} bytes")

    def _require_ready(self) -> ctypes.CDLL:
        if _liboqs is None:
            raise RuntimeError("liboqs is not available; cannot use ML-DSA backend")
        return _liboqs

    def _liboqs_keypair(self, *, seed: bytes | None) -> tuple[bytes, bytes]:
        global _current_stream
        lib = self._require_ready()
        sig_ptr = lib.OQS_SIG_new(self.alg_name.encode("ascii"))
        if not sig_ptr:
            raise RuntimeError(f"OQS_SIG_new failed for {self.alg_name}")
        try:
            pk_buf = ctypes.create_string_buffer(self._pk_len)
            sk_buf = ctypes.create_string_buffer(self._sk_len)
            if seed is None:
                rv = lib.OQS_SIG_keypair(sig_ptr, pk_buf, sk_buf)
            else:
                assert _CALLBACK_REF is not None
                with _rng_lock:
                    _current_stream = _SeedStream(seed)
                    lib.OQS_randombytes_custom_algorithm(_CALLBACK_REF)
                    try:
                        rv = lib.OQS_SIG_keypair(sig_ptr, pk_buf, sk_buf)
                    finally:
                        lib.OQS_randombytes_switch_algorithm(b"system")
                        _current_stream = None
            if rv != _OQS_SUCCESS:
                raise RuntimeError(f"OQS_SIG_keypair({self.alg_name}) failed with rv={rv}")
            return bytes(pk_buf.raw[: self._pk_len]), bytes(sk_buf.raw[: self._sk_len])
        finally:
            lib.OQS_SIG_free(sig_ptr)

    def _liboqs_sign(self, sk: bytes, message: bytes) -> bytes:
        lib = self._require_ready()
        sig_ptr = lib.OQS_SIG_new(self.alg_name.encode("ascii"))
        if not sig_ptr:
            raise RuntimeError(f"OQS_SIG_new failed for {self.alg_name}")
        try:
            sig_buf = ctypes.create_string_buffer(self._sig_len)
            sig_out_len = ctypes.c_size_t(self._sig_len)
            rv = lib.OQS_SIG_sign(
                sig_ptr,
                sig_buf,
                ctypes.byref(sig_out_len),
                message,
                len(message),
                sk,
            )
            if rv != _OQS_SUCCESS:
                raise RuntimeError(f"OQS_SIG_sign({self.alg_name}) failed with rv={rv}")
            return bytes(sig_buf.raw[: sig_out_len.value])
        finally:
            lib.OQS_SIG_free(sig_ptr)

    def _liboqs_verify(self, pubkey: bytes, message: bytes, signature: bytes) -> bool:
        lib = self._require_ready()
        sig_ptr = lib.OQS_SIG_new(self.alg_name.encode("ascii"))
        if not sig_ptr:
            raise RuntimeError(f"OQS_SIG_new failed for {self.alg_name}")
        try:
            rv = lib.OQS_SIG_verify(
                sig_ptr,
                message,
                len(message),
                signature,
                len(signature),
                pubkey,
            )
            return rv == _OQS_SUCCESS
        finally:
            lib.OQS_SIG_free(sig_ptr)


ML_DSA_44 = MLDSASignatureScheme(
    scheme_id=SCHEME_ML_DSA_44,
    name="ml-dsa-44",
    alg_name="ML-DSA-44",
)
ML_DSA_65 = MLDSASignatureScheme(
    scheme_id=SCHEME_ML_DSA_65,
    name="ml-dsa-65",
    alg_name="ML-DSA-65",
)
ML_DSA_87 = MLDSASignatureScheme(
    scheme_id=SCHEME_ML_DSA_87,
    name="ml-dsa-87",
    alg_name="ML-DSA-87",
)


def ml_dsa_schemes() -> tuple[MLDSASignatureScheme, ...]:
    return (ML_DSA_44, ML_DSA_65, ML_DSA_87)
