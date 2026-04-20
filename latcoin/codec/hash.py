import hashlib

def hash32(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()
