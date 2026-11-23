"""
Per-stream key derivation: K_stream = HKDF-SHA256(ikm=K_master, salt=header.salt, info=header_bytes).

Why a per-stream key at all: every file encrypted under the same master key gets its own
AES key, so a chunk cut from file A can't be pasted into file B (cross-stream splicing),
and two files can never share a (key, nonce) pair even if their 7-byte prefixes collide.

Why the whole header as `info`: it binds every header field to the key. Flip the chunk
size, the version or the algorithm byte and you get a different key, so nothing decrypts.
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from header import HEADER_SIZE, SALT_SIZE

MASTER_KEY_SIZE = 32  # AES-256
STREAM_KEY_SIZE = 32  # AES-256


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Plain RFC 5869 HKDF with SHA-256 (extract, then expand)."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def derive_stream_key(master_key: bytes, salt: bytes, header_bytes: bytes) -> bytes:
    # HKDF accepts any length, but the master key must carry at least 256 bits of
    # randomness. A human password would first need Argon2/scrypt (out of scope).
    if len(master_key) < MASTER_KEY_SIZE:
        raise ValueError("master key must be at least 32 random bytes")
    if len(salt) != SALT_SIZE:
        raise ValueError("salt must be 32 bytes")
    if len(header_bytes) != HEADER_SIZE:
        raise ValueError("header_bytes must be the full 49-byte header")
    return hkdf_sha256(master_key, salt, header_bytes, STREAM_KEY_SIZE)
