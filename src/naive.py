"""
DELIBERATELY BROKEN. Never use this for real data.

"AES-GCM in a loop": the design most people write first, kept only so attacks.py can show
what goes wrong. Each thing it leaves out (compared with stream.py) enables one attack:

    no per-file key       the master key encrypts every chunk of every file -> splicing,
                          and nonce reuse across files
    random 12-byte nonce  stored next to each chunk; says nothing about position
                          -> reordering, replay
    no final flag         nothing marks the end -> truncation

Format: a sequence of records, each  nonce (12 B) || ciphertext || tag (16 B).
"""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
TAG_SIZE = 16


def naive_encrypt(master_key: bytes, data: bytes, chunk_size: int, random_bytes=os.urandom) -> bytes:
    """`random_bytes` exists so attacks.py can simulate a repeated random nonce, which is how
    random nonces fail in practice (a VM snapshot restored twice, a forked process)."""
    aead = AESGCM(master_key)
    out = bytearray()
    for i in range(0, len(data), chunk_size):
        nonce = random_bytes(NONCE_SIZE)
        out += nonce + aead.encrypt(nonce, data[i:i + chunk_size], None)
    return bytes(out)


def naive_records(blob: bytes, chunk_size: int) -> list[bytes]:
    size = NONCE_SIZE + chunk_size + TAG_SIZE
    return [blob[i:i + size] for i in range(0, len(blob), size)]


def naive_decrypt(master_key: bytes, blob: bytes, chunk_size: int) -> bytes:
    """Checks every chunk's tag (raises InvalidTag), but never checks order, count or origin."""
    aead = AESGCM(master_key)
    return b"".join(aead.decrypt(rec[:NONCE_SIZE], rec[NONCE_SIZE:], None)
                    for rec in naive_records(blob, chunk_size))
