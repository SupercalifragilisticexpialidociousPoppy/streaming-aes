"""
One chunk = one complete AES-256-GCM call:  sealed = ciphertext || tag (16 B).

Two interchangeable backends:
  "library"   -- the `cryptography` package (OpenSSL, hardware AES + carry-less multiply).
                 Fast; this is what the stream uses.
  "reference" -- our own GCM (ref_gcm.py) on our own GHASH. Slow, but it's ours, and it
                 produces byte-identical output -- test_chunk_aead.py and test_stream.py check that.

No associated data is used: the header is already bound in through the stream key (kdf.py).
"""
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from errors import AuthenticationError
from nonce import NONCE_SIZE
from ref_gcm import reference_gcm_decrypt, reference_gcm_encrypt

TAG_SIZE = 16
BACKENDS = ("library", "reference")


def _check(key: bytes, nonce: bytes, backend: str) -> None:
    if len(key) != 32:
        raise ValueError("chunk key must be 32 bytes (AES-256)")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("nonce must be 12 bytes")
    if backend not in BACKENDS:
        raise ValueError(f"backend must be one of {BACKENDS}")


def seal_chunk(key: bytes, nonce: bytes, plaintext: bytes, backend: str = "library") -> bytes:
    _check(key, nonce, backend)
    if backend == "library":
        return AESGCM(key).encrypt(nonce, plaintext, None)
    ciphertext, tag = reference_gcm_encrypt(key, nonce, plaintext, b"")
    return ciphertext + tag


def open_chunk(key: bytes, nonce: bytes, sealed: bytes, backend: str = "library") -> bytes:
    """
    Verify, then decrypt. Either returns the full plaintext of a chunk whose tag checked
    out, or raises AuthenticationError and returns nothing at all.
    """
    _check(key, nonce, backend)
    if len(sealed) < TAG_SIZE:
        raise AuthenticationError("chunk shorter than its tag")
    try:
        if backend == "library":
            return AESGCM(key).decrypt(nonce, sealed, None)
        return reference_gcm_decrypt(key, nonce, sealed[:-TAG_SIZE], sealed[-TAG_SIZE:], b"")
    except (InvalidTag, ValueError):
        raise AuthenticationError("chunk failed authentication") from None
