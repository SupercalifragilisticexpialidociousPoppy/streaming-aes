"""
The AES side of GCM, named the way NIST SP 800-38D names it. No ECB mode anywhere.

    aes_block(K, X)      = E_K(X)    the AES block cipher on one 16-byte block (CIPH_K)
    gctr(K, ICB, data)   = GCTR_K    GCM's counter mode (SP 800-38D, Algorithm 3)

The `cryptography` library only exposes AES through a mode, so both are built on its
CTR mode: CTR starting at block X, applied to 16 zero bytes, outputs E_K(X) XOR 0 = E_K(X).
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16


def _ctr_keystream_xor(key: bytes, start_block: bytes, data: bytes) -> bytes:
    return Cipher(algorithms.AES(key), modes.CTR(start_block)).encryptor().update(data)


def aes_block(key: bytes, block: bytes) -> bytes:
    """E_K(block): apply the AES block cipher once. Used for H = E_K(0^128) and for the tag mask E_K(J0)."""
    if len(block) != BLOCK:
        raise ValueError("AES works on exactly 16-byte blocks.")
    return _ctr_keystream_xor(key, block, bytes(BLOCK))


def gctr(key: bytes, icb: bytes, data: bytes) -> bytes:
    """
    GCTR_K(ICB, data): XOR data with E_K(ICB), E_K(inc32(ICB)), E_K(inc32(inc32(ICB))), ...

    GCM's inc32 adds 1 to the LAST 32 bits only and wraps them mod 2^32, leaving the first
    96 bits alone. The library's CTR mode adds 1 to all 128 bits, so the two only differ when
    the low 32 bits wrap. We restart the library's CTR at exactly that point.
    """
    if len(icb) != BLOCK:
        raise ValueError("Counter block must be exactly 16 bytes.")

    prefix = icb[:12]
    ctr = int.from_bytes(icb[12:], "big")
    out = bytearray()
    pos = 0
    while pos < len(data):
        room = ((1 << 32) - ctr) * BLOCK          # bytes left before the low 32 bits wrap
        segment = data[pos:pos + room]
        out += _ctr_keystream_xor(key, prefix + ctr.to_bytes(4, "big"), segment)
        pos += len(segment)
        ctr = 0                                   # inc32 wrapped: prefix || 00000000
    return bytes(out)


def encrypt_block(key: bytes, y_i: bytes, pt_chunk: bytes) -> bytes:
    """One counter block's worth: pt_chunk (up to 16 bytes) XOR E_K(Y_i)."""
    keystream_block = aes_block(key, y_i)
    # zip() truncates for a final block shorter than 16 bytes
    return bytes(p ^ k for p, k in zip(pt_chunk, keystream_block))


def encrypt_plaintext(key: bytes, y1: bytes, plaintext: bytes) -> bytes:
    """Counter-mode encryption of the whole plaintext, starting at counter block Y_1."""
    return gctr(key, y1, plaintext)


def decrypt_ciphertext(key: bytes, y1: bytes, ciphertext: bytes) -> bytes:
    """Counter mode is its own inverse: XOR with the same keystream again."""
    return gctr(key, y1, ciphertext)
