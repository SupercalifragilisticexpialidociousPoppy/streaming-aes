"""
Our own AES-GCM (SP 800-38D), built from:
    aes_ctr.py             E_K and GCTR (AES itself comes from the `cryptography` library)
    poly_multiplication.py GF(2^128) multiplication and Shoup's 4 KB table
    ghash.py               H = E_K(0^128) and GHASH
    counter.py             J0 / inc32
    tag_gen.py             T = GHASH XOR E_K(J0)
Correct (all 47,250 NIST vectors) but slow and not constant-time: it is a reference to prove
we understand GCM and to cross-check the library, not the production path.
"""
import hmac

from aes_ctr import gctr
from counter import init_counters
from ghash import build_ghash_payload, derive_hash_key, run_ghash_loop
from poly_multiplication import build_shoup_table
from tag_gen import generate_tag


def _setup(key: bytes, iv: bytes):
    shoup_table = build_shoup_table(derive_hash_key(key))   # H = E_K(0^128) -> 4 KB table
    j0, j1 = init_counters(iv, shoup_table)
    return shoup_table, j0, j1


def reference_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes,
                          tag_len: int = 16) -> tuple[bytes, bytes]:
    shoup_table, j0, j1 = _setup(key, iv)
    ciphertext = gctr(key, j1, plaintext)                                       # secrecy
    raw_ghash = run_ghash_loop(build_ghash_payload(aad, ciphertext), shoup_table)  # integrity
    return ciphertext, generate_tag(key, j0, raw_ghash, tag_len)


def reference_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    """Verify-then-release: the tag is checked first; plaintext is produced only if it matches."""
    shoup_table, j0, j1 = _setup(key, iv)
    raw_ghash = run_ghash_loop(build_ghash_payload(aad, ciphertext), shoup_table)
    expected_tag = generate_tag(key, j0, raw_ghash, tag_len=len(tag))

    if not hmac.compare_digest(expected_tag, tag):   # constant-time comparison
        raise ValueError("Authentication Failed: The tag is invalid or the ciphertext was tampered with.")

    return gctr(key, j1, ciphertext)
