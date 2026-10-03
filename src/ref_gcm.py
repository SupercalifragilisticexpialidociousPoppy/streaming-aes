# ref_gcm.py
import hmac

from ghash import derive_hash_key, build_ghash_payload, run_ghash_loop
from poly_multiplication import build_shoup_table
from counter import init_counters
from aes_ctr import encrypt_plaintext, decrypt_ciphertext
from tag_gen import generate_tag

def reference_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes, tag_len: int = 16) -> tuple[bytes, bytes]:
    """
    The complete Reference GCM Encryption pipeline.
    Wires together H derivation, Shoup tables, CTR encryption, and GHASH.
    """
    # Stage 1: Setup and Precomputation
    h_int = derive_hash_key(key)
    shoup_table = build_shoup_table(h_int)

    # Stage 2: Initialize Counters
    # Pass the Shoup table (not h_int) — init_counters needs it to call run_ghash_loop
    # for IVs that aren't exactly 96 bits, same as decrypt does.
    y0, y1 = init_counters(iv, shoup_table)

    # Stage 3: Encrypt Plaintext (AES-CTR)
    ciphertext = encrypt_plaintext(key, y1, plaintext)

    # Stage 4: Format GHASH Payload and Run Loop
    ghash_payload = build_ghash_payload(aad, ciphertext)
    raw_ghash = run_ghash_loop(ghash_payload, shoup_table)

    # Stage 5: Generate Final Tag (truncated to tag_len, per NIST's MSB_t definition)
    tag = generate_tag(key, y0, raw_ghash, tag_len=tag_len)

    return ciphertext, tag


def reference_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    """
    The complete Reference GCM Decryption pipeline.
    Enforces verify-then-release: authenticates the ciphertext first,
    and only decrypts if the tag is valid.
    """
    # Stage 1: Setup and Precomputation
    h_int = derive_hash_key(key)
    shoup_table = build_shoup_table(h_int)

    # Stage 2: Initialize Counters — same call shape as encrypt now, no adapter needed
    y0, y1 = init_counters(iv, shoup_table)

    # Stage 3: Authenticate the Ciphertext first
    ghash_payload = build_ghash_payload(aad, ciphertext)
    raw_ghash = run_ghash_loop(ghash_payload, shoup_table)

    # Tag length is whatever the caller/vector handed us — matters for truncated tags
    expected_tag = generate_tag(key, y0, raw_ghash, tag_len=len(tag))

    # Stage 4: Constant-Time Tag Verification
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("Authentication Failed: The tag is invalid or the ciphertext was tampered with.")

    # Stage 5: Decrypt and Release — only runs if the tag is perfectly valid
    plaintext = decrypt_ciphertext(key, y1, ciphertext)

    return plaintext