# tag_gen.py
from aes_ctr import encrypt_block

def generate_tag(key: bytes, y0: bytes, raw_ghash: bytes, tag_len: int = 16) -> bytes:
    """
    Masks the raw GHASH output with E(K, Y_0) to produce the full 128-bit tag,
    then truncates to the leftmost `tag_len` bytes, per NIST SP 800-38D's
    MSB_t(...) definition. tag_len defaults to 16 (full 128-bit tag);
    pass 8 or 4 for a 64-bit or 32-bit tag.
    """
    mask = encrypt_block(key, y0, b'\x00' * 16)
    full_tag = bytes(g ^ m for g, m in zip(raw_ghash, mask))
    return full_tag[:tag_len]