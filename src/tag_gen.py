from aes_ctr import aes_block


def generate_tag(key: bytes, j0: bytes, raw_ghash: bytes, tag_len: int = 16) -> bytes:
    """
    T = MSB_t( GHASH_H(A, C) XOR E_K(J0) ).
    The mask E_K(J0) hides the raw GHASH value; without it, the tag would be a public
    polynomial in H and an attacker could solve for H. tag_len is in bytes (16 = full tag).
    """
    mask = aes_block(key, j0)
    full_tag = bytes(g ^ m for g, m in zip(raw_ghash, mask))
    return full_tag[:tag_len]
