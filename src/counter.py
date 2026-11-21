import struct

from ghash import run_ghash_loop


def init_counters(iv: bytes, shoup_table: list[int]) -> tuple[bytes, bytes]:
    """
    Builds J0 (the pre-counter block, used only to mask the tag) and J1 = inc32(J0)
    (the first counter block used for data), per SP 800-38D section 7.1.

    96-bit IV (the fast path, and what our stream always uses): J0 = IV || 0^31 || 1.
    Any other length: J0 = GHASH_H(IV || zero padding || 64 zero bits || [len(IV) in bits]_64).
    """
    if len(iv) == 12:
        j0 = iv + struct.pack('>I', 1)
    else:
        pad_len = (16 - (len(iv) % 16)) % 16
        len_block = struct.pack('>QQ', 0, len(iv) * 8)
        j0 = run_ghash_loop(iv + b'\x00' * pad_len + len_block, shoup_table)

    return j0, increment_counter(j0)


def increment_counter(counter_block: bytes) -> bytes:
    """
    inc32: increments the 32-bit big-endian integer in the rightmost 4 bytes
    of a 16-byte counter block (mod 2^32) while keeping the 12-byte prefix intact.
    """
    if len(counter_block) != 16:
        raise ValueError("Counter block must be exactly 16 bytes.")

    prefix = counter_block[:12]
    ctr_val = struct.unpack('>I', counter_block[12:])[0]
    return prefix + struct.pack('>I', (ctr_val + 1) % (1 << 32))
