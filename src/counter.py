import struct
from ghash import run_ghash_loop

# counter.py — only this line changes inside init_counters
def init_counters(iv: bytes, h: bytes = None, ghash_func = run_ghash_loop) -> tuple[bytes, bytes]:
    if len(iv) == 12:
        y0 = iv + struct.pack('>I', 1)
    else:
        if h is None or ghash_func is None:
            raise ValueError("Non-96-bit IVs require the Hash Subkey (H) and GHASH function.")

        pad_len = (16 - (len(iv) % 16)) % 16
        padded_iv = iv + (b'\x00' * pad_len)

        iv_bits = len(iv) * 8
        len_block = struct.pack('>QQ', 0, iv_bits)

        # payload first, table second — matches run_ghash_loop's real signature
        y0 = ghash_func(padded_iv + len_block, h)

    y1 = increment_counter(y0)
    return y0, y1


def increment_counter(counter_block: bytes) -> bytes:
    """
    Increments the 32-bit big-endian integer in the rightmost 4 bytes
    of a 16-byte counter block while keeping the 12-byte prefix intact.
    """
    if len(counter_block) != 16:
        raise ValueError("Counter block must be exactly 16 bytes.")
    
    prefix = counter_block[:12]
    ctr_val = struct.unpack('>I', counter_block[12:])[0]
    
    next_ctr_val = (ctr_val + 1) % (1 << 32)
    
    return prefix + struct.pack('>I', next_ctr_val)