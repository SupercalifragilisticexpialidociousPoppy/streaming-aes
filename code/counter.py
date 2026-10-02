import struct

def init_counters(iv: bytes) -> tuple[bytes, bytes]:
    """
    Initializes Y_0 (tag mask counter) and Y_1 (first data block counter)
    from a 96-bit (12-byte) IV according to NIST SP 800-38D.
    
    Returns: (Y_0, Y_1)
    """
    if len(iv) != 12:
        raise ValueError("Standard GCM fast-path requires a 96-bit (12-byte) IV.")
    
    # Append 32-bit big-endian integer 1 for Y_0
    y0 = iv + struct.pack('>I', 1)
    
    # Append 32-bit big-endian integer 2 for Y_1
    y1 = iv + struct.pack('>I', 2)
    
    return y0, y1


def increment_counter(counter_block: bytes) -> bytes:
    """
    Increments the 32-bit big-endian integer in the rightmost 4 bytes
    of a 16-byte counter block while keeping the 12-byte prefix intact.
    """
    if len(counter_block) != 16:
        raise ValueError("Counter block must be exactly 16 bytes.")
    
    prefix = counter_block[:12]
    # Extract the last 4 bytes as an unsigned 32-bit big-endian integer
    ctr_val = struct.unpack('>I', counter_block[12:])[0]
    
    # Increment modulo 2^32
    next_ctr_val = (ctr_val + 1) % (1 << 32)
    
    # Re-pack into 16 bytes
    return prefix + struct.pack('>I', next_ctr_val)