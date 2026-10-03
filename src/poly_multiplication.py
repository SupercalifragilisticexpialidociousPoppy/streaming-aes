def gf_2_128_mul(x: int, y: int) -> int:
    """
    Textbook bitwise GF(2^128) multiplication.
    Slow, but required for correctness and building the table.
    """
    # The static GCM irreducible polynomial
    R = 0xe1000000000000000000000000000000 
    
    z = 0
    v = x
    
    # Loop 128 times (once for every bit)
    for i in range(128):
        # If the current bit of y is 1, XOR v into our running total z
        if (y >> (127 - i)) & 1:
            z ^= v
            
        # Shift v for the next loop, applying the polynomial if it overflows
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
            
    return z


def build_shoup_table(H: int) -> list[int]:
    """
    Precomputes a 256-entry table for the given Hash Key (H).
    256 entries * 16 bytes per integer = exactly 4,096 bytes (4K Table).
    """
    table = [0] * 256
    
    for i in range(256):
        # Shoup's method requires shifting the 8-bit index 
        # to the highest byte of a 128-bit block before multiplying
        val = i << 120 
        
        # Calculate the GF(2^128) multiplication once and save it
        table[i] = gf_2_128_mul(val, H)
        
    return table