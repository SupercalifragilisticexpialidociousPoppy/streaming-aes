# The static GCM reduction constant. It encodes the irreducible polynomial
# x^128 + x^7 + x^2 + x + 1 in GCM's reflected bit order (11100001 = 1 + x + x^2 + x^7).
R = 0xe1000000000000000000000000000000


def gf_2_128_mul(x: int, y: int) -> int:
    """
    Textbook bitwise GF(2^128) multiplication (Algorithm 1 of NIST SP 800-38D).
    Slow, but obviously correct -- every faster method is checked against this one.
    """
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


def build_shoup_table_bitwise(H: int) -> list[int]:
    """
    The original, slow way to build the table: 256 full multiplications.
    Kept so the tests can prove build_shoup_table() produces the same thing.
    """
    table = [0] * 256

    for i in range(256):
        # Shoup's method requires shifting the 8-bit index
        # to the highest byte of a 128-bit block before multiplying
        table[i] = gf_2_128_mul(i << 120, H)

    return table


def build_shoup_table(H: int) -> list[int]:
    """
    Precomputes a 256-entry table for the given Hash Key (H): table[i] = (i << 120) * H.
    256 entries * 16 bytes per integer = exactly 4,096 bytes (4K Table).

    Multiplication distributes over XOR, so only 8 entries need real work -- one per bit of
    the index byte. In GCM's bit order the top bit (0x80 << 120) is the field element "1",
    so table[0x80] = H, and each lower bit is the previous entry times x (a right shift,
    reduced by R). Every other entry is the XOR of the power-of-two entries it is made of.
    """
    table = [0] * 256

    v = H
    bit = 0x80
    while bit:
        table[bit] = v
        v = (v >> 1) ^ R if v & 1 else v >> 1
        bit >>= 1

    for i in range(1, 256):
        if i & (i - 1):  # not a power of two
            low = i & -i
            table[i] = table[low] ^ table[i ^ low]

    return table
