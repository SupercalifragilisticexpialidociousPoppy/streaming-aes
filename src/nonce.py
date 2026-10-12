import struct

class CounterOverflowError(Exception):
    """Raised when the chunk counter exceeds the 32-bit maximum."""
    pass

def build_nonce(nonce_prefix: bytes, counter: int, is_final: bool) -> bytes:
    """
    Constructs a deterministic 96-bit (12-byte) nonce for AES-GCM.
    
    Layout:
    [ 7 bytes: nonce_prefix ] [ 4 bytes: counter (big-endian) ] [ 1 byte: flag ]
    """
    if len(nonce_prefix) != 7:
        raise ValueError(f"Invalid nonce prefix length: expected 7 bytes, got {len(nonce_prefix)}")
        
    if counter < 0:
        raise ValueError("Counter cannot be negative.")
        
    # STRICT GUARD: A 4-byte unsigned integer maxes out at 4,294,967,295 (2^32 - 1).
    # If we hit 2^32, the counter would mathematically wrap back to 0.
    # Wrapping back to 0 would instantly trigger a fatal nonce-reuse attack.
    if counter >= (1 << 32):
        raise CounterOverflowError("Maximum chunk counter exceeded. Cannot encrypt further.")
        
    # The flag is 0x01 if this is the final chunk, and 0x00 otherwise
    flag = 0x01 if is_final else 0x00
    
    # Pack the components:
    # >  : Big-endian
    # 7s : 7-byte string
    # I  : 4-byte unsigned integer
    # B  : 1-byte unsigned char
    return struct.pack('>7s I B', nonce_prefix, counter, flag)