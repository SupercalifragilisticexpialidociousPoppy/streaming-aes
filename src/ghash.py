from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import struct

def derive_hash_key(master_key: bytes) -> int:
    # 1. Create a 16-byte (128-bit) block of pure zeros
    zero_block = b'\x00' * 16
    
    # 2. Set up AES using your master key. 
    # (ECB mode is used here to encrypt a single raw block without needing an IV)
    cipher = Cipher(algorithms.AES(master_key), modes.ECB())
    encryptor = cipher.encryptor()
    
    # 3. Encrypt the zero block to get H as bytes
    h_bytes = encryptor.update(zero_block) + encryptor.finalize()
    
    # 4. Convert those bytes into a standard Python integer for your math functions
    return int.from_bytes(h_bytes, byteorder='big')

def build_ghash_payload(aad: bytes, ciphertext: bytes) -> bytes:
    """
    Structures the AAD, Ciphertext, and Length Block into a single 
    continuous byte sequence where every chunk is exactly 16 bytes.
    """
    # 1. Calculate how many zero bytes are needed to reach the next 16-byte boundary
    aad_pad_len = (16 - (len(aad) % 16)) % 16
    ct_pad_len = (16 - (len(ciphertext) % 16)) % 16
    
    # 2. Apply the padding
    padded_aad = aad + (b'\x00' * aad_pad_len)
    padded_ct = ciphertext + (b'\x00' * ct_pad_len)
    
    # 3. Create the 16-byte Length Block 
    # The specification requires the lengths to be in BITS, not bytes.
    # struct.pack('>QQ', ...) packs two 64-bit unsigned integers in big-endian format.
    aad_bit_len = len(aad) * 8
    ct_bit_len = len(ciphertext) * 8
    length_block = struct.pack('>QQ', aad_bit_len, ct_bit_len)
    
    # 4. Concatenate everything together
    return padded_aad + padded_ct + length_block

def shoup_multiply(state: int, table: list[int]) -> int:
    """
    Multiplies a 128-bit state by H using the precomputed 256-entry Shoup table.
    Processes the state byte-by-byte from right to left (Horner's Method).
    """
    z = 0
    R = 0xe1000000000000000000000000000000
    
    # Process from the lowest byte (LSB) up to the highest byte (MSB)
    for i in range(16):
        # Extract the i-th byte from the right
        byte_val = (state >> (8 * i)) & 0xFF
        
        # Look up the precomputed multiplication and XOR it into z
        z ^= table[byte_val]
        
        # For all but the final byte, shift z right by 8 bits (in the Galois field)
        if i < 15:
            for _ in range(8):
                if z & 1:
                    z = (z >> 1) ^ R
                else:
                    z >>= 1
                    
    return z

def run_ghash_loop(payload: bytes, shoup_table: list[int]) -> bytes:
    """
    Consumes the properly formatted GHASH payload (Padded AAD + Padded CT + Length).
    Loops through in 16-byte blocks, XORing and multiplying by H via the Shoup table.
    """
    if len(payload) % 16 != 0:
        raise ValueError("Payload must be exactly divisible by 16 bytes.")
        
    state = 0
    
    # Process the train of bytes, one 16-byte car at a time
    for i in range(0, len(payload), 16):
        block = payload[i:i+16]
        block_int = int.from_bytes(block, byteorder='big')
        
        # 1. XOR the block into the running state
        state ^= block_int
        
        # 2. Multiply the state by H using our fast table lookup
        state = shoup_multiply(state, shoup_table)
        
    # Return the final raw GHASH value as a 16-byte block
    return state.to_bytes(16, byteorder='big')