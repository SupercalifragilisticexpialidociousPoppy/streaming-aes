from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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



