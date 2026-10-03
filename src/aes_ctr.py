from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from counter import increment_counter

def encrypt_block(key: bytes, y_i: bytes, pt_chunk: bytes) -> bytes:
    """
    Takes a single plaintext chunk (up to 16 bytes) and a counter block (Y_i).
    Encrypts Y_i to create a keystream, then XORs it with the plaintext.
    """
    if len(y_i) != 16:
        raise ValueError("Counter block Y_i must be exactly 16 bytes.")
        
    # 1. Encrypt Y_i using AES in ECB mode to generate the keystream block
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    keystream_block = encryptor.update(y_i) + encryptor.finalize()
    
    # 2. XOR the keystream with the plaintext chunk
    # Note: zip() automatically truncates the XOR operation if pt_chunk 
    # is less than 16 bytes (which happens on the final block of a file).
    return bytes(p ^ k for p, k in zip(pt_chunk, keystream_block))

def encrypt_plaintext(key: bytes, y1: bytes, plaintext: bytes) -> bytes:
    """
    Loops through the entire plaintext in 16-byte chunks.
    Encrypts each chunk using the current counter, then increments the counter.
    
    Returns the complete ciphertext.
    """
    ciphertext = bytearray()
    current_y = y1
    
    for i in range(0, len(plaintext), 16):
        # Slice out a chunk of up to 16 bytes
        pt_chunk = plaintext[i:i+16]
        
        # 1. Encrypt the single chunk
        ct_chunk = encrypt_block(key, current_y, pt_chunk)
        ciphertext.extend(ct_chunk)
        
        # 2. Increment the counter for the next loop iteration
        current_y = increment_counter(current_y)
        
    return bytes(ciphertext)

def decrypt_block(key: bytes, y_i: bytes, ct_chunk: bytes) -> bytes:
    """
    Takes a single ciphertext chunk (up to 16 bytes) and a counter block (Y_i).
    Encrypts Y_i to recreate the keystream, then XORs it with the ciphertext chunk.
    """
    if len(y_i) != 16:
        raise ValueError("Counter block Y_i must be exactly 16 bytes.")
        
    # Encrypt Y_i using AES in ECB mode to generate the keystream block
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    keystream_block = encryptor.update(y_i) + encryptor.finalize()
    
    # XOR the keystream with the ciphertext chunk to recover plaintext
    return bytes(c ^ k for c, k in zip(ct_chunk, keystream_block))

def decrypt_ciphertext(key: bytes, y1: bytes, ciphertext: bytes) -> bytes:
    """
    Loops through the entire ciphertext in 16-byte chunks.
    Decrypts each chunk using the current counter, then increments the counter.
    
    Returns the recovered plaintext.
    """
    plaintext = bytearray()
    current_y = y1
    
    for i in range(0, len(ciphertext), 16):
        # Slice out a chunk of up to 16 bytes
        ct_chunk = ciphertext[i:i+16]
        
        # 1. Decrypt the single chunk
        pt_chunk = decrypt_block(key, current_y, ct_chunk)
        plaintext.extend(pt_chunk)
        
        # 2. Increment the counter for the next loop iteration
        current_y = increment_counter(current_y)
        
    return bytes(plaintext)