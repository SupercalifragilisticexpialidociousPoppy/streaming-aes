from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def derive_stream_key(master_key: bytes, salt: bytes, header_bytes: bytes) -> bytes:
    """
    Derives a unique 32-byte stream key using HKDF-SHA256.
    
    By passing the entire 49-byte serialized header into the `info` parameter, 
    we cryptographically bind the stream key to the specific file metadata.
    """
    if len(salt) != 32:
        raise ValueError(f"Invalid salt length: expected 32 bytes, got {len(salt)}")
        
    if len(header_bytes) != 49:
        raise ValueError(f"Invalid header length: expected 49 bytes, got {len(header_bytes)}")

    # Initialize the HKDF-SHA256 derivation function
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,          # We want a 256-bit (32-byte) key for AES-256-GCM
        salt=salt,          # 32 random bytes from the file's header
        info=header_bytes   # The complete 49-byte header payload
    )
    
    # Extract and expand the master key into the final stream key
    return hkdf.derive(master_key)