import pytest
from kdf import derive_stream_key
from header import Header
import os

def test_kdf_determinism_and_binding():
    master_key = os.urandom(32)
    h = Header.generate()
    header_bytes = h.serialise()
    
    # 1. Determinism: Same inputs must produce the exact same key
    key1 = derive_stream_key(master_key, h.salt, header_bytes)
    key2 = derive_stream_key(master_key, h.salt, header_bytes)
    assert key1 == key2
    
    # 2. Context Binding: Altering the header must produce a different key
    h_tampered = Header(
        magic=h.magic,
        version=h.version,
        alg_id=h.alg_id,
        chunk_size=1024,  # An attacker changes the chunk size
        salt=h.salt,
        nonce_prefix=h.nonce_prefix
    )
    key_tampered = derive_stream_key(master_key, h.salt, h_tampered.serialise())
    
    assert key1 != key_tampered