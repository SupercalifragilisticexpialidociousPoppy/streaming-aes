"""
Week-3 milestone: a whole message as ONE chunk, end to end, in the frozen v1 format.

    blob = header (49 B) || ciphertext || tag (16 B)

This is exactly what the week-4 StreamEncryptor will emit for any input that fits in one
chunk: chunk 0 is also the last chunk, so its nonce is  prefix || 00 00 00 00 || 01.

    encrypt: fresh header -> HKDF(master, salt, header) -> nonce(prefix, 0, final) -> AES-GCM
    decrypt: parse+validate header -> same HKDF -> same nonce -> verify tag -> plaintext
"""
from chunk_aead import TAG_SIZE, open_chunk, seal_chunk
from errors import ChunkcryptError
from header import DEFAULT_CHUNK_SIZE, HEADER_SIZE, Header
from kdf import derive_stream_key
from nonce import build_nonce


def encrypt_single_chunk(master_key: bytes, plaintext: bytes,
                         chunk_size: int = DEFAULT_CHUNK_SIZE,
                         backend: str = "library") -> bytes:
    """
    There is deliberately no way to pass in a salt or nonce prefix: they are generated
    inside, fresh, every call. Calling this twice on the same input gives two unrelated
    ciphertexts, so a retry can never reuse a (key, nonce) pair.
    """
    if len(plaintext) > chunk_size:
        raise ValueError("plaintext is larger than one chunk (multi-chunk streams are week 4)")

    header = Header.new(chunk_size)
    header_bytes = header.serialise()
    stream_key = derive_stream_key(master_key, header.salt, header_bytes)
    nonce = build_nonce(header.nonce_prefix, counter=0, is_final=True)
    return header_bytes + seal_chunk(stream_key, nonce, plaintext, backend)


def decrypt_single_chunk(master_key: bytes, blob: bytes, backend: str = "library") -> bytes:
    """
    Returns the plaintext only if everything checks out; otherwise raises a
    ChunkcryptError subclass and no plaintext is released.
    """
    header_bytes = blob[:HEADER_SIZE]
    header = Header.parse(header_bytes)  # HeaderError if short, wrong magic, bad fields

    body = blob[HEADER_SIZE:]
    if len(body) > header.chunk_size + TAG_SIZE:
        raise ChunkcryptError("stream has more than one chunk (multi-chunk streams are week 4)")

    # Derive from the bytes we actually received, so any change to them changes the key.
    stream_key = derive_stream_key(master_key, header.salt, header_bytes)

    # We expect chunk 0 to also be the final chunk. If the sender marked it non-final
    # (more chunks were meant to follow and were cut off), the tag will not verify.
    nonce = build_nonce(header.nonce_prefix, counter=0, is_final=True)
    return open_chunk(stream_key, nonce, body, backend)
