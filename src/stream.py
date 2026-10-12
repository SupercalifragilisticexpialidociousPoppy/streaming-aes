import os
import typing
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from header import Header
from kdf import derive_stream_key
from nonce import build_nonce

class StreamEncryptor:
    """
    Encrypts an arbitrarily large input stream into a chunked AES-256-GCM format.
    Single-use only to structurally prevent nonce-reuse (the forbidden attack).
    """
    
    def __init__(self, master_key: bytes, chunk_size: int = 1048576):
        self.master_key = master_key
        # Generates fresh salt and nonce_prefix internally
        self.header = Header.generate(chunk_size=chunk_size)
        
        # Bind the stream key to the exact metadata of this file
        self.stream_key = derive_stream_key(
            self.master_key, 
            self.header.salt, 
            self.header.serialise()
        )
        
        self._consumed = False

    def encrypt(self, src: typing.BinaryIO, dst: typing.BinaryIO) -> None:
        """
        Reads plaintext from `src`, encrypts it in chunks, and writes to `dst`.
        Operates in constant memory regardless of stream size.
        """
        # H-01: Prevent accidental re-runs that would trigger nonce reuse
        if self._consumed:
            raise RuntimeError("StreamEncryptor is single-use. Create a new instance per file.")
        self._consumed = True

        # 1. Write the 49-byte plaintext header to the output stream
        dst.write(self.header.serialise())

        # Initialize the hardware-accelerated AES-GCM engine
        aead = AESGCM(self.stream_key)
        chunk_size = self.header.chunk_size
        counter = 0

        # 2. The Look-Ahead-By-One Loop
        # We must read chunk i+1 to know if chunk i is the final chunk.
        current_chunk = src.read(chunk_size)

        # Edge case: The input file is exactly 0 bytes long.
        # We still must emit one final authenticated chunk (an empty ciphertext + 16 byte tag)
        # to prove the stream wasn't truncated before it began.
        if not current_chunk:
            nonce = build_nonce(self.header.nonce_prefix, counter, is_final=True)
            ct = aead.encrypt(nonce, b"", associated_data=None)
            dst.write(ct)
            return

        while True:
            # Look ahead to the next chunk
            next_chunk = src.read(chunk_size)
            
            # If the next read is empty, the current chunk is definitively the last one
            is_final = len(next_chunk) == 0
            
            # Build the deterministic coordinate nonce
            nonce = build_nonce(self.header.nonce_prefix, counter, is_final)
            
            # Encrypt and authenticate the chunk. 
            # (AAD is None because the header is already bound into the stream key via HKDF)
            ct = aead.encrypt(nonce, current_chunk, associated_data=None)
            dst.write(ct)
            
            if is_final:
                break
                
            current_chunk = next_chunk
            counter += 1



class StreamDecryptor:
    """
    Decrypts a chunked AES-256-GCM stream. 
    Enforces strict verify-then-write and atomic all-or-nothing file delivery.
    """
    
    def __init__(self, master_key: bytes):
        self.master_key = master_key

    def decrypt(self, src: typing.BinaryIO, dst: typing.BinaryIO) -> None:
        """
        Reads ciphertext from `src`, verifies and decrypts it chunk by chunk, 
        and writes valid plaintext to `dst`.
        """
        # 1. Read and parse the 49-byte header
        header_bytes = src.read(49)
        if len(header_bytes) < 49:
            raise ValueError("File is too small to contain a valid header (truncated stream).")
            
        header = Header.parse(header_bytes)
        
        # 2. Re-derive the exact stream key using the parsed header
        stream_key = derive_stream_key(self.master_key, header.salt, header_bytes)
        aead = AESGCM(stream_key)
        
        # Ciphertext chunks are exactly the chunk size + the 16-byte GHASH tag
        chunk_read_size = header.chunk_size + 16
        counter = 0
        
        # 3. Look-Ahead-By-One Decryption Loop
        current_chunk = src.read(chunk_read_size)
        if not current_chunk:
            raise ValueError("Stream ends abruptly after header (truncated stream).")

        while True:
            next_chunk = src.read(chunk_read_size)
            
            # If there is no more data, this current chunk MUST be the final one.
            is_final = len(next_chunk) == 0
            
            nonce = build_nonce(header.nonce_prefix, counter, is_final)
            
            try:
                # H-09: Verify-then-write.
                # aead.decrypt() mathematically processes the GHASH tag first.
                # If the tag is forged or the nonce is wrong, it raises InvalidTag
                # and returns absolutely nothing, protecting the output stream.
                pt = aead.decrypt(nonce, current_chunk, associated_data=None)
            except InvalidTag:
                raise ValueError(f"Authentication failed at chunk {counter}. The stream has been tampered with or truncated.")
                
            dst.write(pt)
            
            if is_final:
                break
                
            current_chunk = next_chunk
            counter += 1

    def decrypt_to_path(self, src: typing.BinaryIO, final_path: str) -> None:
        """
        Preferred entry point. Decrypts to a temporary file and atomically renames 
        it only upon 100% success, restoring all-or-nothing semantics.
        """
        temp_path = final_path + ".tmp"
        
        try:
            with open(temp_path, "wb") as dst:
                self.decrypt(src, dst)
        except Exception as e:
            # If authentication fails midway, aggressively delete the poisoned partial file
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise e
            
        # H-05: Atomic replacement. The user only ever sees a complete, valid file.
        os.replace(temp_path, final_path)