import os
import struct
from dataclasses import dataclass

@dataclass
class Header:
    """
    Represents the 49-byte plaintext header for the streaming AEAD format.
    """
    magic: bytes = b'CHNK'
    version: int = 0x01
    alg_id: int = 0x01
    chunk_size: int = 1048576  # Default to 1 MiB
    salt: bytes = b''
    nonce_prefix: bytes = b''

    @classmethod
    def generate(cls, chunk_size: int = 1048576) -> 'Header':
        """
        Factory method to generate a fresh header for a new encryption stream.
        Pulls cryptographically secure randomness from the OS.
        """
        return cls(
            chunk_size=chunk_size,
            salt=os.urandom(32),
            nonce_prefix=os.urandom(7)
        )

    def serialise(self) -> bytes:
        """
        Packs the header fields into a strict 49-byte big-endian binary string.
        Format mapping:
          >  : Big-endian (network byte order)
          4s : 4-byte string (magic)
          B  : 1-byte unsigned char (version)
          B  : 1-byte unsigned char (alg_id)
          I  : 4-byte unsigned integer (chunk_size)
          32s: 32-byte string (salt)
          7s : 7-byte string (nonce_prefix)
        """
        return struct.pack(
            '>4s B B I 32s 7s',
            self.magic,
            self.version,
            self.alg_id,
            self.chunk_size,
            self.salt,
            self.nonce_prefix
        )

    @classmethod
    def parse(cls, data: bytes) -> 'Header':
        """
        Unpacks a 49-byte sequence into a Header object and immediately validates it.
        """
        if len(data) != 49:
            raise ValueError(f"Invalid header length: expected 49 bytes, got {len(data)}")
        
        # Unpack exactly as serialised
        unpacked = struct.unpack('>4s B B I 32s 7s', data)
        
        header = cls(
            magic=unpacked[0],
            version=unpacked[1],
            alg_id=unpacked[2],
            chunk_size=unpacked[3],
            salt=unpacked[4],
            nonce_prefix=unpacked[5]
        )
        
        header.validate()
        return header

    def validate(self):
        """
        Enforces the format specification. Rejects unsupported configurations.
        """
        if self.magic != b'CHNK':
            raise ValueError(f"Invalid magic bytes: expected b'CHNK', got {self.magic}")
            
        if self.version != 0x01:
            raise ValueError(f"Unsupported version: {self.version}")
            
        if self.alg_id != 0x01:
            raise ValueError(f"Unsupported algorithm ID: {self.alg_id}. Expected 0x01 (AES-256-GCM-HKDF).")
            
        # Reject absurd chunk sizes (e.g., smaller than 1 KiB or larger than 1 GiB)
        if not (1024 <= self.chunk_size <= (1024 * 1024 * 1024)):
            raise ValueError(f"Absurd chunk size: {self.chunk_size} bytes.")
            
        if len(self.salt) != 32:
            raise ValueError(f"Invalid salt length: expected 32 bytes, got {len(self.salt)}")
            
        if len(self.nonce_prefix) != 7:
            raise ValueError(f"Invalid nonce prefix length: expected 7 bytes, got {len(self.nonce_prefix)}")