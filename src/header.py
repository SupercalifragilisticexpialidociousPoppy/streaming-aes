"""
The 49-byte stream header (format v1, frozen -- see docs/SPEC.md).

    offset  field         size  value
    0       magic          4 B  b"CHNK"
    4       version        1 B  0x01
    5       alg_id         1 B  0x01 = AES-256-GCM, key from HKDF-SHA256
    6       chunk_size     4 B  big-endian, plaintext bytes per chunk
    10      salt          32 B  random per stream, feeds HKDF
    42      nonce_prefix   7 B  random per stream, first 7 bytes of every nonce

The header travels in the clear. It is authenticated *implicitly*: all 49 bytes are the
HKDF `info`, so changing any byte changes the stream key and every chunk then fails.
"""
import os
import struct
from dataclasses import dataclass

from errors import HeaderError

MAGIC = b"CHNK"
VERSION = 0x01
ALG_AES256_GCM_HKDF_SHA256 = 0x01

SALT_SIZE = 32
NONCE_PREFIX_SIZE = 7
HEADER_SIZE = 4 + 1 + 1 + 4 + SALT_SIZE + NONCE_PREFIX_SIZE  # = 49

DEFAULT_CHUNK_SIZE = 1 << 20   # 1 MiB
MIN_CHUNK_SIZE = 16            # one AES block; tiny sizes are only useful in tests
MAX_CHUNK_SIZE = 1 << 24       # 16 MiB; the decryptor buffers one chunk, so this caps its memory

_FIXED = struct.Struct(">4sBBI")  # magic, version, alg_id, chunk_size = first 10 bytes


@dataclass(frozen=True)
class Header:
    chunk_size: int
    salt: bytes
    nonce_prefix: bytes
    version: int = VERSION
    alg_id: int = ALG_AES256_GCM_HKDF_SHA256

    @classmethod
    def new(cls, chunk_size: int = DEFAULT_CHUNK_SIZE) -> "Header":
        """
        A fresh header for a new stream. Salt and prefix come from the OS CSPRNG, right
        now, at the moment of use -- never at import time and never from the caller.
        """
        header = cls(chunk_size=chunk_size,
                     salt=os.urandom(SALT_SIZE),
                     nonce_prefix=os.urandom(NONCE_PREFIX_SIZE))
        header.validate()
        return header

    def validate(self) -> None:
        if self.version != VERSION:
            raise HeaderError(f"unsupported version {self.version}")
        if self.alg_id != ALG_AES256_GCM_HKDF_SHA256:
            raise HeaderError(f"unsupported alg_id {self.alg_id}")
        if not MIN_CHUNK_SIZE <= self.chunk_size <= MAX_CHUNK_SIZE:
            raise HeaderError(f"chunk_size {self.chunk_size} outside "
                              f"[{MIN_CHUNK_SIZE}, {MAX_CHUNK_SIZE}]")
        if len(self.salt) != SALT_SIZE:
            raise HeaderError("salt must be 32 bytes")
        if len(self.nonce_prefix) != NONCE_PREFIX_SIZE:
            raise HeaderError("nonce_prefix must be 7 bytes")

    def serialise(self) -> bytes:
        self.validate()
        return (_FIXED.pack(MAGIC, self.version, self.alg_id, self.chunk_size)
                + self.salt + self.nonce_prefix)

    @classmethod
    def parse(cls, data: bytes) -> "Header":
        """
        Parses and validates exactly HEADER_SIZE bytes. Runs before any key is derived,
        so a garbage header is rejected up front instead of making us allocate a huge
        chunk buffer or try an algorithm we don't support.
        """
        if len(data) != HEADER_SIZE:
            raise HeaderError(f"header must be {HEADER_SIZE} bytes, got {len(data)}")

        magic, version, alg_id, chunk_size = _FIXED.unpack_from(data, 0)
        if magic != MAGIC:
            raise HeaderError("bad magic: not a chunkcrypt stream")

        header = cls(chunk_size=chunk_size,
                     salt=data[10:10 + SALT_SIZE],
                     nonce_prefix=data[10 + SALT_SIZE:HEADER_SIZE],
                     version=version,
                     alg_id=alg_id)
        header.validate()
        return header
