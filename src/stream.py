"""
The streaming engine: encrypt/decrypt a file of any size in constant memory (format v1,
docs/SPEC.md).

    HEADER (49 B) | chunk 0 | chunk 1 | ... | last chunk
    chunk i = AES-256-GCM(K_stream, nonce = prefix || i || final_flag, plaintext_i) = ct || tag

At most two chunks are held at once (the current one and the look-ahead one), so memory
depends on chunk_size, never on the file size.
"""
import os
import tempfile
from typing import BinaryIO

from chunk_aead import TAG_SIZE, open_chunk, seal_chunk
from errors import AuthenticationError
from header import DEFAULT_CHUNK_SIZE, HEADER_SIZE, Header
from kdf import derive_stream_key
from nonce import build_nonce


def _read_full(src: BinaryIO, n: int) -> bytes:
    """Read exactly n bytes, or fewer only at end of stream. Sockets and pipes may return
    short reads mid-stream, which would otherwise be mistaken for the end of the file."""
    first = src.read(n)
    if len(first) == n or not first:      # the usual case for files: no extra copies
        return first
    buf = bytearray(first)
    while len(buf) < n:
        part = src.read(n - len(buf))
        if not part:
            break
        buf += part
    return bytes(buf)


class StreamEncryptor:
    """
    Single-use: the salt and nonce prefix are generated here, fresh, and there is no way to
    pass them in. Encrypting twice with one instance would reuse (key, nonce) pairs, so the
    second call raises.
    """

    def __init__(self, master_key: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE,
                 backend: str = "library"):
        self.header = Header.generate(chunk_size)
        self.header_bytes = self.header.serialise()
        # Per-file key, bound to every header byte (kdf.py explains why)
        self.stream_key = derive_stream_key(master_key, self.header.salt, self.header_bytes)
        self.backend = backend
        self._consumed = False

    def encrypt(self, src: BinaryIO, dst: BinaryIO) -> None:
        if self._consumed:
            raise RuntimeError("StreamEncryptor is single-use. Create a new instance per file.")
        self._consumed = True

        dst.write(self.header_bytes)
        chunk_size = self.header.chunk_size
        counter = 0

        # Look-ahead-by-one: chunk i can only be marked final once we know chunk i+1 is empty.
        # An empty input still produces one (empty) final chunk, so "everything was deleted"
        # can't pass as a valid empty file.
        current = _read_full(src, chunk_size)
        while True:
            upcoming = _read_full(src, chunk_size)
            is_final = not upcoming
            nonce = build_nonce(self.header.nonce_prefix, counter, is_final)
            dst.write(seal_chunk(self.stream_key, nonce, current, self.backend))
            if is_final:
                return
            current = upcoming
            counter += 1


class StreamDecryptor:
    """Verify-then-write per chunk; all-or-nothing per file via decrypt_to_path."""

    def __init__(self, master_key: bytes, backend: str = "library"):
        self.master_key = master_key
        self.backend = backend

    def decrypt(self, src: BinaryIO, dst: BinaryIO) -> None:
        """
        Writes each chunk's plaintext only after that chunk's tag verifies. Earlier chunks may
        already be in `dst` when a later one fails, so use decrypt_to_path for files.
        """
        header_bytes = _read_full(src, HEADER_SIZE)
        header = Header.parse(header_bytes)          # HeaderError if short or invalid
        stream_key = derive_stream_key(self.master_key, header.salt, header_bytes)

        record_size = header.chunk_size + TAG_SIZE
        counter = 0
        current = _read_full(src, record_size)
        if not current:
            raise AuthenticationError("Stream has a header but no chunks (truncated).")

        while True:
            upcoming = _read_full(src, record_size)
            # No more data: this chunk must have been sealed as the final one. If the stream was
            # cut short, this chunk was sealed with flag 0, so its tag fails here.
            is_final = not upcoming
            nonce = build_nonce(header.nonce_prefix, counter, is_final)
            dst.write(open_chunk(stream_key, nonce, current, self.backend))
            if is_final:
                return
            current = upcoming
            counter += 1

    def decrypt_to_path(self, src: BinaryIO, final_path: str) -> None:
        """
        Decrypts into a uniquely named temporary file in the same folder and renames it into
        place (os.replace, atomic) only after the final chunk verifies. On any failure the
        temporary file is deleted, so a partial or tampered plaintext never appears.
        """
        folder = os.path.dirname(os.path.abspath(final_path))
        fd, temp_path = tempfile.mkstemp(dir=folder, prefix=".", suffix=".partial")
        try:
            with os.fdopen(fd, "wb") as dst:
                self.decrypt(src, dst)
            os.replace(temp_path, final_path)
        except BaseException:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
