"""
The streaming engine end to end: round trips at every boundary, and every way of
tampering with a multi-chunk stream.
"""
import io
import os
import struct

import pytest

from chunk_aead import TAG_SIZE
from errors import AuthenticationError, ChunkcryptError, HeaderError
from header import HEADER_SIZE
from stream import StreamDecryptor, StreamEncryptor

KEY = os.urandom(32)
CHUNK = 1024
RECORD = CHUNK + TAG_SIZE


def encrypt(data: bytes, key: bytes = KEY, chunk: int = CHUNK, backend: str = "library") -> bytes:
    out = io.BytesIO()
    StreamEncryptor(key, chunk, backend).encrypt(io.BytesIO(data), out)
    return out.getvalue()


def decrypt(blob: bytes, key: bytes = KEY, backend: str = "library") -> bytes:
    out = io.BytesIO()
    StreamDecryptor(key, backend).decrypt(io.BytesIO(blob), out)
    return out.getvalue()


def records(blob: bytes) -> tuple[bytes, list[bytes]]:
    body = blob[HEADER_SIZE:]
    return blob[:HEADER_SIZE], [body[i:i + RECORD] for i in range(0, len(body), RECORD)]


# ---------------------------------------------------------------- round trips

@pytest.mark.parametrize("size", [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 10 * CHUNK + 7])
def test_round_trip_at_every_boundary(size):
    data = os.urandom(size)
    blob = encrypt(data)
    chunks = max(1, -(-size // CHUNK))
    assert len(blob) == HEADER_SIZE + size + chunks * TAG_SIZE   # 16 B per chunk, nothing else
    assert decrypt(blob) == data


def test_empty_file_still_has_one_authenticated_chunk():
    blob = encrypt(b"")
    assert len(blob) == HEADER_SIZE + TAG_SIZE
    with pytest.raises(AuthenticationError):
        decrypt(blob[:HEADER_SIZE])                # all chunks removed


def test_our_gcm_and_the_library_are_interchangeable():
    data = os.urandom(2 * CHUNK + 100)
    assert decrypt(encrypt(data, backend="reference"), backend="library") == data
    assert decrypt(encrypt(data, backend="library"), backend="reference") == data


def test_encryptor_is_single_use():
    enc = StreamEncryptor(KEY, CHUNK)
    enc.encrypt(io.BytesIO(b"once"), io.BytesIO())
    with pytest.raises(RuntimeError):
        enc.encrypt(io.BytesIO(b"twice"), io.BytesIO())


def test_same_file_twice_gives_unrelated_ciphertexts():
    data = b"A" * 3000
    a, b = encrypt(data), encrypt(data)
    assert a[HEADER_SIZE:] != b[HEADER_SIZE:]


class TrickleReader(io.RawIOBase):
    """Returns at most 100 bytes per read, like a socket."""
    def __init__(self, data):
        self.buf = io.BytesIO(data)
    def readable(self):
        return True
    def read(self, n=-1):
        return self.buf.read(min(n, 100) if n > 0 else 100)


def test_short_reads_are_not_mistaken_for_end_of_stream():
    data = os.urandom(5 * CHUNK)
    out = io.BytesIO()
    StreamEncryptor(KEY, CHUNK).encrypt(TrickleReader(data), out)
    plain = io.BytesIO()
    StreamDecryptor(KEY).decrypt(TrickleReader(out.getvalue()), plain)
    assert plain.getvalue() == data


# ---------------------------------------------------------------- stream attacks

DATA = bytes(range(256)) * 20          # 5,120 bytes = 5 chunks


def test_truncation_at_a_chunk_boundary_is_rejected():
    header, recs = records(encrypt(DATA))
    for keep in range(1, len(recs)):
        with pytest.raises(AuthenticationError):
            decrypt(header + b"".join(recs[:keep]))


def test_truncation_mid_chunk_is_rejected():
    blob = encrypt(DATA)
    for cut in (1, TAG_SIZE, RECORD // 2):
        with pytest.raises(AuthenticationError):
            decrypt(blob[:-cut])


def test_reordering_is_rejected():
    header, recs = records(encrypt(DATA))
    recs[1], recs[2] = recs[2], recs[1]
    with pytest.raises(AuthenticationError):
        decrypt(header + b"".join(recs))


def test_replaying_a_chunk_is_rejected():
    header, recs = records(encrypt(DATA))
    with pytest.raises(AuthenticationError):
        decrypt(header + b"".join(recs[:2] + [recs[1]] + recs[2:]))


def test_appending_data_after_the_final_chunk_is_rejected():
    blob = encrypt(DATA)
    with pytest.raises(AuthenticationError):
        decrypt(blob + records(encrypt(DATA))[1][0])


def test_splicing_a_chunk_from_another_file_is_rejected():
    header, recs = records(encrypt(DATA))
    _, other = records(encrypt(DATA))           # same master key, same plaintext, other file
    recs[2] = other[2]
    with pytest.raises(AuthenticationError):
        decrypt(header + b"".join(recs))


def test_every_header_byte_is_protected():
    blob = encrypt(DATA)
    for i in range(HEADER_SIZE):
        bad = bytearray(blob)
        bad[i] ^= 0x01
        with pytest.raises(ChunkcryptError):      # HeaderError or AuthenticationError
            decrypt(bytes(bad))


def test_chunk_size_edit_that_still_parses_fails_authentication():
    blob = encrypt(DATA)
    edited = blob[:6] + struct.pack(">I", 2 * CHUNK) + blob[10:]
    with pytest.raises(AuthenticationError):
        decrypt(edited)


def test_bit_flip_in_any_chunk_is_rejected():
    blob = encrypt(DATA)
    for pos in range(HEADER_SIZE, len(blob), 97):
        bad = bytearray(blob)
        bad[pos] ^= 0x80
        with pytest.raises(AuthenticationError):
            decrypt(bytes(bad))


def test_wrong_master_key_is_rejected():
    with pytest.raises(AuthenticationError):
        decrypt(encrypt(DATA), key=os.urandom(32))


def test_header_only_or_garbage_is_a_header_error():
    with pytest.raises(HeaderError):
        decrypt(b"")
    with pytest.raises(HeaderError):
        decrypt(os.urandom(200))


# ---------------------------------------------------------------- all-or-nothing on disk

def test_failed_decryption_leaves_no_output_file(tmp_path):
    header, recs = records(encrypt(DATA))
    out = tmp_path / "out.bin"
    with pytest.raises(AuthenticationError):
        StreamDecryptor(KEY).decrypt_to_path(io.BytesIO(header + b"".join(recs[:3])), str(out))
    assert not out.exists()
    assert list(tmp_path.iterdir()) == []         # temp file cleaned up too


def test_successful_decryption_replaces_the_file_atomically(tmp_path):
    out = tmp_path / "out.bin"
    out.write_bytes(b"old contents")
    StreamDecryptor(KEY).decrypt_to_path(io.BytesIO(encrypt(DATA)), str(out))
    assert out.read_bytes() == DATA
    assert list(tmp_path.iterdir()) == [out]
