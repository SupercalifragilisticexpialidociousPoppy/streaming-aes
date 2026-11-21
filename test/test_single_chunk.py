"""
Week-3 milestone: single-chunk end-to-end round trip in the frozen v1 format,
plus every tamper we can already detect with one chunk.
"""
import os
import struct

import pytest

from chunk_aead import TAG_SIZE, seal_chunk
from errors import AuthenticationError, ChunkcryptError, HeaderError
from header import HEADER_SIZE, Header
from kdf import derive_stream_key
from nonce import build_nonce
from single_chunk import decrypt_single_chunk, encrypt_single_chunk

MASTER = os.urandom(32)
CHUNK = 1024


def flip(blob: bytes, byte_index: int, bit: int = 0) -> bytes:
    b = bytearray(blob)
    b[byte_index] ^= 1 << bit
    return bytes(b)


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, CHUNK - 1, CHUNK])
@pytest.mark.parametrize("backend", ["library", "reference"])
def test_round_trip(size, backend):
    pt = os.urandom(size)
    blob = encrypt_single_chunk(MASTER, pt, chunk_size=CHUNK, backend=backend)
    assert len(blob) == HEADER_SIZE + size + TAG_SIZE
    assert decrypt_single_chunk(MASTER, blob, backend=backend) == pt


def test_cross_backend_round_trip():
    pt = os.urandom(500)
    assert decrypt_single_chunk(MASTER, encrypt_single_chunk(MASTER, pt, CHUNK, "library"),
                                "reference") == pt
    assert decrypt_single_chunk(MASTER, encrypt_single_chunk(MASTER, pt, CHUNK, "reference"),
                                "library") == pt


def test_default_1_mib_chunk_round_trip():
    pt = os.urandom(1 << 20)
    assert decrypt_single_chunk(MASTER, encrypt_single_chunk(MASTER, pt)) == pt


def test_same_plaintext_twice_gives_unrelated_ciphertexts():
    pt = b"attack at dawn" * 10
    a = encrypt_single_chunk(MASTER, pt, CHUNK)
    b = encrypt_single_chunk(MASTER, pt, CHUNK)
    assert a[10:HEADER_SIZE] != b[10:HEADER_SIZE]   # fresh salt + prefix
    assert a[HEADER_SIZE:] != b[HEADER_SIZE:]       # so different key -> different ciphertext


def test_too_big_for_one_chunk():
    with pytest.raises(ValueError):
        encrypt_single_chunk(MASTER, bytes(CHUNK + 1), chunk_size=CHUNK)


def test_every_single_bit_flip_anywhere_is_rejected():
    blob = encrypt_single_chunk(MASTER, os.urandom(40), chunk_size=CHUNK)
    for i in range(len(blob) * 8):
        with pytest.raises(ChunkcryptError):
            decrypt_single_chunk(MASTER, flip(blob, i // 8, i % 8))


def test_header_tamper_that_still_parses_fails_authentication():
    blob = encrypt_single_chunk(MASTER, b"hello", chunk_size=CHUNK)
    bigger = blob[:6] + struct.pack(">I", 2 * CHUNK) + blob[10:]
    Header.parse(bigger[:HEADER_SIZE])  # it is a perfectly valid header...
    with pytest.raises(AuthenticationError):
        decrypt_single_chunk(MASTER, bigger)  # ...but it changes the key, so the tag fails


def test_header_tamper_that_breaks_parsing_is_a_header_error():
    blob = encrypt_single_chunk(MASTER, b"hello", chunk_size=CHUNK)
    with pytest.raises(HeaderError):
        decrypt_single_chunk(MASTER, b"XXXX" + blob[4:])


def test_wrong_master_key():
    blob = encrypt_single_chunk(MASTER, b"hello", chunk_size=CHUNK)
    with pytest.raises(AuthenticationError):
        decrypt_single_chunk(os.urandom(32), blob)


@pytest.mark.parametrize("cut", [1, TAG_SIZE, TAG_SIZE + 5])
def test_truncated_blob(cut):
    blob = encrypt_single_chunk(MASTER, b"hello world, this is a test", chunk_size=CHUNK)
    with pytest.raises(ChunkcryptError):
        decrypt_single_chunk(MASTER, blob[:-cut])


def test_header_only_or_shorter():
    blob = encrypt_single_chunk(MASTER, b"hi", chunk_size=CHUNK)
    for n in (0, 10, HEADER_SIZE - 1, HEADER_SIZE):
        with pytest.raises(ChunkcryptError):
            decrypt_single_chunk(MASTER, blob[:n])


def _forge(chunk_counter: int, is_final: bool, pt: bytes) -> bytes:
    """Build a stream by hand whose only chunk has the given counter/flag."""
    header = Header.new(CHUNK)
    raw = header.serialise()
    key = derive_stream_key(MASTER, header.salt, raw)
    return raw + seal_chunk(key, build_nonce(header.nonce_prefix, chunk_counter, is_final), pt)


def test_truncation_in_miniature_non_final_chunk_is_rejected():
    # Chunk 0 of a longer stream (flag 0), with everything after it cut off.
    with pytest.raises(AuthenticationError):
        decrypt_single_chunk(MASTER, _forge(0, False, b"first chunk of many"))


def test_chunk_from_another_position_is_rejected():
    # A genuine final chunk, but sealed as chunk #1 -- presented at position 0.
    with pytest.raises(AuthenticationError):
        decrypt_single_chunk(MASTER, _forge(1, True, b"I belong at position 1"))


def test_chunk_spliced_from_another_stream_is_rejected():
    a = encrypt_single_chunk(MASTER, b"stream A secret", chunk_size=CHUNK)
    b = encrypt_single_chunk(MASTER, b"stream B secret", chunk_size=CHUNK)
    spliced = b[:HEADER_SIZE] + a[HEADER_SIZE:]   # B's header, A's chunk
    with pytest.raises(AuthenticationError):
        decrypt_single_chunk(MASTER, spliced)


def test_more_than_one_chunk_of_data_is_refused_for_now():
    blob = encrypt_single_chunk(MASTER, bytes(CHUNK), chunk_size=CHUNK)
    with pytest.raises(ChunkcryptError):
        decrypt_single_chunk(MASTER, blob + bytes(1))
