import os

import pytest

from chunk_aead import TAG_SIZE, open_chunk, seal_chunk
from errors import AuthenticationError
from nonce import build_nonce

KEY = bytes(range(32))
PREFIX = bytes(7)


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 1000, 4096])
def test_our_gcm_and_openssl_produce_identical_chunks(size):
    pt = os.urandom(size)
    nonce = build_nonce(PREFIX, 3, is_final=False)
    lib = seal_chunk(KEY, nonce, pt, backend="library")
    ref = seal_chunk(KEY, nonce, pt, backend="reference")
    assert lib == ref
    assert len(lib) == size + TAG_SIZE
    # and each can open what the other sealed
    assert open_chunk(KEY, nonce, lib, backend="reference") == pt
    assert open_chunk(KEY, nonce, ref, backend="library") == pt


@pytest.mark.parametrize("backend", ["library", "reference"])
def test_wrong_position_or_flag_fails(backend):
    pt = b"chunk payload"
    sealed = seal_chunk(KEY, build_nonce(PREFIX, 5, False), pt, backend)
    with pytest.raises(AuthenticationError):
        open_chunk(KEY, build_nonce(PREFIX, 6, False), sealed, backend)   # moved
    with pytest.raises(AuthenticationError):
        open_chunk(KEY, build_nonce(PREFIX, 5, True), sealed, backend)    # flag changed


@pytest.mark.parametrize("backend", ["library", "reference"])
def test_too_short_is_rejected(backend):
    with pytest.raises(AuthenticationError):
        open_chunk(KEY, build_nonce(PREFIX, 0, True), b"\x00" * 15, backend)
