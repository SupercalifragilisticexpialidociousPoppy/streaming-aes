import struct

import pytest

from errors import HeaderError
from header import (HEADER_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, NONCE_PREFIX_SIZE, SALT_SIZE,
                    Header)


def test_header_is_49_bytes_with_fields_at_spec_offsets():
    h = Header.new(1 << 20)
    raw = h.serialise()
    assert HEADER_SIZE == 49 and len(raw) == 49
    assert raw[0:4] == b"CHNK"
    assert raw[4] == 0x01
    assert raw[5] == 0x01
    assert struct.unpack(">I", raw[6:10])[0] == 1 << 20
    assert raw[10:42] == h.salt and len(h.salt) == SALT_SIZE
    assert raw[42:49] == h.nonce_prefix and len(h.nonce_prefix) == NONCE_PREFIX_SIZE


def test_round_trip():
    h = Header.new(4096)
    assert Header.parse(h.serialise()) == h


def test_each_new_header_has_fresh_randomness():
    a, b = Header.new(), Header.new()
    assert a.salt != b.salt
    assert a.nonce_prefix != b.nonce_prefix


def _tweak(raw: bytes, offset: int, value: bytes) -> bytes:
    return raw[:offset] + value + raw[offset + len(value):]


@pytest.mark.parametrize("bad, why", [
    (lambda raw: _tweak(raw, 0, b"XXXX"), "magic"),
    (lambda raw: _tweak(raw, 4, b"\x02"), "version"),
    (lambda raw: _tweak(raw, 5, b"\x07"), "alg_id"),
    (lambda raw: _tweak(raw, 6, struct.pack(">I", 0)), "chunk_size zero"),
    (lambda raw: _tweak(raw, 6, struct.pack(">I", MIN_CHUNK_SIZE - 1)), "chunk_size tiny"),
    (lambda raw: _tweak(raw, 6, struct.pack(">I", MAX_CHUNK_SIZE + 1)), "chunk_size huge"),
    (lambda raw: _tweak(raw, 6, struct.pack(">I", 0xFFFFFFFF)), "chunk_size 4 GiB"),
    (lambda raw: raw[:48], "truncated"),
    (lambda raw: raw + b"\x00", "too long"),
    (lambda raw: b"", "empty"),
])
def test_parse_rejects_malformed_headers(bad, why):
    raw = Header.new(1 << 20).serialise()
    with pytest.raises(HeaderError):
        Header.parse(bad(raw))


def test_cannot_build_invalid_header():
    with pytest.raises(HeaderError):
        Header.new(chunk_size=0)
    with pytest.raises(HeaderError):
        Header(chunk_size=1024, salt=b"short", nonce_prefix=bytes(7)).serialise()


def test_random_bytes_never_crash_the_parser():
    import random
    rng = random.Random(7)
    for _ in range(2000):
        blob = rng.randbytes(rng.choice([0, 1, 48, 49, 49, 49, 50]))
        try:
            Header.parse(blob)
        except HeaderError:
            pass
