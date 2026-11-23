import pytest

from header import Header
from kdf import derive_stream_key, hkdf_sha256


def test_hkdf_matches_rfc5869_test_case_1():
    ikm = bytes([0x0b] * 22)
    salt = bytes(range(0x00, 0x0d))
    info = bytes(range(0xf0, 0xfa))
    okm = hkdf_sha256(ikm, salt, info, 42)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")


def test_stream_key_is_32_bytes_and_deterministic():
    master = bytes(range(32))
    h = Header.new()
    raw = h.serialise()
    k1 = derive_stream_key(master, h.salt, raw)
    assert len(k1) == 32
    assert derive_stream_key(master, h.salt, raw) == k1


def test_every_input_changes_the_key():
    master = bytes(range(32))
    h = Header.new()
    raw = h.serialise()
    base = derive_stream_key(master, h.salt, raw)

    other_master = bytes([1]) + master[1:]
    assert derive_stream_key(other_master, h.salt, raw) != base

    other = Header.new()  # fresh salt -> fresh key: why splicing between streams fails
    assert derive_stream_key(master, other.salt, other.serialise()) != base

    # same salt, but the chunk_size byte changed -> different key: why header tampering fails
    tampered = raw[:6] + b"\x00\x20\x00\x00" + raw[10:]
    assert derive_stream_key(master, h.salt, tampered) != base


def test_rejects_wrong_sizes():
    h = Header.new()
    raw = h.serialise()
    with pytest.raises(ValueError):
        derive_stream_key(bytes(16), h.salt, raw)
    with pytest.raises(ValueError):
        derive_stream_key(bytes(32), h.salt[:16], raw)
    with pytest.raises(ValueError):
        derive_stream_key(bytes(32), h.salt, raw[:48])
