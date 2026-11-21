"""
GF(2^128) arithmetic and GHASH (week 2). The fast Shoup path must agree with the
textbook bitwise multiply everywhere; the bitwise multiply must obey field laws.
"""
import random

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ghash import build_ghash_payload, derive_hash_key, run_ghash_loop, shoup_multiply
from poly_multiplication import build_shoup_table, build_shoup_table_bitwise, gf_2_128_mul
from ref_gcm import reference_gcm_decrypt, reference_gcm_encrypt

ONE = 1 << 127  # In GCM's bit order the leftmost bit is x^0, so "1" is 0x80000...0
X = 1 << 126    # and the polynomial "x" is 0x40000...0

rng = random.Random(2026)  # fixed seed: reproducible test inputs (not used for any keys)


def rand128():
    return rng.getrandbits(128)


def test_one_is_the_identity():
    for _ in range(100):
        a = rand128()
        assert gf_2_128_mul(a, ONE) == a
        assert gf_2_128_mul(ONE, a) == a


def test_zero_annihilates():
    assert gf_2_128_mul(rand128(), 0) == 0


def test_multiplication_commutes_and_distributes():
    for _ in range(200):
        a, b, c = rand128(), rand128(), rand128()
        assert gf_2_128_mul(a, b) == gf_2_128_mul(b, a)
        assert gf_2_128_mul(a, b ^ c) == gf_2_128_mul(a, b) ^ gf_2_128_mul(a, c)
        assert gf_2_128_mul(gf_2_128_mul(a, b), c) == gf_2_128_mul(a, gf_2_128_mul(b, c))


def test_x_to_the_128_wraps_to_the_reduction_polynomial():
    # x^127 * x = x^128 = x^7 + x^2 + x + 1  (mod the GCM polynomial)
    x127 = 1  # the rightmost bit is x^127
    expected = (1 << 127) | (1 << 126) | (1 << 125) | (1 << 120)  # 1 + x + x^2 + x^7
    assert gf_2_128_mul(x127, X) == expected


def test_fast_table_matches_bitwise_table():
    for _ in range(20):
        h = rand128()
        assert build_shoup_table(h) == build_shoup_table_bitwise(h)


def test_shoup_multiply_matches_bitwise_on_10000_random_inputs():
    for _ in range(100):
        h = rand128()
        table = build_shoup_table(h)
        for _ in range(100):
            a = rand128()
            assert shoup_multiply(a, table) == gf_2_128_mul(a, h)


def test_ghash_known_answer_gcm_spec_test_case_2():
    # McGrew-Viega GCM spec, Test Case 2: K = 0^128, IV = 0^96, P = 0^128
    key = bytes(16)
    h = derive_hash_key(key)
    assert h == 0x66e94bd4ef8a2c3b884cfa59ca342b2e

    ciphertext = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")
    payload = build_ghash_payload(b"", ciphertext)
    assert run_ghash_loop(payload, build_shoup_table(h)).hex() == "f38cbb1ad69223dcc3457ae5b6b0f885"

    ct, tag = reference_gcm_encrypt(key, bytes(12), bytes(16), b"")
    assert ct == ciphertext
    assert tag.hex() == "ab6e47d42cec13bdf53a67b21257bddf"


@pytest.mark.parametrize("key_len", [16, 24, 32])
@pytest.mark.parametrize("iv_len", [12, 8, 60])
def test_reference_gcm_matches_openssl_on_random_inputs(key_len, iv_len):
    for _ in range(25):
        key = rng.randbytes(key_len)
        iv = rng.randbytes(iv_len)
        pt = rng.randbytes(rng.randrange(0, 200))
        aad = rng.randbytes(rng.randrange(0, 50))

        ct, tag = reference_gcm_encrypt(key, iv, pt, aad)
        assert ct + tag == AESGCM(key).encrypt(iv, pt, aad)
        assert reference_gcm_decrypt(key, iv, ct, tag, aad) == pt


def test_reference_gcm_rejects_any_single_bit_flip():
    key, iv = rng.randbytes(32), rng.randbytes(12)
    pt, aad = rng.randbytes(40), rng.randbytes(10)
    ct, tag = reference_gcm_encrypt(key, iv, pt, aad)

    for i in range(len(ct) * 8):
        bad = bytearray(ct)
        bad[i // 8] ^= 1 << (i % 8)
        with pytest.raises(ValueError):
            reference_gcm_decrypt(key, iv, bytes(bad), tag, aad)

    for i in range(len(tag) * 8):
        bad = bytearray(tag)
        bad[i // 8] ^= 1 << (i % 8)
        with pytest.raises(ValueError):
            reference_gcm_decrypt(key, iv, ct, bytes(bad), aad)
