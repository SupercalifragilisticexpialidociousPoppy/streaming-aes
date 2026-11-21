import pytest

from errors import CounterOverflowError
from nonce import MAX_COUNTER, NONCE_SIZE, build_nonce

PREFIX = bytes.fromhex("a1a2a3a4a5a6a7")


def test_layout_prefix_counter_flag():
    n = build_nonce(PREFIX, 0x01020304, is_final=False)
    assert len(n) == NONCE_SIZE == 12
    assert n == PREFIX + bytes.fromhex("01020304") + b"\x00"
    assert build_nonce(PREFIX, 0, is_final=True) == PREFIX + bytes(4) + b"\x01"


def test_nonces_never_repeat_within_a_stream():
    seen = set()
    for counter in range(5000):
        seen.add(build_nonce(PREFIX, counter, is_final=False))
    seen.add(build_nonce(PREFIX, 5000, is_final=True))
    assert len(seen) == 5001


def test_final_flag_changes_the_nonce():
    assert build_nonce(PREFIX, 7, False) != build_nonce(PREFIX, 7, True)


def test_last_legal_counter_is_fine():
    assert build_nonce(PREFIX, MAX_COUNTER, True)[7:11] == b"\xff\xff\xff\xff"


def test_counter_overflow_raises_instead_of_wrapping():
    assert MAX_COUNTER == 2**32 - 1
    with pytest.raises(CounterOverflowError):
        build_nonce(PREFIX, 2**32, is_final=False)


def test_bad_inputs():
    with pytest.raises(ValueError):
        build_nonce(PREFIX, -1, False)
    with pytest.raises(ValueError):
        build_nonce(PREFIX[:6], 0, False)
