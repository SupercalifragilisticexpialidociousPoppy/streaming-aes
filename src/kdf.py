import pytest
from nonce import build_nonce, CounterOverflowError

def test_build_nonce_normal():
    """Ensure normal nonces are packed correctly."""
    prefix = b'\x11\x22\x33\x44\x55\x66\x77'
    
    # Test a normal chunk (counter 0, not final)
    nonce = build_nonce(prefix, 0, is_final=False)
    assert len(nonce) == 12
    assert nonce == b'\x11\x22\x33\x44\x55\x66\x77\x00\x00\x00\x00\x00'
    
    # Test the final chunk (counter 5, final)
    nonce_final = build_nonce(prefix, 5, is_final=True)
    assert len(nonce_final) == 12
    assert nonce_final == b'\x11\x22\x33\x44\x55\x66\x77\x00\x00\x00\x05\x01'

def test_counter_overflow_guard():
    """Ensure the system hard-crashes before a nonce can wrap back to 0."""
    prefix = b'\x00' * 7
    max_safe_counter = (1 << 32) - 1  # 4,294,967,295
    
    # The maximum safe value should succeed
    safe_nonce = build_nonce(prefix, max_safe_counter, False)
    assert len(safe_nonce) == 12
    
    # The moment we hit 2^32, it must raise our specific error
    unsafe_counter = 1 << 32
    with pytest.raises(CounterOverflowError, match="Maximum chunk counter exceeded"):
        build_nonce(prefix, unsafe_counter, False)