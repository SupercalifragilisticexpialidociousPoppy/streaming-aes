from counter import init_counters
from aes_ctr import encrypt_plaintext, decrypt_ciphertext

# Setup test parameters
key = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121315415161718191a1b1c1d1e1f")
iv = bytes.fromhex("101112131415161718191a1b")
original_pt = b"This is a secret message that spans multiple blocks!"

# 1. Setup counters
y0, y1 = init_counters(iv)

# 2. Encrypt
ct = encrypt_plaintext(key, y1, original_pt)

# 3. Decrypt
recovered_pt = decrypt_ciphertext(key, y1, ct)

print(f"Original PT:  {original_pt}")
print(f"Ciphertext:   {ct.hex()}")
print(f"Recovered PT: {recovered_pt}")

assert recovered_pt == original_pt, "Decryption failed to recover original plaintext!"
print("\nSUCCESS: Symmetrical CTR round-trip complete!")