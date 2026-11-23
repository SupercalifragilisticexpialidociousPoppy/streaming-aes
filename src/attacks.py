"""
The attack suite: five attacks on the naive design (naive.py), each repeated on ours (stream.py).

    python attacks.py

The attacker can read and rewrite ciphertext but never sees a key. "Accepted" means the
receiver's decryptor returned plaintext without raising an error.
"""
import io
import os

from cryptography.exceptions import InvalidTag

from chunk_aead import TAG_SIZE, seal_chunk
from errors import ChunkcryptError
from ghash import build_ghash_payload, derive_hash_key, run_ghash_loop
from header import HEADER_SIZE, Header
from kdf import derive_stream_key
from naive import naive_decrypt, naive_encrypt, naive_records
from nonce import build_nonce
from poly_multiplication import build_shoup_table, gf_2_128_mul
from stream import StreamDecryptor, StreamEncryptor

KEY = os.urandom(32)          # the victim's master key; the attacker never uses it
CHUNK = 1024
DATA = os.urandom(4 * CHUNK)  # a 4-chunk file


# ---------------------------------------------------------------- helpers

def hardened_encrypt(data: bytes, chunk: int = CHUNK) -> bytes:
    out = io.BytesIO()
    StreamEncryptor(KEY, chunk).encrypt(io.BytesIO(data), out)
    return out.getvalue()


def hardened_accepts(blob: bytes) -> bool:
    try:
        StreamDecryptor(KEY).decrypt(io.BytesIO(blob), io.BytesIO())
        return True
    except ChunkcryptError:
        return False


def naive_accepts(blob: bytes, chunk: int = CHUNK) -> bool:
    try:
        naive_decrypt(KEY, blob, chunk)
        return True
    except InvalidTag:
        return False


def hardened_records(blob: bytes, chunk: int = CHUNK) -> tuple[bytes, list[bytes]]:
    body, size = blob[HEADER_SIZE:], chunk + TAG_SIZE
    return blob[:HEADER_SIZE], [body[i:i + size] for i in range(0, len(body), size)]


# ---------------------------------------------------------------- attacks 1-4: move valid chunks

def truncation():
    naive = naive_records(naive_encrypt(KEY, DATA, CHUNK), CHUNK)
    header, recs = hardened_records(hardened_encrypt(DATA))
    return naive_accepts(b"".join(naive[:-1])), hardened_accepts(header + b"".join(recs[:-1]))


def reordering():
    naive = naive_records(naive_encrypt(KEY, DATA, CHUNK), CHUNK)
    header, recs = hardened_records(hardened_encrypt(DATA))
    naive[0], naive[1] = naive[1], naive[0]
    recs[0], recs[1] = recs[1], recs[0]
    return naive_accepts(b"".join(naive)), hardened_accepts(header + b"".join(recs))


def replay():
    naive = naive_records(naive_encrypt(KEY, DATA, CHUNK), CHUNK)
    header, recs = hardened_records(hardened_encrypt(DATA))
    return (naive_accepts(b"".join(naive[:2] + [naive[1]] + naive[2:])),
            hardened_accepts(header + b"".join(recs[:2] + [recs[1]] + recs[2:])))


def splicing():
    other = os.urandom(len(DATA))                       # a second file, same master key
    naive_a = naive_records(naive_encrypt(KEY, DATA, CHUNK), CHUNK)
    naive_b = naive_records(naive_encrypt(KEY, other, CHUNK), CHUNK)
    header_a, recs_a = hardened_records(hardened_encrypt(DATA))
    _, recs_b = hardened_records(hardened_encrypt(other))
    naive_a[1], recs_a[1] = naive_b[1], recs_b[1]
    return naive_accepts(b"".join(naive_a)), hardened_accepts(header_a + b"".join(recs_a))


# ---------------------------------------------------------------- attack 5: nonce reuse -> forgery
#
# Two 16-byte messages sealed under the same key and nonce. With no AAD, GHASH of a one-block
# message C is  S = C*H^2 XOR L*H  (L = the length block), and the tag is  T = S XOR E_K(J0).
# XOR the two tags: the L*H and E_K(J0) terms cancel, leaving
#       T1 XOR T2 = (C1 XOR C2) * H^2      =>      H^2 = (T1 XOR T2) / (C1 XOR C2)
# Squaring is one-to-one in GF(2^128), so H is the unique square root: H = (H^2)^(2^127).
# Then E_K(J0) = T1 XOR GHASH_H(C1), and the attacker can tag any ciphertext they like.

ONE = 1 << 127                 # the field element "1" in GCM's reversed bit order


def gf_pow(x: int, e: int) -> int:
    result = ONE
    while e:
        if e & 1:
            result = gf_2_128_mul(result, x)
        x = gf_2_128_mul(x, x)
        e >>= 1
    return result


def ghash_one_block(h: int, block: bytes) -> int:
    return int.from_bytes(run_ghash_loop(build_ghash_payload(b"", block), build_shoup_table(h)), "big")


def recover_h(c1: bytes, t1: bytes, c2: bytes, t2: bytes) -> int:
    dc = int.from_bytes(c1, "big") ^ int.from_bytes(c2, "big")
    dt = int.from_bytes(t1, "big") ^ int.from_bytes(t2, "big")
    h_squared = gf_2_128_mul(dt, gf_pow(dc, (1 << 128) - 2))   # x^(2^128 - 2) = 1/x
    return gf_pow(h_squared, 1 << 127)                          # square root


def forge(c1: bytes, t1: bytes, c2: bytes, t2: bytes, known_p1: bytes, wanted: bytes) -> tuple[bytes, bytes, int]:
    """Known plaintext P1 gives the keystream; H gives the tag. Returns (C*, T*, recovered H)."""
    h = recover_h(c1, t1, c2, t2)
    mask = int.from_bytes(t1, "big") ^ ghash_one_block(h, c1)
    forged_c = bytes(a ^ b ^ w for a, b, w in zip(c1, known_p1, wanted))
    forged_t = (ghash_one_block(h, forged_c) ^ mask).to_bytes(16, "big")
    return forged_c, forged_t, h


P1 = b"PAY ALICE 100.00"       # known to the attacker (e.g. a fixed file header)
P2 = b"PAY BOB   250.00"
WANTED = b"PAY EVE 99999.99"   # what the attacker wants the receiver to accept


def nonce_reuse():
    # Naive: random nonces repeat when the random source does (simulated: same 12 bytes twice).
    repeated = os.urandom(12)
    r1 = naive_encrypt(KEY, P1, 16, random_bytes=lambda n: repeated)
    r2 = naive_encrypt(KEY, P2, 16, random_bytes=lambda n: repeated)
    c1, t1 = r1[12:28], r1[28:]
    c2, t2 = r2[12:28], r2[28:]
    forged_c, forged_t, h = forge(c1, t1, c2, t2, P1, WANTED)
    forged = repeated + forged_c + forged_t
    naive_ok = naive_accepts(forged, 16) and naive_decrypt(KEY, forged, 16) == WANTED
    h_matches = h == derive_hash_key(KEY)

    # Ours: two files whose 7-byte nonce prefixes collide (likely after ~2^28 files). Built with
    # the production functions; the only thing forced is the shared prefix.
    prefix = os.urandom(7)
    nonce = build_nonce(prefix, 0, True)
    files = []
    for p in (P1, P2):
        header = Header(chunk_size=16, salt=os.urandom(32), nonce_prefix=prefix)
        header_bytes = header.serialise()
        key = derive_stream_key(KEY, header.salt, header_bytes)
        files.append(header_bytes + seal_chunk(key, nonce, p))
    (h1, s1), (h2, s2) = [(f[:HEADER_SIZE], f[HEADER_SIZE:]) for f in files]
    forged_c, forged_t, _ = forge(s1[:16], s1[16:], s2[:16], s2[16:], P1, WANTED)
    hardened_ok = hardened_accepts(h1 + forged_c + forged_t)
    return naive_ok, hardened_ok, h_matches


ATTACKS = [
    ("1. Truncation (drop the last chunk)", truncation),
    ("2. Reordering (swap chunks 0 and 1)", reordering),
    ("3. Replay (repeat chunk 1)", replay),
    ("4. Splicing (chunk 1 from another file)", splicing),
    ("5. Nonce reuse -> recover H -> forge", nonce_reuse),
]


def main():
    print(f"{'Attack':<42} {'Naive':<10} {'Ours':<10}")
    print("-" * 62)
    for name, attack in ATTACKS:
        naive_ok, ours_ok, *extra = attack()
        verdict = lambda ok: "ACCEPTED" if ok else "rejected"
        print(f"{name:<42} {verdict(naive_ok):<10} {verdict(ours_ok):<10}")
        if extra:
            print(f"{'':<42} recovered H == real H: {extra[0]}")


if __name__ == "__main__":
    main()
