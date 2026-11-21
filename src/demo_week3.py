"""
Week-3 live demo: one message, encrypted as a single chunk in the frozen v1 format,
then attacked eleven ways.

    python demo_week3.py
    python demo_week3.py "your own message here"
"""
import os
import struct
import sys

from chunk_aead import TAG_SIZE, open_chunk, seal_chunk
from errors import ChunkcryptError, CounterOverflowError
from header import HEADER_SIZE, Header
from kdf import derive_stream_key
from nonce import build_nonce
from single_chunk import decrypt_single_chunk, encrypt_single_chunk

CHUNK = 1 << 20


def hx(b: bytes, n: int = 16) -> str:
    return b[:n].hex(" ") + (" ..." if len(b) > n else "")


def step(title: str) -> None:
    print(f"\n== {title} " + "=" * max(0, 64 - len(title)))


def flip(blob: bytes, i: int) -> bytes:
    b = bytearray(blob)
    b[i] ^= 0x01
    return bytes(b)


def by_hand(master: bytes, pt: bytes, counter: int, final: bool, header: Header | None = None) -> bytes:
    header = header or Header.new(CHUNK)
    raw = header.serialise()
    key = derive_stream_key(master, header.salt, raw)
    return raw + seal_chunk(key, build_nonce(header.nonce_prefix, counter, final), pt)


def main() -> None:
    message = (sys.argv[1] if len(sys.argv) > 1 else "Meet at the library at 6pm. Bring the notes.").encode()
    master = os.urandom(32)

    step("1. Inputs")
    print(f"{'master key (32 B, secret)':<27}: {hx(master)}")
    print(f"{f'plaintext ({len(message)} B)':<27}: {message.decode(errors='replace')}")

    step("2. Header: 49 bytes, sent in the clear")
    header = Header.new(CHUNK)
    raw = header.serialise()
    print(f"magic      : {raw[0:4]!r}")
    print(f"version    : {raw[4]}    alg_id: {raw[5]} (AES-256-GCM, key from HKDF-SHA256)")
    print(f"chunk_size : {header.chunk_size:,} bytes")
    print(f"salt       : {hx(header.salt)}  (32 B, fresh random)")
    print(f"prefix     : {header.nonce_prefix.hex(' ')}  (7 B, fresh random)")

    step("3. HKDF: per-stream key = HKDF(master, salt, info = all 49 header bytes)")
    key = derive_stream_key(master, header.salt, raw)
    print(f"stream key : {hx(key)}")

    step("4. Nonce for chunk 0, which is also the last chunk")
    nonce = build_nonce(header.nonce_prefix, 0, True)
    print(f"nonce      : [{nonce[:7].hex(' ')}] [{nonce[7:11].hex(' ')}] [{nonce[11:].hex()}]")
    print("               prefix (7 B)           counter (4 B) final")

    step("5. AES-256-GCM: one call seals the chunk")
    sealed = seal_chunk(key, nonce, message)
    blob = raw + sealed
    print(f"ciphertext : {hx(sealed[:-TAG_SIZE])}")
    print(f"tag        : {sealed[-TAG_SIZE:].hex(' ')}")
    print(f"on the wire: {HEADER_SIZE} + {len(message)} + {TAG_SIZE} = {len(blob)} bytes")

    step("6. Decrypt (OpenSSL) and cross-check with OUR OWN GCM + GHASH")
    print(f"library    : {decrypt_single_chunk(master, blob, 'library').decode(errors='replace')}")
    print(f"our GCM    : {decrypt_single_chunk(master, blob, 'reference').decode(errors='replace')}")
    same = seal_chunk(key, nonce, message, "reference") == sealed
    print(f"our GCM produces byte-identical ciphertext + tag: {same}")

    step("7. Attacks: every one must be REJECTED")
    other = encrypt_single_chunk(master, b"a completely different file", CHUNK)
    resized = raw[:6] + struct.pack(">I", 2 * CHUNK) + raw[10:]
    attacks = [
        ("flip 1 bit of ciphertext", flip(blob, HEADER_SIZE)),
        ("flip 1 bit of the tag", flip(blob, len(blob) - 1)),
        ("change chunk_size in header (1 MiB -> 2 MiB)", resized + sealed),
        ("change 1 bit of the salt", flip(blob, 10)),
        ("change 1 bit of the nonce prefix", flip(blob, 42)),
        ("corrupt the magic bytes", flip(blob, 0)),
        ("cut off the last 5 bytes", blob[:-5]),
        ("decrypt with the wrong master key", None),
        ("truncation: chunk 0 of a longer stream, rest cut off", by_hand(master, message, 0, False)),
        ("reorder: a chunk sealed for position 1, shown at 0", by_hand(master, message, 1, True)),
        ("splice: this stream's header + another stream's chunk", raw + other[HEADER_SIZE:]),
    ]
    for name, forged in attacks:
        try:
            if forged is None:
                decrypt_single_chunk(os.urandom(32), blob)
            else:
                decrypt_single_chunk(master, forged)
            verdict = "ACCEPTED  <-- BUG"
        except ChunkcryptError as e:
            verdict = f"REJECTED  ({type(e).__name__})"
        print(f"  {name:<54} {verdict}")

    step("8. Same message encrypted twice")
    a, b = encrypt_single_chunk(master, message, CHUNK), encrypt_single_chunk(master, message, CHUNK)
    print(f"run 1 ciphertext: {hx(a[HEADER_SIZE:])}")
    print(f"run 2 ciphertext: {hx(b[HEADER_SIZE:])}")
    print("different every time (fresh salt -> fresh key), so retries never reuse a nonce")

    step("9. Counter overflow guard")
    try:
        build_nonce(header.nonce_prefix, 2**32, False)
        print("chunk 2^32 accepted  <-- BUG")
    except CounterOverflowError:
        print("chunk 2^32 refused with CounterOverflowError (never wraps to 0)")


if __name__ == "__main__":
    main()
