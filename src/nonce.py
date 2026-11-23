"""
The 96-bit per-chunk nonce:

    | nonce_prefix (7 B) | counter (4 B, big-endian) | final flag (1 B) |

- prefix: fixed for the whole stream (from the header)
- counter: chunk index 0, 1, 2, ... -- binds each chunk to its position (stops reordering/replay)
- flag: 0x00 for every chunk except the last, 0x01 for the last (stops truncation)

Within one stream the counter never repeats, so a nonce can never repeat: the collision
probability is exactly zero, not merely small. 96 bits is GCM's fast path -- any other
IV length costs an extra GHASH pass to turn it into a counter block.
"""
import struct

from errors import CounterOverflowError  # re-exported: `from nonce import CounterOverflowError` works
from header import NONCE_PREFIX_SIZE

NONCE_SIZE = 12
MAX_COUNTER = (1 << 32) - 1   # 2^32 chunks x 1 MiB = 4 PiB per stream
FLAG_NOT_FINAL = 0x00
FLAG_FINAL = 0x01


def build_nonce(prefix: bytes, counter: int, is_final: bool) -> bytes:
    if len(prefix) != NONCE_PREFIX_SIZE:
        raise ValueError("nonce prefix must be 7 bytes")
    if counter < 0:
        raise ValueError("counter must be non-negative")
    if counter > MAX_COUNTER:
        # Never wrap: a wrapped counter is a repeated nonce, and a repeated GCM nonce
        # leaks the XOR of two plaintexts and lets an attacker solve for H.
        raise CounterOverflowError("stream exceeds 2^32 chunks")
    flag = FLAG_FINAL if is_final else FLAG_NOT_FINAL
    return prefix + struct.pack(">IB", counter, flag)

