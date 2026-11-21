"""
Benchmarks behind docs/BENCHMARKS.md.

    python bench/bench.py

1. Throughput and size overhead vs chunk size (the evidence for choosing 1 MiB).
2. Peak memory: streaming vs one-shot AES-GCM on the same file.
3. Our pure-Python GCM vs the library (OpenSSL) on one 1 MiB chunk.
"""
import io
import os
import sys
import time
import tracemalloc

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

from chunk_aead import seal_chunk  # noqa: E402
from nonce import build_nonce  # noqa: E402
from stream import StreamEncryptor  # noqa: E402

KiB, MiB = 1024, 1024 * 1024
KEY = os.urandom(32)


class Sink:
    """Discards output, so only encryption is timed and no output buffer is kept."""
    def write(self, data):
        pass


def best_of(runs, fn):
    times = []
    for _ in range(runs):
        t = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t)
    return min(times)


def throughput_vs_chunk_size(total=128 * MiB, rounds=5):
    """Sizes are interleaved round by round and the median reported, because single runs
    swing by 2x on a laptop (CPU frequency, cache effects)."""
    data = os.urandom(total)
    sizes = (4 * KiB, 16 * KiB, 64 * KiB, 256 * KiB, 1 * MiB, 4 * MiB, 16 * MiB)
    speeds = {s: [] for s in sizes}
    for _ in range(rounds):
        for s in sizes:
            secs = best_of(1, lambda: StreamEncryptor(KEY, s).encrypt(io.BytesIO(data), Sink()))
            speeds[s].append(total / MiB / secs)

    print(f"\n## 1. Throughput vs chunk size ({total // MiB} MiB, library backend, {rounds} rounds)\n")
    print("| Chunk size | Chunks | Median MiB/s | Range MiB/s | Size overhead | Max file (2^32 chunks) |")
    print("|---|---|---|---|---|---|")
    for s in sizes:
        chunks = -(-total // s)
        overhead = (49 + 16 * chunks) / total * 100
        label = f"{s // KiB} KiB" if s < MiB else f"{s // MiB} MiB"
        max_file = (s << 32) / 2 ** 40
        max_label = f"{max_file:,.0f} TiB" if max_file < 1024 else f"{max_file / 1024:,.0f} PiB"
        v = sorted(speeds[s])
        print(f"| {label} | {chunks:,} | {v[len(v) // 2]:,.0f} | {v[0]:,.0f}-{v[-1]:,.0f} | "
              f"{overhead:.4f} % | {max_label} |")
    one_shot = best_of(3, lambda: AESGCM(KEY).encrypt(os.urandom(12), data, None))
    print(f"| one-shot AES-GCM | 1 | {total / MiB / one_shot:,.0f} | | {16 / total * 100:.6f} % | 64 GiB |")


def peak_memory(total=256 * MiB):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_bench_input.bin")
    with open(path, "wb") as f:
        for _ in range(total // MiB):
            f.write(os.urandom(MiB))
    try:
        def streaming():
            with open(path, "rb") as src:
                StreamEncryptor(KEY).encrypt(src, Sink())

        def one_shot():
            with open(path, "rb") as src:
                AESGCM(KEY).encrypt(os.urandom(12), src.read(), None)

        print(f"\n## 2. Peak memory encrypting a {total // MiB} MiB file (tracemalloc)\n")
        print("| Method | Peak memory |")
        print("|---|---|")
        for name, fn in (("Streaming, 1 MiB chunks", streaming), ("One-shot AES-GCM", one_shot)):
            tracemalloc.start()
            fn()
            peak = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
            print(f"| {name} | {peak / MiB:,.2f} MiB |")
    finally:
        os.remove(path)


def ours_vs_library():
    chunk = os.urandom(MiB)
    nonce = build_nonce(os.urandom(7), 0, True)
    lib = best_of(20, lambda: seal_chunk(KEY, nonce, chunk, "library"))
    ours = best_of(1, lambda: seal_chunk(KEY, nonce, chunk, "reference"))
    print("\n## 3. Sealing one 1 MiB chunk\n")
    print("| Implementation | Time | Throughput |")
    print("|---|---|---|")
    print(f"| Library (OpenSSL: AES-NI + PCLMULQDQ) | {lib * 1000:.2f} ms | {1 / lib:,.0f} MiB/s |")
    print(f"| Ours (pure Python, Shoup 4 KB table) | {ours * 1000:,.0f} ms | {1 / ours:.1f} MiB/s |")
    print(f"\nRatio: about {ours / lib:,.0f}x")


if __name__ == "__main__":
    throughput_vs_chunk_size()
    peak_memory()
    ours_vs_library()
