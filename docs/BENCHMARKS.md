# Benchmarks

    python bench/bench.py

Measured on an AMD Ryzen 7 7745HX laptop, 15 GB RAM, Windows 11, Python 3.12, `cryptography` 50.
Encryption output goes to a sink that discards it, so disk speed is not measured.

## 1. Throughput vs chunk size (128 MiB, library backend, 5 interleaved rounds)

| Chunk size | Chunks | Median MiB/s | Range MiB/s | Size overhead | Max file (2³² chunks) |
|---|---|---|---|---|---|
| 4 KiB | 32,768 | 1,506 | 1,472–1,531 | 0.3907 % | 16 TiB |
| 16 KiB | 8,192 | 3,807 | 3,587–3,872 | 0.0977 % | 64 TiB |
| 64 KiB | 2,048 | 6,468 | 6,133–6,625 | 0.0245 % | 256 TiB |
| 256 KiB | 512 | 7,966 | 7,474–8,104 | 0.0061 % | 1 PiB |
| **1 MiB** | **128** | **2,498** | **2,441–2,538** | **0.0016 %** | **4 PiB** |
| 4 MiB | 32 | 3,037 | 2,962–3,071 | 0.0004 % | 16 PiB |
| 16 MiB | 8 | 3,043 | 2,883–3,145 | 0.0001 % | 64 PiB |
| one-shot AES-GCM | 1 | 5,533 | | 0.000012 % | 64 GiB |

**Reading it.**
- Below 16 KiB the fixed cost per chunk (a GCM setup and a Python loop iteration) dominates.
- 64–256 KiB is fastest because a chunk and its copies fit in the CPU's cache. 256 KiB was not
  stable: in a separate run of 5 rounds it measured 2,170–5,170 MiB/s, while 1 MiB stayed at
  ~2,500 MiB/s in every run.
- From 1 MiB up, every chunk spills out of the cache and speed levels off near 2.5–3 GB/s.

**Why 1 MiB.** Every size from 16 KiB up is faster than a typical SSD (2–3 GB/s), so throughput
does not decide it. 64 KiB is fastest but caps a file at 256 TiB, below the PRD's ≥ 1 PiB
requirement. 256 KiB meets it but was unstable. 1 MiB is stable, has the lowest overhead of the
sizes that keep memory small, and allows 4 PiB.

## 2. Peak memory encrypting a 256 MiB file (tracemalloc)

| Method | Peak memory |
|---|---|
| Streaming, 1 MiB chunks | **3.01 MiB** |
| One-shot AES-GCM | 512.01 MiB (the whole file plus the whole ciphertext) |

`test/test_memory.py` checks that peak memory is the same for a 5 MiB and a 50 MiB file, for both
encryption and decryption: **3.02 MiB** in all four cases. The three 1 MiB buffers alive at the
peak are the current chunk, the look-ahead chunk, and the chunk being produced.

tracemalloc counts memory allocated by Python code, not the whole process (the interpreter itself
uses more than this). What matters is that the number does not change with file size.

The midsem figure was 4.02 MiB; reading each chunk without an extra copy brought it to 3.02 MiB.

## 3. Our GCM vs the library, sealing one 1 MiB chunk

| Implementation | Time | Throughput |
|---|---|---|
| Library (OpenSSL: AES-NI + PCLMULQDQ) | 0.23 ms | 4,440 MiB/s |
| Ours (pure Python, Shoup 4 KB table) | 162 ms | 6.2 MiB/s |

About **700x**. CPUs have dedicated instructions: AES-NI runs AES rounds in hardware, and
PCLMULQDQ is a carry-less multiply that does most of a GF(2¹²⁸) multiplication in one instruction.
Our version does each byte and table lookup in the Python interpreter. Both produce identical
output; ours exists to show we understand GCM and to cross-check the library.

Within our own GCM, Shoup's table makes GHASH **6.3x faster** than bit-by-bit multiplication
(64 KiB of data: 10 ms vs 63 ms), and the NIST suite runs in about 1 s per file. At the midsem it
took 30–45 s per file, because the table was rebuilt with 256 full multiplications for every test
case and a new AES object was created for every 16-byte block.
