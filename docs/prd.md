# Streaming AEAD over AES-GCM
## Product Requirements Document v1.0

**Working title:** `chunkcrypt` *(placeholder — rename freely)*
**Type:** Cryptographic library + CLI + attack demonstration suite
**Language:** Python 3.11+
**Status:** Design complete, ready to build

---

# 1. What This Project Is

A **chunked authenticated-encryption layer over AES-256-GCM** that encrypts arbitrarily large files in constant memory, without weakening the security guarantees of the underlying cipher.

Concretely, you are building four things:

1. **A library** that turns AES-GCM — a mode specified for a single atomic message — into a streaming cipher that handles a 50 GiB file in 4 MiB of RAM.
2. **A GHASH / GF(2¹²⁸) implementation from scratch**, table-driven, validated against NIST test vectors. This is the pedagogical core.
3. **A working attack suite** that breaks the naive version of this design five different ways, and demonstrates the hardened version resisting all five.
4. **A quantitative security argument** deriving your chunk size and stream limits *from* published security bounds rather than from convention.

The deliverable is not "we implemented it and it works." The deliverable is a specific number: the concrete security bound your construction achieves, and the measured cost of achieving it.

---

# 2. Motivation

AES-GCM is specified for **one atomic message**. Two consequences follow, and together they are the entire reason this project exists.

**The memory problem.** The AEAD security definition requires verify-then-release: you must not act on plaintext before its tag verifies. The naive way to guarantee that is to buffer the whole file. So encrypting a 50 GiB file needs 50+ GiB of RAM. This is why most reference implementations, tutorials, and student projects quietly cap out at file sizes that fit in memory.

**The correctness problem.** NIST SP 800-38D caps a single GCM invocation at 2³⁹ − 256 bits ≈ **64 GiB**. Above that, AES-GCM is not slow — it is *undefined*. A monolithic implementation has a hard, specification-mandated ceiling it typically does not enforce or even detect.

Chunking solves both. But chunking done naively is catastrophic: it introduces reordering, replay, truncation, splicing, and — worst — nonce reuse, which collapses GCM entirely via the forbidden attack. The engineering content of this project is showing that chunking can be done such that the security bound is *provably unchanged*.

This design is known-good — it is the STREAM construction (Hoang–Reyhanitabar–Rogaway–Vizár, CRYPTO 2015), used by Google Tink's Streaming AEAD, the `age` file format, and the TLS 1.3 record layer. You are re-deriving a published design and proving you understand *why* each element exists. That is the correct ambition level.

---

# 3. Goals and Non-Goals

## 3.1 Goals

| ID | Goal |
|---|---|
| G1 | Constant memory: ≤ 4 MiB working set regardless of file size |
| G2 | Remove the 64 GiB ceiling; support ≥ 4 PiB by construction |
| G3 | Zero probability of (key, nonce) reuse — structural, not probabilistic |
| G4 | Confidentiality and total forgery bounds numerically identical to monolithic AES-GCM |
| G5 | All-or-nothing semantics as observed by the user, despite incremental processing |
| G6 | Detect truncation, reordering, replay, and cross-stream splicing |
| G7 | Own GHASH implementation, validated against NIST SP 800-38D vectors |

## 3.2 Non-Goals

- **Implementing AES itself.** Use the `cryptography` library's AES. A from-scratch AES belongs in an appendix at most.
- **Inventing a new AEAD mode.** You are implementing a published construction.
- **New security proofs.** Reduction-*style reasoning* from existing theorems is the assessed deliverable.
- **A production file-sync product.** No accounts, no server, no database. A socket demo for the presentation is in scope; a product is not.
- **Post-quantum anything.**

## 3.3 Language choice

Python 3.11+ with `cryptography` (OpenSSL backend). Rationale: fast to build, and the OpenSSL backend gives honest hardware-accelerated numbers for the benchmark comparison. Your own GHASH stays as the pedagogical piece, benchmarked separately and honestly.

*Known constraint:* pure-Python GHASH will run at roughly 1–5 MB/s versus ~2–4 GB/s for the PCLMULQDQ path. That three-order-of-magnitude gap is not a failure — it is a result, and explaining *why* hardware crypto instructions exist is worth a slide. Do not use your own GHASH for the throughput benchmarks; use it for correctness and for the GHASH-vs-GHASH comparison only.

*(Go is a valid substitute if the team prefers it — `crypto/cipher` gives the same OpenSSL-class performance. Everything in this document transfers unchanged.)*

---

# 4. System Architecture

```
                    ┌──────────────────────────────┐
   plaintext  ──►   │   StreamEncryptor            │  ──►  ciphertext
   (any size)       │                              │       (header + chunks)
                    │  ┌────────────────────────┐  │
                    │  │ 1. generate salt+prefix│  │
                    │  │ 2. build header        │  │
                    │  │ 3. HKDF → K_stream     │  │
                    │  │ 4. loop:               │  │
                    │  │      read chunk        │  │
                    │  │      build nonce       │  │
                    │  │      AES-GCM encrypt   │  │
                    │  │      write ct ‖ tag    │  │
                    │  └────────────────────────┘  │
                    └──────────────────────────────┘
                              │
                              │  constant memory: 1 chunk + tag
                              ▼
     ┌──────────┬──────────┬──────────┬─────┬──────────┐
     │  HEADER  │ CHUNK 0  │ CHUNK 1  │ ... │ CHUNK n-1│
     │  49 B    │ 1MiB+16B │ 1MiB+16B │     │  ≤+16B   │
     └──────────┴──────────┴──────────┴─────┴──────────┘
                                                  ▲
                                          final flag = 0x01
```

## 4.1 Module breakdown

| Module | Responsibility | Depends on |
|---|---|---|
| `ghash.py` | GF(2¹²⁸) multiplication, Shoup 4K table, GHASH | — |
| `gcm.py` | Reference GCM using own GHASH (correctness only) | `ghash` |
| `header.py` | Header serialise / parse / validate | — |
| `kdf.py` | HKDF-SHA256 key derivation | `cryptography` |
| `nonce.py` | Structured nonce construction, overflow guard | — |
| `stream.py` | `StreamEncryptor` / `StreamDecryptor` | all above |
| `naive.py` | **Deliberately broken** baseline for the attack demo | — |
| `cli.py` | `encrypt` / `decrypt` commands | `stream` |

---

# 5. Wire Format Specification

## 5.1 Layout

```
┌──────────────────────────────────────────────────────────┐
│ HEADER — 49 bytes, plaintext on the wire, authenticated  │
├────────┬──────────────┬───────┬──────────────────────────┤
│ offset │ field        │ size  │ value                    │
├────────┼──────────────┼───────┼──────────────────────────┤
│   0    │ magic        │  4 B  │ "CHNK"                   │
│   4    │ version      │  1 B  │ 0x01                     │
│   5    │ alg_id       │  1 B  │ 0x01 = AES-256-GCM-HKDF  │
│   6    │ chunk_size   │  4 B  │ big-endian, bytes        │
│  10    │ salt         │ 32 B  │ os.urandom(32)           │
│  42    │ nonce_prefix │  7 B  │ os.urandom(7)            │
└────────┴──────────────┴───────┴──────────────────────────┘
┌──────────────────────────────────────────────────────────┐
│ CHUNK i  =  ciphertext ‖ tag(16 B)                       │
│ all chunks are chunk_size bytes except the last          │
└──────────────────────────────────────────────────────────┘
```

## 5.2 Key derivation

```python
K_stream = HKDF-SHA256(
    ikm    = K_master,
    salt   = header.salt,        # 32 random bytes
    info   = header_bytes[0:49], # binds EVERY parameter
    length = 32
)
```

Binding the whole header into HKDF `info` means any tampering with `version`, `alg_id`, or `chunk_size` produces a different `K_stream`, so every chunk fails to authenticate. This is cheaper and harder to get wrong than binding the header as AAD on chunk 0 only.

## 5.3 Nonce construction

```
┌──────── 7 bytes ────────┬── 4 bytes ──┬─ 1 byte ─┐
│      nonce_prefix       │   counter   │   flag   │
└─────────────────────────┴─────────────┴──────────┘
       from header          big-endian    0x00 non-final
                            from 0        0x01 final
```

96 bits total — this is deliberate. GCM has a fast path for 96-bit IVs that skips a GHASH invocation during nonce processing. A 128-bit nonce would cost you throughput for no security benefit.

**Uniqueness argument:**
- *Within a stream:* the prefix is fixed and the counter strictly increments, so collision probability is **exactly zero**, not merely small.
- *Across streams:* the 32-byte salt yields a fresh `K_stream` per file. Two streams never share a key, so a nonce-prefix collision between streams is not a (key, nonce) reuse at all. Salt collision probability ≈ 2⁻¹⁷⁷ across 2⁴⁰ streams. The 7-byte prefix is defence in depth; the salt carries the argument.

## 5.4 Parameters

| Parameter | Value | Justification |
|---|---|---|
| chunk_size | 1 MiB | 0.0015% expansion; matches Tink's default |
| salt | 32 B | Collision ≈ 2⁻¹⁷⁷ over 2⁴⁰ streams |
| nonce_prefix | 7 B | Fills the 96-bit nonce; defence in depth |
| counter | 4 B | 2³² chunks = 4 PiB. **Hard error on overflow — never wrap** |
| tag | 16 B | Full length, no truncation |

**Chunk-size trade-off** (for a 50 GiB file):

| Chunk size | Chunk count | Tag overhead | Expansion |
|---|---|---|---|
| 4 KiB | 13,107,200 | 210 MB | 0.39% |
| 64 KiB | 819,200 | 13.1 MB | 0.024% |
| **1 MiB** | **51,200** | **819 KB** | **0.0015%** |
| 16 MiB | 3,200 | 51 KB | 0.0001% |

Below ~16 KiB, per-chunk overhead becomes measurable in throughput. Above ~4 MiB you burn memory for negligible gain. `age` uses 64 KiB, Tink uses 1 MiB — both are defensible; pick one and justify it from this table.

---

# 6. Functional Requirements

Each is testable. Write the test before the code.

| ID | Requirement | Verification |
|---|---|---|
| FR-1 | Encrypt a file of any size to a valid `chunkcrypt` stream | Round-trip test, 0 B to 8 GiB |
| FR-2 | Decrypt a valid stream to the exact original bytes | SHA-256 comparison |
| FR-3 | Peak RSS ≤ 4 MiB during both operations | `resource.getrusage` assertion |
| FR-4 | Reject any stream whose header fails to parse or validate | Fuzz + hand-crafted malformed headers |
| FR-5 | Reject a stream with any chunk modified | Bit-flip every chunk, assert failure |
| FR-6 | Reject a truncated stream (missing final flag) | Drop last 1..N chunks |
| FR-7 | Reject a stream with chunks reordered | Permutation test |
| FR-8 | Reject a chunk replayed from elsewhere in the same stream | Duplicate-chunk test |
| FR-9 | Reject a chunk spliced from a different stream | Cross-stream substitution |
| FR-10 | Emit **zero bytes** to output before the corresponding tag verifies | Instrumented writer, byte counter |
| FR-11 | Output file appears only on full successful decryption | Temp file + atomic rename |
| FR-12 | Hard error on counter overflow, never wrap | Unit test driving counter to 2³²−1 |
| FR-13 | Fresh salt and nonce_prefix per encryption attempt | Encryptor is single-use; re-init raises |
| FR-14 | Own GHASH matches NIST SP 800-38D vectors | 100% of published vectors |
| FR-15 | CLI: `chunkcrypt encrypt/decrypt -k KEY in out` | Integration test |

---

# 7. Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| NFR-1 | Throughput vs. monolithic AES-GCM | ≥ 90% of raw library throughput |
| NFR-2 | Wall-clock on a 50 GiB file vs. monolithic | ≥ 2× faster (pipelining) |
| NFR-3 | Ciphertext expansion | ≤ 0.002% |
| NFR-4 | Max supported file size | ≥ 1 PiB |
| NFR-5 | All randomness from `os.urandom` / `secrets` | Static check; no `random` module |
| NFR-6 | Constant-time comparisons where hand-rolled | `hmac.compare_digest` |
| NFR-7 | No plaintext or key material in logs or exceptions | Manual review + grep |
| NFR-8 | Works on a stream (pipe/socket), not just a seekable file | Socket demo |

---

# 8. Threat Model

**In scope**

- **Passive attacker** with full read access to the ciphertext.
- **Active attacker** with full read/write on the ciphertext and the wire — can reorder, truncate, replay, splice, and substitute at will.
- **Malicious storage provider** — the adversary holds the ciphertext indefinitely and controls what is returned on read.

**Out of scope**

- Compromised endpoint (malware, keylogger, cold-boot attack).
- Traffic analysis and timing side channels on the network.
- Denial of service.
- Key management, distribution, and password-based derivation of `K_master` *(note it as future work; do not build it)*.

**Security goals**

| ID | Goal |
|---|---|
| SG-1 | Confidentiality of plaintext against an active attacker |
| SG-2 | Integrity and authenticity of every chunk |
| SG-3 | Integrity of the stream *as a whole* — order, completeness, and provenance |
| SG-4 | The user never observes a partially-authenticated file as complete |

SG-3 is the one that distinguishes this from "we called AES-GCM in a loop." A loop gives you SG-1 and SG-2 and nothing else.

---

# 9. Security Design Hazards

These are the ways this construction fails. Each maps to a specific design element and to a test.

### H-01 — Nonce reuse `CRITICAL`

Two different plaintexts under the same (key, nonce) is the **forbidden attack** (Joux): XOR the ciphertexts to recover the plaintext difference, then solve the GHASH polynomial for the authentication key H. Once H is known, every future tag under that key is forgeable. GCM offers no residual security whatsoever.

The realistic path to this is not carelessness with nonces — it is **re-running an encryption with the same header**. A retry loop, a resumed operation, a re-encrypt after a crash.

> **Design response:** `StreamEncryptor` is single-use. It generates its salt and prefix in `__init__` and sets a `_consumed` flag on first use; any second call raises. There is no API that lets a caller supply a salt or nonce prefix.

### H-02 — Random nonces instead of counters

If you generate a fresh random 96-bit nonce per chunk, collision probability is q²/2⁹⁷ — about 2⁻⁶⁶ for one 50 GiB file. Tolerable in isolation, but it accumulates across every file ever encrypted under the same key, and NIST caps random-IV GCM at 2³² invocations for this reason. "We did the birthday math and it's probably fine" is a weak position to defend.

> **Design response:** Counter-based nonce. Collision probability becomes exactly zero. Probabilistic → structural.

### H-03 — Fork / snapshot RNG duplication

If the process forks after generating a salt, or a VM is snapshot-restored, two processes emit an identical nonce stream. Tink's own documentation explicitly flags that implementations of this construction are expected not to be fork-safe.

> **Design response:** Generate randomness as late as possible — at encryptor construction, immediately before first use, never at import or program start. Document the hazard.

### H-04 — Counter overflow

A 4-byte counter wraps at 2³². A silent wrap is silent nonce reuse.

> **Design response:** Bounds check per chunk, raise `CounterOverflowError`. Test that drives it to the limit.

### H-05 — Truncation and the authenticated-prefix problem

This is the **one irreducible difference** between monolithic and chunked AEAD. Monolithic decryption is all-or-nothing. Chunked decryption yields an *authenticated prefix* — every chunk you verified is genuine, you just may not have all of them. The final-chunk flag makes truncation detectable, but only at the end, by which point you may have written 49 GiB to disk.

> **Design response:** Decrypt to a temporary file; `os.replace()` into position only after the `0x01` flag verifies. `os.replace` is atomic on POSIX and Windows. This costs one inode and restores all-or-nothing semantics *as the user experiences them*. Frame this precisely: you relaxed the guarantee at the transport layer and restored it at the filesystem layer.

### H-06 — Reordering and replay

Without the counter in the nonce, a permuted stream verifies chunk-by-chunk perfectly.

> **Design response:** Counter in nonce. **Keep `naive.py` and demo the attack.**

### H-07 — Cross-stream splicing

Without per-stream key derivation, chunk 5 of stream A substitutes cleanly into stream B.

> **Design response:** HKDF per stream. Also demo-worthy.

### H-08 — Header downgrade

An unauthenticated `chunk_size` or `alg_id` lets an attacker force misparsing or algorithm downgrade.

> **Design response:** Full header bound into HKDF `info`.

### H-09 — Release of unverified plaintext

If the decryptor writes bytes before the tag verifies, GCM's guarantees do not apply to those bytes at all. This is easy to introduce accidentally when optimising the write path.

> **Design response:** Verify-then-write, per chunk, no exceptions. FR-10's instrumented test is non-negotiable.

### H-10 — Chunk-boundary length leak `ACCEPTED`

File length leaks to ~1 MiB granularity. Negligible against an attacker who already sees the exact ciphertext size. Document as accepted.

---

# 10. Implementation Plan — Step by Step

## Phase 0 — Setup *(half a day)*

1. `git init`, virtualenv, `pip install cryptography pytest pytest-benchmark`
2. Create the repo skeleton (§13)
3. Download NIST SP 800-38D GCM test vectors into `tests/vectors/`
4. Write `docs/THREAT_MODEL.md` from §8 — **before writing code**

## Phase 1 — GHASH and GF(2¹²⁸) *(3–4 days)*

5. Implement `gf_mult(x, y)` — bitwise, unoptimised, textbook. Correctness only.
6. Test against known GF(2¹²⁸) multiplication vectors.
7. Implement Shoup's 4K table method: precompute a 256-entry table from H, reducing multiplication to table lookups and shifts.
8. Verify the table version agrees with the bitwise version on 10,000 random inputs.
9. Implement `ghash(H, aad, ciphertext)` — the full authenticated hash.
10. **Validate against NIST SP 800-38D vectors. Do not proceed until 100% pass.**
11. Implement `gcm.py`: full GCM encrypt/decrypt using your GHASH and library AES. Validate against the same vector set.

*Milestone: you can encrypt one message with your own GCM and NIST agrees with the answer.*

## Phase 2 — Format and key derivation *(2 days)*

12. `header.py`: `Header` dataclass, `serialise()`, `parse()`, `validate()`. Reject bad magic, unknown version, unknown alg_id, absurd chunk_size.
13. `kdf.py`: `derive_stream_key(master_key, salt, header_bytes)` wrapping HKDF-SHA256.
14. `nonce.py`: `build_nonce(prefix, counter, is_final)` with overflow guard.
15. Unit-test all three, including malformed input and the counter overflow path.
16. Freeze the format. Write `docs/SPEC.md`. **Changing it after this point invalidates earlier test artifacts.**

## Phase 3 — Streaming core *(4–5 days)*

17. `StreamEncryptor.__init__` — generate salt and prefix, build header, derive key, set `_consumed = False`.
18. Implement the **look-ahead-by-one** read loop. This is the subtle part: you cannot set the final flag on a chunk until you know it is the last, so you must read chunk *i+1* before emitting chunk *i*.
19. `StreamDecryptor` — parse header, re-derive key, loop, **verify then write**.
20. Round-trip tests: 0 bytes, 1 byte, chunk_size−1, exactly chunk_size, chunk_size+1, 10 chunks, 1000 chunks.
21. Memory assertion test (FR-3) on a 4 GiB file.
22. Add the temp-file + `os.replace` discipline to the decryptor (H-05).
23. Add the single-use guard to the encryptor (H-01).

*Milestone: end-to-end encryption of a file larger than RAM, in constant memory.*

## Phase 4 — Attack suite *(4–5 days)* — **the presentation centrepiece**

24. Write `naive.py`: same chunking, but **random nonce per chunk, single key, no final flag, no header binding.** Deliberately broken, clearly commented as such.
25. **Attack 1 — Nonce reuse → key recovery.** Force a nonce collision in the naive version, XOR the two ciphertexts, solve the resulting polynomial over GF(2¹²⁸) for H, then forge a valid tag on a message of your choosing. This is the hardest and most impressive one. Budget two days.
26. **Attack 2 — Truncation.** Drop the last N chunks. Naive: accepts silently. Hardened: rejects on missing final flag.
27. **Attack 3 — Reordering.** Permute chunks. Naive: accepts. Hardened: rejects.
28. **Attack 4 — Replay.** Duplicate a chunk. Naive: accepts. Hardened: rejects.
29. **Attack 5 — Cross-stream splicing.** Move chunk 5 from stream A into stream B. Naive: accepts. Hardened: rejects.
30. Wire all five into `tests/test_attacks.py` as permanent regression tests, each asserting *both* that naive fails and hardened succeeds.

*Milestone: a live demo where the obvious design is broken five ways on screen.*

## Phase 5 — Benchmarks and parameter derivation *(3 days)*

31. Throughput vs. chunk size: 1 KiB → 16 MiB, log scale.
32. Your GHASH vs. OpenSSL's PCLMULQDQ path. Report the gap honestly and explain it.
33. Chunked vs. monolithic wall-clock on a large file, with peak RSS for both.
34. Comparison against ChaCha20-Poly1305 and AES-GCM-SIV.
35. Compute an Internet Performance Index over a realistic packet-size distribution, mirroring McGrew–Viega's methodology.
36. **Derive your chunk size and stream cap from Theorem 1 and Corollary 1 of the paper — not from convention.** Show the arithmetic. This is where the marks are.

## Phase 6 — Security argument *(3 days)*

37. Write the bound-invariance analysis (§11).
38. Comparison table against TLS 1.3 record layer, Tink Streaming AEAD, and `age`.
39. **Stretch:** attempt round-trip interoperability with Tink's Python `streamingaead`. If your ciphertext decrypts under Tink, that is an extremely strong correctness signal.

## Phase 7 — Demo and writeup *(4 days)*

40. `demo/server.py` + `demo/client.py`: stream an encrypted file over a TCP socket, decrypting on the fly. Proves NFR-8 — the construction works on a non-seekable stream, which a monolithic design cannot do.
41. Add a mid-stream truncation switch to the demo so you can cut the connection live and show the receiver refusing the partial file.
42. Final report, slides, rehearsal.

---

# 11. The Security Argument

This is the intellectual core of the report. State it quantitatively.

For a 50 GiB file (σ ≈ 2³¹·⁶ blocks of 128 bits):

| | Monolithic AES-GCM | Chunked @ 1 MiB |
|---|---|---|
| Nonce collision probability | 0 (single nonce) | **0** (counter, structural) |
| Confidentiality bound ≈ σ²/2¹²⁸ | 2⁻⁶⁴·⁷ | **2⁻⁶⁴·⁷** — identical |
| Max blocks per authenticated message ℓ | 2³¹·⁶ | 2¹⁶ |
| Forgery probability per attempt ≈ ℓ/2¹²⁸ | 2⁻⁹⁶·⁴ | **2⁻¹¹²** — better |
| Number of forgery targets | 1 | 51,200 |
| **Total forgery advantage** | 2⁻⁹⁶·⁴ | **2⁻⁹⁶·⁴** — identical |
| Max file size | **64 GiB (hard limit)** | 4 PiB |
| Peak memory | 50+ GiB | 1 MiB |

**In one sentence:** *chunking is bound-neutral for confidentiality and bound-neutral for total forgery advantage — conditional on counter-based nonces and per-stream key derivation. Remove either condition and it collapses entirely.*

**Why confidentiality is invariant:** GCM's IND-CPA bound depends on total blocks encrypted under the key, not on how those blocks are partitioned into messages. Splitting does not change σ, so it does not change the bound.

**Why per-attempt authenticity improves:** GCM's forgery bound is linear in message length. Your messages just became 32,000× shorter, so the attacker's forgery polynomial has 32,000× fewer roots to exploit. The attacker gains more targets, but the product ℓ·q is conserved, so the total lands in exactly the same place.

That last result is counter-intuitive and defensible. Counter-intuitive-and-defensible is what examiners reward.

---

# 12. Test Plan

| Category | Content | Gate |
|---|---|---|
| **Test vectors** | NIST SP 800-38D, all published GCM vectors | 100% pass before Phase 2 |
| **Round-trip** | 0 B, 1 B, boundaries around chunk_size, multi-GiB | Byte-exact via SHA-256 |
| **Memory** | Peak RSS during 4 GiB encrypt and decrypt | ≤ 4 MiB |
| **Tamper** | Flip one bit in every chunk position | 100% rejected |
| **RUP** | Instrumented writer counting bytes emitted before verification | Must be 0 |
| **Attacks** | All five, naive vs. hardened | 5/5 succeed on naive, 5/5 fail on hardened |
| **Fuzzing** | `atheris` or `hypothesis` on the header parser | No crashes, no hangs |
| **Overflow** | Counter driven to 2³²−1 | Raises, does not wrap |
| **Interop** | Tink round-trip | Stretch goal |

**Test-first discipline:** every FR in §6 gets its test written before its implementation. In a cryptographic project, a test written after the code tends to test what the code does rather than what the specification requires.

---

# 13. Repository Layout

```
chunkcrypt/
├── chunkcrypt/
│   ├── __init__.py
│   ├── ghash.py          # GF(2^128), Shoup 4K table
│   ├── gcm.py            # reference GCM on own GHASH
│   ├── header.py         # serialise / parse / validate
│   ├── kdf.py            # HKDF-SHA256
│   ├── nonce.py          # structured nonce + overflow guard
│   ├── stream.py         # StreamEncryptor / StreamDecryptor
│   ├── naive.py          # DELIBERATELY BROKEN baseline
│   └── cli.py
├── tests/
│   ├── vectors/          # NIST SP 800-38D
│   ├── test_ghash.py
│   ├── test_vectors.py
│   ├── test_roundtrip.py
│   ├── test_memory.py
│   ├── test_rup.py
│   └── test_attacks.py   # the five attacks
├── bench/
│   ├── bench_chunksize.py
│   ├── bench_ghash.py
│   └── bench_compare.py  # vs ChaCha20-Poly1305, AES-GCM-SIV
├── demo/
│   ├── server.py
│   └── client.py
├── docs/
│   ├── SPEC.md
│   ├── THREAT_MODEL.md
│   └── SECURITY_ARGUMENT.md
└── README.md
```

## Public API sketch

```python
class StreamEncryptor:
    """Single-use. Construct a new instance per encryption."""
    def __init__(self, master_key: bytes, chunk_size: int = 1 << 20): ...
    def encrypt(self, src: BinaryIO, dst: BinaryIO) -> None: ...

class StreamDecryptor:
    def __init__(self, master_key: bytes): ...
    def decrypt(self, src: BinaryIO, dst: BinaryIO) -> None: ...
    def decrypt_to_path(self, src: BinaryIO, path: str) -> None:
        """Temp file + atomic rename. Preferred entry point."""
```

Note there is no parameter allowing a caller to supply a salt or nonce prefix. That absence is a security control, not an oversight — document it as such.

---

# 14. Timeline

Mapped to 10% / 15% / 25% milestones.

| Week | Phase | Work | Milestone |
|---|---|---|---|
| 1 | 0 | Read McGrew–Viega, SP 800-38D, HRRV15, Tink spec, `age` spec. Threat model + format sketch | **Proposal (10%)** |
| 2 | 1 | GHASH + GCM; NIST vectors passing | |
| 3 | 2–3 | Format frozen; single-chunk end-to-end | |
| 4 | 3 | Full streaming API; large-file demo; memory assertion | **Midsem report (15%)** |
| 5 | 4 | Attack suite — all five | |
| 6 | 5 | Benchmarks + parameter derivation from bounds | |
| 7 | 6 | Security argument; comparison table; Tink interop | |
| 8 | 7 | Socket demo, final report, slides | **Final report (25%)** |

## Scope discipline

Do not implement AES from scratch. Do not invent a new mode. Do not attempt new proofs. If you are behind schedule, cut the Tink interop and the AES-GCM-SIV comparison first — never the attack suite.

---

# 15. Success Metrics

| Metric | Target |
|---|---|
| NIST SP 800-38D vectors passed | 100% |
| Peak memory, 50 GiB file | ≤ 4 MiB |
| Wall-clock vs. monolithic | ≥ 2× faster |
| Ciphertext expansion | ≤ 0.002% |
| Attacks succeeding against naive | 5 / 5 |
| Attacks defeated by hardened | 5 / 5 |
| Max supported file size | ≥ 1 PiB |
| Tink interoperability | Round-trip (stretch) |

## Target conclusion

> "Chunk size 1 MiB with STREAM nonce encoding and per-stream key derivation gives stream-level confidentiality and integrity at 0.0015% ciphertext expansion and 2.4× lower wall-clock time than monolithic AES-GCM, with a total forgery advantage of 2⁻⁹⁶·⁴ for a 50 GiB stream — numerically identical to the monolithic construction it replaces, while removing the 64 GiB specification ceiling and reducing peak memory from 50 GiB to 1 MiB."

Fill in the real measured numbers. **A specific number is the deliverable.**

---

# 16. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Attack 1 (H recovery) is harder than expected | High — it's the demo highlight | Start it in week 5, not week 7. Budget 2 full days. Polynomial root-finding over GF(2¹²⁸) is the tricky part |
| Pure-Python GHASH too slow to benchmark meaningfully | Medium | Expected. Use it for correctness only; benchmark the library path for throughput. The gap *is* a result |
| Look-ahead-by-one logic has off-by-one bugs | Medium | Exhaustive boundary tests at 0, 1, n−1, n, n+1 chunks |
| Format churn invalidates test artifacts | Medium | Freeze the format at end of Phase 2. Version the header from day one |
| Scope creep into building a product | High | §3.2 is binding. No accounts, no server, no database |

---

# 17. Open Questions

1. **1 MiB or 64 KiB chunks?** Both defensible. Decide from your own benchmark data in Phase 5 rather than by copying a library, and show the working.
2. **Tink wire-format compatibility as an explicit goal?** Constrains your header layout, but a successful cross-implementation round-trip is a very strong correctness claim to put on a slide.
3. **Is password-based derivation of `K_master` in scope?** Currently a non-goal. If added, use Argon2id and document the parameters — but this is a distraction from the core contribution.
4. **Team size?** Natural split: (a) GHASH/GCM + vectors, (b) streaming core + format, (c) attack suite, (d) benchmarks + security argument. The attack suite should not be one person's sole responsibility — it is too important to the grade.

---

## References

- McGrew & Viega, *The Security and Performance of the Galois/Counter Mode of Operation*
- NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation: GCM and GMAC*
- Hoang, Reyhanitabar, Rogaway, Vizár, *Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance*, CRYPTO 2015 — the STREAM construction
- Hoang & Shen, *Security of Streaming Encryption in Google's Tink Library*, IACR ePrint 2020/1019
- Joux, *Authentication Failures in NIST Version of GCM* — the forbidden attack
- Google Tink, AES-GCM-HKDF Streaming AEAD specification
- `age` file format specification v1 — c2sp.org/age
- Shoup, *On Fast and Provably Secure Message Authentication Based on Universal Hashing* — the 4K table method
