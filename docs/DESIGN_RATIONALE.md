# Design rationale: why every component is there

For each part: what it does, why we need it, and the simpler alternative we considered and why
it was not enough. If a part could not pass this test it was removed (see the end).

## The cryptographic core

### AES itself comes from a library (`cryptography` / OpenSSL)
- **Why:** writing AES is a solved, well-tested problem, and a hand-written AES in Python would
  leak timing information through table lookups. The PRD lists it as a non-goal.
- **Simpler alternative:** none simpler.

### No AES-ECB anywhere (`aes_ctr.py`)
- GCM is defined (SP 800-38D) in terms of two things only: **E_K**, the AES block cipher applied
  to one 16-byte block, and **GCTR**, GCM's counter mode. ECB mode is not part of GCM.
- The library only exposes AES through a mode, so we build both on its **CTR** mode:
  CTR starting at block X over 16 zero bytes outputs exactly E_K(X).
- GCM's counter (`inc32`) only increments the last 32 bits; the library's CTR increments all 128.
  `gctr()` restarts the library's CTR at the 32-bit wrap so the two agree exactly
  (`test_gctr_matches_inc32_across_the_32_bit_wrap`). A test fails if `modes.ECB` ever reappears.
- **Earlier version:** used `modes.ECB()` on single blocks. The output was the same, but it was
  conceptually wrong and was rightly flagged at the midsem.

### Our own GCM (`ref_gcm.py`, `ghash.py`, `poly_multiplication.py`, `counter.py`, `tag_gen.py`)
- **Why:** Phase I of the project is to understand GCM by building it, and to prove it against
  NIST's official test vectors (all 47,250 pass). It is also a second, independent implementation
  that cross-checks the library byte for byte.
- **Where it is used:** NIST validation, the `reference` backend of the streaming engine, and the
  nonce-reuse attack (which needs GF(2¹²⁸) arithmetic).
- **Not used for real encryption:** it is ~700x slower than OpenSSL and not constant-time.

### Shoup's 4 KB table + reduction table (`poly_multiplication.py`, `ghash.py`)
- **Why:** multiplying by H bit by bit takes 128 steps per block. Because H is fixed for a whole
  message, we precompute H × (every byte value) once (256 entries × 16 B = 4 KB); each multiply
  is then 16 lookups and 15 one-byte shifts, and a second 256-entry table fixes up the bits that
  fall off each shift.
- **Measured:** GHASH is **6.3x faster**, and the NIST suite runs 3x faster (1.7 s vs 5.3 s for two
  files). The PRD's benchmark plan also compares GHASH implementations.
- **Simpler alternative:** bit-by-bit multiplication only. It is still in the code
  (`gf_2_128_mul`) as the ground truth the table is tested against (10,000 random products).
- The table itself is built with 8 multiplications instead of 256, because multiplication
  distributes over XOR.

## The file format

### Chunking at all
- **Why:** one GCM call must see the whole message before it can say "authentic", so a safe
  one-shot decryptor holds the whole file in memory (measured: 512 MiB of memory to encrypt a
  256 MiB file), and one GCM call is capped at 2³⁹ − 256 bits ≈ 64 GiB.
- With 1 MiB chunks: **3.02 MiB** peak memory for any file size, and a 4 PiB size limit.

### Chunk size: 1 MiB (default), stored in the header
- **Why this value:** measured (`docs/BENCHMARKS.md`). Every size from 16 KiB up runs at 1.5 GB/s
  or more, which is faster than a typical SSD, so throughput is not what decides it. Among those:
  - 64 KiB was fastest in memory (~6.5 GB/s) but caps a file at 2³² × 64 KiB = 256 TiB, below
    the PRD's ≥ 1 PiB requirement.
  - 256 KiB was fast in some runs and 3x slower in others (it sits at the edge of the CPU cache).
  - 1 MiB was stable (~2.5 GB/s), has 0.0016 % size overhead, and gives 4 PiB.
- **Why it's in the header:** the decryptor must know where one chunk ends before it can check
  anything. Any size from 16 B to 16 MiB decrypts; the 16 MiB cap stops a forged header from
  making the decryptor read gigabytes before the first tag check.

### Per-file key via HKDF-SHA256 (`kdf.py`)
**This is necessary, not decoration.** Without it, every file would be encrypted directly under
the one master key, and:
1. **Nonces would repeat across files.** A file's nonces are its random 7-byte prefix plus a
   counter. Two files with the same prefix reuse every (key, nonce) pair, which is GCM's
   catastrophic failure: the plaintext XOR leaks and H can be solved for, so anything can be
   forged (`attacks.py` attack 5 does exactly this). The chance of some two files sharing a
   prefix is about n² / 2⁵⁷: **1 in 130,000 at a million files, about 7 % at 100 million.**
   With a per-file key from a 32-byte salt, a clash needs a salt collision: about n² / 2²⁵⁷.
2. **Chunks could be moved between files** (attack 4, splicing), since every file has the same key.
3. **The header would not be protected.** HKDF's `info` is the whole header, so changing any
   header byte (chunk size, version, algorithm) gives a different key and every chunk fails.
4. **GCM's security budget is per key.** Its bounds degrade with the total data under one key;
   a key per file means each file gets the full budget instead of all files sharing it.
5. **The master key need not be a perfect AES key.** HKDF's extract step turns the input key
   into a uniform 256-bit key.

- **Simpler alternatives considered:**
  - *Use the master key directly, header as associated data:* fixes (3) only; (1), (2), (4) remain.
  - *Random 96-bit nonce per chunk, one key:* collisions become possible (q² / 2⁹⁷ per file,
    adding up across all files), and order/completeness still need a counter and flag anyway.
  - *Generate a random per-file key and encrypt it with the master key ("envelope encryption"):*
    also correct, but every file then stores a wrapped key (40–60 bytes) and needs a second
    encryption step; HKDF achieves the same with one derivation from a public salt.
- **Why HKDF specifically:** it is the standard (RFC 5869), analysed KDF used by TLS 1.3, Tink and
  age, and its `info` input gives header binding for free.

### Salt: 32 bytes
- **Why:** it is what makes each file's key unique. RFC 5869 recommends a salt as long as the hash
  output (32 bytes for SHA-256). 16 bytes (as in age) would also be safe; 32 costs 16 more bytes
  per file and follows the RFC.

### Nonce = prefix (7 B) ‖ chunk counter (4 B) ‖ final flag (1 B) (`nonce.py`)
- **Counter:** binds each chunk to its position, so reordering and replay fail (attacks 2, 3).
  It also makes nonces within a file unique by construction: probability of a repeat is exactly
  zero, not merely small. It raises an error at chunk 2³² instead of wrapping.
- **Final flag:** 1 only on the last chunk, so cutting the stream short (attack 1) or appending
  data fails.
- **96 bits total:** GCM's fast path (the first counter block is simply nonce ‖ 1); other lengths
  need an extra GHASH pass, and the original GCM proof was flawed for them (Iwata, Ohashi,
  Minematsu, 2012).
- **The 7-byte random prefix, honestly:** with a per-file key, a fixed prefix would also give
  unique (key, nonce) pairs, so the prefix is **defence in depth, not strictly required**. It
  costs 7 bytes per file, matches Google Tink's nonce layout, and keeps nonces distinct if a key
  were ever reused across streams. We keep it but do not claim it is essential.
- **The nonce is never stored:** the receiver rebuilds it from the position, so an attacker cannot
  "fix" a moved chunk by editing its nonce.

### Magic, version, algorithm ID (6 bytes)
- **Magic "CHNK":** rejects files that aren't ours immediately, with a clear error, instead of a
  confusing authentication failure.
- **Version:** lets the format change later without misreading old files.
- **Algorithm ID:** names the cipher, so a future version could add e.g. ChaCha20-Poly1305 for
  CPUs without AES instructions. A version byte alone could carry this; a separate byte keeps
  "format layout" and "cipher choice" independent. Both are bound into the key (via HKDF `info`),
  so an attacker cannot downgrade a file by editing them.

## The streaming engine (`stream.py`)

### Look-ahead by one chunk
- **Why:** a chunk can only be sealed with the final flag once we know nothing follows it, so we
  read chunk i+1 before sealing chunk i. The decryptor does the same to know which flag to expect.
  This holds at most two chunks in memory.

### Verify-then-write per chunk, and temp file + atomic rename (`decrypt_to_path`)
- **Why:** every chunk's tag is checked before its plaintext is written. But truncation can only
  be detected at the end, so earlier chunks are written to a uniquely named temporary file, which
  is renamed into place (`os.replace`, atomic) only after the final chunk verifies, and deleted
  on any failure. The user never sees a partial or tampered file.
- **Simpler alternative:** write straight to the output file. Then a cut-off stream leaves a
  plausible-looking partial file behind.

### Single-use encryptor, randomness drawn at construction
- **Why:** the salt and prefix are generated inside the encryptor and cannot be passed in;
  encrypting twice with one instance raises. A retry can therefore never reuse (key, nonce) pairs.

### `_read_full`
- **Why:** sockets and pipes may return fewer bytes than asked for mid-stream; treating that as the
  end of the file would mis-mark a chunk as final. Tested with a reader that returns 100 bytes at
  a time. For ordinary files the first read is complete and no copy is made.

### Two backends (`chunk_aead.py`: `library` or `reference`)
- **Why:** it connects Phase I to Phase III. The stream uses OpenSSL by default; switching to our
  own GCM produces byte-identical files (tested both ways). This was limitation 1 at the midsem.

### Exception types (`errors.py`)
- `HeaderError` (not our file / malformed), `AuthenticationError` (tampered, wrong key, truncated),
  `CounterOverflowError`. They let the CLI and tests tell "not a valid file" from "tampered", and
  all subclass `ValueError` so code catching `ValueError` still works.

## Tools and evidence (PRD deliverables)

| File | Why it exists |
|---|---|
| `nist_parser.py` | Runs NIST's official vectors (all 47,250) against our GCM |
| `naive.py` | The deliberately broken baseline the attacks are demonstrated on |
| `attacks.py` | The five attacks: succeed on naive, fail on ours |
| `cli.py` | Usable tool: keygen / encrypt / decrypt; decrypt only to a file (all-or-nothing) |
| `socket_demo.py` | Shows one-pass streaming over a network and a mid-stream cut being rejected |
| `bench/bench.py` | The measurements behind the chunk size and the memory claims |

## Removed during the audit (redundant or replaced)

| Removed | Why |
|---|---|
| `single_chunk.py`, `demo_week3.py` | A one-chunk message is just the stream engine with one chunk |
| `run_nist.py`, `test/nist_tester/` | Duplicated `nist_parser.py`; the old runners also skipped 10,822 vectors |
| `src/test.py`, `test_message.*` | Ad-hoc demo, replaced by `test/test_stream.py` and `cli.py` |
| `parse_nonce()` | Only used by the removed demo |
| Per-block AES helpers in `aes_ctr.py` | Replaced by one `gctr()` call |
| `modes.ECB()` | Not part of GCM (see above) |
