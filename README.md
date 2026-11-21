# streaming-aes

Streaming AEAD over AES-256-GCM: encrypt files of any size in constant memory, using the
STREAM construction (Hoang–Reyhanitabar–Rogaway–Vizár, CRYPTO 2015). Design: [docs/prd.md](docs/prd.md).
Frozen wire format: [docs/SPEC.md](docs/SPEC.md). Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Status

| Week | Deliverable                                                     | State |
|------|-----------------------------------------------------------------|-------|
| W1   | Threat model + format sketch                                    | done  |
| W2   | Own GF(2¹²⁸) GHASH (Shoup 4K table), reference GCM, NIST vectors | done — 47,250 / 47,250 vectors pass |
| W3   | Header, HKDF, nonce frozen; single-chunk end-to-end round trip  | done  |
| W4   | StreamEncryptor / StreamDecryptor, look-ahead loop, memory test | first version done (`stream.py`, `test_memory.py`) |

Our GCM never uses ECB mode: the AES block cipher E_K and GCM's counter mode (GCTR) are
built on the library's CTR mode (`aes_ctr.py`), matching NIST SP 800-38D's definitions.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
```

## Run

```bash
python -m pytest test -q                 # all tests (~6 s)
cd src && python run_nist.py             # all 6 NIST files (47,250 vectors), per file, with timings
cd src && python test.py                 # stream demo: encrypt + decrypt test_message.txt
cd src && python -m pytest -s test_memory.py   # peak memory, 5 MB vs 50 MB file
cd src && python demo_week3.py           # narrated single-chunk demo with 11 tamper attempts
```

## Code map (`src/`)

| File                    | What it does                                                            |
|-------------------------|-------------------------------------------------------------------------|
| `poly_multiplication.py`| GF(2¹²⁸) multiply (bitwise) and the 256-entry Shoup table for H          |
| `ghash.py`              | H = AES_K(0¹²⁸), GHASH payload layout, Shoup multiply with reduction table |
| `counter.py`            | J0 / counter blocks, 32-bit increment                                   |
| `aes_ctr.py`            | E_K (AES on one block) and GCTR (GCM counter mode with inc32); no ECB    |
| `tag_gen.py`            | Tag = GHASH ⊕ AES_K(J0), truncated to tag length                        |
| `ref_gcm.py`            | Our full GCM encrypt / decrypt (verify-then-decrypt)                    |
| `nist_parser.py`        | Runs NIST CAVS `.rsp` files against `ref_gcm`                           |
| `header.py`             | 49-byte header: build, serialise, parse, validate                       |
| `kdf.py`                | HKDF-SHA256 per-stream key                                              |
| `nonce.py`              | prefix ‖ counter ‖ final-flag nonce, overflow guard                     |
| `chunk_aead.py`         | Seal / open one chunk (OpenSSL or our own GCM)                          |
| `single_chunk.py`       | Week-3 milestone: header + one final chunk, end to end                  |
| `errors.py`             | `HeaderError`, `AuthenticationError`, `CounterOverflowError`            |
| `stream.py`             | `StreamEncryptor` / `StreamDecryptor`: look-ahead loop, temp file + atomic rename |
| `test_memory.py`        | tracemalloc peak-memory test (5 MB vs 50 MB)                            |
| `run_nist.py`           | Runs all six NIST files through `nist_parser.py`                        |

`test/nist_tester/` holds the older NIST runners. They skip records with an empty plaintext or AAD
(36,428 of 47,250); use `src/run_nist.py` instead.
