# streaming-aes

Encrypt files of any size in constant memory with AES-256-GCM, safely. The file is split into
1 MiB chunks, and each chunk is sealed so that it is tied to its file, its position, and whether
it is the last one (the STREAM construction, Hoang–Reyhanitabar–Rogaway–Vizár, CRYPTO 2015).

| What | Result |
|---|---|
| Our own GCM vs NIST's official test vectors | 47,250 / 47,250 pass |
| Peak memory, encrypt or decrypt, 5 MiB or 50 MiB file | 3.02 MiB (one-shot GCM on 256 MiB: 512 MiB) |
| Attacks on a naive "GCM in a loop" design | 5 / 5 succeed |
| The same attacks on ours | 0 / 5 succeed |
| Max file size | 4 PiB (one GCM call: 64 GiB) |

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
```

## Use

```bash
cd src
python cli.py keygen key.hex
python cli.py encrypt key.hex big_file.bin big_file.enc
python cli.py decrypt key.hex big_file.enc big_file.out   # file appears only if fully verified
```

## Demos and evidence

```bash
python -m pytest test -q          # all tests (from the repo root)
cd src
python nist_parser.py             # all 6 NIST files, with counts and timings
python attacks.py                 # the 5 attacks: naive vs ours
python socket_demo.py demo        # network transfer, intact and cut mid-stream
python ../bench/bench.py          # throughput vs chunk size, memory, our GCM vs OpenSSL
```

## Documents

| File | Contents |
|---|---|
| [docs/STUDY_GUIDE.md](docs/STUDY_GUIDE.md) | Everything explained from zero: every component, every slide, every number, viva questions |
| [docs/report/final_report.pdf](docs/report/final_report.pdf) | Final report (LaTeX source alongside) |
| [docs/DESIGN_RATIONALE.md](docs/DESIGN_RATIONALE.md) | Why every component exists, and the simpler alternative we rejected |
| [docs/SECURITY_ARGUMENT.md](docs/SECURITY_ARGUMENT.md) | What we claim, the bounds, and what we don't claim |
| [docs/ATTACKS.md](docs/ATTACKS.md) | The five attacks, including recovering H after nonce reuse |
| [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | Measurements and how the chunk size was chosen |
| [docs/SPEC.md](docs/SPEC.md) | The frozen v1 file format |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Attacker model and hazard → defence map |
| [docs/gcm_diagram.svg](docs/gcm_diagram.svg) | GCM encryption, drawn from SP 800-38D |
| [docs/MIDSEM_FIXES.md](docs/MIDSEM_FIXES.md) | Corrections to the midsem slides and report |
| [docs/prd.md](docs/prd.md) | Original requirements |

## Code map (`src/`)

| File | What it does |
|---|---|
| `aes_ctr.py` | E_K (AES on one block) and GCTR (GCM counter mode with inc32); no ECB |
| `poly_multiplication.py` | GF(2¹²⁸) multiplication (bitwise) and Shoup's 4 KB table for H |
| `ghash.py` | H = E_K(0¹²⁸), the GHASH input layout, fast multiply with the reduction table |
| `counter.py` | J₀ (incl. non-96-bit IVs) and inc32 |
| `tag_gen.py` | T = GHASH ⊕ E_K(J₀), truncated to the tag length |
| `ref_gcm.py` | Our complete GCM: encrypt, and verify-then-decrypt |
| `nist_parser.py` | Runs NIST CAVS `.rsp` files against our GCM |
| `header.py` | The 49-byte header: build, serialise, parse, validate |
| `kdf.py` | HKDF-SHA256 per-file key, bound to the whole header |
| `nonce.py` | prefix ‖ counter ‖ final flag; refuses to wrap |
| `chunk_aead.py` | Seal / open one chunk with OpenSSL or with our own GCM |
| `stream.py` | `StreamEncryptor` / `StreamDecryptor`: look-ahead loop, temp file + atomic rename |
| `errors.py` | `HeaderError`, `AuthenticationError`, `CounterOverflowError` |
| `cli.py` | keygen / encrypt / decrypt |
| `naive.py` | Deliberately broken baseline for the attacks |
| `attacks.py` | The five attacks |
| `socket_demo.py` | Encrypted transfer over TCP, with an optional mid-stream cut |
