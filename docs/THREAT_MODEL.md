# Threat model (week 1)

## Attacker we defend against

- **Passive:** reads all ciphertext.
- **Active:** reads and rewrites anything on the wire or on disk: flips bits, drops, reorders,
  duplicates, or swaps in chunks from other files, edits the header.
- **Malicious storage:** holds our ciphertext forever and chooses what to hand back.

## Out of scope

Compromised endpoints (malware, keyloggers, cold boot), traffic analysis and timing side
channels, denial of service, and key management (how `K_master` is created and shared).

## Security goals

| ID   | Goal                                                                      |
|------|---------------------------------------------------------------------------|
| SG-1 | Confidentiality of the plaintext                                          |
| SG-2 | Integrity of every chunk                                                  |
| SG-3 | Integrity of the stream as a whole: right order, nothing missing, nothing from elsewhere |
| SG-4 | The user never sees a partially verified file as if it were complete      |

Calling AES-GCM in a loop gives SG-1 and SG-2 only. SG-3 and SG-4 are what this project adds.

## Hazards → design response → where it lives

| Hazard                                  | Response                                              | Code / status          |
|-----------------------------------------|-------------------------------------------------------|------------------------|
| H-01 nonce reuse (catastrophic in GCM)  | per-file HKDF key; salt + prefix generated inside, never caller-supplied; single-use encryptor | `kdf.py`, `stream.py`; attack 5 |
| H-02 random per-chunk nonces            | counter in nonce → collisions within a file impossible | `nonce.py`             |
| H-03 fork/VM-snapshot RNG duplication   | randomness drawn at encryption time, not import; documented as not covered | `stream.py`, SECURITY_ARGUMENT.md |
| H-04 counter overflow                   | hard error at 2³², never wrap                         | `nonce.py`, `test_nonce.py` |
| H-05 truncation                         | final flag in nonce; temp file + atomic rename        | `stream.py`; attack 1  |
| H-06 reordering / replay                | counter in nonce                                      | `nonce.py`; attacks 2, 3 |
| H-07 cross-stream splicing              | per-file HKDF key                                     | `kdf.py`; attack 4     |
| H-08 header downgrade / tamper          | whole header is HKDF `info`                           | `kdf.py`, `test_stream.py` |
| H-09 release of unverified plaintext    | verify-then-write per chunk; file appears only when complete | `stream.py`, `cli.py` |
| H-10 length leak to ~1 MiB granularity  | accepted                                              | —                      |
| H-11 forged header forcing a huge read  | chunk_size capped at 16 MiB before any read           | `header.py`            |
