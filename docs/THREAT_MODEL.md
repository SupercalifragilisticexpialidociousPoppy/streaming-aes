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
| H-01 nonce reuse (catastrophic in GCM)  | salt + prefix generated inside, never caller-supplied | `header.py` ✅          |
| H-02 random per-chunk nonces            | counter in nonce → collisions impossible              | `nonce.py` ✅           |
| H-03 fork/VM-snapshot RNG duplication   | randomness drawn at first use, not import             | `Header.new` ✅ (documented) |
| H-04 counter overflow                   | hard error at 2³², never wrap                         | `nonce.py` ✅           |
| H-05 truncation                         | final flag in nonce; temp file + atomic rename        | flag ✅, rename week 4  |
| H-06 reordering / replay                | counter in nonce                                      | `nonce.py` ✅           |
| H-07 cross-stream splicing              | per-stream HKDF key                                   | `kdf.py` ✅             |
| H-08 header downgrade / tamper          | whole header is HKDF `info`                           | `kdf.py` ✅             |
| H-09 release of unverified plaintext    | verify-then-write per chunk                           | `chunk_aead.py` ✅      |
| H-10 length leak to ~1 MiB granularity  | accepted                                              | —                      |
