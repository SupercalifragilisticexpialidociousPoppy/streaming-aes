# chunkcrypt wire format — v1 (FROZEN, week 3)

Changing anything here after week 3 invalidates earlier test artifacts. Bump `version` instead.

## Stream layout

```
HEADER (49 B) | CHUNK 0 | CHUNK 1 | ... | CHUNK n-1
                                          ^ final flag = 0x01 in its nonce
CHUNK i = ciphertext (chunk_size bytes, last one may be shorter, may be 0) || tag (16 B)
```

## Header — 49 bytes, sent in the clear, authenticated implicitly via HKDF

| offset | field        | size | value                                         |
|-------:|--------------|-----:|-----------------------------------------------|
| 0      | magic        | 4 B  | `"CHNK"`                                      |
| 4      | version      | 1 B  | `0x01`                                        |
| 5      | alg_id       | 1 B  | `0x01` = AES-256-GCM, key from HKDF-SHA256    |
| 6      | chunk_size   | 4 B  | big-endian, plaintext bytes per chunk         |
| 10     | salt         | 32 B | `os.urandom(32)`, fresh per stream            |
| 42     | nonce_prefix | 7 B  | `os.urandom(7)`, fresh per stream             |

Parser rejects (`HeaderError`): length ≠ 49, wrong magic, version ≠ 1, alg_id ≠ 1,
`chunk_size` outside [16 B, 16 MiB]. Default `chunk_size` = 1 MiB.

The upper bound matters because the decryptor must allocate one chunk *before* it can
authenticate anything; without it a tampered header could demand a 4 GiB buffer.

## Key derivation

```
K_stream = HKDF-SHA256(ikm = K_master (32 B), salt = header.salt, info = header[0:49], L = 32)
```

All 49 header bytes are the `info`, so changing any header field changes `K_stream` and every
chunk fails authentication. No separate header MAC or AAD is needed.

## Nonce — 96 bits

```
| nonce_prefix (7 B) | counter (4 B, big-endian, starts at 0) | flag (1 B: 0x00, or 0x01 on the last chunk) |
```

- Counter > 2³² − 1 → `CounterOverflowError`. Never wraps. Max stream = 2³² chunks = 4 PiB at 1 MiB.
- Exactly one chunk per stream carries flag `0x01`: the last one. A 1-chunk stream's only chunk is
  `counter = 0, flag = 0x01`.

## Per chunk

`sealed_i = AES-256-GCM(K_stream).encrypt(nonce_i, plaintext_i, aad = empty)` → ciphertext ‖ 16-byte tag.

Decrypt = verify the tag first; release the plaintext only if it verifies.

## Overheads

| item          | size                  | at 1 MiB chunks |
|---------------|-----------------------|-----------------|
| header        | 49 B once             | —               |
| tag per chunk | 16 B                  | 0.0015 %        |
