# Security argument

What we claim, what it rests on, and what we do not claim. Numbers are for a 50 GiB file with
1 MiB chunks unless stated.

## Assumptions

1. AES-256 behaves like a random permutation (the standard assumption behind every GCM proof).
2. HKDF-SHA256 behaves like a random function of its inputs (standard for HMAC-SHA256).
3. The master key is 32 uniformly random bytes and stays secret.
4. The operating system's random generator works: salts and prefixes are fresh for every file.

## Claim 1: no (key, nonce) pair is ever used twice

- **Within a file:** nonce = prefix ‖ counter ‖ flag, and the counter is different for every
  chunk (0, 1, 2, …), refusing to go past 2³² − 1. So two chunks of one file never share a nonce.
  This is certain, not probabilistic.
- **Across files:** each file has its own key K = HKDF(master, salt, header). Two files share a key
  only if they share a salt: for n files, probability ≤ n² / 2²⁵⁷ (2⁻¹⁷⁷ at a trillion files).

This matters because nonce reuse is the one failure GCM cannot survive: `attacks.py` attack 5
recovers H from two messages under a repeated nonce and forges a new valid message.

## Claim 2: each chunk is as secure as a GCM message

Each chunk is one ordinary AES-GCM call under a unique (key, nonce), so McGrew and Viega's
theorems apply directly, with q = number of chunks and σ = total plaintext blocks under the key.

**Confidentiality (Theorem 1):**

    Adv ≤ Adv_AES + (σ + 2q)² / 2¹²⁹ + (much smaller terms)

50 GiB = 2³¹·⁶⁴ blocks. One-shot (q = 1): 2⁻⁶⁵·⁷. Chunked (q = 51,200): σ + 2q grows by only
0.003 %, so still **2⁻⁶⁵·⁷**. The largest of the smaller terms is 2⁻⁷⁸·⁷. (The rough rule σ²/2¹²⁸
gives 2⁻⁶⁴·⁷; Theorem 1 divides by 2¹²⁹.)

**Authenticity (Theorem 2):** the same quadratic term plus, for each forgery attempt, about
ℓ / 2¹²⁸, where ℓ is the number of blocks in the message being forged:

| | One-shot GCM | Chunked, 1 MiB |
|---|---|---|
| Per forgery attempt | 2³¹·⁶⁴ / 2¹²⁸ = 2⁻⁹⁶·⁴ | 2¹⁶ / 2¹²⁸ = 2⁻¹¹² |
| One attempt at every chunk (51,200) | — | 2⁻⁹⁶·⁴ |

So chunking is **bound-neutral**: no number gets worse. This holds only because of Claim 1; with
random nonces or a shared key across files it would not.

Note: Iwata, Ohashi and Minematsu (CRYPTO 2012) found a flaw in McGrew–Viega's proof for nonces
that are not 96 bits and repaired the bounds; for 96-bit nonces, which we always use, the
repaired bounds are better than the general case.

## Claim 3: the stream as a whole cannot be rearranged

The receiver computes each chunk's expected nonce from its position and from whether it is the
last chunk, under the file's own key. So:

| Attack | Why it fails |
|---|---|
| Truncation | The new last chunk was sealed with flag 0 but is checked with flag 1 |
| Appending | The real last chunk (flag 1) is no longer last, so it's checked with flag 0 |
| Reordering, replay | A chunk sealed at position i is checked with counter j ≠ i |
| Splicing from another file | The chunk was sealed under a different file key |
| Header edits | The header is HKDF's `info`, so the key changes and every chunk fails |

In each case, the attacker would need a chunk to verify under a (key, nonce) it was not sealed
with: a GCM forgery, bounded by Claim 2. This is the STREAM construction of Hoang, Reyhanitabar,
Rogaway and Vizár (CRYPTO 2015), whose security reduces to that of the underlying AEAD.

All five attacks are implemented and tested (`attacks.py`, `test/test_attacks.py`): each succeeds
against the naive design and fails against ours.

## Claim 4: the user never sees unverified or partial output

Each chunk's plaintext is released only after its tag verifies. The output file appears (atomic
rename) only after the final chunk verifies; on any failure the temporary file is deleted
(`test_failed_decryption_leaves_no_output_file`).

## What we do not claim

- **Whole-file rollback:** an attacker can replace a file with an older genuine version. Detecting
  that needs version numbers or timestamps at a higher layer.
- **A broken random generator:** if the RNG repeats (e.g. a VM snapshot restored twice), two files
  can get the same salt and prefix, hence the same key and nonces. No design that relies on
  randomness survives this; we generate randomness as late as possible (at encryption time).
- **Side channels:** OpenSSL's AES-GCM is constant-time; our Python reference GCM is not and is not
  used for real encryption.
- **Length hiding:** the file size is visible to within one chunk (accepted in the threat model).
- **The 4 PiB format limit is a capacity, not a safety guarantee.** At 4 PiB (2⁴⁸ blocks under one
  key), Theorem 1 gives about 2⁻³³, much weaker than 2⁻⁶⁵·⁷ at 50 GiB. Very large files should be
  split, or the bound re-derived for the intended size.
- **Key management** (creating, storing and sharing the master key) is out of scope. A
  password-based key would first need a password-hashing function such as Argon2.
