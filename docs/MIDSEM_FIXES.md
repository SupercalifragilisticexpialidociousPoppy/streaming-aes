# Corrections to the midsem slides and report

What the professor flagged, what else was wrong, and replacement text to use in the final report
and slides.

## Flagged by the professor

### 1. "AES-ECB": GCM uses no ECB
- **Slide 3, steps 1 and 3** said H and the keystream come from "AES-ECB". GCM is defined with the
  AES block cipher E_K and GCM's counter mode (GCTR) only. The code now has no ECB (`aes_ctr.py`).
- **Replacement text:**
  > 1. Hash subkey: H = E_K(0¹²⁸), the AES block cipher applied once to the all-zero block.
  > 3. Counter mode (GCTR): J₁, J₂, … are encrypted with E_K and XORed with the plaintext blocks.

### 2. Why HKDF is necessary
Add this (full version: `DESIGN_RATIONALE.md`, "Per-file key via HKDF-SHA256"):
> Without HKDF every file would be encrypted under the same master key. Two files with the same
> random 7-byte nonce prefix would then reuse every (key, nonce) pair, which lets an attacker recover
> GCM's hash key H and forge messages; across a million files the chance is about 1 in 130,000.
> Chunks could also be moved between files, and nothing would protect the header. HKDF gives each
> file its own key from a 32-byte random salt and binds the whole header into that key.

### 3. The GCM diagram
- Replace the copied figure with `docs/gcm_diagram.svg` (our own, from SP 800-38D). It shows what
  the old one did not: where H comes from (H = E_K(0¹²⁸)), that ⊗H is multiplication in GF(2¹²⁸)
  (carry-less, reduced mod x¹²⁸ + x⁷ + x² + x + 1), the order A → C₁ → C₂ → lengths, that
  X₀ = 0, and that J₀ is used only to mask the tag. Data flows top to bottom.
- The slide text should also say GHASH runs over the AAD, the ciphertext **and** the length block,
  not "every ciphertext block".

## Other errors found

| Where | Was | Should be |
|---|---|---|
| Slide 3 | "master password" | the AES key K (in the stream: the per-file stream key) |
| Slide 3 | "4-bit counter" | 4-byte (32-bit) counter |
| Slide 3, step 5 | "encrypted zero counter block" | E_K(J₀), the encrypted pre-counter block (E_K(0¹²⁸) is H) |
| Slide 4 | 36,428 test cases | **47,250** (all 7,875 records in each of the 6 files). The old runner skipped records with an empty plaintext or AAD. |
| Slide 4 / Limitations | 30–45 s per NIST file | about 1 s per file now |
| Slide 6 | "Final Tag" | final **flag** (the 16-byte tag is something else) |
| Slide 6 | "lets the hardware backend skip GHASH" | the GCM spec skips GHASH of the IV for 96-bit IVs, in any implementation |
| Slide 7 | N = ceil(plaintext_size / chunk_size') for decryption | ceil((ciphertext_size − 49) / (chunk_size + 16)) |
| Slide 7 | "write plaintext to disk" | write to a temporary file, renamed into place only after the final chunk verifies |
| Slide 8 / Report 4.5 | "encrypts and decrypts" (only encryption was measured) | both are measured now: 3.02 MiB for each |
| Slide 8 | 4.02 MiB | 3.02 MiB (one copy per chunk removed) |
| Limitations 1–2 | our GCM not integrated | integrated: `backend="reference"`, byte-identical to the library |
| Report | citations shown as [?] | add bibliography entries: PRD, NIST CAVP, RFC 5869, Tink Streaming AEAD, age spec, the midsem slides |
| Report | "6 References" followed by a second "References" heading | one heading |
| Report 3.1 | "The PRD specifies" twice | once |
| Report 2.1 | T = E_K(J₀) ⊕ GHASH_H(A, C) | GHASH input is A ‖ 0ᵛ ‖ C ‖ 0ᵘ ‖ [len(A)]₆₄ ‖ [len(C)]₆₄ |
| Report 5.5 | security bounds "not established" | now derived in `SECURITY_ARGUMENT.md` (2⁻⁶⁵·⁷ from Theorem 1, not 2⁻⁶⁴·⁷) |
