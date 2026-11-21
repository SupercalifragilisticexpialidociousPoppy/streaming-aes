# The attack suite

    cd src && python attacks.py

```
Attack                                     Naive      Ours
--------------------------------------------------------------
1. Truncation (drop the last chunk)        ACCEPTED   rejected
2. Reordering (swap chunks 0 and 1)        ACCEPTED   rejected
3. Replay (repeat chunk 1)                 ACCEPTED   rejected
4. Splicing (chunk 1 from another file)    ACCEPTED   rejected
5. Nonce reuse -> recover H -> forge       ACCEPTED   rejected
                                           recovered H == real H: True
```

**The naive design (`naive.py`)** is "AES-GCM in a loop": every chunk of every file is encrypted
under the master key with a random 12-byte nonce stored next to it, and there is no final flag.
Every chunk still passes its own tag check. That's exactly why attacks 1–4 work: they never break
GCM, they only move whole, valid chunks around.

| Attack | What the attacker does | Why naive accepts | What stops it in ours |
|---|---|---|---|
| 1. Truncation | Drops the last chunk | Nothing marks the end | Final flag in the nonce |
| 2. Reordering | Swaps two chunks | The nonce says nothing about position | Counter in the nonce |
| 3. Replay | Repeats a chunk | Same | Counter in the nonce |
| 4. Splicing | Copies a chunk from another file | All files share one key | Per-file key (HKDF + salt) |
| 5. Nonce reuse | Forges a message after a nonce repeats | Nonces are random and keys are shared | Per-file key; nonces unique by counter |

## Attack 5 in detail: recovering H and forging

Two 16-byte messages P₁, P₂ are encrypted under the same key and nonce. In the naive design this
happens when the random source repeats (simulated in the script); in a design without per-file
keys it happens whenever two files draw the same nonce prefix.

For a one-block message C with no AAD, GHASH is S = C·H² ⊕ L·H (L is the length block) and the
tag is T = S ⊕ E_K(J₀). XOR the two tags: L·H and E_K(J₀) are identical and cancel, leaving

    T₁ ⊕ T₂ = (C₁ ⊕ C₂) · H²     so     H² = (T₁ ⊕ T₂) / (C₁ ⊕ C₂)

Every element of GF(2¹²⁸) has exactly one square root, H = (H²)^(2¹²⁷), so H is recovered exactly
(the script checks it equals the real H). Then:

1. E_K(J₀) = T₁ ⊕ GHASH_H(C₁): the tag mask.
2. Knowing P₁ (e.g. a fixed file header) gives the keystream: C₁ ⊕ P₁.
3. For any wanted message P*: C* = keystream ⊕ P*, and T* = GHASH_H(C*) ⊕ E_K(J₀).

The naive decryptor accepts (C*, T*) and outputs "PAY EVE 99999.99".

**Against our design:** we force the worst case that is realistic for us: two files whose 7-byte
nonce prefixes collide. Their salts differ, so their keys differ. The tags no longer share
E_K(J₀) or H, so the algebra produces a meaningless value and the forged chunk is rejected.

Longer messages give a higher-degree polynomial in H whose roots must be found with a general
algorithm (e.g. Cantor–Zassenhaus). One-block messages show the same weakness with only a field
inverse and a square root, which keeps the attack short and easy to follow.
