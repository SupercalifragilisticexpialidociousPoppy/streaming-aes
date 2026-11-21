"""
Runs NIST CAVS 14.0 GCM test vectors (.rsp files) against our own reference GCM.

    python nist_parser.py < ../test/vectors/gcmDecrypt256.rsp
    python nist_parser.py < ../test/vectors/gcmEncryptExtIV256.rsp

Every record is checked in both directions where the file allows it:
  - encrypt(Key, IV, PT, AAD) must give exactly (CT, Tag)
  - decrypt(Key, IV, CT, AAD, Tag) must give exactly PT
  - a record marked FAIL must be rejected by decrypt
"""
import sys
from typing import Iterable, Iterator

from ref_gcm import reference_gcm_decrypt, reference_gcm_encrypt

FIELDS = ("Count", "Key", "IV", "PT", "AAD", "CT", "Tag")


def iter_vectors(lines: Iterable[str]) -> Iterator[dict]:
    """
    Yields one dict per test record, with the active [Keylen/IVlen/...] config merged in.

    A record ends at a blank line, a new "Count =" line, a new "[...]" config line, or EOF.
    Lines like "PT = " (empty value) are kept as empty fields -- they're real vectors
    (empty plaintext / empty AAD), and dropping them silently skips ~10% of the suite.
    """
    config = {}
    record = {}

    def flush():
        if "Key" in record:
            yield {**config, **record}
        record.clear()

    for raw in lines:
        line = raw.strip()

        if line.startswith("#"):
            continue

        if not line:
            yield from flush()
            continue

        if line.startswith("[") and line.endswith("]"):
            yield from flush()
            inner = line[1:-1]
            if "=" in inner:
                k, v = inner.split("=", 1)
                config[k.strip()] = int(v.strip())
            continue

        if line == "FAIL":
            record["FAIL"] = True
            continue

        if "=" in line:
            k, v = line.split("=", 1)
            k = k.strip()
            if k == "Count":
                yield from flush()
            if k in FIELDS:
                record[k] = v.strip()

    yield from flush()


def check_vector(vec: dict) -> str | None:
    """Returns None if the vector passes, otherwise a short reason it failed."""
    key = bytes.fromhex(vec["Key"])
    iv = bytes.fromhex(vec["IV"])
    aad = bytes.fromhex(vec.get("AAD", ""))
    ct = bytes.fromhex(vec.get("CT", ""))
    tag = bytes.fromhex(vec["Tag"])

    if vec.get("FAIL"):
        try:
            reference_gcm_decrypt(key, iv, ct, tag, aad)
        except ValueError:
            return None
        return "accepted an invalid tag"

    pt = bytes.fromhex(vec.get("PT", ""))

    got_ct, got_tag = reference_gcm_encrypt(key, iv, pt, aad, tag_len=len(tag))
    if got_ct != ct:
        return "encrypt: ciphertext mismatch"
    if got_tag != tag:
        return "encrypt: tag mismatch"

    try:
        got_pt = reference_gcm_decrypt(key, iv, ct, tag, aad)
    except ValueError:
        return "decrypt: rejected a valid tag"
    if got_pt != pt:
        return "decrypt: plaintext mismatch"

    return None


def main():
    passed = 0
    failed = 0
    test_count = 0

    for vec in iter_vectors(sys.stdin):
        test_count += 1
        reason = check_vector(vec)
        if reason is None:
            passed += 1
        else:
            failed += 1
            print(f"Test {test_count} (Keylen={vec.get('Keylen')}, Count={vec.get('Count')}) failed: {reason}")

    print("\n--- NIST CAVS 14.0 GCM Results ---")
    print(f"Total Tests Executed : {test_count}")
    print(f"Passed               : {passed}")
    print(f"Failed               : {failed}")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
