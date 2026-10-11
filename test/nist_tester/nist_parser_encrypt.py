import sys
from ref_gcm import reference_gcm_encrypt

# Replace with your actual reference encryption import
# from ref_gcm import reference_gcm_encrypt

def mock_custom_gcm_encrypt(key: bytes, iv: bytes, pt: bytes, aad: bytes) -> tuple[bool, bytes, bytes]:
    """
    Wraps the encryption algorithm. 
    Returns (success_status, ciphertext, tag).
    """
    try:
        # Note: Encryption takes PT and AAD, and generates CT and Tag.
        ciphertext, tag = reference_gcm_encrypt(key, iv, pt, aad)
        return True, ciphertext, tag
    except Exception as e:
        # Catch unexpected errors (e.g., unsupported IV lengths or buffer issues)
        return False, b"", b""

def main():
    current_test = {}
    config = {}
    passed = 0
    failed = 0
    test_count = 0
    current_key = None

# Read directly from standard input
    for line in sys.stdin:
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        # Parse global configuration brackets
        if line.startswith("[") and line.endswith("]"):
            inner = line[1:-1]
            if "=" in inner:
                k, v = inner.split("=")
                config[k.strip()] = int(v.strip())
            continue

        # Handle standard Key = Value pairs
        if "=" in line:
            parts = line.split(" = ")
            if len(parts) == 2:
                k, v = parts[0].strip(), parts[1].strip()
                current_test[k] = v
                current_key = k
        # Handle wrapped hexadecimal strings (copy-paste artifacts)
        elif current_key and all(c in "0123456789abcdefABCDEF" for c in line):
            current_test[current_key] += line

        # A complete encryption test block contains all 6 of these variables
        if current_key == "Tag" and all(k in current_test for k in ("Key", "IV", "PT", "AAD", "CT", "Tag")):
            test_count += 1

            # Convert defined bit lengths to byte lengths
            pt_len_bytes = config.get("PTlen", 0) // 8
            aad_len_bytes = config.get("AADlen", 0) // 8
            tag_len_bytes = config.get("Taglen", 128) // 8

            key = bytes.fromhex(current_test.get("Key", ""))
            iv = bytes.fromhex(current_test.get("IV", ""))

            # Truncate inputs to strip phantom bytes
            pt = bytes.fromhex(current_test.get("PT", ""))[:pt_len_bytes]
            aad = bytes.fromhex(current_test.get("AAD", ""))[:aad_len_bytes]

            # Truncate expected outputs to match the specified lengths
            expected_ct = bytes.fromhex(current_test.get("CT", ""))[:pt_len_bytes]
            expected_tag = bytes.fromhex(current_test.get("Tag", ""))[:tag_len_bytes]

            # Execute the encryption pipeline
            success, computed_ct, computed_tag = mock_custom_gcm_encrypt(key, iv, pt, aad)
            
            # Force Truncation
            if success:
                computed_tag = computed_tag[:tag_len_bytes]

            # Evaluate results
            if success and computed_ct == expected_ct and computed_tag == expected_tag:
                passed += 1
            elif not success:
                print(f"Test {test_count} Failed: Algorithm threw an exception during encryption.")
                failed += 1
            else:
                print(f"Test {test_count} Failed: Output mismatch.")
                if computed_ct != expected_ct:
                    print(f"  -> CT mismatch.\n     Expected: {expected_ct.hex()}\n     Got:      {computed_ct.hex()}")
                if computed_tag != expected_tag:
                    print(f"  -> Tag mismatch.\n     Expected: {expected_tag.hex()}\n     Got:      {computed_tag.hex()}")
                failed += 1

            current_test.clear()
            current_key = None

    print("\n--- NIST CAVS 14.0 GCM Encryption Results ---")
    print(f"Total Tests Executed : {test_count}")
    print(f"Passed               : {passed}")
    print(f"Failed               : {failed}")

    if failed > 0:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
