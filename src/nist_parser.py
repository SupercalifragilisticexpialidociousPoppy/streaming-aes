import sys
from ref_gcm import reference_gcm_decrypt

# Replace this import with your actual GCM implementation
# from my_gcm import custom_gcm_decrypt

def mock_custom_gcm_decrypt(key: bytes, iv: bytes, ct: bytes, aad: bytes, tag: bytes) -> tuple[bool, bytes]:
    """
    Placeholder for your actual GCM decryption function.
    Must return a tuple of (is_valid_tag: bool, plaintext: bytes).
    """
    # For testing the parser, we'll just pretend everything fails
    try:
        plaintext = reference_gcm_decrypt(key, iv, ct, tag, aad)
        # If no ValueError is raised, decryption succeeded
        return True, plaintext
    except ValueError:
        # If the tag is invalid, return authentication failure status
        return False, b""


def main():
    current_test = {}
    config = {}  # Store global [Keylen = 128] etc.
    passed = 0
    failed = 0
    test_count = 0

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

        if line == "FAIL":
            current_test["FAIL"] = True
        else:
            key_value = line.split(" = ")
            if len(key_value) == 2:
                k, v = key_value[0].strip(), key_value[1].strip()
                current_test[k] = v

        if "PT" in current_test or "FAIL" in current_test:
            test_count += 1
            
            # Convert defined bit lengths to byte lengths
            pt_len_bytes = config.get("PTlen", 0) // 8
            aad_len_bytes = config.get("AADlen", 0) // 8
            
            key = bytes.fromhex(current_test.get("Key", ""))
            iv = bytes.fromhex(current_test.get("IV", ""))
            
            # Truncate CT and AAD to their exact required lengths
            ct = bytes.fromhex(current_test.get("CT", ""))[:pt_len_bytes]
            aad = bytes.fromhex(current_test.get("AAD", ""))[:aad_len_bytes]
            
            expected_tag = bytes.fromhex(current_test.get("Tag", ""))
            
            # The config dict now holds IVlen, Keylen, Taglen, etc. 
            # if your decryption function needs explicit lengths.
            
            is_valid, decrypted_pt = mock_custom_gcm_decrypt(key, iv, ct, aad, expected_tag)
            
            if "FAIL" in current_test:
                if not is_valid:
                    passed += 1
                else:
                    print(f"Test {test_count} Failed: Accepted invalid tag.")
                    failed += 1
            else:
                # Also ensure the expected plaintext is truncated if necessary
                expected_pt = bytes.fromhex(current_test.get("PT", ""))[:pt_len_bytes]
                
                if is_valid and decrypted_pt == expected_pt:
                    passed += 1
                elif not is_valid:
                    print(f"Test {test_count} Failed: Rejected valid tag.")
                    failed += 1
                else:
                    print(f"Test {test_count} Failed: Plaintext mismatch.")
                    failed += 1

            current_test.clear()

    print("\n--- NIST CAVS 14.0 GCM Decryption Results ---")
    print(f"Total Tests Executed : {test_count}")
    print(f"Passed               : {passed}")
    print(f"Failed               : {failed}")
    
    if failed > 0:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()