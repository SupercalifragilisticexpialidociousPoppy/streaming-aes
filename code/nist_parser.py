def parse_and_run_nist_vectors(rsp_filename: str):
    with open(rsp_filename, "r") as f:
        lines = f.readlines()

    current_test = {}
    passed = 0
    failed = 0

    for line in lines:
        line = line.strip()
        
        # Skip comments or empty lines
        if not line or line.startswith("#") or line.startswith("["):
            continue

        key_value = line.split(" = ")
        if len(key_value) == 2:
            k, v = key_value[0].strip(), key_value[1].strip()
            current_test[k] = v

        # A complete test block in .rsp typically ends after 'Tag' or 'Result'
        if "Tag" in current_test and ("PT" in current_test or "CT" in current_test):
            key = bytes.fromhex(current_test.get("Key", ""))
            iv = bytes.fromhex(current_test.get("IV", ""))
            aad = bytes.fromhex(current_test.get("AAD", ""))
            
            # Encrypt test case
            if "PT" in current_test:
                pt = bytes.fromhex(current_test.get("PT", ""))
                expected_ct = bytes.fromhex(current_test.get("CT", ""))
                expected_tag = bytes.fromhex(current_test.get("Tag", ""))

                # Execute custom pipeline
                # ct, tag = custom_gcm_encrypt(key, iv, pt, aad)
                # if ct == expected_ct and tag == expected_tag:
                #     passed += 1
                # else:
                #     failed += 1

            current_test = {}

    print(f"NIST Verification Complete: {passed} Passed, {failed} Failed.")

# Run against your downloaded vector file
# parse_and_run_nist_vectors("gcmtst256.rsp")