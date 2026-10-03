import sys

def main():
    current_test = {}
    config = {}  # Store global [Keylen = 128] etc.
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

        # Trigger once we hit the end of a block
        if "PT" in current_test or "FAIL" in current_test:
            test_count += 1
            
            # Isolate and print testcase 251 (128), 280, 5030(192), 4985(256)
            if test_count == 4985:
                print(f"--- TESTCASE {test_count} DATA ---")
                print("Active Configuration:")
                for k, v in config.items():
                    print(f"  {k}: {v}")
                
                print("\nTest Variables:")
                for k, v in current_test.items():
                    print(f"  {k}: {v}")
                print("--------------------------")
                
                # Exit immediately after printing the target test case
                sys.exit(0)

            current_test.clear()

if __name__ == "__main__":
    main()