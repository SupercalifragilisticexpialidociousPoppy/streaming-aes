import os
import subprocess
import sys
import time

# Run from src/:  python .\test.py
HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "..", "test", "nist_vectors")

# Define the file paths and the target parser script
tasks = [
    {"input_file": "gcmDecrypt128.rsp", "label": "128-bit Decryption"},
    {"input_file": "gcmDecrypt192.rsp", "label": "192-bit Decryption"},
    {"input_file": "gcmDecrypt256.rsp", "label": "256-bit Decryption"},
    {"input_file": "gcmEncryptExtIV128.rsp", "label": "128-bit Encryption"},
    {"input_file": "gcmEncryptExtIV192.rsp", "label": "192-bit Encryption"},
    {"input_file": "gcmEncryptExtIV256.rsp", "label": "256-bit Encryption"},
]

parser_script = [sys.executable, os.path.join(HERE, "nist_parser.py")]


def run_benchmarks():
    any_failed = False

    for index, task in enumerate(tasks, 1):
        input_path = os.path.join(VECTORS, task["input_file"])

        print("=" * 60)
        print(f"Running Subcommand {index}: {task['label']}")
        print(f"Feeding {task['input_file']} -> nist_parser.py")
        print("=" * 60)
        sys.stdout.flush()

        if not os.path.exists(input_path):
            print(f"Error: Input file not found at {input_path}")
            print("=" * 60 + "\n")
            any_failed = True
            continue

        # Track start time
        start_time = time.perf_counter()

        # Open the response file and pipe it directly to nist_parser.py
        with open(input_path, "r", encoding="utf-8", errors="ignore") as infile:
            process = subprocess.Popen(
                parser_script,
                stdin=infile,
                stdout=None,  # Inherits terminal stdout so it streams live
                stderr=sys.stderr,
            )
            process.wait()
        any_failed |= process.returncode != 0

        # Track end time
        execution_time = time.perf_counter() - start_time

        print("-" * 60)
        print(f"Subcommand {index} completed.")
        print(f"Execution Time: {execution_time:.4f} seconds")
        print("=" * 60 + "\n")
        sys.stdout.flush()

    sys.exit(1 if any_failed else 0)


if __name__ == '__main__':
    run_benchmarks()
