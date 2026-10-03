import subprocess
import time
import sys
import os

# Define the file paths and the target parser script
tasks = [
    {"input_file": r"..\test\vectors\gcmDecrypt128.rsp", "label": "128-bit Decryption"},
    {"input_file": r"..\test\vectors\gcmDecrypt192.rsp", "label": "192-bit Decryption"},
    {"input_file": r"..\test\vectors\gcmDecrypt256.rsp", "label": "256-bit Decryption"}
]

parser_script = [sys.executable, r".\nist_parser.py"]

def run_benchmarks():
    for index, task in enumerate(tasks, 1):
        input_path = task["input_file"]
        
        print("=" * 60)
        print(f"Running Subcommand {index}: {task['label']}")
        print(f"Feeding {input_path} -> nist_parser.py")
        print("=" * 60)
        sys.stdout.flush()
        
        if not os.path.exists(input_path):
            print(f"Error: Input file not found at {input_path}")
            print("=" * 60 + "\n")
            continue

        # Track start time
        start_time = time.perf_counter()
        
        # Open the response file and pipe it directly to python .\nist_parser.py
        with open(input_path, "r", encoding="utf-8", errors="ignore") as infile:
            process = subprocess.Popen(
                parser_script,
                stdin=infile,
                stdout=None,  # Inherits terminal stdout so it streams live
                stderr=sys.stderr
            )
            process.wait()
        
        # Track end time
        end_time = time.perf_counter()
        execution_time = end_time - start_time
        
        print("-" * 60)
        print(f"Subcommand {index} completed.")
        print(f"Execution Time: {execution_time:.4f} seconds")
        print("=" * 60 + "\n")
        sys.stdout.flush()

if __name__ == '__main__':
    run_benchmarks()
import subprocess
import time
import sys
import os

# Define the file paths and the target parser script
tasks = [
    {"input_file": r"..\test\vectors\gcmDecrypt128.rsp", "label": "128-bit Decryption"},
    {"input_file": r"..\test\vectors\gcmDecrypt192.rsp", "label": "192-bit Decryption"},
    {"input_file": r"..\test\vectors\gcmDecrypt256.rsp", "label": "256-bit Decryption"}
]

parser_script = [sys.executable, r".\nist_parser.py"]

def run_benchmarks():
    for index, task in enumerate(tasks, 1):
        input_path = task["input_file"]
        
        print("=" * 60)
        print(f"Running Subcommand {index}: {task['label']}")
        print(f"Feeding {input_path} -> nist_parser.py")
        print("=" * 60)
        sys.stdout.flush()
        
        if not os.path.exists(input_path):
            print(f"Error: Input file not found at {input_path}")
            print("=" * 60 + "\n")
            continue

        # Track start time
        start_time = time.perf_counter()
        
        # Open the response file and pipe it directly to python .\nist_parser.py
        with open(input_path, "r", encoding="utf-8", errors="ignore") as infile:
            process = subprocess.Popen(
                parser_script,
                stdin=infile,
                stdout=None,  # Inherits terminal stdout so it streams live
                stderr=sys.stderr
            )
            process.wait()
        
        # Track end time
        end_time = time.perf_counter()
        execution_time = end_time - start_time
        
        print("-" * 60)
        print(f"Subcommand {index} completed.")
        print(f"Execution Time: {execution_time:.4f} seconds")
        print("=" * 60 + "\n")
        sys.stdout.flush()

if __name__ == '__main__':
    run_benchmarks()
import subprocess
import time
import sys
import os

# Define the file paths and the target parser script
tasks = [
    {"input_file": r"..\test\vectors\gcmDecrypt128.rsp", "label": "128-bit Decryption"},
    {"input_file": r"..\test\vectors\gcmDecrypt192.rsp", "label": "192-bit Decryption"},
    {"input_file": r"..\test\vectors\gcmDecrypt256.rsp", "label": "256-bit Decryption"}
]

parser_script = [sys.executable, r".\nist_parser.py"]

def run_benchmarks():
    for index, task in enumerate(tasks, 1):
        input_path = task["input_file"]
        
        print("=" * 60)
        print(f"Running Subcommand {index}: {task['label']}")
        print(f"Feeding {input_path} -> nist_parser.py")
        print("=" * 60)
        sys.stdout.flush()
        
        if not os.path.exists(input_path):
            print(f"Error: Input file not found at {input_path}")
            print("=" * 60 + "\n")
            continue

        # Track start time
        start_time = time.perf_counter()
        
        # Open the response file and pipe it directly to python .\nist_parser.py
        with open(input_path, "r", encoding="utf-8", errors="ignore") as infile:
            process = subprocess.Popen(
                parser_script,
                stdin=infile,
                stdout=None,  # Inherits terminal stdout so it streams live
                stderr=sys.stderr
            )
            process.wait()
        
        # Track end time
        end_time = time.perf_counter()
        execution_time = end_time - start_time
        
        print("-" * 60)
        print(f"Subcommand {index} completed.")
        print(f"Execution Time: {execution_time:.4f} seconds")
        print("=" * 60 + "\n")
        sys.stdout.flush()

if __name__ == '__main__':
    run_benchmarks()


# python .\test.py
# ============================================================
# Running Subcommand 1: 128-bit Decryption
# Feeding ..\test\vectors\gcmDecrypt128.rsp -> nist_parser.py
# ============================================================

# --- NIST CAVS 14.0 GCM Decryption Results ---
# Total Tests Executed : 7086
# Passed               : 7086
# Failed               : 0
# ------------------------------------------------------------
# Subcommand 1 completed.
# Execution Time: 33.5158 seconds
# ============================================================

# ============================================================
# Running Subcommand 2: 192-bit Decryption
# Feeding ..\test\vectors\gcmDecrypt192.rsp -> nist_parser.py
# ============================================================

# --- NIST CAVS 14.0 GCM Decryption Results ---
# Total Tests Executed : 7129
# Passed               : 7129
# Failed               : 0
# ------------------------------------------------------------
# Subcommand 2 completed.
# Execution Time: 28.2797 seconds
# ============================================================

# ============================================================
# Running Subcommand 3: 256-bit Decryption
# Feeding ..\test\vectors\gcmDecrypt256.rsp -> nist_parser.py
# ============================================================

# --- NIST CAVS 14.0 GCM Decryption Results ---
# Total Tests Executed : 7084
# Passed               : 7084
# Failed               : 0
# ------------------------------------------------------------
# Subcommand 3 completed.
# Execution Time: 28.0207 seconds
# ============================================================

# ============================================================
# Running Subcommand 1: 128-bit Decryption
# Feeding ..\test\vectors\gcmDecrypt128.rsp -> nist_parser.py
# ============================================================

# --- NIST CAVS 14.0 GCM Decryption Results ---
# Total Tests Executed : 7086
# Passed               : 7086
# Failed               : 0
# ------------------------------------------------------------
# Subcommand 1 completed.
# Execution Time: 28.4664 seconds
# ============================================================

# ============================================================
# Running Subcommand 2: 192-bit Decryption
# Feeding ..\test\vectors\gcmDecrypt192.rsp -> nist_parser.py
# ============================================================

# --- NIST CAVS 14.0 GCM Decryption Results ---
# Total Tests Executed : 7129
# Passed               : 7129
# Failed               : 0
# ------------------------------------------------------------
# Subcommand 2 completed.
# Execution Time: 35.0936 seconds
# ============================================================

# ============================================================
# Running Subcommand 3: 256-bit Decryption
# Feeding ..\test\vectors\gcmDecrypt256.rsp -> nist_parser.py
# ============================================================

# --- NIST CAVS 14.0 GCM Decryption Results ---
# Total Tests Executed : 7084
# Passed               : 7084
# Failed               : 0
# ------------------------------------------------------------
# Subcommand 3 completed.
# Execution Time: 29.3088 seconds
# ============================================================
