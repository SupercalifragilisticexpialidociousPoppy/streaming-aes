import os
import tracemalloc
from stream import StreamEncryptor

def measure_peak_memory(input_path, output_path, master_key):
    """Runs the encryption and returns the peak Python heap memory used in bytes."""
    tracemalloc.start()
    
    encryptor = StreamEncryptor(master_key, chunk_size=1048576) # 1 MiB chunks
    with open(input_path, "rb") as src, open(output_path, "wb") as dst:
        encryptor.encrypt(src, dst)
        
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak

def test_constant_memory_complexity(tmp_path):
    """
    Proves O(1) constant memory usage by ensuring a large file 
    requires the same RAM buffer footprint as a small file.
    """
    master_key = os.urandom(32)
    
    small_input = tmp_path / "small_input.bin"
    small_output = tmp_path / "small_output.enc"
    
    large_input = tmp_path / "large_input.bin"
    large_output = tmp_path / "large_output.enc"

    # 1. Create a 5 MB file and a 50 MB file
    chunk_1mb = b'\x00' * (1024 * 1024)
    
    with open(small_input, "wb") as f:
        for _ in range(5): f.write(chunk_1mb)
            
    with open(large_input, "wb") as f:
        for _ in range(50): f.write(chunk_1mb)

    # 2. Measure peak heap memory for both operations
    peak_small = measure_peak_memory(small_input, small_output, master_key)
    peak_large = measure_peak_memory(large_input, large_output, master_key)
    
    peak_small_mib = peak_small / (1024 * 1024)
    peak_large_mib = peak_large / (1024 * 1024)
    
    print(f"\nPeak RAM (5 MB file)  : {peak_small_mib:.2f} MiB")
    print(f"Peak RAM (50 MB file) : {peak_large_mib:.2f} MiB")

    # 3. Assert the memory footprint is constant
    # We allow a tiny 512 KiB margin for Python's internal garbage collection timing
    memory_difference = abs(peak_large - peak_small)
    assert memory_difference < (512 * 1024), (
        f"Memory leak detected! The large file used {(memory_difference / 1024 / 1024):.2f} MiB more RAM."
    )