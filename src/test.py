import os
from stream import StreamEncryptor, StreamDecryptor

def main():
    # 1. Setup a master key and create a small text file
    master_key = os.urandom(32)
    original_path = "test_message.txt"
    encrypted_path = "test_message.enc"
    decrypted_path = "test_message.dec"

    # with open(original_path, "wb") as f:
    #     f.write(b"Hello world! This is a streaming AES-GCM test.\n" * 50)

    # 2. Encrypt the file
    # We set a deliberately tiny chunk size (1024 bytes) so even a small 
    # text file gets split into multiple chunks, forcing the loop to run.
    encryptor = StreamEncryptor(master_key, chunk_size=1024)
    
    with open(original_path, "rb") as src, open(encrypted_path, "wb") as dst:
        encryptor.encrypt(src, dst)
        
    print(f"Encrypted size: {os.path.getsize(encrypted_path)} bytes")

    # 3. Decrypt the file using the secure atomic replacement method
    decryptor = StreamDecryptor(master_key)
    
    with open(encrypted_path, "rb") as src:
        decryptor.decrypt_to_path(src, decrypted_path)

    # 4. Verify the decrypted bytes perfectly match the original
    with open(original_path, "rb") as original, open(decrypted_path, "rb") as decrypted:
        if original.read() == decrypted.read():
            print("Success: Decrypted file perfectly matches the original.")
        else:
            print("Failure: Plaintext mismatch.")

if __name__ == "__main__":
    main()