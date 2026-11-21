"""
Command-line interface.

    python cli.py keygen  KEYFILE
    python cli.py encrypt KEYFILE INPUT OUTPUT      (INPUT / OUTPUT may be "-" for stdin / stdout)
    python cli.py decrypt KEYFILE INPUT OUTPUT      (INPUT may be "-"; OUTPUT must be a file path)

The master key is 32 random bytes from the OS, stored as hex. Decryption only writes to a
file path, because the file appears only once the whole stream has verified; streaming
plaintext to stdout would hand out data before truncation could be detected.
"""
import argparse
import os
import sys

from errors import ChunkcryptError
from stream import StreamDecryptor, StreamEncryptor


def load_key(path: str) -> bytes:
    with open(path, encoding="ascii") as f:
        key = bytes.fromhex(f.read().strip())
    if len(key) != 32:
        raise SystemExit("key file must hold 32 bytes (64 hex characters)")
    return key


def keygen(args):
    if os.path.exists(args.keyfile):
        raise SystemExit(f"{args.keyfile} already exists; refusing to overwrite a key")
    with open(args.keyfile, "x", encoding="ascii") as f:
        f.write(os.urandom(32).hex() + "\n")
    print(f"wrote a new 256-bit key to {args.keyfile}")


def encrypt(args):
    src = sys.stdin.buffer if args.input == "-" else open(args.input, "rb")
    dst = sys.stdout.buffer if args.output == "-" else open(args.output, "wb")
    with src, dst:
        StreamEncryptor(load_key(args.keyfile)).encrypt(src, dst)


def decrypt(args):
    if args.output == "-":
        raise SystemExit("decrypt needs a file path for OUTPUT (all-or-nothing output)")
    src = sys.stdin.buffer if args.input == "-" else open(args.input, "rb")
    with src:
        try:
            StreamDecryptor(load_key(args.keyfile)).decrypt_to_path(src, args.output)
        except ChunkcryptError as e:
            raise SystemExit(f"decryption failed, no output written: {e}")


def main():
    parser = argparse.ArgumentParser(description="Streaming AES-256-GCM file encryption")
    sub = parser.add_subparsers(required=True)

    p = sub.add_parser("keygen", help="create a new random master key file")
    p.add_argument("keyfile")
    p.set_defaults(func=keygen)

    for name, func in (("encrypt", encrypt), ("decrypt", decrypt)):
        p = sub.add_parser(name)
        p.add_argument("keyfile")
        p.add_argument("input")
        p.add_argument("output")
        p.set_defaults(func=func)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
