"""
Encrypted file transfer over a TCP socket: proves the design works on a one-pass stream that
can't be rewound, and that a connection cut mid-transfer is caught.

Two terminals:
    python socket_demo.py receive 9000 key.hex received.bin
    python socket_demo.py send localhost 9000 key.hex big_file.bin [--cut-after BYTES]

One command, both sides on this machine (an intact transfer, then one cut halfway):
    python socket_demo.py demo
"""
import argparse
import os
import socket
import tempfile
import threading

from cli import load_key
from errors import ChunkcryptError
from stream import StreamDecryptor, StreamEncryptor


class CutAfter:
    """A writer that silently stops forwarding after `limit` bytes, like a dropped connection."""
    def __init__(self, inner, limit):
        self.inner, self.left = inner, limit
    def write(self, data):
        keep = data[:max(self.left, 0)]
        self.left -= len(data)
        if keep:
            self.inner.write(keep)


def send(host, port, key, path, cut_after=None):
    with socket.create_connection((host, port)) as sock, sock.makefile("wb") as wire, \
            open(path, "rb") as src:
        dst = CutAfter(wire, cut_after) if cut_after is not None else wire
        StreamEncryptor(key).encrypt(src, dst)


def receive(listener, key, out_path) -> bool:
    conn, _ = listener.accept()
    with conn, conn.makefile("rb") as wire:
        try:
            StreamDecryptor(key).decrypt_to_path(wire, out_path)
            print(f"  receiver: stream verified, wrote {os.path.getsize(out_path):,} bytes")
            return True
        except ChunkcryptError as e:
            print(f"  receiver: REJECTED ({e}); {out_path} exists: {os.path.exists(out_path)}")
            return False


def demo():
    key = os.urandom(32)
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "file.bin")
        with open(src, "wb") as f:
            f.write(os.urandom(10 * 1024 * 1024))                  # 10 MiB = 10 chunks
        for label, cut in (("intact transfer", None), ("connection cut after 5 MiB", 5 * 1024 * 1024)):
            print(label)
            out = os.path.join(tmp, f"out_{cut}.bin")
            with socket.create_server(("127.0.0.1", 0)) as listener:
                port = listener.getsockname()[1]
                sender = threading.Thread(target=send, args=("127.0.0.1", port, key, src, cut))
                sender.start()
                receive(listener, key, out)
                sender.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("receive")
    r.add_argument("port", type=int)
    r.add_argument("keyfile")
    r.add_argument("output")
    s = sub.add_parser("send")
    s.add_argument("host")
    s.add_argument("port", type=int)
    s.add_argument("keyfile")
    s.add_argument("input")
    s.add_argument("--cut-after", type=int)
    sub.add_parser("demo")
    args = parser.parse_args()

    if args.cmd == "demo":
        demo()
    elif args.cmd == "receive":
        with socket.create_server(("", args.port)) as listener:
            print(f"listening on port {args.port}")
            receive(listener, load_key(args.keyfile), args.output)
    else:
        send(args.host, args.port, load_key(args.keyfile), args.input, args.cut_after)


if __name__ == "__main__":
    main()
