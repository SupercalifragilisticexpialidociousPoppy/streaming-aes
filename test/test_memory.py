"""
Constant memory: peak Python-heap allocation (tracemalloc) while encrypting AND decrypting
must not grow with file size. tracemalloc measures what our code allocates, not the whole
process (the interpreter itself uses more than 4 MiB).
"""
import os
import tracemalloc

from stream import StreamDecryptor, StreamEncryptor

MiB = 1024 * 1024
KEY = os.urandom(32)


def _peak(fn) -> int:
    tracemalloc.start()
    fn()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak


def _make_file(path, mib):
    with open(path, "wb") as f:
        for _ in range(mib):
            f.write(os.urandom(MiB))


def _measure(tmp_path, mib):
    plain, enc, dec = tmp_path / f"p{mib}", tmp_path / f"e{mib}", tmp_path / f"d{mib}"
    _make_file(plain, mib)

    def encrypt():
        with open(plain, "rb") as src, open(enc, "wb") as dst:
            StreamEncryptor(KEY).encrypt(src, dst)

    def decrypt():
        with open(enc, "rb") as src:
            StreamDecryptor(KEY).decrypt_to_path(src, str(dec))

    enc_peak, dec_peak = _peak(encrypt), _peak(decrypt)
    assert dec.read_bytes() == plain.read_bytes()
    return enc_peak, dec_peak


def test_peak_memory_does_not_grow_with_file_size(tmp_path):
    small = _measure(tmp_path, 5)
    large = _measure(tmp_path, 50)
    for label, s, l in (("encrypt", small[0], large[0]), ("decrypt", small[1], large[1])):
        print(f"\n{label}: 5 MiB file peak {s / MiB:.2f} MiB, 50 MiB file peak {l / MiB:.2f} MiB")
        assert abs(l - s) < MiB // 2      # same footprint, 10x the data
        assert l < 6 * MiB                # a few 1 MiB buffers, never the file
