"""
NIST CAVS 14.0 GCM vectors (SP 800-38D), all key sizes, encrypt and decrypt files,
against our own GCM. Gate for week 2: 100% must pass.
"""
import os

import pytest
from conftest import VECTORS

from nist_parser import check_vector, iter_vectors

FILES = [
    "gcmDecrypt128.rsp", "gcmDecrypt192.rsp", "gcmDecrypt256.rsp",
    "gcmEncryptExtIV128.rsp", "gcmEncryptExtIV192.rsp", "gcmEncryptExtIV256.rsp",
]


def load(name):
    with open(os.path.join(VECTORS, name), encoding="utf-8", errors="ignore") as f:
        return list(iter_vectors(f))


@pytest.mark.parametrize("name", FILES)
def test_every_vector_in_file(name):
    vectors = load(name)
    # Each CAVS file has 7875 records; a parser that drops empty-PT records finds ~7086.
    assert len(vectors) == 7875

    failures = [(v.get("Count"), r) for v in vectors if (r := check_vector(v)) is not None]
    assert failures == []


def test_parser_keeps_empty_plaintext_and_aad_records():
    vectors = load("gcmDecrypt128.rsp")
    empty_pt = [v for v in vectors if v.get("PT") == "" and not v.get("FAIL")]
    assert len(empty_pt) == 789
    assert all(v["AAD"] == "" or len(bytes.fromhex(v["AAD"])) * 8 == v["AADlen"] for v in vectors)
