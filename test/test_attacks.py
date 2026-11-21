"""Every attack must succeed against naive.py and fail against stream.py."""
import pytest

import attacks


@pytest.mark.parametrize("name, attack", attacks.ATTACKS)
def test_attack_breaks_naive_but_not_ours(name, attack):
    naive_accepted, ours_accepted, *_ = attack()
    assert naive_accepted, f"{name}: naive design should accept the attack"
    assert not ours_accepted, f"{name}: our design must reject the attack"


def test_nonce_reuse_recovers_the_real_hash_key():
    _, _, h_matches = attacks.nonce_reuse()
    assert h_matches
