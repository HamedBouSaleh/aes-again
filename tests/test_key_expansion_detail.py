import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aes_core as aes


def test_expansion_first_four_words_from_key():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    rks = aes.key_expansion(key)
    rk0 = rks[0]
    w0 = (rk0[0][0] << 24) | (rk0[1][0] << 16) | (rk0[2][0] << 8) | rk0[3][0]
    assert w0 == 0x00010203
    w3 = (rk0[0][3] << 24) | (rk0[1][3] << 16) | (rk0[2][3] << 8) | rk0[3][3]
    assert w3 == 0x0c0d0e0f


def test_expansion_11_round_keys():
    key = bytes(16)
    rks = aes.key_expansion(key)
    assert len(rks) == 11
    for i, rk in enumerate(rks):
        assert len(rk) == 4
        assert all(len(rk[r]) == 4 for r in range(4))


def test_expansion_different_key_different_schedule():
    k1 = bytes.fromhex("00000000000000000000000000000000")
    k2 = bytes.fromhex("00000000000000000000000000000001")
    rks1 = aes.key_expansion(k1)
    rks2 = aes.key_expansion(k2)
    assert rks1[0] != rks2[0] or rks1[1] != rks2[1]


def test_words_to_hex_words_format():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    rks = aes.key_expansion(key)
    hex_groups = aes.words_to_hex_words(rks)
    assert len(hex_groups) == 11
    for g in hex_groups:
        assert len(g) == 4
        for w in g:
            assert len(w) == 8
            assert all(c in "0123456789abcdef" for c in w)
