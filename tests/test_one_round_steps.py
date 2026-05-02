import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aes_core as aes


def test_round_0_one_step():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    rks = aes.key_expansion(key)
    steps = aes.one_round_steps(block, rks, 0)
    assert len(steps) == 1
    assert "AddRoundKey" in steps[0][0]


def test_round_1_has_subbytes_shiftrows_mixcolumns_addroundkey():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    rks = aes.key_expansion(key)
    steps = aes.one_round_steps(block, rks, 1)
    names = [s[0] for s in steps]
    assert "SubBytes" in names
    assert "ShiftRows" in names
    assert "MixColumns" in names
    assert "AddRoundKey" in names
    assert "Initial state" in names[0] or "Initial" in names[0]


def test_round_10_no_mix_columns():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    rks = aes.key_expansion(key)
    steps = aes.one_round_steps(block, rks, 10)
    names = [s[0] for s in steps]
    assert "MixColumns" not in names


def test_each_step_has_4x4_state():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    rks = aes.key_expansion(key)
    for rnd in range(11):
        steps = aes.one_round_steps(block, rks, rnd)
        for name, state in steps:
            assert len(state) == 4
            assert all(len(row) == 4 for row in state)
            assert all(0 <= state[r][c] <= 255 for r in range(4) for c in range(4))


def test_one_round_steps_match_full_encryption_round_boundaries():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    block = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    rks = aes.key_expansion(key)
    full_round_states = aes.encrypt_block_with_rounds(block, rks)

    for rnd in range(1, 11):
        steps = aes.one_round_steps(block, rks, rnd)
        assert steps[0][1] == full_round_states[rnd - 1]
        assert steps[-1][1] == full_round_states[rnd]


def test_one_round_steps_round_10_reaches_nist_ciphertext():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    block = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    expected_ct = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    rks = aes.key_expansion(key)
    steps = aes.one_round_steps(block, rks, 10)
    assert aes.state_to_bytes(steps[-1][1]) == expected_ct
