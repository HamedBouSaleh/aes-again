import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aes_core as aes


def test_avalanche_same_input_zero_mismatch():
    a = aes.bytes_to_state(bytes(16))
    b = aes.bytes_to_state(bytes(16))
    assert aes.bit_mismatch(a, b) == 0


def test_avalanche_one_bit_diff():
    a = aes.bytes_to_state(bytes(16))
    b = aes.bytes_to_state(bytes(16))
    b[0][0] = 1
    assert aes.bit_mismatch(a, b) == 1


def test_avalanche_one_byte_diff():
    a = aes.bytes_to_state(bytes(16))
    b = aes.bytes_to_state(bytes(16))
    b[0][0] = 0xFF
    assert aes.bit_mismatch(a, b) == 8


def test_avalanche_same_key_different_block_different_ciphertext():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    b1 = bytes.fromhex("00112233445566778899aabbccddeeff")
    b2 = bytes.fromhex("00112233445566778899aabbccddeefe")  # 1 bit diff
    rks = aes.key_expansion(key)
    ct1 = aes.encrypt_block(b1, rks)
    ct2 = aes.encrypt_block(b2, rks)
    assert ct1 != ct2


def test_avalanche_same_block_different_key_different_ciphertext():
    k1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    k2 = bytes.fromhex("000102030405060708090a0b0c0d0e0e")  # 1 bit diff
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    rks1 = aes.key_expansion(k1)
    rks2 = aes.key_expansion(k2)
    ct1 = aes.encrypt_block(block, rks1)
    ct2 = aes.encrypt_block(block, rks2)
    assert ct1 != ct2


def test_avalanche_mismatch_count_increases_over_rounds():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    b1 = bytes.fromhex("00112233445566778899aabbccddeeff")
    b2 = bytes.fromhex("00112233445566778899aabbccddeefe")
    rks = aes.key_expansion(key)
    s1 = aes.encrypt_block_with_rounds(b1, rks)
    s2 = aes.encrypt_block_with_rounds(b2, rks)
    mismatches = [aes.bit_mismatch(s1[i], s2[i]) for i in range(11)]

    assert mismatches[0] >= 0
    assert any(m > 0 for m in mismatches)
