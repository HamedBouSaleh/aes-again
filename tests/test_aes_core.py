import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aes_core as aes


def test_parse_hex_block_valid():
    b = aes.parse_hex_block("00112233445566778899aabbccddeeff")
    assert len(b) == 16
    assert b.hex() == "00112233445566778899aabbccddeeff"


def test_parse_hex_block_with_spaces():
    b = aes.parse_hex_block("00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff")
    assert len(b) == 16
    assert b[0] == 0x00 and b[15] == 0xff


def test_parse_hex_block_uppercase():
    b = aes.parse_hex_block("00112233445566778899AABBCCDDEEFF")
    assert b.hex() == "00112233445566778899aabbccddeeff"


def test_parse_hex_block_invalid_length():
    with pytest.raises(ValueError, match="32 hexadecimal"):
        aes.parse_hex_block("00" * 15)
    with pytest.raises(ValueError, match="32 hexadecimal"):
        aes.parse_hex_block("00" * 33)


def test_parse_hex_block_invalid_chars():
    with pytest.raises(ValueError, match="32 hexadecimal"):
        aes.parse_hex_block("00" * 15 + "gg")


def test_parse_hex_key_same_as_block():
    k = aes.parse_hex_key("000102030405060708090a0b0c0d0e0f")
    assert len(k) == 16


def test_bytes_to_state_to_bytes_roundtrip():
    block = bytes(range(16))
    state = aes.bytes_to_state(block)
    back = aes.state_to_bytes(state)
    assert back == block


def test_state_copy_is_deep():
    state = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]]
    c = aes.state_copy(state)
    c[0][0] = 99
    assert state[0][0] == 1


def test_key_expansion_length():
    key = aes.parse_hex_key("000102030405060708090a0b0c0d0e0f")
    rks = aes.key_expansion(key)
    assert len(rks) == 11
    for rk in rks:
        assert len(rk) == 4 and len(rk[0]) == 4


def test_key_expansion_invalid_key():
    with pytest.raises(ValueError, match="16 bytes"):
        aes.key_expansion(bytes(8))


def test_encrypt_decrypt_roundtrip():
    key = aes.parse_hex_key("000102030405060708090a0b0c0d0e0f")
    block = aes.parse_hex_block("00112233445566778899aabbccddeeff")
    rks = aes.key_expansion(key)
    ct = aes.encrypt_block(block, rks)
    pt = aes.decrypt_block(ct, rks)
    assert pt == block


def test_encrypt_block_with_rounds_returns_11_states():
    key = aes.parse_hex_key("000102030405060708090a0b0c0d0e0f")
    block = aes.parse_hex_block("00112233445566778899aabbccddeeff")
    rks = aes.key_expansion(key)
    states = aes.encrypt_block_with_rounds(block, rks)
    assert len(states) == 11
    last_state = states[-1]
    assert aes.state_to_bytes(last_state) == aes.encrypt_block(block, rks)


def test_decrypt_block_with_rounds_returns_11_states():
    key = aes.parse_hex_key("000102030405060708090a0b0c0d0e0f")
    block = aes.parse_hex_block("00112233445566778899aabbccddeeff")
    rks = aes.key_expansion(key)
    ct = aes.encrypt_block(block, rks)
    states = aes.decrypt_block_with_rounds(ct, rks)
    assert len(states) == 11
    assert aes.state_to_bytes(states[-1]) == block


def test_one_round_steps_round_0():
    key = aes.parse_hex_key("000102030405060708090a0b0c0d0e0f")
    block = aes.parse_hex_block("00112233445566778899aabbccddeeff")
    rks = aes.key_expansion(key)
    steps = aes.one_round_steps(block, rks, 0)
    assert len(steps) == 1
    assert "AddRoundKey" in steps[0][0]


def test_one_round_steps_round_1():
    key = aes.parse_hex_key("000102030405060708090a0b0c0d0e0f")
    block = aes.parse_hex_block("00112233445566778899aabbccddeeff")
    rks = aes.key_expansion(key)
    steps = aes.one_round_steps(block, rks, 1)
    assert len(steps) >= 4
    names = [s[0] for s in steps]
    assert "SubBytes" in names and "ShiftRows" in names and "AddRoundKey" in names


def test_one_round_steps_round_10_no_mix_columns():
    key = aes.parse_hex_key("000102030405060708090a0b0c0d0e0f")
    block = aes.parse_hex_block("00112233445566778899aabbccddeeff")
    rks = aes.key_expansion(key)
    steps = aes.one_round_steps(block, rks, 10)
    names = [s[0] for s in steps]
    assert "MixColumns" not in names


def test_bit_mismatch_identical():
    state = aes.bytes_to_state(bytes(range(16)))
    same = aes.state_copy(state)
    assert aes.bit_mismatch(state, same) == 0


def test_bit_mismatch_one_byte_diff():
    a = aes.bytes_to_state(bytes(16))
    b = aes.bytes_to_state(bytes(16))
    b[0][0] = 0x01  # 1 bit difference
    assert aes.bit_mismatch(a, b) == 1


def test_bit_mismatch_max():
    a = aes.bytes_to_state(bytes(16))
    b = aes.bytes_to_state(bytes([0xff] * 16))
    assert aes.bit_mismatch(a, b) == 128


def test_state_to_hex_grid():
    state = [[0x00, 0x11, 0x22, 0x33],
             [0x44, 0x55, 0x66, 0x77],
             [0x88, 0x99, 0xaa, 0xbb],
             [0xcc, 0xdd, 0xee, 0xff]]
    grid = aes.state_to_hex_grid(state)
    assert "00 11 22 33" in grid
    assert "cc dd ee ff" in grid


def test_words_to_hex_words():
    key = aes.parse_hex_key("000102030405060708090a0b0c0d0e0f")
    rks = aes.key_expansion(key)
    hex_groups = aes.words_to_hex_words(rks)
    assert len(hex_groups) == 11
    assert len(hex_groups[0]) == 4
    assert all(len(g) == 4 for g in hex_groups)
