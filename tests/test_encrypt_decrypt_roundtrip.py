import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aes_core as aes


@pytest.mark.parametrize("key_hex,block_hex", [
    ("0" * 32, "0" * 32),
    ("f" * 32, "f" * 32),
    ("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff"),
    ("2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734"),
])
def test_encrypt_decrypt_roundtrip(key_hex, block_hex):
    key = bytes.fromhex(key_hex)
    block = bytes.fromhex(block_hex)
    rks = aes.key_expansion(key)
    ct = aes.encrypt_block(block, rks)
    pt = aes.decrypt_block(ct, rks)
    assert pt == block


def test_encrypt_with_rounds_final_equals_encrypt_block():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    rks = aes.key_expansion(key)
    states = aes.encrypt_block_with_rounds(block, rks)
    ct_from_states = aes.state_to_bytes(states[-1])
    ct_direct = aes.encrypt_block(block, rks)
    assert ct_from_states == ct_direct


def test_decrypt_with_rounds_final_equals_plaintext():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    rks = aes.key_expansion(key)
    ct = aes.encrypt_block(block, rks)
    states = aes.decrypt_block_with_rounds(ct, rks)
    pt_from_states = aes.state_to_bytes(states[-1])
    assert pt_from_states == block


def test_ciphertext_different_from_plaintext():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    rks = aes.key_expansion(key)
    ct = aes.encrypt_block(block, rks)
    assert ct != block
