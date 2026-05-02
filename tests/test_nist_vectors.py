import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aes_core as aes

NIST_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
NIST_PLAINTEXT = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
NIST_CIPHERTEXT = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")


def test_nist_encrypt():
    rks = aes.key_expansion(NIST_KEY)
    ct = aes.encrypt_block(NIST_PLAINTEXT, rks)
    assert ct == NIST_CIPHERTEXT, f"Encrypt: got {ct.hex()}, expected {NIST_CIPHERTEXT.hex()}"


def test_nist_decrypt():
    rks = aes.key_expansion(NIST_KEY)
    pt = aes.decrypt_block(NIST_CIPHERTEXT, rks)
    assert pt == NIST_PLAINTEXT, f"Decrypt: got {pt.hex()}, expected {NIST_PLAINTEXT.hex()}"


def test_nist_parse_and_encrypt():
    key = aes.parse_hex_key("2b7e151628aed2a6abf7158809cf4f3c")
    block = aes.parse_hex_block("3243f6a8885a308d313198a2e0370734")
    rks = aes.key_expansion(key)
    ct = aes.encrypt_block(block, rks)
    assert ct == NIST_CIPHERTEXT


def test_zero_key_zero_plaintext_roundtrip():
    key = bytes(16)
    block = bytes(16)
    rks = aes.key_expansion(key)
    ct = aes.encrypt_block(block, rks)
    pt = aes.decrypt_block(ct, rks)
    assert pt == block
