import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aes_core as aes


def test_parse_32_lowercase():
    b = aes.parse_hex_block("0" * 32)
    assert len(b) == 16 and b == bytes(16)


def test_parse_32_uppercase():
    b = aes.parse_hex_block("FF" * 16)
    assert b == bytes([0xFF] * 16)


def test_parse_with_newlines():
    s = "00\n11\n22\n33\n44\n55\n66\n77\n88\n99\naa\nbb\ncc\ndd\nee\nff"
    b = aes.parse_hex_block(s)
    assert b.hex() == "00112233445566778899aabbccddeeff"


def test_parse_empty_fails():
    with pytest.raises(ValueError):
        aes.parse_hex_block("")


def test_parse_31_chars_fails():
    with pytest.raises(ValueError):
        aes.parse_hex_block("0" * 31)


def test_parse_33_chars_fails():
    with pytest.raises(ValueError):
        aes.parse_hex_block("0" * 33)


def test_parse_invalid_char_g_fails():
    with pytest.raises(ValueError):
        aes.parse_hex_block("0" * 31 + "g")


def test_parse_key_alias():
    k = aes.parse_hex_key("a" * 32)
    assert len(k) == 16
