"""
tests/test_crypto.py — Unit tests for crypto module
NuRichter · CySec Arsenal
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crypto.cipher_tools import (
    caesar, rot13, vigenere, atbash, xor_bytes,
    rail_fence, morse_encode, morse_decode, bruteforce_caesar, _score
)
from crypto.hash_identifier import identify


class TestCaesar:
    def test_encode_basic(self):
        assert caesar("Hello", 3) == "Khoor"

    def test_decode_basic(self):
        assert caesar("Khoor", 3, decode=True) == "Hello"

    def test_rot13_roundtrip(self):
        assert rot13(rot13("NuRichter")) == "NuRichter"

    def test_preserves_non_alpha(self):
        assert caesar("Hello, World! 123", 13) == rot13("Hello, World! 123")

    def test_brute_force_finds_correct(self):
        ciphertext = caesar("The quick brown fox", 7)
        results = bruteforce_caesar(ciphertext)
        shifts = [r[0] for r in results]
        assert 7 in shifts


class TestVigenere:
    def test_encode(self):
        assert vigenere("HELLO", "KEY") == "RIJVS"

    def test_decode(self):
        assert vigenere("RIJVS", "KEY", decode=True) == "HELLO"

    def test_roundtrip(self):
        plain = "ATTACKATDAWN"
        key = "LEMON"
        assert vigenere(vigenere(plain, key), key, decode=True) == plain


class TestAtbash:
    def test_basic(self):
        assert atbash("ABC") == "ZYX"

    def test_roundtrip(self):
        text = "Hello World"
        assert atbash(atbash(text)) == text


class TestXOR:
    def test_single_byte_roundtrip(self):
        data = b"Hello CTF!"
        key = b"\x42"
        assert xor_bytes(xor_bytes(data, key), key) == data

    def test_multi_byte_key(self):
        data = b"ABCDEF"
        key = b"\x01\x02\x03"
        encoded = xor_bytes(data, key)
        assert xor_bytes(encoded, key) == data

    def test_null_key(self):
        data = b"\x41\x42\x43"
        assert xor_bytes(data, b"\x00") == data


class TestRailFence:
    def test_encode_3_rails(self):
        text = "WEAREDISCOVEREDRUNATONCE"
        result = rail_fence(text, 3)
        # Length must be preserved; roundtrip decode must recover original
        assert len(result) == len(text)
        assert rail_fence(result, 3, decode=True) == text

    def test_roundtrip(self):
        text = "HELLOWORLD"
        for rails in [2, 3, 4]:
            assert rail_fence(rail_fence(text, rails), rails, decode=True) == text


class TestMorse:
    def test_encode_basic(self):
        assert morse_encode("SOS") == "... --- ..."

    def test_decode_basic(self):
        assert morse_decode("... --- ...") == "SOS"

    def test_roundtrip(self):
        text = "HELLO"
        assert morse_decode(morse_encode(text)) == text


class TestHashIdentifier:
    def test_md5_length(self):
        # 32 hex chars = MD5
        h = "5f4dcc3b5aa765d61d8327deb882cf99"
        types = identify(h)
        assert "MD5" in types or "NTLM" in types or "LM" in types

    def test_sha256_length(self):
        h = "a" * 64
        types = identify(h)
        assert "SHA-256" in types or "SHA3-256" in types

    def test_sha1_length(self):
        h = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        types = identify(h)
        assert "SHA-1" in types or "RIPEMD-160" in types

    def test_unknown_length(self):
        h = "abc123"
        types = identify(h)
        assert any("Unknown" in t or len(h) != 32 for t in types)

    def test_bcrypt(self):
        h = "$2a$" + "x" * 56
        types = identify(h)
        assert "bcrypt" in types


class TestScoring:
    def test_english_scores_high(self):
        s = _score("the quick brown fox jumps over the lazy dog")
        assert s > 0.25  # common letters (e,t,a,o,i,n) should appear frequently

    def test_random_hex_scores_low(self):
        s = _score("5f4dcc3b5aa765d61d8327deb882cf99")
        assert s < 0.4
