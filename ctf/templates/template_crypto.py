#!/usr/bin/env python3
"""
ctf/templates/template_crypto.py — CTF Cryptography Solve Template
NuRichter · CySec Arsenal

Edit the CONFIG section, then fill in exploit stages.
"""
from Crypto.Util.number import *
from Crypto.Cipher import AES, DES
import hashlib, itertools, base64, struct, os, sys

# ─── CONFIG ──────────────────────────────────────────────────────────────────
HOST = "challenge.ctf.io"
PORT = 1337
FLAG_FORMAT = r"[A-Z0-9_]+\{[^}]+\}"

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b * (len(a) // len(b) + 1)))

def pad_pkcs7(data: bytes, block=16) -> bytes:
    n = block - len(data) % block
    return data + bytes([n] * n)

def unpad_pkcs7(data: bytes) -> bytes:
    n = data[-1]
    assert all(b == n for b in data[-n:]), "Bad padding"
    return data[:-n]

def long_to_hex(n: int) -> str:
    return f"{n:x}" if n else "0"

def hex_to_long(h: str) -> int:
    return int(h, 16)

def bytes_to_long(b: bytes) -> int:
    return int.from_bytes(b, "big")

def long_to_bytes(n: int) -> bytes:
    length = max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(length, "big")

def extract_flag(text: str) -> list[str]:
    import re
    flags = re.findall(FLAG_FORMAT, text, re.IGNORECASE)
    for f in flags:
        print(f"\n  🚩 FLAG: {f}\n")
    return flags

# ─── RSA HELPERS ─────────────────────────────────────────────────────────────

def rsa_decrypt(c: int, d: int, n: int) -> bytes:
    return long_to_bytes(pow(c, d, n))

def rsa_small_e_attack(c: int, e: int, n: int) -> int | None:
    """Cube-root attack when e=3 and message is small (no padding)."""
    import gmpy2
    m, exact = gmpy2.iroot(c, e)
    return int(m) if exact else None

def rsa_common_modulus(c1: int, c2: int, e1: int, e2: int, n: int) -> bytes:
    """Common modulus attack when same n, different e, same plaintext."""
    from math import gcd
    g, s1, s2 = extended_gcd(e1, e2)
    if g != 1:
        return b""
    if s1 < 0:
        c1 = pow(modinv(c1, n), -s1, n)
        s1 = -s1
    if s2 < 0:
        c2 = pow(modinv(c2, n), -s2, n)
        s2 = -s2
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return long_to_bytes(m)

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y

def modinv(a: int, m: int) -> int:
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

# ─── AES HELPERS ─────────────────────────────────────────────────────────────

def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(pad_pkcs7(data))

def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    return unpad_pkcs7(AES.new(key, AES.MODE_ECB).decrypt(data))

def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad_pkcs7(data))

def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return unpad_pkcs7(AES.new(key, AES.MODE_CBC, iv).decrypt(data))

def detect_ecb_mode(ciphertext: bytes, block=16) -> bool:
    """ECB mode produces identical blocks for identical plaintext blocks."""
    blocks = [ciphertext[i:i+block] for i in range(0, len(ciphertext), block)]
    return len(blocks) != len(set(blocks))

# ─── HASH HELPERS ─────────────────────────────────────────────────────────────

def hash_length_extension(original_hash: str, original_len: int,
                           append_data: bytes, secret_len: int) -> tuple[str, bytes]:
    """SHA-256 length extension attack stub — use hashpumpy in practice."""
    # pip install hashpumpy
    try:
        import hashpumpy
        new_sig, new_msg = hashpumpy.hashpump(
            original_hash, b"\x00" * original_len, append_data, secret_len
        )
        return new_sig, new_msg
    except ImportError:
        print("  [!] pip install hashpumpy")
        return "", b""

# ─── SOLVE STAGES ────────────────────────────────────────────────────────────

def stage_connect():
    """Connect to remote and gather challenge data."""
    import socket
    print(f"[*] Connecting to {HOST}:{PORT}...")
    s = socket.socket()
    s.connect((HOST, PORT))
    s.settimeout(5)
    data = s.recv(4096).decode()
    print(f"[*] Server:\n{data}")
    return s


def stage_solve(data: str) -> bytes:
    """Main solve logic — fill this in."""
    print("[*] Solving...")

    # ── RSA example ──────────────────────────────────────────────────────────
    # n = int(data_lines[0])
    # e = int(data_lines[1])
    # c = int(data_lines[2])
    # m = rsa_small_e_attack(c, e, n)
    # return long_to_bytes(m)

    # ── AES ECB byte-at-a-time example ────────────────────────────────────────
    # Detect ECB: craft input → get ciphertext → check repeated blocks
    # detect_ecb_mode(ciphertext)

    # ── XOR stream cipher example ─────────────────────────────────────────────
    # known_plain = b"Hello, world!"
    # keystream = xor(ciphertext, known_plain)
    # flag_plain = xor(target_ciphertext, keystream)

    return b""


def main():
    # ── Local test / offline challenge ────────────────────────────────────────
    # stage_solve("<paste_challenge_data_here>")

    # ── Remote challenge ──────────────────────────────────────────────────────
    # sock = stage_connect()
    # data = sock.recv(4096).decode()
    # answer = stage_solve(data)
    # sock.send(answer + b"\n")
    # flag_data = sock.recv(4096).decode()
    # extract_flag(flag_data)

    print("[*] Edit stage_solve() and uncomment the appropriate flow.")


if __name__ == "__main__":
    main()
