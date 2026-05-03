#!/usr/bin/env python3
"""
crypto/cipher_tools.py — Classic cipher encode/decode for CTF
NuRichter · CySec Arsenal

Supports: Caesar, ROT13, Vigenere, XOR, Base64, Atbash, Rail-fence,
          Morse, hex, binary

Usage:
    python crypto/cipher_tools.py caesar  --decode --text "Khoor Zruog" --shift 3
    python crypto/cipher_tools.py vigenere --decode --text "RIJVS" --key "KEY"
    python crypto/cipher_tools.py xor     --text "68656c6c6f" --key "41" --hex
    python crypto/cipher_tools.py bruteforce-caesar --text "Khoor Zruog"
    python crypto/cipher_tools.py auto    --text "SGVsbG8gV29ybGQ="
"""
import argparse
import base64
import itertools
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils import ok, warn, err, info, found, get_logger

log = get_logger("cipher_tools")

ALPHABET = string.ascii_uppercase
MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".",
    "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
    "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
    "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
    "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
    "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....",
    "7": "--...", "8": "---..", "9": "----.", " ": "/",
}
MORSE_REV = {v: k for k, v in MORSE.items()}

# English letter frequency for auto-detect scoring
ENGLISH_FREQ = "etaoinshrdlcumwfgypbvkjxqz"


# ─── Ciphers ──────────────────────────────────────────────────────────────────

def caesar(text: str, shift: int, decode: bool = False) -> str:
    if decode:
        shift = -shift
    result = []
    for ch in text:
        if ch.upper() in ALPHABET:
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def rot13(text: str) -> str:
    return caesar(text, 13)


def vigenere(text: str, key: str, decode: bool = False) -> str:
    key = key.upper()
    result = []
    ki = 0
    for ch in text:
        if ch.upper() in ALPHABET:
            base = ord("A") if ch.isupper() else ord("a")
            ks = ord(key[ki % len(key)]) - ord("A")
            if decode:
                ks = -ks
            result.append(chr((ord(ch) - base + ks) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return "".join(result)


def atbash(text: str) -> str:
    result = []
    for ch in text:
        if ch.upper() in ALPHABET:
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr(base + 25 - (ord(ch) - base)))
        else:
            result.append(ch)
    return "".join(result)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def rail_fence(text: str, rails: int, decode: bool = False) -> str:
    if not decode:
        fence = [[] for _ in range(rails)]
        rail, direction = 0, 1
        for ch in text:
            fence[rail].append(ch)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction
        return "".join("".join(r) for r in fence)
    else:
        n = len(text)
        pattern = []
        rail, direction = 0, 1
        for _ in range(n):
            pattern.append(rail)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction
        indices = sorted(range(n), key=lambda i: pattern[i])
        result = [""] * n
        for idx, ch in zip(indices, text):
            result[idx] = ch
        return "".join(result)


def morse_encode(text: str) -> str:
    return " ".join(MORSE.get(ch.upper(), "?") for ch in text)


def morse_decode(text: str) -> str:
    return "".join(MORSE_REV.get(code, "?") for code in text.split(" "))


# ─── Auto-detect / Brute force ────────────────────────────────────────────────

def _score(text: str) -> float:
    """Score text based on English letter frequency."""
    lower = text.lower()
    count = sum(lower.count(ch) for ch in ENGLISH_FREQ[:6])
    total = sum(c.isalpha() for c in lower)
    return count / max(total, 1)


def bruteforce_caesar(text: str, top: int = 5) -> list[tuple[int, str]]:
    results = []
    for shift in range(26):
        dec = caesar(text, shift, decode=True)
        results.append((shift, dec, _score(dec)))
    results.sort(key=lambda x: x[2], reverse=True)
    return [(r[0], r[1]) for r in results[:top]]


def auto_detect(text: str) -> None:
    """Try common encodings and report results."""
    print(info("Auto-detecting encoding...\n"))

    # Base64
    try:
        dec = base64.b64decode(text).decode("utf-8")
        print(found(f"[Base64]  → {dec}"))
    except Exception:
        pass

    # Hex
    try:
        dec = bytes.fromhex(text).decode("utf-8")
        print(found(f"[Hex]     → {dec}"))
    except Exception:
        pass

    # Binary
    try:
        parts = text.split()
        if all(set(p) <= {"0", "1"} for p in parts):
            dec = "".join(chr(int(b, 2)) for b in parts)
            print(found(f"[Binary]  → {dec}"))
    except Exception:
        pass

    # ROT13
    dec = rot13(text)
    if _score(dec) > 0.4:
        print(found(f"[ROT13]   → {dec}"))

    # Caesar brute force
    results = bruteforce_caesar(text)
    best_shift, best = results[0]
    if _score(best) > 0.5:
        print(found(f"[Caesar]  shift={best_shift} → {best}"))

    # Atbash
    dec = atbash(text)
    if _score(dec) > 0.4:
        print(found(f"[Atbash]  → {dec}"))

    # Morse
    if set(text) <= set(".- /\t\n"):
        print(found(f"[Morse]   → {morse_decode(text)}"))


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Cipher Tools (CTF) — NuRichter CySec Arsenal"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    for name in ["caesar", "rot13", "atbash", "vigenere", "xor",
                 "rail-fence", "morse", "b64", "hex", "binary",
                 "bruteforce-caesar", "auto"]:
        sp = sub.add_parser(name)
        sp.add_argument("--text", required=True)
        sp.add_argument("--decode", action="store_true")
        sp.add_argument("--shift", type=int, default=3)
        sp.add_argument("--key", default="KEY")
        sp.add_argument("--rails", type=int, default=3)
        sp.add_argument("--hex", action="store_true",
                        help="Input/output as hex (for XOR)")

    args = parser.parse_args()
    text = args.text

    print()
    if args.cmd == "caesar":
        print(found(caesar(text, args.shift, args.decode)))
    elif args.cmd == "rot13":
        print(found(rot13(text)))
    elif args.cmd == "atbash":
        print(found(atbash(text)))
    elif args.cmd == "vigenere":
        print(found(vigenere(text, args.key, args.decode)))
    elif args.cmd == "xor":
        if args.hex:
            data = bytes.fromhex(text)
            key = bytes.fromhex(args.key)
        else:
            data = text.encode()
            key = args.key.encode()
        result = xor_bytes(data, key)
        print(found(f"hex: {result.hex()}  ascii: {result.decode(errors='?')}"))
    elif args.cmd == "rail-fence":
        print(found(rail_fence(text, args.rails, args.decode)))
    elif args.cmd == "morse":
        if args.decode:
            print(found(morse_decode(text)))
        else:
            print(found(morse_encode(text)))
    elif args.cmd == "b64":
        if args.decode:
            print(found(base64.b64decode(text).decode(errors="?")))
        else:
            print(found(base64.b64encode(text.encode()).decode()))
    elif args.cmd == "hex":
        if args.decode:
            print(found(bytes.fromhex(text).decode(errors="?")))
        else:
            print(found(text.encode().hex()))
    elif args.cmd == "binary":
        if args.decode:
            parts = text.split()
            print(found("".join(chr(int(b, 2)) for b in parts)))
        else:
            print(found(" ".join(f"{ord(c):08b}" for c in text)))
    elif args.cmd == "bruteforce-caesar":
        results = bruteforce_caesar(text)
        for shift, dec in results:
            print(f"  shift={shift:2d}: {dec}")
    elif args.cmd == "auto":
        auto_detect(text)
    print()


if __name__ == "__main__":
    main()
