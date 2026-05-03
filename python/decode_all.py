#!/usr/bin/env python3
"""
python/decode_all.py — Multi-encoding brute decoder for CTF crypto
NuRichter · CySec Arsenal  (~5% Python tier)

Tries every common encoding against the input and prints candidates
that score well as English text or contain a flag pattern.

Usage:
    python python/decode_all.py "SGVsbG8h"
    python python/decode_all.py "48 65 6c 6c 6f"
    python python/decode_all.py --file encoded.txt
    echo "dGVzdA==" | python python/decode_all.py -
"""
import argparse
import base64
import binascii
import itertools
import math
import re
import sys
import zlib
from urllib.parse import unquote, unquote_plus

FLAG_RE = re.compile(r"[A-Z0-9_]{2,}\{[^}]{1,80}\}", re.IGNORECASE)
ENGLISH_COMMON = set("etaoinshrdlcumwfgypbvkjxqz ETAOINSHRDLCUMWFGYPBVKJXQZ")


def english_score(text: str) -> float:
    if not text:
        return 0.0
    alpha = sum(c.isalpha() for c in text)
    total = len(text)
    if total == 0:
        return 0.0
    common_hits = sum(1 for c in text if c in ENGLISH_COMMON)
    return (common_hits / total) * (alpha / total)


def is_printable(data: bytes, threshold: float = 0.85) -> bool:
    printable = sum(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in data)
    return printable / max(len(data), 1) >= threshold


def try_decode(label: str, raw: str, data: bytes) -> list[dict]:
    results = []

    def emit(method: str, decoded: bytes):
        if not decoded or len(decoded) < 2:
            return
        if not is_printable(decoded):
            return
        text = decoded.decode("utf-8", errors="replace")
        score = english_score(text)
        has_flag = bool(FLAG_RE.search(text))
        if score > 0.25 or has_flag or len(text) < 12:
            results.append({
                "method": method,
                "text": text[:200],
                "score": round(score, 3),
                "flag": has_flag,
            })

    # ── Base64 variants ──────────────────────────────────────────────────────
    for pad in ["", "=", "=="]:
        try:
            emit(f"base64", base64.b64decode(raw.strip() + pad))
        except Exception:
            pass

    try:
        emit("base64-url", base64.urlsafe_b64decode(raw.strip() + "=="))
    except Exception:
        pass

    try:
        emit("base32", base64.b32decode(raw.strip().upper() + "=" * (8 - len(raw.strip()) % 8)))
    except Exception:
        pass

    try:
        emit("base16", base64.b16decode(raw.strip().upper()))
    except Exception:
        pass

    try:
        emit("base85", base64.b85decode(raw.strip()))
    except Exception:
        pass

    # ── Hex ──────────────────────────────────────────────────────────────────
    clean_hex = raw.replace(" ", "").replace("0x", "").replace("\\x", "").strip()
    try:
        emit("hex", bytes.fromhex(clean_hex))
    except Exception:
        pass

    # ── URL encoding ──────────────────────────────────────────────────────────
    try:
        emit("url-decode", unquote(raw).encode())
    except Exception:
        pass
    try:
        emit("url-decode+", unquote_plus(raw).encode())
    except Exception:
        pass

    # ── Binary (space-separated 8-bit groups) ────────────────────────────────
    parts = raw.strip().split()
    if all(set(p) <= {"0", "1"} and len(p) == 8 for p in parts):
        try:
            emit("binary", bytes(int(p, 2) for p in parts))
        except Exception:
            pass

    # ── Decimal bytes ─────────────────────────────────────────────────────────
    try:
        nums = [int(x) for x in raw.strip().split() if x.isdigit()]
        if nums and all(0 <= n <= 255 for n in nums):
            emit("decimal-bytes", bytes(nums))
    except Exception:
        pass

    # ── ROT variants ──────────────────────────────────────────────────────────
    def caesar(text: str, shift: int) -> str:
        out = []
        for c in text:
            if c.isascii() and c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                out.append(chr((ord(c) - base + shift) % 26 + base))
            else:
                out.append(c)
        return "".join(out)

    for shift in range(1, 26):
        rotated = caesar(raw, shift)
        score = english_score(rotated)
        has_flag = bool(FLAG_RE.search(rotated))
        if score > 0.4 or has_flag:
            results.append({
                "method": f"caesar-{shift}",
                "text": rotated[:200],
                "score": round(score, 3),
                "flag": has_flag,
            })

    # ── Atbash ────────────────────────────────────────────────────────────────
    def atbash(text: str) -> str:
        out = []
        for c in text:
            if c.isascii() and c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                out.append(chr(base + 25 - (ord(c) - base)))
            else:
                out.append(c)
        return "".join(out)

    ab = atbash(raw)
    if english_score(ab) > 0.3 or FLAG_RE.search(ab):
        results.append({"method": "atbash", "text": ab[:200],
                         "score": round(english_score(ab), 3), "flag": bool(FLAG_RE.search(ab))})

    # ── Morse ─────────────────────────────────────────────────────────────────
    MORSE_REV = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
        "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
        "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
        ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
        "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
        "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
        "...--": "3", "....-": "4", ".....": "5", "-....": "6",
        "--...": "7", "---..": "8", "----.": "9", "/": " ",
    }
    morse_chars = set(".-/ \t")
    if all(c in morse_chars for c in raw.strip()):
        decoded_morse = "".join(
            MORSE_REV.get(token, "?") for token in raw.strip().split(" ")
        )
        if "?" not in decoded_morse or FLAG_RE.search(decoded_morse):
            results.append({"method": "morse", "text": decoded_morse,
                             "score": 0.9, "flag": bool(FLAG_RE.search(decoded_morse))})

    # ── zlib decompress ───────────────────────────────────────────────────────
    try:
        emit("zlib", zlib.decompress(data))
    except Exception:
        pass

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Multi-encoding brute decoder — NuRichter CySec Arsenal"
    )
    parser.add_argument("input", nargs="?", help="Encoded string or '-' for stdin")
    parser.add_argument("--file", "-f", help="Read from file")
    parser.add_argument("--top", "-n", type=int, default=10,
                        help="Show top N results (default: 10)")
    parser.add_argument("--all", "-a", action="store_true",
                        help="Show all results regardless of score")
    args = parser.parse_args()

    if args.file:
        raw = open(args.file).read().strip()
    elif args.input == "-" or not args.input:
        raw = sys.stdin.read().strip()
    else:
        raw = args.input

    try:
        data = bytes.fromhex(raw.replace(" ", "").replace("\\x", ""))
    except ValueError:
        data = raw.encode()

    print(f"\n  Input  : {raw[:80]}{'...' if len(raw)>80 else ''}")
    print(f"  Length : {len(raw)} chars / {len(data)} bytes\n")
    print(f"  {'Method':<18} {'Score':>6}  {'Flag':>4}  Result")
    print(f"  {'─'*70}")

    results = try_decode("input", raw, data)
    results.sort(key=lambda r: (r["flag"], r["score"]), reverse=True)

    shown = 0
    for r in results:
        if shown >= args.top and not args.all:
            break
        flag_marker = " 🚩" if r["flag"] else ""
        preview = r["text"].replace("\n", "↵")[:60]
        print(f"  {r['method']:<18} {r['score']:>6.3f}  {'YES' if r['flag'] else '':>4}  {preview}{flag_marker}")
        shown += 1

    if not results:
        print("  (no decodable results found)")
    print()


if __name__ == "__main__":
    main()
