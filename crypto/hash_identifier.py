#!/usr/bin/env python3
"""
crypto/hash_identifier.py — Identify hash type & attempt dictionary crack
NuRichter · CySec Arsenal

Usage:
    python crypto/hash_identifier.py -H "5f4dcc3b5aa765d61d8327deb882cf99"
    python crypto/hash_identifier.py -H "..." -w /usr/share/wordlists/rockyou.txt
    python crypto/hash_identifier.py --file hashes.txt -w wordlist.txt
"""
import argparse
import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils import ok, warn, err, info, found, get_logger

log = get_logger("hash_identifier")

# ─── Hash signatures ─────────────────────────────────────────────────────────
HASH_PATTERNS = [
    # (name, length, regex_hint)
    ("MD5",            32,  r"^[a-fA-F0-9]{32}$"),
    ("SHA-1",          40,  r"^[a-fA-F0-9]{40}$"),
    ("SHA-224",        56,  r"^[a-fA-F0-9]{56}$"),
    ("SHA-256",        64,  r"^[a-fA-F0-9]{64}$"),
    ("SHA-384",        96,  r"^[a-fA-F0-9]{96}$"),
    ("SHA-512",       128,  r"^[a-fA-F0-9]{128}$"),
    ("MD5(Unix)",      34,  r"^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$"),
    ("bcrypt",         60,  r"^\$2[ayb]\$.{56}$"),
    ("SHA-512(Unix)",  98,  r"^\$6\$.{86}$"),
    ("SHA-256(Unix)",  74,  r"^\$5\$.{71}$"),
    ("NTLM",           32,  r"^[a-fA-F0-9]{32}$"),
    ("LM",             32,  r"^[a-fA-F0-9]{32}$"),
    ("CRC32",           8,  r"^[a-fA-F0-9]{8}$"),
    ("MySQL323",       16,  r"^[a-fA-F0-9]{16}$"),
    ("SHA3-256",       64,  r"^[a-fA-F0-9]{64}$"),
    ("RIPEMD-160",     40,  r"^[a-fA-F0-9]{40}$"),
    ("Whirlpool",     128,  r"^[a-fA-F0-9]{128}$"),
    ("Adler32",         8,  r"^[a-fA-F0-9]{8}$"),
]

# hashlib algos for cracking
CRACK_ALGOS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512",
               "sha3_256", "sha3_512", "blake2b", "blake2s"]


def identify(hash_str: str) -> list[str]:
    """Return list of possible hash types for the given hash string."""
    candidates = []
    hash_clean = hash_str.strip()
    length = len(hash_clean)

    for name, expected_len, pattern in HASH_PATTERNS:
        if re.match(pattern, hash_clean):
            candidates.append(name)

    if not candidates:
        candidates.append(f"Unknown (length={length})")

    return candidates


def crack_single(hash_str: str, wordlist_path: str) -> str | None:
    hash_clean = hash_str.strip().lower()
    total = 0

    try:
        with open(wordlist_path, "rb") as wl:
            for line in wl:
                word = line.rstrip(b"\n\r")
                for algo in CRACK_ALGOS:
                    try:
                        h = hashlib.new(algo, word).hexdigest()
                        if h == hash_clean:
                            plaintext = word.decode(errors="ignore")
                            return plaintext
                    except Exception:
                        pass
                total += 1
                if total % 100_000 == 0:
                    print(info(f"  Tried {total:,} passwords..."), end="\r")
    except FileNotFoundError:
        print(err(f"Wordlist not found: {wordlist_path}"))
        return None

    print()
    return None


def process_hash(hash_str: str, wordlist: str | None):
    print(f"\n  Hash     : {hash_str}")
    candidates = identify(hash_str)
    print(f"  Type(s)  : {', '.join(candidates)}")

    if wordlist:
        print(info(f"  Cracking with wordlist: {wordlist}"))
        result = crack_single(hash_str, wordlist)
        if result:
            print(found(f"  CRACKED  : {repr(result)}"))
            log.info(f"CRACKED: {hash_str} → {repr(result)}")
        else:
            print(warn("  Not found in wordlist."))
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Hash Identifier & Cracker — NuRichter CySec Arsenal"
    )
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("-H", "--hash", help="Single hash string")
    grp.add_argument("--file", help="File containing one hash per line")
    parser.add_argument("-w", "--wordlist", default="",
                        help="Wordlist for dictionary attack")
    parser.add_argument("--identify-only", action="store_true",
                        help="Only identify, skip cracking")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print("  Hash Identifier & Cracker — NuRichter CySec Arsenal")
    print(f"{'='*60}")

    wordlist = None if args.identify_only else (args.wordlist or None)

    if args.hash:
        process_hash(args.hash, wordlist)
    elif args.file:
        lines = Path(args.file).read_text().splitlines()
        hashes = [l.strip() for l in lines if l.strip()]
        print(info(f"Loaded {len(hashes)} hash(es) from {args.file}\n"))
        for h in hashes:
            process_hash(h, wordlist)

    print(ok("Done."))


if __name__ == "__main__":
    main()
