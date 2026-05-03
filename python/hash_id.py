#!/usr/bin/env python3
"""
python/hash_id.py — Hash type identifier with regex fingerprinting
NuRichter · CySec Arsenal  (~5% Python tier)

Usage:
    python python/hash_id.py "5f4dcc3b5aa765d61d8327deb882cf99"
    python python/hash_id.py --file hashes.txt
    echo "da39a3ee5e6b4b0d3255bfef95601890afd80709" | python python/hash_id.py -
"""
import argparse
import re
import sys

HASH_SIGNATURES = [
    # (name, regex, example)
    ("MD5",             re.compile(r"^[a-f0-9]{32}$", re.I),           "5f4dcc3b5aa765d61d8327deb882cf99"),
    ("NTLM",            re.compile(r"^[a-f0-9]{32}$", re.I),           "cc03e747a6afbbcbf8be7668acfebee5"),
    ("MD4",             re.compile(r"^[a-f0-9]{32}$", re.I),           "20c9a2b7e3d09bed7d0e3f0f5c4c7d9a"),
    ("SHA-1",           re.compile(r"^[a-f0-9]{40}$", re.I),           "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    ("RIPEMD-160",      re.compile(r"^[a-f0-9]{40}$", re.I),           "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    ("SHA-224",         re.compile(r"^[a-f0-9]{56}$", re.I),           "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
    ("SHA-256",         re.compile(r"^[a-f0-9]{64}$", re.I),           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("SHA3-256",        re.compile(r"^[a-f0-9]{64}$", re.I),           "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
    ("BLAKE2s-256",     re.compile(r"^[a-f0-9]{64}$", re.I),           "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"),
    ("SHA-384",         re.compile(r"^[a-f0-9]{96}$", re.I),           "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
    ("SHA-512",         re.compile(r"^[a-f0-9]{128}$", re.I),          "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
    ("SHA3-512",        re.compile(r"^[a-f0-9]{128}$", re.I),          "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"),
    ("BLAKE2b-512",     re.compile(r"^[a-f0-9]{128}$", re.I),          "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"),
    ("CRC32",           re.compile(r"^[a-f0-9]{8}$", re.I),            "ad9be6f3"),
    ("CRC64",           re.compile(r"^[a-f0-9]{16}$", re.I),           "6c87b03c801d7853"),
    ("MySQL323",        re.compile(r"^[a-f0-9]{16}$", re.I),           "4d2989b17f14af8a"),
    ("bcrypt",          re.compile(r"^\$2[ayb]\$.{56}$"),               "$2a$12$..."),
    ("MD5-Unix",        re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"), "$1$salt$hash"),
    ("SHA-256-Unix",    re.compile(r"^\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$"), "$5$salt$hash"),
    ("SHA-512-Unix",    re.compile(r"^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$"), "$6$salt$hash"),
    ("Argon2",          re.compile(r"^\$argon2"),                        "$argon2id$..."),
    ("scrypt",          re.compile(r"^\$s0\$"),                          "$s0$..."),
    ("PBKDF2-SHA256",   re.compile(r"^pbkdf2_sha256\$"),                 "pbkdf2_sha256$..."),
    ("Django-PBKDF2",   re.compile(r"^pbkdf2_"),                         "pbkdf2_sha1$..."),
    ("LM-Hash",         re.compile(r"^[a-f0-9]{32}$", re.I),            "aad3b435b51404eeaad3b435b51404ee"),
    ("NTLM-v2",         re.compile(r"^[a-f0-9]{32}:[a-f0-9]+$", re.I),  "hash:blob"),
    ("WPA-PMKID",       re.compile(r"^\*[a-f0-9]{40}$", re.I),          "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"),
    ("MySQL4.1+",       re.compile(r"^\*[a-f0-9]{40}$", re.I),          "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"),
    ("SHA-1-Base64",    re.compile(r"^\{SHA\}[A-Za-z0-9+/=]{28}$"),     "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="),
    ("Whirlpool",       re.compile(r"^[a-f0-9]{128}$", re.I),           "19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3"),
]

COLORS = {
    "green":   "\033[0;32m",
    "cyan":    "\033[0;36m",
    "magenta": "\033[0;35m",
    "yellow":  "\033[0;33m",
    "reset":   "\033[0m",
    "dim":     "\033[2m",
    "bold":    "\033[1m",
}

def c(color: str, text: str) -> str:
    return f"{COLORS.get(color,'')}{text}{COLORS['reset']}"


def identify(hash_str: str) -> list[str]:
    h = hash_str.strip()
    matches = []
    for name, pattern, _ in HASH_SIGNATURES:
        if pattern.match(h):
            if name not in matches:  # deduplicate
                matches.append(name)
    return matches if matches else ["Unknown"]


def process(hash_str: str, show_hint: bool = True) -> list[str]:
    h = hash_str.strip()
    if not h:
        return []

    types = identify(h)
    length = len(h)

    print(f"\n  {c('cyan', 'Hash')}    : {h[:80]}{'...' if len(h)>80 else ''}")
    print(f"  {c('cyan', 'Length')}  : {length} chars")
    print(f"  {c('cyan', 'Type(s)')} : {c('bold', ', '.join(types))}")

    # Entropy estimate
    import math
    unique = len(set(h.lower()))
    entropy = math.log2(unique) * len(h) / len(h) if unique > 1 else 0
    print(f"  {c('dim', f'Charset : {unique} unique chars  Bits/char ≈ {math.log2(max(unique,1)):.1f}')}")

    if show_hint:
        for name in types:
            hint = _crack_hint(name)
            if hint:
                print(f"  {c('yellow', 'Crack')}   : {hint}")

    return types


def _crack_hint(hash_type: str) -> str:
    hints = {
        "MD5":          "hashcat -m 0 hash.txt rockyou.txt",
        "NTLM":         "hashcat -m 1000 hash.txt rockyou.txt",
        "SHA-1":        "hashcat -m 100 hash.txt rockyou.txt",
        "SHA-256":      "hashcat -m 1400 hash.txt rockyou.txt",
        "SHA-512":      "hashcat -m 1700 hash.txt rockyou.txt",
        "bcrypt":       "hashcat -m 3200 hash.txt rockyou.txt  (slow!)",
        "MD5-Unix":     "hashcat -m 500  hash.txt rockyou.txt",
        "SHA-512-Unix": "hashcat -m 1800 hash.txt rockyou.txt",
        "SHA-256-Unix": "hashcat -m 7400 hash.txt rockyou.txt",
        "MySQL4.1+":    "hashcat -m 300  hash.txt rockyou.txt",
        "WPA-PMKID":    "hashcat -m 22000 cap.hc22000 rockyou.txt",
    }
    return hints.get(hash_type, "")


def main():
    parser = argparse.ArgumentParser(
        description="Hash Type Identifier — NuRichter CySec Arsenal"
    )
    parser.add_argument("hash", nargs="?", help="Hash string, or '-' for stdin")
    parser.add_argument("-f", "--file", help="File with one hash per line")
    parser.add_argument("--no-hint", action="store_true", help="Skip hashcat hints")
    args = parser.parse_args()

    print(f"\n  {c('magenta', '[hash_id]')}  NuRichter · CySec Arsenal\n")

    if args.file:
        hashes = open(args.file).read().splitlines()
    elif args.hash == "-" or not args.hash:
        hashes = sys.stdin.read().splitlines()
    else:
        hashes = [args.hash]

    for h in hashes:
        h = h.strip()
        if h:
            process(h, show_hint=not args.no_hint)

    print()


if __name__ == "__main__":
    main()
