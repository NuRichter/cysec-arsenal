#!/usr/bin/env python3
"""
ctf/templates/template_forensics.py — CTF Forensics Solve Template
NuRichter · CySec Arsenal

Covers: file analysis, PCAP parsing, steganography, memory forensics hints.
"""
import os
import re
import struct
import sys
import zlib
from pathlib import Path

FLAG_FORMAT = r"[A-Z0-9_]+\{[^}]+\}"

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def extract_flag(text: str, label: str = "") -> list[str]:
    flags = re.findall(FLAG_FORMAT, text, re.IGNORECASE)
    for f in flags:
        tag = f"[{label}] " if label else ""
        print(f"\n  🚩 {tag}FLAG: {f}\n")
    return flags

def read_bytes(path: str) -> bytes:
    return Path(path).read_bytes()

def write_bytes(path: str, data: bytes) -> None:
    Path(path).write_bytes(data)
    print(f"  [+] Written: {path}  ({len(data)} bytes)")

def hexdump(data: bytes, width: int = 16, limit: int = 256) -> None:
    for i in range(0, min(len(data), limit), width):
        chunk = data[i:i+width]
        hex_part  = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        print(f"  {i:08x}  {hex_part:<{width*3}}  {ascii_part}")

def strings(data: bytes, min_len: int = 6) -> list[str]:
    result, current = [], []
    for byte in data:
        if 0x20 <= byte < 0x7f:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    return result

def detect_magic(data: bytes) -> str:
    sigs = {
        b"\x89PNG\r\n\x1a\n": "PNG",
        b"\xff\xd8\xff":       "JPEG",
        b"GIF89a":             "GIF89a",
        b"GIF87a":             "GIF87a",
        b"%PDF":               "PDF",
        b"PK\x03\x04":        "ZIP",
        b"\x1f\x8b":           "GZIP",
        b"\x7fELF":            "ELF",
        b"MZ":                 "PE/EXE",
        b"\xca\xfe\xba\xbe":  "Mach-O",
        b"SQLite format 3":    "SQLite",
        b"Rar!":               "RAR",
        b"7z\xbc\xaf":        "7-ZIP",
        b"RIFF":               "RIFF(WAV/AVI)",
        b"ID3":                "MP3",
        b"\xd4\xc3\xb2\xa1":  "PCAP",
        b"OggS":               "OGG",
    }
    for sig, name in sigs.items():
        if data[:len(sig)] == sig:
            return name
    return f"Unknown (header: {data[:8].hex()})"

# ─── FILE ANALYSIS ───────────────────────────────────────────────────────────

def analyze_file(path: str) -> None:
    data = read_bytes(path)
    print(f"\n  [*] File      : {path}")
    print(f"  [*] Size      : {len(data):,} bytes")
    print(f"  [*] Magic     : {detect_magic(data)}")
    print(f"\n  [*] Hex dump (first 64 bytes):")
    hexdump(data[:64])

    # Strings
    all_strs = strings(data)
    print(f"\n  [*] Strings   : {len(all_strs)} found")
    keywords = ["flag", "FLAG", "ctf", "CTF", "password", "secret", "key",
                "http", "token", "hidden"]
    interesting = [s for s in all_strs if any(kw in s for kw in keywords)]
    for s in interesting[:20]:
        print(f"  [>] {s}")

    # Check for embedded files (naive)
    print("\n  [*] Embedded file signatures:")
    for sig, name in {b"PK\x03\x04": "ZIP", b"\xff\xd8\xff": "JPEG",
                       b"\x89PNG": "PNG", b"%PDF": "PDF"}.items():
        positions = [i for i in range(len(data)) if data[i:i+len(sig)] == sig]
        if positions:
            print(f"  [>] {name} at offsets: {positions[:5]}")

    # Flag search in raw data
    raw_str = data.decode("latin-1")
    flags = extract_flag(raw_str, "raw")
    if not flags:
        print("  [-] No flags found in raw bytes")

# ─── PNG ANALYSIS ─────────────────────────────────────────────────────────────

def parse_png_chunks(data: bytes) -> list[dict]:
    """Parse PNG chunks — useful for LSB steg, injected data."""
    chunks = []
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return []
    pos = 8
    while pos < len(data):
        length = struct.unpack(">I", data[pos:pos+4])[0]
        ctype  = data[pos+4:pos+8].decode("ascii", errors="?")
        cdata  = data[pos+8:pos+8+length]
        crc    = data[pos+8+length:pos+12+length]
        chunks.append({"type": ctype, "length": length, "data": cdata[:32]})
        pos += 12 + length
        if ctype == "IEND":
            remainder = data[pos:]
            if remainder:
                print(f"  [!] Data after IEND: {len(remainder)} bytes")
                print(f"      {remainder[:64].hex()}")
                extract_flag(remainder.decode("latin-1"), "after-IEND")
            break
    return chunks

# ─── PCAP PARSING ─────────────────────────────────────────────────────────────

def parse_pcap_simple(path: str) -> None:
    """Extract printable strings from PCAP (no scapy dependency)."""
    data = read_bytes(path)
    if data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        print("  [-] Not a valid PCAP file")
        return

    raw_str = data.decode("latin-1")
    print(f"  [*] PCAP size: {len(data):,} bytes")

    # HTTP credentials / interesting strings
    keywords = ["Authorization", "password", "pass=", "token=",
                "FLAG", "flag", "HTTP/", "GET ", "POST "]
    found_strs = strings(data, min_len=8)
    for s in found_strs:
        if any(kw in s for kw in keywords):
            print(f"  [>] {s[:120]}")

    extract_flag(raw_str, "pcap")

# ─── LSB STEGANOGRAPHY ────────────────────────────────────────────────────────

def lsb_extract_png(path: str, n_bits: int = 1) -> bytes:
    """Extract LSB-encoded data from PNG (requires Pillow)."""
    try:
        from PIL import Image
        img = Image.open(path).convert("RGB")
        pixels = list(img.getdata())
        bits = []
        for r, g, b in pixels:
            for channel in (r, g, b):
                bits.append(channel & ((1 << n_bits) - 1))

        # Reconstruct bytes
        bit_str = "".join(f"{b:0{n_bits}b}" for b in bits)
        result = bytes(
            int(bit_str[i:i+8], 2) for i in range(0, len(bit_str) - 7, 8)
        )
        # Look for flag / null terminator
        if b"\x00" in result[:1000]:
            result = result[:result.index(b"\x00")]
        return result
    except ImportError:
        print("  [!] pip install Pillow")
        return b""

# ─── ZIP / ARCHIVE ────────────────────────────────────────────────────────────

def crack_zip(path: str, wordlist_path: str) -> str | None:
    """Brute-force a password-protected ZIP."""
    try:
        import zipfile
        z = zipfile.ZipFile(path)
        with open(wordlist_path, "rb") as wl:
            for line in wl:
                pwd = line.strip()
                try:
                    z.extractall(pwd=pwd)
                    print(f"  [+] Password found: {pwd.decode()}")
                    return pwd.decode()
                except Exception:
                    pass
    except ImportError:
        pass
    return None

# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: template_forensics.py <challenge_file>")
        print("       template_forensics.py --pcap capture.pcap")
        return

    if sys.argv[1] == "--pcap":
        parse_pcap_simple(sys.argv[2])
    else:
        analyze_file(sys.argv[1])

        # PNG-specific
        data = read_bytes(sys.argv[1])
        if detect_magic(data) == "PNG":
            print("\n  [*] PNG chunk analysis:")
            for chunk in parse_png_chunks(data):
                print(f"  {chunk['type']:<8} {chunk['length']:>8} bytes")

            print("\n  [*] LSB extraction (1-bit):")
            lsb_data = lsb_extract_png(sys.argv[1])
            if lsb_data:
                print(f"  First 64 bytes: {lsb_data[:64]}")
                extract_flag(lsb_data.decode("latin-1"), "LSB")


if __name__ == "__main__":
    main()
