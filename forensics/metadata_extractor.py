#!/usr/bin/env python3
"""
forensics/metadata_extractor.py — Extract metadata from files (CTF forensics)
NuRichter · CySec Arsenal

Supports: images (EXIF), PDFs, Office docs, generic file signatures

Usage:
    python forensics/metadata_extractor.py -f image.jpg
    python forensics/metadata_extractor.py -f document.pdf
    python forensics/metadata_extractor.py -d /path/to/dir --recursive
"""
import argparse
import os
import struct
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils import ok, warn, err, info, found, get_logger

log = get_logger("metadata_extractor")

# ─── Magic bytes for file type detection ─────────────────────────────────────
MAGIC = {
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"\xff\xd8\xff":       "JPEG",
    b"GIF87a":             "GIF87a",
    b"GIF89a":             "GIF89a",
    b"%PDF":               "PDF",
    b"PK\x03\x04":        "ZIP/DOCX/XLSX",
    b"\x7fELF":            "ELF Binary",
    b"MZ":                 "PE/EXE",
    b"\xca\xfe\xba\xbe":  "Mach-O",
    b"BM":                 "BMP",
    b"RIFF":               "RIFF (WAV/AVI)",
    b"ftyp":               "MP4/MOV",
    b"\x1f\x8b":           "GZIP",
    b"BZh":                "BZIP2",
    b"\xfd7zXZ":           "XZ",
    b"Rar!":               "RAR",
    b"7z\xbc\xaf'\x1c":   "7-ZIP",
    b"OggS":               "OGG",
    b"ID3":                "MP3",
    b"\x00\x00\x01\xba":  "MPEG",
    b"SQLite":             "SQLite DB",
}


def detect_magic(path: Path) -> str:
    with open(path, "rb") as f:
        header = f.read(16)
    for sig, name in MAGIC.items():
        if header.startswith(sig) or sig in header:
            return name
    return f"Unknown (header: {header[:8].hex()})"


def extract_strings(path: Path, min_len: int = 6) -> list[str]:
    """Extract printable strings from binary (like Unix `strings`)."""
    result = []
    current = []
    try:
        with open(path, "rb") as f:
            for byte in f.read():
                if 0x20 <= byte < 0x7F:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_len:
                        result.append("".join(current))
                    current = []
    except Exception as e:
        print(warn(f"strings extraction failed: {e}"))
    return result


def extract_exif(path: Path) -> dict:
    """Extract EXIF from JPEG/PNG using Pillow if available."""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        img = Image.open(path)
        exif_data = img._getexif()
        if not exif_data:
            return {}
        return {TAGS.get(k, k): v for k, v in exif_data.items()
                if not isinstance(v, bytes)}
    except ImportError:
        print(warn("Pillow not installed (pip install Pillow). EXIF skipped."))
        return {}
    except Exception:
        return {}


def extract_pdf_metadata(path: Path) -> dict:
    """Very basic PDF metadata extraction (no deps)."""
    meta = {}
    try:
        content = path.read_bytes().decode(errors="ignore")
        import re
        for tag in ["Title", "Author", "Subject", "Creator", "Producer",
                    "CreationDate", "ModDate", "Keywords"]:
            match = re.search(rf"/{tag}\s*\(([^)]+)\)", content)
            if match:
                meta[tag] = match.group(1)
    except Exception as e:
        print(warn(f"PDF parse error: {e}"))
    return meta


def analyze_file(path: Path, verbose: bool = False):
    print(f"\n{'─'*55}")
    print(f"  File     : {path.name}")
    print(f"  Path     : {path}")
    print(f"  Size     : {path.stat().st_size:,} bytes")
    mtime = datetime.fromtimestamp(path.stat().st_mtime)
    print(f"  Modified : {mtime}")

    magic = detect_magic(path)
    print(f"  Type     : {magic}")

    # EXIF
    if any(magic.startswith(t) for t in ["JPEG", "PNG"]):
        exif = extract_exif(path)
        if exif:
            print(info("  EXIF metadata:"))
            for k, v in exif.items():
                print(f"    {k:<30}: {v}")
            if "GPSInfo" in exif:
                print(found("  GPS coordinates found in EXIF!"))

    # PDF
    if magic == "PDF":
        meta = extract_pdf_metadata(path)
        if meta:
            print(info("  PDF metadata:"))
            for k, v in meta.items():
                print(f"    {k:<15}: {v}")

    # Strings (useful for CTF flags, hidden URLs, credentials)
    if verbose:
        strings = extract_strings(path)
        interesting = [s for s in strings if any(
            kw in s.lower() for kw in
            ["flag", "ctf", "password", "secret", "key", "token",
             "http", "ftp", "ssh", "user", "admin", "root"]
        )]
        if interesting:
            print(found(f"  Interesting strings ({len(interesting)}):"))
            for s in interesting[:20]:
                print(f"    → {s}")

    log.info(f"Analyzed: {path} ({magic})")


def main():
    parser = argparse.ArgumentParser(
        description="Metadata Extractor (Forensics/CTF) — NuRichter CySec Arsenal"
    )
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("-f", "--file", help="Single file to analyze")
    grp.add_argument("-d", "--dir",  help="Directory to scan")
    parser.add_argument("-r", "--recursive", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Extract and show interesting strings")
    args = parser.parse_args()

    if args.file:
        analyze_file(Path(args.file), args.verbose)
    elif args.dir:
        base = Path(args.dir)
        pattern = "**/*" if args.recursive else "*"
        files = [f for f in base.glob(pattern) if f.is_file()]
        print(info(f"Scanning {len(files)} file(s) in {base}"))
        for f in sorted(files):
            try:
                analyze_file(f, args.verbose)
            except Exception as e:
                print(err(f"  Error on {f.name}: {e}"))

    print(f"\n{ok('Analysis complete.')}")


if __name__ == "__main__":
    main()
