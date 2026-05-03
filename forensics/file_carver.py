#!/usr/bin/env python3
"""
forensics/file_carver.py — File signature carving from raw/image files
NuRichter · CySec Arsenal

Carves embedded files from binary blobs, disk images, memory dumps, STEGo containers.
Common CTF use-case: extracting hidden files from images, pcaps, or raw dumps.

Usage:
    python forensics/file_carver.py -f challenge.jpg --out extracted/
    python forensics/file_carver.py -f memory.bin --out carved/ --min-size 512
    python forensics/file_carver.py -f capture.pcap --out extracted/
"""
import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils import ok, warn, err, info, found, get_logger

log = get_logger("file_carver")


@dataclass
class Signature:
    name: str
    ext: str
    header: bytes
    footer: bytes | None = None
    max_size: int = 50 * 1024 * 1024  # 50 MB default cap


SIGNATURES: list[Signature] = [
    Signature("JPEG",    "jpg",  b"\xff\xd8\xff",       b"\xff\xd9"),
    Signature("PNG",     "png",  b"\x89PNG\r\n\x1a\n",  b"\x00\x00\x00\x00IEND\xaeB`\x82"),
    Signature("GIF87",   "gif",  b"GIF87a",              b"\x00\x3b"),
    Signature("GIF89",   "gif",  b"GIF89a",              b"\x00\x3b"),
    Signature("PDF",     "pdf",  b"%PDF",                b"%%EOF", max_size=200*1024*1024),
    Signature("ZIP",     "zip",  b"PK\x03\x04",         b"PK\x05\x06"),
    Signature("GZIP",    "gz",   b"\x1f\x8b\x08",       None, max_size=500*1024*1024),
    Signature("BMP",     "bmp",  b"BM",                  None),
    Signature("ELF",     "elf",  b"\x7fELF",             None),
    Signature("MP3",     "mp3",  b"ID3",                 None),
    Signature("7ZIP",    "7z",   b"7z\xbc\xaf'\x1c",    None),
    Signature("RAR4",    "rar",  b"Rar!\x1a\x07\x00",   None),
    Signature("RAR5",    "rar",  b"Rar!\x1a\x07\x01",   None),
    Signature("SQLite",  "db",   b"SQLite format 3\x00", None),
    Signature("PCAP",    "pcap", b"\xd4\xc3\xb2\xa1",   None),
    Signature("CLASS",   "class",b"\xca\xfe\xba\xbe",   None),
    Signature("DOCX",    "docx", b"PK\x03\x04",         None),  # same as ZIP
]


class FileCarver:
    def __init__(self, source: Path, output_dir: Path, min_size: int = 128):
        self.source = source
        self.output_dir = output_dir
        self.min_size = min_size
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.data = source.read_bytes()
        self.found: list[dict] = []

    def scan(self):
        print(info(f"Carving {self.source.name} ({len(self.data):,} bytes)"))
        print(info(f"Looking for {len(SIGNATURES)} signature types...\n"))

        for sig in SIGNATURES:
            self._carve_signature(sig)

        return self.found

    def _carve_signature(self, sig: Signature):
        offset = 0
        count = 0
        while offset < len(self.data):
            idx = self.data.find(sig.header, offset)
            if idx == -1:
                break

            # Determine end
            if sig.footer:
                end = self.data.find(sig.footer, idx + len(sig.header))
                if end == -1:
                    offset = idx + 1
                    continue
                end += len(sig.footer)
            else:
                end = min(idx + sig.max_size, len(self.data))

            chunk = self.data[idx:end]

            if len(chunk) < self.min_size:
                offset = idx + 1
                continue

            # Skip if this is the source file itself (starts at 0 and is same size)
            if idx == 0 and len(chunk) == len(self.data) and sig.ext in self.source.suffix:
                offset = idx + 1
                continue

            count += 1
            out_name = f"{sig.name}_{idx:08x}_{count}.{sig.ext}"
            out_path = self.output_dir / out_name
            out_path.write_bytes(chunk)

            entry = {
                "type": sig.name,
                "offset": idx,
                "size": len(chunk),
                "path": str(out_path),
            }
            self.found.append(entry)
            print(found(
                f"[{sig.name:<8}]  offset=0x{idx:08x}  "
                f"size={len(chunk):,}B  → {out_name}"
            ))
            log.info(f"Carved: {out_name} ({len(chunk)} bytes @ 0x{idx:08x})")

            offset = idx + 1

        if count == 0:
            pass  # silent if not found
        else:
            print(ok(f"  {count} {sig.name} file(s) carved."))


def main():
    parser = argparse.ArgumentParser(
        description="File Carver (Forensics/CTF) — NuRichter CySec Arsenal"
    )
    parser.add_argument("-f", "--file", required=True,
                        help="Input file (image, dump, pcap, etc.)")
    parser.add_argument("--out", default="carved_output",
                        help="Output directory (default: carved_output/)")
    parser.add_argument("--min-size", type=int, default=128,
                        help="Minimum carved file size in bytes (default: 128)")
    args = parser.parse_args()

    src = Path(args.file)
    if not src.exists():
        print(err(f"File not found: {src}"))
        sys.exit(1)

    carver = FileCarver(
        source=src,
        output_dir=Path(args.out),
        min_size=args.min_size,
    )
    results = carver.scan()

    print(f"\n{'='*55}")
    print(ok(f"Total carved: {len(results)} file(s) → {args.out}/"))
    if results:
        print(info("Summary:"))
        from collections import Counter
        for ftype, cnt in Counter(r["type"] for r in results).items():
            print(f"  {ftype:<10}: {cnt}")
    print(f"{'='*55}")


if __name__ == "__main__":
    main()
